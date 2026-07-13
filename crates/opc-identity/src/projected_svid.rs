//! Coherent, bounded X.509-SVID loading from Kubernetes projected volumes.
//!
//! Kubernetes publishes a projected Secret by atomically replacing the
//! `..data` symlink. Reading the user-facing file symlinks independently can
//! therefore combine files from different Secret generations. This adapter
//! resolves `..data` once, reads every material file directly from that
//! immutable generation directory, and verifies that `..data` did not change
//! after each read before publishing the candidate.

use crate::{
    build_identity_state, extract_spiffe_id_from_cert_der, parse_certs_pem, parse_key_pem,
    IdentityReloadError, IdentityReloadEvent, IdentityState, TrustBundle, TrustBundleSet,
    TrustDomain,
};
use rustls_pki_types::CertificateDer;
use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, watch, Mutex};
use zeroize::Zeroizing;

/// Maximum size of the PEM file containing the leaf and intermediate chain.
pub const MAX_PROJECTED_SVID_CERT_FILE_BYTES: usize = 1024 * 1024;
/// Maximum size of the PEM file containing the private key.
pub const MAX_PROJECTED_SVID_KEY_FILE_BYTES: usize = 64 * 1024;
/// Maximum size of each PEM trust-bundle file.
pub const MAX_PROJECTED_SVID_BUNDLE_FILE_BYTES: usize = 1024 * 1024;
/// Maximum combined bytes read for one projected-material candidate.
pub const MAX_PROJECTED_SVID_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of certificate files that may contribute trust anchors.
pub const MAX_PROJECTED_SVID_BUNDLE_FILES: usize = 16;
/// Maximum number of certificates in the SVID leaf/intermediate chain.
pub const MAX_PROJECTED_SVID_CERTIFICATES: usize = 16;
/// Maximum total number of trust anchors across all bundle files.
pub const MAX_PROJECTED_SVID_TRUST_ANCHORS: usize = 128;
/// Number of retries after the initial read when `..data` changes mid-read.
pub const MAX_PROJECTED_SVID_GENERATION_RETRIES: usize = 3;
/// Maximum wall-clock work allowed for one generation-read attempt.
pub const PROJECTED_SVID_READ_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// Smallest accepted polling interval for the production projected source.
pub const MIN_PROJECTED_SVID_POLL_INTERVAL: Duration = Duration::from_millis(100);

const DATA_SYMLINK: &str = "..data";

/// Invalid projected-volume source configuration.
///
/// Variants deliberately contain no paths or secret-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProjectedSvidConfigError {
    /// A material path was empty, absolute, or contained `.` or `..`.
    #[error("projected material path is invalid")]
    InvalidMaterialPath,
    /// The certificate, key, or bundle paths overlap.
    #[error("projected material paths must be distinct")]
    DuplicateMaterialPath,
    /// At least one trust-bundle file is required.
    #[error("projected source requires a trust bundle")]
    MissingTrustBundle,
    /// The configured number of bundle files exceeds the fixed bound.
    #[error("projected trust-bundle file count exceeds the limit")]
    TooManyTrustBundleFiles,
    /// A zero or excessively aggressive poll interval was requested.
    #[error("projected source poll interval is below the minimum")]
    PollIntervalTooShort,
}

/// Availability of the projected identity source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedSvidAvailability {
    /// No valid material has been published yet.
    Initializing,
    /// The latest observed generation was validated and published.
    Ready,
    /// A candidate failed and the previous unexpired identity remains active.
    RetainingLastGood,
    /// No unexpired validated identity is available.
    Unavailable,
}

impl ProjectedSvidAvailability {
    /// Stable low-cardinality representation for metrics and status APIs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::RetainingLastGood => "retaining_last_good",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Closed, redaction-safe reason for the latest projected-material outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectedSvidReloadReason {
    /// The source has not completed its first successful load.
    AwaitingInitialMaterial,
    /// The `..data` link or its target could not be read.
    GenerationUnavailable,
    /// The `..data` target was not one relative directory component.
    InvalidGenerationLink,
    /// `..data` changed while material was being read.
    GenerationChanged,
    /// Every bounded retry observed a different generation.
    GenerationRetryLimit,
    /// One generation-read attempt exhausted its fixed work deadline.
    ReadAttemptTimeout,
    /// A configured material file could not be read.
    MaterialUnavailable,
    /// A configured material path did not resolve to a regular file.
    MaterialNotRegular,
    /// One material file exceeded its fixed byte limit.
    MaterialFileTooLarge,
    /// Combined candidate material exceeded its fixed byte limit.
    TotalMaterialTooLarge,
    /// The leaf/intermediate chain exceeded its certificate-count limit.
    CertificateCountExceeded,
    /// The trust bundles exceeded their total anchor-count limit.
    TrustAnchorCountExceeded,
    /// The SVID certificate PEM was malformed or empty.
    MalformedCertificate,
    /// The private-key PEM was malformed.
    MalformedPrivateKey,
    /// A trust-bundle PEM was malformed or empty.
    MalformedTrustBundle,
    /// The leaf did not validate to the supplied bundle.
    InvalidCertificateChain,
    /// The private key did not match the leaf certificate.
    PrivateKeyMismatch,
    /// The candidate SVID was expired.
    ExpiredSvid,
    /// The candidate SVID was not yet valid.
    NotYetValidSvid,
    /// The candidate workload identity was invalid.
    InvalidWorkloadIdentity,
    /// The last known-good identity reached its expiry boundary.
    LastGoodExpired,
    /// The opaque publication generation could not be incremented.
    GenerationExhausted,
}

impl ProjectedSvidReloadReason {
    /// Stable low-cardinality representation for events and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingInitialMaterial => "awaiting_initial_material",
            Self::GenerationUnavailable => "generation_unavailable",
            Self::InvalidGenerationLink => "invalid_generation_link",
            Self::GenerationChanged => "generation_changed",
            Self::GenerationRetryLimit => "generation_retry_limit",
            Self::ReadAttemptTimeout => "read_attempt_timeout",
            Self::MaterialUnavailable => "material_unavailable",
            Self::MaterialNotRegular => "material_not_regular",
            Self::MaterialFileTooLarge => "material_file_too_large",
            Self::TotalMaterialTooLarge => "total_material_too_large",
            Self::CertificateCountExceeded => "certificate_count_exceeded",
            Self::TrustAnchorCountExceeded => "trust_anchor_count_exceeded",
            Self::MalformedCertificate => "malformed_certificate",
            Self::MalformedPrivateKey => "malformed_private_key",
            Self::MalformedTrustBundle => "malformed_trust_bundle",
            Self::InvalidCertificateChain => "invalid_certificate_chain",
            Self::PrivateKeyMismatch => "private_key_mismatch",
            Self::ExpiredSvid => "expired_svid",
            Self::NotYetValidSvid => "not_yet_valid_svid",
            Self::InvalidWorkloadIdentity => "invalid_workload_identity",
            Self::LastGoodExpired => "last_good_expired",
            Self::GenerationExhausted => "generation_exhausted",
        }
    }
}

impl fmt::Display for ProjectedSvidReloadReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redaction-safe status for a [`ProjectedSvidSource`].
///
/// `generation` is an opaque process-local publication counter. It starts at
/// zero and increases for every successfully validated publication, including
/// rollback to material seen before. It does not expose the Kubernetes
/// generation-directory name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ProjectedSvidReloadStatus {
    generation: u64,
    availability: ProjectedSvidAvailability,
    reason: Option<ProjectedSvidReloadReason>,
}

impl ProjectedSvidReloadStatus {
    const fn initial() -> Self {
        Self {
            generation: 0,
            availability: ProjectedSvidAvailability::Initializing,
            reason: Some(ProjectedSvidReloadReason::AwaitingInitialMaterial),
        }
    }

    /// Opaque monotonic publication generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Current source availability.
    pub const fn availability(self) -> ProjectedSvidAvailability {
        self.availability
    }

    /// Closed reason for the latest non-ready status.
    pub const fn reason(self) -> Option<ProjectedSvidReloadReason> {
        self.reason
    }
}

#[derive(Debug, Clone)]
struct ProjectedSvidConfig {
    root: PathBuf,
    cert_file: PathBuf,
    key_file: PathBuf,
    bundle_files: Vec<PathBuf>,
    poll_interval: Duration,
}

/// Production X.509-SVID source for a Kubernetes projected volume.
///
/// The constructor accepts paths relative to the projected-volume root. The
/// adapter never follows the user-facing per-file symlinks; it reads directly
/// from one `..data` generation and retains the prior validated identity when
/// a candidate fails. Once that prior identity expires, state becomes
/// unavailable even if no replacement can be loaded.
pub struct ProjectedSvidSource {
    state_rx: watch::Receiver<Option<IdentityState>>,
    status_rx: watch::Receiver<ProjectedSvidReloadStatus>,
    event_tx: broadcast::Sender<IdentityReloadEvent>,
    task_handle: tokio::task::JoinHandle<()>,
    expiry_task_handle: tokio::task::JoinHandle<()>,
}

impl ProjectedSvidSource {
    /// Start a bounded projected-volume source.
    ///
    /// `cert_file`, `key_file`, and every `bundle_file` must be distinct,
    /// normalized relative paths below `volume_root`. The default poll
    /// interval is five seconds.
    pub fn new(
        volume_root: impl AsRef<Path>,
        cert_file: impl AsRef<Path>,
        key_file: impl AsRef<Path>,
        bundle_files: Vec<impl AsRef<Path>>,
        poll_interval: Option<Duration>,
    ) -> Result<Self, ProjectedSvidConfigError> {
        let cert_file = cert_file.as_ref().to_path_buf();
        let key_file = key_file.as_ref().to_path_buf();
        let bundle_files = bundle_files
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect::<Vec<_>>();
        validate_config_paths(&cert_file, &key_file, &bundle_files)?;

        let poll_interval = poll_interval.unwrap_or(Duration::from_secs(5));
        if poll_interval < MIN_PROJECTED_SVID_POLL_INTERVAL {
            return Err(ProjectedSvidConfigError::PollIntervalTooShort);
        }

        let config = ProjectedSvidConfig {
            root: volume_root.as_ref().to_path_buf(),
            cert_file,
            key_file,
            bundle_files,
            poll_interval,
        };
        let (state_tx, state_rx) = watch::channel(None);
        let (status_tx, status_rx) = watch::channel(ProjectedSvidReloadStatus::initial());
        let (event_tx, _) = broadcast::channel(32);
        let publication_guard = Arc::new(Mutex::new(()));

        let task_handle = tokio::spawn(run_source(
            config,
            state_tx.clone(),
            status_tx.clone(),
            event_tx.clone(),
            publication_guard.clone(),
        ));
        let expiry_task_handle = spawn_projected_expiry_monitor(
            state_tx,
            status_tx,
            event_tx.clone(),
            publication_guard,
        );

        Ok(Self {
            state_rx,
            status_rx,
            event_tx,
            task_handle,
            expiry_task_handle,
        })
    }

    /// Subscribe to the source-compatible identity-state channel.
    pub fn subscribe(&self) -> watch::Receiver<Option<IdentityState>> {
        self.state_rx.clone()
    }

    /// Subscribe to existing source-compatible success/failure events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<IdentityReloadEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to typed, redaction-safe projected-source status.
    pub fn subscribe_status(&self) -> watch::Receiver<ProjectedSvidReloadStatus> {
        self.status_rx.clone()
    }

    /// Return the current typed projected-source status.
    pub fn status(&self) -> ProjectedSvidReloadStatus {
        *self.status_rx.borrow()
    }

    /// Wait for the first valid identity, retaining the existing file-source
    /// timeout behavior.
    pub async fn wait_for_initial_identity(
        &self,
        timeout: Duration,
    ) -> Result<IdentityState, IdentityReloadError> {
        let mut rx = self.subscribe();
        if let Some(state) = rx.borrow().clone() {
            return Ok(state);
        }
        match tokio::time::timeout(timeout, async {
            loop {
                rx.changed()
                    .await
                    .map_err(|_| IdentityReloadError::IoError)?;
                if let Some(state) = rx.borrow().clone() {
                    return Ok(state);
                }
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(IdentityReloadError::IoError),
        }
    }
}

impl Drop for ProjectedSvidSource {
    fn drop(&mut self) {
        self.task_handle.abort();
        self.expiry_task_handle.abort();
    }
}

fn validate_config_paths(
    cert_file: &Path,
    key_file: &Path,
    bundle_files: &[PathBuf],
) -> Result<(), ProjectedSvidConfigError> {
    if bundle_files.is_empty() {
        return Err(ProjectedSvidConfigError::MissingTrustBundle);
    }
    if bundle_files.len() > MAX_PROJECTED_SVID_BUNDLE_FILES {
        return Err(ProjectedSvidConfigError::TooManyTrustBundleFiles);
    }

    let paths = std::iter::once(cert_file)
        .chain(std::iter::once(key_file))
        .chain(bundle_files.iter().map(PathBuf::as_path));
    let mut distinct = HashSet::with_capacity(bundle_files.len() + 2);
    for path in paths {
        if !is_normal_relative_path(path) {
            return Err(ProjectedSvidConfigError::InvalidMaterialPath);
        }
        if !distinct.insert(path.to_path_buf()) {
            return Err(ProjectedSvidConfigError::DuplicateMaterialPath);
        }
    }
    Ok(())
}

fn is_normal_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

async fn run_source(
    config: ProjectedSvidConfig,
    state_tx: watch::Sender<Option<IdentityState>>,
    status_tx: watch::Sender<ProjectedSvidReloadStatus>,
    event_tx: broadcast::Sender<IdentityReloadEvent>,
    publication_guard: Arc<Mutex<()>>,
) {
    let mut last_published_target: Option<PathBuf> = None;
    let mut last_observed_target: Option<PathBuf> = None;
    loop {
        let should_load = match resolve_generation_target(&config.root).await {
            Ok(target) => {
                let target_is_published = last_published_target.as_ref() == Some(&target);
                let target_changed = last_observed_target.as_ref() != Some(&target);
                last_observed_target = Some(target);
                !target_is_published
                    || target_changed
                    || status_tx.borrow().availability != ProjectedSvidAvailability::Ready
            }
            Err(_) => {
                last_observed_target = None;
                true
            }
        };

        if should_load {
            match load_projected_generation(&config, &NoopReadObserver).await {
                Ok(loaded) => {
                    let publication = publication_guard.lock().await;
                    let current_generation = status_tx.borrow().generation;
                    let Some(next_generation) = current_generation.checked_add(1) else {
                        drop(publication);
                        publish_failure(
                            ProjectedSvidReloadReason::GenerationExhausted,
                            &state_tx,
                            &status_tx,
                            &event_tx,
                            &publication_guard,
                        )
                        .await;
                        tokio::time::sleep(config.poll_interval).await;
                        continue;
                    };
                    let expires_at = loaded
                        .state
                        .identity
                        .expires_at
                        .as_offset_datetime()
                        .unix_timestamp();
                    state_tx.send_replace(Some(loaded.state));
                    status_tx.send_replace(ProjectedSvidReloadStatus {
                        generation: next_generation,
                        availability: ProjectedSvidAvailability::Ready,
                        reason: None,
                    });
                    last_observed_target = Some(loaded.target.clone());
                    last_published_target = Some(loaded.target);
                    let _ = event_tx.send(IdentityReloadEvent::Success {
                        expires_at: u64::try_from(expires_at).unwrap_or_default(),
                    });
                }
                Err(reason) => {
                    publish_failure(reason, &state_tx, &status_tx, &event_tx, &publication_guard)
                        .await;
                }
            }
        }

        tokio::time::sleep(config.poll_interval).await;
    }
}

async fn publish_failure(
    reason: ProjectedSvidReloadReason,
    state_tx: &watch::Sender<Option<IdentityState>>,
    status_tx: &watch::Sender<ProjectedSvidReloadStatus>,
    event_tx: &broadcast::Sender<IdentityReloadEvent>,
    publication_guard: &Mutex<()>,
) {
    let _publication = publication_guard.lock().await;
    let (has_last_good, expired_last_good) = match state_tx.borrow().as_ref() {
        Some(current) if current.is_expired() => (false, true),
        Some(_) => (true, false),
        None => (false, false),
    };
    if expired_last_good {
        state_tx.send_replace(None);
    }
    let current_status = *status_tx.borrow();
    let reason = if expired_last_good
        || (!has_last_good
            && current_status.reason == Some(ProjectedSvidReloadReason::LastGoodExpired))
    {
        ProjectedSvidReloadReason::LastGoodExpired
    } else {
        reason
    };
    let availability = if has_last_good {
        ProjectedSvidAvailability::RetainingLastGood
    } else {
        ProjectedSvidAvailability::Unavailable
    };
    let generation = current_status.generation;
    status_tx.send_replace(ProjectedSvidReloadStatus {
        generation,
        availability,
        reason: Some(reason),
    });
    let _ = event_tx.send(IdentityReloadEvent::Failure {
        error: reason.to_string(),
    });
}

fn spawn_projected_expiry_monitor(
    state_tx: watch::Sender<Option<IdentityState>>,
    status_tx: watch::Sender<ProjectedSvidReloadStatus>,
    event_tx: broadcast::Sender<IdentityReloadEvent>,
    publication_guard: Arc<Mutex<()>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state_rx = state_tx.subscribe();
        loop {
            let sleep_for = projected_expiry_sleep_duration(state_rx.borrow().as_ref());
            tokio::select! {
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = tokio::time::sleep(sleep_for) => {
                    let _publication = publication_guard.lock().await;
                    let observed_generation = status_tx.borrow().generation;
                    let expired = state_tx
                        .borrow()
                        .as_ref()
                        .is_some_and(IdentityState::is_expired);
                    if expired {
                        state_tx.send_replace(None);
                        let generation_is_current =
                            status_tx.borrow().generation == observed_generation;
                        if generation_is_current {
                            status_tx.send_replace(ProjectedSvidReloadStatus {
                                generation: observed_generation,
                                availability: ProjectedSvidAvailability::Unavailable,
                                reason: Some(ProjectedSvidReloadReason::LastGoodExpired),
                            });
                        }
                        let _ = event_tx.send(IdentityReloadEvent::Failure {
                            error: ProjectedSvidReloadReason::LastGoodExpired.to_string(),
                        });
                    }
                }
            }
        }
    })
}

fn projected_expiry_sleep_duration(state: Option<&IdentityState>) -> Duration {
    const MAX_SLEEP: Duration = Duration::from_secs(60);
    let Some(state) = state else {
        return MAX_SLEEP;
    };
    let expires_at = *state.identity.expires_at.as_offset_datetime();
    let now = time::OffsetDateTime::now_utc();
    if expires_at <= now {
        return Duration::ZERO;
    }
    let until_expiry = (expires_at - now).try_into().unwrap_or(Duration::ZERO);
    until_expiry.min(MAX_SLEEP)
}

#[derive(Debug)]
struct LoadedGeneration {
    target: PathBuf,
    state: IdentityState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectedReadPhase {
    GenerationResolved,
    CertificateRead,
    PrivateKeyRead,
    TrustBundleRead(usize),
    BeforeFinalCheck,
}

trait ReadPhaseObserver: Send + Sync {
    fn after_phase(&self, phase: ProjectedReadPhase);
}

struct NoopReadObserver;

impl ReadPhaseObserver for NoopReadObserver {
    fn after_phase(&self, _phase: ProjectedReadPhase) {}
}

async fn load_projected_generation<O: ReadPhaseObserver>(
    config: &ProjectedSvidConfig,
    observer: &O,
) -> Result<LoadedGeneration, ProjectedSvidReloadReason> {
    for retry in 0..=MAX_PROJECTED_SVID_GENERATION_RETRIES {
        let attempt = tokio::time::timeout(
            PROJECTED_SVID_READ_ATTEMPT_TIMEOUT,
            load_projected_generation_once(config, observer),
        )
        .await
        .map_err(|_| ProjectedSvidReloadReason::ReadAttemptTimeout)?;
        match attempt {
            Err(ProjectedSvidReloadReason::GenerationChanged)
                if retry < MAX_PROJECTED_SVID_GENERATION_RETRIES =>
            {
                tokio::task::yield_now().await;
            }
            Err(ProjectedSvidReloadReason::GenerationChanged) => {
                return Err(ProjectedSvidReloadReason::GenerationRetryLimit);
            }
            result => return result,
        }
    }
    Err(ProjectedSvidReloadReason::GenerationRetryLimit)
}

async fn load_projected_generation_once<O: ReadPhaseObserver>(
    config: &ProjectedSvidConfig,
    observer: &O,
) -> Result<LoadedGeneration, ProjectedSvidReloadReason> {
    let target = resolve_generation_target(&config.root).await?;
    let generation_dir = config.root.join(&target);
    let metadata = match tokio::fs::symlink_metadata(&generation_dir).await {
        Ok(metadata) => metadata,
        Err(_) => {
            ensure_generation_current(&config.root, &target).await?;
            return Err(ProjectedSvidReloadReason::GenerationUnavailable);
        }
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        ensure_generation_current(&config.root, &target).await?;
        return Err(ProjectedSvidReloadReason::InvalidGenerationLink);
    }
    observer.after_phase(ProjectedReadPhase::GenerationResolved);
    ensure_generation_current(&config.root, &target).await?;

    let mut budget = MaterialBudget::default();
    let cert_bytes = read_generation_file(
        &config.root,
        &target,
        &generation_dir.join(&config.cert_file),
        MAX_PROJECTED_SVID_CERT_FILE_BYTES,
    )
    .await?;
    budget.add(cert_bytes.len())?;
    observer.after_phase(ProjectedReadPhase::CertificateRead);
    ensure_generation_current(&config.root, &target).await?;

    let key_bytes = Zeroizing::new(
        read_generation_file(
            &config.root,
            &target,
            &generation_dir.join(&config.key_file),
            MAX_PROJECTED_SVID_KEY_FILE_BYTES,
        )
        .await?,
    );
    budget.add(key_bytes.len())?;
    observer.after_phase(ProjectedReadPhase::PrivateKeyRead);
    ensure_generation_current(&config.root, &target).await?;

    let mut bundle_bytes = Vec::with_capacity(config.bundle_files.len());
    for (index, bundle_file) in config.bundle_files.iter().enumerate() {
        let bytes = read_generation_file(
            &config.root,
            &target,
            &generation_dir.join(bundle_file),
            MAX_PROJECTED_SVID_BUNDLE_FILE_BYTES,
        )
        .await?;
        budget.add(bytes.len())?;
        bundle_bytes.push(bytes);
        observer.after_phase(ProjectedReadPhase::TrustBundleRead(index));
        ensure_generation_current(&config.root, &target).await?;
    }
    observer.after_phase(ProjectedReadPhase::BeforeFinalCheck);
    ensure_generation_current(&config.root, &target).await?;

    let cert_chain = parse_bounded_certificate_chain(&cert_bytes)?;

    let key_pem = std::str::from_utf8(&key_bytes)
        .map_err(|_| ProjectedSvidReloadReason::MalformedPrivateKey)?;
    let private_key =
        parse_key_pem(key_pem).map_err(|_| ProjectedSvidReloadReason::MalformedPrivateKey)?;

    let leaf = cert_chain
        .first()
        .ok_or(ProjectedSvidReloadReason::MalformedCertificate)?;
    let trust_domain = extract_leaf_trust_domain(leaf.as_ref())?;
    let mut anchors = Vec::new();
    for bytes in bundle_bytes {
        let certs = parse_bounded_trust_bundle(&bytes)?;
        let next_count = anchors
            .len()
            .checked_add(certs.len())
            .ok_or(ProjectedSvidReloadReason::TrustAnchorCountExceeded)?;
        ensure_count(
            next_count,
            MAX_PROJECTED_SVID_TRUST_ANCHORS,
            ProjectedSvidReloadReason::TrustAnchorCountExceeded,
        )?;
        anchors.extend(certs);
    }

    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain,
        certificates: anchors,
    });
    let state =
        build_identity_state(cert_chain, private_key, bundles).map_err(map_identity_error)?;
    Ok(LoadedGeneration { target, state })
}

async fn resolve_generation_target(root: &Path) -> Result<PathBuf, ProjectedSvidReloadReason> {
    let target = tokio::fs::read_link(root.join(DATA_SYMLINK))
        .await
        .map_err(|_| ProjectedSvidReloadReason::GenerationUnavailable)?;
    let mut components = target.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(ProjectedSvidReloadReason::InvalidGenerationLink);
    }
    Ok(target)
}

async fn ensure_generation_current(
    root: &Path,
    expected: &Path,
) -> Result<(), ProjectedSvidReloadReason> {
    match resolve_generation_target(root).await {
        Ok(actual) if actual == expected => Ok(()),
        Ok(_) | Err(_) => Err(ProjectedSvidReloadReason::GenerationChanged),
    }
}

async fn read_bounded_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ProjectedSvidReloadReason> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|_| ProjectedSvidReloadReason::MaterialUnavailable)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ProjectedSvidReloadReason::MaterialNotRegular);
    }
    if metadata.len() > maximum as u64 {
        return Err(ProjectedSvidReloadReason::MaterialFileTooLarge);
    }

    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ProjectedSvidReloadReason::MaterialUnavailable)?;
    let opened_metadata = file
        .metadata()
        .await
        .map_err(|_| ProjectedSvidReloadReason::MaterialUnavailable)?;
    if !opened_metadata.is_file() || opened_metadata.len() > maximum as u64 {
        return Err(if opened_metadata.len() > maximum as u64 {
            ProjectedSvidReloadReason::MaterialFileTooLarge
        } else {
            ProjectedSvidReloadReason::MaterialNotRegular
        });
    }

    let capacity = usize::try_from(opened_metadata.len())
        .unwrap_or(maximum)
        .min(maximum);
    let mut bytes = Vec::with_capacity(capacity);
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ProjectedSvidReloadReason::MaterialUnavailable)?;
    if bytes.len() > maximum {
        return Err(ProjectedSvidReloadReason::MaterialFileTooLarge);
    }
    Ok(bytes)
}

async fn read_generation_file(
    root: &Path,
    generation: &Path,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ProjectedSvidReloadReason> {
    match read_bounded_file(path, maximum).await {
        Ok(bytes) => Ok(bytes),
        Err(reason) => {
            ensure_generation_current(root, generation).await?;
            Err(reason)
        }
    }
}

fn parse_bounded_certificate_chain(
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, ProjectedSvidReloadReason> {
    let pem =
        std::str::from_utf8(bytes).map_err(|_| ProjectedSvidReloadReason::MalformedCertificate)?;
    let certificates =
        parse_certs_pem(pem).map_err(|_| ProjectedSvidReloadReason::MalformedCertificate)?;
    if certificates.is_empty() {
        return Err(ProjectedSvidReloadReason::MalformedCertificate);
    }
    ensure_count(
        certificates.len(),
        MAX_PROJECTED_SVID_CERTIFICATES,
        ProjectedSvidReloadReason::CertificateCountExceeded,
    )?;
    Ok(certificates)
}

fn parse_bounded_trust_bundle(
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, ProjectedSvidReloadReason> {
    let pem =
        std::str::from_utf8(bytes).map_err(|_| ProjectedSvidReloadReason::MalformedTrustBundle)?;
    let certificates =
        parse_certs_pem(pem).map_err(|_| ProjectedSvidReloadReason::MalformedTrustBundle)?;
    if certificates.is_empty() {
        return Err(ProjectedSvidReloadReason::MalformedTrustBundle);
    }
    ensure_count(
        certificates.len(),
        MAX_PROJECTED_SVID_TRUST_ANCHORS,
        ProjectedSvidReloadReason::TrustAnchorCountExceeded,
    )?;
    Ok(certificates)
}

#[derive(Default)]
struct MaterialBudget {
    bytes: usize,
}

impl MaterialBudget {
    fn add(&mut self, bytes: usize) -> Result<(), ProjectedSvidReloadReason> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(ProjectedSvidReloadReason::TotalMaterialTooLarge)?;
        if self.bytes > MAX_PROJECTED_SVID_TOTAL_BYTES {
            return Err(ProjectedSvidReloadReason::TotalMaterialTooLarge);
        }
        Ok(())
    }
}

fn ensure_count(
    count: usize,
    maximum: usize,
    reason: ProjectedSvidReloadReason,
) -> Result<(), ProjectedSvidReloadReason> {
    if count > maximum {
        Err(reason)
    } else {
        Ok(())
    }
}

fn extract_leaf_trust_domain(leaf_der: &[u8]) -> Result<TrustDomain, ProjectedSvidReloadReason> {
    let spiffe_id = extract_spiffe_id_from_cert_der(leaf_der)
        .map_err(|_| ProjectedSvidReloadReason::InvalidWorkloadIdentity)?;
    let remainder = spiffe_id
        .as_str()
        .strip_prefix("spiffe://")
        .ok_or(ProjectedSvidReloadReason::InvalidWorkloadIdentity)?;
    let value = remainder
        .split_once('/')
        .map(|(trust_domain, _)| trust_domain)
        .ok_or(ProjectedSvidReloadReason::InvalidWorkloadIdentity)?;
    TrustDomain::new(value).map_err(|_| ProjectedSvidReloadReason::InvalidWorkloadIdentity)
}

fn map_identity_error(error: IdentityReloadError) -> ProjectedSvidReloadReason {
    match error {
        IdentityReloadError::ExpiredSvid => ProjectedSvidReloadReason::ExpiredSvid,
        IdentityReloadError::NotYetValidSvid => ProjectedSvidReloadReason::NotYetValidSvid,
        IdentityReloadError::InvalidCertificateChain | IdentityReloadError::UnknownTrustDomain => {
            ProjectedSvidReloadReason::InvalidCertificateChain
        }
        IdentityReloadError::PrivateKeyMismatch => ProjectedSvidReloadReason::PrivateKeyMismatch,
        _ => ProjectedSvidReloadReason::InvalidWorkloadIdentity,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use opc_types::Timestamp;
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::time::timeout;

    const CERT_FILE: &str = "tls.crt";
    const KEY_FILE: &str = "tls.key";
    const BUNDLE_FILE: &str = "ca.crt";
    const SECOND_BUNDLE_FILE: &str = "ca-2.crt";
    const SPIFFE_A: &str =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-0";
    const SPIFFE_B: &str =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-1";

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
    static NEXT_LINK: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let ordinal = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "opc-projected-svid-{label}-{}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test projected volume");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestMaterial {
        cert_chain_pem: String,
        private_key_pem: String,
        bundle_pem: String,
    }

    fn test_ca(common_name: &str) -> (rcgen::Certificate, KeyPair) {
        let mut parameters = CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().expect("generate test CA key");
        let certificate = parameters.self_signed(&key).expect("sign test CA");
        (certificate, key)
    }

    fn workload_certificate(
        spiffe_id: &str,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (rcgen::Certificate, KeyPair) {
        let mut parameters = CertificateParams::default();
        parameters
            .distinguished_name
            .push(DnType::CommonName, "projected workload");
        parameters.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("test SPIFFE ID"),
        ));
        parameters.not_before = not_before;
        parameters.not_after = not_after;
        let key = KeyPair::generate().expect("generate workload key");
        let certificate = parameters
            .signed_by(&key, ca, ca_key)
            .expect("sign workload certificate");
        (certificate, key)
    }

    fn valid_material(spiffe_id: &str) -> TestMaterial {
        let (ca, ca_key) = test_ca("projected test CA");
        material_signed_by(spiffe_id, &ca, &ca_key, None)
    }

    fn material_signed_by(
        spiffe_id: &str,
        ca: &rcgen::Certificate,
        ca_key: &KeyPair,
        validity: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
    ) -> TestMaterial {
        let now = time::OffsetDateTime::now_utc();
        let (not_before, not_after) = validity.unwrap_or((
            now - time::Duration::hours(1),
            now + time::Duration::hours(1),
        ));
        let (workload, workload_key) =
            workload_certificate(spiffe_id, ca, ca_key, not_before, not_after);
        TestMaterial {
            cert_chain_pem: workload.pem() + &ca.pem(),
            private_key_pem: workload_key.serialize_pem(),
            bundle_pem: ca.pem(),
        }
    }

    fn write_generation(root: &Path, name: &str, material: &TestMaterial) -> PathBuf {
        let directory = root.join(name);
        fs::create_dir_all(&directory).expect("create projected generation");
        fs::write(directory.join(CERT_FILE), &material.cert_chain_pem)
            .expect("write test certificate");
        fs::write(directory.join(KEY_FILE), &material.private_key_pem)
            .expect("write test private key");
        fs::write(directory.join(BUNDLE_FILE), &material.bundle_pem)
            .expect("write test trust bundle");
        directory
    }

    fn switch_generation(root: &Path, target: &str) {
        let ordinal = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
        let temporary = root.join(format!("..data-next-{ordinal}"));
        symlink(target, &temporary).expect("create replacement ..data link");
        fs::rename(temporary, root.join(DATA_SYMLINK)).expect("atomically replace ..data link");
    }

    fn config(root: &Path) -> ProjectedSvidConfig {
        ProjectedSvidConfig {
            root: root.to_path_buf(),
            cert_file: PathBuf::from(CERT_FILE),
            key_file: PathBuf::from(KEY_FILE),
            bundle_files: vec![PathBuf::from(BUNDLE_FILE)],
            poll_interval: MIN_PROJECTED_SVID_POLL_INTERVAL,
        }
    }

    fn source(root: &Path) -> ProjectedSvidSource {
        ProjectedSvidSource::new(
            root,
            CERT_FILE,
            KEY_FILE,
            vec![BUNDLE_FILE],
            Some(MIN_PROJECTED_SVID_POLL_INTERVAL),
        )
        .expect("valid projected source configuration")
    }

    async fn wait_for_status(
        source: &ProjectedSvidSource,
        predicate: impl Fn(ProjectedSvidReloadStatus) -> bool,
    ) -> ProjectedSvidReloadStatus {
        let mut receiver = source.subscribe_status();
        timeout(Duration::from_secs(5), async {
            loop {
                let status = *receiver.borrow();
                if predicate(status) {
                    return status;
                }
                receiver.changed().await.expect("projected status sender");
            }
        })
        .await
        .expect("projected status deadline")
    }

    async fn wait_for_failure_event(
        receiver: &mut broadcast::Receiver<IdentityReloadEvent>,
        reason: ProjectedSvidReloadReason,
    ) {
        let event = timeout(Duration::from_secs(5), async {
            loop {
                let event = receiver.recv().await.expect("projected reload event");
                if matches!(&event, IdentityReloadEvent::Failure { error } if error == reason.as_str())
                {
                    return event;
                }
            }
        })
        .await
        .expect("failure event deadline");
        assert_eq!(
            match event {
                IdentityReloadEvent::Failure { error } => error,
                IdentityReloadEvent::Success { .. } => unreachable!("filtered above"),
            },
            reason.as_str()
        );
    }

    fn assert_identity_bytes_equal(left: &IdentityState, right: &IdentityState) {
        let left_chain = left
            .svid
            .cert_chain
            .iter()
            .map(|certificate| certificate.as_ref())
            .collect::<Vec<_>>();
        let right_chain = right
            .svid
            .cert_chain
            .iter()
            .map(|certificate| certificate.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(left_chain, right_chain);
        assert_eq!(
            left.svid.private_key.secret_der(),
            right.svid.private_key.secret_der()
        );
        let trust_domain = &left.identity.trust_domain;
        let left_bundle = left
            .trust_bundles
            .get(trust_domain)
            .expect("left trust bundle");
        let right_bundle = right
            .trust_bundles
            .get(trust_domain)
            .expect("right trust bundle");
        assert_eq!(
            left_bundle
                .certificates
                .iter()
                .map(|certificate| certificate.as_ref())
                .collect::<Vec<_>>(),
            right_bundle
                .certificates
                .iter()
                .map(|certificate| certificate.as_ref())
                .collect::<Vec<_>>()
        );
    }

    struct SwapOnceObserver {
        root: PathBuf,
        target: &'static str,
        phase: ProjectedReadPhase,
        swapped: AtomicBool,
    }

    impl ReadPhaseObserver for SwapOnceObserver {
        fn after_phase(&self, phase: ProjectedReadPhase) {
            if phase == self.phase && !self.swapped.swap(true, Ordering::SeqCst) {
                switch_generation(&self.root, self.target);
            }
        }
    }

    struct SwapEveryAttemptObserver {
        root: PathBuf,
        attempts: AtomicUsize,
    }

    impl ReadPhaseObserver for SwapEveryAttemptObserver {
        fn after_phase(&self, phase: ProjectedReadPhase) {
            if phase != ProjectedReadPhase::GenerationResolved {
                return;
            }
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            let target = if attempt.is_multiple_of(2) {
                "..gen-b"
            } else {
                "..gen-a"
            };
            switch_generation(&self.root, target);
        }
    }

    #[test]
    fn configuration_rejects_unsafe_paths_duplicates_counts_and_fast_polling() {
        assert_eq!(
            validate_config_paths(
                Path::new("../tls.crt"),
                Path::new(KEY_FILE),
                &[BUNDLE_FILE.into()]
            ),
            Err(ProjectedSvidConfigError::InvalidMaterialPath)
        );
        assert_eq!(
            validate_config_paths(
                Path::new(CERT_FILE),
                Path::new(CERT_FILE),
                &[BUNDLE_FILE.into()]
            ),
            Err(ProjectedSvidConfigError::DuplicateMaterialPath)
        );
        assert_eq!(
            validate_config_paths(Path::new(CERT_FILE), Path::new(KEY_FILE), &[]),
            Err(ProjectedSvidConfigError::MissingTrustBundle)
        );
        let exact = (0..MAX_PROJECTED_SVID_BUNDLE_FILES)
            .map(|index| PathBuf::from(format!("bundle-{index}.pem")))
            .collect::<Vec<_>>();
        assert!(validate_config_paths(Path::new(CERT_FILE), Path::new(KEY_FILE), &exact).is_ok());
        let one_over = (0..=MAX_PROJECTED_SVID_BUNDLE_FILES)
            .map(|index| PathBuf::from(format!("bundle-{index}.pem")))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_config_paths(Path::new(CERT_FILE), Path::new(KEY_FILE), &one_over),
            Err(ProjectedSvidConfigError::TooManyTrustBundleFiles)
        );
    }

    #[tokio::test]
    async fn constructor_enforces_the_exact_poll_interval_boundary() {
        let directory = TestDirectory::new("poll-bound");
        let exact = ProjectedSvidSource::new(
            directory.path(),
            CERT_FILE,
            KEY_FILE,
            vec![BUNDLE_FILE],
            Some(MIN_PROJECTED_SVID_POLL_INTERVAL),
        );
        assert!(exact.is_ok());
        let below = ProjectedSvidSource::new(
            directory.path(),
            CERT_FILE,
            KEY_FILE,
            vec![BUNDLE_FILE],
            Some(MIN_PROJECTED_SVID_POLL_INTERVAL - Duration::from_nanos(1)),
        );
        assert!(matches!(
            below,
            Err(ProjectedSvidConfigError::PollIntervalTooShort)
        ));
    }

    #[tokio::test]
    async fn per_file_and_total_byte_limits_accept_exact_and_reject_one_over() {
        let directory = TestDirectory::new("byte-bounds");
        for (name, maximum) in [
            ("cert.pem", MAX_PROJECTED_SVID_CERT_FILE_BYTES),
            ("key.pem", MAX_PROJECTED_SVID_KEY_FILE_BYTES),
            ("bundle.pem", MAX_PROJECTED_SVID_BUNDLE_FILE_BYTES),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, vec![b'x'; maximum]).expect("write exact-bound file");
            assert_eq!(
                read_bounded_file(&path, maximum)
                    .await
                    .expect("exact file bound")
                    .len(),
                maximum
            );
            fs::write(&path, vec![b'x'; maximum + 1]).expect("write over-bound file");
            assert_eq!(
                read_bounded_file(&path, maximum).await,
                Err(ProjectedSvidReloadReason::MaterialFileTooLarge)
            );
        }

        let mut budget = MaterialBudget::default();
        assert!(budget.add(MAX_PROJECTED_SVID_TOTAL_BYTES).is_ok());
        assert_eq!(
            budget.add(1),
            Err(ProjectedSvidReloadReason::TotalMaterialTooLarge)
        );
    }

    #[tokio::test]
    async fn aggregate_material_limit_applies_before_candidate_parsing() {
        let directory = TestDirectory::new("aggregate-bound");
        let generation = directory.path().join("..gen-a");
        fs::create_dir_all(&generation).expect("create aggregate generation");
        fs::write(
            generation.join(CERT_FILE),
            vec![b'x'; MAX_PROJECTED_SVID_CERT_FILE_BYTES],
        )
        .expect("write exact-size certificate file");
        fs::write(
            generation.join(KEY_FILE),
            vec![b'x'; MAX_PROJECTED_SVID_KEY_FILE_BYTES],
        )
        .expect("write exact-size private-key file");
        let bundle_files = (0..3)
            .map(|index| PathBuf::from(format!("bundle-{index}.pem")))
            .collect::<Vec<_>>();
        for bundle_file in &bundle_files {
            fs::write(
                generation.join(bundle_file),
                vec![b'x'; MAX_PROJECTED_SVID_BUNDLE_FILE_BYTES],
            )
            .expect("write exact-size bundle file");
        }
        switch_generation(directory.path(), "..gen-a");
        let aggregate_config = ProjectedSvidConfig {
            root: directory.path().to_path_buf(),
            cert_file: PathBuf::from(CERT_FILE),
            key_file: PathBuf::from(KEY_FILE),
            bundle_files,
            poll_interval: MIN_PROJECTED_SVID_POLL_INTERVAL,
        };

        assert!(matches!(
            load_projected_generation(&aggregate_config, &NoopReadObserver).await,
            Err(ProjectedSvidReloadReason::TotalMaterialTooLarge)
        ));
    }

    #[test]
    fn parsed_certificate_and_anchor_counts_accept_exact_and_reject_one_over() {
        let material = valid_material(SPIFFE_A);
        let mut exact_chain = material.cert_chain_pem.clone();
        exact_chain.push_str(
            &material
                .bundle_pem
                .repeat(MAX_PROJECTED_SVID_CERTIFICATES - 2),
        );
        assert_eq!(
            parse_bounded_certificate_chain(exact_chain.as_bytes())
                .expect("exact certificate count")
                .len(),
            MAX_PROJECTED_SVID_CERTIFICATES
        );
        exact_chain.push_str(&material.bundle_pem);
        assert_eq!(
            parse_bounded_certificate_chain(exact_chain.as_bytes()),
            Err(ProjectedSvidReloadReason::CertificateCountExceeded)
        );

        let mut exact_anchors = material.bundle_pem.repeat(MAX_PROJECTED_SVID_TRUST_ANCHORS);
        assert_eq!(
            parse_bounded_trust_bundle(exact_anchors.as_bytes())
                .expect("exact trust-anchor count")
                .len(),
            MAX_PROJECTED_SVID_TRUST_ANCHORS
        );
        exact_anchors.push_str(&material.bundle_pem);
        assert_eq!(
            parse_bounded_trust_bundle(exact_anchors.as_bytes()),
            Err(ProjectedSvidReloadReason::TrustAnchorCountExceeded)
        );
    }

    #[tokio::test]
    async fn generation_swap_at_every_read_phase_retries_without_mixing_material() {
        let phases = [
            ProjectedReadPhase::GenerationResolved,
            ProjectedReadPhase::CertificateRead,
            ProjectedReadPhase::PrivateKeyRead,
            ProjectedReadPhase::TrustBundleRead(0),
            ProjectedReadPhase::TrustBundleRead(1),
            ProjectedReadPhase::BeforeFinalCheck,
        ];
        for (index, phase) in phases.into_iter().enumerate() {
            let directory = TestDirectory::new(&format!("phase-{index}"));
            let material_a = valid_material(SPIFFE_A);
            let material_b = valid_material(SPIFFE_B);
            let generation_a = write_generation(directory.path(), "..gen-a", &material_a);
            let generation_b = write_generation(directory.path(), "..gen-b", &material_b);
            fs::write(
                generation_a.join(SECOND_BUNDLE_FILE),
                &material_a.bundle_pem,
            )
            .expect("write second generation-A bundle");
            fs::write(
                generation_b.join(SECOND_BUNDLE_FILE),
                &material_b.bundle_pem,
            )
            .expect("write second generation-B bundle");
            switch_generation(directory.path(), "..gen-a");
            let observer = SwapOnceObserver {
                root: directory.path().to_path_buf(),
                target: "..gen-b",
                phase,
                swapped: AtomicBool::new(false),
            };
            let mut phase_config = config(directory.path());
            phase_config
                .bundle_files
                .push(PathBuf::from(SECOND_BUNDLE_FILE));

            let loaded = load_projected_generation(&phase_config, &observer)
                .await
                .expect("retry coherent generation");
            assert!(observer.swapped.load(Ordering::SeqCst));
            assert_eq!(loaded.target, PathBuf::from("..gen-b"));
            assert_eq!(loaded.state.identity.spiffe_id.as_str(), SPIFFE_B);
        }
    }

    #[tokio::test]
    async fn generation_retry_count_is_exactly_bounded() {
        let directory = TestDirectory::new("retry-bound");
        write_generation(directory.path(), "..gen-a", &valid_material(SPIFFE_A));
        write_generation(directory.path(), "..gen-b", &valid_material(SPIFFE_B));
        switch_generation(directory.path(), "..gen-a");
        let observer = SwapEveryAttemptObserver {
            root: directory.path().to_path_buf(),
            attempts: AtomicUsize::new(0),
        };

        assert!(matches!(
            load_projected_generation(&config(directory.path()), &observer).await,
            Err(ProjectedSvidReloadReason::GenerationRetryLimit)
        ));
        assert_eq!(
            observer.attempts.load(Ordering::SeqCst),
            MAX_PROJECTED_SVID_GENERATION_RETRIES + 1
        );
    }

    #[tokio::test]
    async fn invalid_generation_and_material_symlinks_fail_closed() {
        let directory = TestDirectory::new("unsafe-links");
        let outside = TestDirectory::new("outside");
        write_generation(outside.path(), "..outside", &valid_material(SPIFFE_A));
        symlink(
            outside.path().join("..outside"),
            directory.path().join(DATA_SYMLINK),
        )
        .expect("absolute ..data link");
        assert!(matches!(
            load_projected_generation(&config(directory.path()), &NoopReadObserver).await,
            Err(ProjectedSvidReloadReason::InvalidGenerationLink)
        ));

        fs::remove_file(directory.path().join(DATA_SYMLINK)).expect("remove invalid link");
        let material = valid_material(SPIFFE_A);
        let generation = write_generation(directory.path(), "..gen-a", &material);
        fs::remove_file(generation.join(KEY_FILE)).expect("remove key file");
        symlink(
            outside.path().join("..outside").join(KEY_FILE),
            generation.join(KEY_FILE),
        )
        .expect("material symlink");
        switch_generation(directory.path(), "..gen-a");
        assert!(matches!(
            load_projected_generation(&config(directory.path()), &NoopReadObserver).await,
            Err(ProjectedSvidReloadReason::MaterialNotRegular)
        ));
    }

    #[tokio::test]
    async fn rejected_candidates_retain_the_exact_last_good_state() {
        let directory = TestDirectory::new("rejections");
        let (ca, ca_key) = test_ca("stable CA");
        let initial_material = material_signed_by(SPIFFE_A, &ca, &ca_key, None);
        write_generation(directory.path(), "..good", &initial_material);
        switch_generation(directory.path(), "..good");
        let source = source(directory.path());
        let initial = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("initial projected identity");
        let mut retained_state_rx = source.subscribe();
        drop(retained_state_rx.borrow_and_update());
        let mut event_rx = source.subscribe_events();
        assert_eq!(source.status().generation(), 1);

        let malformed = TestMaterial {
            cert_chain_pem: "not PEM".to_string(),
            private_key_pem: initial_material.private_key_pem.clone(),
            bundle_pem: initial_material.bundle_pem.clone(),
        };
        write_generation(directory.path(), "..malformed", &malformed);
        switch_generation(directory.path(), "..malformed");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MalformedCertificate)
        })
        .await;
        wait_for_failure_event(
            &mut event_rx,
            ProjectedSvidReloadReason::MalformedCertificate,
        )
        .await;
        assert!(
            timeout(Duration::from_millis(25), retained_state_rx.changed())
                .await
                .is_err(),
            "a rejected candidate must not republish the retained state"
        );
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let malformed_key = TestMaterial {
            cert_chain_pem: initial_material.cert_chain_pem.clone(),
            private_key_pem: "not a private key".to_string(),
            bundle_pem: initial_material.bundle_pem.clone(),
        };
        write_generation(directory.path(), "..malformed-key", &malformed_key);
        switch_generation(directory.path(), "..malformed-key");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MalformedPrivateKey)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let malformed_bundle = TestMaterial {
            cert_chain_pem: initial_material.cert_chain_pem.clone(),
            private_key_pem: initial_material.private_key_pem.clone(),
            bundle_pem: "not a trust bundle".to_string(),
        };
        write_generation(directory.path(), "..malformed-bundle", &malformed_bundle);
        switch_generation(directory.path(), "..malformed-bundle");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MalformedTrustBundle)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let incomplete = directory.path().join("..incomplete");
        fs::create_dir_all(&incomplete).expect("incomplete generation");
        fs::write(incomplete.join(CERT_FILE), &initial_material.cert_chain_pem)
            .expect("incomplete cert");
        fs::write(incomplete.join(BUNDLE_FILE), &initial_material.bundle_pem)
            .expect("incomplete bundle");
        switch_generation(directory.path(), "..incomplete");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MaterialUnavailable)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let oversized = directory.path().join("..oversized");
        fs::create_dir_all(&oversized).expect("oversized generation");
        fs::write(
            oversized.join(CERT_FILE),
            vec![b'x'; MAX_PROJECTED_SVID_CERT_FILE_BYTES + 1],
        )
        .expect("oversized cert");
        fs::write(oversized.join(KEY_FILE), &initial_material.private_key_pem)
            .expect("oversized key");
        fs::write(oversized.join(BUNDLE_FILE), &initial_material.bundle_pem)
            .expect("oversized bundle");
        switch_generation(directory.path(), "..oversized");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MaterialFileTooLarge)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let valid_second = material_signed_by(SPIFFE_B, &ca, &ca_key, None);
        let wrong_key = TestMaterial {
            cert_chain_pem: valid_second.cert_chain_pem.clone(),
            private_key_pem: initial_material.private_key_pem.clone(),
            bundle_pem: valid_second.bundle_pem.clone(),
        };
        write_generation(directory.path(), "..wrong-key", &wrong_key);
        switch_generation(directory.path(), "..wrong-key");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::PrivateKeyMismatch)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let wrong_chain_material = valid_material(SPIFFE_B);
        let wrong_chain = TestMaterial {
            cert_chain_pem: wrong_chain_material.cert_chain_pem,
            private_key_pem: wrong_chain_material.private_key_pem,
            bundle_pem: initial_material.bundle_pem.clone(),
        };
        write_generation(directory.path(), "..wrong-chain", &wrong_chain);
        switch_generation(directory.path(), "..wrong-chain");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::InvalidCertificateChain)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let now = time::OffsetDateTime::now_utc();
        let expired = material_signed_by(
            SPIFFE_B,
            &ca,
            &ca_key,
            Some((
                now - time::Duration::hours(2),
                now - time::Duration::hours(1),
            )),
        );
        write_generation(directory.path(), "..expired", &expired);
        switch_generation(directory.path(), "..expired");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::ExpiredSvid)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let not_yet_valid = material_signed_by(
            SPIFFE_B,
            &ca,
            &ca_key,
            Some((
                now + time::Duration::hours(1),
                now + time::Duration::hours(2),
            )),
        );
        write_generation(directory.path(), "..future", &not_yet_valid);
        switch_generation(directory.path(), "..future");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::NotYetValidSvid)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );

        let io_failure = directory.path().join("..io-failure");
        fs::create_dir_all(&io_failure).expect("I/O failure generation");
        fs::write(io_failure.join(CERT_FILE), &initial_material.cert_chain_pem)
            .expect("I/O failure cert");
        fs::write(io_failure.join(KEY_FILE), &initial_material.private_key_pem)
            .expect("I/O failure key");
        fs::create_dir(io_failure.join(BUNDLE_FILE)).expect("bundle directory");
        switch_generation(directory.path(), "..io-failure");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MaterialNotRegular)
        })
        .await;
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("retained identity"),
        );
        assert_eq!(source.status().generation(), 1);
        assert_eq!(
            source.status().availability(),
            ProjectedSvidAvailability::RetainingLastGood
        );

        switch_generation(directory.path(), "..good");
        let rollback_status = wait_for_status(&source, |status| {
            status.generation() == 2 && status.availability() == ProjectedSvidAvailability::Ready
        })
        .await;
        assert_eq!(rollback_status.reason(), None);
        assert_identity_bytes_equal(
            &initial,
            &source
                .subscribe()
                .borrow()
                .clone()
                .expect("republished rollback identity"),
        );
    }

    #[tokio::test]
    async fn rollback_republishes_prior_material_with_a_new_monotonic_generation() {
        let directory = TestDirectory::new("rollback");
        let material_a = valid_material(SPIFFE_A);
        let material_b = valid_material(SPIFFE_B);
        write_generation(directory.path(), "..gen-a", &material_a);
        write_generation(directory.path(), "..gen-b", &material_b);
        switch_generation(directory.path(), "..gen-a");
        let source = source(directory.path());
        let state_a = source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("first generation");
        assert_eq!(source.status().generation(), 1);

        switch_generation(directory.path(), "..gen-b");
        let status_b = wait_for_status(&source, |status| {
            status.generation() == 2 && status.availability() == ProjectedSvidAvailability::Ready
        })
        .await;
        assert_eq!(status_b.reason(), None);
        assert_eq!(
            source
                .subscribe()
                .borrow()
                .as_ref()
                .expect("second identity")
                .identity
                .spiffe_id
                .as_str(),
            SPIFFE_B
        );

        switch_generation(directory.path(), "..gen-a");
        let status_rollback = wait_for_status(&source, |status| {
            status.generation() == 3 && status.availability() == ProjectedSvidAvailability::Ready
        })
        .await;
        assert_eq!(status_rollback.reason(), None);
        let rolled_back = source
            .subscribe()
            .borrow()
            .clone()
            .expect("rolled-back identity");
        assert_identity_bytes_equal(&state_a, &rolled_back);
    }

    #[tokio::test]
    async fn expired_last_good_is_cleared_and_reported_unavailable() {
        let directory = TestDirectory::new("expiry");
        write_generation(directory.path(), "..gen-a", &valid_material(SPIFFE_A));
        switch_generation(directory.path(), "..gen-a");
        let mut loaded = load_projected_generation(&config(directory.path()), &NoopReadObserver)
            .await
            .expect("valid identity")
            .state;
        let expired = Timestamp::now_utc();
        loaded.identity.expires_at = expired;
        loaded.svid.expires_at = expired;

        let (state_tx, mut state_rx) = watch::channel(Some(loaded));
        let (status_tx, status_rx) = watch::channel(ProjectedSvidReloadStatus {
            generation: 7,
            availability: ProjectedSvidAvailability::RetainingLastGood,
            reason: Some(ProjectedSvidReloadReason::MalformedCertificate),
        });
        let (event_tx, _) = broadcast::channel(4);
        let handle =
            spawn_projected_expiry_monitor(state_tx, status_tx, event_tx, Arc::new(Mutex::new(())));
        timeout(Duration::from_secs(1), async {
            loop {
                if state_rx.borrow().is_none() {
                    break;
                }
                state_rx.changed().await.expect("expiry state sender");
            }
        })
        .await
        .expect("expiry monitor deadline");
        assert_eq!(
            *status_rx.borrow(),
            ProjectedSvidReloadStatus {
                generation: 7,
                availability: ProjectedSvidAvailability::Unavailable,
                reason: Some(ProjectedSvidReloadReason::LastGoodExpired),
            }
        );
        handle.abort();
    }

    #[tokio::test]
    async fn candidate_failures_cannot_replace_an_expired_last_good_reason() {
        let directory = TestDirectory::new("expiry-failure-race");
        write_generation(directory.path(), "..gen-a", &valid_material(SPIFFE_A));
        switch_generation(directory.path(), "..gen-a");
        let mut loaded = load_projected_generation(&config(directory.path()), &NoopReadObserver)
            .await
            .expect("valid identity")
            .state;
        let expired = Timestamp::now_utc();
        loaded.identity.expires_at = expired;
        loaded.svid.expires_at = expired;

        let (state_tx, state_rx) = watch::channel(Some(loaded));
        let (status_tx, status_rx) = watch::channel(ProjectedSvidReloadStatus {
            generation: 11,
            availability: ProjectedSvidAvailability::Ready,
            reason: None,
        });
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let publication_guard = Mutex::new(());

        publish_failure(
            ProjectedSvidReloadReason::MalformedCertificate,
            &state_tx,
            &status_tx,
            &event_tx,
            &publication_guard,
        )
        .await;
        assert!(state_rx.borrow().is_none());
        assert_eq!(
            *status_rx.borrow(),
            ProjectedSvidReloadStatus {
                generation: 11,
                availability: ProjectedSvidAvailability::Unavailable,
                reason: Some(ProjectedSvidReloadReason::LastGoodExpired),
            }
        );
        assert!(matches!(
            event_rx.try_recv(),
            Ok(IdentityReloadEvent::Failure { error })
                if error == ProjectedSvidReloadReason::LastGoodExpired.as_str()
        ));

        publish_failure(
            ProjectedSvidReloadReason::MaterialUnavailable,
            &state_tx,
            &status_tx,
            &event_tx,
            &publication_guard,
        )
        .await;
        assert_eq!(
            status_rx.borrow().reason(),
            Some(ProjectedSvidReloadReason::LastGoodExpired)
        );
    }

    #[tokio::test]
    async fn typed_status_and_compatibility_events_never_expose_secret_controlled_text() {
        let directory = TestDirectory::new("do-not-leak-super-secret-path");
        let material = valid_material(SPIFFE_A);
        write_generation(directory.path(), "..gen-a", &material);
        switch_generation(directory.path(), "..gen-a");
        let source = source(directory.path());
        source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("initial identity");
        let mut events = source.subscribe_events();

        let secret_marker = "private-secret-marker";
        let malformed = TestMaterial {
            cert_chain_pem: secret_marker.to_string(),
            private_key_pem: secret_marker.to_string(),
            bundle_pem: secret_marker.to_string(),
        };
        write_generation(directory.path(), "..secret-candidate", &malformed);
        switch_generation(directory.path(), "..secret-candidate");
        wait_for_status(&source, |status| {
            status.reason() == Some(ProjectedSvidReloadReason::MalformedCertificate)
        })
        .await;
        let event = timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("event timeout")
            .expect("failure event");
        let status_debug = format!("{:?}", source.status());
        let event_debug = format!("{event:?}");
        for forbidden in [
            secret_marker,
            "do-not-leak-super-secret-path",
            SPIFFE_A,
            directory.path().to_str().expect("UTF-8 test path"),
        ] {
            assert!(!status_debug.contains(forbidden));
            assert!(!event_debug.contains(forbidden));
        }
        assert!(matches!(
            event,
            IdentityReloadEvent::Failure { ref error }
                if error == ProjectedSvidReloadReason::MalformedCertificate.as_str()
        ));
    }

    #[test]
    fn status_codes_are_stable_and_redaction_safe() {
        assert_eq!(ProjectedSvidAvailability::Ready.as_str(), "ready");
        assert_eq!(
            ProjectedSvidReloadReason::GenerationRetryLimit.as_str(),
            "generation_retry_limit"
        );
        assert_eq!(
            ProjectedSvidReloadReason::PrivateKeyMismatch.to_string(),
            "private_key_mismatch"
        );
        assert_eq!(
            ProjectedSvidReloadReason::ReadAttemptTimeout.as_str(),
            "read_attempt_timeout"
        );
        let status = ProjectedSvidReloadStatus::initial();
        assert_eq!(status.generation(), 0);
        assert_eq!(
            status.availability(),
            ProjectedSvidAvailability::Initializing
        );
        assert_eq!(
            status.reason(),
            Some(ProjectedSvidReloadReason::AwaitingInitialMaterial)
        );
    }

    #[test]
    fn source_handles_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProjectedSvidSource>();
        assert_send_sync::<Arc<ProjectedSvidSource>>();
    }
}
