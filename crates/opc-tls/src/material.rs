//! Coherent, bounded TLS material epochs for individual handshakes.

use opc_identity::projected_svid::ProjectedSvidControllerPublication;
use opc_identity::{
    build_identity_state, IdentityReloadError, IdentityState, ProjectedSvidControllerClaimError,
    ProjectedSvidSource,
};
use opc_redaction::metrics::{
    SecurityMetricsAcceptance, SecurityMetricsController, SecurityMetricsPublication,
    SecurityRotationKind,
};
use opc_types::{SpiffeId, Timestamp};
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::CertificateDer;
use serde::Serialize;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::runtime::Handle;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

/// Maximum certificate count accepted in one local SVID chain.
pub const MAX_TLS_MATERIAL_CHAIN_CERTIFICATES: usize = 16;
/// Maximum number of trust-domain bundles accepted in one snapshot.
pub const MAX_TLS_MATERIAL_TRUST_BUNDLES: usize = 16;
/// Maximum aggregate trust-anchor count accepted in one snapshot.
pub const MAX_TLS_MATERIAL_TRUST_ANCHORS: usize = 128;
/// Maximum private-key bytes accepted in one snapshot.
pub const MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES: usize = 64 * 1024;
/// Maximum aggregate certificate, private-key, and bundle-metadata bytes.
pub const MAX_TLS_MATERIAL_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Number of epoch-change retries permitted after the initial handshake attempt.
pub const MAX_TLS_HANDSHAKE_EPOCH_RETRIES: usize = 2;
/// Maximum controller-owned bounded handshake operations in flight.
pub const MAX_TLS_CONCURRENT_HANDSHAKES: usize = 128;

/// Opaque, process-local TLS material publication epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TlsMaterialEpoch(u64);

impl TlsMaterialEpoch {
    const INITIAL: Self = Self(0);

    /// Numeric process-local value for status correlation.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Availability of coherent TLS material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialAvailability {
    /// The controller has not accepted material yet.
    Initializing,
    /// A coherent, unexpired snapshot is available.
    Ready,
    /// A candidate failed while the prior unexpired snapshot remains usable.
    RetainingLastGood,
    /// No coherent, unexpired snapshot is available.
    Unavailable,
}

impl TlsMaterialAvailability {
    /// Stable low-cardinality representation for metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::RetainingLastGood => "retaining_last_good",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Closed, redaction-safe TLS material outcome reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialReloadReason {
    /// No source value has been observed yet.
    AwaitingInitialMaterial,
    /// The identity source has no current value.
    MaterialUnavailable,
    /// The identity source sender closed.
    SourceClosed,
    /// The candidate exceeded a fixed count or byte bound.
    MaterialLimitExceeded,
    /// The candidate certificate chain was invalid for its trust bundle.
    InvalidCertificateChain,
    /// The candidate private key did not match its leaf certificate.
    PrivateKeyMismatch,
    /// The candidate was already expired.
    ExpiredMaterial,
    /// The candidate was not yet valid.
    NotYetValidMaterial,
    /// The candidate workload identity was invalid or internally inconsistent.
    InvalidWorkloadIdentity,
    /// The candidate changed the controller's pinned local SPIFFE identity.
    LocalIdentityChanged,
    /// The last accepted snapshot reached its effective certificate-chain
    /// expiry boundary.
    LastGoodExpired,
    /// The process-local epoch counter could not advance.
    EpochExhausted,
}

impl TlsMaterialReloadReason {
    /// Every closed reason, for exhaustive fixed-cardinality handling.
    pub const ALL: [Self; 12] = [
        Self::AwaitingInitialMaterial,
        Self::MaterialUnavailable,
        Self::SourceClosed,
        Self::MaterialLimitExceeded,
        Self::InvalidCertificateChain,
        Self::PrivateKeyMismatch,
        Self::ExpiredMaterial,
        Self::NotYetValidMaterial,
        Self::InvalidWorkloadIdentity,
        Self::LocalIdentityChanged,
        Self::LastGoodExpired,
        Self::EpochExhausted,
    ];

    /// Stable low-cardinality representation for events and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingInitialMaterial => "awaiting_initial_material",
            Self::MaterialUnavailable => "material_unavailable",
            Self::SourceClosed => "source_closed",
            Self::MaterialLimitExceeded => "material_limit_exceeded",
            Self::InvalidCertificateChain => "invalid_certificate_chain",
            Self::PrivateKeyMismatch => "private_key_mismatch",
            Self::ExpiredMaterial => "expired_material",
            Self::NotYetValidMaterial => "not_yet_valid_material",
            Self::InvalidWorkloadIdentity => "invalid_workload_identity",
            Self::LocalIdentityChanged => "local_identity_changed",
            Self::LastGoodExpired => "last_good_expired",
            Self::EpochExhausted => "epoch_exhausted",
        }
    }
}

impl fmt::Display for TlsMaterialReloadReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Redaction-safe status published by [`TlsMaterialController`].
///
/// This is the authoritative TLS-handshake availability status: the
/// controller validates every certificate it will present. An upstream
/// identity-source status describes source acquisition and is not a substitute
/// for this admission status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsMaterialStatus {
    epoch: TlsMaterialEpoch,
    availability: TlsMaterialAvailability,
    reason: Option<TlsMaterialReloadReason>,
    leaf_expires_at: Option<Timestamp>,
    certificate_chain_expires_at: Option<Timestamp>,
}

impl TlsMaterialStatus {
    const fn initial() -> Self {
        Self {
            epoch: TlsMaterialEpoch::INITIAL,
            availability: TlsMaterialAvailability::Initializing,
            reason: Some(TlsMaterialReloadReason::AwaitingInitialMaterial),
            leaf_expires_at: None,
            certificate_chain_expires_at: None,
        }
    }

    /// Latest successfully published epoch, or zero before first publication.
    pub const fn epoch(self) -> TlsMaterialEpoch {
        self.epoch
    }

    /// Current controller availability.
    pub const fn availability(self) -> TlsMaterialAvailability {
        self.availability
    }

    /// Closed reason for the latest non-ready state.
    pub const fn reason(self) -> Option<TlsMaterialReloadReason> {
        self.reason
    }

    /// Leaf expiry for the retained snapshot, when one is available.
    pub const fn leaf_expires_at(self) -> Option<Timestamp> {
        self.leaf_expires_at
    }

    /// Earliest expiry across the retained presented certificate chain.
    pub const fn certificate_chain_expires_at(self) -> Option<Timestamp> {
        self.certificate_chain_expires_at
    }
}

/// Failure to begin or admit a coherent TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TlsMaterialError {
    /// No unexpired coherent snapshot is available.
    #[error("TLS material is unavailable")]
    Unavailable,
    /// The controller advanced while this handshake or application negotiation ran.
    #[error("TLS material epoch changed during handshake")]
    EpochChanged,
    /// Every bounded retry observed another material epoch change.
    #[error("TLS material epoch retry limit exhausted")]
    EpochRetryLimit,
    /// A fixed rustls configuration could not be built.
    #[error("TLS material configuration failed")]
    Configuration,
}

impl TlsMaterialError {
    /// Stable low-cardinality representation for transport metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "material_unavailable",
            Self::EpochChanged => "epoch_changed",
            Self::EpochRetryLimit => "epoch_retry_limit",
            Self::Configuration => "configuration_failed",
        }
    }
}

#[derive(Clone)]
pub(crate) struct TlsMaterialSnapshot {
    epoch: TlsMaterialEpoch,
    leaf_expires_at: Timestamp,
    certificate_chain_expires_at: Timestamp,
    pub(crate) state: Arc<IdentityState>,
    metrics_publication: Option<SecurityMetricsPublication>,
}

impl TlsMaterialSnapshot {
    pub(crate) fn epoch(&self) -> TlsMaterialEpoch {
        self.epoch
    }

    pub(crate) fn leaf_expires_at(&self) -> Timestamp {
        self.leaf_expires_at
    }

    pub(crate) fn certificate_chain_expires_at(&self) -> Timestamp {
        self.certificate_chain_expires_at
    }
}

impl fmt::Debug for TlsMaterialSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsMaterialSnapshot")
            .field("epoch", &self.epoch)
            .field("leaf_expires_at", &self.leaf_expires_at)
            .field(
                "certificate_chain_expires_at",
                &self.certificate_chain_expires_at,
            )
            .finish_non_exhaustive()
    }
}

struct ControllerState {
    pinned_spiffe_id: Option<SpiffeId>,
    snapshot: Option<TlsMaterialSnapshot>,
    source_closed_reported: bool,
}

struct ControllerInner {
    source_rx: Mutex<MaterialSourceReceiver>,
    builder_rx: watch::Receiver<Option<IdentityState>>,
    state: Mutex<ControllerState>,
    status_tx: watch::Sender<TlsMaterialStatus>,
    handshake_gate: Arc<Semaphore>,
    metrics: Option<SecurityMetricsController>,
    reconciliation_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
enum MaterialSourceReceiver {
    Generic(watch::Receiver<Option<IdentityState>>),
    Projected(watch::Receiver<Option<ProjectedSvidControllerPublication>>),
}

impl MaterialSourceReceiver {
    async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        match self {
            Self::Generic(receiver) => receiver.changed().await,
            Self::Projected(receiver) => receiver.changed().await,
        }
    }
}

impl Drop for ControllerInner {
    fn drop(&mut self) {
        let task = self
            .reconciliation_task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            task.abort();
        }
    }
}

/// Shared coherent TLS material authority for new handshakes.
///
/// The controller consumes already parsed identity state, revalidates it under
/// fixed count/byte bounds, pins the local SPIFFE identity, and publishes an
/// immutable snapshot for each accepted update. Clones share one epoch and pin.
#[derive(Clone)]
pub struct TlsMaterialController {
    inner: Arc<ControllerInner>,
}

/// Opaque event-driven subscription to coherent material publications.
///
/// The receiver exposes only the redaction-safe status. Source identity,
/// certificate and key material never cross this boundary.
#[derive(Clone)]
pub struct TlsMaterialStatusReceiver {
    controller: TlsMaterialController,
    source_rx: MaterialSourceReceiver,
}

impl TlsMaterialStatusReceiver {
    /// Wait for a source publication, reconcile it, and return safe status.
    pub async fn changed(&mut self) -> Result<TlsMaterialStatus, watch::error::RecvError> {
        if let Err(closed) = self.source_rx.changed().await {
            let _ = self.controller.status();
            return Err(closed);
        }
        Ok(self.controller.status())
    }

    /// Current reconciled redaction-safe status.
    pub fn status(&self) -> TlsMaterialStatus {
        self.controller.status()
    }
}

impl fmt::Debug for TlsMaterialStatusReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsMaterialStatusReceiver([redacted])")
    }
}

impl TlsMaterialController {
    /// Create a controller that pins the first accepted local SPIFFE identity.
    ///
    /// Use [`Self::new_from_projected_source`] for a
    /// [`ProjectedSvidSource`]; that constructor pairs the exact channel and
    /// telemetry authority and owns background reconciliation. Generic
    /// controllers remain compatible but never mutate process-wide security
    /// evidence.
    pub fn new(source_rx: watch::Receiver<Option<IdentityState>>) -> Self {
        Self::new_with_optional_pin(
            MaterialSourceReceiver::Generic(source_rx.clone()),
            source_rx,
            None,
            None,
        )
    }

    /// Create a controller pinned to one explicit local SPIFFE identity.
    pub fn new_pinned(
        source_rx: watch::Receiver<Option<IdentityState>>,
        local_spiffe_id: SpiffeId,
    ) -> Self {
        Self::new_with_optional_pin(
            MaterialSourceReceiver::Generic(source_rx.clone()),
            source_rx,
            Some(local_spiffe_id),
            None,
        )
    }

    /// Claim one projected source as this controller's sole authority.
    ///
    /// The source records source failures, while this controller publishes
    /// accepted epochs and controller rejections. Either side's first
    /// observation of expiry for the active ticket may clear the expiry gauge
    /// under their shared lifecycle. The paired input prevents channel/recorder
    /// mismatch, and a background reconciliation task is owned by the controller
    /// rather than a droppable external monitor.
    pub fn new_from_projected_source(
        source: &ProjectedSvidSource,
    ) -> Result<Self, ProjectedSvidControllerClaimError> {
        Self::new_from_projected_source_with_optional_pin(source, None)
    }

    /// Claim one projected source and pin its expected local SPIFFE identity.
    pub fn new_pinned_from_projected_source(
        source: &ProjectedSvidSource,
        local_spiffe_id: SpiffeId,
    ) -> Result<Self, ProjectedSvidControllerClaimError> {
        Self::new_from_projected_source_with_optional_pin(source, Some(local_spiffe_id))
    }

    fn new_from_projected_source_with_optional_pin(
        source: &ProjectedSvidSource,
        pinned_spiffe_id: Option<SpiffeId>,
    ) -> Result<Self, ProjectedSvidControllerClaimError> {
        let builder_rx = source.subscribe();
        let (source_rx, metrics, runtime) = source.claim_tls_controller()?.into_parts();
        let controller = Self::new_with_optional_pin(
            MaterialSourceReceiver::Projected(source_rx),
            builder_rx,
            pinned_spiffe_id,
            Some(metrics),
        );
        controller.start_reconciliation_task(runtime);
        Ok(controller)
    }

    fn new_with_optional_pin(
        source_rx: MaterialSourceReceiver,
        builder_rx: watch::Receiver<Option<IdentityState>>,
        pinned_spiffe_id: Option<SpiffeId>,
        metrics: Option<SecurityMetricsController>,
    ) -> Self {
        let (status_tx, _) = watch::channel(TlsMaterialStatus::initial());
        let controller = Self {
            inner: Arc::new(ControllerInner {
                source_rx: Mutex::new(source_rx),
                builder_rx,
                state: Mutex::new(ControllerState {
                    pinned_spiffe_id,
                    snapshot: None,
                    source_closed_reported: false,
                }),
                status_tx,
                handshake_gate: Arc::new(Semaphore::new(MAX_TLS_CONCURRENT_HANDSHAKES)),
                metrics,
                reconciliation_task: Mutex::new(None),
            }),
        };
        controller.refresh_initial();
        controller
    }

    fn start_reconciliation_task(&self, runtime: Handle) {
        let mut source_changes = self.material_source_receiver();
        let weak = Arc::downgrade(&self.inner);
        let task = runtime.spawn(async move {
            loop {
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                TlsMaterialController { inner }.status();

                if source_changes.changed().await.is_err() {
                    if let Some(inner) = weak.upgrade() {
                        TlsMaterialController { inner }.status();
                    }
                    break;
                }
            }
        });
        *lock_unpoisoned(&self.inner.reconciliation_task) = Some(task);
    }

    /// Return the current redaction-safe status after reconciling source changes.
    pub fn status(&self) -> TlsMaterialStatus {
        self.refresh();
        *self.inner.status_tx.borrow()
    }

    /// Subscribe to status changes driven by snapshot/status access.
    pub fn subscribe_status(&self) -> watch::Receiver<TlsMaterialStatus> {
        self.refresh();
        self.inner.status_tx.subscribe()
    }

    /// Subscribe to source-driven changes while exposing safe status only.
    pub fn subscribe_material_changes(&self) -> TlsMaterialStatusReceiver {
        TlsMaterialStatusReceiver {
            controller: self.clone(),
            source_rx: self.material_source_receiver(),
        }
    }

    fn material_source_receiver(&self) -> MaterialSourceReceiver {
        lock_unpoisoned(&self.inner.source_rx).clone()
    }

    pub(crate) fn source_receiver(&self) -> watch::Receiver<Option<IdentityState>> {
        self.inner.builder_rx.clone()
    }

    pub(crate) fn snapshot(&self) -> Result<TlsMaterialSnapshot, TlsMaterialError> {
        self.refresh();
        lock_unpoisoned(&self.inner.state)
            .snapshot
            .clone()
            .ok_or(TlsMaterialError::Unavailable)
    }

    pub(crate) fn admit(
        &self,
        snapshot: &TlsMaterialSnapshot,
    ) -> Result<TlsAdmittedConnection, TlsMaterialError> {
        self.refresh();
        let state = lock_unpoisoned(&self.inner.state);
        let current = state
            .snapshot
            .as_ref()
            .ok_or(TlsMaterialError::Unavailable)?;
        if current.epoch != snapshot.epoch {
            return Err(TlsMaterialError::EpochChanged);
        }
        Ok(TlsAdmittedConnection {
            epoch: snapshot.epoch,
            leaf_expires_at: snapshot.leaf_expires_at,
            certificate_chain_expires_at: snapshot.certificate_chain_expires_at,
        })
    }

    pub(crate) async fn acquire_handshake(&self) -> Result<OwnedSemaphorePermit, TlsMaterialError> {
        self.inner
            .handshake_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TlsMaterialError::Unavailable)
    }

    fn refresh_initial(&self) {
        let mut source_rx = lock_unpoisoned(&self.inner.source_rx);
        match &mut *source_rx {
            MaterialSourceReceiver::Generic(receiver) => {
                let candidate = receiver.borrow_and_update();
                self.apply_candidate(candidate.as_ref(), None);
            }
            MaterialSourceReceiver::Projected(receiver) => {
                let candidate = receiver.borrow_and_update();
                self.apply_candidate(
                    candidate
                        .as_ref()
                        .map(ProjectedSvidControllerPublication::identity_state),
                    candidate
                        .as_ref()
                        .map(ProjectedSvidControllerPublication::metrics_publication),
                );
            }
        }
    }

    fn refresh(&self) {
        let mut source_rx = lock_unpoisoned(&self.inner.source_rx);
        match &mut *source_rx {
            MaterialSourceReceiver::Generic(receiver) => match receiver.has_changed() {
                Ok(true) => {
                    let candidate = receiver.borrow_and_update();
                    self.apply_candidate(candidate.as_ref(), None);
                }
                Ok(false) => self.expire_if_needed(),
                Err(_) => self.report_source_closed(),
            },
            MaterialSourceReceiver::Projected(receiver) => match receiver.has_changed() {
                Ok(true) => {
                    let candidate = receiver.borrow_and_update();
                    self.apply_candidate(
                        candidate
                            .as_ref()
                            .map(ProjectedSvidControllerPublication::identity_state),
                        candidate
                            .as_ref()
                            .map(ProjectedSvidControllerPublication::metrics_publication),
                    );
                }
                Ok(false) => self.expire_if_needed(),
                Err(_) => self.report_source_closed(),
            },
        }
    }

    fn apply_candidate(
        &self,
        candidate: Option<&IdentityState>,
        metrics_publication: Option<&SecurityMetricsPublication>,
    ) {
        let mut controller = lock_unpoisoned(&self.inner.state);
        expire_locked(
            &mut controller,
            &self.inner.status_tx,
            self.inner.metrics.as_ref(),
        );

        let Some(candidate) = candidate else {
            publish_rejection(
                &controller,
                &self.inner.status_tx,
                self.inner.metrics.as_ref(),
                TlsMaterialReloadReason::MaterialUnavailable,
            );
            return;
        };
        let (validated, certificate_chain_expires_at) = match validate_candidate(candidate) {
            Ok(validated) => validated,
            Err(reason) => {
                publish_rejection(
                    &controller,
                    &self.inner.status_tx,
                    self.inner.metrics.as_ref(),
                    reason,
                );
                return;
            }
        };

        if let Some(pin) = controller.pinned_spiffe_id.as_ref() {
            if pin != &validated.identity.spiffe_id {
                publish_rejection(
                    &controller,
                    &self.inner.status_tx,
                    self.inner.metrics.as_ref(),
                    TlsMaterialReloadReason::LocalIdentityChanged,
                );
                return;
            }
        }

        let current_epoch = self.inner.status_tx.borrow().epoch;
        let Some(next_epoch) = current_epoch.0.checked_add(1).map(TlsMaterialEpoch) else {
            publish_rejection(
                &controller,
                &self.inner.status_tx,
                self.inner.metrics.as_ref(),
                TlsMaterialReloadReason::EpochExhausted,
            );
            return;
        };
        let leaf_expires_at = validated.identity.expires_at;
        let snapshot = TlsMaterialSnapshot {
            epoch: next_epoch,
            leaf_expires_at,
            certificate_chain_expires_at,
            state: Arc::new(validated),
            metrics_publication: metrics_publication.cloned(),
        };
        let status = TlsMaterialStatus {
            epoch: next_epoch,
            availability: TlsMaterialAvailability::Ready,
            reason: None,
            leaf_expires_at: Some(leaf_expires_at),
            certificate_chain_expires_at: Some(certificate_chain_expires_at),
        };
        let pin = snapshot.state.identity.spiffe_id.clone();
        match (self.inner.metrics.as_ref(), metrics_publication) {
            (Some(metrics), Some(publication)) => {
                // Lock order is ControllerState (held above), publication
                // lifecycle, then active registry. Once Ready, only infallible
                // field moves occur before commit; status is published after.
                let acceptance = metrics.prepare_success_if_active(
                    publication,
                    next_epoch.get(),
                    certificate_chain_expires_at
                        .as_offset_datetime()
                        .unix_timestamp(),
                );
                match acceptance {
                    SecurityMetricsAcceptance::Ready(permit) => {
                        if controller.pinned_spiffe_id.is_none() {
                            controller.pinned_spiffe_id = Some(pin);
                        }
                        controller.snapshot = Some(snapshot);
                        permit.commit();
                        self.inner.status_tx.send_replace(status);
                    }
                    SecurityMetricsAcceptance::AlreadyAccepted => {}
                    SecurityMetricsAcceptance::Expired => {
                        publish_expired_candidate(&controller, &self.inner.status_tx);
                    }
                    SecurityMetricsAcceptance::RegistryMismatch => {
                        publish_rejection(
                            &controller,
                            &self.inner.status_tx,
                            self.inner.metrics.as_ref(),
                            TlsMaterialReloadReason::MaterialUnavailable,
                        );
                    }
                }
            }
            (None, None) => {
                if controller.pinned_spiffe_id.is_none() {
                    controller.pinned_spiffe_id = Some(pin);
                }
                controller.snapshot = Some(snapshot);
                self.inner.status_tx.send_replace(status);
            }
            _ => {
                publish_rejection(
                    &controller,
                    &self.inner.status_tx,
                    self.inner.metrics.as_ref(),
                    TlsMaterialReloadReason::MaterialUnavailable,
                );
            }
        }
    }

    fn expire_if_needed(&self) {
        let mut controller = lock_unpoisoned(&self.inner.state);
        expire_locked(
            &mut controller,
            &self.inner.status_tx,
            self.inner.metrics.as_ref(),
        );
    }

    fn report_source_closed(&self) {
        let mut controller = lock_unpoisoned(&self.inner.state);
        expire_locked(
            &mut controller,
            &self.inner.status_tx,
            self.inner.metrics.as_ref(),
        );
        if controller.source_closed_reported {
            return;
        }
        controller.source_closed_reported = true;
        publish_rejection(
            &controller,
            &self.inner.status_tx,
            self.inner.metrics.as_ref(),
            TlsMaterialReloadReason::SourceClosed,
        );
    }
}

impl fmt::Debug for TlsMaterialController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsMaterialController([redacted])")
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn expire_locked(
    controller: &mut ControllerState,
    status_tx: &watch::Sender<TlsMaterialStatus>,
    metrics: Option<&SecurityMetricsController>,
) {
    let expired = controller
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.certificate_chain_expires_at <= Timestamp::now_utc());
    if !expired {
        return;
    }
    let metrics_publication = controller
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.metrics_publication.as_ref())
        .cloned();
    controller.snapshot = None;
    let epoch = status_tx.borrow().epoch;
    status_tx.send_replace(TlsMaterialStatus {
        epoch,
        availability: TlsMaterialAvailability::Unavailable,
        reason: Some(TlsMaterialReloadReason::LastGoodExpired),
        leaf_expires_at: None,
        certificate_chain_expires_at: None,
    });
    if let (Some(metrics), Some(publication)) = (metrics, metrics_publication.as_ref()) {
        metrics.record_expired_once(publication);
    }
}

fn publish_rejection(
    controller: &ControllerState,
    status_tx: &watch::Sender<TlsMaterialStatus>,
    metrics: Option<&SecurityMetricsController>,
    reason: TlsMaterialReloadReason,
) {
    let current = *status_tx.borrow();
    let retained = controller.snapshot.as_ref();
    let effective_reason =
        if retained.is_none() && current.reason == Some(TlsMaterialReloadReason::LastGoodExpired) {
            TlsMaterialReloadReason::LastGoodExpired
        } else {
            reason
        };
    status_tx.send_replace(TlsMaterialStatus {
        epoch: current.epoch,
        availability: if retained.is_some() {
            TlsMaterialAvailability::RetainingLastGood
        } else {
            TlsMaterialAvailability::Unavailable
        },
        reason: Some(effective_reason),
        leaf_expires_at: retained.map(TlsMaterialSnapshot::leaf_expires_at),
        certificate_chain_expires_at: retained
            .map(TlsMaterialSnapshot::certificate_chain_expires_at),
    });
    if reason == TlsMaterialReloadReason::LastGoodExpired {
        return;
    }
    let kind = controller_reason_kind(reason);
    if retained.is_some() {
        if let Some(metrics) = metrics {
            metrics.record_retained_last_good(kind);
        }
    } else {
        let initial_absence = current.reason
            == Some(TlsMaterialReloadReason::AwaitingInitialMaterial)
            && reason == TlsMaterialReloadReason::MaterialUnavailable;
        let expiry_source_clear = current.reason == Some(TlsMaterialReloadReason::LastGoodExpired)
            && reason == TlsMaterialReloadReason::MaterialUnavailable;
        if !initial_absence && !expiry_source_clear {
            if let Some(metrics) = metrics {
                metrics.record_rejected(kind, current.epoch.get());
            }
        }
    }
}

fn publish_expired_candidate(
    controller: &ControllerState,
    status_tx: &watch::Sender<TlsMaterialStatus>,
) {
    let current = *status_tx.borrow();
    let retained = controller.snapshot.as_ref();
    status_tx.send_replace(TlsMaterialStatus {
        epoch: current.epoch,
        availability: if retained.is_some() {
            TlsMaterialAvailability::RetainingLastGood
        } else {
            TlsMaterialAvailability::Unavailable
        },
        reason: Some(TlsMaterialReloadReason::ExpiredMaterial),
        leaf_expires_at: retained.map(TlsMaterialSnapshot::leaf_expires_at),
        certificate_chain_expires_at: retained
            .map(TlsMaterialSnapshot::certificate_chain_expires_at),
    });
}

fn controller_reason_kind(reason: TlsMaterialReloadReason) -> SecurityRotationKind {
    match reason {
        TlsMaterialReloadReason::PrivateKeyMismatch
        | TlsMaterialReloadReason::ExpiredMaterial
        | TlsMaterialReloadReason::NotYetValidMaterial
        | TlsMaterialReloadReason::LocalIdentityChanged
        | TlsMaterialReloadReason::LastGoodExpired => SecurityRotationKind::Svid,
        TlsMaterialReloadReason::AwaitingInitialMaterial
        | TlsMaterialReloadReason::MaterialUnavailable
        | TlsMaterialReloadReason::SourceClosed
        | TlsMaterialReloadReason::MaterialLimitExceeded
        | TlsMaterialReloadReason::InvalidCertificateChain
        | TlsMaterialReloadReason::InvalidWorkloadIdentity
        | TlsMaterialReloadReason::EpochExhausted => SecurityRotationKind::TlsMaterial,
    }
}

fn validate_candidate_chain_temporal_validity(
    certificates: &[CertificateDer<'_>],
    now: Timestamp,
) -> Result<Timestamp, TlsMaterialReloadReason> {
    let mut earliest_expiry = None;
    let mut has_expired_certificate = false;
    let mut has_not_yet_valid_certificate = false;
    for certificate in certificates {
        let validity = crate::certificate_validity(certificate)
            .map_err(|()| TlsMaterialReloadReason::InvalidCertificateChain)?;
        earliest_expiry = Some(
            earliest_expiry.map_or(validity.not_after, |earliest: Timestamp| {
                earliest.min(validity.not_after)
            }),
        );
        has_expired_certificate |= validity.not_after <= now;
        has_not_yet_valid_certificate |= validity.not_before > now;
    }
    let earliest_expiry =
        earliest_expiry.ok_or(TlsMaterialReloadReason::InvalidCertificateChain)?;
    if has_expired_certificate {
        return Err(TlsMaterialReloadReason::ExpiredMaterial);
    }
    if has_not_yet_valid_certificate {
        return Err(TlsMaterialReloadReason::NotYetValidMaterial);
    }
    Ok(earliest_expiry)
}

fn validate_candidate(
    candidate: &IdentityState,
) -> Result<(IdentityState, Timestamp), TlsMaterialReloadReason> {
    if candidate.svid.cert_chain.is_empty()
        || candidate.svid.cert_chain.len() > MAX_TLS_MATERIAL_CHAIN_CERTIFICATES
        || candidate.trust_bundles.bundles.len() > MAX_TLS_MATERIAL_TRUST_BUNDLES
        || candidate.svid.private_key.secret_der().len() > MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES
    {
        return Err(TlsMaterialReloadReason::MaterialLimitExceeded);
    }
    let mut anchor_count = 0usize;
    let mut material_bytes = candidate
        .svid
        .private_key
        .secret_der()
        .len()
        .checked_add(
            candidate
                .svid
                .cert_chain
                .iter()
                .try_fold(0usize, |total, certificate| {
                    total.checked_add(certificate.as_ref().len())
                })
                .ok_or(TlsMaterialReloadReason::MaterialLimitExceeded)?,
        )
        .ok_or(TlsMaterialReloadReason::MaterialLimitExceeded)?;
    for bundle in candidate.trust_bundles.bundles.values() {
        anchor_count = anchor_count
            .checked_add(bundle.certificates.len())
            .ok_or(TlsMaterialReloadReason::MaterialLimitExceeded)?;
        if anchor_count > MAX_TLS_MATERIAL_TRUST_ANCHORS {
            return Err(TlsMaterialReloadReason::MaterialLimitExceeded);
        }
        for certificate in &bundle.certificates {
            material_bytes = material_bytes
                .checked_add(certificate.as_ref().len())
                .ok_or(TlsMaterialReloadReason::MaterialLimitExceeded)?;
        }
    }
    for (domain, bundle) in &candidate.trust_bundles.bundles {
        if domain != &bundle.trust_domain {
            return Err(TlsMaterialReloadReason::InvalidWorkloadIdentity);
        }
        material_bytes = material_bytes
            .checked_add(domain.as_str().len())
            .and_then(|bytes| bytes.checked_add(bundle.trust_domain.as_str().len()))
            .ok_or(TlsMaterialReloadReason::MaterialLimitExceeded)?;
    }
    validate_material_shape(
        candidate.svid.cert_chain.len(),
        candidate.trust_bundles.bundles.len(),
        anchor_count,
        candidate.svid.private_key.secret_der().len(),
        material_bytes,
    )?;
    let certificate_chain_expires_at = validate_candidate_chain_temporal_validity(
        &candidate.svid.cert_chain,
        Timestamp::now_utc(),
    )?;

    let validated = build_identity_state(
        candidate.svid.cert_chain.clone(),
        candidate.svid.private_key.clone_key(),
        candidate.trust_bundles.clone(),
    )
    .map_err(map_identity_error)?;
    if validated.identity != candidate.identity
        || validated.svid.spiffe_id != candidate.svid.spiffe_id
        || validated.svid.expires_at != candidate.svid.expires_at
    {
        return Err(TlsMaterialReloadReason::InvalidWorkloadIdentity);
    }
    Ok((validated, certificate_chain_expires_at))
}

fn validate_material_shape(
    chain_certificates: usize,
    trust_bundles: usize,
    trust_anchors: usize,
    private_key_bytes: usize,
    total_bytes: usize,
) -> Result<(), TlsMaterialReloadReason> {
    if chain_certificates == 0
        || chain_certificates > MAX_TLS_MATERIAL_CHAIN_CERTIFICATES
        || trust_bundles > MAX_TLS_MATERIAL_TRUST_BUNDLES
        || trust_anchors > MAX_TLS_MATERIAL_TRUST_ANCHORS
        || private_key_bytes > MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES
        || total_bytes > MAX_TLS_MATERIAL_TOTAL_BYTES
    {
        Err(TlsMaterialReloadReason::MaterialLimitExceeded)
    } else {
        Ok(())
    }
}

fn map_identity_error(error: IdentityReloadError) -> TlsMaterialReloadReason {
    match error {
        IdentityReloadError::ExpiredSvid => TlsMaterialReloadReason::ExpiredMaterial,
        IdentityReloadError::NotYetValidSvid => TlsMaterialReloadReason::NotYetValidMaterial,
        IdentityReloadError::InvalidCertificateChain | IdentityReloadError::UnknownTrustDomain => {
            TlsMaterialReloadReason::InvalidCertificateChain
        }
        IdentityReloadError::PrivateKeyMismatch => TlsMaterialReloadReason::PrivateKeyMismatch,
        _ => TlsMaterialReloadReason::InvalidWorkloadIdentity,
    }
}

/// Exact material evidence recorded for an admitted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsAdmittedConnection {
    epoch: TlsMaterialEpoch,
    leaf_expires_at: Timestamp,
    certificate_chain_expires_at: Timestamp,
}

impl TlsAdmittedConnection {
    /// Exact material epoch used by the admitted TLS connection.
    pub const fn epoch(self) -> TlsMaterialEpoch {
        self.epoch
    }

    /// Local leaf expiry used by the admitted TLS connection.
    pub const fn leaf_expires_at(self) -> Timestamp {
        self.leaf_expires_at
    }

    /// Earliest expiry across the local certificate chain used by the connection.
    pub const fn certificate_chain_expires_at(self) -> Timestamp {
        self.certificate_chain_expires_at
    }
}

/// One immutable client-side material snapshot for TLS plus application negotiation.
#[derive(Clone)]
pub struct TlsClientHandshake {
    pub(crate) config: Arc<ClientConfig>,
    controller: TlsMaterialController,
    snapshot: TlsMaterialSnapshot,
}

impl TlsClientHandshake {
    pub(crate) fn new(
        config: Arc<ClientConfig>,
        controller: TlsMaterialController,
        snapshot: TlsMaterialSnapshot,
    ) -> Self {
        Self {
            config,
            controller,
            snapshot,
        }
    }

    /// Fixed rustls configuration for exactly this handshake attempt.
    pub fn rustls_config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.config)
    }

    /// Material epoch fixed before this handshake began.
    pub fn epoch(&self) -> TlsMaterialEpoch {
        self.snapshot.epoch()
    }

    /// Local leaf expiry fixed before this handshake began.
    pub fn leaf_expires_at(&self) -> Timestamp {
        self.snapshot.leaf_expires_at()
    }

    /// Earliest expiry across the fixed local certificate chain.
    pub fn certificate_chain_expires_at(&self) -> Timestamp {
        self.snapshot.certificate_chain_expires_at()
    }

    /// Verify the snapshot is still current after TLS and application negotiation.
    pub fn admit(&self) -> Result<TlsAdmittedConnection, TlsMaterialError> {
        self.controller.admit(&self.snapshot)
    }
}

impl fmt::Debug for TlsClientHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientHandshake")
            .field("epoch", &self.snapshot.epoch)
            .field("leaf_expires_at", &self.snapshot.leaf_expires_at)
            .field(
                "certificate_chain_expires_at",
                &self.snapshot.certificate_chain_expires_at,
            )
            .finish_non_exhaustive()
    }
}

/// One immutable server-side material snapshot for TLS plus application negotiation.
#[derive(Clone)]
pub struct TlsServerHandshake {
    pub(crate) config: Arc<ServerConfig>,
    controller: TlsMaterialController,
    snapshot: TlsMaterialSnapshot,
}

impl TlsServerHandshake {
    pub(crate) fn new(
        config: Arc<ServerConfig>,
        controller: TlsMaterialController,
        snapshot: TlsMaterialSnapshot,
    ) -> Self {
        Self {
            config,
            controller,
            snapshot,
        }
    }

    /// Fixed rustls configuration for exactly this handshake attempt.
    pub fn rustls_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Material epoch fixed before this handshake began.
    pub fn epoch(&self) -> TlsMaterialEpoch {
        self.snapshot.epoch()
    }

    /// Local leaf expiry fixed before this handshake began.
    pub fn leaf_expires_at(&self) -> Timestamp {
        self.snapshot.leaf_expires_at()
    }

    /// Earliest expiry across the fixed local certificate chain.
    pub fn certificate_chain_expires_at(&self) -> Timestamp {
        self.snapshot.certificate_chain_expires_at()
    }

    /// Verify the snapshot is still current after TLS and application negotiation.
    pub fn admit(&self) -> Result<TlsAdmittedConnection, TlsMaterialError> {
        self.controller.admit(&self.snapshot)
    }
}

impl fmt::Debug for TlsServerHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsServerHandshake")
            .field("epoch", &self.snapshot.epoch)
            .field("leaf_expires_at", &self.snapshot.leaf_expires_at)
            .field(
                "certificate_chain_expires_at",
                &self.snapshot.certificate_chain_expires_at,
            )
            .finish_non_exhaustive()
    }
}

/// Successful bounded handshake operation plus its admission evidence.
#[derive(Debug)]
pub struct TlsHandshakeOutcome<T> {
    pub(crate) value: T,
    pub(crate) admission: TlsAdmittedConnection,
}

impl<T> TlsHandshakeOutcome<T> {
    /// Consume the outcome into the application value and admission evidence.
    pub fn into_parts(self) -> (T, TlsAdmittedConnection) {
        (self.value, self.admission)
    }

    /// Admission evidence for this operation.
    pub const fn admission(&self) -> TlsAdmittedConnection {
        self.admission
    }

    /// Borrow the application value.
    pub const fn value(&self) -> &T {
        &self.value
    }
}

/// Failure from a bounded handshake operation.
pub enum TlsHandshakeRunError<E> {
    /// TLS material was unavailable, stale, or changed too often.
    Material(TlsMaterialError),
    /// The caller's TLS/application negotiation operation failed.
    Operation(E),
}

impl<E> TlsHandshakeRunError<E> {
    /// Recover the caller-owned operation error, when present.
    pub fn into_operation_error(self) -> Option<E> {
        match self {
            Self::Operation(error) => Some(error),
            Self::Material(_) => None,
        }
    }
}

impl<E> fmt::Debug for TlsHandshakeRunError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Material(error) => formatter.debug_tuple("Material").field(error).finish(),
            Self::Operation(_) => formatter.write_str("Operation([redacted])"),
        }
    }
}

impl<E> fmt::Display for TlsHandshakeRunError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Material(error) => error.fmt(formatter),
            Self::Operation(_) => formatter.write_str("TLS handshake operation failed"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TlsHandshakeRunError<E> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn material_shape_bounds_accept_exact_and_reject_each_one_over() {
        assert!(validate_material_shape(
            MAX_TLS_MATERIAL_CHAIN_CERTIFICATES,
            MAX_TLS_MATERIAL_TRUST_BUNDLES,
            MAX_TLS_MATERIAL_TRUST_ANCHORS,
            MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES,
            MAX_TLS_MATERIAL_TOTAL_BYTES,
        )
        .is_ok());
        for result in [
            validate_material_shape(MAX_TLS_MATERIAL_CHAIN_CERTIFICATES + 1, 1, 1, 1, 1),
            validate_material_shape(1, MAX_TLS_MATERIAL_TRUST_BUNDLES + 1, 1, 1, 1),
            validate_material_shape(1, 1, MAX_TLS_MATERIAL_TRUST_ANCHORS + 1, 1, 1),
            validate_material_shape(1, 1, 1, MAX_TLS_MATERIAL_PRIVATE_KEY_BYTES + 1, 1),
            validate_material_shape(1, 1, 1, 1, MAX_TLS_MATERIAL_TOTAL_BYTES + 1),
            validate_material_shape(0, 1, 1, 1, 1),
        ] {
            assert_eq!(result, Err(TlsMaterialReloadReason::MaterialLimitExceeded));
        }
    }

    #[test]
    fn status_and_controller_debug_are_redaction_safe() {
        let (_tx, rx) = watch::channel(None);
        let controller = TlsMaterialController::new(rx);
        assert_eq!(
            format!("{controller:?}"),
            "TlsMaterialController([redacted])"
        );
        let debug = format!("{:?}", controller.status());
        assert!(!debug.contains("spiffe://"));
        assert!(!debug.contains("BEGIN"));
    }

    #[test]
    fn controller_reasons_use_svid_only_when_the_component_is_provable() {
        assert_eq!(TlsMaterialReloadReason::ALL.len(), 12);
        for reason in TlsMaterialReloadReason::ALL {
            let expected = match reason {
                TlsMaterialReloadReason::PrivateKeyMismatch
                | TlsMaterialReloadReason::ExpiredMaterial
                | TlsMaterialReloadReason::NotYetValidMaterial
                | TlsMaterialReloadReason::LocalIdentityChanged
                | TlsMaterialReloadReason::LastGoodExpired => SecurityRotationKind::Svid,
                TlsMaterialReloadReason::AwaitingInitialMaterial
                | TlsMaterialReloadReason::MaterialUnavailable
                | TlsMaterialReloadReason::SourceClosed
                | TlsMaterialReloadReason::MaterialLimitExceeded
                | TlsMaterialReloadReason::InvalidCertificateChain
                | TlsMaterialReloadReason::InvalidWorkloadIdentity
                | TlsMaterialReloadReason::EpochExhausted => SecurityRotationKind::TlsMaterial,
            };
            assert_eq!(controller_reason_kind(reason), expected, "{reason:?}");
        }
    }
}
