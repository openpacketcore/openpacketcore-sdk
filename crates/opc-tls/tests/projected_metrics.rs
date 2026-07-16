#![cfg(unix)]

use opc_identity::projected_svid::MIN_PROJECTED_SVID_POLL_INTERVAL;
use opc_identity::{
    ProjectedSvidAvailability, ProjectedSvidControllerClaimError, ProjectedSvidReloadReason,
    ProjectedSvidSource,
};
use opc_redaction::metrics::{
    SecurityMetricsAuthority, SecurityMetricsReader, SecurityRotationKind, SecurityRotationOutcome,
};
use opc_tls::{TlsMaterialAvailability, TlsMaterialController, TlsMaterialReloadReason};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;

const CERT_FILE: &str = "tls.crt";
const KEY_FILE: &str = "tls.key";
const BUNDLE_FILE: &str = "ca.crt";
const SPIFFE_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/replica-0";

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static NEXT_LINK: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "opc-tls-projected-metrics-{}-{ordinal}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create projected metrics directory");
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

#[derive(Clone)]
struct TestMaterial {
    certificate_chain: String,
    private_key: String,
    trust_bundle: String,
}

fn valid_material() -> TestMaterial {
    material_expiring_after(time::Duration::hours(1))
}

fn material_expiring_after(valid_for: time::Duration) -> TestMaterial {
    material_for_id_expiring_after(SPIFFE_ID, valid_for)
}

fn material_for_id_expiring_after(spiffe_id: &str, valid_for: time::Duration) -> TestMaterial {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "projected metrics CA");
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca = ca_params.self_signed(&ca_key).expect("sign CA");

    let now = time::OffsetDateTime::now_utc();
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names.push(SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("test SPIFFE ID"),
    ));
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + valid_for;
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("sign leaf");

    TestMaterial {
        certificate_chain: leaf.pem() + &ca.pem(),
        private_key: leaf_key.serialize_pem(),
        trust_bundle: ca.pem(),
    }
}

fn material_with_short_intermediate() -> TestMaterial {
    let now = time::OffsetDateTime::now_utc();
    let mut root_params = CertificateParams::default();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params
        .distinguished_name
        .push(DnType::CommonName, "projected metrics root");
    let root_key = KeyPair::generate().expect("generate root key");
    let root = root_params.self_signed(&root_key).expect("sign root");

    let mut intermediate_params = CertificateParams::default();
    intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    intermediate_params.not_before = now - time::Duration::minutes(1);
    intermediate_params.not_after = now + time::Duration::seconds(3);
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "projected metrics intermediate");
    let intermediate_key = KeyPair::generate().expect("generate intermediate key");
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root, &root_key)
        .expect("sign intermediate");

    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names.push(SanType::URI(
        rcgen::Ia5String::try_from(SPIFFE_ID).expect("test SPIFFE ID"),
    ));
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::seconds(5);
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &intermediate, &intermediate_key)
        .expect("sign leaf");

    TestMaterial {
        certificate_chain: leaf.pem() + &intermediate.pem(),
        private_key: leaf_key.serialize_pem(),
        trust_bundle: root.pem(),
    }
}

fn malformed_material(valid: &TestMaterial) -> TestMaterial {
    TestMaterial {
        certificate_chain: "not a certificate".to_string(),
        private_key: valid.private_key.clone(),
        trust_bundle: valid.trust_bundle.clone(),
    }
}

fn write_generation(root: &Path, name: &str, material: &TestMaterial) {
    let generation = root.join(name);
    fs::create_dir_all(&generation).expect("create generation");
    fs::write(generation.join(CERT_FILE), &material.certificate_chain)
        .expect("write certificate chain");
    fs::write(generation.join(KEY_FILE), &material.private_key).expect("write private key");
    fs::write(generation.join(BUNDLE_FILE), &material.trust_bundle).expect("write trust bundle");
}

fn switch_generation(root: &Path, generation: &str) {
    let ordinal = NEXT_LINK.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!("..data-next-{ordinal}"));
    symlink(generation, &temporary).expect("create projected data link");
    fs::rename(temporary, root.join("..data")).expect("replace projected data link");
}

fn source_with_metrics(
    directory: &TestDirectory,
    poll_interval: Duration,
    metrics: SecurityMetricsAuthority,
) -> ProjectedSvidSource {
    ProjectedSvidSource::new_with_metrics(
        directory.path(),
        CERT_FILE,
        KEY_FILE,
        vec![BUNDLE_FILE],
        Some(poll_interval),
        metrics,
    )
    .expect("projected source")
}

async fn wait_for_source_status(
    source: &ProjectedSvidSource,
    predicate: impl Fn(opc_identity::ProjectedSvidReloadStatus) -> bool,
) {
    let mut status = source.subscribe_status();
    timeout(Duration::from_secs(5), async {
        loop {
            if predicate(*status.borrow()) {
                return;
            }
            status.changed().await.expect("projected source status");
        }
    })
    .await
    .expect("projected source status deadline");
}

async fn wait_for_controller_status(
    controller: &TlsMaterialController,
    predicate: impl Fn(opc_tls::TlsMaterialStatus) -> bool,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            let status = controller.status();
            if predicate(status) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TLS material status deadline");
}

async fn wait_for_metric(
    metrics: &SecurityMetricsReader,
    predicate: impl Fn(opc_redaction::metrics::SecurityMetricsSnapshot) -> bool,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = metrics.snapshot();
            if predicate(snapshot) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("security metric deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_identity_wait_is_an_immediate_controller_readiness_barrier() {
    const ITERATIONS: usize = 32;

    let valid = valid_material();
    for _ in 0..ITERATIONS {
        let directory = TestDirectory::new();
        write_generation(directory.path(), "..valid", &valid);
        switch_generation(directory.path(), "..valid");
        let (metrics, _reader) = SecurityMetricsAuthority::isolated();
        let source = source_with_metrics(&directory, MIN_PROJECTED_SVID_POLL_INTERVAL, metrics);

        source
            .wait_for_initial_identity(Duration::from_secs(5))
            .await
            .expect("initial projected identity and controller publication");
        let controller = TlsMaterialController::new_from_projected_source(&source)
            .expect("immediate paired controller");
        assert_eq!(
            controller.status().availability(),
            TlsMaterialAvailability::Ready,
            "the initial identity barrier must not expose an empty controller feed"
        );
    }
}

#[tokio::test]
async fn recovery_before_pairing_cannot_replay_rejection_over_ready_gauges() {
    let directory = TestDirectory::new();
    let valid = valid_material();
    write_generation(directory.path(), "..malformed", &malformed_material(&valid));
    switch_generation(directory.path(), "..malformed");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );

    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Unavailable
            && status.reason() == Some(ProjectedSvidReloadReason::MalformedCertificate)
    })
    .await;
    write_generation(directory.path(), "..valid", &valid);
    switch_generation(directory.path(), "..valid");
    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Ready
    })
    .await;
    let rejected_before = metrics.snapshot().rotation(
        SecurityRotationKind::Svid,
        SecurityRotationOutcome::Rejected,
    );
    assert!(rejected_before > 0);

    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let status = controller.status();
    let snapshot = metrics.snapshot();
    assert!(status.epoch().get() > 0);
    assert!(snapshot.bundle_version() > 0);
    assert!(snapshot.svid_expires_seconds() > 0);
    assert_eq!(snapshot.bundle_version(), status.epoch().get());
    assert_eq!(
        snapshot.rotation(
            SecurityRotationKind::Svid,
            SecurityRotationOutcome::Rejected,
        ),
        rejected_before
    );
}

#[tokio::test]
async fn paired_controller_rejects_second_authority_and_ignores_another_source() {
    let directory_a = TestDirectory::new();
    let directory_b = TestDirectory::new();
    let (metrics_a, _reader_a) = SecurityMetricsAuthority::isolated();
    let (metrics_b, _reader_b) = SecurityMetricsAuthority::isolated();
    let source_a = source_with_metrics(&directory_a, MIN_PROJECTED_SVID_POLL_INTERVAL, metrics_a);
    let source_b = source_with_metrics(&directory_b, MIN_PROJECTED_SVID_POLL_INTERVAL, metrics_b);
    let controller_a =
        TlsMaterialController::new_from_projected_source(&source_a).expect("first authority");
    assert!(matches!(
        TlsMaterialController::new_from_projected_source(&source_a),
        Err(ProjectedSvidControllerClaimError::AlreadyClaimed)
    ));

    let valid = valid_material();
    write_generation(directory_b.path(), "..valid-b", &valid);
    switch_generation(directory_b.path(), "..valid-b");
    wait_for_source_status(&source_b, |status| {
        status.availability() == ProjectedSvidAvailability::Ready
    })
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(controller_a.status().epoch().get(), 0);
    assert_ne!(
        controller_a.status().availability(),
        TlsMaterialAvailability::Ready,
        "another source cannot drive the paired controller"
    );

    write_generation(directory_a.path(), "..valid-a", &valid);
    switch_generation(directory_a.path(), "..valid-a");
    wait_for_controller_status(&controller_a, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;

    let controller_b =
        TlsMaterialController::new_from_projected_source(&source_b).expect("source B authority");
    assert_eq!(
        controller_b.status().availability(),
        TlsMaterialAvailability::Ready
    );
}

#[test]
fn controller_runtime_preflight_does_not_burn_the_one_time_claim() {
    let directory = TestDirectory::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let source = runtime.block_on(async {
        let (metrics, _reader) = SecurityMetricsAuthority::isolated();
        source_with_metrics(&directory, MIN_PROJECTED_SVID_POLL_INTERVAL, metrics)
    });

    let without_runtime = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        TlsMaterialController::new_from_projected_source(&source)
    }));
    assert!(
        without_runtime.is_ok(),
        "controller construction must return instead of panicking"
    );
    assert!(matches!(
        without_runtime.expect("controller runtime result"),
        Err(ProjectedSvidControllerClaimError::RuntimeUnavailable)
    ));

    let retry =
        runtime.block_on(async { TlsMaterialController::new_from_projected_source(&source) });
    assert!(retry.is_ok(), "runtime failure must not consume the claim");
}

#[tokio::test]
async fn initial_empty_source_records_once_without_controller_gauge_rejection() {
    let directory = TestDirectory::new();
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(&directory, Duration::from_secs(60), metrics_authority);
    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");

    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Unavailable
    })
    .await;
    wait_for_metric(&metrics, |snapshot| {
        snapshot.rotation(
            SecurityRotationKind::TlsMaterial,
            SecurityRotationOutcome::Rejected,
        ) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.bundle_version(), 0);
    assert_eq!(snapshot.svid_expires_seconds(), 0);
    assert_eq!(
        snapshot.rotation(
            SecurityRotationKind::TlsMaterial,
            SecurityRotationOutcome::Rejected,
        ),
        1,
        "initial controller absence must not duplicate the producer rejection"
    );
    assert_eq!(controller.status().epoch().get(), 0);
}

#[tokio::test]
async fn generic_controller_from_raw_source_cannot_mutate_process_security_metrics() {
    let global = SecurityMetricsReader::global();
    let before = global.snapshot();
    let directory = TestDirectory::new();
    let valid = valid_material();
    write_generation(directory.path(), "..valid", &valid);
    switch_generation(directory.path(), "..valid");
    let source = ProjectedSvidSource::new(
        directory.path(),
        CERT_FILE,
        KEY_FILE,
        vec![BUNDLE_FILE],
        Some(MIN_PROJECTED_SVID_POLL_INTERVAL),
    )
    .expect("compatibility projected source");
    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Ready
    })
    .await;
    let generic = TlsMaterialController::new(source.subscribe());
    assert_eq!(
        generic.status().availability(),
        TlsMaterialAvailability::Ready
    );

    assert_eq!(global.snapshot(), before);
}

#[tokio::test]
async fn retained_source_failure_changes_only_its_counter() {
    let directory = TestDirectory::new();
    let valid = valid_material();
    write_generation(directory.path(), "..valid", &valid);
    switch_generation(directory.path(), "..valid");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );
    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;
    let before = metrics.snapshot();

    write_generation(directory.path(), "..malformed", &malformed_material(&valid));
    switch_generation(directory.path(), "..malformed");
    wait_for_metric(&metrics, |snapshot| {
        snapshot.rotation(
            SecurityRotationKind::Svid,
            SecurityRotationOutcome::RetainedLastGood,
        ) > 0
    })
    .await;

    let after = metrics.snapshot();
    assert_eq!(after.bundle_version(), before.bundle_version());
    assert_eq!(after.svid_expires_seconds(), before.svid_expires_seconds());
    assert_eq!(
        controller.status().availability(),
        TlsMaterialAvailability::Ready,
        "source-level candidate rejection does not replace controller state"
    );
}

#[tokio::test]
async fn rejected_unaccepted_publication_expiry_preserves_active_material() {
    const REPLACEMENT_ID: &str =
        "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/replica-1";
    let directory = TestDirectory::new();
    let active_material = valid_material();
    write_generation(directory.path(), "..active", &active_material);
    switch_generation(directory.path(), "..active");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );
    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;
    let active = metrics.snapshot();
    let success_before = active.rotation(
        SecurityRotationKind::TlsMaterial,
        SecurityRotationOutcome::Success,
    );

    let rejected = material_for_id_expiring_after(REPLACEMENT_ID, time::Duration::seconds(3));
    write_generation(directory.path(), "..rejected", &rejected);
    switch_generation(directory.path(), "..rejected");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::RetainingLastGood
            && status.reason() == Some(TlsMaterialReloadReason::LocalIdentityChanged)
    })
    .await;
    assert_eq!(metrics.snapshot().bundle_version(), active.bundle_version());
    assert_eq!(
        metrics.snapshot().svid_expires_seconds(),
        active.svid_expires_seconds()
    );

    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Unavailable
            && status.reason() == Some(ProjectedSvidReloadReason::LastGoodExpired)
    })
    .await;
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::RetainingLastGood
    })
    .await;
    wait_for_metric(&metrics, |snapshot| {
        snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired) == 1
    })
    .await;

    let after = metrics.snapshot();
    assert_eq!(after.bundle_version(), active.bundle_version());
    assert_eq!(after.svid_expires_seconds(), active.svid_expires_seconds());
    assert_eq!(
        after.rotation(
            SecurityRotationKind::TlsMaterial,
            SecurityRotationOutcome::Success,
        ),
        success_before,
        "the rejected publication never records controller success"
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        metrics
            .snapshot()
            .rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired),
        1,
        "source/controller observation records the rejected ticket expiry once"
    );
}

#[tokio::test]
async fn projected_svid_expiry_before_pairing_is_recorded_exactly_once() {
    let directory = TestDirectory::new();
    let short = material_expiring_after(time::Duration::seconds(3));
    write_generation(directory.path(), "..short", &short);
    switch_generation(directory.path(), "..short");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );

    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Ready
    })
    .await;
    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Unavailable
            && status.reason() == Some(ProjectedSvidReloadReason::LastGoodExpired)
    })
    .await;
    wait_for_metric(&metrics, |snapshot| {
        snapshot.rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired) == 1
    })
    .await;

    let expired = metrics.snapshot();
    assert_eq!(expired.bundle_version(), 0);
    assert_eq!(expired.svid_expires_seconds(), 0);
    assert!(source.subscribe().borrow().is_none());

    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("late paired controller");
    assert_eq!(
        controller.status().availability(),
        TlsMaterialAvailability::Unavailable
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        metrics
            .snapshot()
            .rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired,),
        1,
        "late pairing and repeated reconciliation cannot duplicate expiry"
    );
}

#[tokio::test]
async fn controller_chain_expiry_then_source_leaf_expiry_is_one_outcome() {
    let directory = TestDirectory::new();
    let material = material_with_short_intermediate();
    write_generation(directory.path(), "..short-chain", &material);
    switch_generation(directory.path(), "..short-chain");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );
    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;

    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Unavailable
            && status.reason() == Some(TlsMaterialReloadReason::LastGoodExpired)
    })
    .await;
    assert_eq!(
        metrics
            .snapshot()
            .rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired,),
        1
    );

    wait_for_source_status(&source, |status| {
        status.availability() == ProjectedSvidAvailability::Unavailable
            && status.reason() == Some(ProjectedSvidReloadReason::LastGoodExpired)
    })
    .await;
    assert_eq!(
        metrics
            .snapshot()
            .rotation(SecurityRotationKind::Svid, SecurityRotationOutcome::Expired,),
        1,
        "later source leaf expiry must reuse the controller publication ticket"
    );
}

#[tokio::test]
async fn source_closure_is_reconciled_once_by_the_owned_controller_task() {
    let directory = TestDirectory::new();
    let valid = valid_material();
    write_generation(directory.path(), "..valid", &valid);
    switch_generation(directory.path(), "..valid");
    let (metrics_authority, metrics) = SecurityMetricsAuthority::isolated();
    let source = source_with_metrics(
        &directory,
        MIN_PROJECTED_SVID_POLL_INTERVAL,
        metrics_authority,
    );
    let controller =
        TlsMaterialController::new_from_projected_source(&source).expect("paired controller");
    wait_for_controller_status(&controller, |status| {
        status.availability() == TlsMaterialAvailability::Ready
    })
    .await;
    let ready = metrics.snapshot();

    drop(source);
    wait_for_metric(&metrics, |snapshot| {
        snapshot.rotation(
            SecurityRotationKind::TlsMaterial,
            SecurityRotationOutcome::RetainedLastGood,
        ) == 1
    })
    .await;
    let status = controller.status();
    assert_eq!(
        status.availability(),
        TlsMaterialAvailability::RetainingLastGood
    );
    assert_eq!(status.reason(), Some(TlsMaterialReloadReason::SourceClosed));
    assert_eq!(metrics.snapshot().bundle_version(), ready.bundle_version());
    assert_eq!(
        metrics.snapshot().svid_expires_seconds(),
        ready.svid_expires_seconds()
    );
    let _ = controller.status();
    assert_eq!(
        metrics.snapshot().rotation(
            SecurityRotationKind::TlsMaterial,
            SecurityRotationOutcome::RetainedLastGood,
        ),
        1
    );
}
