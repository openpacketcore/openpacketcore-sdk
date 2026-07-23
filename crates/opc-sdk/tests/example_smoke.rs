//! Smoke test that the minimal_cnf example compiles and the runtime
//! can be instantiated with the SDK facade.

use std::time::Duration;

use opc_sdk::prelude::*;

#[tokio::test]
async fn sdk_facade_runtime_starts_and_shuts_down() {
    let profile = RuntimeProfile::dev("smoke-test");
    let alarms = SharedAlarmManager::default();

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms)
        .build()
        .await
        .expect("runtime should start");

    assert!(!handle.shutdown_token().is_shutdown_requested());

    handle.shutdown_token().request_shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(handle.shutdown_token().is_shutdown_requested());
}

#[tokio::test]
async fn sdk_alarm_raise_clear_roundtrip() {
    use opc_sdk::opc_alarm::{
        AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity,
    };

    let alarms = SharedAlarmManager::default();
    let affected = AffectedObject::NfInstance {
        kind: "smoke".into(),
        instance: "smoke-01".into(),
    };

    alarms.raise(
        AlarmType::new("smoke.test.alarm"),
        Severity::Warning,
        ProbableCause::Other("smoke".into()),
        affected.clone(),
        None,
        None,
        None,
        RedactedText::new("smoke alarm"),
        AlarmDetails::empty(),
    );

    assert_eq!(alarms.active_alarms().len(), 1);

    alarms.clear(
        &AlarmType::new("smoke.test.alarm"),
        ProbableCause::Other("smoke".into()),
        &affected,
        None,
        None,
        None,
    );

    assert!(alarms.active_alarms().is_empty());
}

#[test]
fn sdk_prelude_exposes_security_entry_points() {
    let trust_domain = TrustDomain::new("core.example").expect("trust domain");
    assert_eq!(trust_domain.as_str(), "core.example");

    let trust_bundles = TrustBundleSet::new();
    assert!(!trust_bundles.contains(&trust_domain));

    let policy = PeerPolicy::default();
    assert!(policy.is_unconstrained());

    let key_id = KeyId::new("session-key-2026-01").expect("key id");
    assert_eq!(key_id.as_str(), "session-key-2026-01");
    assert_eq!(KeyPurpose::Session.as_str(), "session");

    let _crypto_envelope: Option<CryptoEnvelopeV1> = None;
    let _crypto_error = CryptoError::InvalidEnvelope;
    let custody_requirements = key_custody_required_capabilities();
    assert!(custody_requirements.contains(CryptoCapability::SealedKeyStorage));
    assert_eq!(MAX_KEY_CUSTODY_BOUND_AAD_BYTES, 64 * 1024);
    let _admitted_custody: Option<AdmittedKeyCustody> = None;
    let _custody_install_error: Option<KeyCustodyInstallError> = None;
    let _direct_remote_provider: Option<&dyn RemoteSealProvider> = None;
    let _kms_provider_size = std::mem::size_of::<KmsKeyProvider>();
    let _memory_provider_size = std::mem::size_of::<MemoryKeyProvider>();
    let _tls_builder_size = std::mem::size_of::<TlsConfigBuilder>();
}
