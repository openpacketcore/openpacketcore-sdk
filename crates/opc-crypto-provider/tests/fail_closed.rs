//! End-to-end fail-closed contract for the capability seam.
//!
//! Every test drives the public API only: a configurable [`FakeCryptoModule`]
//! is probed into a [`CapabilityReport`] and checked against a
//! [`ProviderPolicy`], proving that a capability that is unreported, failed,
//! or unready can never be admitted.

use opc_crypto_provider::testkit::FakeCryptoModule;
use opc_crypto_provider::{
    probe_capability_report, CapabilityReport, CapabilitySet, CryptoCapability, PolicyAdmission,
    PolicyError, ProviderIdentity, ProviderName, ProviderPolicy, ProviderVersion, SelfTestEvidence,
    ValidationReference, ValidationState,
};

const TLS_AND_IKE: &[CryptoCapability] = &[
    CryptoCapability::Tls,
    CryptoCapability::IkePrf,
    CryptoCapability::IkeIntegrity,
    CryptoCapability::IkeEncryption,
    CryptoCapability::IkeSignature,
    CryptoCapability::IkeDiffieHellman,
];

fn identity() -> ProviderIdentity {
    ProviderIdentity::from_parts("fixture module", "9.9.9").expect("valid fixture identity")
}

fn tls_and_ike_policy() -> ProviderPolicy {
    ProviderPolicy::new().require_all(CapabilitySet::from_slice(TLS_AND_IKE))
}

/// Stand-in for a slice-2..5 operation gate: callable only with an admission.
fn operation_gate(admission: &PolicyAdmission) -> CapabilitySet {
    admission.granted_capabilities()
}

#[tokio::test]
async fn a_satisfying_provider_reports_exactly_the_advertised_set_bound_to_its_identity() {
    let advertised = CapabilitySet::from_slice(TLS_AND_IKE);
    let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);

    let report = probe_capability_report(&module).await;
    assert_eq!(report.identity(), &identity());
    assert_eq!(report.identity().name().as_str(), "fixture module");
    assert_eq!(report.identity().version().as_str(), "9.9.9");
    assert_eq!(report.advertised_capabilities(), advertised);
    assert_eq!(report.effective_capabilities(), advertised);
    for capability in CryptoCapability::ALL.iter().copied() {
        assert_eq!(
            report.effective_capabilities().contains(capability),
            advertised.contains(capability),
            "{capability} must be effective exactly when advertised"
        );
    }

    let admission = tls_and_ike_policy()
        .admit(&report)
        .expect("fully satisfied policy must admit");
    assert_eq!(admission.identity(), report.identity());
    assert_eq!(operation_gate(&admission), advertised);
}

#[tokio::test]
async fn removing_any_required_capability_rejects_before_any_operation_is_admitted() {
    let policy = tls_and_ike_policy();
    for dropped in TLS_AND_IKE.iter().copied() {
        let advertised = CapabilitySet::from_slice(TLS_AND_IKE).without(dropped);
        let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);
        let report = probe_capability_report(&module).await;

        // The operation gate takes a `&PolicyAdmission`, and `admit` is the
        // only constructor of that type, so counting gate entries proves the
        // rejection happens strictly before any operation could be admitted.
        let mut operations_admitted = 0_u32;
        match policy.admit(&report) {
            Ok(admission) => {
                let _ = operation_gate(&admission);
                operations_admitted += 1;
            }
            Err(error) => {
                assert_eq!(error.as_str(), "policy_capability_unavailable");
                assert_eq!(
                    error,
                    PolicyError::CapabilityUnavailable {
                        missing: CapabilitySet::empty().with(dropped),
                    },
                    "missing set must name exactly the dropped capability"
                );
            }
        }
        assert_eq!(
            operations_admitted, 0,
            "no operation may be admitted when {dropped} is unreported"
        );
    }
}

#[tokio::test]
async fn a_self_test_failure_withdraws_the_capability_and_shows_in_the_evidence() {
    let advertised = CapabilitySet::from_slice(TLS_AND_IKE);
    let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);
    module.fail_self_test_for(CapabilitySet::empty().with(CryptoCapability::IkePrf));

    let report = probe_capability_report(&module).await;
    assert_eq!(report.advertised_capabilities(), advertised);
    assert_eq!(
        report.effective_capabilities(),
        advertised.without(CryptoCapability::IkePrf),
        "the failed capability must be withdrawn, the rest kept"
    );
    match report.self_test() {
        SelfTestEvidence::Completed(outcome) => {
            assert!(outcome.failed().contains(CryptoCapability::IkePrf));
            assert!(!outcome.passed().contains(CryptoCapability::IkePrf));
        }
        other => panic!("expected completed self-test evidence, got {other}"),
    }
    let json = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(json["self_test"]["completed"]["failed"][0], "ike_prf");
    assert!(!json["effective"]
        .as_array()
        .expect("effective is a list")
        .iter()
        .any(|value| value == "ike_prf"));

    assert_eq!(
        tls_and_ike_policy().admit(&report),
        Err(PolicyError::CapabilityUnavailable {
            missing: CapabilitySet::empty().with(CryptoCapability::IkePrf),
        })
    );
}

#[tokio::test]
async fn a_self_test_that_cannot_run_withdraws_every_capability() {
    let advertised = CapabilitySet::from_slice(TLS_AND_IKE);
    let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);
    module.make_self_test_unavailable();

    let report = probe_capability_report(&module).await;
    assert_eq!(report.self_test(), &SelfTestEvidence::Unavailable);
    assert!(report.effective_capabilities().is_empty());
    assert_eq!(
        tls_and_ike_policy().admit(&report),
        Err(PolicyError::CapabilityUnavailable {
            missing: advertised,
        })
    );
}

#[tokio::test]
async fn losing_readiness_withdraws_the_capability_the_same_way_as_a_failed_self_test() {
    let advertised = CapabilitySet::from_slice(TLS_AND_IKE);
    let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);
    module.withdraw_serviceability(CapabilitySet::empty().with(CryptoCapability::Tls));

    let report = probe_capability_report(&module).await;
    assert_eq!(report.advertised_capabilities(), advertised);
    assert!(!report
        .readiness()
        .serviceable_capabilities()
        .contains(CryptoCapability::Tls));
    assert_eq!(
        report.effective_capabilities(),
        advertised.without(CryptoCapability::Tls)
    );
    assert_eq!(
        tls_and_ike_policy().admit(&report),
        Err(PolicyError::CapabilityUnavailable {
            missing: CapabilitySet::empty().with(CryptoCapability::Tls),
        })
    );

    module.restore_serviceability(CapabilitySet::empty().with(CryptoCapability::Tls));
    let recovered = probe_capability_report(&module).await;
    assert_eq!(recovered.effective_capabilities(), advertised);
}

#[tokio::test]
async fn a_non_validated_provider_composes_without_claiming_validation() {
    let advertised = CapabilitySet::from_slice(TLS_AND_IKE);
    let module = FakeCryptoModule::new(identity()).with_advertised_capabilities(advertised);

    let report = probe_capability_report(&module).await;
    assert_eq!(report.validation_state(), &ValidationState::NotValidated);
    let json = serde_json::to_value(&report).expect("report serializes");
    assert_eq!(json["validation"], "not_validated");

    let admission = tls_and_ike_policy()
        .admit(&report)
        .expect("non-validated module must compose under an ordinary policy");
    assert_eq!(
        admission.validation_state(),
        &ValidationState::NotValidated,
        "admission must not upgrade the declared state"
    );

    assert_eq!(
        tls_and_ike_policy()
            .require_declared_validation()
            .admit(&report),
        Err(PolicyError::ValidationNotDeclared),
        "requiring declared validation must fail closed on a non-validated module"
    );
}

#[tokio::test]
async fn an_unreported_or_unknown_capability_never_reads_as_available() {
    // Empty sets and defaults are all withdrawn.
    for capability in CryptoCapability::ALL.iter().copied() {
        assert!(!CapabilitySet::default().contains(capability));
        assert!(!CapabilitySet::empty().contains(capability));
    }
    assert!(SelfTestEvidence::default().passed_capabilities().is_empty());

    // A module that reports nothing yields nothing effective, and any
    // requirement over it rejects.
    let module = FakeCryptoModule::new(identity());
    let report = probe_capability_report(&module).await;
    assert!(report.effective_capabilities().is_empty());
    for capability in CryptoCapability::ALL.iter().copied() {
        assert!(!report.effective_capabilities().contains(capability));
        assert!(ProviderPolicy::new()
            .require(capability)
            .admit(&report)
            .is_err());
    }
}

#[tokio::test]
async fn evidence_is_bounded_and_carries_no_key_material() {
    // A sentinel that stands in for key material living in test scope. No
    // constructor of any evidence type accepts raw bytes, so it can never
    // enter the report; the assertions pin that invariant.
    let sentinel_key_hex = "deadbeefcafef00d0123456789abcdef";

    let name = ProviderName::new("N".repeat(ProviderName::MAX_LEN)).expect("max-length name");
    let version =
        ProviderVersion::new("V".repeat(ProviderVersion::MAX_LEN)).expect("max-length version");
    let reference = ValidationReference::new("R".repeat(ValidationReference::MAX_LEN))
        .expect("max-length reference");
    let module = FakeCryptoModule::new(ProviderIdentity::new(name, version))
        .with_advertised_capabilities(CapabilitySet::from_slice(CryptoCapability::ALL))
        .with_validation_state(ValidationState::DeclaredValidated {
            reference: Some(reference),
        });
    module.fail_self_test_for(CapabilitySet::empty().with(CryptoCapability::Zeroization));
    module.withdraw_serviceability(CapabilitySet::empty().with(CryptoCapability::Tls));

    let report = probe_capability_report(&module).await;
    let json = serde_json::to_string(&report).expect("report serializes");
    assert!(
        json.len() <= CapabilityReport::MAX_JSON_BYTES,
        "serialized report ({} bytes) exceeded MAX_JSON_BYTES",
        json.len()
    );
    assert!(
        json.starts_with("{\"provider\":"),
        "evidence must lead with the answering module's identity"
    );
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    // `serde_json::Value` maps iterate in sorted key order.
    let fields: Vec<&str> = value
        .as_object()
        .expect("report is a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        [
            "advertised",
            "effective",
            "provider",
            "self_test",
            "serviceable",
            "validation"
        ],
        "the evidence surface is exactly the documented field set"
    );

    for rendered in [json, format!("{report:?}"), report.to_string()] {
        assert!(
            !rendered.contains(sentinel_key_hex),
            "evidence must not carry key material"
        );
        assert!(
            rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "evidence renderings must stay printable ASCII"
        );
        assert!(
            rendered.len() <= CapabilityReport::MAX_JSON_BYTES,
            "every rendering must stay bounded"
        );
    }
}
