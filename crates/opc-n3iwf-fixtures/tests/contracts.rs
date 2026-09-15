//! Catalog gates for the N3IWF fixture contracts.

use opc_n3iwf_fixtures::{
    redact_contract_debug, wire_digest, ContractError, ContractErrorCode, FixtureCatalog,
    REQUIRED_CASE_CLASSES, SUBSETS,
};

#[test]
fn catalog_detects_clean_committed_fixtures() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    catalog.detect().expect("committed catalog must be clean");
    assert_eq!(catalog.completions().len(), SUBSETS.len());
}

#[test]
fn every_subset_has_required_case_classes_and_runtime_claim_false() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    for subset in SUBSETS {
        let completion = catalog
            .completions()
            .get(*subset)
            .expect("completion record");
        assert!(completion.consumers_may_depend);
        assert!(!completion.runtime_claim);
        assert_eq!(completion.status, "complete");
        for required in REQUIRED_CASE_CLASSES {
            assert!(
                completion
                    .case_classes
                    .iter()
                    .any(|value| value == required),
                "{subset} missing {required}"
            );
        }
    }
    for (manifest, _) in catalog.manifests() {
        assert!(!manifest.runtime_claim);
    }
}

#[test]
fn eap_distinguishes_unknown_parameter_from_duplicate_policy() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let mut saw_ignore = false;
    let mut saw_caller = false;
    for (manifest, _) in catalog.manifests() {
        if manifest.subset != "eap5g" {
            continue;
        }
        if manifest.expected_outcome == "ignore" {
            saw_ignore = manifest
                .semantic_assertions
                .iter()
                .any(|value| value.contains("not_caller_duplicate_policy"));
        }
        if manifest.expected_outcome == "caller-policy" {
            saw_caller = manifest
                .semantic_assertions
                .iter()
                .any(|value| value.contains("caller-duplicate-singleton-policy"));
        }
    }
    assert!(saw_ignore);
    assert!(saw_caller);
}

#[test]
fn nas_tcp_partial_reads_remain_need_more_data() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let outcomes: Vec<_> = catalog
        .manifests()
        .filter(|(manifest, _)| manifest.subset == "nas-tcp")
        .filter(|(manifest, _)| manifest.expected_outcome == "need-more-data")
        .map(|(manifest, _)| manifest.sdk_fixture_id.as_str())
        .collect();
    assert!(outcomes
        .iter()
        .any(|id| id.contains("partial-need-more-data")));
    assert!(outcomes
        .iter()
        .any(|id| id.contains("truncated-length-octet")));
}

#[test]
fn gre_covers_received_nonzero_protocol_type() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "gre-qfi"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "protocol_type=0x0800")
            && manifest.expected_outcome == "ignore"
    }));
}

#[test]
fn n3_covers_direction_specific_psc_and_recovery() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let mut dl = false;
    let mut ul = false;
    let mut recovery = false;
    for (manifest, _) in catalog.manifests() {
        if manifest.subset != "n3-gtpu" {
            continue;
        }
        dl |= manifest
            .semantic_assertions
            .iter()
            .any(|value| value == "direction=downlink");
        ul |= manifest
            .semantic_assertions
            .iter()
            .any(|value| value == "direction=uplink");
        recovery |= manifest
            .semantic_assertions
            .iter()
            .any(|value| value == "received_recovery_ignored=true");
    }
    assert!(dl && ul && recovery);
}

#[test]
fn ike_and_xfrm_are_separated() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "nwu-ike"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "backend_roster=out-of-scope")
    }));
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "xfrm-roster"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "ike_notify_parsing=out-of-scope")
    }));
}

#[test]
fn protocol_key_never_publishes_key_material() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    for (manifest, wire) in catalog.manifests() {
        if manifest.subset != "protocol-key" {
            continue;
        }
        assert!(manifest
            .sanitized_fields
            .iter()
            .any(|field| field.name == "key-material" && field.treatment == "never-published"));
        let text = String::from_utf8_lossy(wire);
        assert!(!text.contains("BEGIN"));
        assert!(text.contains("opc-n3iwf") || wire.len() < 8);
    }
}

#[test]
fn dtls_covers_ppid66_and_redacted_errors() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "n2-dtls"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "ppid=66")
    }));
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "n2-dtls"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "error_redacted=true")
    }));
}

#[test]
fn publication_records_public_sdk_and_interoperability_limit() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let publication = catalog.publication();
    assert_eq!(
        publication.repository,
        "https://github.com/openpacketcore/openpacketcore-sdk"
    );
    assert_eq!(publication.base.len(), 40);
    assert!(publication
        .interoperability_note
        .contains("do not prove external interoperability"));
}

#[test]
fn debug_and_errors_are_redacted() {
    let error = ContractError::new(ContractErrorCode::ForbiddenContent);
    let rendered = format!("{error:?}");
    assert!(!rendered.contains("192.0.2"));
    assert!(!rendered.contains("nas"));
    assert_eq!(
        redact_contract_debug(&error),
        "contract_error=n3iwf_fixture_forbidden_content"
    );
    assert_eq!(wire_digest(b"abc").len(), 64);
}
