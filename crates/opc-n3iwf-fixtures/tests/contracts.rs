//! Catalog gates for the N3IWF fixture contracts.

use std::collections::BTreeSet;

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
fn eap_covers_notification_and_stop() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let mut notification = false;
    let mut stop = false;
    for (manifest, _) in catalog.manifests() {
        if manifest.subset != "eap5g" {
            continue;
        }
        notification |= manifest
            .semantic_assertions
            .iter()
            .any(|value| value == "message_id=3");
        stop |= manifest
            .semantic_assertions
            .iter()
            .any(|value| value == "message_id=4");
    }
    assert!(notification && stop);
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
fn nas_tcp_eof_loss_finalizes_instead_of_need_more_data() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    assert!(catalog.manifests().any(|(manifest, _)| {
        manifest.subset == "nas-tcp"
            && manifest
                .sdk_fixture_id
                .contains("eof-loss-incomplete-frame")
            && manifest.expected_outcome == "reject"
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "not_need_more_data")
            && manifest
                .semantic_assertions
                .iter()
                .any(|value| value == "eof_or_loss=true")
    }));
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
    let ike_needles = [
        "procedure=create-child-sa",
        "procedure=modify-child-sa",
        "notify_type=55504",
        "notify_type=55508",
        "notify_types=55501,55504",
        "notify_types=55508,55501",
        "protocol=ESP",
        "mobility_wire_only=true",
        "backend_roster=out-of-scope",
    ];
    for needle in ike_needles {
        assert!(
            catalog.manifests().any(|(manifest, _)| {
                manifest.subset == "nwu-ike"
                    && manifest
                        .semantic_assertions
                        .iter()
                        .any(|value| value == needle)
            }),
            "nwu-ike missing {needle}"
        );
    }
    let xfrm_needles = [
        "overlap=true",
        "inbound_spi_unknown=true",
        "rekey=true",
        "relocation=true",
        "ike_notify_parsing=out-of-scope",
    ];
    for needle in xfrm_needles {
        assert!(
            catalog.manifests().any(|(manifest, _)| {
                manifest.subset == "xfrm-roster"
                    && manifest
                        .semantic_assertions
                        .iter()
                        .any(|value| value == needle)
            }),
            "xfrm-roster missing {needle}"
        );
    }
}

#[test]
fn ngap_publishes_matrices_for_every_admitted_outcome() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let completion = catalog.completions().get("ngap").expect("ngap completion");
    assert!(!completion.admitted_outcomes.is_empty());
    assert_eq!(completion.matrices.len(), catalog.ngap_matrices().len());
    let fixture_ids: BTreeSet<&str> = catalog
        .manifests()
        .filter(|(manifest, _)| manifest.subset == "ngap")
        .map(|(manifest, _)| manifest.sdk_fixture_id.as_str())
        .collect();
    let mut messages = BTreeSet::new();
    let mut saw_paging = false;
    for matrix in catalog.ngap_matrices() {
        assert_eq!(matrix.source.release, "V18.10.0");
        assert_eq!(matrix.application.release, "V18.5.0");
        assert!(!matrix.ies.is_empty());
        assert!(!matrix.constructed_send);
        messages.insert(matrix.message.as_str());
        if let Some(fixture_id) = &matrix.wire_fixture_id {
            assert!(fixture_ids.contains(fixture_id.as_str()), "{fixture_id}");
        }
        match matrix.ts29413_clause.as_str() {
            "5.2" => assert_eq!(matrix.admitted_disposition, "receive"),
            "5.4" => {
                assert_eq!(matrix.message, "Paging");
                assert_eq!(matrix.admitted_disposition, "unsupported");
                saw_paging = true;
            }
            other => panic!("unexpected TS 29.413 clause {other}"),
        }
    }
    for admitted in &completion.admitted_outcomes {
        assert!(messages.contains(admitted.as_str()), "{admitted}");
    }
    assert!(saw_paging);
    assert!(completion
        .admission_scope
        .contains("first-cnf-typed-subset"));
    assert!(fixture_ids
        .iter()
        .any(|id| id.contains("positive-ngsetup-external")));
    assert!(fixture_ids
        .iter()
        .any(|id| id.contains("unsupported-paging-5-4")));
}

#[test]
fn ngap_matrices_use_pinned_release18_rows_supported_by_policy_rs() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let policy = include_str!("../../opc-proto-ngap/src/policy.rs");
    let names = [
        ("NGSetupRequest", "NG_SETUP_REQUEST"),
        ("NGSetupResponse", "NG_SETUP_RESPONSE"),
        ("NGSetupFailure", "NG_SETUP_FAILURE"),
        ("InitialUEMessage", "INITIAL_UE_MESSAGE"),
        ("DownlinkNASTransport", "DOWNLINK_NAS_TRANSPORT"),
        ("UplinkNASTransport", "UPLINK_NAS_TRANSPORT"),
        ("NASNonDeliveryIndication", "NAS_NON_DELIVERY_INDICATION"),
        ("UEContextReleaseRequest", "UE_CONTEXT_RELEASE_REQUEST"),
        ("NGReset", "NG_RESET"),
        ("NGResetAcknowledge", "NG_RESET_ACKNOWLEDGE"),
        ("ErrorIndication", "ERROR_INDICATION"),
        ("PDUSessionResourceNotify", "PDU_SESSION_RESOURCE_NOTIFY"),
        (
            "PDUSessionResourceModifyRequest",
            "PDU_SESSION_RESOURCE_MODIFY_REQUEST",
        ),
        (
            "PDUSessionResourceModifyResponse",
            "PDU_SESSION_RESOURCE_MODIFY_RESPONSE",
        ),
        (
            "InitialContextSetupRequest",
            "INITIAL_CONTEXT_SETUP_REQUEST",
        ),
        (
            "InitialContextSetupResponse",
            "INITIAL_CONTEXT_SETUP_RESPONSE",
        ),
        (
            "InitialContextSetupFailure",
            "INITIAL_CONTEXT_SETUP_FAILURE",
        ),
        (
            "PDUSessionResourceSetupRequest",
            "PDU_SESSION_RESOURCE_SETUP_REQUEST",
        ),
        (
            "PDUSessionResourceSetupResponse",
            "PDU_SESSION_RESOURCE_SETUP_RESPONSE",
        ),
        (
            "PDUSessionResourceReleaseCommand",
            "PDU_SESSION_RESOURCE_RELEASE_COMMAND",
        ),
        (
            "PDUSessionResourceReleaseResponse",
            "PDU_SESSION_RESOURCE_RELEASE_RESPONSE",
        ),
        ("UEContextReleaseCommand", "UE_CONTEXT_RELEASE_COMMAND"),
        ("UEContextReleaseComplete", "UE_CONTEXT_RELEASE_COMPLETE"),
        ("Paging", "PAGING"),
    ];
    for matrix in catalog.ngap_matrices() {
        let const_name = names
            .iter()
            .find(|(message, _)| *message == matrix.message)
            .map(|(_, name)| *name)
            .expect("matrix outcome is admitted");
        let marker = format!("const {const_name}: IeProfile");
        let start = policy.find(&marker).expect(const_name);
        let rest = &policy[start..];
        let end = rest.find("]);").expect("profile end");
        let block = &rest[..end];
        let mut ids = BTreeSet::new();
        for line in block.lines() {
            let Some(after) = line.split("IeRule::singleton(").nth(1) else {
                continue;
            };
            let parts: Vec<&str> = after.split(',').collect();
            let id: u16 = parts[0].trim().parse().expect("ie id");
            let crit = if parts[1].contains("REJECT") {
                "reject"
            } else if parts[1].contains("IGNORE") {
                "ignore"
            } else {
                "notify"
            };
            ids.insert((id, crit.to_string()));
        }
        let published: BTreeSet<(u16, String)> = matrix
            .ies
            .iter()
            .map(|ie| (ie.id, ie.criticality.clone()))
            .collect();
        // The current codec admits newer-release extensions as well. The
        // fixture's exact Release-18 row set is independently pinned below.
        assert!(
            published.is_subset(&ids),
            "Release-18 rules drifted from the codec"
        );
        let oracle: serde_json::Value =
            serde_json::from_str(include_str!("../oracles/ngap-rel18.json"))
                .expect("pinned oracle");
        let expected = &oracle["messages"][&matrix.message];
        assert_eq!(serde_json::to_value(&matrix.ies).expect("rows"), *expected);
        assert!(matrix
            .n3iwf_content_exceptions
            .contains("5.3 RAN-specific ignore is not encoded"));
    }
}

#[test]
fn protocol_key_publication_contains_only_labels_and_public_test_inputs() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let mut saw_wrong = false;
    let mut saw_reuse = false;
    let mut saw_drop = false;
    let mut saw_cancel = false;
    let mut labels = 0;
    let mut known_answers = 0;
    for (manifest, wire) in catalog.manifests() {
        if manifest.subset != "protocol-key" {
            continue;
        }
        if manifest.validation_scope == "ike-auth-known-answer" {
            known_answers += 1;
            assert!(manifest.provenance.synthetic && !manifest.provenance.independent_capture);
            assert!(!manifest.runtime_claim);
            assert_eq!(manifest.context["sdk_custody_validation"], false);
            assert!(manifest
                .sanitized_fields
                .iter()
                .any(|field| field.name == "key-inputs"
                    && field.treatment == "public-test-scalars-1-and-2-and-zero-NGAP-placeholder"
                    && field.value_class == "synthetic-not-peer-key"));
            let key = manifest.context["inputs"]["auth_keying_material"]
                .as_str()
                .expect("test input");
            assert!(
                key.is_empty() || key == "00".repeat(32) || key == format!("01{}", "00".repeat(31))
            );
            assert!((3..=36).contains(&wire.len()));
            // The independent recipe gate pins every remaining input and
            // negative mutation to public scalar/nonce/identity recipes.
            continue;
        }
        assert_eq!(manifest.validation_scope, "handle-lifecycle-contract");
        labels += 1;
        assert!(manifest
            .sanitized_fields
            .iter()
            .any(|field| field.name == "key-material" && field.treatment == "never-published"));
        let text = String::from_utf8_lossy(wire);
        assert!(!text.contains("BEGIN"));
        assert!(text.contains("opc-n3iwf") || wire.len() < 8);
        saw_wrong |= manifest.sdk_fixture_id.contains("wrong-generation");
        saw_reuse |= manifest.sdk_fixture_id.contains("reuse-after-consume");
        saw_drop |= manifest.sdk_fixture_id.contains("drop-zeroize");
        saw_cancel |= manifest.sdk_fixture_id.contains("cancellation");
    }
    assert!(saw_wrong && saw_reuse && saw_drop && saw_cancel);
    assert_eq!(labels, 10);
    assert_eq!(known_answers, 30);
}

#[test]
fn dtls_covers_ppid66_and_redacted_errors() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let needles = [
        "ppid=66",
        "identity=expected-peer-label",
        "reliable_delivery=true",
        "rekey=true",
        "rotation=true",
        "path_failure=true",
        "error_redacted=true",
    ];
    for needle in needles {
        assert!(
            catalog.manifests().any(|(manifest, _)| {
                manifest.subset == "n2-dtls"
                    && manifest
                        .semantic_assertions
                        .iter()
                        .any(|value| value == needle)
            }),
            "n2-dtls missing {needle}"
        );
    }
}

#[test]
fn oracles_are_pinned_to_issue_784_releases() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let mut saw_24502 = false;
    let mut saw_38413 = false;
    let mut saw_29413 = false;
    let mut saw_38412 = false;
    let mut saw_29281 = false;
    let mut saw_38415 = false;
    let mut saw_33501 = false;
    let mut saw_6083 = false;
    let mut saw_7296 = false;
    let mut saw_4555 = false;
    for (manifest, _) in catalog.manifests() {
        let source = &manifest.source;
        match (source.document.as_str(), source.release.as_str()) {
            ("3GPP TS 24.502", "V18.8.0") => saw_24502 = true,
            ("3GPP TS 38.413", "V18.10.0") => saw_38413 = true,
            ("3GPP TS 38.412", "V18.1.0") => saw_38412 = true,
            ("3GPP TS 29.281", "V18.4.0") => saw_29281 = true,
            ("3GPP TS 38.415", "V18.2.0") => saw_38415 = true,
            ("3GPP TS 33.501", "V18.12.0") => saw_33501 = true,
            ("IETF RFC 6083", "RFC 6083") => saw_6083 = true,
            ("IETF RFC 7296", "RFC 7296") => saw_7296 = true,
            ("IETF RFC 4555", "RFC 4555") => saw_4555 = true,
            _ => {}
        }
    }
    for matrix in catalog.ngap_matrices() {
        if matrix.application.document == "3GPP TS 29.413"
            && matrix.application.release == "V18.5.0"
        {
            saw_29413 = true;
        }
    }
    assert!(
        saw_24502
            && saw_38413
            && saw_29413
            && saw_38412
            && saw_29281
            && saw_38415
            && saw_33501
            && saw_6083
            && saw_7296
            && saw_4555
    );
}

#[test]
fn scope_excludes_app_policy_and_tracking_795() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    for (manifest, _) in catalog.manifests() {
        assert_ne!(manifest.subset, "795");
        assert!(!manifest.sdk_fixture_id.contains("795"));
        assert!(!manifest.prerequisite.contains("AMF selection"));
        assert!(!manifest
            .prerequisite
            .contains("subscriber authentication decision"));
    }
    let ngap = catalog.completions().get("ngap").expect("ngap");
    assert!(ngap
        .unsupported
        .iter()
        .any(|value| value.contains("AMF selection")));
}

#[test]
fn reused_public_vectors_remain_locked_to_merged_sources() {
    let catalog = FixtureCatalog::load().expect("catalog must load");
    let ngap_src = include_str!("../../opc-proto-ngap/src/lib.rs");
    let gtpu_control = include_str!("../../opc-proto-gtpu/tests/control_messages.rs");
    let gtpu_user = include_str!("../../opc-proto-gtpu/tests/gtpu_tests.rs");
    fn octets(source: &str, marker: &str) -> Vec<u8> {
        let body = source
            .split_once(marker)
            .expect("source marker")
            .1
            .split_once(']')
            .expect("literal end")
            .0;
        let stripped = body
            .lines()
            .map(|line| line.split("//").next().expect("line"))
            .collect::<Vec<_>>()
            .join(" ");
        stripped
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| {
                if let Some(hex) = token.strip_prefix("0x") {
                    u8::from_str_radix(hex, 16).expect("hex octet")
                } else {
                    token.parse().expect("decimal octet")
                }
            })
            .collect()
    }
    let source = ngap_src
        .split_once("fn ngsetup_request_fixture()")
        .expect("source function")
        .1;
    let mut ngap = octets(source, "vec![");
    assert_eq!(
        wire_digest(&ngap),
        "183cf47d3546a4a0a9ac72ae66ca166da4ae90c6bed0ed98e82f38832be57f2d"
    );
    ngap[2] = 0; // Correct NGSetup procedure criticality to reject.
    for offset in [12, 48, 61] {
        ngap[offset..offset + 3].copy_from_slice(&[0, 0xf1, 0x10]);
    }
    ngap[25..38].copy_from_slice(b"Synthetic RAN");
    let request = octets(gtpu_control, "const ECHO_REQUEST: &[u8] = &[");
    let response = octets(gtpu_control, "const ECHO_RESPONSE: &[u8] = &[");
    let psc_source = gtpu_user
        .split_once("fn test_decode_with_extension_headers()")
        .expect("PSC source")
        .1;
    let psc = octets(psc_source, "let raw = vec![");
    for (manifest, wire) in catalog.manifests() {
        if manifest
            .sdk_fixture_id
            .ends_with("positive-ngsetup-external")
        {
            assert_eq!(wire_digest(wire), manifest.wire.digest_sha256);
            assert_eq!(wire, ngap);
        }
        if manifest.sdk_fixture_id.ends_with("positive-echo-request") {
            assert_eq!(wire, request);
            assert_eq!(
                wire,
                &[0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x12, 0x34, 0, 0]
            );
        }
        if manifest
            .sdk_fixture_id
            .ends_with("positive-echo-response-recovery-zero")
        {
            assert_eq!(wire, response);
            assert_eq!(
                wire,
                &[0x32, 0x02, 0x00, 0x06, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0x0e, 0]
            );
        }
        if manifest.sdk_fixture_id.ends_with("positive-dl-psc") {
            assert_eq!(wire, psc);
            assert_eq!(
                wire,
                &[
                    0x36, 0xff, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x00, 0x05, 0x00, 0x85, 0x01,
                    0x00, 0x09, 0x00
                ]
            );
        }
    }
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
