use opc_session_store::RestoreBlockReason;
use opc_session_testkit::RestoreEvidenceAsserter;

#[test]
fn restore_asserter_accepts_stale_owner_and_traffic_gate_evidence() {
    let evidence = vec![
        RestoreBlockReason::stale_owner_rejected(
            "stale owner from 192.0.2.10 tried /var/lib/opc/session.db",
        ),
        RestoreBlockReason::dataplane_reinstall_pending("dataplane reinstall is pending"),
    ];

    RestoreEvidenceAsserter::new(&evidence)
        .has_stale_owner_rejection()
        .blocks_traffic_until_restore_complete()
        .has_redaction_safe_messages();
}

#[test]
#[should_panic(expected = "expected stale owner rejection")]
fn restore_asserter_rejects_missing_stale_owner_rejection() {
    let evidence = vec![RestoreBlockReason::dataplane_reinstall_pending(
        "dataplane reinstall is pending",
    )];

    RestoreEvidenceAsserter::new(&evidence).has_stale_owner_rejection();
}
