//! Genuine public audit history at the retained operation limit.
//!
//! Each historical operation is admitted, rejected and finished through the
//! original store APIs before the selected preparation and its deadline exist.
//! This reaches 1,024 operations with the selected Intent, not the independent
//! 4,096-event decoder limit. No retained row is copied or injected.

use super::*;
use opc_persist::config_capacity_observation::{NativeOwnerSample, NativeStage};

const PUBLIC_HISTORY_OPERATIONS: usize = 1_023;

pub(super) async fn fill(stores: &[ConsensusConfigStore], leader: usize, principal: &str) {
    use opc_persist::{
        ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
        ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    };

    let started = std::time::Instant::now();
    let mut completed = 0;
    for number in 0..PUBLIC_HISTORY_OPERATIONS {
        let mut request = [0xCF; 16];
        request[..8].copy_from_slice(&(number as u64).to_be_bytes());
        let event = ManagementAuditEventRecord::try_new(
            request,
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .expect("synthetic public-history event time"),
            "test",
            principal,
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Update,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            ["/fixture:config"],
            Some("synthetic-public-operation-capacity"),
        )
        .expect("bounded original public-history event");
        let handle = stores[leader]
            .prepare_audit_intent(
                &joint::privacy(),
                &event,
                ConfigVersion::new(1),
                &request,
                Duration::from_secs(60),
            )
            .expect("prepare original public-history handle");
        let AuditAdmission::Applied(admitted) = stores[leader]
            .admit_audit_operation_local(&handle, joint::caller(principal))
            .await
        else {
            panic!("public-history Intent {number} must actually apply");
        };
        assert_eq!(admitted.handle(), &handle);
        assert_eq!(admitted.state(), AuditOperationState::Intent);
        assert!(!admitted.terminal_recorded());
        let AuditAdmission::Applied(rejected) = stores[leader]
            .reject_audit_operation(&handle, joint::caller(principal))
            .await
        else {
            panic!("public-history rejection {number} must actually apply");
        };
        assert_eq!(rejected.handle(), &handle);
        assert_eq!(rejected.state(), AuditOperationState::Rejected);
        assert!(!rejected.terminal_recorded());
        let AuditAdmission::Applied(terminal) = stores[leader]
            .finish_audit_operation(&handle, joint::caller(principal))
            .await
        else {
            panic!("public-history terminal {number} must actually apply");
        };
        assert_eq!(terminal.handle(), &handle);
        assert_eq!(terminal.state(), AuditOperationState::Rejected);
        assert!(terminal.terminal_recorded());
        completed += 1;
        if number + 1 == PUBLIC_HISTORY_OPERATIONS {
            // Prove the final genuine history operation is readable at a
            // quorum-current barrier on each original store before measuring.
            for store in stores {
                let retained = store
                    .lookup_audit_operation(&handle, joint::caller(principal))
                    .await
                    .expect("original-store public-history read barrier")
                    .expect("original public-history terminal retained");
                assert_eq!(retained.handle(), &handle);
                assert_eq!(retained.state(), AuditOperationState::Rejected);
                assert!(retained.terminal_recorded());
            }
        }
    }
    let rows = completed * 3;
    println!("CONFIG_CAPACITY_NINE_PUBLIC_HISTORY_SETUP operations={completed} rows={rows} admissions={completed} rejections={completed} terminals={completed} elapsed_ms={} original_stores=9 native_public_ports=true copied_rows=false decoder_row_limit_claim=false", started.elapsed().as_millis());
}

// All assertions run after the shared scenario has released and joined its
// original RPCs, encoder, stores and servers. No first sample stands in for a
// later or larger callback: the selected apply must visit each stage once.
pub(super) fn assert_native_shape(sample: NativeOwnerSample, callbacks: usize) {
    assert_eq!(callbacks, 1,
        "CONFIG_CAPACITY_NINE_PUBLIC_HISTORY_CALLBACK_RED: exactly one selected native checkpoint per stage");
    assert_eq!(
        sample.native_ledger_entries,
        if sample.stage == NativeStage::LedgerWrite {
            3_071
        } else {
            3_070
        },
        "CONFIG_CAPACITY_NINE_PUBLIC_HISTORY_ROWS_RED"
    );
    assert_eq!(
        sample.native_ledger_operations, 1_024,
        "CONFIG_CAPACITY_NINE_PUBLIC_HISTORY_OPERATIONS_RED"
    );
    assert_eq!(sample.native_continuity_rows, 0);
    assert!(sample.native_ledger_capacities[0] >= sample.native_ledger_entries);
    assert!(sample.native_ledger_capacities[1] >= sample.native_ledger_operations);
    assert_eq!(sample.native_ledger_capacities[2], 0);
    println!("CONFIG_CAPACITY_NINE_PUBLIC_HISTORY_CHECKPOINT stage={:?} ledger_entries={} ledger_operations={} continuity_rows={} ledger_capacities={:?} callbacks={callbacks} native_public_history=true decoder_row_limit_claim=false", sample.stage, sample.native_ledger_entries, sample.native_ledger_operations, sample.native_continuity_rows, sample.native_ledger_capacities);
}

native_case!(
    config_capacity_957_nine_public_history_four_rpc_recovery_checkpoint,
    { super::native_tail::run(super::native_tail::AuditHistory::PublicOperationLimit).await }
);
