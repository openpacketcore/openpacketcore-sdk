//! Supported legacy ledger shapes, distinct from public-history reachability.
//!
//! Real signed Event transitions fill the retained representation's event limit.
//! Those transitions are a component fixture API; the public Intent/result/
//! terminal history has a separate, lower row count at the operation limit.
//! This checks decoded collection/Box capacity and actual SQL apply owners. It
//! does not qualify retained target recovery Strings, parser scratch, allocator
//! overhead, concurrent replication, retries, or the complete operation bound.

use super::*;
use crate::audit_authority::continuity::chain::{ContinuityState, SignedAuditRow};
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::{
    AuditCheckpoint, AuditKeyRing, AuditKeyTransition, AuditSigningKey,
};
use crate::audit_authority::ledger::{
    EntryPayload as LedgerPayload, LedgerEntry, LedgerOperation, MAX_LEDGER_EVENTS,
    MAX_LEDGER_OPERATIONS, MAX_STATE_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Shape {
    Operations,
    EventsAndOperations,
    EventsOperationsAndContinuity,
}

impl Shape {
    fn initial_entries(self) -> usize {
        match self {
            Self::Operations => 3 * (MAX_LEDGER_OPERATIONS - 1) + 1,
            Self::EventsAndOperations | Self::EventsOperationsAndContinuity => {
                MAX_LEDGER_EVENTS - 2
            }
        }
    }

    pub(super) fn keys(self) -> Option<AuditKeyRing> {
        (self == Self::EventsOperationsAndContinuity).then(|| {
            AuditKeyRing::new(vec![
                AuditSigningKey::new(1, [0xA8; 32]).expect("synthetic continuity key")
            ])
            .expect("real bounded signing key ring")
        })
    }

    pub(super) fn ledger(
        self,
        prepared: &PreparedAuditedMutation,
        keys: Option<&AuditKeyRing>,
    ) -> LedgerState {
        let mut ledger = super::ledger(prepared);
        let missing = self.initial_entries() - ledger.entries.len();
        for number in 0..missing {
            // Use a fresh SDK privacy projection and the production signed
            // append path, never padding vectors or forging retained JSON.
            let event = handle((MAX_LEDGER_OPERATIONS + number) as u64, None)
                .body
                .event;
            ledger
                .append_event(&key(), event)
                .expect("real retained Event transition");
        }
        if keys.is_some() {
            ledger.continuity = Some(ContinuityState::new(1));
            ledger
                .seal_continuity(keys)
                .expect("real signatures for the complete retained prefix");
        }
        self.check(&ledger, keys, 0);
        assert_eq!(ledger.used_capacity().unwrap(), self.initial_entries() + 2);
        ledger
    }

    pub(super) fn check(self, ledger: &LedgerState, keys: Option<&AuditKeyRing>, added: usize) {
        ledger
            .validate(&key(), identity())
            .expect("authenticate complete supported ledger");
        ledger
            .validate_continuity(keys)
            .expect("authenticate complete continuity history");
        let entries = self.initial_entries() + added;
        let rows = if keys.is_some() { entries } else { 0 };
        assert_eq!(ledger.entries.len(), entries);
        assert_eq!(ledger.operations.len(), MAX_LEDGER_OPERATIONS);
        assert_eq!(ledger.entries.capacity(), entries);
        assert_eq!(ledger.operations.capacity(), MAX_LEDGER_OPERATIONS);
        assert_eq!(
            ledger
                .continuity
                .as_ref()
                .map_or((0, 0), |chain| (chain.rows.len(), chain.rows.capacity())),
            (rows, rows),
            "actual continuity capacity, including unused slots"
        );
        assert_eq!(
            ledger
                .entries
                .iter()
                .filter(|entry| matches!(entry.payload, LedgerPayload::Intent(_)))
                .count(),
            MAX_LEDGER_OPERATIONS
        );
        assert!(ledger.entries.iter().all(|entry| !matches!(
            entry.payload,
            LedgerPayload::TargetIntent(_) | LedgerPayload::EmptyCommit(_)
        )));
        let decoded =
            crate::consensus::config_capacity_simultaneous_working_tests::ledger::ledger_heap(
                ledger,
            );
        assert!(decoded <= legacy_decoded_capacity_ceiling());
    }

    pub(super) fn checkpoint(self, conn: &Connection, keys: Option<&AuditKeyRing>) {
        let Some(keys) = keys else {
            return;
        };
        let ledger =
            crate::consensus::audit::read_with_keys_sync(conn, &key(), Some(keys), identity())
                .expect("authenticated checkpoint prefix")
                .expect("active continuity ledger");
        let chain = ledger.continuity.as_ref().expect("actual signed prefix");
        let checkpoint = AuditCheckpoint::issue(
            keys,
            CheckpointBody {
                version: 1,
                identity: identity(),
                sequence: ledger.sequence,
                root_anchor: ledger.terminal,
                anchor: chain.terminal,
                epoch_at_sequence: chain.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: [0; 32],
            },
        )
        .expect("authenticate exact component checkpoint");
        drop(ledger);
        // The component uses real checkpoint authentication/application. It
        // does not model the public external checkpoint port or its durability.
        assert!(crate::consensus::audit::apply_sync(
            conn,
            &key(),
            identity(),
            &crate::consensus::audit::AuditCommand::Checkpoint(checkpoint),
            100,
            Some(keys),
        )
        .expect("actual checkpoint application")
        .is_ok());
    }

    pub(super) fn finish(
        self,
        conn: &Connection,
        topology: &ConfigConsensusTopology,
        prepared: &PreparedAuditedMutation,
        keys: Option<&AuditKeyRing>,
    ) {
        if self == Self::Operations {
            return;
        }
        // Spend the original reserved terminal slot through the same native
        // apply function. The previous result readback has already been dropped.
        let entry = Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, topology.local_node_id()), 2),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: 8,
                identity: identity(),
                request_id: ConsensusRequestId::from_bytes([0xA9; 16]),
                logical_time: logical_time(),
                intent: ConfigMutationIntent::ManagementAudit(Box::new(
                    crate::consensus::audit::AuditCommand::Terminal(prepared.handle().clone()),
                )),
            }),
        };
        append_committed(conn, topology, &entry);
        assert!(apply_with_keys(conn, topology, vec![entry], keys)
            .result
            .is_ok());
        self.checkpoint(conn, keys);
        let ledger = crate::consensus::audit::read_with_keys_sync(conn, &key(), keys, identity())
            .expect("authenticate terminal retained state")
            .expect("retained full ledger");
        self.check(&ledger, keys, 2);
        assert_eq!(ledger.entries.len(), MAX_LEDGER_EVENTS);
        assert_eq!(ledger.used_capacity().unwrap(), MAX_LEDGER_EVENTS);
        let receipt = ledger
            .lookup(
                &key(),
                prepared.handle(),
                prepared.handle().body.binding.caller,
            )
            .expect("exact original terminal lookup")
            .expect("exact retained operation");
        assert!(receipt.terminal_recorded());
        assert!(matches!(
            receipt.state(),
            AuditOperationState::Committed { version: 1 }
        ));
        let encoded: usize = conn
            .query_row(
                "SELECT length(state_json) FROM config_raft_management_audit WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("actual retained canonical byte count");
        assert!(encoded <= MAX_STATE_BYTES);
        let layout = [
            size_of::<LedgerEntry>(),
            size_of::<LedgerOperation>(),
            size_of::<AuditOperationHandle>(),
            size_of::<ProjectedAuditEvent>(),
            size_of::<AuditKeyTransition>(),
            size_of::<SignedAuditRow>(),
        ];
        println!(
            "CONFIG_CAPACITY_LEDGER_SUPPORTED_SHAPE shape={self:?} entries={} operations={} continuity_rows={} decoded_capacity={} decoded_shape_ceiling={} layout={layout:?} canonical_bytes={encoded} complete_operation_bound=false",
            ledger.entries.len(), ledger.operations.len(),
            ledger.continuity.as_ref().map_or(0, |chain| chain.rows.len()),
            crate::consensus::config_capacity_simultaneous_working_tests::ledger::ledger_heap(&ledger),
            legacy_decoded_capacity_ceiling(),
        );
    }
}

// The retained decoder counts before exact reserves. Each legacy entry owns at
// most one of these closed Boxes; outcomes and terminals have no nested heap.
// Charge the maximum Box for every event, even though 4096 Intents would fail
// later operation authentication. This is a finite bound on these decoded
// owners, independent of the particular signed fixture's MAC byte widths.
// It deliberately makes no claim about target Strings or transient validation.
fn legacy_decoded_capacity_ceiling() -> usize {
    let boxed = size_of::<AuditOperationHandle>()
        .max(size_of::<ProjectedAuditEvent>())
        .max(size_of::<AuditKeyTransition>());
    MAX_LEDGER_EVENTS * (size_of::<LedgerEntry>() + boxed + size_of::<SignedAuditRow>())
        + MAX_LEDGER_OPERATIONS * size_of::<LedgerOperation>()
}

#[cfg(feature = "dangerous-test-hooks")]
mod native {
    use super::*;
    use crate::consensus::capacity_observation::{
        NativeOwnerObserver, NativeOwnerSample, NativeRegistration, NativeStage, PreparationCensus,
        PreparationOwner,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Samples(Mutex<Vec<NativeOwnerSample>>);

    impl NativeOwnerObserver for Samples {
        fn observe(&self, sample: NativeOwnerSample) {
            self.0.lock().expect("native metadata samples").push(sample);
        }
    }

    pub(in super::super) struct NativeCapture<'a> {
        registration: NativeRegistration,
        prepared: PreparationOwner<'a>,
        census: Arc<PreparationCensus>,
        samples: Arc<Samples>,
    }

    impl<'a> NativeCapture<'a> {
        pub(in super::super) fn new(
            conn: &Connection,
            topology: &ConfigConsensusTopology,
            prepared: &'a PreparedAuditedMutation,
        ) -> Self {
            let census = Arc::new(PreparationCensus::default());
            let owner = census
                .observe_audited(topology.local_node_id(), prepared)
                .expect("borrow exact original preparation");
            let samples = Arc::new(Samples::default());
            let registration = NativeRegistration::new(
                conn,
                identity(),
                topology.local_node_id(),
                command(prepared).request_id,
                prepared,
                census.clone(),
                samples.clone(),
            )
            .expect("exact native connection/request registration");
            Self {
                registration,
                prepared: owner,
                census,
                samples,
            }
        }

        pub(in super::super) fn finish(self, shape: Shape) {
            let drain = self.registration.snapshot();
            self.registration.detach();
            assert_eq!(drain.native_scopes, 0);
            assert_eq!(drain.transport_scopes, 0);
            assert_eq!(drain.append_scopes, 0);
            let samples = self.samples.0.lock().expect("finished native samples");
            assert_eq!(drain.callbacks, samples.len());
            for stage in [
                NativeStage::DecodedLedger,
                NativeStage::ValidatedLedger,
                NativeStage::AuthenticatedMutation,
                NativeStage::LedgerWrite,
            ] {
                assert!(samples.iter().any(|sample| sample.stage == stage));
            }
            for sample in samples.iter() {
                assert!((shape.initial_entries()..=shape.initial_entries() + 1)
                    .contains(&sample.native_ledger_entries));
                assert_eq!(sample.native_ledger_operations, MAX_LEDGER_OPERATIONS);
                let rows = if shape == Shape::EventsOperationsAndContinuity {
                    sample.native_ledger_entries
                } else {
                    0
                };
                assert_eq!(sample.native_continuity_rows, rows);
                assert_eq!(
                    sample.native_ledger_capacities,
                    [sample.native_ledger_entries, MAX_LEDGER_OPERATIONS, rows]
                );
                assert!(sample.native_ledger_bytes <= legacy_decoded_capacity_ceiling());
                assert!(sample.native_is_distinct && sample.selected_prepared_bytes > 0);
                #[cfg(target_os = "linux")]
                assert!(sample.independent_oracles_match);
                if sample.stage == NativeStage::ValidatedLedger {
                    assert_eq!(
                        sample.native_derived_bytes,
                        MAX_LEDGER_OPERATIONS * size_of::<LedgerOperation>()
                    );
                }
                if sample.stage == NativeStage::LedgerWrite {
                    assert_eq!(sample.native_ledger_entries, shape.initial_entries() + 1);
                    assert!(sample.native_write_bytes > 0);
                }
            }
            println!("CONFIG_CAPACITY_LEDGER_NATIVE_SHAPE shape={shape:?} samples={} all_scopes_drained=true", samples.len());
            drop(samples);
            drop(self.prepared);
            assert_eq!(self.census.snapshot().registrations, 0);
        }
    }
}

#[cfg(feature = "dangerous-test-hooks")]
pub(super) use native::NativeCapture;

#[test]
fn config_capacity_957_ledger_workspace_full_event_and_operation_limits() {
    simultaneous_apply_for_shape(false, Shape::EventsAndOperations);
}

#[test]
fn config_capacity_957_ledger_workspace_full_limits_and_admitted_spare() {
    simultaneous_apply_for_shape(true, Shape::EventsAndOperations);
}

#[test]
fn config_capacity_957_ledger_workspace_full_continuity() {
    simultaneous_apply_for_shape(false, Shape::EventsOperationsAndContinuity);
}
