//! Bounded reuse of pure payload decoding within a synchronous SQL WAL owner.
//!
//! Each caller still fetches and validates its own database row. A hit proves
//! only that these exact bytes already passed the complete durable-log decoder;
//! it proves nothing about row identity, authority, projection or publication.
//! The final application stored-byte audit remains independent of this cache.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use super::{Entry, EntryPayload, SessionMutationIntent, SessionRaftTypeConfig};

const MAX_RETAINED_BYTES: usize = 8 * 1024 * 1024;

struct Row {
    encoded: Box<[u8]>,
    entry: Entry<SessionRaftTypeConfig>,
    allocation_bytes: usize,
}

/// Two recent scope payloads cover the current append and its previous witness.
/// Historical reads cannot evict either with an older row. Retention is bounded
/// by both row count and the actual raw/typed capacities, independently of the
/// number of stored children or log entries. Ineligible rows use the decoder.
#[derive(Default)]
pub(super) struct Cache {
    rows: Mutex<[Option<Row>; 2]>,
}

thread_local! {
    static ACTIVE: RefCell<Option<Arc<Cache>>> = const { RefCell::new(None) };
}

/// Installed only while holding State in a synchronous method. The !Send guard
/// cannot cross a task migration, and nested owners restore the earlier scope.
pub(super) struct Guard {
    previous: Option<Arc<Cache>>,
    _same_thread: PhantomData<Rc<()>>,
}

impl Cache {
    pub(super) fn enter(self: &Arc<Self>) -> Guard {
        Guard {
            previous: ACTIVE.with(|active| active.replace(Some(Arc::clone(self)))),
            _same_thread: PhantomData,
        }
    }

    pub(super) fn clear(&self) {
        if let Ok(mut rows) = self.rows.lock() {
            *rows = [None, None];
        }
    }

    fn fixed_bytes() -> usize {
        std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>()
    }

    fn allocation_bytes(encoded: &[u8], entry: &Entry<SessionRaftTypeConfig>) -> Option<usize> {
        let EntryPayload::Normal(command) = &entry.payload else {
            return None;
        };
        let (intent, authorized_bytes) = match &command.intent {
            SessionMutationIntent::Authorized { mutation, .. } => (
                mutation.as_ref(),
                std::mem::size_of::<SessionMutationIntent>(),
            ),
            intent => (intent, 0),
        };
        let SessionMutationIntent::ScopeBatch(command) = intent else {
            return None;
        };
        // The fixed owner includes both inline Entries. The command charges
        // its Box, all nested Vec capacities, values and bounded identifiers.
        encoded
            .len()
            .checked_add(authorized_bytes)?
            .checked_add(command.log_row_reuse_allocation_bytes()?)
    }

    fn remember(&self, encoded: &[u8], entry: &Entry<SessionRaftTypeConfig>) {
        let Some(bytes) = Self::allocation_bytes(encoded, entry)
            .and_then(|bytes| (bytes <= MAX_RETAINED_BYTES - Self::fixed_bytes()).then_some(bytes))
        else {
            return;
        };
        let Ok(mut rows) = self.rows.lock() else {
            return;
        };
        let slot = if let Some(slot) = rows.iter().position(|row| {
            row.as_ref()
                .is_some_and(|row| row.entry.log_id.index == entry.log_id.index)
        }) {
            slot
        } else if let Some(slot) = rows.iter().position(Option::is_none) {
            slot
        } else {
            let slot = usize::from(
                rows[1].as_ref().map(|row| row.entry.log_id.index)
                    < rows[0].as_ref().map(|row| row.entry.log_id.index),
            );
            if rows[slot]
                .as_ref()
                .is_some_and(|row| row.entry.log_id.index > entry.log_id.index)
            {
                return;
            }
            slot
        };
        // Release replaced allocations before copying, so temporary retention
        // cannot exceed the same bound. Cloning these Vecs cannot increase any
        // charged capacity; the caller's original Entry is never retained.
        rows[slot] = None;
        let other = 1 - slot;
        if rows[other].as_ref().is_some_and(|row| {
            row.allocation_bytes > MAX_RETAINED_BYTES - Self::fixed_bytes() - bytes
        }) {
            rows[other] = None;
        }
        rows[slot] = Some(Row {
            encoded: encoded.into(),
            entry: entry.clone(),
            allocation_bytes: bytes,
        });
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.replace(self.previous.take()));
    }
}

pub(super) fn decoded(encoded: &[u8]) -> Option<Entry<SessionRaftTypeConfig>> {
    let cache = ACTIVE.with(|active| active.borrow().clone())?;
    let rows = cache.rows.lock().ok()?;
    rows.iter().flatten().find_map(|row| {
        // Compare every original byte, including legacy ignored fields and
        // whitespace. A changed row always takes the original full decoder.
        (row.encoded.as_ref() == encoded).then(|| row.entry.clone())
    })
}

pub(super) fn remember(encoded: &[u8], entry: &Entry<SessionRaftTypeConfig>) {
    if let Some(cache) = ACTIVE.with(|active| active.borrow().clone()) {
        cache.remember(encoded, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        SessionConsensusCommand, SessionConsensusNodeId, SessionConsensusRequestId,
        SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use crate::scope_authority::tests::{admitted, at, scope};
    use crate::scope_batch::tests::create;
    use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest};
    use crate::sqlite::consensus::{decode_consensus_log_entry, log_row_reuse_test_observer};
    use opc_consensus::engine::{CommittedLeaderId, LogId};

    fn entry(index: u64, authorized: bool) -> Entry<SessionRaftTypeConfig> {
        let node = SessionConsensusNodeId::new(1).unwrap();
        let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap();
        let identity = crate::consensus::SessionConsensusIdentity::new(
            scope().store(),
            opc_consensus::derive_configuration_id(scope().store(), epoch, &[[1; 32]]),
            epoch,
        );
        let authority = admitted();
        let intent = SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::in_lane(
                authority.view.stamp().unwrap(),
                [2; 16],
                0,
                index,
                vec![create(1, &[2])],
                vec![],
            )
            .unwrap(),
        }));
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node), index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity,
                request_id: SessionConsensusRequestId::from_bytes([2; 16]),
                logical_time: at(0),
                intent: if authorized {
                    SessionMutationIntent::Authorized {
                        origin: node,
                        authority_identity: identity,
                        mutation: Box::new(intent),
                    }
                } else {
                    intent
                },
            }),
        }
    }

    fn full_decodes(call: impl FnOnce()) -> usize {
        let observation = log_row_reuse_test_observer::Scope::new();
        call();
        observation
            .finish()
            .iter()
            .filter(|event| **event == log_row_reuse_test_observer::Event::FullDecode)
            .count()
    }

    #[test]
    fn hits_require_every_byte_and_cannot_be_changed_by_a_caller() {
        for authorized in [false, true] {
            let cache = Arc::new(Cache::default());
            let _guard = cache.enter();
            let original = entry(1, authorized);
            let encoded = serde_json::to_vec(&original).unwrap();
            assert_eq!(
                full_decodes(|| {
                    assert!(decode_consensus_log_entry(&encoded).unwrap() == original);
                }),
                1
            );
            assert_eq!(
                full_decodes(|| {
                    let mut returned = decode_consensus_log_entry(&encoded).unwrap();
                    returned.log_id.index = 55;
                    returned.payload = EntryPayload::Blank;
                    assert_eq!(returned.log_id.index, 55);
                    assert!(decode_consensus_log_entry(&encoded).unwrap() == original);
                }),
                0
            );
            // The same row ID with a different valid command is not a hit.
            let mut changed = original.clone();
            let EntryPayload::Normal(command) = &mut changed.payload else {
                unreachable!()
            };
            command.logical_time = at(1);
            let changed_bytes = serde_json::to_vec(&changed).unwrap();
            assert_eq!(
                full_decodes(|| {
                    assert!(decode_consensus_log_entry(&changed_bytes).unwrap() == changed);
                }),
                1
            );
            // Preserve legacy compatibility, but do not equate alternate raw
            // images merely because their decoded values compare equal.
            let mut padded = changed_bytes.clone();
            padded.push(b' ');
            assert_eq!(
                full_decodes(|| {
                    assert!(decode_consensus_log_entry(&padded).unwrap() == changed);
                }),
                1
            );
            assert_eq!(
                full_decodes(|| {
                    assert!(decode_consensus_log_entry(b"{").is_err());
                    assert!(decode_consensus_log_entry(&padded).unwrap() == changed);
                }),
                1
            );
        }
    }

    #[test]
    fn retention_keeps_two_recent_rows_and_refuses_oversized_or_other_commands() {
        let cache = Arc::new(Cache::default());
        let _guard = cache.enter();
        for index in 1..=16 {
            let encoded = serde_json::to_vec(&entry(index, true)).unwrap();
            decode_consensus_log_entry(&encoded).unwrap();
            let rows = cache.rows.lock().unwrap();
            assert_eq!(rows.iter().flatten().count(), usize::min(index as usize, 2));
            assert!(
                Cache::fixed_bytes()
                    + rows
                        .iter()
                        .flatten()
                        .map(|row| row.allocation_bytes)
                        .sum::<usize>()
                    <= MAX_RETAINED_BYTES
            );
        }
        let old = serde_json::to_vec(&entry(1, true)).unwrap();
        assert_eq!(
            full_decodes(|| {
                decode_consensus_log_entry(&old).unwrap();
                for index in [15, 16] {
                    decode_consensus_log_entry(&serde_json::to_vec(&entry(index, true)).unwrap())
                        .unwrap();
                }
            }),
            1,
            "a historical read must not evict the current and previous payloads"
        );
        let mut oversized = serde_json::to_vec(&entry(17, true)).unwrap();
        oversized.resize(MAX_RETAINED_BYTES + 1, b' ');
        assert_eq!(
            full_decodes(|| {
                for _ in 0..2 {
                    assert!(decode_consensus_log_entry(&oversized).unwrap() == entry(17, true));
                }
            }),
            2,
            "optional retention must not narrow durable-row acceptance"
        );
        for index in [18, 19] {
            let mut padded = serde_json::to_vec(&entry(index, true)).unwrap();
            padded.resize(5 * 1024 * 1024, b' ');
            decode_consensus_log_entry(&padded).unwrap();
        }
        {
            let rows = cache.rows.lock().unwrap();
            assert_eq!(
                rows.iter().flatten().count(),
                1,
                "aggregate byte cap evicts the other row"
            );
            assert!(
                Cache::fixed_bytes()
                    + rows
                        .iter()
                        .flatten()
                        .map(|row| row.allocation_bytes)
                        .sum::<usize>()
                    <= MAX_RETAINED_BYTES
            );
        }
        let mut blank = entry(18, false);
        blank.payload = EntryPayload::Blank;
        let blank = serde_json::to_vec(&blank).unwrap();
        assert_eq!(
            full_decodes(|| {
                decode_consensus_log_entry(&blank).unwrap();
                decode_consensus_log_entry(&blank).unwrap();
            }),
            2
        );
        cache.clear();
        assert!(cache.rows.lock().unwrap().iter().all(Option::is_none));
        assert_eq!(
            full_decodes(|| {
                decode_consensus_log_entry(&old).unwrap();
            }),
            1
        );
    }

    #[test]
    fn a_warm_payload_never_authorizes_a_different_row_or_command_scope() {
        use crate::sqlite::consensus::{
            decode_durable_log_audit_row, validate_command_for_log, EncodedDurableLogAuditRow,
        };
        let cache = Arc::new(Cache::default());
        let _guard = cache.enter();
        let original = entry(1, true);
        let EntryPayload::Normal(command) = &original.payload else {
            unreachable!()
        };
        let identity = command.identity;
        let encoded = serde_json::to_vec(&original).unwrap();
        decode_consensus_log_entry(&encoded).unwrap();
        for (epoch, term, index) in [(1, 1, 1), (2, 1, 1), (1, 2, 1), (1, 1, 2)] {
            let row = EncodedDurableLogAuditRow {
                epoch,
                term,
                index,
                encoded: encoded.clone(),
            };
            assert_eq!(
                full_decodes(|| {
                    let result = decode_durable_log_audit_row(&row, identity);
                    assert_eq!(result.is_ok(), (epoch, term, index) == (1, 1, 1));
                }),
                0,
                "a hit must still execute the independent row checks"
            );
        }
        let decoded = decode_consensus_log_entry(&encoded).unwrap();
        let EntryPayload::Normal(command) = &decoded.payload else {
            unreachable!()
        };
        validate_command_for_log(command, identity).unwrap();
        let foreign = crate::consensus::SessionConsensusIdentity::new(
            opc_consensus::ConsensusClusterId::new("other-payload-owner").unwrap(),
            identity.configuration_id(),
            identity.configuration_epoch(),
        );
        assert!(validate_command_for_log(command, foreign).is_err());
        let unauthorized = serde_json::to_vec(&entry(1, false)).unwrap();
        decode_consensus_log_entry(&unauthorized).unwrap();
        assert_eq!(
            full_decodes(|| {
                let decoded = decode_consensus_log_entry(&unauthorized).unwrap();
                let EntryPayload::Normal(command) = &decoded.payload else {
                    unreachable!()
                };
                assert_eq!(
                    validate_command_for_log(command, identity)
                        .unwrap_err()
                        .to_string(),
                    "scope batch requires current authority"
                );
            }),
            0,
            "an already decoded command still requires authority"
        );
    }

    #[test]
    fn owners_are_isolated_and_nested_unwind_restores_the_previous_owner() {
        let first = Arc::new(Cache::default());
        let second = Arc::new(Cache::default());
        let encoded = serde_json::to_vec(&entry(1, false)).unwrap();
        {
            let _first = first.enter();
            assert_eq!(
                full_decodes(|| {
                    decode_consensus_log_entry(&encoded).unwrap();
                }),
                1
            );
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _second = second.enter();
                assert_eq!(
                    full_decodes(|| {
                        decode_consensus_log_entry(&encoded).unwrap();
                    }),
                    1
                );
                panic!("exercise context cleanup");
            }))
            .is_err());
            assert_eq!(
                full_decodes(|| {
                    decode_consensus_log_entry(&encoded).unwrap();
                }),
                0
            );
            std::thread::scope(|threads| {
                threads
                    .spawn(|| {
                        assert_eq!(
                            full_decodes(|| {
                                decode_consensus_log_entry(&encoded).unwrap();
                            }),
                            1
                        );
                    })
                    .join()
                    .unwrap();
            });
        }
        assert_eq!(
            full_decodes(|| {
                decode_consensus_log_entry(&encoded).unwrap();
            }),
            1
        );
    }
}
