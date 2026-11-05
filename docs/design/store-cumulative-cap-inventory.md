# Store cumulative-cap inventory

Source baseline: `601343e14037794aab7dbca6dceef9c5e6c76c97`.
Inventory for [SDK #1307](https://github.com/openpacketcore/openpacketcore-sdk/issues/1307).
This is an inventory, not a claim that the sibling protocols have been fixed.

| Area | Bound and consequence | Source |
| --- | --- | --- |
| Protected roster history | 131,072 live/retained rows, durable epoch bindings, floors and retirement cursors, with 24-hour terminal retention. Completed admissions exhaust the rolling allowance. Admission, native reconstruction, streamed snapshots and recovery preflight repeat the bound. In scope for #1307. | `fenced_mutation_roster.rs`; `fenced_mutation_roster_storage.rs`; `consensus/native/roster.rs`; `consensus/native/generation_roster_catalog.rs`; `recovery/sqlite.rs` |
| Fenced transition V1 | 4,096 permanent request-ID/body bindings per consensus identity, including compact tombstones. The next distinct request is permanently refused after the lifetime ceiling. | `fenced_transition.rs::FENCED_TRANSITION_MAX_HISTORY_ENTRIES`; `consensus/native/v1.rs`; `sqlite/consensus.rs`; `fenced_transition_journal.rs` |
| Fenced transition V2 | 131,072 bindings per writable epoch, one writable plus seven replayable epochs, at most 1,048,576 retained bindings. Rotation and bounded reclamation prevent a lifetime ceiling, but the 24-hour replay-retention requirement and finite replay epochs impose a rolling capacity ceiling. | `fenced_transition.rs::FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES`, `FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS`, `FENCED_TRANSITION_OUTCOME_RETENTION`; `consensus/native/lifecycle.rs`; `sqlite/consensus.rs` |
| Protected transition journal V2 | Mirrors the retained-epoch/count ceilings above; additionally limits each of 4,096 hash buckets to 512 retained entries. A full bucket can refuse before the aggregate cap. Reclamation follows epoch retirement. | `fenced_transition_journal.rs::V2_JOURNAL_BUCKET_MAX_ENTRIES`; V2 journal insertion and membership validation |
| Membership history | 4,096 predecessor-history entries and 4,096 retained terminal transitions. New transitions return `CompactionRequired` at the boundary. Production retains both histories; the test-only predecessor-compaction helper moves predecessors into history and does not reclaim that history. No production deletion path was found, so this is a cumulative bound. | `sqlite/consensus.rs::MEMBERSHIP_HISTORY_MAX_ENTRIES`, `read_membership_history_sync`, `read_membership_terminal_history_sync`, `retain_completed_terminal_in_tx` |
| Native retained key state | Native validation and image/catalog readers limit key state, ordinary receipts and notifications to 1,048,576 entries. Retained key fencing floors can outlive session deletion, so distinct historical keys require a lifecycle audit; receipt/notification limits must be assessed with their pruning paths. | `consensus/native/validation.rs::MAX_ITEMS`, `validate_frontiers`; `consensus/native/image.rs`; `consensus/native/generation_catalog.rs` |

Limits requiring a different classification:

| Limit | Why it is not by itself a cumulative-operation quota |
| --- | --- |
| Roster live reservations: 1,024 | Counts unresolved live work and releases on terminalization. The admission API still needs backpressure instead of refusal. |
| Protected V2 recovery journal: 4,096 | Counts live recovery obligations; exact resolution or authenticated retired-floor reclamation removes rows. Its fail-fast admission behavior is a separate backpressure concern. |
| Native Raft log: 1,048,576 retained entries | Bounds the retained suffix. Purge reclaims entries; the full-bound lifecycle proofs establish reuse. It must not be confused with the monotonically increasing log index. |
| Scan pages, reclaim batches, transport batches, ownership cache and payload cache | Bound one operation or evictable resident state. They do not count all historical completions. |
| Recovery inspection row/byte ceilings and snapshot physical size | Bound an inspection or artifact. They must remain distinguishable from protocol admission limits, and cannot reject otherwise valid roster state merely because the old roster quota was reached. |
| Fence, credential, sequence, history epoch and generation integer exhaustion | Checked representation limits, generally `i64::MAX` for SQLite interoperability. Retain overflow rejection; these are not a justification for small operational quotas. |

All paths above are relative to `crates/opc-session-store/src/`. Follow-up
verification must trace each claimed reclamation path, including restore and
restart; renaming a cumulative counter to a capacity counter does not fix it.
