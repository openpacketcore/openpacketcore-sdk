# RFC draft: Bounded configuration consensus capacity

**Status:** Proposed; no larger-configuration capability is qualified or enabled.

**Date:** 2026-09-22

**Tracking:** Refs #957. Sequential RFC number pending allocation.

## Problem and scope

At main `4db544930c3bdab3c99609d85f159b62484e2a5b`, configuration admission
limits the complete postcard command to 1,048,576 bytes. A configuration of
that size cannot fit after encryption and metadata. The generic replication
batcher's oversized-singleton rule does not change this admission fence.

Propose a **1,572,864-byte (1.5 MiB) logical configuration limit**, with the
separate limits below. The guarantee covers a valid configuration and valid
metadata that satisfy every independent bound, sufficient admitted storage,
and the existing authority/durability requirements. It does not promise that
arbitrary replay plans or audit histories fit because the configuration fits.
The same limits apply to local and forwarded writes, ordinary and audited
commits, confirmed successors, and rollback successors.

The new profile is explicit opt-in. Existing constructors retain the current
admission profile; metadata-heavy existing writes must not silently acquire
smaller replay or audit allowances. A larger-profile store and its plaintext
adapter must select the same immutable profile before use. Qualification and
the new capacity promise apply to that profile, not to legacy callers.

Logical bytes mean the UTF-8 bytes emitted by the SDK's JSON serialization of
the configuration value alone. They exclude the encrypted replay wrapper,
AEAD framing and audit records. They are neither Rust heap size nor the size
of an incoming protocol document. Whitespace in a protocol request, transport
encoding, Kubernetes objects and session-value limits define other budgets.

This RFC changes configuration capacity only. It preserves the shared 2 MiB
RPC ceiling, 1 MiB replication target, snapshot chunk size, clocks, deadlines,
proposal-slot count, storage engines, native WAL, and explicit Durable/Async
semantics. It does not qualify #683, #741, #923, protocol auditing or audit
export cryptography. It introduces no consumer-side fragments or new crypto.

## Current limit map

These are source observations, not runtime qualification. Paths are relative
to the repository root at the revision above.

| Boundary | Current limit or gap | Source |
| --- | --- | --- |
| Logical configuration JSON | Optional caller-configured `ConfigBus` limit; asks the model for its size. No common consensus capability limit. | `crates/opc-config-bus/src/commit.rs`, `enforce_candidate_payload_limit` |
| Encrypted plaintext | Version-2 JSON wrapper contains config, source, replay key, apply plan, request fingerprint and request ID. Serialization allocates before consensus admission; no separate replay-byte ceiling. | `crates/opc-config-bus/src/datastore.rs`, `ConfigPlaintextV2Ref`, `EncryptingDatastore::encrypt_record` |
| Crypto envelope | 16-byte header; key ID at most 512 bytes; nonce 12 or 24 bytes; tag 16 bytes. AAD length uses a `u32`; custody modules separately cap bound AAD at 65,536 bytes. Envelope parsing alone is not a logical-size policy. | `crates/opc-crypto/src/lib.rs`, `CryptoEnvelopeV1`; `crates/opc-key/src/{scope,custody}.rs` |
| Fresh-write attestation | The opaque claim binds envelope bytes and plaintext digest, but carries no logical/replay length or capacity profile. Public direct attested writes need not pass through the plaintext adapter. | `crates/opc-crypto/src/lib.rs`, `AuthenticatedEnvelopeClaim`; `crates/opc-persist/src/types.rs`, `AttestedConfigCommit`; `crates/opc-persist/src/consensus/store.rs` |
| Principal and replay lookup | Stored principal at most 16,384 bytes, including adapter JSON wrapper; replay lookup is a 64-character digest. Rollback label at most 128 bytes. Plaintext replay data remains encrypted. | `crates/opc-persist/src/consensus/types.rs`; `crates/opc-config-bus-consensus/src/lib.rs`, `PersistedBusMetadata` |
| Configuration audit | At most 16,384 records; each path at most 8,192 bytes before and after predicate tokenization. Values become fixed redacted strings. Individual maxima do not imply their Cartesian product fits a command. | `crates/opc-persist/src/consensus/types.rs`, `PreparedConfigCommit` |
| Canonical audit chain | A separate management-audit canonical field stream caps its encoding at 1,048,576 bytes. This is not the postcard command ceiling or a ciphertext limit. | `crates/opc-persist/src/types.rs`, `calculate_audit_chain_hmac` |
| Audited effect and recovery | Audit-authority authenticated JSON has a 16,777,216-byte ceiling; encoded recovery handles have an 8,192-byte ceiling. The ledger admits 3–4,096 events and 1–1,024 operations, with three event slots reserved per operation. Unresolved operations retain unused reservations. | `crates/opc-persist/src/audit_authority/ledger.rs` |
| Complete command | 1,048,576 bytes, including maximum leader-selected timestamp in the preflight probe. Ordinary and audited submission both enforce it. | `crates/opc-persist/src/consensus/store.rs`, `preflight_config_command_replication_budget`; `store/audit.rs` |
| Private serialization/RPC | Complete postcard payload at most 2,097,152 bytes. Exact configuration wire revision is 7. Forwarding adds compatibility and remaining deadline; replication adds vote/log/membership framing. | `crates/opc-consensus/src/{codec,transport}.rs`; `crates/opc-persist/src/consensus/{types,raft_adapter,store}.rs` |
| Outer authenticated transport | Encoded frames negotiate from 9,437,184 to 16,777,216 bytes. Default server connection ceiling 128; one in-flight call per client connection. These are separate from inner postcard limits. | `crates/opc-session-net/src/{protocol,consensus}.rs` |
| Replication batching | At most 64 entries and soft target 1,048,576 serialized entry bytes. An oversized first entry closes its batch; the complete singleton RPC must still fit. | `crates/opc-consensus/src/{codec,profile}.rs` |
| Durable log serialization | JSON entry at most 16,777,216 bytes; append callback at most 1,024 entries and 67,108,864 encoded bytes. JSON byte arrays expand independently of postcard. | `crates/opc-persist/src/consensus/sqlite.rs` |
| Proposal concurrency | Eight accepted proposals per node. Accepted-work supervision retains the permit after caller cancellation. Waiting callers and pre-admission clones/serialization are not bounded by those permits. | `crates/opc-consensus/src/profile.rs`; `crates/opc-persist/src/consensus/store.rs` |
| Snapshot creation/transfer | SQLite body at most 68,719,476,736 bytes plus 50-byte footer; 1,048,576-byte chunks/copy buffers; at most 8,192 directory entries; storage operation bound 60 seconds. Existing profile triggers after 4,096 logs and retains 1,024 logs. | `crates/opc-persist/src/consensus/storage.rs`; `crates/opc-consensus/src/profile.rs` |
| Retained history | Explicit limits support 2–1,000,000 records and 1–1,073,741,824 canonical bytes. They become authoritative through acknowledged retention; they are not a default total database-size cap. | `crates/opc-persist/src/consensus/history.rs`, `ConfigHistoryLimits` |
| Exact-operation results | Ordinary internal results expire after a 4,096-applied-sequence window; they have no public read-only lookup. Audited operations have a distinct caller-bound lookup and bounded ledger. History, ordinary results and audit reservations have different retention rules. | `crates/opc-persist/src/consensus/sqlite.rs`, `read_outcome_sync`; `store/audit.rs`, `lookup_audit_operation` |
| Reopen and restoration | Retained admission has a caller-selected byte budget, at most 68,719,476,736 bytes, for database plus recovery journals. Snapshot restore checks identity, checksum, membership, schema and bounded log/record structure. Disk space, journal space and validation copies remain separate requirements. | `crates/opc-persist/src/retained.rs`; `crates/opc-persist/src/consensus/{storage,sqlite}.rs` |
| Readback/watch | Local history pages at most 64 records. Remote watch requests at most 16,384 bytes, responses at most 8,388,608 bytes, 32 concurrent connections and 256 client identities. Existing adaptive paging halves an oversized request down to one record while preserving its cursor. | `crates/opc-persist/src/types.rs`; `crates/opc-config-bus-consensus/src/remote_watch.rs`, `load_page_adaptive` |
| Aggregate memory/storage | Existing component limits do not constitute a whole-process RSS cap or an automatically provisioned storage budget. Generic config models can have arbitrary heap amplification. | All boundaries above; qualification must measure composition. |

## Proposed byte contract

All comparisons are inclusive; one additional byte rejects. Size accounting
must use checked arithmetic and the actual encoders, including length prefixes,
escaping and field discriminants. It must not trust an application-supplied
length, inspect plaintext inside consensus, or allocate the rejected encoding.

| Quantity | Maximum bytes | Definition |
| --- | ---: | --- |
| Logical configuration | 1,572,864 | Exact serialized configuration JSON |
| Encrypted replay/framing overhead | 65,536 | Complete AEAD plaintext length minus logical length; includes version magic, JSON wrapper, source and every replay field |
| Complete AEAD plaintext | 1,638,400 | Logical plus replay/framing; both constituent limits also apply |
| Bound AAD | 65,536 | Complete bound AAD, including key binding |
| Key ID | 512 | Existing key-ID maximum |
| Nonce | 24 | Worst supported algorithm; actual algorithm length must match |
| Crypto framing and expansion | 66,104 | 16 header + 512 key ID + 24 nonce + 65,536 AAD + 16 tag |
| Complete encrypted envelope | 1,704,504 | Complete plaintext plus worst crypto expansion |
| Non-envelope command metadata | 196,608 | Complete command encoding minus envelope byte content; includes the envelope length prefix, record, principal wrapper, finalized audit, operation handle/binding, resolutions, identity, request ID and maximum logical timestamp |
| Sum of component ceilings | 1,901,112 | Envelope plus non-envelope metadata maxima; arithmetic upper bound, not evidence that every maximum is jointly reachable |
| Complete configuration command | 1,966,080 | Dedicated hard ceiling; leaves 64,968 bytes beyond the combination above |
| Complete private RPC | 2,097,152 | Unchanged; 131,072 bytes beyond the command ceiling for engine/forwarding framing |
| Complete durable JSON entry | 16,777,216 | Unchanged; exact serialized-entry preflight is also mandatory |

This choice admits values strictly above 1 MiB without widening a shared
transport family or borrowing session-roster exceptions. The remaining RPC
allowance is a budget to verify with worst-case real encoders, not proof from
subtraction alone. Tests must construct maximum timestamps, terms, indexes,
node IDs, parent/resolution fields and compatible audited-operation metadata.
Use valid, reachable combinations for public success tests. When independent
earlier limits make an encoding ceiling unreachable, test that encoder directly
at and above its ceiling and separately prove rejection at the earlier public
boundary. A malformed fixture or an earlier rejection is not an at-limit
success observation for the later boundary.

The existing per-field metadata limits still apply. The 192 KiB aggregate
metadata allowance is an additional explicit capacity bound. A valid 1.5 MiB
config with metadata at that aggregate maximum must succeed; an over-budget
audit list must reject without dropping records or weakening redaction. The
plaintext digest is exactly the existing SHA-256 shape for new attested writes.

## Logical-size attestation

An envelope-byte limit cannot establish the logical limit. A 1,572,865-byte
configuration with small replay overhead can fit within the envelope allowance
reserved for a valid at-limit configuration with maximum replay overhead. An
adapter-only check would therefore leave direct attested writes unbounded by
the promised logical limit once the current command fence is widened.

The larger profile must require opaque SDK-produced size evidence bound to
the exact encrypted serialization, its existing plaintext digest and the
selected profile. The evidence must distinguish logical bytes from replay
bytes; caller-supplied lengths or a capacity flag are insufficient. All direct,
audited and adapter entrypoints must carry and validate it before effects.
Forwarding must preserve the validated binding under the authenticated peer
contract. Missing or mismatched evidence rejects new larger-profile writes.
Existing claims remain valid for the legacy write profile and historical read
compatibility; they do not implicitly authorize larger-profile admission.

The public construction and transfer API for this evidence is still a blocking
design decision. The existing `AuthenticatedEnvelopeClaim` and
`AttestedConfigCommit` do not supply it. Extending these exact boundaries needs
an explicit ownership handoff and API review before source edits. This RFC
does not prescribe consumer cryptography or assert that a new cryptographic
primitive is necessary.

## Admission and compatibility

1. The plaintext adapter obtains the immutable capacity profile from its
   sealed datastore. It reserves bounded preparation work before copying or
   serializing input. A counting/limited writer enforces logical and full
   plaintext limits using the same serialization as encryption. Stateful or
   inconsistent serializers must not bypass the limit on the bytes actually
   encrypted. Over-limit plaintext/replay rejects before key-provider calls,
   encryption, audit-intent admission, transmission or durable mutation.
2. Envelope/AAD limits and finalized aggregate metadata are checked before
   consensus submission. Preflight covers the eventual audited mutation
   before its audit intent is admitted. Rejecting the mutation after reserving
   a durable audit intent is too late to establish this no-effect property.
3. Leader-local and forwarded paths share one borrowed size calculation for
   the complete command, singleton AppendEntries, forwarded request and
   durable JSON entry, with maximum-width engine fields. The receiver repeats
   validation before accepting proposal ownership. Do not serialize a large
   temporary command merely to measure it.
4. The eight existing accepted-proposal slots remain unchanged. An additional
   bounded preparation reservation must cover local callers and inbound
   forwarding before SDK-owned clones/decoding. Capacity exhaustion returns a
   value-free rejection before that attempt submits; it cannot create an
   unbounded queue of large prepared commands. The result is definite only if
   no earlier transmission of the same operation remains uncertain. A sent
   proposal retains its reservation until its supervised completion, even after
   timeout/cancel.
5. The normal apply transaction retains exact parent/version, replay, audit and
   retention checks. No partial fragments, second writer or alternate durable
   engine are introduced. Genuine post-transmission uncertainty remains
   indeterminate; callers recover the exact original operation read-only.
   A later peer's capacity rejection cannot prove that an earlier peer did not
   commit. Route retries and leadership changes must preserve that uncertainty
   until an authoritative lookup resolves the exact operation. A known commit
   result must not become a reported failure because subsequent bookkeeping
   failed.

Expose a named immutable capacity profile and value-free rejection categories
for logical bytes, replay bytes, envelope/AAD, metadata, command/RPC, storage
serialization and resource admission. Final public symbols require the RFC's
API review. Existing error classifications and known commit outcomes remain
truthful; errors must not contain payloads, identities or provider details.

Advertise the larger capability only on peers that agree on its exact profile
and revised config wire/command admission contract. Mixed fleets fail closed
before formation or mutation; no silent downgrade is allowed. Existing
revision-1 through revision-7 durable commands remain readable under their
original semantics. New aggregate bounds must not make old accepted history
unreadable. Profile agreement must cover AppendEntries and InstallSnapshot as
well as forwarded writes and read barriers. Opening a retained larger-profile
store with a legacy-only profile must refuse before original WAL recovery;
checking only the later consensus-store constructor is too late. The immutable
retained binding and snapshot validation must prevent accidental downgrade.
Snapshots must carry a validated source capacity profile while preserving the
destination's local authority binding. A local-only binding omitted from the
snapshot does not establish compatibility. These are additional exact-symbol
handoff and implementation prerequisites. Provision the new profile explicitly;
an existing store is not silently promoted. Any migration needs its own reviewed
procedure and compatibility evidence.
Shared transport and session profiles remain byte-identical.

## Resource and recovery contract

The proposed preparation/admitted-mutation envelope is **eight reservations
of at most 32 MiB per node (256 MiB aggregate)**. This is a proposed bound for
SDK-owned mutation working buffers, not a claim about total RSS. The
implementation must inventory every live original/clone, ciphertext copy,
postcard buffer, JSON log buffer and decoded audit allocation, and reject
before exceeding its reservation. Count allocated capacities and overlapping
lifetimes, including rejected inbound decoding and leader fan-out, rather than
only payload lengths. If that inventory cannot fit, the RFC must
be revised before admission changes; an unmeasured multiplier is not evidence.

Account separately for caller-owned arbitrary config objects, Openraft retained
entries/channels, SQLite caches, TLS/outer frames, peer connections, history
readback and snapshot operations. The authenticated transport's connection and
frame limits remain fixed. The qualification profile must state the actual
connection count and prove aggregate transport occupancy, including rejected
and cancelled inbound traffic and the existing maximum of nine members. A
three-node functional test does not qualify the maximum fan-out. Config
admission cannot claim to bound memory already allocated by an unrelated
transport listener.

Snapshots remain file-backed and chunked. Installation must restore the full
configuration, audit and replay binding atomically with the applied frontier.
Test the chunk boundary, nonzero offsets, missing/truncated/tampered chunks,
oversize body/footer and concurrent operations without relaxing timeouts.
Retained reopen uses the same original identities, paths and durability mode;
creating new storage is not reopen evidence.

Ordinary exact-operation recovery needs a public caller-scoped, read-only
lookup contract; the current internal result cache and mutation retry API do
not supply it. Qualify recovery within its existing 4,096-applied-sequence
window, including reopen and snapshot transfer. A missing or expired result
outside a proven coverage window remains unresolved: it is not evidence of
noncommit and does not authorize another operation identity. Any additional
proof from retained history must identify exactly which original operation it
covers. Audited recovery uses its distinct caller-bound operation handle and
ledger rules. The final API must document both windows and their negative
results without widening retention or silently introducing mutations.

History retention is explicitly acknowledged. The existing ordinary-result
expiry does not authorize pruning unresolved audit reservations or other
evidence outside its own retention contract. Admission must account for
the configured canonical history budget, JSON log expansion, live database,
native journals, snapshots and validation/restore copies. A fresh database with
unlimited history is not a bounded storage qualification. The final profile
must state retained-record count, canonical bytes, physical high-water marks,
snapshot overlap and required free-space reserve. Existing snapshot/reopen
ceilings remain hard ceilings, not a promise of completing a maximum-sized
database transfer within every deployment's fixed deadline.

One at-limit record must read back locally and remotely. Qualify the existing
adaptive remote page path: an oversized page shrinks without advancing past
undelivered records, and a one-record response fits with worst metadata. An
unrepresentable single record must fail explicitly. Never silently omit
committed records. Restore and read paths distinguish historical compatibility
from admission of new writes.

## Qualification required before capability delivery

Every row requires exact base/head/tree, settings and retained results. Current
status for all runtime rows is **missing**. A setup failure is not a detector
failure, and component loopback evidence is not production transport evidence.

| Row | Required observations |
| --- | --- |
| Runtime detector | A real encrypted, attested configuration above 1 MiB fails the proposed success assertion on the original source. A smaller control commits and reads back. Preserve the original result. |
| Logical boundary | At 1,572,864 bytes succeeds; 1,572,865 rejects before provider/audit/consensus effects. Exercise escaping, multibyte strings, inconsistent size reporting and direct attested entrypoints that bypass the adapter. Reject absent, mismatched or reused size evidence. |
| Replay/encryption | At-limit config plus maximum replay/framing, key ID, algorithm nonce/tag and bound AAD; one-over each independently; exact ciphertext/decrypted readback. |
| Metadata/serialization | Aggregate metadata at/one-over 196,608; raw and tokenized path boundaries; principal/label/count bounds; actual command, worst singleton/forwarding, JSON log and authenticated audit-effect encodings, and recovery-handle bounds. |
| Routing/atomicity | Real three-node authenticated transport and retained disk; leader-local and follower-forwarded ordinary/audited/confirmed/rollback successors; exact all-or-nothing config, audit and replay readback. |
| Ambiguity/leader loss | Lose the original leader and lose the exact operation's response independently; then exercise a later peer's capacity rejection. Recover the original ordinary/audited operation read-only, preserving uncertainty and known results without another mutation identity. Exercise ordinary results inside and outside the retained sequence window. |
| Profile compatibility | Reject mismatched profiles on every mutation and replication RPC family, retained reopen before original WAL recovery, and snapshot installation before effects. Prove legacy-history reads and no implicit promotion or downgrade. |
| Reopen | Retain original roots and identities after orderly and unclean process loss; prove pre-catch-up restoration, then convergence and exact decrypt/readback. Preserve corruption and stale-fence negatives. |
| Snapshot transfer/restore | Force actual snapshot transfer to a lagging voter, then reopen installed state; prove configuration, lineage, audit and exact-operation recovery across the transfer. |
| Concurrency/memory | Saturate all eight slots with at-limit inputs; observe allocated capacities, exact reservations and high-water marks; one-over admission, cancellation, response loss and shutdown conserve ownership. Include rejected decoding, maximum nine-member fan-out, transport and snapshot overlap. |
| Remote history | At-limit records and worst metadata read back through adaptive paging under the existing response ceiling, with exact cursor continuity and no omission. |
| Storage | Configured history at/one-over, JSON entry/append bounds, retained-validation budget and snapshot bounds reject at their supported boundary; retained free-space and journal measurements fit the stated profile. |
| Causal validation | Remove only the fix and retain RED; apply a distinct adversarial mutation, such as bypassing aggregate metadata or releasing a reservation on caller cancellation, and retain its failing detector. Restore the exact fix and pass. |
| Delivery | Current full repository/hosted gates, independent full-diff review of the exact candidate, refreshed-main integration and tested-tree identity. No issue closure from partial evidence. |

## Review and implementation sequence

First review this contract and its source map. Governance requires discussion,
maintainer approval before RFC merge, and implementation PRs that reference the
approved RFC number. It does not prohibit authorized local preparation.
Repository Discussions was disabled when this draft was prepared; the
maintainer must provide the discussion venue or an explicit disposition of that
prerequisite. This draft makes no approval claim and does not enable a larger
value. Author adversarial review does not supply the separately required
independent full-diff review.

The exact shared boundary needing coordination is
`EncryptingDatastore::encrypt_record` / `ConfigPlaintextV2Ref` and a capacity
policy port on `ManagedDatastore`, plus the sealed consensus adapter's policy
override. Additional exact boundaries identified by adversarial review are
the claim/commit size-evidence transfer and retained-profile validation before
WAL recovery. Their API designs and handoffs remain open. The ordinary
read-only recovery API and its coverage semantics also require review.
Required-audit sequencing and authority custody remain with their owners.
Public exports and the final RFC number require a recorded handoff. No
transport-budget, manifest or dependency expansion is proposed by this draft.

Prepare the original-behavior detector and bounded implementation design while
these decisions are reviewed. Before delivering a wider admission fence,
complete the approved plaintext/sealed admission and resource contract, qualify
every row, and integrate against current main. The existing 1 MiB command fence
remains in place in this contract slice. Follow-up
assessments of #724 and #683 begin only after #957 has complete evidence;
those assessments do not authorize their implementations.
