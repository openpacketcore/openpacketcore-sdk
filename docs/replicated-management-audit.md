# Replicated management audit and operation recovery

Tracking: #796, #797, #798. This document describes the configuration-authority
slice of #797. Protocol-server composition and #798's multi-epoch,
export/checkpoint and safe-pruning contracts remain separate acceptance work.

## Authority and storage

`opc-persist::ConsensusConfigStore` owns one management ledger in the existing
configuration Openraft state machine. It does not open another SQLite owner,
create a second quorum, or change native session WAL, Durable/Async modes or
call-session admission. Intent, denial and terminal entries do not increment
the configuration revision. The replicated order is authoritative; an event's
source time is descriptive and cannot order competing voters.

The bounded ledger is explicitly initialized once. A signed inactive row is
created with new configuration authority, so deleting an active row cannot
make the ledger look uninitialized. Its identity includes the exact
configuration fleet/epoch. The existing configuration authentication key
purpose-separates handles, entries and the authenticated state root. No key
material enters a command, receipt, snapshot or diagnostic.

The current slice uses one fixed signing epoch. Replacing that key is not a
rotation protocol. A coherent rollback of the database and its local anchor
is not detectable from this slice alone. Do not claim #798's external
checkpoint or complete-range export guarantees from it.

## Privacy and preparation

`AuditPrivacyProjection` processes typed, length-delimited, purpose-separated
fields before queue admission, replication or storage. The SDK HMAC provider
uses separate explicit material from the signing key; an approved external
provider may implement the same contract. Length checks alone are not privacy
projection. Tenant, principal, request, transaction, schema paths and reason
become keyed opaque tokens. `AuditCaller` must come from trusted authenticated
context, never from an unauthenticated request or a decoded handle.

The trusted application must enforce authorization before preparation. These
SDK ports bind and recover authorized work; they do not replace NACM or infer
a principal's permission from possession of a handle. Handles, prepared
mutations and encoded exports of them are protected recovery data, not log,
metric, status or error values. Their Debug representations are redacted.

`prepare_audited_commit` consumes an authenticated, freshly sealed config
commit and binds its exact ciphertext, parent, revision, mode and confirmation
resolution. Separate typed methods bind confirmation and rollback-point
mutations. The handle's fixed expiry, authenticated caller and operation/base
binding cannot be changed. A prepared object grants no admission authority.
Its encoded recovery form is bounded and authenticated again at submission.

Standalone intents and observations use the same handle protocol. An observed
`Success` is explicitly `Observed`, never an authoritative configuration
`Committed` result.

## Required call sequence

1. Prepare and securely retain the exact handle/prepared mutation before
   awaiting admission. A client may lose a response at every later boundary.
2. `admit_audit_operation` replicates the intent and reserves capacity for the
   authoritative outcome and terminal record. Only an `Applied` receipt for
   that exact intent permits submission. `Unknown` or `Rejected` forbids it.
3. `submit_audited_mutation` requires the acknowledged receipt. It verifies the
   exact prepared bytes again. The state machine checks the admitted intent,
   fixed expiry and base revision, then atomically applies configuration and
   its result in one transaction. A logical rejection rolls back the config
   effect while preserving a durable rejection. Storage failure rolls back
   both and leaves the caller uncertain.
4. `finish_audit_operation` consumes the reserved terminal slot. Failure or
   response loss cannot rewrite a committed result as failure.
5. `lookup_audit_operation` authenticates the handle and caller, takes a quorum
   barrier and reads the exact retained result. A stale or substituted handle
   cannot authorize a different operation. A duplicate returns the original
   result. `None` never authorizes a newly minted retry; an expired absent
   handle returns `Expired`.

The applying state machine includes an authenticated receipt in its existing
durable response cache. A successful response carrying a settled outcome is
verified against the exact operation and caller and returned without requiring
a second quorum read. Losing read quorum after that response cannot erase a
known commit or rejection. This receipt proves the outcome at that apply point;
authorized lookup returns the current terminal-record status. An intent-only
response is refreshed because its undecided state may have since resolved.

Once the ledger is enabled, legacy append, confirmation and rollback-point
mutation commands are refused by the state machine. This prevents callers from
bypassing the required intent. Internal recovery-marker clearing and explicit
acknowledged configuration retention remain their existing typed operations.
Consumers must compose the audited API before enabling this ledger; simply
replacing a local `AuditSink` does not upgrade an existing config-bus adapter.

## Recovery and bounded work

The existing proposal supervisor retains accepted work after caller
cancellation. The durable ledger retains a known commit even when its terminal
acknowledgement or client reply is lost. Restart uses the same signed ledger
and Openraft snapshot; no process-local map is recovery authority.

`reconcile_audit_obligations(limit)` is a privileged, bounded maintenance port
for the management supervisor. It completes known outcomes idempotently and
rejects abandoned intents only after their fixed deadline. A competing commit
and rejection are serialized by the same state machine. Recovery does not
extend an expiry, invent a new operation or blind-replay configuration. Live
intents cannot starve later actionable terminal work. Unknown results remain
pending for another authoritative read. The consumer must invoke this port
at startup and during maintenance; no detached second storage owner is spawned.

Each intent reserves three events. All reservations count against the admitted
limits before mutation. Denial observations need one event. Full capacity
refuses new work while preserving reserved outcome/terminal capacity. An
unfinished operation protects its referenced configuration base/result from
configuration-history retention. No management-history pruning exists in this
slice; safe reclamation requires #798's export/checkpoint boundary. Therefore
this bounded initial slice eventually refuses new admission if history is not
safely reclaimed by the completed retention implementation.

## Representation cutover

The additional durable authority advances configuration command/RPC revision
to 5 and configuration storage/snapshot representation to 3. Command revisions
1 through 4 retain their original semantics and ordinal encodings. Revision 4
remains the minimum for the older retention command. New audit commands require
revision 5. These revisions are independent of session-store transport/WAL.

Representation-1 and representation-2 databases/snapshots are refused. A binary
restart is not a migration, and a missing ledger row is not permission to reset
history. This change supplies no automatic conversion, downgrade path or
operator authorization to delete retained authority. Preserve old files and
use only an explicitly reviewed cutover/recovery procedure before deployment.

## Evidence boundary

Synthetic real-quorum tests independently check the audit receipt and config
revision across lost intent/config/terminal acknowledgements, caller
cancellation after apply, leader replacement, retained restart and exact retry.
Other detectors cover changed handles/payloads, unauthorized lookup, standalone
denials, hard capacity, stale bases, fixed expiry, recovery fairness, protected
config-history references and missing durable authority. Model tests cover
purpose separation, authenticated fields and order/roster corruption.

These tests do not prove deployed storage/network behavior, a product release,
key rotation, rollback resistance against whole-database restore, or complete
northbound recovery. No private product, subscriber or deployment fixtures are
part of this contract.
