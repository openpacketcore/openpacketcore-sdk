# RFC 019 extension: Retained NETCONF targets and lifecycle authority

**Status:** Proposed format and API extension. The retained-target approach is
selected. This document must complete review and merge before architectural
implementation; it does not declare the full profile available.

**Date:** 2026-09-24

**Version:** 0.2.0

**Parent:** [RFC 019](019-netconf-required-audit.md). Refs #958.

## Scope and availability

The full required-audit profile places encrypted candidate and startup state in
the existing configuration consensus authority. Staging, discard, copy, startup
writes and protocol lifecycle transitions depend on that authority and its
independent audit checkpoint service. An unavailable authority cannot be replaced
by a local candidate edit or a successful application audit callback.

The existing writable-running required-audit profile remains available. Legacy
volatile candidate and synchronous startup implementations retain their behavior
outside the full profile. Full-profile attachment explicitly refuses an arbitrary
startup implementation or a datastore without the closed target capability.

There is one logical NETCONF device owner per configuration authority. This is
distinct from its replicated voters. Starting a replacement device owner is an
explicit retained lifecycle transition. Starting a voter or a checkpoint provider
does not make that transition. The embedding application must use the SDK device
owner lifecycle before serving authenticated NETCONF sessions; possession of a
database connection or a numeric session identifier grants no such ownership.

## Public capability and result contract

The following additions are SDK-owned types with private fields, validated
constructors and redacted `Debug`. They are proposed APIs, not existing symbols.

| Type or operation | Contract |
| --- | --- |
| `ConfigBus::required_netconf_audit` | Returns `RequiredNetconfAudit<C>` only when the exact worker has both the existing required running port and the reviewed retained-target port. Default/custom datastore implementations refuse. |
| `ReadOnlyNetconfServer::with_required_netconf_audit` | Attaches that capability and its observation sink. Checks exact worker, target profile and device ownership at attachment and each dispatch. Never hides an advertised capability or grants NACM/principal authority. |
| `CandidateGeneration`, `StartupRevision` | Distinct authority-scoped, checked `u64` counters. Neither converts to `ConfigVersion`. Zero denotes only the authenticated initial absent state. Deletion/discard retains a tombstone and advances the counter. |
| `NetconfDeviceOwner`, `NetconfSessionOwner`, `NetconfLockLease` | Authority-minted incarnation-bound capabilities. Session ownership binds authenticated caller and device incarnation; each lock lease also binds its datastore and monotonically increasing lock incarnation. Numeric NETCONF session IDs remain correlation only. |
| `NetconfTargetRequest<C>` | Original request/caller/transport, fixed expiry, exact target/action, expected generations, immutable validated content and authenticated source selection. No request field asserts that an effect already happened. |
| `PreparedTargetMutation` | Closed encrypted effect plus authenticated original operation handle, prepared by the SDK adapter/authority. No public field setters or construction from caller-asserted ciphertext digests. Encoding is bounded protected recovery data, never diagnostics. |
| `NetconfMutationResult` | A disjoint typed applied result, definite rejection, or unresolved original handle. A known result cannot become rejection because a later read/report failed. |
| Authorized lookup/recovery | Takes the original handle and independently authenticated caller/recovery capability. Lookup never submits a replacement effect, extends expiry, or treats a missing row as success. |

The typed applied result distinguishes `Candidate { generation }`,
`Startup { revision }`, `CopiedRunning { running_version }`,
`Promoted { running_version, retired_generation }`,
`Tentative { running_version, retired_generation, pending }`,
`Confirmed { pending }`, `RolledBack { running_version, pending }` and
`Lifecycle { incarnation }`. Pending and incarnation values are opaque scoped
tokens. Existing `AuditOperationState::Committed { version }` keeps its running
meaning and byte representation. New target outcomes use a separate variant;
no candidate generation or startup revision is encoded as a running version.

Session and lock ownership are not derived from user-supplied audit labels. The
SDK authenticates a session before issuing its owner capability. A replacement
worker over the same database cannot reuse the old worker's capability. Ordinary
running gNMI and NETCONF writes continue through their current required port;
when the full profile is active, its retained debt/lifecycle fences also apply
to those writes at the shared authority boundary.

The submission surface has these signatures (the proposed types above are not
yet available):

```text
ConfigBus<C>::required_netconf_audit(&self)
    -> Result<RequiredNetconfAudit<C>, StoreError>
ReadOnlyNetconfServer::with_required_netconf_audit(self, RequiredNetconfAudit<C>)
    -> Result<Self, ServerInitError>
RequiredNetconfAudit<C>::belongs_to(&self, &ConfigBus<C>) -> bool
RequiredNetconfAudit<C>::submit(&self, NetconfTargetRequest<C>, AuditEvent)
    -> Future<Output = NetconfMutationResult>
RequiredNetconfAudit<C>::recover(&self, &NetconfRecoveryHandle, &TrustedPrincipal)
    -> Future<Output = NetconfMutationResult>
```

`NetconfMutationResult` has `Applied(NetconfAppliedReceipt)`,
`Rejected(CommitError)` and `Unknown(NetconfRecoveryHandle)` variants. The receipt
exposes the typed outcome and terminal-recorded status; the recovery handle is
opaque and bounded. A rejected result guarantees no effect by that admission;
an unknown result grants no permission to resubmit different work. Separate
SDK lifecycle methods create device/session/lock capabilities only after current
authority and caller authorization; `submit` cannot mint them from request fields.

### Frozen edit preparation

The persistence preparation surface uses `ConsensusConfigStore::read_netconf_target`
to return an opaque `NetconfTargetRead` bound to the exact active worker/session,
destination counter, running base and lock. The encrypted target or absent-candidate
running fallback comes from the same authenticated transaction as its ledger and
checkpoint anchor. The independent checkpoint is verified before returning the
read. Absence retains its exact tombstone; reading never creates target content.

`NetconfTargetRead::decrypt_configuration` authenticates that frozen ciphertext
through the existing provider for the expected tenant, verifies its full plaintext
digest and returns zeroizing storage. The embedding worker remains responsible
for read authorization, parsing and model validation. This is an edit base, not a
replacement for the separate protocol read/observation path.

`NetconfTargetReplacement::edit` pairs the validated replacement with that original
read and an Update intent; `inline_copy` uses Replace for explicit inline content.
Neither asserts a copy relationship to another datastore. The authority's
`prepare_netconf_target_replacement` accepts the exact session, this immutable
input, original audit event and fixed lifetime. It never fetches a newer counter
to authorize content computed from an older read. The SDK creates the encrypted
target envelope using the existing provider and complete pre-encryption binding,
then rechecks retained expectations and reservations. Admission separately checks
the complete command and replication bounds before transmission. Provider failure
or cancellation during preparation admits no intent and permits no effect.

Datastore-copy selection requires its own authenticated source binding; presenting
inline content does not qualify that mutation mode. Once an original operation
may have been transmitted, recovery must use that operation rather than repeat
encryption or prepare a replacement. These preparation types do not activate the
full NETCONF runtime profile or confer recipient-only audit verification.

### Original running-copy read

`read_netconf_running_copy` returns an opaque `NetconfRunningCopyRead` before
content is prepared. It freezes the exact candidate/startup source or candidate
fallback, running destination version and running lock with the authenticated
ledger/device/session transaction and independent checkpoint. Its `source()`
uses the existing provider-backed read/decryption contract. The worker authorizes
and validates that original content before preparing an attested running envelope.

`NetconfRunningCopy::new` pairs that envelope with the original read, and
`prepare_netconf_copy_to_running` authenticates the frozen source and destination
for the event's tenant. It never selects a newer source during preparation.
Identical configuration in a newer source generation is still a different effect
and must not be substituted. Preflight and admission recheck the original source,
running version and lock; unknown transmission recovers only the retained original.
Copy into running preserves candidate/startup state and cannot install, confirm
or resolve a confirmed commit. This API does not activate the public target runtime.

### Ordinary candidate promotion preparation

`read_netconf_candidate_promotion` returns an opaque
`NetconfCandidatePromotionRead` for an actual staged generation whose original
session, caller and running base match. Its `candidate()` supplies the original
provider-backed content. The shared authoritative read verifies current locks,
ledger/device state and independent checkpoint. It refuses absent candidate,
running fallback, startup, pending confirmation and unresolved audit obligations.

`NetconfCandidatePromotion::new` pairs that read with the proposed attested running
envelope. `prepare_netconf_candidate_promotion` requires the original session and
NETCONF Exec Intent, expected tenant and provider-authenticated exact configuration.
The prepared action 6 retains the original generation and running base; preflight,
admission and application recheck them. Running commit and retirement of that
candidate are atomic; replay returns the original typed `Promoted` result without
advancing either again. Known promotion remains known when terminal persistence
is owed, and the retained obligation fences subsequent writes.

This ordinary preparation cannot install or resolve confirmed ownership. Empty
plain commit and confirmation require their distinct contracts below. These ports
alone do not activate the public full-profile NETCONF runtime.

### Frozen datastore-copy preparation

`ConsensusConfigStore::read_netconf_target_copy` returns a private-field
`NetconfTargetCopyRead` capturing a selected running/candidate/startup source
and a distinct candidate/startup destination in one pinned authority transaction.
Its ledger, current device/session, both lock owners and independent checkpoint
are verified before return. An absent candidate source binds its exact tombstone
and running fallback. An absent startup or running source is refused; the read
does not synthesize an authenticated configuration from defaults.

`decrypt_source` uses the existing provider, expected tenant and complete stored
plaintext digest. The worker authorizes both paths and validates the configuration
model, then pairs its immutable serialized wrapper with the original read through
`NetconfTargetCopy::new`. `prepare_netconf_target_copy` authenticates that same
source and compares exact serialized configuration bytes using the existing strict
config-only/V2 parser. New replay metadata may differ; copied configuration and
schema must remain the same. The destination envelope binds the original source
and destination before encryption. No consumer-supplied digest asserts equality,
and no provider or plaintext is retained in the operation or target state.

Preparation preserves the original target counter, running base, destination
lock and selected source even when state changes before it runs. Preflight and
application independently refuse stale originals. Intent admission, terminal
debt and original-operation recovery use the existing closed target path.
These ports do not activate the public NETCONF target runtime; running as a
destination continues to use its separate prepared running-copy port.

Datastore copies into candidate/startup enforce the selected source's current
lock owner as well as the destination's original lock expectation, matching the
existing running-copy rule. An absent-candidate fallback uses the candidate
source lock and still binds its exact running version and ciphertext. Acquiring
a foreign source lock after preparation prevents application without advancing
either target. Ordinary read observations do not use this mutation admission.

## Closed effect representation

`TargetEffectV1` is an explicitly tagged, bounded record. Its common fields, in
encoding order, are: format revision, authority identity, profile incarnation,
device incarnation, projected caller, original projected request, action,
destination expectation, source expectation, lock expectation, fixed expiry,
encrypted effect payload and effect-specific resolution. Optional fields use
explicit option tags; absent and empty content are different values.

Action tags are fixed within this new record: 0 activate, 1 begin device,
2 acquire lock, 3 release lock, 4 stage candidate, 5 discard candidate,
6 promote candidate, 7 replace startup, 8 delete startup, 9 tentative promotion,
10 confirm pending, 11 cancel pending, 12 expire pending, 13 end session and
14 reboot recovery and 15 copy to running. Unknown tags and trailing data are
rejected. Legacy command and effect tags are not renumbered.

Destination expectations contain the exact current target generation, not just
the desired successor. Source expectations bind source datastore, generation or
running version, immutable source ciphertext digest and schema. Copy preparation
authenticates/decrypts that exact source through the existing provider, then
constructs the destination envelope. Application rechecks the source expectation
and cannot silently fetch a newer source. The closed SDK preparation path binds
the source plaintext to the destination encryption; a caller's matching digest
claim alone is insufficient. When an absent candidate is read as the current
running configuration, the source expectation binds both its exact tombstone
generation and the exact running version/ciphertext used for that fallback.
Either changing before application invalidates the prepared copy.

Promotion carries the ordinary prepared running commit plus the exact candidate
expectation. The common running preparation/capacity contract is used unchanged.
It commits running state and retires the candidate in one existing authority
transaction. A delayed generation-A promotion cannot commit or clear generation
B. The applied outcome records both the running version and retired generation.

Copy from candidate or startup to running uses action 15 and a `CopiedRunning`
result. It carries the same bounded prepared running commit and exact source
expectation, but does not retire or modify its source. A candidate-to-running
copy therefore leaves the candidate generation and encrypted content intact.
All current lock and pending-resolution fences still apply; a copy cannot
silently resolve another pending operation. This is distinct from candidate
promotion and cannot be routed through an unbound read followed by ordinary
running submission.

Target encryption uses existing `KeyProvider`, `EnvelopeAad::config`,
`ConfigAad` and attested-envelope APIs. The target counter occupies the AAD's
generic numeric version field; it is never represented as `ConfigVersion`.
The target's store-kind domain is distinct from `running` and includes the
target/profile binding digest in a fixed canonical hexadecimal spelling.
Candidate, startup and confirmation-ownership domains are separate. The digest
is computed from the pre-encryption common binding, including authority, target,
source, destination, schema, caller and request. It excludes the destination
envelope bytes and MAC, avoiding a circular dependency. It is authenticated AAD, not a new
encryption algorithm or a substitute for provider attestation.

Principal/tenant metadata uses the existing projection and encrypted envelope
rules. Persistent confirmation credentials are encrypted through the same custody
seam, with their exact pending identity and device ownership in AAD. Raw tokens,
requests and configuration payloads do not appear in typed errors or diagnostics.
Legacy running plaintext wrappers and authentication domains remain unchanged.

The running payload's `provider-copy` form binds source and destination
ciphertext digests, their separate complete plaintext digests, and schema under
the original effect MAC. Only SDK preparation constructs it after authenticating
both exact envelopes with the existing provider. It compares the serialized
configuration bytes, without JSON value normalization or numeric conversion.
The existing config-only JSON format and the SDK's config-first V2 wrapper are
recognized; V2 request/replay fields remain inside their respective encrypted
envelopes and may differ. Duplicate/unknown wrapper fields and unknown formats
are refused. No configuration digest, plaintext, key, or provider object is
retained in this binding. A decoded binding is untrusted until the authority
authenticates the complete original effect. Application still checks the source
generation/version/ciphertext and its original complete plaintext digest.
An ordinary running payload continues to require equality of complete plaintext
digests. Provider verification is an online authority-preparation requirement;
this supplies no recipient-only or offline cryptographic capability.


## Admission, application and terminal recovery

Every changing full-profile action follows this order:

1. Enforce authentication, authorization, current configuration authority, device
   ownership, lock and source/destination expectations. Validate/encrypt through
   the existing SDK provider seam and preflight the complete eventual command,
   including audit metadata and terminal reservation. Reject before admission if
   any command, retained-state or reservation bound would be exceeded.
2. Retain the original closed recovery description with its required intent.
   The operation reserves its outcome and terminal capacity. Independently
   checkpoint that intent before allowing application. Rejected or indeterminate
   intent admission permits no effect, including local registry publication.
3. Apply the authenticated closed effect and typed outcome atomically in the
   configuration authority's application transaction. Revalidate current versions,
   ownership, expiry and all fences at that boundary. An admitted stale effect
   receives a definite retained rejection without partially changing a target.
4. Complete the original terminal/checkpoint obligation. Its failure cannot erase
   a known applied result. Retained debt fences subsequent configuration and
   target changes, including replacement lock/device admission, until exact
   original-operation reconciliation succeeds.

The ConfigBus worker and retained operation own completion after admission.
Dropping a protocol future cannot drop candidate retirement, confirmation
ownership or a lifecycle recovery fence. A protocol error after transfer does
not produce a second terminal or relabel a possible commit as a failure.

Exact request replay returns the original typed result without advancing any
generation again. Reuse with another action, source, target, caller or ciphertext
is rejected. Recovery never mints a new request to discover an old result. An
expired original handle can recover an already-established result under existing
authorization rules; it cannot authorize a newly applied effect.

If an expired operation is authoritatively resolved as unapplied/rejected, a
separately authorized recovery attempt may address the still-fenced lifecycle
event. It must first settle the original obligation; an unknown original outcome
never permits this replacement. The new attempt does not extend the original
confirmed deadline, change the pending parent or convert an earlier failure to
success. This distinction permits recovery after a long authority outage without
replaying a possibly applied operation.

## Retained state and compatibility

The target extension proposes config command/wire revision **9** and
storage/snapshot revision **7**. Revision 8 and storage/snapshot 6 are reserved by
the separate capacity contract. These numbers do not imply that an unimplemented
capacity profile is available. Implementation must preserve the exact landed
capacity variants and bounds, and qualify each supported profile combination.
The first target profile uses the currently supported capacity contract and
refuses combinations without a landed, qualified implementation.

To avoid colliding with capacity append variants, the target command is appended
inside the existing management-audit command family. At the inspected base,
`AuditCommand::NetconfTarget` follows `AcknowledgeExport` with index 9; outer
`ConfigMutationIntent::ManagementAudit` retains index 6. Its minimum command
revision is 9. The old running `AuditedConfigEffect` representation is unchanged.
If the shared base changes these indices, reconcile the contract before code;
never reuse an allocated tag or copy a parallel experimental implementation.

The storage extension adds three bounded authenticated tables to the existing
SQLite authority, not another database or storage engine:

| Table | Exact logical rows and body fields |
| --- | --- |
| `config_netconf_profile` | Singleton: format, authority, selected target/capacity profile, activation operation, original bootstrap checkpoint, current device incarnation, last target-transition sequence and state digest. |
| `config_netconf_targets` | Exactly candidate and startup rows: target tag, generation, present/tombstone tag, schema, encrypted envelope or absent marker, source/base binding and last applying operation. |
| `config_netconf_lifecycle` | Singleton: device ownership, three datastore lock slots, optional exact pending confirmation, original rollback parent/deadline, encrypted confirmation ownership, and bounded unresolved cleanup/recovery descriptions. |

Bodies use the repository's bounded JSON serialized-struct and authenticated-state
helpers. Field order follows the table above, field names use `snake_case`, and
fixed byte arrays retain the existing JSON integer-array encoding. Every body
has format 1; new outcome payloads have a separate `target-v1` tag. Decoders reject
unknown fields and invalid tags. The enclosing command uses the existing bounded
postcard codec; these body/tag definitions do not redefine that codec.
Target tags are candidate=0 and startup=1. Counters never wrap. Locks
have fixed running/candidate/startup slots. At most one pending confirmation and
one cleanup obligation per owned lock are retained; duplicate delivery refers to
the original obligation rather than growing an unbounded event list. Admission
accounts for the complete encoded bodies and reserved recovery descriptions
within the existing authenticated-state and complete-command bounds. Limits are
not multiplied by treating each field as independently entitled to the maximum.

The sealed authority table manifest, reopen validator, history validator and
snapshot copy/restore set include these exact tables and row invariants. Their
authenticated state digest binds authority, format, all row tags, generations,
ownership, ciphertext and unresolved obligations. Digest input uses the canonical
row bodies in profile, candidate, startup, lifecycle order and excludes the stored
state digest and MAC fields themselves. The resulting digest is covered by the
row authenticator; no self-referential digest is required. The applied target
outcome binds that digest into the existing authenticated audit history; the
profile anchor preserves this relation across acknowledged pruning. Tampering
with a target while retaining a valid unrelated running history must fail.

The snapshot body and envelope identify target and capacity profiles. Snapshot
construction captures validation, frontier and all tables from one pinned source
read transaction. Import verifies the independently admitted destination profile,
identity, authenticated body, lifecycle/audit checkpoint relation and table set
before replacing authority. An old-format or partial-body snapshot cannot clear
a newer target fence. All copies retain existing storage limits and deadlines.

Old ledger entries, running outcomes, effect encodings, key transitions and
independent checkpoints retain their original bytes and authentication. New
target outcome payloads are explicitly versioned and disjoint. Export manifests
bind the target format/profile and the frozen predecessor/terminal boundaries;
unsupported readers fail with typed errors. An ordinary mutation checkpoint
still grants no verified-export retention authority. This does not provide the
recipient-only verification capability requested by #959.

## Activation and bootstrap

Full-profile provisioning is explicit. New-format stores start with authenticated
inactive target state; absence of its row is corruption, not permission to
initialize. Activation records both zero-generation tombstones, device ownership
and the exact audit/checkpoint anchor before serving mutations.

Existing stores require a quiescent, separately invoked SDK upgrade. The upgrade
binds the exact source authority, applied frontier, audit/checkpoint anchor and
approved destination profile. All participating readers/writers must support
that profile; fixed membership and exact peer-profile agreement are verified
before activation. Legacy writers cannot rejoin or recover a new-profile store
under a legacy binding. Refusal must precede mutation of the original WAL; a
later server capability check is insufficient.

Quiescence includes no candidate owner, pending staging request, unresolved
cleanup, old terminal obligation or pending confirmation whose original ownership
cannot be resolved. Upgrade retains the source history and authenticated recovery
evidence; it does not reset the database, replace historical MACs or rotate keys.
An interrupted upgrade is either still the old inactive authority or a retained
new-profile recovery obligation that blocks writes. It cannot publish a partially
upgraded authority. Downgrade after activation is unsupported.

Legacy startup content is not trusted merely because a callback returns it. Any
import is an explicit authorized exact-content target mutation after bootstrap,
with independent source verification and its own intent/result. No staged legacy
candidate is silently imported or discarded. If these preconditions cannot be
proved by the SDK's retained-opening and upgrade APIs, activation stays refused.

## Session, lock and confirmed-commit lifecycle

The SDK issues a fresh session incarnation after authentication under the retained
device owner. A lock request reserves the registry's existing atomic operation
permit, admits the exact retained lease, then publishes that lease locally. Caller
cancellation after admission is completed by the owner. A crash between retained
admission and local publication is reconciled before serving another session.
Local registry entries are projections and cannot manufacture durable ownership.

Candidate unlock admits a generation/lock-bound discard and atomically releases
that retained lease. Explicit unlock returns success only after that result is
known. Session disappearance invalidates its local authority immediately and
retains cleanup independently of an RPC future. While cleanup admission or its
checkpoint is unavailable, new ownership/effects remain fenced. Late cleanup for
one incarnation cannot clear a later stage or another owner's lease.

An empty plain candidate commit is an observation only after one authoritative
read proves both no staged target and no pending confirmation, with the exact
generation and pending-state expectation rechecked before observation admission.
It is not inferred from a local cache, missing database row or timeout. An empty
commit that confirms pending ownership uses action 10 with its exact pending
identity and required intent/result/terminal sequence. A confirming commit with
staged changes uses action 6 with that same explicit pending resolution; the
running effect, candidate retirement and pending resolution are one transaction.
Validate/test-only and ordinary reads remain observations; they cannot acquire
configuration-effect authority.

Tentative promotion retains the pending transaction, rollback parent, original
deadline and encrypted session/persistent ownership in the same transaction as
the tentative effect. Confirmation and cancellation compare that exact pending
identity. Replays and recovery preserve the deadline. A separately authorized
follow-up confirmed commit has a new request; it is not an extension of a retry.

Session loss rolls back nonpersistent pending ownership. Persistent-token session
loss retains the original deadline and token binding. Beginning a replacement
NETCONF device owner is a device-reboot boundary and schedules rollback even for
persistent ownership before ordinary writes resume. Voter election, store reopen
for a voter and checkpoint-provider restart do not themselves begin a device.
The trusted embedding must distinguish those starts; the SDK exposes an explicit
device-start transition and refuses serving under an unestablished incarnation.

Lifecycle recovery uses an SDK-scoped recovery actor linked to the original
principal and pending effect. It cannot fabricate credentials or take the most
recent pending transaction instead. Repeated session/reboot delivery recovers
the same retained operation and original rollback parent. Known rollback with
terminal debt remains known rollback; the debt fence survives further restart.

These lifecycle requirements follow [candidate lock release](https://www.rfc-editor.org/rfc/rfc6241.html#section-8.3.5.2)
and [confirmed commit](https://www.rfc-editor.org/rfc/rfc6241.html#section-8.4.1).

## Qualification and delivery

Every enabled row in the parent RFC's mutation inventory remains mandatory,
including positive authenticated wire copy between distinct supported targets.
The existing helper-only copy and explicit profile-refusal tests cannot qualify
those operations. A full-profile negative reads all relevant authoritative target,
running, pending and audit state; unchanged running version alone is inadequate.
Copy-to-running tests additionally prove unchanged source generation/ciphertext,
including absent-candidate fallback substitution. Empty plain commit without a
pending operation and empty confirmation of an exact pending operation require
separate controls; only the former is an observation.

Use synthetic real-authority fixtures for stale generation, discard/recreate ABA,
source/action/ciphertext substitution, wrong caller/worker/session/token,
conflicting request reuse, refused/unknown checkpoint admission and terminal debt.
Keep deterministic cancellation barriers, fixed original deadlines and stale-owner
negatives. Extend retained reopen, process loss, independent checkpoint-provider
restart and authenticated voter-replacement fixtures; distinguish device reboot
and session loss with their own controls.

Freeze old-format byte fixtures and add new command/state/snapshot/export
fixtures, including omitted/reordered/substituted state, truncated snapshots,
unknown format, unsupported profile, partial upgrade and coherent rollback.
Preserve #925 checkpoint ordering/recovery and the #927 gNMI regression suite.
Test complete command and recovery reservations at their actual bounds without
raising limits or bypassing the capacity contract.

Implementation requires runnable desired-behavior RED, exact fix-removal RED,
a distinct adversarial mutation, restoration of the exact fix, full applicable
local/hosted checks, exact candidate review and normal current-main integration.
Author review is identified as author review; it is not independent approval.
Use Refs #958 until every acceptance row is complete. Native WAL and explicit
Durable/Async behavior remain unchanged.

### Provider-bound tentative and empty-confirmation preparation

`NetconfTentativePromotion` pairs an original candidate-promotion read with the
exact attested running envelope, fixed deadline and optional borrowed persistent
credential. `prepare_netconf_tentative_promotion` requires a nonempty original
running parent, authenticates the same staged configuration through the provider
and creates an opaque pending identity. The action9 effect includes that original
parent/deadline and encrypted ownership before its intent can be admitted. The
same existing preflight, command bounds, checkpoints and atomic reducer apply.

`read_netconf_pending_confirmation` returns an opaque `NetconfPendingRead` from
the authenticated, quorum-current transaction and independent checkpoint. It
binds the original caller/tenant, device, pending identity, candidate state and
running lock. Session-only ownership requires its original session incarnation.
Persistent ownership may be used by another session of the same projected caller
and tenant, with the exact credential; it does not delegate across principals.

`NetconfEmptyConfirmation` supplies that original read, provider and optional
credential to `prepare_netconf_empty_confirmation`. The SDK authenticates the
retained ownership for its exact tenant, schema, version and confirmation AAD,
checks its complete plaintext digest and verifies the credential. Its action10
binds the original lifecycle digest and pending identity. A staged candidate is
refused, and concurrent candidate changes invalidate preflight and application.
The running revision does not advance. Known confirmation remains known through
terminal debt and exact replay.

Ownership plaintext begins with the eight bytes `4f 50 43 4e 43 4f 01 00`, a
mode byte (0 session-only or 1 persistent), 16 fresh random UUIDv4 bytes, a four-byte
big-endian credential length and exact UTF-8 credential bytes. Session-only
requires zero length; persistent requires nonempty bytes. The existing 256 KiB
private-operation input bound applies before allocation; the body is at most
29 + 262144 bytes. Unknown versions/modes, inconsistent lengths and trailing bytes
are refused. The encrypted random bytes prevent the existing plaintext digest
from becoming a deterministic credential fingerprint or a direct verifier for
guessed credentials.

Encoding and decryption use zeroizing storage. The caller owns the borrowed input
credential's lifetime. AEAD and randomness use existing provider/SDK primitives;
credential digest equality uses the existing RustCrypto `CtOutput<Sha256>`
constant-time comparison. No credential, provider or signing material enters the
recovery descriptor, error or Debug output. The existing confirmation AAD digest
binds the pending identity, original effect, caller, device, owner session, parent
and deadline before encryption. Provider failure or cancellation during
preparation admits no intent or effect. Unknown transmission recovers only the
retained original prepared operation.

Staged confirmation, cancellation and internal timeout/session/reboot rollback
require their distinct preparation contracts. These ports do not activate the
public full-profile runtime or provide recipient-only/offline audit verification.

### Staged confirmation and explicit cancellation preparation

`read_netconf_staged_confirmation` freezes the original staged candidate and
pending confirmation in the same authenticated transaction and checks the
independent checkpoint. Its opaque `NetconfStagedConfirmationRead` preserves
original staging owner, caller, generation, running base and both locks. It
cannot grant ordinary promotion while a confirmation is pending.

`NetconfStagedConfirmation` pairs that read with the exact provider-attested
running successor and ownership credential. `prepare_netconf_staged_confirmation`
authenticates the original ownership, then proves exact candidate configuration
through the existing provider. Action 6 binds the original pending identity and
deadline; running commit, candidate retirement and confirmation resolve together.

The pending read also freezes the retained rollback parent's exact ciphertext,
schema, digest and version under the authenticated history. Its protected
`rollback_configuration` and `tentative_transaction` accessors support preparing
the exact successor before intent admission. They grant no effect authority.
`NetconfCancellation` supplies that original read, provider-attested successor
and ownership credential to `prepare_netconf_cancellation`. The SDK verifies the
expected tenant and exact retained parent configuration, `CommitConfirmedRestore`,
the tentative transaction as parent and the next running revision. No confirmed
deadline or legacy resolution is accepted in that successor. Action 11 resolves
the same original pending identity and fixed deadline, under the original caller,
session or persistent credential, and current running lock. Existing candidate
state is preserved by cancellation.

Both operations retain their original prepared command before possible
transmission. Known effects stay known through terminal debt, and uncertain
transmission recovers only that exact command. Provider failure or cancellation
during preparation admits no intent or effect. Shared private ownership
authentication preserves all empty-confirmation refusals and does not retain
credentials or providers. Internal timeout, session-loss and reboot rollback
require a distinct SDK recovery capability; caller-provided transport or a revoked
session cannot confer it. These preparation ports do not activate the public
full-profile runtime.
