# RFC 019 proposed addition: session-bound running writes

**Status:** Proposed. Must complete review and merge before architectural
implementation. No new API is implemented or qualified.

**Parent:** [RFC 019 retained targets](019-netconf-retained-targets.md). Refs #958.
This completes the retained full-profile running-write contract while preserving
the existing ordinary running/gNMI contract.

The server accepts datastore sources for `copy-config` and explicitly rejects
inline configuration sources. That unsupported input remains outside this
proposal. Datastore-to-running copy retains action 15 and its authenticated
source equality contract.

A full-profile NETCONF session may edit running while holding its own retained
running lock. The exact retained session/lease grants this authority. Equal
principal and tenant, a numeric session identifier, or access to the same
database cannot substitute for that lease. The ordinary required-audit path has
no such lease and continues to refuse every held running lock.

## Proposed closed surface

`ConsensusConfigStore::read_netconf_running_write` returns an opaque
`NetconfRunningWriteRead`, bound to the exact active worker, device and session,
current running version, original running ciphertext or authenticated absence,
and complete running-lock expectation. The same pinned authority read verifies
the ledger, retained lifecycle and independent checkpoint. It refuses unresolved
terminal/checkpoint debt, pending confirmation and lifecycle cleanup. The
ConfigBus wrapper also binds the read to its exact worker channel; another bus
over the same store cannot reuse it.

Provider-backed decryption authenticates the original running content for the
projected tenant and complete stored plaintext digest. An initial absent running
record is an explicit version-zero state, not an invented authenticated default
ciphertext. In that case the exact worker retains its original configured
version-zero snapshot as the edit base and validates the complete immutable
replacement. It cannot substitute a later local snapshot or manufacture a stored
envelope for that initial content. Read and edit authorization remain the
protocol/worker's responsibility.

The exact worker pairs the read with a validated, provider-attested running
successor through the closed edit constructor:

| Mode | Constructor | Intent | Proposed action | Typed applied result |
| --- | --- | --- | --- | --- |
| `edit-config` / advertised `edit-data` targeting running | `NetconfRunningWrite::edit` | Update | 16 | `EditedRunning { running_version }` |

`prepare_netconf_running_write` takes that immutable pairing, the original
session, event and fixed lifetime. Preparation authenticates the proposed
encrypted running envelope using the existing key provider and attestation
contract. It rechecks schema, parent, next version, payload bounds, intended
operation and original session/lock. It cannot refresh the read to authorize
content calculated from an earlier base. No provider secret or plaintext is
retained in the prepared operation, audit event, receipt or error.

The new action has a running destination expectation and exact running-lock
expectation. It carries no candidate/startup source equality claim, no confirmed
deadline, no pending resolution and no rollback label. Original read content is
an edit base; it is not required to equal the edited successor. Copy from a
datastore continues to use action 15 and its authenticated source equality.

## Admission, application and recovery

The original prepared handle and exact encrypted successor are retained before
intent admission can be transmitted. Rejected or indeterminate intent admission
permits no effect. Admission and apply authenticate the complete original effect,
caller, device and session and use the existing bounded target-command family.

Apply rechecks running version, active device, exact lock incarnation and owner,
and absence of debt, pending confirmation or lifecycle cleanup. An unheld lock
is also an exact expectation: acquisition after preparation invalidates it.
Release/reacquisition invalidates an old preparation even for the same session.
A held lock survives a successful owning-session write unchanged. Candidate,
startup and all other lock rows remain unchanged. One running successor and its
typed applied outcome are atomic under the existing native WAL and configured
Durable/Async behavior.

An authenticated known result is retained before terminal/checkpoint work. Its
failure cannot turn that result into rejection or unknown. Retained obligations
fence later ordinary and target writes; original lookup and completion recovery
remain possible. Cancellation, response loss, timeout or worker/process/leader
change recovers only the protected original operation and independently
authenticated caller. Recovery never prepares, encrypts, admits or submits a
new running edit, and never extends the original expiry.

## Encoding decision for maintainer review

Preferred: allocate action 16 and append its result variant to the
proposed retained-target V1 contract before enabling that profile.
No existing action, result, legacy operation or command discriminant changes.
Unknown actions/results remain typed refusals. Every voter, opener, replay
decoder and snapshot importer must support the completed profile before it may
be selected. A partially implemented target profile is not a rolling-compatible
deployment. Existing legacy profile bytes and rejection behavior are preserved.

Alternative: allocate a distinct retained-target format/profile revision for
this action, with explicit command/reply/snapshot dispatch and a reviewed
upgrade procedure. Earlier deployed readers stay bound to their original
profile and must refuse the new revision. Switching profiles requires that
reviewed procedure and a complete compatibility matrix. It must not reuse the separately allocated capacity profile or silently
upgrade an existing retained binding.

The preferred allocation requires confirmation that the target V1 implementation
has not been deployed as a supported durable profile. If that cannot be confirmed,
the alternative must be specified and reviewed before implementation. This
proposal grants no implicit migration or mixed-version compatibility.

## Required runnable evidence

- Actual authenticated NETCONF `lock running` followed by each advertised edit
  alias succeeds only for the original owning session. Observe full running
  content, one intent/result, original lock and unchanged targets.
- A second session with equal principal/tenant and reused numeric correlation,
  wrong worker/authority, stale device, stale base or replaced lock cannot write.
  Ordinary/gNMI attempts remain refused while the running lock is held; their
  unlocked positive case remains covered separately.
- Provider failure before preparation, refused/unknown intent, expired original,
  pending confirmation and unresolved terminal/checkpoint debt permit no effect.
- Known commits remain truthful after terminal failure, response loss and panic;
  later writes stay fenced until original completion. Cancellation, timeout,
  fresh-process/provider/leader recovery must retain the original operation.
- Frozen original absence and an existing running record both work. Neither a
  newer base nor a source-copy envelope can be substituted during preparation.
- Lock/source/operation/result substitution, unknown tags, oversized/trailing
  encodings and legacy-profile use fail with typed, value-free errors.
- Fix-removal and a distinct adversarial mutation hit their intended assertions,
  then the exact fix and gNMI boundary pass. Formatting/source inspection alone
  supplies none of this behavioral evidence.

Implementation of these additions waits for the reviewed format decision. The
remaining ConfigBus worker and protocol integration proceeds within its existing
authorization and exact shared-file handoffs.
