# RFC 026: Authenticated scope and voter management transport

Status: authenticated scope implementation under qualification.
Voter management remains deferred until its RFC 023 dependencies land.

## Scope and delivery boundary

The scope transport supplies the untimed client/server and boot verification
required by [RFC 022](022-scope-leases.md). The narrow RFC 023 voter-management
channel follows **after its proof helpers reach main**; the scope transport does
not depend on that unfinished channel. Neither transport introduces a timed grant, renewal, clock correlation, compatibility
reader or independent authority ledger. Selection/retirement, replicated apply,
voter replacement, kernel containment and scheduling retain their own owners.

| Surface / module | Responsibility |
| --- | --- |
| `opc-session-net::scope` | New scope client/server, bounded framing, boot responder, trusted adapter ports and exact retry. Do not extend the legacy consumer operation enum. |
| `opc-tls` | Connection/purpose exporter helper on an admitted, completed TLS connection; keep existing immutable material and epoch checks. |
| Untimed store contract | Core requests, immutable digest helper, durable boot-key binding, closure/admission token construction and atomic apply. The transport supplies configured verification adapters. |
| Deferred `opc-consensus::voter_management` module | Network framing, candidate responder and dispatch using landed RFC 023 ports. No concurrent edits to `voter_slots` helpers, coordinator or engine admission. |

Reuse the locked rustls/ring, tokio-rustls, SHA-256 and `p256` 0.14 stacks.
Signers normalize P-256 signatures to low-S; verifiers reject high-S. There is
no new TLS stack or handwritten signature arithmetic. The normative
[wire appendix](026-scope-authenticated-transport-wire.md) and
[golden vectors](026-scope-authenticated-transport-vectors.json) are part of this
proposal, including the language-independent startup protocol.

For the current native store profile, the wire's installation routing field
contains the existing name-derived consensus cluster ID. Reusing a cluster name
reuses that routing domain; this transport does not change consensus identity.
Installation-qualified consensus identity is deferred to SDK #1187. Fresh boot
keys and live channel proofs remain required for every new worker process.

## Scope API, roles and capabilities

```text
BootIdentity::generate() -> process-owned nonce and signing key
ScopeProcess::new(scope, workload, boot, exclusion_directory)
BootstrapIssuerClient::probe(enrollment, mode) -> IssuerStartupSession
BootProofResponder::respond_once(live_connection) -> StartupSession
IssuerStartupSession::deliver_ticket_notice(trusted_ticket_source)
StartupSession::receive_ticket_notice(deadline, evidence_sink) -> BootTicket
ScopeBootAuthority::{read_current, read_known}(scope, ...)
ScopeClosureSource::{read_final, read_local}(predecessor, digest)
ScopeClient::{prepare_initial, prepare_successor, prepare_close}(...)
    -> PendingScopeAuthority
ScopeClient::submit(pending, attempt_duration) -> ScopeAuthorityReply
ScopeClient::{current, outcome, lookup_outcome}(..., attempt_duration)
ScopeClient::batches(own_committed_authority, class, attempt_duration)
    -> ScopeBatchCoordinator
ScopeClient::batch_outcome(exact_attempt, class, attempt_duration)
ScopeReadClient::{current, outcome, batch_outcome}(..., attempt_duration)
ScopeServer::new(ScopeServerConfig)::serve(class_addresses)
```

These types live in `opc_session_net::scope`; authority and result types come
from the untimed store. Pending authority requests own their canonical bytes,
request ID and digest. Retrying uses the same pending object, while reconnecting
creates a fresh proof. The read client serves controller and observer roles.
Batch clients use the store's shared lane coordinator. Its factory takes one
opening-read reservation; its private transport port reuses the coordinator's
lane and resident reservation for every later apply, cancel and resolution read.
An observer disappearing cannot discard accepted work. Exact terminal results
remain on the completion stream until the caller reconciles and acknowledges
them. Reopening the factory preserves that shared state. Dynamic retry priority
selects the corresponding physical connection without changing canonical bytes.
`AdmitInitial` is only for an unused domain. **Every later boot, including a
same-workload container restart, uses `SucceedClosed`.** Retirement and selection
of a new cohort remain reserved for their separate contract, with no public
transport operation in this profile.

The server checks live policy before allocating a challenge and on dispatch.
A worker transport principal may hold an explicit grant for several stable
scopes. Each process remains bound to one slot by its ticket and protected boot
key; startup independently checks the Pod-bound token's exact Pod name and UID
against trusted enrollment for that slot. Sharing a transport identity grants
no sibling's authority and requires no per-slot certificate or runtime CA.
Controller and observer policies also explicitly name scopes.
Worker columns below describe the boot's relationship to committed authority;
they do not add roles to the store contract.

| Operation | Candidate boot | Current execution | Successor boot | Scope controller | Observer | Required proof |
| --- | --- | --- | --- | --- | --- | --- |
| `AdmitInitial` | Self, unused domain only | No | No | No | No | Independently current ticket and candidate's own boot-key proof. |
| `SucceedClosed` | No initial-admission shortcut | No self-reopen | Self | Reserved; denied by this scope profile | No | Successor ticket/key proof on its own outgoing connection plus verified exact predecessor closure. |
| `Close` | No | Self only | No | No | No | Current boot-key proof and verified irreversible local quiescence. |
| Batch apply/cancel | No | Own committed stamp | After succession commits | No | No | Own committed boot-key proof; replicated apply checks the stamp. |
| `current`, exact authority/batch outcome, batch reopen | Own scope | Own scope | Own scope | Authorized scopes | Authorized scopes | Worker proves its own boot key; controller/observer use mTLS and live policy, without an invented boot-key requirement. |

Reads use a full-round linearizable barrier, never a lease or clock-based read.
Predecessor batch lookup carries its immutable attempt, not a mutation under a
new stamp. Applied, Cancelled, NotApplied, NotRecorded and Pruned remain distinct;
Pruned is unresolved history and never permission to repeat an external effect.
The read may name an older namespace in the same stable scope. Known non-current
workers retain these resolution reads, but an Emergency declaration spends
classification capacity until a fresh proof establishes the current boot.
Only a current boot can dispatch a batch mutation using established Emergency.
Scope clients authenticate servers with constrained mTLS, installation and
profile binding. They need no voter-key discovery service. Controllers may read
committed outcomes; they never receive a successor's `CommittedScopeAuthority`. Only the checked
`ScopeClient` factory constructs that opaque, non-deserializable capability,
from an authenticated committed result for **its own boot's call**, bound to the
exact request ID/digest, installation and execution, while still current. A
controller result, read view, wire stamp or old success cannot construct one.
The scope transport supports worker self-submission only. Controller-submitted succession, its
worker resolver, inbound voter-to-worker proof path and capability delivery are
future work. The future operation must still return only an outcome to the
controller; its successor must prove its own boot and exactly retry the complete
request to receive a capability. Reconnect never creates a new boot.

## Boot identity, closure and issuance races

Each boot creates a nonzero OS-random 128-bit process nonce and ephemeral P-256
key. Its public commitment is SHA-256 of the 33-byte compressed point. The key
has no export, serialization, diagnostic or arbitrary-signing API and is
zeroized on drop. On Linux, make and verify the process non-dumpable before
creating it; an unsupported protection mode refuses boot admission. Verify the kernel adapter's
`/proc/self` and `/proc/<pid>` FD/image readbacks after the change under the
worker container's real UID/capabilities; do not assume host-root results qualify it. Typed RPC
builders obtain the exporter from their own live connection, not a caller's
bytes. The startup responder signs only liveness/candidate domains. Voter keys
are a different type, durable with voter data under RFC 023.

The ticket binds stable scope/installation, logical identity, workload UUID,
process nonce, admission generation, boot-key commitment and immutable authority
record UID/revision. After durable issuance, the issuer sends the typed ticket
notice on that same authenticated startup connection. It delivers the boot
binding, generation, record reference and paged evidence references for every
unresolved possible predecessor. The worker checks that its own scope, workload,
nonce and key match, but treats the notice as a hint: admission independently
reads the issuer record again. The appendix specifies its bytes and retry/page
correlation. The notice ID commits the complete ordered evidence set. A fresh
authenticated startup exchange may deliver updated predecessor hints for the
same issuance when a predecessor commits later; the worker replaces its hints
only after checking the complete new set. Refreshing hints never rewrites an
in-flight canonical request. The cohort is the store's ordered `ScopeIncarnation`; do
not introduce a second workload-incarnation UUID. Platform container/start
observations stay in the trusted adapter, outside the replicated execution
codec. Authority revisions are bounded opaque bytes compared for equality,
never ordered. The issuer's write path is exclusive; the verifier independently
reads that record consistently, rather than trusting a client copy or cache.

The server's closure verifier checks the exact predecessor stamp and the immutable
evidence reference. For succession it accepts only an exact committed `Close`
or trusted final termination of that process/container. Self-`Close` may use
trusted local quiescence: all mutation and peer-control submission paths are
irreversibly shut, with only final `Close` delivery retained. Its commit fences
outstanding store writes. **Installed forwarding is excluded from closure** and
may continue. A public Boolean, missing Pod, elapsed timeout or caller-provided
termination claim is insufficient. The configured verifier and store service
produce the opaque verified token; decoding its public evidence reference does
not. The closure kind and evidence digest stay inside immutable request bytes. The
appendix defines exact FinalTermination/LocalQuiescence inputs and uses the
committed Close request digest for CommittedClose, with cross-language vectors.

The Rust adapter publishes local quiescence through the configured
`ScopeLocalClosurePublisher` only after its irreversible gate has drained.
This opaque publication includes the exact predecessor and generated fence nonce.
The server's independent `ScopeClosureSource` retrieves that retained record
and recomputes the specified digest. The wire still carries only the canonical
closure kind and digest. These are trusted installation ports: implementations
must bind the publication to its SDK process and preserve it for exact Close
retries; accepting a peer-provided Boolean or nonce as a verified record is
outside the contract. A failed publication attempt leaves the gate closed and
reuses the same nonce on retry. It needs no operator or node cleanup.

The issuer must preserve closure evidence for **all unresolved possible
committed predecessors**, not just the last ticket it issued. For example:
B0 is current; B1 receives generation g, then dies before its succession outcome
is known; B2 receives g+1. B2 resolves `current()` and the exact B1 outcome. The
predecessor can be B0 or B1; its closure evidence must still be obtainable.
Issuance never proves B1 committed. The issuer must not garbage-collect either
possible predecessor's evidence until the ambiguity is resolved. This retention
and reconciliation obligation is part of the operator/adapter integration and
has a no-stall qualification case.

For a new admission, outside Raft apply:

1. Authenticate and authorize the exact scope, role and method.
2. Independently read the current ticket, compare every boot field, and verify
   candidate possession over its own TLS connection and this request digest.
   The worker submits for itself; the scope profile refuses controller-submitted succession.
3. Verify exact predecessor closure for succession or local quiescence for Close.
4. Revalidate ticket authority UID/revision before proposal. Changed observations
   restart verification; unavailable evidence leaves automatic retry pending.
5. Submit through the untimed service with exact expected revision and floors.
   Apply remains the atomic arbiter of committed order.

A higher ticket is not retroactive revocation: no transaction spans platform
reads and Raft. The committed record atomically retains the execution's public
boot-key commitment and generation floor. A reconnect proves that retained key
afresh; normal mutation need not read the platform API on every call. A retained
binding can never admit a new boot. The one-use `VerifiedScopeCall` binds the
live connection, role, scope, execution, request digest and authorized scheduling
context; only configured verification can construct it. Raw production handlers
require the same checks. There is no allow-all path.

## Pod-bound bootstrap credential and threat model

The Kubernetes adapter uses a **Pod-bound projected service-account JWT** with
a dedicated audience, verified offline against the configured cluster issuer's
published keys. It requires **no new cluster-scoped grant**. Kubelet projects and
refreshes the token; the application needs no TokenRequest permission. Kubernetes
normally grants issuer discovery to all service accounts through its built-in
`system:service-account-issuer-discovery` binding. The verifier uses its own
API credential to read `/.well-known/openid-configuration` and `/openid/v1/jwks`;
it does not send the bootstrap-audience token to those endpoints. See the
[Kubernetes issuer-discovery contract](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery).
Check discovery/JWKS access when this mode is installed or activated. If a
hardened cluster removes that default access, return `UnsupportedPrerequisite`
early; do not defer discovery until a restart, create a cluster grant, fall back
to `pods/proxy`, or silently weaken bootstrap. No TokenReview, SubjectAccessReview or Node permission is used.

Transient API outages and source deadlines remain `Unavailable`. Activation
tries at most three times, with 100 ms and 200 ms backoffs and a five-second
source deadline per try; the installation driver can retry activation later.
Only a definitive discovery-binding refusal is `UnsupportedPrerequisite`.
Malformed discovery, issuer configuration or public keys are rejected.

The issuer establishes **end-to-end mTLS directly to the worker's restricted
startup responder**, using a route obtained from the trusted Pod API. The issuer
uses an SVID from the existing identity setup and namespaced NetworkPolicy
access to workers; this adds no cluster-wide identity registration. Both
peers have constrained role policies: the worker sends its bearer token only to
an authenticated bootstrap issuer, over that connection. A transparent tunnel
may carry the TLS stream; a terminating or unauthenticated `pods/proxy` hop
cannot establish admission. Existing proxy reachability is at most a liveness
hint. Merely signing the hash of a token exposed on an unauthenticated hop would
allow theft and rebinding; this protocol never exposes it there.

Verify configured issuer, exact bootstrap audience, allowed RS256/ES256
algorithm, published `kid`, signature, validity and Pod name/UID, namespace and
service-account name/UID claims. Require the trusted time interval wholly within
`nbf`/`exp`, with `iat` no later than its earliest bound. Trust discovery/JWKS
only through the configured HTTPS/API-CA endpoint, never a JWT-selected URL or
`jku`. Refresh keys on an unknown `kid` or a signature-verification failure,
including a changed key under an existing ID. Both triggers share one refresh
attempt per second and replace the published key set; unknown keys never grant
admission. An exact-name,
consistent Pod GET (no `resourceVersion=0`, no informer snapshot) must match
UID, owner, service account and current running container observation. Ticket
and closure readers need only exact-name, namespaced read access. Check the
service-account UID against installed enrollment or an exact-name consistent
ServiceAccount GET; Pod spec alone contains only its name. Offline JWT
verification cannot detect Pod deletion by itself, as the
[Kubernetes token documentation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) explains;
the current GET, issuer generation floor and local guard remain necessary.
Pending Pods, missing addresses, containers still waiting to start, and
terminated containers still shown in the Pod status return `Unavailable`;
enrollment and controlling-owner mismatches remain invalid.

The retained issuer startup session keeps the verified JWT validity bounds,
without retaining its bearer token. Recheck these bounds and TLS authentication
after independent platform reads and immediately before durable issuance. An
expired or overlapping authentication interval produces a retryable time
refusal; it never changes an already committed execution or receipt.

Mount the projected token only into the worker container. Bind its exact-byte
hash, Pod identity, observed boot, ephemeral public key, process nonce, local
context, fresh challenge and TLS binding in the startup proof. Candidate proof
requires the held trusted exclusion guard and closed new-effect gates throughout
signing. Liveness has a different domain, may precede a ticket and readiness,
and accepts any independently verified boot at the exact workload UID; it never
asserts exclusion or admission. A token alone cannot admit a boot.

Defend against unauthenticated peers, siblings with a shared worker SVID, stale
workers/tickets, stolen public transcripts, relays, retired voters with old
volumes and revoked controllers. Trust the issuer/write boundary, consistent
platform reads, configured identity roots, OS randomness, SDK local guard/key
handling and non-Byzantine consensus. Node/kernel, issuer or worker-process
compromise is outside this boundary; a Pod token does not cryptographically
prove that SDK code holds an OS lock. Keeping the bearer credential and ephemeral
key confined to the trusted worker is therefore a deployment prerequisite.

## TLS binding and authentication clocks

Use TLS 1.3, mandatory mTLS, no resumption/early data, and exact ALPNs
`opc-scope/1` and `opc-voter-management/1`. Both ends use constrained `opc-tls`
`PeerPolicy`, never `allow_any_trusted_peer` or compatibility mode. Keep these
listeners separate from the consensus ALPN. Use immutable handshake material,
final material-epoch admission and existing credential/trust/policy retirement.
Peer identities come from the completed TLS connection, not payload claims.

Derive **one 32-byte regular exporter per connection and proof purpose**, as in
[RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5), with label
`EXPERIMENTAL-openpacketcore-channel-binding-v1` (the private-use convention in
[RFC 5705 §4](https://www.rfc-editor.org/rfc/rfc5705.html#section-4)). Its context
is SHA-256 of length-prefixed ALPN, purpose, client and server SPIFFE identities,
installation and optional scope. Both identities are explicit because the
exporter transcript excludes the client's Certificate/CertificateVerify.
**Neither challenge, request digest nor scheduling header enters this context.**
Both endpoints compute it locally immediately after admission. Each signed
instance instead binds the one-use challenge, request digest, method, direction
and scheduling header. The appendix fixes every byte. Pass this binding
unchanged to RFC 023's `issue_candidate` / `issue_rpc`; they can then generate
the challenge without a circular dependency. The same helper serves consensus
incarnation proofs when that integration lands.

An installed platform realtime clock supplies an earliest/latest interval with
configured uncertainty for certificate, bootstrap JWT and RFC 023 attestation
validity. Rustls's single handshake `now` is insufficient: before application
admission, explicitly check every presented certificate's `notBefore` at the
early bound and `notAfter` at the late bound, as well as the local handshake
material's interval. Keep both bounds in peer evidence. These are
**authentication-freshness checks only**. An unavailable or
regressed clock, detected skew outside that budget, or an interval crossing a
validity boundary gives a typed retryable authentication-time refusal. Clock
ahead/behind tests must cover certificates not yet valid and already expired,
and attestations whose full interval cannot be established. Alarm and retry
as clock synchronization recovers; never expand the uncertainty budget to pass.
Undetected skew is a limitation of the trusted clock source. No time result
can grant/revoke ownership, lower a floor, imply closure/retirement, undo an
accepted Prepare/receipt or order installed emergency forwarding to stop.
Existing accepted work remains resolvable after credential expiry or rotation.
Challenge and dispatched-attempt deadlines use local monotonic time only.
After a detected step, the adapter alarms and records only a recovery baseline.
Without a newer synchronization generation, three consistent observations at
least one second apart over at least three seconds restore authentication.
Another step restarts recovery, and repeated immediate calls cannot advance it.
The same fixed uncertainty budget applies throughout.

## Deferred voter-management exchanges

This deferred slice exposes `VoterManagementClient::{replace_lost_voter,
replacement_status,pull_candidate_binding}`, `VoterManagementServer::serve` and
`VoterCandidateResponder::serve` on `opc-voter-management/1`.
`open_replacement_candidate` stays local. Management is reachable before scope
activation; controllers are not voters and acquire no worker/voting permission.

| Exchange | Verification and authoritative key source |
| --- | --- |
| Controller → retained voter | Current controller mTLS identity/SPKI and live installation/slot policy, plus RFC 023's canonical signed attestation. A follower may receive it. |
| Receiving voter → selected candidate | The **same receiving process** resolves/dials the candidate using RFC 023's trusted resolver, proves its retained voter key in the separate management-request domain, challenges the selected candidate key and consumes `VerifiedVoterCandidate` in `VoterReplacementVerifier::verify`. The candidate responder never accepts a controller-carried verified token. |
| Voter reply → controller or candidate | Separate management-response domain binds exact request, result, installation/slot, responder incarnation/key and fresh caller challenge/channel. Check the retained key through installed `TrustedVoterKeyAuthority`. |
| Voter ↔ voter forwarding | RFC 023's existing two-way member-bound RPC proofs. Only the service-validated command crosses the internal forwarding boundary; public witnesses stay local. |

`TrustedVoterKeyAuthority` independently reads the trusted enrollment authority's
**committed** voter table for the installation/slot, including configuration,
incarnation and key commitment. The controller owns that durable enrollment
record; candidate policy installs its trusted reader. A candidate-selection
record, SVID, response-provided key or bootstrap flag is insufficient. Bootstrap
and completed replacement refresh this committed table through that reader;
unavailable or unmatched keys backpressure/retry rather than accepting an
unknown responder.
A proposed candidate's key is checked separately against its exact verified
selection. Do not misuse RFC 023's two-member RPC binding for a non-voter.

Reuse RFC 023's request digest, attestation, candidate possession and challenge
helpers unchanged. Binding pull performs a linearizable lookup for exact
installation/slot/candidate-key selection, challenges its selected incarnation
and request digest, then returns that binding; the original controller's request
ID is unnecessary. New public connections require new proofs. Routing hints
never establish authority. The request/response management domains and exporter
purposes are fixed in the appendix; no missing key source is delegated to mTLS.

Every successfully verified voter-incarnation proof on these paths calls
`observe_authenticated` **before any later payload or slot refusal**, feeding
the same recent-traffic tracker as the consensus transport. Return typed
no-effect `TargetStillLive` only when RFC 023's coordinator returns it; once
submission was possible the outcome remains unknown until resolved. Test a
controller request reaching the target voter itself. A live compromised voter
must be stopped, then replaced; live voter-key rotation is outside this profile.

## Scheduling, challenge limits and frame admission

RFC 024 owns operation classes, scope fairness, lane arbitration, resident retry
entitlements, priority inheritance and store proposal capacity. Preserve that
context through follower forwarding. SafetyControl never waits for a data lane.
Unresolved work keeps its existing resident entitlement and exact bytes, releases
only the attempt's running credit, and retries under RFC 024's rules; transport
must not introduce a second reserve step that can deadlock a full queue.

Use separate connections and send/receive/accept/handshake/proof/dispatch budgets
per class. Established Emergency and EmergencyClassification are separate.
The concrete voter transport is configured with
`RemoteSessionConsensusPeer::with_class_resolvers` and
`SessionConsensusServer::listen_classified`. Both ends decode the native bounded
forwarding request to select/check its class; an endpoint number alone cannot
promote a mutation. Every class owns its connection coordinator, including cold
handshake, reconnect and cached-connection state. The five listeners also retain
separate handler and reply credits. Configure these endpoints on each voter hop
when installing the scope transport.
Untimed scope observations use the full ReadIndex barrier; its native RPC uses
the control transport pool. The leader's existing FIFO read-barrier admission
retains the class-unaware boundary documented in RFC 024. End-to-end isolation
under arbitrary read pressure additionally requires class arbitration at that
stage. Transport qualification covers the separate forwarding, handshake and
proof capacities supplied here.
Use class-specific listeners/accept queues so ordinary traffic cannot fill a
shared pre-TLS backlog. Each class retains positive capacity; no borrowing from
protected classes. Within a class reserve distinct controller, candidate and
current-worker/observer role buckets, with caps per transport principal and
authorized scope. A candidate SVID is
not enough to claim established-Emergency priority; require established scope
binding. Split each worker peer allowance into unproven and proven-current
connection shares. Only an SDK-verified proof of the committed current boot
key on that exact connection promotes it; a claimed key, ticket or shared SVID
cannot. Sibling/retired Pods with the same SVID use the separately capped
unproven share and cannot consume the current worker's SafetyControl/Emergency
share. Invalidate promotion when its committed binding or authentication is
superseded. Reserve controller and candidate capacity before store activation.
On a cold reconnect, even the current worker shares the unproven classification
or class bucket until that new connection proves its committed boot. Same-SVID
siblings can delay that first proof. This is an accepted limit; the protected
current-worker share applies only to a connection already proven current.
With grants for several slots, this shared-identity limit spans the whole fleet.
Only a compromised worker, outside the trust boundary above, can target other
slots' unproven proof capacity or pre-fill their precreated closure-publication
records. Both affect liveness only and grant no cross-slot authority. Pre-filled
closure records fail closed; independently verified termination evidence remains
the fallback.

Initial proof limits are two pending/in-flight exchanges per
principal/scope/role/class,
eight per protected role/class bucket, and at most 128 across the configured
non-borrowing buckets. The three role groups across five class/sub-budget groups
use 120 exchanges by default. Divide a worker bucket into four proven-current
and four unproven exchanges, with separate per-principal/scope allowances of two.
Several slots sharing an SVID have independent allowances within the same global
bound; no caller-selected ungranted slot allocates a proof allowance. Adding
a distinct role requires reallocating that budget. Validate that bucket sums fit this bound; never add a shared FIFO
semaphore ahead of reserved buckets. Each class listener permits
eight incomplete handshakes with a five-second monotonic handshake deadline.
Unauthenticated arrivals cannot claim role-reserved proof capacity. Handshake
buckets still require the deployment's ordinary ingress protection against an
unauthenticated flood of the protected listener itself.
An accept error does not terminate a class listener or its established
connections. Descriptor exhaustion backs off from 10 ms to at most 250 ms;
explicit shutdown interrupts that wait and reaps the class's connections.

A connection has one proof exchange at a time; a busy ordinary connection never
carries another class's recovery call. Each reserved exchange allows at most
8 KiB of buffered proof data. A challenge lives for the lesser of five seconds
and the remaining dispatched-attempt deadline (also within RFC 023's cap); it
is consumed on success, failure, cancellation or expiry. Issue it only after
role, ALPN, exact scope/slot, method and proof-capacity checks. Pending challenges,
in-flight verification and bytes all count against the same bucket caps.

The fixed header is checked before body allocation/read. Validate the role and
method, then await the authorized class/role reservation. Decode under that
credit, recompute the canonical digest, and compare routing claims. Class and
Emergency sub-budget remain outside immutable command bytes/digest/receipts,
but inside the fresh proof's signed header. Authorized inheritance/retry may
change them without changing the request. Forward verified scheduling context,
not a bare caller-supplied priority label, through store proposal admission.
A worker may classify its own batch as Emergency, Normal or Maintenance, never
SafetyControl; use RFC 024's typed map for control, reads, proofs and scans.

Queue waits have no implicit timeout, overload refusal or session quota. Bound
producer descriptors upstream and backpressure before materializing a body.
Attempt/challenge deadlines begin only after the corresponding dispatch/proof
credit. Scope frames allow the existing 2 MiB command **plus 512 bytes of fixed
transport allowance**; proof frames cap at 8 KiB and management frames at 64 KiB.
Keep the tighter operation bounds and RFC 023's 8 KiB attestation/2,048-byte
identity limits. Replies retain class capacity. Quiescing ordinary pools keeps
SafetyControl available through outcome resolution and final `Close`.

## Exact retry, refusal and qualification

Request IDs are nonzero OS-random 16-byte values. Prepare immutable request
bytes before first send: operation, scope, execution, exact expected revision,
closure reference and payload share the core digest. Credentials, exporter,
challenges, deadlines and class do not. Never change a body/revision or allocate
a new ID as a transport retry. Same ID with different bytes conflicts.

After authenticating and authorizing a retry, resolve a retained exact receipt
**before demanding a newly current admission ticket**. Proving the recorded
boot permits outcome resolution even if issuance advanced; it does not create
new ownership. A missing/replaced old receipt is not evidence of no effect.

| Result | Caller behavior |
| --- | --- |
| Proven no submission/effect | Retry exact bytes if transient; no claim about an earlier unknown attempt. |
| Committed exact receipt | Verify ID/digest and authenticated binding; return the recorded outcome. Capability delivery additionally requires this boot still current. |
| Submission possible, result unavailable | `OutcomeUnknown`; retain exact retry material and resolve linearly. Cancellation does not undo consensus work. |
| Obsolete, superseded or receipt replaced | Read current state; never invent “no effect” or automatically resubmit under a new ID. |

A worker call cannot reach dispatch before its possession proof is sent and
verified. I/O failure or deadline before proof transmission is `Retry` (proven
no submission), including an idle close. Evict pooled connections after four
seconds idle, before the server's five-second limit, and reconnect at most once
within the original attempt deadline. Request ID, digest and command bytes stay
unchanged; nonce, challenge and channel proof are fresh. After proof transmission
starts, transport failure remains `OutcomeUnknown`.

Before a challenge, server clock, material or live-policy refusal returns a
correlated `ProvenNoEffect`. A role refusal may read the fixed caller nonce to
bind that result, but never reads or allocates the forbidden canonical body.
An invalid possession proof receives no reply. A valid proof whose independent
retained record mismatches receives a typed unauthorized refusal.

A once-admitted boot proving its own key receives typed `Superseded`, `Closed`
or `Retired`, rather than endless authentication retry. A lagging follower's
local mismatch is retryable pending a linearizable resolution, not a definitive
unauthorized result. Diagnostics contain bounded reason codes and redacted
correlation commitments, never credentials, keys, tokens, proofs or challenges.

Implement tests first, including mutations removing each critical guard:

1. Appendix vectors in Rust and the external issuer implementation; malformed
   lengths, enum tags, UTF-8, points, noncanonical Postcard, high-S, cross-domain,
   direction/method/header changes and response/request swaps. On real rustls
   client/server sockets both sides derive identical exporters; changing either
   identity, purpose, ALPN, context or label changes the value.
2. Real mTLS ticket forgery/high generation, wrong scope/key/install, replay,
   connection splice and a relay with a valid shared SVID. Liveness/candidate
   proofs cannot become RPC proofs. Wrong issuer role, Pod/SA UID, token audience,
   JWT key, revoked policy and token interception/rebinding fail closed.
3. Authoritative-read/issuance races, unknown B1 succession followed by B2,
   retained B0/B1 closure evidence, forged/wrong-predecessor/swapped closure,
   controller-submission refusal, worker exact retry, changed-ticket receipt
   resolution, stale follower and typed old-worker refusal. Prove no slot stalls
   because the last-issued ticket differs from the committed predecessor.
4. Three separate disk-backed StrictDurable voters: leader/reply loss, changed
   body conflict, apply after succession/retirement, restart/snapshot boot-key
   and floor retention. Same SVIDs cannot reuse another live channel's proof.
   A reinstall using the same names retains the current name-derived cluster ID;
   installation-qualified identity is tracked separately in SDK issue #1187.
5. Clock ahead/behind/regression/unavailable/boundary overlap only refuse/retry;
   accepted Prepare/receipts survive expiry and rotation. No clock drives an
   ownership transition or emergency teardown.
6. Saturate every class/role/peer challenge, handshake, byte and dispatch pool
   on real TLS and follower-forwarded three-voter paths. Controller, candidate,
   SafetyControl and established Emergency progress; exercise reverse-class
   and scope fairness. Mutations merging pools, re-reserving unresolved work,
   allocating before reservation or trusting a class label must fail. With a
   same-SVID sibling holding every unproven challenge, a proven current worker
   must complete SafetyControl/Emergency within at most one bounded exchange.
7. Deferred voter management: same-process candidate verification, retired response key,
   two-way forwarding proof, binding pull, self-target `TargetStillLive`, traffic
   observation before refusal and no-effect/committed/unknown preservation.
8. Cancellation frees resources without relabeling possible commits; final Close
   survives ordinary-pool quiescence. Cover non-dumpable key setup and actual
   worker-container `/proc` self-reads, no raw signing
   oracle, redaction, epoch races and bounded producers.
9. `multi_slot_worker_policy`: cover cross-slot reads (`Current`, `Outcome`,
   `BatchReopen`, `BatchLookup`), batch mutations and `Close`; refuse authority
   without matching slot-bound evidence. Exercise a compromised worker holding
   proof capacity in other slots and pre-filling their closure-publication records.
   Both are fleet-wide liveness-only cases, with no cross-slot admission or effect;
   closure pre-fill fails closed and uses independently verified termination
   evidence as the fallback.

Persist only the core's public binding/floors/receipts and RFC 023's specified
records. Never persist worker keys, exporters, challenges or verified witnesses.
Stored/wire profile changes require a fresh install, with no
migration or mixed-profile fallback. Advertise the shared untimed store profile
only after its component gates pass. Voter management qualifies separately.
The scope implementation is under qualification; the test plan above defines
the required evidence, rather than asserting downstream deployment readiness.
