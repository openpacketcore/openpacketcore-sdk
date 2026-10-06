# ADR 0029: Terminal void receipts for unbound fenced transitions

## Status

Accepted.

## Decision

An independently negotiated V2 profile adds a consensus `void` for one exact,
self-authenticating request ID and its original request body. Stores are
created under one profile and are not converted. The original V2 profile,
its published byte vectors, and stores created under it do not accept void.
Activation establishes the extended profile for the exact voter set. Later
voids use a quorum like other transitions. An older voter or a store under the
original profile cannot supply the extension proof; the consumer retains the
row when no supporting peer is available.

A void uses the original request's authority and fencing checks and the same
receipt key, capacity, retention, and epoch lifecycle. It has a separate outer
consensus request ID and command digest domain. It never mutates a session,
allocates or renews a lease, advances a fence, or emits a watch notification.
It either replays the original receipt or binds a terminal no-effect receipt.

**Invariant: after a bound void for X, X never takes effect.**

## Apply ordering

All replicas apply committed commands in log order, including commands in one
apply batch. Receipt lookup sees earlier writes in that batch.

| Order | Deciding result | Later result |
| --- | --- | --- |
| Original, void | Original success or deterministic rejection | Same receipt |
| Void, original | Terminal no-effect receipt | Same receipt; no original effect |
| Repeated void | First receipt | Same receipt; no additional binding |
| Leader changes between commands | First committed binding | Same receipt on the successor |
| Epoch rotates after binding | Retained binding | Same receipt until retention expires |
| Epoch closes while X remains unbound | No binding for X | Old epoch is not active; neither command can apply X |

Expired receipts preserve their identity/body binding until retirement.
Retirement permanently rejects requests from retired epochs. These states can
close future execution without proving that an old request never took effect;
they must not be described as a successful void. A lost void response remains
ambiguous and retains the journal row until exact status or another void
confirms a terminal result.

## Caller lifetime and journal ownership

No deadline is stored in a journal row. Timing is irrelevant to the consensus
safety argument: the first binding decides. The in-memory deadline protects a
caller that is still waiting. A row prepared by the current process is eligible
for void only after its registered call has returned with a known outcome,
was cancelled or dropped, or its original in-memory deadline has passed.
An unknown return at an attempt deadline continues to wait for the original
deadline. Redispatch clears eligibility before any preparation or wire work.
Dispatch and reclamation claim the same in-memory lifetime: if reclamation
already claimed it, the handle resolves status instead of dispatching again.
Registration precedes visibility of a new row; a second facade cannot treat
that row as inherited. The public trait preparation method receives no
deadline. A direct preparation without a registered call therefore retains
its row against void for this process lifetime; status or epoch retirement
can still resolve it. A caller that needs deadline-based reclamation registers
its original deadline before preparing, as the facade does. No deadline is
invented for a caller that did not supply one.
Eligibility alone never authorizes deletion; an exact receipt is still needed.

A journal created with `FencedTransitionV2RecoveryJournal::create_new_owned`
uses a distinct, authenticated schema version two. The original constructors
retain schema version one and reject version two before exposing any row;
the owned constructors likewise refuse a version-one journal. There is no
conversion or compatibility reader. This prevents an older implementation
that does not honor the ownership lock from becoming a caller on this journal.

The owned journal holds a nonblocking exclusive OS lock on its checked main
file inode before opening SQLite. Its shared owner retains that lock through
every active call and blocking journal operation. Another process cannot open
the journal and classify its rows as inherited until the prior owner exits or
drops every owner reference. The OS releases the lock after a crash; no
sidecar, stale process identifier, durable deadline, or manual cleanup is
needed. SQLite closes before the lock descriptor so closing an extra main-file
descriptor cannot release SQLite's process-scoped locks during an operation.
The contract requires a private directory on a local filesystem that provides
coherent advisory `flock`, atomic same-directory rename, and durable file and
directory sync. Every journal participant must use the SDK ownership protocol.
A filesystem that reports locking unavailable is refused before use; a live
owner has a distinct, retryable refusal reason from corrupt contents. A
filesystem that falsely reports successful locking is outside this contract.

Only owned schema-two creation initializes a private staging file under the final path's integrity
key, checkpoints and closes SQLite, syncs the complete main file, then publishes
it atomically without replacing a journal. The checked parent directory
serializes creation and cleanup. A crash leaves either no final journal or a
complete journal that opens; the next create/open removes predecessor staging
files in that journal's namespace. A process never needs a person to remove a
half-created journal. Process and crash tests cover every publication boundary,
exclusion, automatic recovery, and refusal by the original reader. Schema-one
creation and open retain the original path and coarse error text: they do not
acquire the new directory lock, scan staging files, or perform the new staging
and cleanup syncs.

Once that ownership requirement holds, an inherited row may be voided
immediately. A request from the former owner that is still in flight races the
void at consensus, where either the actual result or the no-effect receipt
wins. Neither outcome requires an operator to repair or remove journal state.

The bounded reclamation sweep considers an eligible row only after exact
`NotFound`, asks a reachable consumer voter for the separate void capability,
and sends one void attempt within its existing attempt deadline. The leader
requires the exact durable activation certificate or the same process's
unanimous admission proof for that exact immutable scope. Before first
activation, readiness is withheld until every voter supplies that proof; one
unreachable voter makes the reachable stores report `NoQuorum`. This applies
after creation, a scope change, or a restart before activation. The proof is
needed because every voter must be able to apply the selected profile. The
first V2 command persists the certificate, and a restart can reuse it. Each
new scope must establish its own proof. Membership changes admit
learners under that same immutable profile. An older binary refuses the store
format, so it cannot later participate in the certified voter set. A voter
outage after activation does not prevent a quorum from committing a void.

Readiness checks its exact-scope in-memory proof before consulting storage.
An uncached activation lookup uses the caller's original readiness deadline;
once read, the certificate seeds that same proof cache. Only fresh peer probes
have the shorter budget of 250 ms or half the time then remaining, whichever
is smaller. A queued SQLite lookup therefore does not consume that probe
budget, and later readiness calls do not repeat the lookup. Mutation admission
still reads the activation certificate before using a cached fresh proof so it
can decide whether an activation proposal is required. Baseline V2 capability
admission retains unavailable-before-unsupported error precedence.

The consensus transport owns cold setup separately from the bounded readiness
caller. Readiness wraps `SessionConsensusPeer::call` with its deadline; it does
not pass 250 ms to `call_with_timeout`. The transport's detached attempt keeps
its existing 1.5-second cold-connect cap after a probe times out, and a later
probe can use the completed connection. Until the required proof exists, a
short probe may still report `NoQuorum` while that setup completes.

An unsupported journal or voter keeps the row and increments `unsupported`
for every retained eligible row that the answer proves unsupported;
a current waiting caller increments `waiting_callers`. An unavailable or
unknown void retains the row, advances the cursor, and suppresses further
void attempts for that pass while status-resolvable rows continue. The cursor
wraps and retries retained rows in a later pass. An exact void receipt removes the row and remains available
to live or recovered handles through a shared in-memory notice. An original
success returned by void remains retained until its caller releases it. A
recovery lookup acquires its notice under the same journal operation permit
as its authenticated row read; removal while handle construction awaits
another lookup cannot lose the deciding receipt. The
caller continues to own the existing bounded sweep scheduling; no new timer
or deadline configuration is introduced.

## Wire and storage boundaries

The extension has its own profile digest, appended command and error variants,
and durable store-profile discriminator. The original request ID and body
commitments retain their existing meaning. The extension's receipt codec adds
one terminal no-effect result under its profile. A baseline store rejects that
result; an old binary rejects the extended store's format before participation.
Snapshot export, installation, cold receipt reads, and reopening preserve and
check the immutable profile. A snapshot cannot convert a store's profile.
The schema bound counts the admitted schema: 44 objects for the complete
original layout and 45 with the void marker. Both roster profiles and dynamic
membership remain supported. Offline recovery validates and hashes the marker
and decodes receipts under the selected profile. Only a void-profile store
probes its voters during readiness and reports
`fenced_transition_profile_mismatch` when its profile is unsupported. This
probe has a short sub-deadline that reserves time for the readiness scope
check, and a positive proof is cached for the exact scope. Baseline readiness
performs no extension probe or lookup and retains its original states, RPC
count, and barrier latency.

Creation uses `SqliteSessionBackend::open_with_fenced_transition_v2_profile`
with `FencedTransitionV2Profile::V2WithVoid`. The atomic consensus initialization
writes database format six and an exact profile marker containing its digest
and the independent lane-layout version. Native frontiers retain that profile
before the first receipt. Other lane activations preserve the outer format.
`open` continues to select the original profile and refuses an extended store.
Crossing a stored-format boundary requires a fresh install.

The appended consensus commands are `VoidFencedTransitionV2` and
`ActivateVoidFencedTransitionV2`; the latter carries the unanimous scope
certificate when no activation exists. `FencedTransitionVoided` is the new
terminal error, fixed receipt tag 26 under the extended profile only. The
existing capability operation continues to answer `V2`; the added
`FencedTransitionV2VoidCapability` operation advertises the extension.

An explicitly opted-in consumer offers `opc-session-consumer/2-void` before
`opc-session-consumer/2`. A baseline consumer retains its single `/2` offer,
and a baseline store retains its exact original ALPN list and selects `/2`
even from an opted-in offer. A void-profile store may select `/2-void`; that
selection establishes decoding support only. Authentication, the exact
revision-five Hello, capability proof, and activation rules still apply.
Construct clients with
`StatelessSessionConsumerClient::with_fenced_transition_v2_void_transport`
before creating persistent pools; selecting an owned journal does not alter
an already constructed client's offer.

The marker is necessary because the frozen decoder closes the connection on
an unknown operation without a reply, indistinguishably from a transport EOF.
After authentication and the scope handshake, a `/2` selection is therefore a
definite unsupported answer for that physical lane. The consumer sends neither
void nor its capability probe on `/2`, and keeps the lane usable for original
operations. On `/2-void`, a definite capability answer is cached for that
physical connection only; reconnect or authority replacement requires a new
answer. Transport and TLS failures before an authenticated selection remain
unavailable and never seed an unsupported cache. When a first positive probe
wins, dropping the competing in-flight probes retires their physical lanes.

Original request bytes, payload and binding commitments, receipt limits, and
epoch-maintenance rules are unchanged. A void may bind the original request's
deterministic authority or fencing rejection instead of `FencedTransitionVoided`;
either is a recorded no-effect result for that exact request.

## Cost and validation

A void occupies one of eight proposal slots. First activation can hold it across
peer profile probes if readiness has not already established the proof;
subsequent voids use the stored exact-scope certificate.
The consumer sweep is sequential and bounded by its existing row and time
budgets. A reclaimed unbound row normally costs three committed log entries:
the preliminary status read's logical-time advance, the void, and the void's
final status read. Retries consume log work but never another receipt binding
for the same ID. Each new binding consumes one ordinary history entry and
uses the existing retention and retirement rules.

The ordinary library shard fills a small configured journal to capacity,
reopens it, drains every row through the real client and voter set, and proves
that preparation succeeds again. The production-capacity proof is opt-in:

```sh
cargo test --locked -p opc-session-testkit --all-features --lib \
  consumer_full_journal_void_reclaims_all_inherited_unbound_rows -- \
  --ignored --test-threads=1 --nocapture
```
