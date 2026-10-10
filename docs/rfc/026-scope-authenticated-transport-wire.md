# RFC 026 wire appendix: scope transport version 1

This normative appendix accompanies [RFC 026](026-scope-authenticated-transport.md).
It freezes startup proof, local context, exporter context, scope header,
authority request digest and response binding bytes. The
[authority/startup vectors](026-scope-authenticated-transport-vectors.json) and
[batch vectors](026-scope-authenticated-transport-batch-vectors.json) use synthetic
public fixtures; they are not credentials or runtime qualification. Store
profile integration must compare these vectors with the landed core helpers
before advertising the profile. Changing a layout changes the wire/profile
contract; do not infer a layout from a Rust struct's memory representation.

## Primitives and identities

Concatenation is `||`. `B[n]` is exactly n octets. `U8`, `U16`, `U32` and `U64`
are unsigned integers of the stated bit width, big-endian, with no padding.
`LP16(x) = U16(len(x)) || x`; `LP32` uses U32. Lengths count octets, not Unicode
characters. Text is exact valid UTF-8, with no NUL/control characters, trimming,
case folding or Unicode normalization. Apply the core identifier validation as
well. Reject missing/trailing bytes, unknown tags, noncanonical encodings,
overflow and a declared length exceeding its bound before allocation.
`H(x)` is SHA-256. Domain literals are ASCII including **one trailing 00 byte**.
An empty optional byte string is encoded with zero length, never omitted.

`I` is the core's 32-byte name-derived consensus-cluster identity. Reinstalling
with the same configured names does not change it. Installation-qualified
identity is a separate breaking change tracked in SDK issue #1187. `W` is the
16-byte workload/Pod UUID, in RFC 9562 network byte order, not its textual UUID.
`N` is a nonzero OS-random 16-byte process nonce. Request IDs use the same width
and random/nonzero rule, independently. Do not derive either from wall time.

```text
S = I || LP16(tenant) || LP16(nf_kind) || slot:B[32]
K = H("openpacketcore/scope/id/v1\0" || S)
```

Tenant and network-function text caps are 128 and 64 bytes. Slot is nonzero.
SPIFFE IDs cap at 2,048 bytes and must pass the configured identity parser.
`S` is this transport's scope encoding; the core's Postcard encoding below is
separate and must not be substituted for it.

A P-256 public key is a valid, non-identity SEC1 compressed point of 33 bytes
(prefix 02 or 03). `key_digest = H(public_key)`. Sign with ECDSA/P-256/SHA-256 over
the complete specified input; SHA-256 is applied **once by the signature
algorithm**, not once by the caller and again by the signer. The 64-byte signature
is unsigned, 32-byte big-endian `r || s`. Require `1 <= r < n` and
`1 <= s <= floor(n/2)` for P-256 order n. Signers replace s by `min(s,n-s)`;
verifiers reject high-S, DER, variable-width or invalid signatures.

## Connection/purpose exporter

Pin each connection to one installation and, for scope ALPN, one `S`; use
another connection for another scope. TLS client/server below means handshake
roles, independent of application roles. After the completed connection passes
material-epoch and peer policy admission, compute:

```text
label = "EXPERIMENTAL-openpacketcore-channel-binding-v1"   # no NUL
context_bytes = LP16(ALPN) || LP16(purpose) || LP16(client_SPIFFE)
             || LP16(server_SPIFFE) || LP16(I) || LP16(S_or_empty)
context = H(context_bytes)
CB[purpose] = TLS-Exporter(label, context, 32)
```

Pass the 32-byte `context` as the regular TLS 1.3 exporter's context value;
TLS internally hashes it again as specified by RFC 8446. Do not use the early
exporter. Compute locally on both endpoints; a received CB is never trusted.
Cache exactly one CB per purpose on this admitted connection. No challenge,
request digest, call nonce, class or header changes `context_bytes`.

| Exact ASCII purpose | ALPN | Last context field |
| --- | --- | --- |
| `scope-request` | `opc-scope/1` | S |
| `scope-response` | `opc-scope/1` | S |
| `boot-liveness` | `opc-scope/1` | S |
| `boot-candidate` | `opc-scope/1` | S |
| `voter-candidate` | `opc-voter-management/1` | Empty |
| `management-request`, `management-response` | `opc-voter-management/1` | Empty |
| `voter-rpc-request`, `voter-rpc-response` | RFC 023's exact consensus ALPN | Empty |

The vector's reference exporter uses TLS_AES_128_GCM_SHA256 and a synthetic
32-byte exporter master secret. For that fixture only:

```text
HKDFLabel(L,label,ctx) = U16(L) || U8(len("tls13 " || label))
                    || "tls13 " || label || U8(len(ctx)) || ctx
ExpandLabel(secret,label,ctx,L) = HKDF-Expand-SHA256(secret, HKDFLabel(...), L)
derived = ExpandLabel(exporter_master_secret, label, H(empty), 32)
CB = ExpandLabel(derived, "exporter", H(context), 32)
```

This checks reference byte construction, not an actual TLS transcript. Real
rustls client/server equality and identity/ALPN/purpose variation are required
implementation tests. Application challenges provide per-instance uniqueness
on reused connections; the exporter is deliberately not a challenge issuer.

## Startup observation and local context

The Kubernetes bootstrap audience is exactly `openpacketcore-scope-bootstrap`.
Require the token's audience set to contain only this value. The issuer URL is
configured out of band. Do not make an issuer URL, key URL or trust root from
JWT input. `credential_digest = H(raw compact JWT ASCII bytes)` including the
original base64url segments and dots, without JSON reserialization. JWT size
is at most 4,096 bytes. Verify its Pod/service-account claims and the current
consistent Pod GET before trusting this credential.

For the Kubernetes adapter, an observed running boot has this exact digest:

```text
O = H("openpacketcore/scope/platform-boot/v1\0"
    || LP16(namespace) || LP16(pod_name) || pod_uid:B[16]
    || LP16(service_account_name) || service_account_uid:B[16]
    || LP16(container_name) || LP16(container_id) || LP16(started_at))
```

Names cap at 253 bytes, container ID at 512 and started_at at 64. The last field
is the exact UTF-8 API timestamp string; compare it as an opaque observation,
not an ownership time. The trusted adapter supplies the exact observation and
checks it against the current container. Other platforms must register their
own observation domain/format, not overload these fields.

`LocalContext = U8(mode) || U8(new_store_paths_closed) || U8(peer_control_closed)`:

| Proof | Exact bytes | Meaning |
| --- | --- | --- |
| Liveness | `00 00 00` | No exclusion/closed-path claim, whether or not the process is serving. |
| Candidate | `01 01 01` | Responder holds its SDK exclusion guard and keeps new store/peer-control effect paths closed throughout signing. |

Reject every other combination. This is trusted local SDK evidence, not remote
cryptographic attestation of a lock. There is deliberately no forwarding field:
installed forwarding may continue. It is not predecessor-closure evidence.

```text
StartupInput = domain || U16(1) || U8(method) || U8(1)
            || S || W || N || public_key:B[33]
            || credential_digest:B[32] || O:B[32] || LocalContext:B[3]
            || challenge:B[32] || CB[purpose]:B[32]
```

The final U8 in the prefix is direction 1, worker responding as TLS server.
The two legal domain/method/purpose combinations are:

| Proof | Domain (including NUL) | Method | Purpose |
| --- | --- | --- | --- |
| Liveness | `openpacketcore/scope/boot-liveness/v1\0` | 7 | `boot-liveness` |
| Candidate | `openpacketcore/scope/boot-candidate/v1\0` | 8 | `boot-candidate` |

The authenticated issuer generates the fresh 32-byte challenge; it is not
selected by the worker. It tracks one-use state on that connection/purpose.
The startup request body is `S || W || O || challenge`. The response proof body
is `LP16(raw_JWT) || LP32(StartupInput) || signature:B[64]`, capped at 8 KiB.
The issuer reconstructs the entire input using its expected observations and
local CB; the encoded copy is only a claim. No ticket, admission generation or
previous boot key is required for liveness. Candidate proof still grants no
scope authority; issuance and store admission follow independently.

## Fixed scope frame header

All scope frames have the following **128-byte** header; offsets are zero-based.
The first field counts bytes **after** itself. No padding or optional header
fields are permitted. The stored profile paired with this wire revision is the
untimed profile; negotiation cannot select the timed predecessor.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | `remaining_length = 124 + payload_length`, U32 |
| 4 | 2 | Wire version, U16 = 1 |
| 6 | 1 | Kind: 1 Call, 2 Challenge, 3 Proof, 4 Result, 5 TicketNotice |
| 7 | 1 | Class: 0 SafetyControl, 1 Emergency, 2 Normal, 3 Maintenance |
| 8 | 1 | Emergency bucket: 0 none, 1 established, 2 classification |
| 9 | 1 | Method: 1 AdmitInitial, 2 SucceedClosed, 3 Close, 4 ApplyBatch, 5 Current, 6 Outcome, 7 Liveness, 8 Candidate, 9 BatchReopen, 10 BatchCancel, 11 BatchLookup |
| 10 | 2 | Flags, U16 = 0 |
| 12 | 32 | Installation I |
| 44 | 32 | Scope commitment K |
| 76 | 16 | Request ID |
| 92 | 32 | Immutable request digest D |
| 124 | 4 | Payload length, U32 |

Emergency requires bucket 1 or 2; every other class requires bucket 0. Method,
class and role must match live policy/RFC 024. Every frame in an attempt matches
the call's method, request ID/digest, installation, scope and authorized class.
A new attempt may change authorized class while keeping immutable bytes/ID/D.
Check all fixed bounds and reserve class/role capacity before reading payload.
One pooled connection has one in-flight call/proof exchange.

A Call payload is `caller_nonce:B[32] || LP32(canonical_request)`. The caller
chooses a fresh nonzero OS-random nonce per attempt, outside D; this distinguishes
responses to exact retries. Startup uses the startup request body above.
For worker calls (methods 1–6 and 9–11), the receiver sends a Challenge payload
`challenge:B[32]` after authorization, bounded body decoding and proof reservation.
Before that challenge it may instead send a correlated Result with status
`ProvenNoEffect`, a zero `own_execution_digest`, and one U16 reason from 1–5
(Invalid, Unauthorized, Retry, AuthTimeUnavailable, ProfileUnavailable). The
payload is exactly 71 bytes: the echoed 32-byte caller nonce, status byte 0,
32 zero bytes, U32 body length 2, and the reason. The Result header matches the
Call's class, method, installation, scope, request ID and digest. A role/policy
refusal reads only the fixed nonce, never allocates or reads the forbidden
command body, sends no challenge and closes the connection. The client accepts
only this no-effect form before proof transmission, after checking its nonce,
header and live TLS authentication; it conveys no committed outcome or capability.
The `succession_prechallenge_refusal` vector pins the Unauthorized form.
A controller/observer read has no fabricated worker proof. Controller succession
is reserved and refused by this scope profile; it defines no inbound voter-to-worker proof RPC.
Startup uses the issuer's challenge from its request body instead.

Canonical commands fit their core bound plus 512 bytes of transport allowance;
512 is an allowance, not emitted padding. Proof/Challenge frames are capped at
8 KiB including header; a scope Call/Result is capped at
`MAX_SCOPE_BATCH_COMMAND_BYTES + 512`. TicketNotice frames cap at 64 KiB.
Kind-specific tighter bounds still apply.

## Core authority bytes and request digest

For authority operations the canonical request is **exactly** the core helper's
Postcard bytes, maximum 4 KiB. This proposal fixes the following schema for the
untimed core integration, including its public boot-key field; it does not copy
or replace the core authority engine. `P` means canonical Postcard, specifically:

- Unsigned integers (other than single-byte fields) and enum indices use shortest
  unsigned LEB128, least-significant 7-bit group first; high bit means another
  group follows. Reject overlong encodings and overflow.
- Fixed byte arrays are raw bytes without a length. Newtypes add no bytes.
- Strings are `ULEB128(UTF8_length) || UTF8_bytes`.
- Structs/tuples concatenate fields in the order below, without names or counts.
- Bool is one byte 00/01; Option is 00 for None or 01 followed by its value.

```text
P(ScopeId) = I || P(tenant_string) || P(nf_kind_string) || slot:B[32]
P(Execution) = P(identity_string) || P(admission_generation:u64)
             || W || N || key_digest:B[32]
P(Namespace) = P(ScopeId) || P(incarnation:u64)
P(Stamp) = P(Namespace) || P(authority_revision:u64) || P(Execution)
P(Evidence) = P(kind) || evidence_digest:B[32]
    kind = 0 LocalQuiescence, 1 FinalTermination, 2 CommittedClose
P(Operation) = P(tag) || fields
    tag 0 AdmitInitial: Execution
    tag 1 SucceedClosed: Stamp(predecessor), Execution(successor), Evidence
    tag 2 Close: Stamp(current), Evidence
P(AuthorityRequest) = P(ScopeId) || request_id:B[16]
                   || P(expected_revision:u64) || P(Operation)
D = H("openpacketcore/scope-authority/request/v4\0" || P(AuthorityRequest))
```

The core validates positive generations/incarnations, bounded counters, nonzero
IDs/commitments and semantic bindings before digest/dispatch. The request's
scope equals each embedded stamp's scope. LocalQuiescence is only for self-Close;
succession requires FinalTermination or CommittedClose. Evidence references
are serializable claims, never the opaque verifier token. Decode and canonically
re-encode to identical bytes before admitting a peer's input. Use the **core
digest method** in production, not a transport-owned second implementation.

Methods 5/6 use `canonical_request = P(ScopeId)` for Current and
`P(ScopeId) || target_request_id:B[16] || target_digest:B[32]` for Outcome.
Their D is `H("openpacketcore/scope/read/v1\0" || U8(method) || request_id ||
canonical_request)`. The read request ID is distinct from the target request ID.
Startup D is `H("openpacketcore/scope/startup-request/v1\0" || U8(method) ||
request_id || canonical_request)`; each challenge is a new startup call, not a
retryable state mutation.

ApplyBatch preserves the exact native request bytes and native core digest
`H("openpacketcore/scope-batch/request/v4\0" || P(ScopeBatchRequest))`.
Its full child/claim/lane schema belongs to the atomic-batch/lane contract;
the transport uses that contract's public canonical helper, never a hash of the
outer transport envelope. The request ID is the native batch request ID.

BatchCancel uses `P(ScopeBatchAttempt)` and the original batch request ID. Its D
is the core's `cancellation_digest()`:
`H("openpacketcore/scope-batch/cancel/v4\0" || P(ScopeBatchAttempt))`.
An attempt contains the complete original stamp, request ID, lane, sequence and
request digest; cancellation cannot retarget it or change its bytes.

BatchReopen uses `P(Stamp)` to name the namespace and BatchLookup uses
`P(ScopeBatchAttempt)` to name an exact historical attempt. Both are read-only:
their independent read ID and D use the same read-domain formula as methods 5/6.
The stamp is a query target, not the caller's execution. Workers prove their own
boot key even when reading a predecessor's result; controllers and observers use
their live scope policy and mTLS. No batch read produces a capability.
Read/cancel request bodies have the 4 KiB authority-metadata bound. Apply keeps
the native command bound. SafetyControl is forbidden for every batch method;
controllers and observers may use only Normal, Maintenance or classification
for batch reads and cannot call ApplyBatch or BatchCancel.

## Ticket notice after durable issuance

After verifying Candidate and durably issuing its ticket, the authenticated
issuer sends `TicketNotice` frames on that startup connection. Each header
retains the Candidate call's installation/scope, method 8, request ID/digest and
class; the payload is `caller_nonce:B[32] || TicketNoticePage`. This is an
issuer-to-worker notification, never a store commit or a capability. Only the
configured issuer identity can deliver it. The worker checks its own S/W/N/key
commitment before exposing the notice to its client admission driver.

```text
TicketNoticePage = "OPTN" || U16(1) || notice_id:B[16]
                 || S || W || N || key_digest:B[32] || generation:U64
                 || authority_reference
                 || total_entries:U32 || first_entry:U32 || count:U16
                 || EvidenceEntry[count]
EvidenceEntry = LP32(P(predecessor_Stamp)) || kind:U8 || evidence_digest:B[32]
              || evidence_record_reference
```

The notice ID commits the immutable issuance, boot and complete ordered evidence
snapshot, including across a fresh startup connection:

```text
NoticeIdInput = "openpacketcore/scope/ticket-notice-id/v1\0"
             || S || W || N || key_digest:B[32] || generation:U64
             || authority_reference || total_entries:U32
             || EvidenceEntry[total_entries]
notice_id = first 16 octets of H(NoticeIdInput)
```

Reject the all-zero ID. This ID is a correlation commitment, not a secret or a
proof of issuance. It does not include the per-connection caller nonce or page
index. Redelivering identical contents preserves the exact page bytes; changed
evidence, including a same-count replacement, changes the ID without changing
the ticket generation or authority reference. Generation is
positive and at most `i64::MAX`. The authority reference has the mandatory form
`01 || LP16(record_uid) || LP16(revision)` defined below. The notice tells the
worker the generation/reference needed for its own request; it is still an
untrusted hint, and the scope server independently reads and revalidates them.

An entry has kind 1 FinalTermination with a mandatory evidence-record reference,
or kind 2 CommittedClose with absent reference `00` (read the core checkpoint).
Kind 0 LocalQuiescence cannot prove a predecessor closed and is forbidden here.
Each predecessor has the same scope and a lower admission generation than this
boot. Digest and predecessor binding are checked independently before use.

Sort entries by lexicographic canonical `P(predecessor_Stamp)` bytes, rejecting
duplicates. Every unresolved possible predecessor has an entry; a missing digest
is not replaced by an absence/timeout claim. Each stamp is at most 4 KiB, each
page has at most eight entries, and the whole frame is at most 64 KiB. Pages have
identical notice ID, boot binding, generation, authority reference and total;
`first_entry` is the zero-based index and `count = min(8,total-first_entry)`.
An empty notice is one page with all three counters zero. Otherwise no empty or
overlapping page is valid. Stream the pages with bounded memory; a caller may
retain only evidence for the committed predecessor it is resolving.
Both sender and receiver incrementally hash all entries, checking the content
commitment before completing delivery. Stage callback hints until the complete
set verifies; a partial set cannot replace the previously completed snapshot.
The issuer uses two bounded passes over one immutable snapshot, first to compute
the ID and then to send pages; changing contents between passes fails delivery.

A lost startup connection causes a fresh authenticated Candidate exchange and
redelivery of the same existing ticket, not a new generation. Restart page
reading from index zero; changed boot or issuance observations restart reconciliation.
Rebuild predecessor entries for each delivery from a fresh linearizable current
read and retained evidence. While the ticket's boot is uncommitted, a newly
committed predecessor missing from the previous set triggers another delivery
on a fresh Candidate exchange. The worker accepts the later complete set for
the same ticket; it never combines pages from different content commitments.
Do not treat a partially received or mismatching page set as complete evidence.
The issuer's retained evidence survives redelivery. Notice bytes, references and
proofs never replace the server's independent consistent read.

## Closure-evidence digests

These definitions do not change the core request schema or its digest domain.
They define the exact value carried in `P(Evidence).digest`. All inputs below
are reconstructed from the trusted verifier's evidence, never accepted because
a request carried a matching-looking hash.

For Kubernetes FinalTermination:

```text
FinalMessageDigest = H(exact API message UTF-8 bytes)
FinalTerminationInput = "openpacketcore/scope/closure/kubernetes-final/v1\0"
                     || U16(1) || LP32(P(predecessor_Stamp))
                     || pod_uid:B[16] || LP16(namespace) || LP16(pod_name)
                     || LP16(container_name) || LP16(container_id)
                     || LP16(exit_code) || LP16(signal) || LP16(reason)
                     || FinalMessageDigest:B[32] || LP16(started_at) || LP16(finished_at)
                     || evidence_record_reference
FinalTerminationDigest = H(FinalTerminationInput)
```

Pod UID must match the predecessor workload, and the trusted retained record
must tie the exact container/termination to that process nonce and boot key.
The predecessor stamp includes its scope, generation and authority revision.
The evidence-record reference is mandatory and names the immutable observation
retained by the issuer. A later outer record revision does not rewrite the
observation's embedded capture reference. Resolve it through the configured
namespaced exact-name reader; never use a request-selected API URL.

Names cap at 253 bytes, container ID at 512, reason at 256, and timestamps at
64. The message has no codec length bound: hash the entire exact API string,
without truncation or normalization, and retain that string in the trusted
immutable observation for independent verification. The evidence input carries
only its fixed 32-byte hash. Kubelet byte-tail truncation can split UTF-8, JSON
encoding replaces invalid bytes with U+FFFD, and runtime text may precede the
file contents. The API capture can therefore exceed the termination-file limit.
See the [kubelet capture and runtime-prefix implementation](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kuberuntime/kuberuntime_container.go)
and [Go JSON string encoding](https://go.dev/src/encoding/json/encode.go).
Vectors cover both file policies, fallback logs, leading replacement characters,
binary replacement at the file and Pod limits, and a runtime-message prefix.
Exit code and signal are canonical signed-32-bit decimal
strings (zero is `0`, no leading plus/zeros); an omitted Kubernetes signal is
`0`. Remaining terminated-state fields are the exact UTF-8 strings retained
from the API, without time conversion or normalization. Unlike identifiers,
these opaque reason/message/timestamp bytes may contain control characters;
they must never enter diagnostics. Missing optional reason/message is the empty
string. Both start and finish observations are required; absence is not final
termination. Their values are evidence fields, never an ownership deadline.

For LocalQuiescence:

```text
LocalQuiescenceInput = "openpacketcore/scope/closure/local-quiescence/v1\0"
                    || U16(1) || LP32(P(current_Stamp)) || fence_nonce:B[32]
                    || U8(1) || U8(1)
LocalQuiescenceDigest = H(LocalQuiescenceInput)
```

The SDK's trusted local quiescence adapter generates the fresh nonzero OS-random
fence nonce only after irreversibly closing new store submissions and draining
peer-control submission paths. The two bytes attest those facts; all other
values are invalid. Installed forwarding is deliberately absent. The typed
Close signer requires this guard/evidence and checks the exact current stamp;
there is no API that signs an arbitrary caller-supplied closure claim. Bind this
digest inside the immutable Close request. The verifier consumes the corresponding
trusted local evidence, not a Boolean decoded from the wire.

`CommittedCloseDigest` is **exactly D of the committed Close request**, with no
extra hash or domain. This equals the authority record's retained `closed_digest`. A successor
cites the resulting closed stamp (whose authority revision advanced at Close),
not the request's earlier active stamp. The verifier resolves the exact closed
checkpoint/receipt and compares its digest; arbitrary request bytes or an
uncommitted Close are insufficient. Reusing the core D keeps Go and Rust aligned
without changing the authority format.

## Worker possession and result binding

Define `E = H("openpacketcore/scope/execution/v1\0" || P(Execution))`.
An admission authority reference is `01 || LP16(record_uid) || LP16(revision)`
(each nonempty and at most 256 bytes); absent reference is exactly `00`.
UID/revision are opaque bytes; do not parse the revision as a generation.

```text
ScopePossessionInput = "openpacketcore/scope/process-possession/v1\0"
                   || U16(1) || U8(direction) || call_header:B[128]
                   || caller_nonce:B[32] || E:B[32] || public_key:B[33]
                   || authority_reference || challenge:B[32]
                   || CB[scope-request]:B[32]
```

Direction is 0 for the worker client originating a scope call. Value 1 is
reserved for future controller-submitted succession and is refused by this scope profile.
The retained exact request and its candidate execution must match before
signing. This is a typed operation, not an API accepting arbitrary signature
inputs or exporters.
The proof body is `LP32(ScopePossessionInput) || signature:B[64]`. The verifier
reconstructs all bytes and checks the actual key against the independently read
ticket or retained committed/receipt binding. For outcome/read proof by a
not-yet-admitted boot use its independently verified ticket; for an old boot
resolving its receipt use that receipt's recorded execution. Admission references
are present on fresh AdmitInitial/SucceedClosed and absent on committed-boot
mutation/read/retry. All forms still require a fresh one-use challenge.

A Result payload is:

```text
caller_nonce:B[32] || status:U8 || own_execution_digest:B[32] || LP32(result_body)
```

Status codes are 0 ProvenNoEffect, 1 Committed, 2 OutcomeUnknown, 3 Obsolete,
4 CurrentView, 5 BatchError. Unknown has an empty result body. ProvenNoEffect carries a
U16 reason (1 Invalid, 2 Unauthorized, 3 Retry, 4 AuthTimeUnavailable,
5 ProfileUnavailable). Obsolete carries U8 (1 Superseded, 2 Closed, 3 Retired,
4 ReceiptUnavailable). These are closed enums in wire version 1.
For authority Committed, result_body is `P(Stamp) || active:U8` (00/01).
CurrentView is `P(ScopeId) || P(revision:u64) || P(retired_through:u64) ||
P(admission_generation_floor:u64) || P(Option<Stamp>) || active:U8 ||
P(Option<closed_digest:B[32]>)`. Exact authority Outcome uses the appropriate
status and body above. Batch Apply returns Committed with
`P(ScopeBatchOutcome)`; BatchCancel returns Committed with
`P(ScopeBatchReceipt)`. BatchReopen returns CurrentView with
`P(ScopeBatchReopen)`, and BatchLookup returns CurrentView with
`P(ScopeBatchLookup)`. BatchError contains the core's canonical
`P(ScopeBatchError)`, bounded at 20 KiB including all conflict metadata. Do not
collapse revision conflicts, cancellation or uncertainty into a generic refusal.
Outcome/receipt/lookup bodies are bounded at 16 KiB; a coherent reopen is bounded
at 24 KiB. Native decoders reject malformed counts, trailing bytes and alternate
encodings. A lookup's Applied outcome must match the exact target attempt.
No wire object is `CommittedScopeAuthority`.

The server sets own_execution_digest to E only for a still-current committed
AdmitInitial/SucceedClosed result delivered to that proven boot, or a committed
ApplyBatch/BatchCancel result for that boot's exact original attempt. A replayed
batch result grants no new authority. Reads and all errors use zero. The client
reconstructs this binding from the received frame:

```text
ResponseBindingInput = "openpacketcore/scope/response-binding/v1\0"
                    || U16(1) || U8(1) || result_header:B[128]
                    || caller_nonce:B[32] || status:U8
                    || own_execution_digest:B[32] || H(result_body)
                    || CB[scope-response]:B[32]
response_binding_digest = H(ResponseBindingInput)
```

The direction is 1, TLS server to requesting client. The binding digest is
local correlation evidence, **not** an unauthenticated wire token, signature or
capability. Authenticity comes from delivery on the client's live admitted
mTLS connection. Validate header ID/D/method/scope/install/class, nonce, status,
canonical result and own execution before the private capability factory can
run. The committed result requires the core's current-authority check; TLS and
the digest alone prove no commit. Controller results and CurrentView cannot
construct a capability. Do not introduce a voter-key requirement for scope RPCs.

## Deferred management proof domains

Deferred voter management keeps RFC 023's candidate/RPC inputs and codecs unchanged. For the additional
voter-to-non-voter management exchanges define the following exact signing input;
the verifier obtains V from the independent committed voter-key authority:

```text
V = I || slot:U16 || incarnation:U64 || raft_node_id:U64
  || configuration_digest:B[32] || public_key:B[33]
ManagementRequestInput = "openpacketcore/consensus/management-request/v1\0"
                     || U16(1) || U8(0) || method:U8 || V
                     || request_id:B[16] || request_digest:B[32]
                     || challenge:B[32] || CB[management-request]:B[32]
ManagementResponseInput = "openpacketcore/consensus/management-response/v1\0"
                      || U16(1) || U8(1) || method:U8 || V
                      || request_id:B[16] || request_digest:B[32]
                      || H(canonical_result) || challenge:B[32]
                      || CB[management-response]:B[32]
```

Management method tags are 1 ReplaceLostVoter, 2 ReplacementStatus,
3 PullCandidateBinding, 4 CandidatePossession. Request input is used for the
receiving voter's call to the candidate responder, not a fictitious controller
voter identity. The peer verifier issues each fresh challenge. Both inputs use
the same P-256 signature format above. Closed status/method and scheduling
metadata in the management envelope must be authenticated by its final framing
contract; do not implement this deferred transport ahead of RFC 023's helpers.
Controller requests retain their existing canonical attestation, identity/SPKI
and policy verification. Two-voter forwarding retains RFC 023's member-bound
RPC proof in each direction. Verified incarnation traffic is recorded before
later service refusal as specified in the main note.
