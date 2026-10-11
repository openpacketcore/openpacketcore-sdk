# RFC 026 addendum: worker child point reads

Status: proposed; design review precedes implementation. Resolves the API gap in
[#1221](https://github.com/openpacketcore/openpacketcore-sdk/issues/1221).
Applies to [RFC 026](026-scope-authenticated-transport.md) and
[RFC 027](027-scope-batch-lanes.md); coherent restore remains RFC 028.

## API and linearization

Add `ScopeClient::read_child(authority, key, class, deadline)`, returning
`Result<Option<ScopeChildRecord>, ScopeBatchError>`. `authority` is this process's
`CommittedScopeAuthority`; its stamp supplies the explicit `ScopeNamespace`.
`key` is a `ScopeChildKey`, never an encoded internal `SessionKey`. The absolute
caller deadline covers local admission, connection ownership and the exchange.

The worker checks its scope, execution and live process gate. The server checks
live principal/scope/method/class policy, TLS authentication, and boot-key
possession bound to the full requested stamp. Only the current worker may use
this method. Historical outcome reads keep their existing separate contract;
this change adds no observer or general claim-read API.

Dispatch through `ScopeBatchStore`, beside its existing `read`. Add a narrow
`read_current(authenticated, stamp, key)` path: perform the existing complete
current-configuration ReadIndex barrier, then read the active authority and
requested child from **one backend cut**. Native uses one admitted immutable
generation; SQLite uses one read transaction. Require the exact active stamp,
including namespace, authority revision, execution and admission generation,
and retain the existing configuration-authority checks before returning.
Separate unlocked authority and child observations are insufficient. The
existing unrestricted local observation method need not change semantics.

A follower uses the existing complete barrier/forwarding path and waits for
its applied position; a configuration change cannot authorize a reply from an
obsolete configuration. This path appends no application command, performs no
TTL or Maintenance proposal, and allocates no replay-lane sequence or retained
scan. Policy and TLS are revalidated before release of the response.

`None` means missing or a deletion tombstone at the read's linearization point.
`Some` carries namespace, opaque key, birth, generation, batch revision, the
complete claim set and canonical sealed envelope. Add the missing public
`ScopeChildRecord::batch_revision()` accessor and bounded canonical record
helpers in `scope_batch`; share stored-row validation rather than duplicating
it in transport. Envelope authentication/decryption and logical AAD checks stay
with the consumer. The observation never constructs an effect capability.
Use exact child conditions/CAS after acquiring the entire consumer key set;
separate point reads do not constitute one multi-key snapshot. A later update
or delete/recreate must conflict with the old generation or birth.

## Admission and builder lifetime

Standalone reads take one resident/running read reservation under the native
stable-scope scheduler key, without acquiring a batch lane. The trusted class
is carried through authenticated framing and class-specific connection,
handshake, proof and server-dispatch pools. Normal is ordinary foreground work;
Emergency is established emergency work; EmergencyClassification handles
unverified classification; Maintenance is background work. SafetyControl is
refused. The server admits a current Emergency worker before spending its
Emergency dispatch credit. The existing class-unaware leader ReadIndex FIFO
boundary remains explicit; this change does not claim isolation beyond it.

Add `ScopeBatchReservation::submit_with_reads` for a post-grant builder with a
borrowed `ScopeBatchReadContext<'run>`. It exposes the existing build context
and `read_child(key, deadline)` through the coordinator's trusted
`ScopeBatchPort::read_child`. The context borrows the running permit, fixes its
effective class and stamp, and has no public constructor or `Clone`. A mutable
read borrow permits one such exchange at a time. It cannot escape the builder,
survive cancellation, or be detached into a task after the permit is released.
Keep the existing `submit` API for builders that need no child reads.

The native port and the local-store adapter reuse that running/resident
entitlement; neither calls the caller scheduler's `reserve` again. The server's
independent admission still applies. The read acquires no additional lane; its
enclosing builder continues to own its original lane until normal transfer or
cancellation. This must progress with caller resident/running limits of one.
Take the process gate per polling step, as scan observations do, so a waiting
read cannot hold graceful Close. Deadline/cancellation releases read resources
without submitting, cancelling or resolving an application batch.

## Wire revision and bounds

Introduce scope transport **revision 2**: TLS ALPN `opc-scope/2`, frame version
`U16(2)`, and revision-2 process-possession/response-binding inputs and vectors.
ALPN participates in the TLS exporter context. Reject revision 1 at negotiation
or framing; there is no old-transport fallback. Independent stored profiles,
authority digests, ticket schemas and envelope formats do not change.

Add method **17 `ChildRead`** and result status **7 `ChildObservation`**. Preserve
the existing header correlation, fresh caller nonce, proof challenge and TLS
response binding. `own_execution_digest` is zero on every observation/error.
Using the wire appendix's `P`, `LP16` and `LP32` notation:

```text
request = LP16(P(Stamp)) || child_key:B[32]
D = H("openpacketcore/scope/child-read/v1\0" || U8(17)
      || request_id:B[16] || request)
observation = LP16(P(Namespace)) || child_key:B[32] || present:U8
            || (LP32(P(ScopeChildRecord)) when present == 1)
```

Request limit: `MAX_SCOPE_AUTHORITY_RECORD_BYTES + 34` (4 KiB + 34).
Observation limit: `MAX_SCOPE_CHILD_VALUE_BYTES + 8192` (1 MiB + 8 KiB).
The existing outer result adds 69 bytes and its fixed header adds 128; enforce
these method-specific limits before allocating/reading variable payloads.
Only presence tags 0/1 are valid. A present record must have a value and match
both the echoed and requested namespace/key. Validate positive bounded birth,
generation and batch revision, at most eight distinct nonzero claims, and the
bounded canonical envelope. Reject trailing bytes, overlong encodings and
invalid lengths/counts before allocation; canonical re-encoding must agree.
Missing replies echo the namespace/key too. A valid envelope for another key
or incarnation is never usable merely because its TLS/header binding passes.

## Error contract

| Condition | Public result |
| --- | --- |
| Invalid local input or an already elapsed deadline | `InvalidRequest` for invalid input; `Unavailable` for deadline expiry |
| Class/authorization, obsolete-stamp, retired-scope or verified profile refusal | Preserve `Scope(Unauthorized/StaleAuthority/Retired/ProfileNotActivated)` |
| Verified stored corruption/incompatible row | `FormatMismatch` |
| Valid correlated store refusal | Preserve its canonical `ScopeBatchError` through existing `BatchError` framing |
| Admission closure, unavailable barrier, deadline, TLS/time failure, malformed or mismatched observation | `Unavailable`; never `None`, a conflict, or a final no-effect claim |
| Existing transport `OutcomeUnknown`, including an ambiguous lost response | Preserve `OutcomeUnknown`; this read alone does not settle any pending batch |

An untrusted reply cannot turn a transport/parser failure into a definitive
store refusal. Decode typed errors only after response authentication and full
request correlation. A fresh read is safe after an unavailable observation;
exact retry rules for already submitted mutations remain unchanged.

## Qualification and operation

Start implementation with REDs from #1221: correctly framed/authenticated
responses containing another key or namespace; wrong process, boot key,
principal or scope (including one principal with two slots); policy change and
stale admission/authority generations; delete/recreate with a new birth and
update with a new generation; malformed/noncanonical/oversized records and
envelopes; follower reads, configuration cutover and dropped replies. Observe
fresh ordered writes through the read and reject replay of an earlier response.

Also prove no application append, no standalone lane/sequence change, no effect
capability issuance, and progress of a post-grant predicate read with the caller
budget saturated by its own builder. Cover borrowed-context escape rejection,
cancellation/Close, and rejection of transport revision 1. Test native TLS plus
both backend cuts; retain every existing assertion and deadline. Run full local
gates on the final candidate before handoff.

Restart discards only in-flight read observations and retries under fresh
authentication. Revision mismatch during rollout produces retryable transport
unavailability until both endpoints use revision 2. No node cleanup, volume
conversion or operator recovery step is introduced. Existing scope ownership,
pending mutation reconciliation and emergency forwarding are unaffected by a
read timeout, restart or dropped response.
