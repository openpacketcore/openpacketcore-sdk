# SCTP receive ownership and unprotected N2 framing

This document covers partial receive ownership and strict unprotected framing in
[#788](https://github.com/openpacketcore/openpacketcore-sdk/issues/788).
It does not qualify the complete N2 profile or external interoperability.

## Standards and local policy

[TS 38.412 V18.1.0](https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/18.01.00_60/ts_138412v180100p.pdf)
clause 7 names RFC 4960 as the SCTP baseline. This change retains that baseline;
it does not silently substitute RFC 9260. RFC 4960
[3.3.1](https://www.rfc-editor.org/rfc/rfc4960.html#section-3.3.1),
[6.6](https://www.rfc-editor.org/rfc/rfc4960.html#section-6.6), and
[10.1 G](https://www.rfc-editor.org/rfc/rfc4960.html#section-10.1) distinguish
stream/SSN and PPID metadata from TSN progress and give unordered SSNs no
significance. The SDK compares available complete ancillary identity using
those distinctions. The kernel still owns SCTP wire reassembly and ordering.

The configured message cap, cancellation ownership, conservative invalidation
on association events, and fail-closed handling of ambiguous events are SDK
resource and lifecycle policy. They are not new wire requirements. A partial
record retains its original cap; a different cap cannot resume it. No automatic
receive timeout is added, and an idle partial record remains owned and bounded
until receive, close or drop.

## Constructed and received behavior

| Boundary | Supported behavior | Limit |
| --- | --- | --- |
| DATA across cancelled/queued receivers | Retain consumed prefixes and the cumulative cap until one complete record is returned | One serialized receiver per socket; no application transaction or NGAP state |
| Complete path, sender-dry and AUTH events | Return the event and retain partial DATA without charging its cap | Existing parsed events only |
| Association change and shutdown | Invalidate the affected association's partial DATA and return the event | No generation token, stream-reset handler or reconnect controller yet |
| Unknown, malformed or truncated event during partial DATA | Fail closed and clear the accumulator | Cannot infer a safe boundary from an unparsed transition |
| Complete ancillary identity | Compare association, stream, PPID, delivery order and ordered SSN | TSN/cumulative TSN/context are not record identity; unordered SSN is ignored |
| Truncated DATA metadata | Preserve existing truncation flags and first-chunk metadata | Not authoritative identity; strict profile admission must reject truncation |
| Terminal error, explicit close or drop | Clear partial DATA; close can do so during pending I/O | No promise to retract a message already completed before close |
| Recoverable readiness error at the socket owner / one-to-many endpoint | Return the error while preserving partial DATA | The one-to-one association API closes on any returned receive error; native syscall errors remain terminal |

No new outbound wire encoding or socket option is introduced. Existing SCTP
association/endpoint APIs, host-order `NGAP_PPID` with network-order ancillary
conversion, multihoming configuration and readback remain the foundation.
The `n2` module now composes strict PPID 60 admission, PPID 66 DATA rejection
and the default N2 service port over those primitives. Typed stream lifecycle,
exact generation fencing and bounded restart remain subsequent work.
Ordinary SCTP and address/PPID
metadata establish no cryptographic protection evidence.

## Strict N2 framing scope

`UnprotectedN2Profile` is a backend-neutral record checker;
`UnprotectedN2Association` consumes the existing SCTP transport and applies the
checker before exposing received DATA. Its transport cannot be bypassed through
a raw I/O handle. Both constructed and received bytes remain opaque to this
module. The existing NGAP codec owns APER and procedure validation.

TS 38.412 V18.1.0 clause 7 specifies big-endian PPID and refers to IANA.
[IANA's PPID registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25)
assigns 60 to NGAP and 66 to NGAP over DTLS/SCTP;
[the service registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ng-control)
assigns port 38412. The helper supplies this default without replacing an
explicit caller-selected additional-TNLA port. The profile introduces no RFC
9260 transport behavior.

| Boundary | Supported behavior | Limit |
| --- | --- | --- |
| Constructed DATA | One nonempty bounded PDU, ordered delivery, PPID 60, caller-selected stream | No stream allocation or UE binding |
| Received DATA | Strict PPID 60, intact payload and ancillary metadata, original stream and association ID | IDs are backend metadata, not generation authority |
| PPID 66, 0 and other DATA PPIDs | Reject and abort the live adapter | No compatibility mode or DTLS fallback |
| Notifications | Return a distinct parsed event, including explicit unknown event types | No new association/path/stream state machine or protection evidence |
| Cancellation | Reuse the socket-owned partial record and receive cap | No extra accumulator or automatic receive deadline |
| Bounds and close | Retain transport cap; reject empty/oversized DATA; abort on inbound failure or owner drop | Already completed deliveries cannot be retracted |
| Readback | Delegate local/peer addresses and existing path-health snapshots | No two-association convergence, path authentication or new primary-path policy |

Nonempty DATA, ordered-only admission, rejecting incomplete/inconsistent
metadata, the caller's size cap and terminal inbound-failure policy are explicit
SDK profile choices. Notification metadata is checked before event routing;
notification PPIDs are not interpreted as DATA PPIDs. The adapter serializes
concurrent receive callers through admission and terminal-close handling, so
another caller cannot pass that boundary between a rejected record and abort.
An invalid local outbound
payload fails before sending without terminating an otherwise live association.
`Debug` and `N2Error` carry only bounded type/classification text. No raw
transport error, peer, payload, identifier or configured bound is formatted by
the new N2 types. Converting an outbound wrapper to a generic SCTP record
explicitly transfers diagnostic and mutation responsibility to the backend.

The native adapter and checker do not grant current-generation capability.
Complete #788 acceptance still requires competing-association races, exact
generation readback, typed stream lifecycle, bounded restart and the composed
multihoming/failover scenarios. AMF selection and NGAP procedure state remain
outside transport.

## Evidence provenance

[`receive_resume_tests.rs`](src/receive_resume_tests.rs) drives the production
receive owner with independently scheduled synthetic syscall results. Tests
cover every split of a nine-byte record, repeated cancellation, interleaved
events larger than the DATA budget, queued receivers, five metadata conflicts,
ordered TSN progress, unordered SSN, matching/foreign association transitions,
ambiguous events, changing limits, recoverable/terminal errors and close while
receive is pending. Values are synthetic and new failure summaries do not print
payload or peer values. These schedules are not captured SCTP packets.

Existing Linux tests separately exercise 100,000-byte multi-chunk records,
concurrent association/endpoint receivers, oversized-message closure,
multihoming/readback and SCTP-AUTH consumers. They require explicit native
execution; ordinary Cargo runs leave those tests ignored.

The reviewed, merged `n2-sctp` fixture subset from
[PR #830](https://github.com/openpacketcore/openpacketcore-sdk/pull/830) remains
unchanged. Its wire/metadata inventory does not by itself prove cancellation
correctness. A later independent byte check found that four metadata vectors
encode port 38428 while claiming 38412. [PR #896](https://github.com/openpacketcore/openpacketcore-sdk/pull/896)
corrected those vectors and their semantic checks and is merged. The N2 tests
now consume the corrected fixtures and independently compare the literal IANA
bytes before exercising host/network-order conversions. The referenced wire
digests are:

| Fixture | SHA-256 |
| --- | --- |
| `positive-ppid60-port` | `5262583a7be26feef143c72a913ee5ce748b80e3a280dda93b70a25ebdfb7572` |
| `unknown-ppid66` | `d930104925fd1c2c1f7418e81c27cb87f77a040e5894f836cb0c18bb342e558d` |

[`n2/tests.rs`](src/n2/tests.rs) covers all 32 single-bit PPID mutations,
explicit protected/legacy/swapped-endian values, both truncation flags,
notification/DATA separation, exact stream/association preservation, bounds and
redaction. The required SCTP CI lane explicitly executes the otherwise ignored
`n2::tests::native::unprotected_n2_profile` test. It checks live PPID/stream
metadata, terminal wrong-PPID rejection with two receive callers,
exact-cap/cap+1 behavior, idle receive
cancellation followed by a 100,000-byte record, and owner drop while an abort
handle survives. The pre-existing deterministic receive schedules remain the
evidence for cancellation after a partial prefix has actually been consumed.
These are synthetic metadata vectors and Linux loopback checks, not live
N3IWF/AMF peer captures.

Candidate evidence must retain exact base/head/tree, failing
baseline and removed-guard results, native checks, required repository gates
and independent review separately. Round trips and synthetic schedules do not
establish live N3IWF/AMF interoperability.
