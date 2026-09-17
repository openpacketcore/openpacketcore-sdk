# SCTP receive reliability scope

This document covers the partial receive ownership slice of
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
| Recoverable readiness error | Return the error while preserving partial DATA | Native syscall errors remain terminal under the existing source contract |

No new outbound wire encoding or socket option is introduced. Existing SCTP
association/endpoint APIs, host-order `NGAP_PPID` with network-order ancillary
conversion, multihoming configuration and readback remain the foundation.
Strict PPID 60 admission, explicit PPID 66 rejection, default N2 service port,
typed path/stream lifecycle, exact generation fencing and bounded restart still
belong to the subsequent N2 profile slice. Ordinary SCTP and address/PPID
metadata establish no cryptographic protection evidence.

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
correctness. Candidate evidence must retain exact base/head/tree, failing
baseline and removed-guard results, native checks, required repository gates
and independent review separately. Round trips and synthetic schedules do not
establish live N3IWF/AMF interoperability.
