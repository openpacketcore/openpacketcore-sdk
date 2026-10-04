# N2 association lifecycle conformance

This contract completes the reusable **unprotected** N2 association scope of
[#788](https://github.com/openpacketcore/openpacketcore-sdk/issues/788) when its
required qualification gates pass. It composes the existing backend-neutral
record checker and native one-to-one SCTP adapter. It does not add NGAP procedure
state, AMF selection, stream allocation, protected PPID 66, or peer trust.

## Standards and resource policy

The [framing conformance record](CONFORMANCE.md) retains TS 38.412 V18.1.0's
RFC 4960 baseline. [RFC 6458 §6](https://www.rfc-editor.org/rfc/rfc6458.html#section-6)
and [RFC 6525 §6](https://www.rfc-editor.org/rfc/rfc6525.html#section-6) define
socket event/reconfiguration semantics separately. Linux native notification
layouts come from the Linux SCTP UAPI (`include/uapi/linux/sctp.h`), not a new
SCTP wire codec. RFC 9260 is not substituted for the baseline. Subscribing to
RFC 6525 events is separate from enabling or originating reset requests.

Maximum DATA bytes, at most 64 explicit reset stream IDs, candidate preference,
attempt count, timeouts and retry delay are **caller/SDK resource policy**.
They are not limits imposed on NGAP or negotiated SCTP stream count by a
standard. Empty reset lists mean all streams; order and duplicate IDs in an
explicit list are preserved. An over-cap list is rejected, never truncated.
Notification scratch space remains independent of the DATA byte cap.

## Authority and lifecycle

`N2AssociationOwner` owns at most one current transport. A connected
`N2Candidate` records owner identity and the owner's state before a connection
attempt begins; `candidate(existing)` records state when the existing adapter
is consumed. Candidates expose no I/O and close on drop or promotion failure.
`promote` requires exact owner identity and unchanged state, retires the old
transport, and publishes one checked, increasing generation. Two candidates
from the same state cannot both win. Retirement cannot create an ABA match,
and generation exhaustion preserves the existing current association.

`N2Generation` is affine and cannot be constructed from a number or kernel
association ID. Dropping the current token closes its transport; dropping an
old token cannot close a successor. Dropping/closing the owner retires current
authority; close is terminal. Caller-retained candidates stay unusable and
cannot promote after close; dropping them releases their connected sockets.

Send/receive admission and completion, address/path readback, path selection
and retirement check exact current authority. Replacement/retirement cancels
pending I/O. A send admitted before replacement may already have submitted
bytes: retirement cannot retract them. Results admitted before a transition
remain tagged with their original generation. A readback is a point-in-time
snapshot, not a continuing lease. The state mutex orders transitions; a receive
gate extends through terminal-event admission so queued receivers cannot cross
the retirement boundary. Socket-owned partial DATA is reused, not copied into
a second accumulator.

| Received event | Partial DATA disposition | N2 generation disposition |
| --- | --- | --- |
| Successful incoming stream reset | Clear matching association and listed stream; empty list clears all streams | Return exact direction/list; no NGAP binding inference |
| Outgoing-only, denied, failed or unrelated reset | Preserve unaffected prefix | Return exact event |
| Successful association reset | Clear matching prefix | Retire before returning event |
| Denied/failed association reset | Preserve prefix | Return event |
| Partial-delivery abort | Clear matching association/stream prefix | Retire before returning event |
| Stream count change | Preserve prefix | Return event; successful zero count retires fail closed |
| Association established with zero error | Existing conservative partial invalidation | Retain current generation |
| Restart, loss, cannot-start, shutdown, unknown association state or nonzero error | Existing affected-association invalidation | Retire before returning event |
| Path, sender-dry, AUTH metadata | Preserve prefix | Return event; no generation or trust authority |
| Unknown event | Fail closed if partial DATA exists | Retire before returning a well-formed unknown event |
| Malformed/truncated event or receive failure | Clear partial state and close | Retire; bounded error |

Stream reset/count events are passive receive support. This API does not enable
or request RFC 6525 reconfiguration, reconstruct an association after a kernel
restart, or restore UE streams. A terminal event requires a fresh connection
and explicit promotion; applications own NGAP Reset and UE state. Generic
SCTP/Diameter subscriptions retain their prior behavior. The N2 owner requires
all four lifecycle subscriptions; unsupported platforms/capabilities return a
bounded error and close the unpromoted adapter.

`N2ReconnectPolicy` bounds attempts, each attempt's duration, total elapsed time
and retry delay. Only connection failure/attempt timeout is retried. Invalid
configuration and missing support fail immediately. Deadlines use checked
arithmetic. Zero delay yields; promotion/retirement/close cancels pending
connectors. A failure or caller cancellation preserves an existing generation.
A successful connection remains a candidate until the caller promotes it.
No automatic AMF, address order, simultaneous-open or convergence preference
is selected by the SDK.

## Metadata and diagnostics

Configuration retains the existing ordered bindx/connectx lists. Readback
retains exact kernel local/peer order and transport path-health metadata;
configured order and kernel readback order are distinct observations. Existing
primary-path membership validation and kernel reconciliation are reused.
Path metadata does not establish reachability at a future time or authenticate
a peer. Primary designation records initial/explicitly selected state; it is
not a claim that every DATA packet uses that path.

New owner/candidate/token/result/readback/stream-list `Debug` output and errors
contain bounded type or classification text. Native transport errors are
mapped to bounded `N2Error` classes. No new logs or metrics print payload,
address, peer, subscriber, key, kernel ID or generation value. Public getters
return intentional readback; callers control subsequent formatting. Test
vectors use synthetic values and new assertions use bounded failure summaries.

## Independent evidence and support limits

The reviewed framing fixtures from #830/#896 are unchanged, with provenance and
digests retained in [CONFORMANCE.md](CONFORMANCE.md). Additional schedules are
independently authored test inputs rather than output from the implementation:

- [`lifecycle_tests.rs`](src/lifecycle_tests.rs): literal Linux event codes and
  native-endian byte layouts; every 16-bit stream-reset flag combination,
  all truncated prefixes, length-bit mutations, trailing data, exact extents,
  malformed states, empty/max/over-cap lists and duplicate/order preservation.
- [`n2_lifecycle_uapi.c`](tests/n2_lifecycle_uapi.c): independent C static
  assertions against the installed Linux headers for constants, sizes and
  field offsets. This proves host ABI agreement, not SCTP wire interoperability.
- [`receive_resume_tests.rs`](src/receive_resume_tests.rs): cancellation at
  every prefix of a nine-byte record, matching/unrelated incoming/outgoing
  reset schedules, failed/denied outcomes, association reset, partial abort
  and stream growth, executing the production receive owner.
- [`n2/owner/tests.rs`](src/n2/owner/tests.rs): both candidate completion orders
  and concurrent promotion, foreign/stale tokens, drop/reinstall/exhaustion,
  pending I/O and queued receive races, terminal event admission, exact
  readback, failures and deterministic paused-clock retry/cancellation bounds.
- [`n2/owner/native_tests.rs`](src/n2/owner/native_tests.rs): real kernel
  candidate races in both orders, peer closure, exact address readback,
  cancellation, ordered records, stale operations, replacement, typed shutdown,
  reconnection and candidate/current-token drop.
- [`cold_multihoming_netns.rs`](tests/cold_multihoming_netns.rs): two actual
  network paths in private namespaces; remove the active primary link while
  exchanging ordered N2 records, require secondary delivery under the same
  generation, unchanged exact address lists, typed unreachable-path metadata
  and explicit secondary primary selection. Namespace cleanup is required.

Required SCTP CI executes the C oracle, both native N2 tests, the existing
framing test and the existing cold primary-down connector test, and requires
completion markers and exactly one passing test per native command. Ordinary
Cargo runs explicitly ignore native tests; ignored-only results do not qualify.
The reset/restart edge schedules are deterministic receive/core evidence;
there is no claim here of native reset-request origination, a live AMF restart
capture, or cross-vendor N3IWF interoperability. Native lifecycle and failover
checks qualify the composed kernel path described above.

The implementation base is `44ac7a6e55ab108253a354d9ca1d612f5d7ca56b` (#911).
The accepting PR records exact public tested head/root tree, test-source
SHA-256 digests, the original failing parser detector, removed-guard failures,
adversarial mutation results and all required repository/native/hosted gates.
Self-referential commit hashes are kept in the PR evidence, not embedded into
the tree they identify. Closing #788 requires that acceptance record.
