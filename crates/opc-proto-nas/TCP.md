# Bounded NAS-over-TCP framing

`opc_proto_nas::tcp` constructs and receives the NAS envelope defined by
[TS 24.502 V18.8.0 clause 9.4](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.08.00_60/ts_124502v180800p.pdf).
Its two-octet big-endian length excludes the prefix and counts only NAS payload
octets. Clause 8.2.4 permits an envelope across TCP packets; clauses 8.2.1–8.2.5
describe surrounding transport behavior that this codec does not implement.

## Receiving and constructing

Create `NasTcpLimit` from an inclusive payload maximum between 1 and 65,535.
`decode_envelope(input, limit)` borrows the first complete opaque payload and
returns its unread tail. A partial prefix or body returns `Ok(None)`. An empty
or above-bound declared length is refused as soon as both prefix octets exist.
A valid first frame remains valid even if its tail contains a partial or
malformed second frame.

`NasTcpDecoder::feed(&mut input)` consumes through at most one frame, advancing
the caller's input slice. Repeat while that slice is nonempty so coalesced
frames and a trailing partial frame are all supplied. `Ok(None)` consumes the
available partial input and means more data is needed while the stream is open.
`NasTcpFrame::into_payload` transfers its allocation to the caller.

For example, feeding `00`, followed by `03 7e 00 41 00`, first needs more data,
then yields the three opaque NAS octets and leaves the final `00` in the caller's
slice. Feeding that last octet needs more data. Only explicit finalization
classifies it as truncation. These octets are synthetic test data.

Call `finish` after feeding all remaining bytes on EOF, transport loss or
cancellation. A clean boundary succeeds permanently and repeated finalization
also succeeds. A partial prefix or body becomes terminal `Truncated`. Earlier
framing errors remain the original error. A terminated decoder never consumes
new input; create a new decoder for a new stream. Dropping an unfinished decoder
discards its buffer but does not report a framing outcome.

`encode_envelope(payload, limit, output)` writes the prefix and exact payload
into caller storage and returns the written length. Invalid lengths and short
output leave all storage untouched. Success preserves the output suffix. A
payload of 65,536 octets is refused rather than wrapped or silently truncated.

## Resource and diagnostic contracts

The incremental decoder holds a two-octet prefix and at most one payload within
the caller's bound. It starts without allocating; prefix validation precedes
`try_reserve_exact` of the declared length. It never reserves the coalesced
input size or builds a queue of completed frames. Completed allocations and
unread input are caller-owned. Allocator bookkeeping is outside this logical
payload bound. Truncation or another framing failure releases the partial
buffer; a reserve failure becomes the static `AllocationFailed` error.

Allocation-counter tests measure zero allocations for partial/invalid prefixes,
borrowed decoding and caller-storage encoding. A three-octet frame in a 1 MiB
coalesced chunk allocates exactly three payload bytes once. Completion transfers
that allocation without copying; explicit finalization and drop release partial
buffers. These tests use the workspace's existing test-only allocation counter.
Production dependencies and the workspace's `unsafe_code = "forbid"` policy
remain unchanged.

All data-bearing `Debug` implementations are redacted. Errors are fixed,
bounded values without an error source or input data; there are no logs or
metrics in this module. Payload accessors deliberately expose opaque NAS to the
caller, which must keep it out of diagnostics. No content decoding, security
verification or subscriber decision is implied by accepting an envelope.

Zero-length refusal, caller-selected limits, sticky termination and buffer
ownership are SDK contracts, separate from the standard's wire layout. TCP
listeners, reconnect selection, IPsec/security termination, SA provenance,
storage and UE lifecycle remain consumer responsibilities.

## Independent evidence

The reviewed `nas-tcp` subset of #784 contains nine fixture cases. It was merged
in [#830](https://github.com/openpacketcore/openpacketcore-sdk/pull/830):

- Source head: `b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d`.
- Merge: `987246c8be773b19304f059231c39baa8d54d123`.
- Subset tree: `10da083aacca09be3ffbc707921a238a7ce6aa10`.
- `COMPLETION.json` SHA-256: `861e6291b5ab727f1fc6318e78b303f60ec04388714dfd570d261bd436196f9a`.

The fixture wires, completion records and original runtime claims are unchanged.
`opc-n3iwf-fixtures/tests/nas_tcp.rs` passes all nine through the real APIs.

`tests/nas_tcp_reference.py` independently generates 174 streams with Python
length arithmetic and `struct.pack`, without importing SDK code or its encoder.
The committed TSV has SHA-256
`3a665814245476e584064a706b74d4b35be6bcb75ba20b7538d4a44a158c65f4`.
Both Rust decoder APIs must match its opaque payloads and outcomes: 54 complete,
46 need-more-data, 46 terminal truncation, eight empty-length refusals and
20 above-bound refusals. Complete streams must encode to the independent wire.

Additional tests cover all 2,048 partitions of a three-frame stream, every
truncation of a two-frame stream, all 65,536 prefixes at five bounds, every-byte
input, the 65,535-byte maximum, wrap refusal, malformed tails, output atomicity,
allocation behavior and value-free diagnostics. Fuzzing uses an independent
cursor model with arbitrary segmentation, coalescing and finalization. A local
run passed 8,110,190 executions in 61 seconds from 206 initial seeds, with a
4,096-byte cap; eight seeds are committed. These are synthetic SDK checks and
do not establish live N3IWF, TCP peer or AMF interoperability.

Reproduce the deterministic checks from the repository root:

```sh
python3 crates/opc-proto-nas/tests/nas_tcp_reference.py --check
python3 scripts/check-n3iwf-fixture-contracts.py --check
cargo test --locked -p opc-proto-nas -p opc-n3iwf-fixtures --all-features
cargo clippy --locked -p opc-proto-nas -p opc-n3iwf-fixtures --all-targets --all-features -- -D warnings
```

From `crates/opc-proto-nas`, run `cargo +nightly fuzz run nas_tcp` with the
repository-pinned fuzz toolchain and the desired time bound.
