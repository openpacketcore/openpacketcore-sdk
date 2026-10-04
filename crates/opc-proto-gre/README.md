# opc-proto-gre

Experimental bounded NWu keyed GRE and abstract QFI associations for
[SDK #789](https://github.com/openpacketcore/openpacketcore-sdk/issues/789).
This crate implements TS 24.502 V18.8.0 §8.3.2 and §9.3.3 using the shared
`opc-protocol` contexts, errors, `Encode`, and `ToOwnedPdu`.

`NwuGrePacket::decode` takes a complete datagram and an explicit `Direction`.
Its borrowed result allocates nothing; all bytes after the eight-octet GRE
header are one opaque, nonempty user payload. Payload contents are not parsed
as IP, Ethernet, or a second GRE header. `OwnedNwuGrePacket::decode` shares the
supplied `Bytes` backing storage. `to_owned_pdu` copies only the bounded payload.
Direction must come from the caller's authenticated transport context; the
codec does not establish authenticity. Directionless decoding traits cannot
express this requirement and are intentionally not implemented.

`Qfi::new` checks 0–63. `DirectionalQos::Uplink` has no RQI field; downlink has
an explicit `Rqi`. Encoding always emits C=0, K=1, S=0, version zero, Protocol
Type zero and zero spare bits. Receive ignores every Protocol Type, as the
NWu specification requires. It rejects unsupported flags, missing/truncated
Key, and uplink RQI. RFC 2784 bits 6–12 are ignored; legacy routing/strict
source/recursion flags are unsupported. Nonzero Key spare bits are accepted
and dropped as an explicit SDK receive choice. See [CONFORMANCE.md](CONFORMANCE.md)
for the distinction between standards rules and local choices.

The context's `max_message_len` limits the entire GRE datagram. Decode checks
it before reading fields. Construction, `wire_len`, and encoding enforce it;
encoding errors leave the destination unchanged. The limit excludes any
preexisting destination prefix. Raw-preserving encoding is unsupported and
fails before writing, since receive-only ignored fields must not alter NWu
transmit coding. Bounds errors contain static reasons, without configured
limits or lengths. Callers should select appropriate limits rather than rely
on the general context default of 65,535 bytes.

GRE has no IE containers, so `max_ies`, `max_depth`, IE policies, and the
advisory allocation budget do not add runtime guards. This fixed-profile API
always uses GRE version zero; the shared `protocol_version` hint is unused.
Every validation level enforces the same structural and directional checks.
The input-slice bound does not limit a `Bytes` buffer's larger backing
allocation, destination capacity, or memory already allocated by the caller.

`FlowMapping::new` borrows a bounded association slice for one caller-scoped
PDU session and direction. A `QfiSet` can associate multiple flows with one
opaque SA identifier. `select` returns **all** explicit QFI matches, or all
caller-declared `DefaultFallbackIntent::Eligible` candidates when no exact
match exists. Overlap, multiple defaults, and duplicate entries remain
visible. Input order has no preference meaning. Empty maps and no-match
results are supported. Selection and iteration allocate nothing, scan at most
the bounded entry count per pass, and do not clone identifiers.

The caller owns session scoping, association authentication/liveness,
allocation, QoS policy, final SA choice, XFRM installation, and supervision.
The model reports fallback intent without executing it. No metrics or runtime
reports are emitted. All packet, field, association, selection, and iterator
`Debug` implementations redact values, including opaque IDs without calling
their formatter. Explicit accessors expose fields to callers that need them.

Validation:

```sh
python3 crates/opc-proto-gre/tests/reference.py --check
cargo test --locked -p opc-proto-gre -p opc-n3iwf-fixtures
cargo clippy --locked -p opc-proto-gre --all-targets -- -D warnings
# From crates/opc-proto-gre:
cargo +nightly-2026-07-23 fuzz run nwu -- -max_total_time=60 -max_len=4096
```

Cargo publication is held (`publish = false`). Graduation requires independent
review, peer interoperability, and downstream evidence that authenticated
session/direction scoping and SA selection honor this boundary.
