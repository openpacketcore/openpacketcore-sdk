# opc-protocol

Shared zero-copy codec contracts for OpenPacketCore protocol crates.

## Purpose

`opc-protocol` is the small foundation crate used by the protocol codecs in
this workspace. It defines the common decode/encode traits, decode and encode
contexts, structured error types, and spec-reference metadata used for
conformance evidence.

It is not a protocol parser by itself. GTP-U, GTPv2-C, PFCP, NAS, NGAP,
Diameter, and IKEv2 crates implement these contracts for their own wire formats.

## API Shape

- `BorrowDecode<'a>` returns a borrowed view plus the unconsumed tail.
- `OwnedDecode` decodes from `bytes::Bytes` into an owned representation.
- `ToOwnedPdu` converts borrowed protocol views into owned PDUs.
- `Encode` provides `encode` and `wire_len` with a fail-before-writing capacity
  contract.
- `DecodeContext` carries protocol version, max depth, max IE count, max
  message length, unknown/duplicate IE policy, validation level, and advisory
  allocation budget.
- `EncodeContext` carries protocol version, raw-preserving mode, and max output
  length.
- `DecodeError`, `EncodeError`, `DecodeErrorCode`, `EncodeErrorCode`, and
  `SpecRef` are log-safe and never store packet bytes.

## Example

```rust
use bytes::BytesMut;
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, Encode,
    EncodeContext, EncodeError,
};

struct TwoOctets<'a>(&'a [u8]);

impl<'a> BorrowDecode<'a> for TwoOctets<'a> {
    fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
        if input.len() < 2 {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0));
        }
        Ok((&input[2..], Self(&input[..2])))
    }
}

impl Encode for TwoOctets<'_> {
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        ctx.check_capacity(self.wire_len(ctx)?)?;
        dst.extend_from_slice(self.0);
        Ok(())
    }

    fn wire_len(&self, _ctx: EncodeContext) -> Result<usize, EncodeError> {
        Ok(2)
    }
}
```

## Status And Limits

The trait, context, and error surface is a ready reusable SDK core within this
narrow contract. That status does not transfer to individual codecs. Protocol
crates are responsible for enforcing their supported context limits and
documenting their own conformance and maturity boundaries.

Allocation budgets are advisory targets, not a runtime allocator sandbox. Use
protocol-specific limits or an external resource guard when hard allocation
control is required.

## Roadmap

- Keep the trait and error contracts stable for downstream protocol crates.
- Add only cross-protocol helpers that reduce duplicated checked arithmetic,
  conformance metadata, or log-safe error handling.
- Continue aligning tests and fuzz shells with RFC 005 round-trip and reject
  stability properties.

## Verification

```bash
cargo check -p opc-protocol --all-targets --all-features
cargo test -p opc-protocol --all-features
(cd crates/opc-protocol && cargo +nightly fuzz list)
```

## License

Apache-2.0. See [LICENSE](../../LICENSE).
