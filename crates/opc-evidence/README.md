# Opc Evidence

Release assurance pipeline: SBOM generation, VEX scanning, gate policy
enforcement, and packet-core evidence packs.

## Status

**Production-ready**

Packet-core evidence schemas (`packet_core`) are **experimental**. They are
versioned within RFC 006 and marked with `experimental: true` in serialized
packs. Downstream products may map their smoke artifacts into this format for
comparability; doing so does not imply SDK or product certification.

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/006-conformance-pipeline.md)

## Quick start

```rust,no_run
use opc_evidence::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## Packet-core evidence packs

The crate provides `PacketCoreProtocolEvidence`, `AttachProcedureEvidence`,
`KernelDataplaneEvidence`, and a top-level `PacketCoreEvidencePack`. Each pack
can be serialized to JSON and validated with
`PacketCoreEvidencePack::validate_redaction`, which fails closed if any string
field contains a raw IMSI, MSISDN, IMEI, NAI, Session-Id, LI identifier, or key
material.

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
