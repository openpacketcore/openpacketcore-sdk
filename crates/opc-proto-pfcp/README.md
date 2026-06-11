# Opc Proto Pfcp

PFCP protocol codec (TS 29.244) for the 5G control plane.

## Status

**Experimental** — v0 covers message header parsing and raw IE preservation.
Typed IE decoding is planned for v1.

## Reference

- 3GPP TS 29.244 — Packet Forwarding Control Protocol

## Quick start

```rust,no_run
use opc_proto_pfcp::{OwnedMessage, DecodeContext};

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
