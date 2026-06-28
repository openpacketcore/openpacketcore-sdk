# Opc Sdk

OpenPacketCore SDK facade crate — compose CNFs from a single dependency.

## Status

**Production-ready core facade**

The default feature set exposes the SDK runtime, configuration, session, SBI,
alarm, identity, key, and shared-type composition surface. Experimental protocol
codecs, including the S2b-focused `opc-proto-gtpv2c` crate, the Diameter base
scaffold in `opc-proto-diameter`, and the IKEv2 scaffold in
`opc-proto-ikev2`, are intentionally not re-exported by this facade or its
prelude; CNFs that need them should add the relevant protocol crate as a
direct dependency and follow that crate's conformance boundary.

## Reference

[RFC 008](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/008-cnf-runtime-chassis.md), [RFC 001](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/001-management-substrate.md), [RFC 004](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/004-session-store.md), [RFC 007](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/007-sbi-service-framework.md)

## Quick start

```rust,no_run
use opc_sdk::prelude::*;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
