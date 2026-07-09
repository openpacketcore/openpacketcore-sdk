# opc-gnmi-server proto

Vendored OpenConfig gNMI protobuf sources used by `opc-gnmi-server`.

The server builds Rust protobuf and tonic server bindings from the pinned
OpenConfig `.proto` files in this directory. Generated Rust output is produced
by the crate build and should not be edited by hand.

## Source And Pin

- Upstream repository: `https://github.com/openconfig/gnmi`
- Pinned tag: `v0.10.0`
- Pinned commit: `5473f2ef722ee45c3f26eee3f4a44a7d827e3575`
- Vendored files:
  - `gnmi.proto`
  - `gnmi_ext.proto`

`gnmi.proto` declares `option (gnmi_service) = "0.10.0";`. The build script
parses that option into `OPC_GNMI_PROTO_VERSION`.

## Generation Shape

The parent crate uses `tonic-build`, `prost`, and a vendored `protoc` binary
from `protoc-bin-vendored`. The build generates server-side bindings required
by `opc-gnmi-server`; client generation is not part of this crate's public API.

## Update Checklist

When updating the vendored proto files:

- Update both `gnmi.proto` and `gnmi_ext.proto` from the same upstream commit.
- Record the new tag and commit in this README.
- Confirm `option (gnmi_service)` still reflects the intended protocol version.
- Run the parent crate tests.
- Do not edit generated Rust artifacts directly.

## Verification

Run:

```sh
cargo test -p opc-gnmi-server
```
