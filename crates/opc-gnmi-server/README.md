# opc-gnmi-server

Capability-honest gNMI server foundation for OpenPacketCore.

This crate contains the pinned protobuf service skeleton for OpenPacketCore
gNMI. ADR 0016 allows `tonic`/`prost` only in this crate. The code here locks
the parts that are independent of full RPC behavior:

- CNF embedding traits over `C: OpcConfig`;
- schema-backed capability data;
- gNMI-shaped path normalization through `opc-mgmt-path`;
- bounded JSON value normalization;
- fail-safe extension handling;
- shared gNMI metrics recorders;
- SDK-managed mTLS listener bootstrap;
- authenticated read-only `Get` for JSON/JSON_IETF config and operational
  data through explicit CNF/generated projection hooks;
- authenticated atomic `Set` through generated patch applicators and
  `opc-config-bus`;
- opt-in OpenPacketCore commit-confirmed `Set` extension for begin, confirm,
  cancel, and timeout. The gNMI extension does not implement NETCONF
  `persist`/`persist-id` or operator-token semantics; token-like unknown payload
  fields are rejected instead of ignored;
- opt-in gNMI master-arbitration for `Set`, fenced by authenticated tenant plus
  gNMI role. Missing role uses the OpenConfig empty-role default. Disabled
  servers reject the extension, optional servers enforce it when present, and
  required servers deny writes that omit it;
- authenticated `Subscribe` for ONCE/POLL snapshots and STREAM sample/config
  on-change delivery. OpenConfig `History` replay is not advertised or
  implemented by this live/snapshot profile; replay requests fail closed.

Current RPC behavior is intentionally capability-honest: `Capabilities` is
served from the generated schema registry and can be exposed over the
`run_gnmi_tls_listener` mTLS path. `Get` is implemented for authenticated
read-only JSON/JSON_IETF reads when the binding supplies projection support.
`Set` is implemented for generated config roots with explicit patch support.
When the OpenPacketCore commit-confirmed extension is registered, `Set` supports
begin/confirm/cancel and timeout only. Persist-token semantics are NETCONF-only
for this SDK boundary. `Set` can also be configured to advertise and enforce
OpenConfig master-arbitration before candidate construction, patching, or
commit-confirmed control.
`Subscribe` supports JSON/JSON_IETF ONCE, POLL, STREAM SAMPLE, config
ON_CHANGE, and operational ON_CHANGE when the binding supplies an event source;
TARGET_DEFINED, aggregation, QoS marking, and history replay are not advertised
by this profile and fail closed.

## Encodings

`Capabilities` advertises only `JSON_IETF` and `JSON`. `BYTES`, `ASCII`, and
`PROTO` are intentionally not advertised and return fail-closed errors for
`Get`, `Set`, and `Subscribe`. Generated renderers produce JSON/RFC 7951
payloads only.

## External Interop

Generated tonic/prost conformance covers Capabilities, Get, Set, Subscribe,
commit-confirmed, master-arbitration-backed Set, and fail-closed unsupported
encoding/history behavior over the supervised mTLS listener.

`scripts/gnmi-interop-gnmic-smoke.sh` provides an optional live-target smoke
test with `gnmic`. It skips unless `OPC_GNMI_INTEROP=1` is set and also skips
when `gnmic` is not on `PATH`. When enabled, it requires:

- `OPC_GNMI_ADDR`
- `OPC_GNMI_CA_CERT`
- `OPC_GNMI_CLIENT_CERT`
- `OPC_GNMI_CLIENT_KEY`

Optional variables are `OPC_GNMI_TLS_SERVER_NAME`, `OPC_GNMI_TIMEOUT`,
`OPC_GNMI_GET_PATH`, `OPC_GNMI_SUBSCRIBE_PATH`, and `OPC_GNMI_ENABLE_SET=1`
with `OPC_GNMI_SET_PATH` plus `OPC_GNMI_SET_JSON` for a mutating Set smoke
test. The script runs Capabilities, Get, Subscribe ONCE, and optional Set over
mTLS using `json_ietf`.
