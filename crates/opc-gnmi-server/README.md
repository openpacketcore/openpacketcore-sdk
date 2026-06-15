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
- authenticated `Subscribe` for ONCE/POLL snapshots and STREAM sample/config
  on-change delivery.

Current RPC behavior is intentionally capability-honest: `Capabilities` is
served from the generated schema registry and can be exposed over the
`run_gnmi_tls_listener` mTLS path. `Get` is implemented for authenticated
read-only JSON/JSON_IETF reads when the binding supplies projection support.
`Set` is implemented for generated config roots with explicit patch support.
`Subscribe` supports JSON/JSON_IETF ONCE, POLL, STREAM SAMPLE, and config
ON_CHANGE; TARGET_DEFINED, aggregation, QoS marking, and operational on-change
remain fail-closed until backed by SDK contracts and tests.
