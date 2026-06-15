# opc-gnmi-server

Protocol-neutral gNMI server foundation for OpenPacketCore.

This crate contains the pinned protobuf service skeleton for OpenPacketCore
gNMI. ADR 0016 allows `tonic`/`prost` only in this crate. The code here locks
the parts that are independent of full RPC behavior:

- CNF embedding traits over `C: OpcConfig`;
- schema-backed capability data;
- gNMI-shaped path normalization through `opc-mgmt-path`;
- bounded JSON value normalization;
- fail-safe extension handling;
- shared gNMI metrics recorders.

Current RPC behavior is intentionally capability-honest: `Capabilities` is
served from the generated schema registry, while `Get`, `Set`, and `Subscribe`
return `UNIMPLEMENTED` until backed by code and tests.
