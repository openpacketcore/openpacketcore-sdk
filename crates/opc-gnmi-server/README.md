# opc-gnmi-server

Protocol-neutral gNMI server foundation for OpenPacketCore.

This crate intentionally does not contain a gRPC service yet. ADR 0016 is still
`Proposed`, so `tonic`/`prost` are not allowed to enter the workspace. The code
here locks the parts that are independent of protobuf generation:

- CNF embedding traits over `C: OpcConfig`;
- schema-backed capability data;
- gNMI-shaped path normalization through `opc-mgmt-path`;
- bounded JSON value normalization;
- fail-safe extension handling;
- shared gNMI metrics recorders.

The future protobuf layer should adapt generated gNMI messages into these
contracts rather than duplicating schema, path, value, extension, or metrics
logic in RPC handlers.
