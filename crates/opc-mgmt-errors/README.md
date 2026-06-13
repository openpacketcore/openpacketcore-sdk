# opc-mgmt-errors

Transport-neutral status taxonomy and the mappings from OpenPacketCore SDK error
codes to gNMI gRPC status codes and NETCONF `<rpc-error>` values.

Both the gNMI and NETCONF servers must translate the same `opc-config-bus`
commit failures (and read/authz denials) into client-facing errors, and they must
do it identically and without leaking internal detail. This crate owns that one
table: [`MgmtStatus`] (a gRPC-aligned code taxonomy that maps 1:1 to
`tonic::Code` in the gNMI server), the NETCONF `<rpc-error>` `error-type`/
`error-tag` enums, and the `commit_error_to_*` mappings. The mappings `match`
`CommitErrorCode` exhaustively, so a new SDK error code cannot be added without
forcing both transport mappings to be updated.
