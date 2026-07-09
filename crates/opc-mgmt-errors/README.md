# opc-mgmt-errors

Shared management-protocol error mapping.

This crate maps config-bus commit failures and authorization denials into stable
gNMI-style status codes and NETCONF `<rpc-error>` classifications. It keeps
protocol crates consistent without making them depend on each other's error
models.

## API Shape

Public API:

- `MgmtStatus`, a compact status enum for gNMI-like responses.
- `NetconfErrorType`, `NetconfErrorTag`, and `NetconfError`.
- `commit_error_to_status` and `commit_error_to_netconf`.
- `nacm_denied_status` and `nacm_denied_netconf`.

Example:

```rust
use opc_mgmt_errors::commit_error_to_status;
use opc_config_model::CommitError;

fn status_for(error: &CommitError) -> opc_mgmt_errors::MgmtStatus {
    commit_error_to_status(error)
}
```

The mapping is based on `CommitErrorCode`. It intentionally does not copy
validation messages, paths, or rejected values into protocol errors.

## Relationships

- Consumes `opc-config-model` commit error codes.
- Used by `opc-gnmi-server`, `opc-netconf-server`, and operational-state
  projections that report config workflow status.

## Status And Limits

Current scope:

- Exhaustive mapping for the shared commit-error code set.
- NACM denial helpers for read/write/exec authorization failures.
- Redaction-friendly protocol errors.

## Roadmap

- Keep protocol mappings centralized when new commit error codes are added.
- Avoid embedding sensitive config details in management error responses.

## Verification

Run:

```sh
cargo test -p opc-mgmt-errors
```
