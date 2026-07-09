# opc-mgmt-limits

Shared management-plane resource limits.

This crate defines bounded request, parser, subscription, and session limits
used by management protocols. It keeps gNMI, NETCONF, and related entry points
aligned on fail-closed resource checks.

## API Shape

Public API:

- `MgmtLimits`, the validated limit set.
- `LimitsError`, the error type returned by validation and check helpers.

`MgmtLimits` covers:

- Request bytes, frame chunks, path count, and value bytes.
- XML depth, attributes, and namespace declarations.
- Subscriber queue bytes, subscriptions per session, and active sessions.
- NETCONF subtree-filter and XPath-filter complexity.
- Minimum sample interval for subscriptions.

Example:

```rust
use opc_mgmt_limits::MgmtLimits;

let limits = MgmtLimits::default();
limits.check_request_bytes(1024)?;
limits.check_paths(4)?;
```

Zero-valued limits are invalid, not unbounded. Defaults validate and include a
minimum sample interval of 100 ms.

## Relationships

- Used by `opc-gnmi-server` and `opc-netconf-server` during request parsing,
  Set/Get/Subscribe handling, and session admission.
- Independent of schema, datastore, and transport crates.

## Status And Limits

Current scope:

- Synchronous validation helpers for shared management resource checks.
- Conservative defaults suitable for protocol crates to enforce directly.

## Roadmap

- Add only protocol-neutral limits here.
- Keep transport- or protocol-specific behavior in the consuming server crate.

## Verification

Run:

```sh
cargo test -p opc-mgmt-limits
```
