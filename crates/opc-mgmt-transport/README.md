# opc-mgmt-transport

Shared transport policy for management-plane listeners.

This crate centralizes the small set of TLS and plaintext rules used by gNMI,
NETCONF, and other management entry points. It wires `opc-tls` server settings
into a fail-closed management policy and keeps plaintext use limited to
non-production runtime modes.

## API Shape

Public API:

- `TlsBootstrap` builds an `opc_tls::ServerConfig` from a runtime mode, peer
  policy, ALPN IDs, TLS-1.2 compatibility setting, and identity watcher.
- `plaintext_permitted` and `ensure_plaintext_permitted` gate cleartext
  management listeners.
- `TransportError` reports invalid peer policy, missing or malformed ALPN IDs,
  disallowed TLS compatibility, plaintext mode violations, and lower-level TLS
  setup failures.
- `ALPN_H2` is the shared HTTP/2 ALPN value used by gNMI.

Example:

```rust
use opc_mgmt_transport::{ensure_plaintext_permitted, TlsBootstrap};
use opc_runtime::RuntimeMode;

ensure_plaintext_permitted(RuntimeMode::Lab)?;
```

`TlsBootstrap` rejects unconstrained peer policy in fail-closed modes such as
`Production` and `Conformance`. Plaintext is allowed only for `Dev` and `Lab`.

## Relationships

- Depends on `opc-tls` for certificate, identity, and server-config mechanics.
- Used by protocol listeners such as `opc-gnmi-server` and
  `opc-netconf-server`.
- Does not authenticate application principals by itself; listener code maps
  verified identities into `opc-mgmt-principal` types.

## Status And Limits

Current scope:

- Management-specific guardrails for TLS and plaintext operation.
- ALPN validation and explicit TLS-1.2 compatibility opt-in.
- No certificate-chain parsing, SPIFFE verification, or key loading logic here.

## Roadmap

- Keep transport policy shared across management protocols.
- Add new ALPN or mode checks only when a concrete listener needs them.

## Verification

Run:

```sh
cargo test -p opc-mgmt-transport
```
