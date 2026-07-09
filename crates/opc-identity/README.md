# opc-identity

Workload identity loading and validation for SPIFFE SVIDs.

## Purpose

`opc-identity` parses SVID certificate material, validates the SPIFFE workload
identity shape used by OpenPacketCore, and publishes reloadable identity state
for TLS and service clients.

## API Shape

- `WorkloadIdentity::from_cert_der` extracts and validates the SPIFFE ID from a
  leaf certificate.
- `build_identity_state` validates the leaf chain against active trust bundles
  and checks that the private key matches the leaf.
- `SvidWatcher::new(socket_path, initial_bundles)` reads length-prefixed JSON
  SVID updates from a SPIRE-like Unix socket and emits reload events.
- `FileSvidSource::new(cert_path, key_path, bundle_paths, poll_interval)` polls
  PEM files and emits the same state/events interface.
- `parse_certs_pem` and `parse_key_pem` are available for callers that already
  own the reload loop.
- Core data types include `TrustDomain`, `TrustBundle`, `TrustBundleSet`,
  `SvidDocument`, `IdentityState`, `IdentityReloadEvent`, `Namespace`, and
  `ServiceAccount`.

```rust,no_run
use opc_identity::{FileSvidSource, IdentityState};
use std::path::PathBuf;
use std::time::Duration;

fn file_source() -> FileSvidSource {
    FileSvidSource::new(
        PathBuf::from("/var/run/svid/cert.pem"),
        PathBuf::from("/var/run/svid/key.pem"),
        vec![PathBuf::from("/var/run/svid/bundle.pem")],
        Duration::from_secs(5),
    )
}
```

## Relationships

- Feeds `opc-tls` with `IdentityState`.
- Uses `opc-types` for tenant, NF kind, instance, SPIFFE ID, and timestamps.
- Used by security testkits to exercise SVID rotation and trust-bundle changes.

## Status Notes

- The accepted SPIFFE path layout is
  `/tenant/<tenant>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance>`.
- Certificates are rejected when expired, not yet valid, missing a trust bundle,
  or carrying an invalid workload path.
- Watchers retain the last good identity after invalid updates and clear expired
  state during expiry monitoring.
- The socket watcher expects the simple JSON protocol used by the SDK testkit;
  it is not a full SPIRE Workload API client.

## Roadmap

- Keep file and test-socket sources as stable SDK test and deployment helpers.
- Add a first-class SPIRE Workload API source only when the SDK owns that
  dependency boundary.
- Continue fail-closed validation for SVID paths and trust bundles.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, file source, watcher, and tests.
- Run with: `cargo test -p opc-identity`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
