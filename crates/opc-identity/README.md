# opc-identity

Workload identity loading and validation for SPIFFE SVIDs.

## Purpose

`opc-identity` parses SVID certificate material, validates the SPIFFE workload
identity shape used by OpenPacketCore, and publishes reloadable identity state
for TLS and service clients.

## API Shape

- `extract_spiffe_id_from_cert_der` extracts exactly one canonical SPIFFE URI
  SAN from a leaf certificate; missing, malformed, duplicate, or ambiguous URI
  SANs fail closed. `WorkloadIdentity::from_cert_der` uses the same primitive.
- `build_identity_state` validates the leaf chain against active trust bundles
  and checks that the private key matches the leaf.
- `SvidWatcher::new(socket_path, initial_bundles)` reads length-prefixed JSON
  SVID updates from a SPIRE-like Unix socket and emits reload events.
- `FileSvidSource::new(cert_path, key_path, bundle_paths, poll_interval)` polls
  independently managed PEM files and emits the same state/events interface.
- `ProjectedSvidSource::new(volume_root, cert_file, key_file, bundle_files,
  poll_interval)` is the production Kubernetes projected-volume adapter. It
  resolves one `..data` generation, reads every file from that immutable
  directory, rejects a generation switch during any read phase, and publishes
  an opaque monotonic generation plus typed status.
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
        Some(Duration::from_secs(5)),
    )
}
```

For a projected Secret with keys `tls.crt`, `tls.key`, and `ca.crt`:

```rust,no_run
use opc_identity::ProjectedSvidSource;
use std::time::Duration;

fn projected_source() -> ProjectedSvidSource {
    ProjectedSvidSource::new(
        "/var/run/secrets/openpacketcore/tls",
        "tls.crt",
        "tls.key",
        vec!["ca.crt"],
        Some(Duration::from_secs(5)),
    )
    .expect("static projected-volume configuration")
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
- `ProjectedSvidSource` accepts 1 MiB for the SVID chain, 64 KiB for the private
  key, and 1 MiB per trust-bundle file, with a 4 MiB total candidate limit. It
  accepts at most 16 bundle files, 16 SVID-chain certificates, and 128 trust
  anchors. A `..data` change is retried three times after the initial attempt;
  each attempt has a five-second deadline, and polling cannot be configured
  below 100 milliseconds.
- Projected-source status contains only a process-local publication generation,
  closed availability/reason enums, and no path, PEM, SPIFFE ID, key, or parser
  text. A failed candidate retains the exact previous state only until its leaf
  expires; expiry makes the source unavailable.
- The socket watcher expects the simple JSON protocol used by the SDK testkit;
  it is not a full SPIRE Workload API client.

## Compatibility

`FileSvidSource`, `SvidWatcher`, `IdentityReloadEvent`, and their subscription
APIs are unchanged. `ProjectedSvidSource` is additive and emits the same legacy
success/failure events; its failure strings are fixed reason codes. The opaque
projected generation restarts at zero with the process and must not be persisted
or compared across process restarts. Rollback to an earlier Kubernetes Secret
payload is a new successful publication and receives a larger generation.

The projected source makes identity material publication coherent. It does not
retire already authenticated TLS connections; coherent per-handshake TLS epochs
are tracked by #162 and bounded connection reauthentication by #163.

## Roadmap

- Keep independent-file and test-socket sources as stable SDK development
  helpers; use the projected source for Kubernetes Secret mounts.
- Add a first-class SPIRE Workload API source only when the SDK owns that
  dependency boundary.
- Continue fail-closed validation for SVID paths and trust bundles.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, independent-file and projected
  sources, watcher, and tests.
- Run with: `cargo test -p opc-identity`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
