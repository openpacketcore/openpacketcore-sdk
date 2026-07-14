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
  poll_interval)` preserves the compatibility source without process-global
  telemetry. `new_authoritative(...)` is the production Kubernetes
  projected-volume adapter and claims the sole process security-metrics
  authority. Both constructors resolve one `..data` generation, read every
  file from that immutable directory, reject a generation switch during any
  read phase, and publish an opaque monotonic generation plus typed status.
  `new_authoritative(...)` validates configuration and captures the active
  Tokio runtime before claiming process telemetry; its
  `ProjectedSvidAuthoritativeError` distinguishes configuration, unavailable
  runtime, and already-claimed authority without changing the exhaustive
  `ProjectedSvidConfigError` variants.
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
    ProjectedSvidSource::new_authoritative(
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
- `opc-tls::TlsMaterialController` revalidates and pins those states into
  immutable per-handshake material epochs; identity publication remains owned
  here and handshake/application admission remains owned by `opc-tls`.
- Uses `opc-types` for tenant, NF kind, instance, SPIFFE ID, and timestamps.
- Used by security testkits to exercise SVID rotation and trust-bundle changes.

## Status Notes

- The accepted SPIFFE path layout is
  `/tenant/<tenant>/ns/<namespace>/sa/<service-account>/nf/<nf-kind>/instance/<instance>`.
- Certificates are rejected when expired, not yet valid, missing a trust bundle,
  or carrying an invalid workload path.
- Watchers retain the last good identity after invalid updates and clear expired
  state during expiry monitoring.
- Authoritative projected-source failure outcomes are synchronously accumulated
  in a fixed, monotonic producer-side matrix under the publication lock.
  Counting does not depend on identity-watch delivery or controller
  construction, so coalescing, scheduler lag, recovery before pairing, and
  source closure cannot lose a failure. Every coherent publication carries one
  exact-once expiry ticket, so an expiry observed before controller pairing,
  while controller-active, or after controller rejection produces one
  `expired` outcome across source/controller races. There is no public outcome
  cursor or separately droppable monitor. Supersession alone does not synthesize
  expiry; production normally drops the replaced ticket. A retained late
  observation of a rejected or superseded ticket is still deduplicated and
  cannot clear the active controller publication's expiry or version gauges.
  Only expiry of the active accepted ticket zeroes the expiry gauge, retaining
  its last accepted controller epoch for correlation.
- `ProjectedSvidSource::claim_tls_controller()` is a one-time pairing boundary
  used by `opc-tls`: it carries the source's exact paired feed and non-cloneable
  controller metrics authority into one process-global telemetry authority. A
  second claim fails before another controller can split or duplicate exported
  telemetry; clones of the first controller remain supported. Compatibility
  identity subscriptions remain available, but controllers built from those
  raw channels never mutate process-global security metrics.
- The controller claim captures an entered Tokio runtime before consuming its
  one-time authority and carries that handle into `opc-tls`; construction
  outside a runtime returns `RuntimeUnavailable` without burning the claim.
- Rust has no cross-crate friend visibility, so the doc-hidden process metrics
  composition primitives remain public for trusted same-process SDK wiring.
  Such code can claim the sole writer first. Cryptographic/material validation
  and the TLS controller own identity and peer authorization. The lifecycle
  ticket and transactional permit gate coherent publication internally, while
  exported metric values are never read to authorize TLS, access, or readiness.
- `new_with_metrics(...)` returns a `ProjectedSvidWithMetricsError` containing
  the unchanged authority when configuration or runtime preflight fails. A
  caller that explicitly claimed process authority can therefore recover it
  and retry without resetting or duplicating the global claim.
- `ProjectedSvidSource` accepts 1 MiB for the SVID chain, 64 KiB for the private
  key, and 1 MiB per trust-bundle file, with a 4 MiB total candidate limit. It
  accepts at most 16 bundle files, 16 SVID-chain certificates, and 128 trust
  anchors. A `..data` change is retried three times after the initial attempt;
  each attempt has a five-second deadline, and polling cannot be configured
  below 100 milliseconds. Deadline exhaustion reports `read_attempt_timeout`;
  exhausting generation-change retries reports `generation_retry_limit`.
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

The projected source makes identity material publication coherent. `opc-tls`
turns accepted states into coherent per-handshake epochs under #162, and
`opc-session-net` consumes those epochs for #163's bounded connection
retirement and full-handshake reauthentication. Authoritative projected-source
rejection and source-observed expiry counters are recorded directly by this
crate. The one-time paired `opc-tls` controller publishes accepted epoch/expiry
gauges and controller-level outcomes in the same selected registry; whichever
side first observes expiry of the active ticket may clear its expiry gauge under
the shared exact-once lifecycle.
`SdkMetrics::reset_all` cannot erase this process security evidence. Exported
metric values are not authorization or readiness inputs and do not change the
legacy identity-state publication contract. Fleet rotation and deployed-network
qualification remain #164/#143.

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
