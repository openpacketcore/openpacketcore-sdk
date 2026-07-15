# opc-tls

SPIFFE-aware Rustls configuration helpers for OpenPacketCore services.

## Purpose

`opc-tls` converts `opc-identity` SVID state into reloadable client and server
TLS configs. It enforces peer policy over SPIFFE trust domain, tenant, NF kind,
and instance metadata.

## API Shape

- `TlsConfigBuilder::new(state_rx)` builds client or server configs from an
  identity watch channel.
- `with_policy` installs a `PeerPolicy`.
- `allow_any_trusted_peer` is required before building with an unconstrained
  default policy.
- `with_compat_mode(true)` enables TLS 1.2 compatibility; otherwise TLS 1.3 is
  used.
- `ReloadingClientCertResolver` and `ReloadingServerCertResolver` serve the
  current SVID certificate/key.
- `SpiffeServerCertVerifier` and `SpiffeClientCertVerifier` validate peer SVIDs
  against trust bundles and policy.
- `build_authenticated_client_config` and
  `build_authenticated_server_config` return opaque, redaction-safe wrappers
  proving that the config was built with this crate's SPIFFE verifier and
  reloadable SVID resolver. Security-sensitive consumers such as
  `opc-session-net` require these wrappers instead of raw Rustls configs.
- `TlsMaterialController::new(source)` pins the first accepted local SPIFFE ID;
  `new_pinned(source, id)` enforces an explicit pin for generic file, socket, or
  custom identity-state channels. Clones share one bounded, process-local
  monotonic epoch and last-good state. These compatibility controllers do not
  mutate process-global security rotation metrics.
- `new_from_projected_source(source)` and
  `new_pinned_from_projected_source(source, id)` are the production pairing
  boundary for an authoritative `ProjectedSvidSource`. They atomically claim
  that source's exact paired feed and non-cloneable controller metrics
  authority; a second controller claim fails before it can split or duplicate
  exported telemetry. Runtime capture happens before the one-time claim, and
  the captured handle owns reconciliation spawning; construction outside an
  entered runtime returns `RuntimeUnavailable` without consuming the claim.
- Projected-source failures are counted synchronously by the source even when a
  rejected candidate leaves the identity-state watch unchanged. The paired
  controller publishes accepted epochs, controller rejections, and current
  gauges. One per-publication ticket deduplicates controller effective-chain
  expiry and source leaf expiry, including expiry observed before pairing or
  after controller rejection. There is no public outcome cursor or separately
  droppable monitor. Supersession alone does not synthesize expiry; production
  normally drops the replaced ticket. A retained late observation of an
  unaccepted or superseded ticket is counted once without changing the active
  snapshot's gauges. Source or controller may clear the expiry gauge only when
  first observing expiry of the active accepted ticket.
- Acceptance follows one lock order: controller state, publication lifecycle,
  then active registry. After validation, the controller installs the snapshot
  and pin, commits the non-cloneable permit with no intervening fallible work,
  and only then publishes `Ready`. No callback executes under registry locks.
  Deliberate same-thread metrics reentry while holding this doc-hidden permit is
  forbidden trusted-process misuse.
- `TlsConfigBuilder::from_material_controller(controller)` lets client and
  server wrappers share that exact authority. `begin_handshake()` freezes one
  leaf/key/chain/trust snapshot; its config must be used for the complete TLS
  exchange, and `admit()` must run only after application negotiation.
- `run_handshake()` enforces 128 concurrent operations and retries at most two
  epoch changes after the initial attempt. Its successful
  `TlsAdmittedConnection` records the exact epoch, local leaf expiry, and the
  earliest expiry across every certificate in the configured SVID chain.
- `peer_spiffe_id_from_client_connection` and
  `peer_spiffe_id_from_server_connection` extract the one canonical SPIFFE URI
  from an established TLS connection. Missing, malformed, or ambiguous URI
  SANs fail closed.
- `peer_tls_identity_from_client_connection` and
  `peer_tls_identity_from_server_connection` additionally retain the peer leaf
  expiry and earliest expiry across every certificate presented by the peer.
- `ServerConfig` and `ClientConfig` are re-exported Rustls config aliases.

```rust,no_run
use opc_tls::{PeerPolicy, TlsConfigBuilder};

fn describe(policy: PeerPolicy) -> bool {
    policy.is_unconstrained()
}

async fn build_configs(
    rx: tokio::sync::watch::Receiver<opc_identity::IdentityState>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let server = TlsConfigBuilder::new(rx)
        .with_policy(PeerPolicy::default())
        .allow_any_trusted_peer()
        .build_server_config()?;
    Ok(server)
}
```

For coherent handshake admission from a generic file, socket, or custom source:

```rust,no_run
use opc_tls::{PeerPolicy, TlsConfigBuilder, TlsMaterialController};

async fn coherent_handshake(
    source: tokio::sync::watch::Receiver<Option<opc_identity::IdentityState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let controller = TlsMaterialController::new(source);
    let client = TlsConfigBuilder::from_material_controller(controller)
        .with_policy(PeerPolicy::default())
        .allow_any_trusted_peer()
        .build_authenticated_client_config()?;

    let outcome = client
        .run_handshake(|attempt| async move {
            let fixed_config = attempt.rustls_config();
            // Perform TLS and application negotiation with fixed_config.
            drop(fixed_config);
            Ok::<_, std::io::Error>(())
        })
        .await?;
    let (_value, admission) = outcome.into_parts();
    let _epoch = admission.epoch();
    Ok(())
}
```

For a Kubernetes projected Secret, use the paired constructor instead of
subscribing its generic identity-state channel directly:

```rust,ignore
let source = opc_identity::ProjectedSvidSource::new_authoritative(
    projected_root,
    "tls.crt",
    "tls.key",
    vec!["ca.crt"],
    Some(projected_poll_interval),
)?;
let controller = opc_tls::TlsMaterialController::new_pinned_from_projected_source(
    &source,
    expected_local_spiffe_id,
)?;
```

## Relationships

- Consumes `opc-identity::IdentityState` from `ProjectedSvidSource`,
  `SvidWatcher`, or `FileSvidSource`.
- Uses `opc-types` identity values embedded in SPIFFE IDs.
- Intended for KMS, session transport, consensus transport, and other mTLS
  service boundaries.
- Both `opc-identity` and `opc-tls` use the shared `opc-redaction` registry for
  the fixed
  `opc_security_svid_expires_seconds`, `opc_security_bundle_version`, and
  `opc_security_rotation_total{kind,outcome}` families: the identity source
  records source outcomes and owns publication tickets, while the paired TLS
  controller records controller outcomes and accepted epochs. Parsing and
  validation do not require an installed exporter. Normal consumers use the
  read-only reader, while one source/controller capability owns writes and
  `SdkMetrics::reset_all` cannot erase them. The
  doc-hidden composition APIs must be public across SDK crates; trusted
  same-process code can claim that sole writer first. Cryptographic/material
  validation and this controller own identity and peer authorization. The
  non-cloneable lifecycle permit is an internal coherent-publication gate;
  exported metric values are never read as an authorization, TLS-admission, or
  readiness input.

## Status Notes

- Safe Rust only.
- Builds fail closed when the peer policy is unconstrained and
  `allow_any_trusted_peer` was not called.
- Default client ALPN includes `h2` and `http/1.1`.
- Protocol adapters may clone an authenticated wrapper and replace ALPN with
  their exact application protocol; the wrapper does not authorize application
  membership by itself.
- Certificate/key rotation is driven by identity state updates; this crate does
  not fetch SVIDs itself.
- Controller status contains only an epoch, closed availability/reason enums,
  local leaf expiry, and effective configured-chain expiry. It never contains
  paths, PEM, key bytes, SPIFFE IDs, parser text, or user operation errors.
  Status/snapshot access reconciles the latest watch value and enforces the
  earliest configured-chain expiry. This controller status is authoritative
  for TLS admission; an upstream source `Ready` status alone is not.
- The SVID expiry gauge is the controller's effective configured/presented-chain
  Unix expiry (zero when unavailable), not necessarily the leaf expiry. The
  bundle-version gauge is the last accepted opaque process-local controller
  epoch, retained when that active ticket expires for correlation. An observed
  rejected, unaccepted, or superseded ticket expiry can increment `expired` but
  changes neither gauge; supersession alone does not synthesize that outcome.
  Rotation labels are a fixed 3-by-4 set; they cannot include identities,
  paths, material, endpoints, or caller text. `retained_last_good`, `rejected`,
  `expired`, and peer authentication/trust failure remain distinct outcomes.
  Private-key mismatch, local-identity change, temporal validity, and expiry
  controller reasons use `kind="svid"`. Chain/workload-identity validation,
  acquisition, limit, closure, and epoch failures do not prove one changed
  component and conservatively use `kind="tls_material"`.
- Readiness code must call `material_status()` or
  `TlsMaterialController::status()` for each evaluation. A previously borrowed
  status/watch value is not a wall-clock expiry timer; source activity or an
  explicit controller access drives reconciliation.
- A candidate is revalidated under limits of 16 chain certificates, 16 trust
  bundles, 128 trust anchors, 64 KiB private-key bytes, and 4 MiB total material.
  Every configured chain certificate is temporally checked before chain
  rebuild. Same-SPIFFE leaf/key and overlapping-trust updates publish a new
  epoch; changed identity, wrong key/chain/trust, malformed/oversized, future,
  or expired candidates preserve the prior snapshot only until the earliest
  configured-chain expiry. A redundantly configured root therefore bounds the
  snapshot; a root present only in a trust bundle does not.

## Compatibility

`TlsConfigBuilder::new`, raw config builders, `rustls_config()`, peer-identity
helpers, raw projected identity subscriptions, and identity-source events
remain source compatible. Generic controllers built from those raw channels
do not write process-global security metrics. The legacy
`rustls_config()` view remains reloadable for existing consumers; it does not
provide the new post-application epoch-current admission proof. New production
transport integrations should use `run_handshake()` by default. Direct
`begin_handshake()` is a low-level adapter primitive: an adapter using it must
independently enforce equivalent concurrency, deadline, epoch-retry, and
post-application `admit()` bounds.

`TlsMaterialStatus`, `TlsAdmittedConnection`, and `PeerTlsIdentity` add
effective-chain-expiry accessors; the first two also serialize that additional
redaction-safe timestamp. Strict external JSON consumers must accept the added
field when adopting this version.

This contract makes each new handshake coherent and records its exact material
epoch and certificate deadlines. It does not itself drain already authenticated
connections or enforce maximum authentication age; `opc-session-net` consumes
the evidence through the #163 lifecycle. Fleet qualification remains #164
under umbrella #158.

## Roadmap

- Complete deployed-CNF projected-material rotation, expiry, rollback, real
  fault/restart, resource/soak, remote-HKMS, and signed independent evidence
  for three- and five-member fleets under #164/#143. Single-host 3/5-process
  rotation and bounded synthetic fault/expiry regression slices are present.
- Add policy dimensions only when encoded in workload identity metadata.
- Keep compatibility mode explicit so TLS 1.2 is never enabled accidentally.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, `src/material.rs`, and
  TLS/identity tests, including `tests/material_epochs.rs`.
- Run with: `cargo test -p opc-tls`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
