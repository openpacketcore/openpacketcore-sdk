# opc-sctp

## Purpose

`opc-sctp` is the safe SCTP transport foundation for OpenPacketCore CNFs that
terminate N2/NGAP, Diameter-over-SCTP, or other SCTP interfaces. It wraps
Linux SCTP sockets from `opc-libsctp-sys` with validation, Tokio readiness,
message-boundary preserving APIs, metadata, health, metrics, and redaction-safe
errors.

The Diameter helper is explicitly **unprotected** SCTP framing. PPID 46 or 47
is payload metadata, not evidence of encryption or peer authentication. A site
using this helper must separately protect and attest the path, for example with
IPsec. Real TLS/TCP and DTLS/SCTP Diameter transports are outside the current
crate boundary.

## API Shape

- PPID helpers: `PayloadProtocolIdentifier`, `NGAP_PPID`,
  `DIAMETER_SCTP_PPID`, and `DIAMETER_DEFAULT_STREAM_ID`. PPID 47 is not
  exposed as a Diameter helper until the SDK has a real protected association
  that can emit it safely.
- Config: `SctpEndpointConfig`, `SctpConnectConfig`, `SctpMode`, `InitConfig`,
  `RtoConfig`, `HeartbeatConfig`, `DeliveryOrder`, `SctpCapabilities`, and
  `MAX_STATIC_MULTIHOMING_ADDRESSES`.
- Messaging: `OutboundMessage`, `InboundMessage`, `SctpEvent`,
  `SctpPeerAddrState`, `SctpEndpoint`, and `SctpAssociation`.
- Observability: `SctpHealth`, `SctpPathHealth`, `SctpPathStatus`,
  `SctpMetrics`, and `SctpMetricsSnapshot`.
- Diameter helpers: `DiameterSctpPeer`, `DiameterSctpAssociation`,
  `DiameterSctpInbound`, `DiameterSctpProtection`, `DiameterInboundPpidPolicy`,
  `DiameterSctpConnectProjection`, `DiameterSctpConnectOutcome`, and
  `DiameterSctpError`. Primary constructors include `new_unprotected` and
  `connect_unprotected_with_config`; the old `DiameterSctpSecurity` selector is
  deprecated and rejects `Dtls` before socket setup or payload framing.
- Errors: `SctpError` and Diameter-specific wrappers expose stable,
  redaction-safe classifications.

## Usage

```rust,no_run
use bytes::Bytes;
use opc_sctp::{
    OutboundMessage, SctpAssociation, SctpConnectConfig, SctpError, NGAP_PPID,
};

async fn send_ngap(remote: std::net::SocketAddr, payload: Bytes) -> Result<(), SctpError> {
    let assoc = SctpAssociation::connect(SctpConnectConfig::new(remote)).await?;
    assoc
        .send(OutboundMessage::ordered(payload, 0, NGAP_PPID))
        .await?;
    Ok(())
}
```

### Multihoming path events and health

`SctpAssociation::recv` returns notifications in wire order through
`InboundMessage::event`. Linux `SCTP_PEER_ADDR_CHANGE` notifications decode to
`SctpEvent::PeerAddrChange`, including the typed transition, kernel error, and
association ID. The peer address is deliberately omitted from `Debug`; it
remains available as a typed field for consumers that apply their own telemetry
redaction policy.

Each connected association exposes a bounded
`SctpAssociation::peer_path_health()` snapshot (also available on
`DiameterSctpAssociation`).
The distinct configured (or bounded kernel-reported accepted) path set
initializes with unknown reachability, while the current
`getpeername`/accepted primary is marked reachable. Calling `recv` processes
available, unreachable, removed, made-primary, confirmed, and
potentially-failed events before returning them.
Made-primary changes only the primary designation and preserves the path's
current reachability classification. The designation is reconciled with the
kernel's current primary under the association control gate, so a notification
dequeued before a concurrent explicit selection cannot roll the snapshot back.
If that health-only current-primary query fails, `recv` still returns the event
and preserves the last known designation rather than applying a possibly stale
address.
Health therefore reflects notifications consumed by the application; it is not
a separate background socket reader. Concurrent active association receives
are serialized so path events are applied in kernel receive order. Receive
futures remain non-cancellation-safe after they begin consuming a multi-chunk
record. IPv6 flow information is ignored for path identity because
system-produced socket addresses may represent it in raw host form; IP address,
port, and scope ID identify the path.

Diameter consumers that need both transport events and payloads use the
event-capable boundary:

```rust,no_run
use opc_sctp::{
    DiameterSctpAssociation, DiameterSctpError, DiameterSctpInbound, SctpEvent,
};

async fn receive_one(
    association: &DiameterSctpAssociation,
) -> Result<(), DiameterSctpError> {
    match association.recv().await? {
        DiameterSctpInbound::Payload(payload) => {
            let _validated_diameter_bytes = payload;
        }
        DiameterSctpInbound::Notification(Some(SctpEvent::PeerAddrChange {
            state, ..
        })) => {
            let _stable_state_name = state.as_str();
        }
        DiameterSctpInbound::Notification(_) => {}
    }
    Ok(())
}
```

`DiameterSctpAssociation::recv_diameter_payload` remains the payload-only
convenience API: it consumes and applies transport notifications, skips them,
and returns the next validated Diameter payload with its existing truncation
and PPID behavior unchanged.

### Path tuning and primary selection

The default `RtoConfig` and `HeartbeatConfig` leave Linux SCTP defaults
unchanged. A deployment with a measured failover target can opt in through the
existing endpoint or connect configuration:

```rust,no_run
use opc_sctp::{
    HeartbeatConfig, RtoConfig, SctpAssociation, SctpConnectConfig, SctpError,
};

async fn connect_tuned(
    primary: std::net::SocketAddr,
    secondary: std::net::SocketAddr,
) -> Result<SctpAssociation, SctpError> {
    let mut config = SctpConnectConfig::new(primary);
    config.remote_addrs.push(secondary);
    config.rto = RtoConfig {
        initial_ms: Some(500),
        min_ms: Some(100),
        max_ms: Some(2_000),
    };
    config.heartbeat = HeartbeatConfig {
        interval_ms: Some(250),
        path_max_retrans: Some(2),
    };

    let association = SctpAssociation::connect(config).await?;
    association.set_primary_peer_path(secondary)?;
    Ok(association)
}
```

Explicit RTO values are nonzero milliseconds and must satisfy every supplied
`min <= initial <= max` relationship. A heartbeat interval of zero requests
RFC 6458 zero-delay mode; the path RTO and jitter still apply. An explicit
path retransmission threshold must be nonzero. Endpoint values are installed
before listen and therefore apply to future accepted one-to-one associations;
connect values are installed before association setup. A kernel that lacks an
option returns a typed `CapabilityUnavailable` error instead of silently using
defaults.

`SctpAssociation::set_primary_peer_path` and the equivalent Diameter method
accept only a current kernel-reported peer path. A successful selection updates
the health snapshot immediately, but it does not disable SCTP failover or
change reachability state. Selection calls and received path notifications are
serialized per association so the kernel selection and health snapshot cannot
be reordered by concurrent callers. All raw `SCTP_RTOINFO`,
`SCTP_PEER_ADDR_PARAMS`, and `SCTP_PRIMARY_ADDR` layouts remain confined to
`opc-libsctp-sys`.

### Legacy Diameter PPID 0 interoperability

Strict inbound PPID validation is the production default. A site that must
interoperate with a known non-conforming or legacy clear-text Diameter peer can
opt in for that peer only:

```rust,no_run
use opc_sctp::{
    DiameterInboundPpidPolicy, DiameterSctpAssociation, DiameterSctpError,
    DiameterSctpPeer,
};

async fn connect_legacy_diameter_peer(
    remote: std::net::SocketAddr,
) -> Result<DiameterSctpAssociation, DiameterSctpError> {
    DiameterSctpPeer::new_unprotected(remote)
        .with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero)
        .connect_association()
        .await
}
```

This escape hatch accepts inbound PPID 0 in addition to PPID 46 only for the
explicitly unprotected Diameter path. Outbound messages remain PPID 46 and
never mirror the peer's zero value. It cannot enable PPID 47 or turn ordinary
SCTP into a protected transport. Static multihoming callers opt in with
`DiameterSctpAssociation::connect_unprotected_with_config_and_inbound_ppid_policy`;
`connect_unprotected_with_config` remains strict. No Cargo feature is required.
Each live association counts accepted legacy messages in
`SctpMetricsSnapshot::accepted_legacy_diameter_zero_ppid_messages` and emits at
most one redaction-safe warning without payload or peer-address data.

Diameter framing can be applied directly to an explicit, validated connect
configuration. This keeps the SDK's PPID and notification handling while
allowing the caller to supply the complete static-multihoming address sets:

```rust,no_run
use bytes::Bytes;
use opc_sctp::{
    DiameterSctpAssociation, DiameterSctpError, SctpConnectConfig,
};

async fn send_diameter(
    primary_remote: std::net::SocketAddr,
    additional_remotes: Vec<std::net::SocketAddr>,
    payload: Bytes,
) -> Result<(), DiameterSctpError> {
    let mut config = SctpConnectConfig::new(primary_remote);
    config.remote_addrs.extend(additional_remotes);
    let association =
        DiameterSctpAssociation::connect_unprotected_with_config(config).await?;
    association.send_diameter_payload(payload).await?;
    Ok(())
}
```

### PPID-only DTLS migration

Earlier releases exposed `DiameterSctpSecurity::Dtls`, but that selector only
changed SCTP metadata to PPID 47; it never ran DTLS. The selector and its
overloaded connect methods are deprecated. A legacy `Dtls` request now returns
`DiameterSctpError::ProtectedTransportUnavailable` before config validation,
socket setup, or payload framing. It never falls back to PPID 46.

Migrate ordinary SCTP callers explicitly:

```rust,no_run
use opc_sctp::{DiameterSctpAssociation, DiameterSctpError, SctpConnectConfig};

async fn connect_unprotected(
    config: SctpConnectConfig,
) -> Result<DiameterSctpAssociation, DiameterSctpError> {
    DiameterSctpAssociation::connect_unprotected_with_config(config).await
}
```

`DiameterSctpPeer::new` is likewise deprecated in favor of
`DiameterSctpPeer::new_unprotected`. Applications that require DTLS must not
use `opc-sctp`'s ordinary association as a substitute; they must use a real
mutually authenticated protected transport. No Cargo feature enables DTLS in
this crate.

## Relationships

- `opc-libsctp-sys` owns the raw Linux SCTP socket boundary.
- NGAP, Diameter, NAS, and other protocol codecs live in their own crates; this
  crate transports bytes and SCTP metadata only.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Linux SCTP sockets are supported; non-Linux hosts fail closed with
  unsupported-platform errors.
- One-to-one and one-to-many modes are represented.
- Static multihoming binds every configured local address and connects with the
  complete remote address set on Linux. Address sets are bounded and must use
  one family and port; exactly one address preserves the original syscall path.
- `DiameterSctpAssociation::connect_unprotected_with_config` applies explicit
  unprotected PPID-46 Diameter framing to the complete connect configuration.
  Unsupported kernel or namespace multihoming remains a typed capability
  error; no address is silently discarded.
- Every `DiameterSctpPeer`, including one built with a public struct literal,
  carries `DiameterSctpProtection::Unprotected`; there is no protected variant
  or implicit external-IPsec attestation.
- Diameter inbound PPID validation is strict by default. Legacy clear-text
  PPID 0 acceptance is an explicit per-peer policy; it never affects outbound
  PPIDs and never implies protected Diameter.
- The deprecated PPID-only `Dtls` selector fails closed with
  `diameter_sctp_protected_transport_unavailable`. No readiness, health, or
  metric emitted by an ordinary SCTP association claims DTLS or protection.
- `capabilities()` advertises build support, kernel policy failures are a typed
  `CapabilityUnavailable` error, and `local_addresses()`/`peer_addresses()`
  expose the kernel-active set. Consumers may therefore choose an explicit
  single-address fallback without silently ignoring configured addresses.
- Association/address/shutdown notification IDs use the Linux UAPI
  `SCTP_SN_TYPE_BASE` values. Peer-address-change decoding supports IPv4 and
  IPv6 `sockaddr_storage` layouts, rejects truncated or unknown-family events,
  and retains unknown future state values as typed `Unknown` transitions.
- Per-path health is bounded to `MAX_STATIC_MULTIHOMING_ADDRESSES` and advances
  only while the consumer receives association messages or notifications.
- Custom RTO and heartbeat configs use exact asserted Linux UAPI layouts and
  preserve kernel defaults when omitted. Primary-path selection validates the
  current kernel peer set before applying `SCTP_PRIMARY_ADDR`.
- Live loopback tests require kernel SCTP support and are ignored where the host
  cannot provide it. The path-failover qualification additionally uses
  passwordless `sudo` to install port-scoped SCTP firewall rules and always
  removes them through a drop guard.

## Roadmap

- Add further SCTP options only with validated UAPI support.
- Keep protocol-specific validation in protocol crates or thin helper layers,
  not in the generic SCTP transport.
- Expand live integration coverage where CI hosts provide SCTP kernel support.

## Verification

```sh
cargo test -p opc-sctp
cargo test -p opc-libsctp-sys linux::tests::loopback_path_tuning_and_primary_selection -- --ignored --exact
cargo test -p opc-sctp tests::loopback_static_multihoming_binds_and_connects_full_sets -- --ignored --exact
cargo test -p opc-sctp tests::loopback_diameter_recv_surfaces_transport_notification -- --ignored --exact
cargo test -p opc-sctp tests::static_multihoming_survives_primary_path_drop -- --ignored --exact
```
