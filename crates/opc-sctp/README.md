# opc-sctp

## Purpose

`opc-sctp` is the safe SCTP transport foundation for OpenPacketCore CNFs that
terminate N2/NGAP, Diameter-over-SCTP, or other SCTP interfaces. It wraps
Linux SCTP sockets from `opc-libsctp-sys` with validation, Tokio readiness,
message-boundary preserving APIs, metadata, health, metrics, and redaction-safe
errors.

## API Shape

- PPID helpers: `PayloadProtocolIdentifier`, `NGAP_PPID`,
  `DIAMETER_SCTP_PPID`, `DIAMETER_DTLS_SCTP_PPID`, and
  `DIAMETER_DEFAULT_STREAM_ID`.
- Config: `SctpEndpointConfig`, `SctpConnectConfig`, `SctpMode`, `InitConfig`,
  `RtoConfig`, `HeartbeatConfig`, `DeliveryOrder`, `SctpCapabilities`, and
  `MAX_STATIC_MULTIHOMING_ADDRESSES`.
- Messaging: `OutboundMessage`, `InboundMessage`, `SctpEvent`,
  `SctpPeerAddrState`, `SctpEndpoint`, and `SctpAssociation`.
- Observability: `SctpHealth`, `SctpPathHealth`, `SctpPathStatus`,
  `SctpMetrics`, and `SctpMetricsSnapshot`.
- Diameter helpers: `DiameterSctpPeer`, `DiameterSctpAssociation`,
  `DiameterSctpInbound`, `DiameterSctpSecurity`, `DiameterInboundPpidPolicy`,
  `DiameterSctpConnectProjection`, `DiameterSctpConnectOutcome`, and
  `DiameterSctpError`.
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
`getpeername`/accepted primary is marked reachable. Calling `recv` applies
available, unreachable, removed, made-primary, confirmed, and
potentially-failed events before returning them.
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
    DiameterSctpPeer::new(remote)
        .with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero)
        .connect_association()
        .await
}
```

This escape hatch accepts inbound PPID 0 in addition to PPID 46 only for
clear-text Diameter. Outbound clear-text messages remain PPID 46 and never
mirror the peer's zero value. DTLS/protected Diameter remains strict. Static
multihoming callers opt in with
`DiameterSctpAssociation::connect_with_config_and_inbound_ppid_policy`; the
existing `connect_with_config` remains strict. No Cargo feature is required.
Each live association counts accepted legacy messages in
`SctpMetricsSnapshot::accepted_legacy_diameter_zero_ppid_messages` and emits at
most one redaction-safe warning without payload or peer-address data.

Diameter framing can be applied directly to an explicit, validated connect
configuration. This keeps the SDK's PPID and notification handling while
allowing the caller to supply the complete static-multihoming address sets:

```rust,no_run
use bytes::Bytes;
use opc_sctp::{
    DiameterSctpAssociation, DiameterSctpError, DiameterSctpSecurity,
    SctpConnectConfig,
};

async fn send_diameter(
    primary_remote: std::net::SocketAddr,
    additional_remotes: Vec<std::net::SocketAddr>,
    payload: Bytes,
) -> Result<(), DiameterSctpError> {
    let mut config = SctpConnectConfig::new(primary_remote);
    config.remote_addrs.extend(additional_remotes);
    let association = DiameterSctpAssociation::connect_with_config(
        config,
        DiameterSctpSecurity::ClearText,
    )
    .await?;
    association.send_diameter_payload(payload).await?;
    Ok(())
}
```

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
- `DiameterSctpAssociation::connect_with_config` applies the existing Diameter
  framing to that complete connect configuration. Unsupported kernel or
  namespace multihoming remains a typed capability error; no address is
  silently discarded.
- Diameter inbound PPID validation is strict by default. Legacy clear-text
  PPID 0 acceptance is an explicit per-peer policy; it never affects outbound
  PPIDs or protected Diameter.
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
- Custom RTO and heartbeat configs are modeled, but non-default values fail
  closed until the corresponding Linux option layouts are safely bound.
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
cargo test -p opc-sctp tests::loopback_static_multihoming_binds_and_connects_full_sets -- --ignored --exact
cargo test -p opc-sctp tests::loopback_diameter_recv_surfaces_transport_notification -- --ignored --exact
cargo test -p opc-sctp tests::static_multihoming_survives_primary_path_drop -- --ignored --exact
```
