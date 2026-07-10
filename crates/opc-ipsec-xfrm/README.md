# opc-ipsec-xfrm

## Purpose

`opc-ipsec-xfrm` is the safe Rust control surface for Linux XFRM IPsec state in
OpenPacketCore. It models Security Associations, Security Policies, replay
state, algorithms, key material, Linux backends, mocks, unsupported backends,
and rollback-aware composite operations.

The crate does not implement IKE negotiation, ESP packet processing, namespace
management, product SA/SPD policy, or deployment defaults.

## API Shape

- `XfrmBackend`: async port for SPI allocation, SA install/query/rekey/remove,
  policy install/rekey/remove, and capability probing.
- `LinuxXfrmBackend`: safe adapter over `NETLINK_XFRM` through
  `opc-linux-xfrm-sys`.
- `MockXfrmBackend`: deterministic in-memory backend with operation capture and
  failure injection.
- `UnsupportedXfrmBackend`: trait-compatible unsupported backend.
- Model exports include `IpAddress`, `XfrmSelector`, `XfrmId`, `SaParameters`,
  `PolicyParameters`, `XfrmTemplate`, `InstallSaRequest`,
  `InstallPolicyRequest`, `QuerySaRequest`, `SaState`, `SaReplayState`,
  `XfrmRequestId`, `UdpEncap`, `XfrmMark`, `LifetimeConfig`, and `XfrmProbe`.
- Algorithm/key exports include `Algorithm`, `AuthAlgorithm`, `AeadAlgorithm`,
  `KeyMaterial`, and Linux XFRM algorithm-name constants.
- Composite helpers include `install_sa_policy_with_rollback`,
  `install_bidirectional_sa_policy_with_rollback`, `rekey_sa_policy`, and
  `remove_policy_sa`.
- With feature `ikev2`, the crate also exports Child SA KEYMAT and negotiation
  mappers from `opc-proto-ikev2` into explicit XFRM install requests.

## Usage

```rust,no_run
use opc_ipsec_xfrm::{
    AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    SaParameters, XfrmBackend, XfrmId, XfrmMode, XfrmSelector,
    MockXfrmBackend,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MockXfrmBackend::new();
    let selector = XfrmSelector::new(
        IpAddress::Ipv4([10, 0, 0, 1]),
        IpAddress::Ipv4([10, 0, 0, 2]),
        50,
    );
    let sa = SaParameters {
        selector,
        id: XfrmId {
            destination: IpAddress::Ipv4([10, 0, 0, 2]),
            spi: 0x1234_5678,
            protocol: 50,
        },
        source_address: IpAddress::Ipv4([10, 0, 0, 1]),
        request_id: None,
        auth: Some((AuthAlgorithm::hmac_sha256(96), KeyMaterial::new(vec![0xab; 32]))),
        crypt: None,
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: None,
        if_id: None,
    };

    backend.install_sa(InstallSaRequest { parameters: sa }).await?;
    Ok(())
}
```

## Relationships

- `opc-linux-xfrm-sys` owns raw XFRM netlink sockets and UAPI layouts.
- `opc-proto-ikev2` is optional and only used behind the `ikev2` feature.
- Route steering, GTP-U, and node-resource checks live in sibling crates and
  are intentionally not folded into this XFRM backend.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Safe Rust only (`#![forbid(unsafe_code)]`).
- `KeyMaterial` zeroizes on drop, redacts debug/display, and compares bytes
  with constant-time equality.
- Linux mutation requires kernel XFRM support and effective `CAP_NET_ADMIN`.
- `query_sa` returns replay/lifetime/statistics state but never key material.
- The `ikev2` feature maps validated Child SA intent to XFRM requests; it does
  not run IKE, allocate SPIs, or choose product policy.
- The IKEv2 mapper keeps SPI-pinned policies as its compatibility default and
  also supports a shared non-zero request ID with wildcard policy-template SPI
  for simultaneous old/new Child-SA rekey overlap.

## Roadmap

- Keep additional XFRM algorithm support explicit and validated before encoding
  it to the kernel.
- Extend restore/query coverage where HA replay continuity requires more kernel
  state.
- Keep IKEv2 mapping exact: reject unrepresentable selector ranges or key shapes
  rather than approximating policy.

## Verification

```sh
cargo test -p opc-ipsec-xfrm
cargo test -p opc-ipsec-xfrm --features ikev2
```
