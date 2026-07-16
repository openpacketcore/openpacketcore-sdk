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
  `XfrmRequestId`, `UdpEncap`, `XfrmMark`, `DscpCodepoint`, `LifetimeConfig`,
  and `XfrmProbe`.
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
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    };

    backend.install_sa(InstallSaRequest { parameters: sa }).await?;
    Ok(())
}
```

## Per-SA output marks

`SaParameters::output_mark` emits the generic Linux
`XFRMA_SET_MARK`/`XFRMA_SET_MARK_MASK` pair. Linux applies that masked value to
`skb->mark` after the SA transforms a packet, including after an inbound SA
decrypts it. This lets a later routing or dataplane boundary distinguish which
SA accepted a packet even when several SAs carry the same inner address. The
Linux and mock backends both return the exact pair as `SaState::output_mark`.
The value and mask must not both be zero: Linux omits that pair from kernel
readback, so use `output_mark: None` when no post-transform mark mutation is
required.

The ignored privileged test installs matching peer and local XFRM paths, sends
real inbound ESP, receives the decrypted UDP payload, and observes the masked
output mark with an `iptables` INPUT counter. This distinguishes datapath
behavior from netlink state readback alone.

The output mark is independent of `SaParameters::mark`: `mark` emits
`XFRMA_MARK` and participates in selecting the SA, while `output_mark` changes
the packet only after that SA runs. For example, a caller can annotate the
inbound half of an IKEv2 Child SA without changing SA lookup:

```rust,no_run
use opc_ipsec_xfrm::{InstallSaRequest, XfrmMark};

fn mark_inbound_bearer(mut request: InstallSaRequest) -> InstallSaRequest {
    request.parameters.output_mark = Some(XfrmMark {
        value: 0x0001_0000,
        mask: 0x00ff_0000,
    });
    request
}
```

Source migration: existing `SaParameters` struct literals must add
`output_mark: None` to preserve their previous wire behavior. Exhaustive
`SaState` destructuring must account for the new `output_mark` field (or use
`..`). No Cargo feature is required.

This generic path remains independent when the Linux backend also has the
fixed-DSCP companion configured: an SA with `egress_dscp: None` may use the
complete mark and mask, including `(value = 0, mask = u32::MAX)` to clear a
stale bearer selector. If `egress_dscp` is set on the same SA, the generic
output-mark value and mask must remain disjoint from the configured seven-bit
token window. The backend combines the disjoint generic value and DSCP token
into the kernel's single output-mark pair and rejects an overlap.

`SaState::output_mark` is always the exact kernel pair. A query cannot recover
whether an arbitrary overlapping generic mark was originally intended as a
DSCP token, so `SaState::egress_dscp` is decoded only when the output-mark pair
exclusively carries one complete token; broader, partial, or presence-free
overlaps remain generic. Callers own
namespace-wide `skb->mark` allocation and must coordinate every producer and
consumer of the selected bits. In particular, packets crossing the DSCP tc
companion must not carry an accidental token in its reserved window. A
successful Linux install or rekey includes an exact GETSA readback of the
output-mark pair; an ACK without that proof returns `StateIndeterminate` and is
never followed by an unsafe compensating delete.

## Fixed Outer DSCP

Linux XFRM exposes a masked output mark but no fixed outer-DSCP SA attribute.
The production backend therefore combines two kernel mechanisms:

1. `XFRMA_SET_MARK`/`XFRMA_SET_MARK_MASK` place a presence bit plus the
   validated six-bit `DscpCodepoint` into a deployment-reserved seven-bit
   `skb->mark` window after XFRM transformation.
2. A committed tc egress eBPF companion on every explicitly configured SWu
   egress interface consumes that token, stamps the outer IPv4 or IPv6 DSCP,
   preserves ECN and unrelated mark bits, updates the IPv4 checksum, and
   clears only the reserved token bits.

Configure the companion before installing any SA with `egress_dscp: Some(_)`:

```rust,no_run
use opc_ipsec_xfrm::{LinuxXfrmBackend, LinuxXfrmDscpMarkingConfig};

let mut marking = LinuxXfrmDscpMarkingConfig::new(
    [String::from("swu0")],
    25, // reserves skb mark bits 25..=31
)?;
marking.bpffs_pin_root = "/sys/fs/bpf/my-cnf/xfrm-dscp".into();
let backend = LinuxXfrmBackend::with_dscp_marking(marking)?;
# Ok::<(), opc_ipsec_xfrm::XfrmError>(())
```

The pin root must be a normalized child of `/sys/fs/bpf`. Interface names,
the tc priority/handle, and the exact seven-bit mask are validated. The CNF
must reserve the chosen mark window against every output-mark producer and
packet-mark consumer in its network namespace. An SA lookup mark may use the
same numeric bits because `XFRMA_MARK` is a separate kernel attribute; a
generic output mark on the same SA as fixed DSCP may compose only when its
value and mask are disjoint from the DSCP window. SAs without `egress_dscp`
remain independent of the backend-level companion configuration, while the
caller still prevents their packet values from accidentally encoding a token
on an interface where that companion runs. Fixed DSCP is accepted only for
tunnel-mode ESP SAs.

Construction eagerly attaches or adopts the exact owned tc slot. Every marked
install/rekey revalidates the live map and filter before sending netlink. The
netlink filter is deliberately kernel-owned rather than loader-owned, so an
old process dropping its Aya handles cannot remove a slot already adopted by
its replacement. Adoption requires the live tc program ID, pinned program ID,
pinned config-map ID/profile, and the embedded SDK artifact's kernel program
tag/type/name to match exactly. A stale pre-upgrade or foreign classifier fails
closed without detaching or replacing the live filter.

Classifier upgrades are intentionally drain-and-replace, not in-place: stop
all SDK writers for the namespace, drain/remove every marked SA and traffic
path, remove only the configured SDK tc priority/handle and its per-interface
pin directory, then start the new binary and require its probe/readback gates
again. Network-namespace teardown performs that cleanup naturally. Never
delete the pin or live filter while marked SAs can still emit traffic; this
implementation does not claim an atomic program-upgrade mechanism.

The probe reports `egress_dscp_marking = Unknown` until exact marked GETSA
readback proves the stable redaction-safe SA fields and both `XFRMA_SET_MARK`
attributes; a NEWSA/UPDSA ACK alone is never attribute proof because an older
kernel may ignore unknown attributes. The ACK linearizes kernel acceptance of
that request, while the later GETSA observes current state. GETSA deliberately
excludes key material, so it cannot prove cryptographic ownership or exclude a
later same-identity UPDSA from another writer. The CNF must serialize
namespace-wide XFRM SA and policy identity mutations and rollback: Linux
DELSA/DELPOLICY has no owner- or generation-conditional delete. The probe
reports `Available` only while the exact companion remains live. Mock,
unsupported, and mainline Linux GTP-style paths reject `Some` instead of
silently ignoring it. `egress_dscp: None` does not require this configuration.
When `output_mark` is also `None`, the backend emits the exact pre-feature XFRM
netlink payload.

An SA or policy's optional input/lookup `XfrmMark` is a separate identity
component from the companion's reserved output-mark window. Use the same mark
on `SaParameters`, `PolicyParameters`, `QuerySaRequest`, `RemoveSaRequest`, and
`RemovePolicyRequest`; the Linux and mock backends keep marked and unmarked SA
identities distinct and Linux applies the mark to exact policy deletion. The
request constructors target unmarked kernel objects, while `with_mark` selects
a marked object. Installs carrying any output mark are not reported successful
until an exact GETSA readback succeeds. If readback fails or any stable returned
field differs after the NEWSA ACK, the backend returns `StateIndeterminate` and
never sends a compensating DELSA: an external writer may already have updated
that identity, so deletion would be unsafe. An output-marked UPDSA readback
failure is likewise `StateIndeterminate` because safe query state deliberately
excludes the old key material needed for rollback.

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
- Fixed outer DSCP additionally requires bpffs, kernel BTF, `CAP_BPF` (or
  `CAP_SYS_ADMIN`), one configured tc egress attachment per SWu interface, and
  a globally reserved seven-bit skb-mark window.
- `query_sa` returns replay/lifetime/statistics and the exact generic/combined
  output mark, but never key material.
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
./scripts/build-ipsec-xfrm-ebpf.sh
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_dscp_privileged -- --ignored --nocapture'
```
