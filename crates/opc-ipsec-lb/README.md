# opc-ipsec-lb

Pure SWu IKE/IPsec load-balancing primitives for OpenPacketCore CNFs.

This crate is the kernel-independent foundation for an ePDG/N3IWF/TWIF
steer layer:

- tagged SPI layout and allocation policy;
- clone-shared tagged-SPI reservations for excluding HA-restored live SAs from
  fresh and rekey allocation, with explicit release on SA retirement;
- rendezvous selection for shard and `IKE_SA_INIT` bootstrap routing;
- destination-scoped canonical ownership keys and generation-bound rendezvous
  owner selection for routed, multi-ingress deployments;
- UDP/500 and UDP/4500 SWu classifier with RFC 3948 non-ESP marker handling;
- stateless IKE cookie helper for edge DoS posture;
- failover safety guards for IV-counter and replay-window restoration;
- audited same-SPI re-pin coordination with monotonic ownership fencing;
- BGP route-export VIP advertisement through the safe route-steering backend;
- protocol-neutral VIP ownership reconciliation gated by caller-supplied
  leadership, quorum health, listener health, and a monotonic fence;
- an external-load-balancer advertiser tier that composes with fenced ownership
  while intentionally performing no local route mutation;
- session-store backed ownership reads and fenced SA-owner promotion;
- Host-XDP cross-node redirect config that fails closed unless mTLS/SPIFFE
  with no plaintext fallback is declared;
- a `VipDelivered` production probe for converged shared-L2 deployments where
  a floating VIP supplies packet delivery and steering mutations are
  intentional no-ops;
- NIC/DPU inline IPsec crypto offload posture validation for documented
  FIPS/HSM key-custody scope;
- reusable ports for steering backends, VIP advertisement, ownership reads,
  ownership fencing, and re-pin audit.

## Destination-scoped ownership

`SessionOwnershipKey` has typed initial-IKE, established-IKE, and ESP forms.
Every form structurally includes a `DestinationContext`: the public destination
address plus an opaque fixed-width `RoutingDomainTag`. Initial IKE additionally
binds the observed outer source tuple, initiator SPI, and wire exchange type;
established IKE binds both SPIs; ESP binds native versus UDP encapsulation and
the inbound SPI. IKE SPIs must be non-zero and RFC 4303's reserved ESP range
`0..=255` is rejected.

Keys implement ordering, hashing, and Serde. For persistence, redirect, or map
ABI boundaries, use the independent `to_canonical_bytes` /
`from_canonical_bytes` format: version 1 is at most 59 bytes and rejects
truncation, trailing data, unknown variants, and reserved values. Serde's shape
is not the stable wire format. `Debug` and `Display` redact the destination,
source tuple, and SPI values; applications must apply the same posture when
using explicit field accessors.

```rust
use opc_ipsec_lb::{
    DestinationContext, EligibleOwnershipMembers, IkeSpi,
    InitialExchangeDiscriminator, InitialIkeOwnershipKey, IpAddress,
    MembershipGeneration, OuterSourceTuple, RendezvousSelector,
    RoutingDomainTag, SessionOwnershipKey, ShardId,
};

# fn select_initial_owner() -> Result<(), Box<dyn std::error::Error>> {
let destination = DestinationContext::new(
    IpAddress::V4([192, 0, 2, 10]),
    RoutingDomainTag::new(7),
);
let initial = InitialIkeOwnershipKey::new(
    destination,
    OuterSourceTuple::new(IpAddress::V4([198, 51, 100, 9]), 45_000),
    IkeSpi::new(0x0102_0304_0506_0708)?,
    InitialExchangeDiscriminator::IKE_SA_INIT,
);
let members = EligibleOwnershipMembers::new(
    MembershipGeneration::new(42)?,
    vec![ShardId::new(0), ShardId::new(1), ShardId::new(2)],
)?;
let selector = RendezvousSelector;
let selected = selector.select_owner(&members, &SessionOwnershipKey::from(initial))?;

// Once the responder SPI is allocated, retain the same owner. Do not rerun
// rendezvous selection for an active initial exchange.
let promotion = initial.promote(IkeSpi::new(0x1112_1314_1516_1718)?);
let established = selected.carry_forward(promotion)?;
assert_eq!(selected.owner(), established.owner());
assert_eq!(
    established.owner_for_generation(members.generation())?,
    selected.owner()
);
# Ok(())
# }
```

`OwnerSelection` carries the membership generation and refuses consumption
against another generation. The generation is deliberately excluded from the
rendezvous score: advancing an unchanged view does not remap all sessions.
Adding or removing a member has HRW/rendezvous minimal-disruption behavior.
`collision_with` separately reports exact-key reuse and protocol-SPI reuse
within one destination/routing-domain context; allocation and collision policy
remain with the consumer.

This layer performs no I/O, fencing, leasing, packet classification, redirect,
route advertisement, or key handling. Those effects remain separate ports and
consumer policy.

## Leadership-gated VIP ownership

`VipOwnershipCoordinator` applies one reusable fail-closed state machine to a
management or dataplane VIP. It advertises only while the caller reports
leader, live quorum, healthy northbound listeners, and a non-zero leadership
fence. A new leadership epoch—including an ABA return to the same node—must use
a strictly newer, deployment-unique `LeadershipFence`. After any withdrawal,
the old fence cannot re-advertise the VIP.

A new coordinator begins in `VipOwnershipState::Uninitialized`; it does not
assume that process-local construction means the provider is clean. Its first
reconcile always withdraws the exact advertisement, accepting `NotFound` as
known absence, before it may advertise a valid first intent. This removes stale
routes left by an earlier process incarnation.

Provider failures and cancellation are represented as
`VipOwnershipState::ProviderStateUnknown`; they are not mistaken for either a
successful advertisement or a clean withdrawal. The next reconcile first
withdraws the exact request to reach known-absent state, accepting `NotFound`
as convergence, before retrying an epoch that is still authorized. Losing any
owner signal revokes that retry, so an ambiguous operation cannot preserve
stale authority. If a confirmed advertisement receives a strictly newer
complete fence, only the coordinator's accepted epoch advances: the identical
VIP route is already installed and no duplicate provider mutation is needed.
`AlreadyExists` is not proof of advertisement ownership: the BGP adapter maps
raw Linux `EEXIST` without route readback, so that result remains provider-
unknown and must pass through withdrawal cleanup before retry.

```rust,no_run
use opc_ipsec_lb::{
    ClusterNode, ExternalLbVipAdvertiser, IpAddress, LeadershipFence,
    VipAdvertisement, VipOwnershipCoordinator, VipOwnershipIntent,
};

# async fn reconcile_management_vip() -> Result<(), opc_ipsec_lb::IpsecLbError> {
let advertisement = VipAdvertisement {
    vip: IpAddress::V4([192, 0, 2, 40]),
    node: ClusterNode::new("control-a"),
};
let mut coordinator = VipOwnershipCoordinator::new(
    advertisement,
    ExternalLbVipAdvertiser::new(),
);

coordinator
    .reconcile(VipOwnershipIntent {
        leader: true,
        quorum_available: true,
        healthy: true,
        fence: Some(LeadershipFence::new(42)?),
    })
    .await?;
# Ok(())
# }
```

The `ExternalLbVipAdvertiser` probe reports that an external load balancer
supplies delivery. Its advertise and withdraw operations are intentional
no-ops: it cannot program a local route. The same coordinator can instead own
any `VipAdvertiser`, including the BGP route-export adapter. The intent contains
no SA, shard, IKE, ESP, key, or other protocol-specific material.

It intentionally does not decrypt ESP, derive IPsec keys, open BGP sessions,
shell out to routing daemons, implement VRRP, or claim packet forwarding.
Host-XDP steering and BGP route-export VIP advertisement are implemented behind
ports; SR-IOV, NIC offload, direct BGP speaker integrations, VRRP adapters, and
live failover evidence remain product/lab tiers built behind the ports. A
re-pin install never sets `forwarding_proven`; packet-flow proof must be
injected by lab/product dataplane evidence.

`SteeringProbe::vip_delivered()` is ready only for a product adapter that has
already established floating-VIP delivery on the converged L2. It deliberately
does not claim Host-XDP, VF-XDP, NIC offload, key custody, or datapath rule
mutation. The default probe remains `Unsupported`; this constructor does not
add a generic production no-op backend or select the tier automatically.

Same-SPI resume supports ESP Child SAs with 64-bit ESN and IKE SAs with a
64-bit AEAD explicit-IV counter; protocol-typed evidence must match the SA and
its steering SPI. Both persisted and live-mirrored key/counter sources must
supply an [RFC 6311](https://www.rfc-editor.org/rfc/rfc6311.html) send-IV
forward-jump of at least `2^30`, and the restored next IV must exactly match the
checked `checkpointed_next + forward_jump` result. The configured jump must
also bound the deployment's maximum packets sent between checkpoints. ESP ESN
evidence must additionally attest `max_peer_sequence_lag`: how far the peer's
highest authenticated sequence may trail `checkpointed_next - 1`, including
pre-checkpoint packet loss. [RFC 4303 Appendix
A2.2](https://www.rfc-editor.org/rfc/rfc4303.html#appendix-A.2.2) reconstructs
the untransmitted high-order bits from receiver replay-window state and assumes
a window no wider than `2^31`, so validation requires the checked sum
`forward_jump + 1 + max_peer_sequence_lag <= 2^31`. The exported ESP maximum
`2^31 - 1` is therefore only the absolute ceiling for an attested zero-lag
peer; any lag reduces it. ESP checkpoints and all resumed SA identifiers must
be non-zero. IKE's explicit-IV checkpoint may be zero and has no ESP-specific
maximum, but checked `u64` overflow always fails closed and requires rekey.

Inbound anti-replay evidence explicitly selects either a bit-for-bit exact
replay-window restore or bounded reopening with no bitmap-continuity claim.
The latter carries the caller-attested total number of previously accepted
values that might reopen, including lost bitmap state and post-checkpoint lag;
the SDK does not invent a deployment policy default. High-watermark rollback,
exact state not bound to its checkpoint, and a zero reopening bound fail closed.

Prepare every re-pin from `OwnershipSource::sa_ownership`, retaining both the
authoritative owner and its exact fence in `RePinRequest`. Generate one non-zero,
deployment-unique `OwnershipTransitionId` for that logical transition and reuse
it only when retrying the identical request; a later transition, including an
A→B→A owner cycle, requires a new ID. The coordinator computes a canonical
SHA-256 fingerprint over the complete safety-critical request and verifies that
the committed grant matches it. Session-store birth records use an empty
plaintext metadata payload; successful promotions replace it with versioned
transition-ID/fingerprint metadata. Ownership records with an expiry, an
arbitrary payload, or any mismatched key/type/owner/fence metadata fail closed.

After a store-backed ownership commit, recoverable audit or steering failures
return a non-cloneable partial for `RePinCoordinator::retry`; callers should
move that value into their retry queue and record its redaction-safe cause.
Before starting `repin`, retain a request clone (or clone `partial.request()`
before `retry`) when the future can be cancelled: replay performs a read-only
exact-fence recovery before it considers another ownership mutation. Steering
and audit ports must treat identical inputs idempotently so apply-then-error
outcomes converge. The coordinator revalidates the exact SA fence and takes a
final target-shard owner snapshot immediately before installing steering.
Those separate reads cannot make the current `SteeringBackend` mutation atomic
or order repeated A→B→C failovers; fence-aware steering replacement is tracked in
[issue #103](https://github.com/openpacketcore/openpacketcore-sdk/issues/103).

## Entropy note

The current ePDG SWu LB draft requires an embedded routing tag while also
requiring at least 64 unpredictable non-tag bits. That is not satisfiable for a
64-bit IKE responder SPI with any fixed tag, and ESP SPIs are only 32 bits.
`TaggedSpiLayout` therefore validates the requested entropy floor and fails
closed when a layout cannot meet it. Tests cover this explicitly so downstream
code cannot silently weaken SPI unpredictability.

## Verification

```sh
cargo fmt --all --check
cargo clippy --locked -p opc-ipsec-lb --all-targets --all-features -- -D warnings
cargo test --locked -p opc-ipsec-lb --all-features -- --test-threads=4
```
