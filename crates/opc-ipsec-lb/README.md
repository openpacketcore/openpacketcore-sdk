# opc-ipsec-lb

Safe SWu IKE/IPsec load-balancing and Host-XDP steering primitives for
OpenPacketCore CNFs.

This crate provides the ownership, recovery, and production Host-XDP datapath
boundaries for an ePDG/N3IWF/TWIF steer layer:

- tagged SPI layout and allocation policy;
- clone-shared tagged-SPI reservations for excluding HA-restored live SAs from
  fresh and rekey allocation, with explicit release on SA retirement;
- rendezvous selection for shard and `IKE_SA_INIT` bootstrap routing;
- destination-scoped canonical ownership keys and generation-bound rendezvous
  owner selection for routed, multi-ingress deployments;
- zero-copy raw IPv4/IPv6 SWu classifier for UDP/500, RFC 3948 UDP/4500,
  native ESP, IKEv2 SKF, fragments, and ICMP/ICMPv6 error quotes;
- a Host-XDP/eBPF fast path (`opc-ipsec-lb-ebpf`) executing the same keyless
  classification in the kernel, steering by destination-scoped ownership keys
  with fenced generations: local pass for self-owned keys, an explicit
  userspace-redirector hand-off interface for remote-owned keys, and
  fail-closed slow-path hand-off with per-verdict counters for map miss,
  stale generation, and unclassifiable candidates (never a silent drop);
- stateless IKE cookie helper for edge DoS posture;
- failover safety guards for IV-counter and replay-window restoration;
- audited same-SPI re-pin coordination with monotonic ownership fencing and
  opaque XFRM-applied ESP counter receipts;
- durable session-level multi-SA re-pin progress and fenced terminal
  retirement with bounded stale-retry tombstones;
- BGP route-export VIP advertisement through the safe route-steering backend;
- typed prefix advertise/withdraw intent toward an established routing stack
  (BIRD control socket), with declarative delta-exact reconcile, health-lease
  gating on an injected clock, per-peer session/BFD path-health telemetry, and
  a deterministic conformance fake — BGP/BFD wire protocols stay in the
  routing component;
- protocol-neutral VIP ownership reconciliation gated by caller-supplied
  leadership, quorum health, listener health, and a monotonic fence;
- an external-load-balancer advertiser tier that composes with fenced ownership
  while intentionally performing no local route mutation;
- session-store backed ownership reads and fenced SA-owner promotion;
- authenticated cross-node ingress redirect over a dedicated SPIFFE mTLS
  control channel and bounded connected UDP data channel, with exporter keys,
  replay protection, ownership fencing, receipts, and hop limits;
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

The ownership model itself performs no I/O, fencing, leasing, redirect, route
advertisement, or key handling. The adjacent keyless classifier constructs
these keys from public packet headers; owner selection and all effects remain
separate ports and consumer policy.

## Keyless raw ingress classification

`classify_keyless_ingress_packet` accepts a borrowed network-layer packet
(starting at the IPv4/IPv6 version octet) plus an opaque `RoutingDomainTag`.
It extracts the observed destination into a `DestinationContext`, the outer
source address and optional UDP port, the wire encapsulation, and typed IKE or
ESP SPI discriminators. Direct packets return the canonical
`SessionOwnershipKey` from the section above. No API accepts SA key material,
decrypts IKE/ESP, or retains packet bytes.

The parser recognizes initial and established IKE on UDP/500, marked IKE and
ESP on UDP/4500, native ESP, and IKEv2 SKF using the same fixed IKE header as
unfragmented traffic. Complete UDP/IKE packets must have one consistent set of
declared envelope lengths. Unfragmented and atomic packets require the UDP and
terminal IP payload lengths to agree exactly. A first fragment must declare a
UDP datagram larger than that fragment's terminal payload, and an ICMP quote
prefix is accepted only when the quoted IP length proves bytes are absent.
IPv6 extension traversal is capped at eight headers, intentionally enforces a
strict fail-closed order, and validates AH's encoded length and eight-octet
alignment. Non-initial IP fragments, malformed lengths, truncated fixed
headers, and unsupported protocols produce a typed `Unclassifiable` verdict;
the parser never guesses a SPI. Parsing allocates nothing and does not walk
encrypted payloads.

Supported ICMPv4/ICMPv6 errors are bound to the address on which the error
arrived, and their quote must show that address as the quoted packet source.
An established IKE SPI pair is direction-neutral and can use its canonical
ownership key. A quoted ESP SPI is normally the peer-owned outbound SPI, so it
is deliberately returned as `QuotedEspIdentity`; `ownership_key()` returns
`None` rather than misrepresenting it as an inbound `EspOwnershipKey`.

```rust
use opc_ipsec_lb::{
    classify_keyless_ingress_packet, KeylessIngressClassification,
    RoutingDomainTag,
};

# fn classify(raw_ipv4_or_ipv6: &[u8]) {
let verdict = classify_keyless_ingress_packet(
    raw_ipv4_or_ipv6,
    RoutingDomainTag::new(7),
);
match verdict {
    KeylessIngressClassification::Classified(packet) => {
        // Direct IKE/ESP returns Some; quoted outbound ESP intentionally does not.
        let destination = packet.destination();
        let ownership_key = packet.ownership_key();
        # let _ = (destination, ownership_key);
    }
    KeylessIngressClassification::NatTraversalKeepalive { .. } => {}
    KeylessIngressClassification::Unclassifiable { reason } => {
        let stable_code = reason.as_str();
        # let _ = stable_code;
    }
    _ => {}
}
# }
```

## Host-XDP fast path

`HostXdpSteeringBackend` loads the committed CO-RE XDP object
(`bpf/opc-ipsec-lb-xdp.bpf.o`) and maintains its pinned owner map. The kernel
program runs the same branch-bounded classification as the keyless userspace
classifier and looks each classified packet up by the canonical
destination-scoped ownership key, so an entry installed from a
`SessionOwnershipKey` is exactly the key the datapath derives from a packet.
The fail-closed XDP subset sends every packet whose base IPv6 header names an
IANA-registered extension kind to that slow path, except direct native ESP,
which is a supported SWu transport. This includes extension kinds the
userspace walker rejects, so an unwalked extension can never conceal UDP/500,
UDP/4500, or ESP from owner steering.
Each entry carries the owner shard and an ownership generation. ABI v5 keeps
the destination-scoped owner in `IPSEC_LB_OWNERS` and its authoritative
generation in the separate `IPSEC_LB_KEY_FENCES` map. Destination-scoped mode
passes or redirects a packet only when both entries exist and their non-zero
generations match exactly; an absent, malformed, or mismatched keyed fence is
stale and goes to the slow path. Each hash-map update publishes an old or new
complete element to concurrent readers, and strict decoding rejects
structurally invalid values.
Attach inventories strictly validated complete and interrupted pinned-map
namespaces, preserves their maximum fence, and stages fresh maps with empty
owners before the program is attached. A crashed process's entries are never
re-armed; malformed, identity-skewed, or active-map-intersecting residue fails
closed without mutating a live link.

Verdicts are fail-closed and the program never drops a packet:

- owner = self -> `XDP_PASS` to the local stack;
- owner = remote -> `XDP_REDIRECT` into the configured userspace-redirector
  hand-off interface. The authenticated steering encapsulation cannot be
  built in the kernel (AEAD is a userspace concern), so this explicit channel
  is the kernel/userspace split: the redirector captures the original packet
  and applies the authenticated transport. The hand-off interface is
  validated at attach (must exist, be up, and differ from the attached
  interface) and the redirect counter is incremented only for
  helper-confirmed redirects;
- map miss, stale or missing destination-scoped fence, unclassifiable
  candidates, and internal errors ->
  `XDP_PASS` to the userspace slow path, each with a distinct per-CPU counter
  exported via `counters()`.

Destination-scoped activation is fence-last. The backend first removes and
reads back the keyed fence, clears the old owner, stages and reads back the new
owner while it remains unreachable, and only then publishes and reads back the
exact authoritative keyed fence. Retirement advances durable ownership first,
then removes and reads back the exact owner and keyed fence. If either path
cannot prove its final state, the backend attempts a per-key stale cut, removes
the CONFIG activation, and detaches; readiness is restored only after detach
and a fresh pin-feasibility check are both proven.

The kernel feature floor and configured topology are enforced at load with the
typed `IpsecLbError::XdpKernelFloorNotMet` error: Linux >= 5.18 with kernel
BTF, the configured pin root inside bpffs, `bpf_xdp_load_bytes`, XDP
`bpf_link`, and effective `CAP_NET_ADMIN` plus `CAP_SYS_ADMIN`. `CAP_BPF`
alone is not sufficient because exact link/program enumeration and ID opens
remain `CAP_SYS_ADMIN`-gated. The attachment interface and any redirect
interface must exist and be up, and the redirect interface must be distinct.
Legacy netlink attachment is rejected.

Cross-process upgrades use the explicit `prepare_upgrade_handoff()` then
`adopt_upgrade_handoff()` boundary. Preparation serializes mutations, empties
and verifies owners, pins the exact live link, and terminalizes the old
backend. Adoption validates the link's program, target interface, live attach
mode, maps, and non-regressing fence; stages a fresh ABI-v5 namespace; then
uses `BPF_LINK_UPDATE` with `BPF_F_REPLACE` and the exact expected old program.
Kernel-interrupted link-state dumps receive up to three retries (four total
attempts), each from a fresh, empty snapshot. Partial observations are never
used for identity decisions, and malformed or repeatedly interrupted replies
still fail closed.
The old process must keep its userspace slow path available until the new
product instance reports readiness. If link-pin cleanup is reported, owner
and fence mutation remains quiesced until
`complete_upgrade_handoff_cleanup()` succeeds.

The per-interface pin directory and its permanent `control` directory are
the process-shared lease identity. Never remove or rename either while any
backend process may live. Use SDK detach/recovery for pin cleanup; manual
cleanup requires quiescing every backend process first and removing only the
documented map/link pins. Lease descriptors are close-on-exec, but a raw
`fork` child that does not immediately `exec` or close inherited descriptors
retains the lease and is unsupported.

Redirect is disabled by default; production remote-owner steering must
explicitly select `HostXdpRedirectHandoff::UserspaceRedirector`.
`HostXdpAttachMode::Native` uses Aya's zero-flag/default request, under which
the kernel may select driver or generic mode. Explicit `Generic` requires a
live SKB-mode hook and is the interoperable choice for veth hand-off peers
without an XDP consumer. See `tests/xdp_privileged.rs` for the gated
netns/veth proof (`OPC_IPSEC_LB_RUN_PRIVILEGED=1`), including legacy ABI
migration, v5 keyed-fence activation and retirement, and cleanup interruption
boundaries.

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

## External routing-stack prefix intent

`PrefixAdvertiserService` carries declarative exact-host-prefix intent to an
established routing stack; it does not implement BGP or BFD. Before BIRD is
started, `spawn_supervised` validates and durably removes the complete
adapter-owned fragment namespace. Before admitting the first advertisement,
`initialize` then reconfigures BIRD and proves every adapter-owned protocol
absent. `reconcile` invokes that second gate automatically, so durable intent
left by an earlier process cannot be silently adopted or briefly exported at
startup. Namespace admission, process-path validation, inventory, cleanup,
helper handshake, and control readiness share the configured startup deadline;
a timed-out pre-launch worker retains the fragment lock and no child is started.
A refused or indeterminate whole-set replacement is never
treated as a successful shrink: the service burns that lease generation and
drives the complete domain to known absence. Apply and withdrawal drivers
survive cancellation, exact-check adapter outcome identities, and recheck the
lease deadline immediately before and after a bounded adapter mutation. A
bounded priority scheduler coalesces overlapping queued intent, admits
withdrawals before queued applies, and withdraws simultaneous expired domains
in one adapter batch after at most the currently active mutation.

```rust,no_run
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opc_ipsec_lb::{
    AdvertisementLease, BirdAdapterConfig, BirdControlSocketAdapter,
    BirdDomainBinding, BirdProcessConfig, HostPrefix, IpAddress,
    LeaseGeneration, PrefixAdvertiserConfig, PrefixAdvertiserService,
    RoutingDomainTag,
};

# async fn configure_routing() -> Result<(), opc_ipsec_lb::IpsecLbError> {
let domain = RoutingDomainTag::new(64_512);
let adapter = BirdControlSocketAdapter::spawn_supervised(
    BirdAdapterConfig {
        socket_path: PathBuf::from("/run/bird/opc-owned.ctl"),
        fragment_dir: PathBuf::from("/etc/bird/opc.d"),
        domains: vec![BirdDomainBinding {
            domain,
            static_protocol: "opc_adv_64512".to_owned(),
            peer_protocols: vec!["edge_a".to_owned()],
        }],
        command_timeout: Duration::from_secs(10),
    },
    BirdProcessConfig {
        supervisor_helper_path: PathBuf::from("/usr/libexec/opc-bird-supervisor"),
        bird_executable_path: PathBuf::from("/usr/sbin/bird"),
        bird_config_path: PathBuf::from("/etc/bird/bird.conf"),
        startup_timeout: Duration::from_secs(20),
        shutdown_timeout: Duration::from_secs(10),
    },
).await?;
let service = Arc::new(PrefixAdvertiserService::new(
    adapter,
    PrefixAdvertiserConfig::default(),
)?);
service.initialize().await?;
// Supervise this watchdog independently from the lease-renewing/election task:
// if that task dies, this task must remain alive to enforce lease expiry.
let (watchdog_shutdown, watchdog_shutdown_rx) = tokio::sync::watch::channel(false);
let watchdog = tokio::spawn({
    let service = Arc::clone(&service);
    async move { service.run(watchdog_shutdown_rx).await }
});

let lease = AdvertisementLease::new(LeaseGeneration::new(7)?, 30)?;
service
    .reconcile(
        domain,
        BTreeSet::from([HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]),
        Some(lease),
    )
    .await?;
let lease_expiry_bound = service.lease_enforcement_bound();
# let _ = lease_expiry_bound;
# let _ = watchdog_shutdown.send(true);
# let _ = watchdog.await;
# Ok(())
# }
```

The BIRD adapter writes one bounded, atomic, domain-keyed fragment per
configured domain, restores previous advertisement intent after a refused or
indeterminate replacement, and removes readback-rejected routes before it
reports an authoritative applied subset. Withdrawal never restores old durable
intent: queued/in-progress configuration is followed by bounded protocol-
absence readback, while refusal, ambiguity, timeout, or surviving protocol
state fail-stops the owned BIRD process. Startup boundedly inventories the
complete reserved fragment namespace, including domains removed by a later
configuration, clears it before child launch, and proves the configured old
protocol instances absent before any new advertisement. The fragment directory
must be absolute, owned by the effective user, and mode `0700`.
It is pinned by descriptor; inventory, no-follow reads, removals, unpredictable
exclusive temporary creation, and rename are descriptor-relative. Unknown,
malformed, symlinked, foreign-owned, or over-limit candidates fail closed.

Peer visibility is read from BIRD's exact local Adj-RIB-Out with
`show route exported <peer> protocol <static>`. A locally originated route that
export policy filters out is therefore not reported in `advertised_to`.
This evidence does not prove that the remote peer installed the route; that
requires product/network evidence. BIRD configuration is capped at 32 peer
protocols total so local-origin and per-peer export readbacks fit one bounded
concurrent poll. BIRD's `export table` option is not required for this command.

Production BIRD is process-owned, not an independently surviving sidecar.
`opc-bird-supervisor` installs Linux `PDEATHSIG`, checks the expected parent to
close the fork/exec race, completes a versioned nonce/pipe handshake, and then
executes exactly `bird -f -c <config> -s <socket>`. There is no arbitrary BIRD
argument vector and no caller-constructible `RoutingProcessSupervision`. The
dedicated spawning thread stays alive for the child lifetime; helper/BIRD
exit immediately invalidates readiness and all mutations. BIRD executables
with set-ID bits or file capabilities are rejected because Linux clears
`PDEATHSIG` across those privilege transitions. Run the service/helper/BIRD
at the desired container identity and ambient/bounding capability set instead
of asking BIRD to daemonize or change effective credentials. The control-socket
parent must likewise be a private owned directory. A cross-process lock and
bounded active-connect check reject a live socket; only a proven-dead owned
socket is removed before restart.

The helper, BIRD executable, main configuration, and control-socket directory
are descriptor-pinned before launch. They must be root- or effective-user-owned
and must not be group/world writable; executable set-ID bits and file
capabilities are rejected. Because BIRD receives the main configuration through
`/proc/self/fd`, every include used by that configuration must be absolute.

`shutdown_timeout` bounds how long the explicit shutdown API waits for terminal
supervisor evidence. It is not a child-reap deadline: after requesting
`SIGKILL`, the supervisor retains the child until the kernel supplies wait
status. It also does not assert when an upstream router withdraws a path. A
consumer may state an upstream withdrawal bound only from actual peer export,
session, or BFD evidence under its configured routing timers.

Control replies, durable fragments, domains, peers, names, prefix sets,
process paths, and every service/process timeout have hard ceilings.

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

`SameSpiOutboundIvResume` makes the outbound cryptographic mode explicit.
`CounterBased` supports ESP Child SAs with 64-bit ESN and IKE SAs with a
64-bit AEAD explicit-IV counter; its protocol-typed evidence must match the SA
and steering SPI. Persisted and live-mirrored counter sources must supply an
[RFC 6311](https://www.rfc-editor.org/rfc/rfc6311.html) send-IV forward-jump of
at least `2^30`, and the restored next IV must exactly match the checked
`checkpointed_next + forward_jump` result. The configured jump must also bound
the deployment's maximum packets sent between checkpoints. ESP ESN evidence
must additionally attest `max_peer_sequence_lag`: how far the peer's highest
authenticated sequence may trail `checkpointed_next - 1`, including
pre-checkpoint packet loss. [RFC 4303 Appendix
A2.2](https://www.rfc-editor.org/rfc/rfc4303.html#appendix-A.2.2) reconstructs
the untransmitted high-order bits from receiver replay-window state and assumes
a window no wider than `2^31`, so validation requires the checked sum
`forward_jump + 1 + max_peer_sequence_lag <= 2^31`. The exported ESP maximum
`2^31 - 1` is therefore only the absolute ceiling for an attested zero-lag
peer; any lag reduces it. ESP checkpoints and all resumed SA identifiers must
be non-zero. IKE's explicit-IV checkpoint may be zero and has no ESP-specific
maximum, but checked `u64` overflow always fails closed and requires rekey.

`IkeRandomIv` is the separate IKE encrypt-then-MAC path. It carries no counter
fields and requires
`IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage`. The caller may
select it only when the protected-payload owner already obtains an independent,
unpredictable IV from a CSPRNG for every newly encrypted IKE message. The
attestation neither generates nor inspects IVs; it binds that product-owned
invariant into the fenced transition. It is rejected for ESP. `Unspecified`
exists only for legacy or ambiguously decoded evidence and always fails closed.

```rust
use opc_ipsec_lb::{
    AntiReplayResume, IkeRandomIvAttestation, ResumeKeySource, SaId,
    SameSpiOutboundIvResume, SameSpiResume,
};

let sa = SaId::Ike { responder_spi: 7 };
let resume = SameSpiResume {
    previous_sa: sa,
    resumed_sa: sa,
    outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
        attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
    },
    anti_replay: AntiReplayResume::ExactWindowRestore {
        checkpoint_highest_accepted: 42,
        restored_highest_accepted: 42,
    },
    key_source: ResumeKeySource::PersistedKeyMaterial,
};
resume.validate_for_repin(sa)?;
# Ok::<(), opc_ipsec_lb::IpsecLbError>(())
```

Inbound anti-replay evidence (ESP sequence state or IKE Message-ID state)
explicitly selects either a bit-for-bit exact replay-window restore or bounded
reopening with no bitmap-continuity claim.
The latter carries the caller-attested total number of previously accepted
values that might reopen, including lost bitmap state and post-checkpoint lag;
the SDK does not invent a deployment policy default. High-watermark rollback,
exact state not bound to its checkpoint, and a zero reopening bound fail closed.

### Applied ESP counter proof

For `SaId::Esp` plus `SameSpiOutboundIvResume::CounterBased`, validated
arithmetic is necessary but not sufficient. `RePinCoordinator::new` fails
closed until it receives an opaque `AppliedEspCounterReceipt` issued by
`opc-ipsec-xfrm` after the exact outbound SA was updated and read back. The
coordinator validates the receipt before a new ownership commit and repeats
GETSA validation after fencing immediately before first steering publication.
IKE counter and random-IV application remain consumer-owned.

```rust,ignore
use std::sync::Arc;

use opc_ipsec_lb::{RePinCoordinator, RePinRequest};
use opc_ipsec_xfrm::{
    EspCounterResumeApplyRequest, EspCounterResumeBinding,
};

// `staged_install` contains the complete outbound SA plus its sole outbound
// allow policy. Only this acknowledged, read-back, committed path can mint the
// live authority; recovery uses `recover_installed_outbound_sa_binding`.
let installed = staged_install
    .run_and_commit_outbound_sa_policy(Arc::clone(&xfrm))
    .await?;
let outbound_sa_binding_id = installed.id();

let request = RePinRequest::new_esp(
    inbound_spi,
    outbound_sa_binding_id,
    transition_id,
    previous_fence,
    previous_owner,
    new_owner,
    rule,
    ownership_key,
    resume,
)?;
let counter_binding = EspCounterResumeBinding::new(
    request.transition_id.get(),
    request.previous_fence.get(),
    outbound_sa_binding_id,
    restored_send_iv_next,
)?;
let receipt = xfrm
    .apply_and_read_back_outbound_esp_counter(
        &installed,
        outbound_sa_binding_id,
        EspCounterResumeApplyRequest::new(counter_binding, complete_outbound_sa),
    )
    .await?;
let live_target = installed.outbound_esp_counter_target();
let coordinator = RePinCoordinator::new(steering, fencer, ownership, audit)
    .with_esp_counter_resume_receipt(receipt, live_target);
let outcome = coordinator.repin(request).await?;
```

`RePinRequest::new_esp` carries the inbound SPI used for ingress ownership and
the distinct key-free `OutboundSaBindingId` issued for the outbound SA/policy.
That ID is safe to persist for correlation but is not authority. The
constructor-private `InstalledOutboundSaBinding`, its independently derived
process-local `OutboundEspCounterTarget`, and the opaque receipt bind the live
namespace actor and exact SA/policy without exposing namespace identity or key
material. A receipt for another operation, fence, binding, counter, actor, or
evicted SA is rejected before steering.

The successor must remain quiescent while evidence is obtained and consumed;
packet-driven sequence advancement is not serialized by product intent alone.
For a fresh activation, the XFRM actor revalidates the exact requested next
sequence at both the ownership boundary and the final publication boundary.
At the latter boundary it holds a short-lived actor guard while Host-XDP makes
the keyed-fence-last publication synchronously. An external
`RePinSteeringBackend` must consume the opaque operation permit with
`publish_with_esp_counter_guard` at its exact synchronous externally visible
publication cut and return the same permit. Returning an unconsumed guard or
publishing after the closure fails closed. `LegacySpiRuleRePinAdapter` rejects
guarded ESP publication and is not a production counter-resume path.

For a bounded session plan, gather every ESP receipt into
`EspCounterResumeProofSet::new`, gather each binding's live target into
`OutboundEspCounterTargetSet::new`, and pass both sets to
`with_esp_counter_resume_proof_set(proofs, targets)`. Each set admits 1 through
64 unique outbound bindings; the IKE entry needs neither. Receipts and live
targets are ephemeral capabilities and are not serialized into the session
journal. After restart, recover each `InstalledOutboundSaBinding` by exact
kernel readback. Reapply/read back every uncommitted ESP entry. Only for an
entry whose exact ownership grant was already committed may the caller use
`recover_committed_outbound_esp_counter` and its distinct
`EspCounterResumeRecoveryRequest`. That read-only receipt accepts monotonic
progress at or above the requested floor when it is issued, then rejects any
later readback below that issuance watermark. It is capped to committed
recovery and cannot authorize a new fence. Rebuild both bounded sets before
`resume`.

Prepare every re-pin from `OwnershipSource::sa_ownership`, retaining both the
authoritative owner and its exact fence in `RePinRequest`. Generate one non-zero,
deployment-unique `OwnershipTransitionId` for that logical transition and reuse
it only when retrying the identical request; a later transition, including an
A→B→A owner cycle, requires a new ID. The coordinator computes a canonical
SHA-256 fingerprint over the complete safety-critical request and verifies that
the committed grant matches it. Destination-scoped IKE and non-counter
requests retain the frozen v4 domain. Counter-based ESP requests use the v5
domain, which additionally binds the `OutboundSaBindingId`; an older SPI-only
or numeric-only grant cannot be recovered as if it carried destination and
kernel-counter authority. Finish an in-flight legacy transition with the old
SDK or rekey and begin a fresh transition; there is no unsafe compatibility
conversion.
Session-store birth records use an empty plaintext metadata payload; successful
promotions replace it with versioned transition-ID/fingerprint metadata.
Ownership records with an expiry, an arbitrary payload, or any mismatched
key/type/owner/fence metadata fail closed.

After a store-backed ownership commit, recoverable audit or steering failures
return a non-cloneable partial for `RePinCoordinator::retry`; callers should
move that value into their retry queue and record its redaction-safe cause.
Before starting `repin`, retain a request clone (or clone `partial.request()`
before `retry`) when the future can be cancelled: replay performs a read-only
exact-fence recovery before it considers another ownership mutation. Steering
and audit ports must treat identical inputs idempotently so apply-then-error
outcomes converge. The coordinator revalidates the exact SA fence and takes a
final target-shard owner snapshot immediately before installing steering. A
`RePinSteeringBackend` operation permit is acquired before those reads and is
retained through ownership fencing and the fenced steering write. The Host-XDP
implementation binds that permit to one backend, exact canonical ownership
key, and operation stripe; a different backend or key cannot consume it. The
private `RePinSteeringUpdate` separately binds the target owner shard and
authoritative generation derived by the coordinator.

### Durable session-level re-pin

Do not coordinate a packet-core session by awaiting several independent
`RePinCoordinator::repin` calls and treating the loop as atomic. An earlier SA
can already hold its new monotonic fence when a later SA fails before its own
commit; rollback or an ownership-record birth/upsert would bypass the exact
predecessor fence. `SessionRePinCoordinator` supplies the forward-only durable
saga for that case.

`SessionRePinPlan` fixes one canonical order and a bounded amount of recovery
work:

1. IKE SA;
2. default-bearer ESP SA;
3. zero or more dedicated-bearer ESP SAs in a caller-stable order.

The plan admits 2 through 64 unique SAs. It requires one common previous owner,
new owner, source shard, and target shard, plus a unique
`OwnershipTransitionId` and the exact `RePinRequest` for each SA. Its v1
SHA-256 fingerprint binds the privacy-preserving session stable ID, one
`SessionRePinOperationId`, the exact prior terminal fingerprint for later
operations, the order, and every per-SA ownership fingerprint. The journal
retains the complete requests, a completed-fence prefix, and any current
post-commit fence. It never derives a replacement request after restart.

```rust,ignore
use opc_ipsec_lb::{
    HostXdpSteeringBackend, HostXdpSteeringBackendConfig, RePinCoordinator,
    SessionOwnershipKeyspace, SessionRePinCoordinator, SessionRePinOperationId,
    SessionRePinPlan, SessionRePinSessionId, SessionStoreOwnershipFencer,
    SessionStoreOwnershipSource, SessionStoreRePinJournal,
};

// `stable_id` is a tenant-keyed digest, never a raw SUPI/IMSI. `requests` is
// ordered IKE, default ESP, then dedicated ESP and was prepared from exact
// authoritative predecessor snapshots.
let session_id = SessionRePinSessionId::from_stable_id(stable_id);
let operation_id = SessionRePinOperationId::new(operation_nonce)?;
let plan = SessionRePinPlan::new(
    session_id.clone(),
    operation_id,
    requests,
)?;
let identity = plan.identity();
let ownership_keys = SessionOwnershipKeyspace::new(tenant.clone(), nf_kind.clone());
let ownership = SessionStoreOwnershipSource::new(
    encrypted_quorum_backend.clone(),
    ownership_keys.clone(),
);
let fencer = SessionStoreOwnershipFencer::new(
    encrypted_quorum_backend.clone(),
    ownership_keys,
);
let journal = SessionStoreRePinJournal::new(
    encrypted_quorum_backend,
    tenant,
    nf_kind,
);
journal.validate_authority().await?;
let steering = HostXdpSteeringBackend::new(
    "swu0",
    HostXdpSteeringBackendConfig {
        routing_domain,
        ..HostXdpSteeringBackendConfig::default()
    }
    .for_destination_scoped_repin(),
);
if !steering.probe_repin().await?.mutation_ready {
    return Err("Host-XDP re-pin is not mutation-ready".into());
}
let saga = SessionRePinCoordinator::new(
    RePinCoordinator::new(steering, fencer, ownership, audit)
        .with_esp_counter_resume_proof_set(esp_counter_proofs, esp_counter_targets),
    journal,
);

match saga.start(plan).await {
    Ok(all_sas) => publish_session_continuity(all_sas),
    Err(error) => quarantine_or_retry_exact(error),
}

// After process restart, the caller supplies the same privacy-safe session key
// and exact operation-plus-plan identity. The SDK reloads and replays the
// retained exact requests.
let all_sas = saga.resume(&session_id, identity).await?;

// A later failover must prove exact succession from the prior terminal plan.
let next_plan = SessionRePinPlan::new_successor(
    session_id,
    next_operation_id,
    all_sas.plan().fingerprint(),
    next_requests,
)?;
```

This Host-XDP path is not a compatibility wrapper: the coordinator carries the
exact destination-scoped key and fenced generation into its private update.
An existing SPI-only backend that still implements `SteeringBackend` must opt
in explicitly with `LegacySpiRuleRePinAdapter::new(legacy_backend)` before it
is passed to `RePinCoordinator`. Do not use that lossy adapter for Host-XDP.

The snippet names product wiring values rather than defining them; the public
constructor signatures above are the integration contract. `start` first
linearizes one active plan per session. A competing different plan cannot
displace a prepared or partially committed saga. An exact duplicate helper is
safe: ownership grant recovery, steering installs, audit events, and journal
updates are idempotent. A completed plan may be replaced only through
`new_successor` with its exact terminal fingerprint. This prevents a stale
completed operation from displacing a newer restart/status authority; the new
operation ID and every per-SA transition ID must also be fresh relative to the
retained predecessor. A rejected successor leaves that terminal predecessor
unchanged. Resume and status require `SessionRePinIdentity`, which binds both
the operation ID and whole-plan fingerprint; retaining only the operation ID is
not sufficient restart authority.

`SessionRePinError::Quarantined` means no SA commit is retained and no
whole-session success is exposed. Once any ownership commit is known,
`ForwardConvergenceRequired` is the only failure result: resume the same
session and exact plan identity until the plan completes or surface an operator-visible
quarantine. Monotonic SA ownership is never rolled back. `SessionRePinStatus`
contains only phase and counts; its formatting, and the formatting of plans,
checkpoints, outcomes, operation IDs, and plan fingerprints, excludes session
IDs, owner/peer names, SAs, SPIs, counters, rules, and fences.

Before the saga mutates the next SA, and again before it returns terminal
success, it uses two deliberately separate phases. Phase one reconciles the
exact steering rule for every completed entry under the typed
`RePinSteeringBackend` permit and idempotency contract. Only after all repairs
finish does phase two perform a
global mutation-free sweep that revalidates every authoritative owner, fence,
transition ID, complete request fingerprint, retry proof, and target shard
owner. Monotonic fences cannot ABA back to a retained value, so a successful
phase-two sweep is the prefix linearization point. Any mismatch fails closed
without touching a later SA. This includes an earlier SA displaced by direct
per-SA `RePinCoordinator` use while a later steering repair was awaiting
completion.

Success proves only that one such whole-prefix convergence point existed during
that `start` or `resume` invocation. It is not an ownership or steering lease
and does not guarantee that the validated state is still current when the
future returns or afterward. A later supported transition may advance a fence
after its validation. Consumers must serialize subsequent transitions and use
current fenced authority at each action boundary. `status()` reports durable
journal progress without rerunning convergence validation; it is not live
ownership or steering authority.

Supported SDK ownership changes go through `RePinCoordinator` and fence before
steering. Host-XDP destination-scoped mode implements only the typed re-pin
port; its legacy raw steering mutation path is unavailable. A downstream
adapter that bypasses the permit and mutates an owner record can still create
post-validation drift without an ownership-fence change and is out of contract.
Callers must not introduce that escape or treat the session journal alone as
live ownership/steering authority.

Production HA must wire `SessionStoreRePinJournal` to the majority-committed
session store and wrap that caller-facing backend with
`EncryptingSessionBackend`. The journal introduces no alternate consensus or
encryption path. Exact recovery metadata is plaintext only above the existing
payload-protection boundary and is an authenticated envelope at the durable
backend, preserving the configured HKMS/KMS key lifecycle and encrypted-at-rest
contract. It persists only the key-free `OutboundSaBindingId` and request
metadata. It never persists `InstalledOutboundSaBinding`,
`AppliedEspCounterReceipt`, `OutboundEspCounterTarget`, namespace-actor
identity, or SA key material. No HKMS API, key wrapping, DEK rotation, or
at-rest encryption boundary changes in this flow. Call `validate_authority`
during startup; every read and write repeats that check and rejects a
capability downgrade or a backend unable to retain the maximum bounded
checkpoint. `MockSessionRePinJournal` is deterministic test support, not
durable or split-brain authority.

First quiesce new product transitions and remove product-owned IKE/XFRM SAs,
keys, and other dataplane state. Do not directly remove Host-XDP owner/fence
entries or durable ownership records. Retire the exact terminal session only
through `SessionRePinCoordinator::retire`; the journal port deliberately has no
direct Active-to-retired-tombstone completion operation. Its lower-level
transition and progress methods accept only coordinator-created opaque proofs
and exist for recovery adapters, not as a supported teardown shortcut.
Retirement accepts only
`SessionRePinPhase::Complete` and requires the same `SessionRePinSessionId`
plus operation-and-plan `SessionRePinIdentity` returned by terminal success. A
prepared or forward-converging checkpoint, predecessor identity, guessed
successor, or missing record fails closed.

The coordinator acquires one bounded, deadlock-free Host operation batch for
the complete session, rechecks the terminal checkpoint and every exact active
ownership grant under that batch, then stores non-expiring v4 `Retiring`
progress. For each ordered SA it advances the durable ownership record to a
higher retirement fence, removes and reads back the exact Host owner and keyed
fence, persists `CleanupComplete`, and only then fenced-deletes ownership. A
strictly newer, different ownership lineage is recorded as `Superseded` and is
never touched in Host. Same-lineage or unbound states fail closed. An
indeterminate authority outcome poisons the affected bounded Host operation
stripe, and `probe_repin` reports not ready until process restart. The next
keyed operation still classifies authoritative store state fail-closed.

Only after every v4 marker is ownership-finalized does the journal write the
fenced/CAS v2 tombstone at the same private tenant/NF/session key. It contains
only the exact session, operation, plan fingerprint, owner, and
retirement/expiry bindings—no SA requests, SPIs, fences, or counter inputs—and
passes through the same `EncryptingSessionBackend` and HKMS/KMS rotation path.
Active checkpoints use v3, in-progress retirement uses v4 without TTL, and the
bounded retired tombstone uses v2. Exact version dispatch rejects every unknown
version or metadata shape; a peer that does not understand one of these shapes
fails closed rather than treating it as absent state. The first completed call
returns `Retired`; an exact retry after a lost acknowledgement or restart
returns `AlreadyRetired` with the original deadline, which retries never
extend.

Upgrade existing deployments deliberately. The old Active v1 checkpoint is
numeric/SPI-only and cannot prove the v3 request, destination, outbound
binding, or live actor authority, so this SDK rejects it instead of rewriting
it. Drain or finish that Active transition on the old SDK before upgrading, or
rekey and start a new v3 transition. The existing exact Retired v2 tombstone
remains readable and continues to fence stale retries; v2 is not treated as an
Active checkpoint. Never delete or relabel an undecodable Active record to
force progress.

`SESSION_REPIN_RETIREMENT_RETENTION` is a fixed seven days. During that exact
horizon the tombstone rejects duplicate `begin`, resume, progress, and
successor attempts; the session-store per-key TTL then bounds cleanup to the
deployment's retirement rate over seven days. Once cleanup occurs, no finite
record can prove that an ancient initial request is stale. Consumers must
therefore mint a non-reused privacy-preserving stable ID for every logical
session and keep all teardown/retry queues shorter than seven days. This is an
explicit bounded guarantee, not indefinite replay history.

Retirement, `begin`, successor admission, and progress writes linearize at the
session-store generation CAS. Activation and retirement use the same bounded
Host operation stripes. Retirement acquires the full batch before changing the
terminal journal; restart recovery acquires the unfinalized suffix and re-reads
v4 progress under the batch. Consequently an activation ownership CAS or Host
publication cannot cross the retirement cut for the same key. The admitted
retirement runs in an owned task over a bounded session batch, so dropping the
observer future does not cancel a store CAS, Host cleanup, or durable marker write. Products must
still quiesce their own transition entry points before deleting product-owned
state; a terminal outcome is not a lease.

```rust,ignore
use opc_ipsec_lb::SessionRePinRetirementDisposition;

let terminal = saga.resume(&session_id, identity).await?;
quiesce_product_transitions(&terminal).await?;
remove_product_owned_ike_xfrm_keys(&terminal).await?;
// Do not remove Host owner/fence entries or session-store ownership directly.
let retired = saga.retire(&session_id, terminal.identity()).await?;
assert!(matches!(
    retired.disposition(),
    SessionRePinRetirementDisposition::Retired
        | SessionRePinRetirementDisposition::AlreadyRetired
));
```

The saga retains each current `SameSpiResume` and its v3 ESP ownership
fingerprint byte-for-byte, but it deliberately does not persist or fabricate
an applied-counter receipt. Its embedded `RePinCoordinator` must carry a proof
set covering every counter-based ESP request. On restart, reconstruct that set
from exact applied readback for uncommitted entries and committed monotonic
readback for entries already represented by the journal's authoritative
ownership progress. Receipt reconstruction uses no journal key material and
does not alter the existing encrypted-at-rest or HKMS/KMS boundary.

Migration from a sequential consumer loop is additive: build all requests
before the first mutation, retain one privacy-preserving session ID and one
operation ID, use `start` once, persist no product-local stage, and use `resume`
after every interruption. Only a terminal `SessionRePinOutcome` authorizes a
whole-session continuity claim. Retain its plan fingerprint and pass it to
`new_successor` for the next failover. Products still own SA discovery,
complete-set membership, transition-ID generation, key custody, counter
application and receipt reconstruction, dataplane blocking/programming, retry
scheduling, and operator quarantine
policy.

## Authenticated cross-node ingress redirect

Routed multi-ingress products can use the `redirect` module to carry an
already-observed IKE/ESP network-layer packet to its current fenced owner. A
fresh, non-resumed SPIFFE mTLS control connection authenticates a bounded peer
manifest and derives directional packet keys with the dedicated
`opc-ipsec-ingress-redirect/1` exporter context. The versioned `OPCR` data
format carries the original packet, canonical ownership key, public fence
generation, sender-identity digest, protection epoch, replay sequence, and hop
state. It never carries IKE, ESP, Child-SA, or other SA key material.

`IngressRedirectProfile::production` selects AES-256-GCM. HMAC-SHA-256 is an
explicit integrity-only profile for deployments whose confidentiality posture
permits it; the unauthenticated wire mode never selects an algorithm. Both
peers must authenticate the same MTU, security mode, hop/replay bounds, queue
limits, receipt-cache capacity, retry policy, maximum authentication age, and
sorted routing-domain allowlist. The real UDP adapter requires safe connected
endpoints in one IP family. The bounded in-memory adapter may deliberately pair
IPv4 and IPv6 to test each direction's exact outer-header ceiling.

The following schematic shows the public composition boundary. The caller
supplies TLS material snapshots, the committed ownership cache, the connected
datagram adapter, and the mandatory packet-too-big reporter; the SDK owns the
authenticated session, exact receipt correlation, and sole receive task.

```rust,no_run
use std::sync::Arc;

use opc_ipsec_lb::{
    establish_ingress_redirect_client, IngressRedirectDatagram,
    IngressRedirectDeliveryReceiver, IngressRedirectEndpoint,
    IngressRedirectError, IngressRedirectInboundOutcome,
    IngressRedirectOperationOutcome,
    IngressRedirectPacketTooBigReporter, IngressRedirectPeerExpectation,
    IngressRedirectPeerManifest, SessionOwnershipKey,
};
use opc_session_store::{
    Clock, FencedOwnershipCache, FencedOwnershipGeneration,
};
use opc_tls::TlsClientHandshake;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

async fn redirect_one<IO, C>(
    control_io: IO,
    server_name: ServerName<'static>,
    handshake: TlsClientHandshake,
    local: &IngressRedirectPeerManifest,
    expected_peer: &IngressRedirectPeerExpectation,
    ownership: Arc<FencedOwnershipCache<C>>,
    datagram: Arc<dyn IngressRedirectDatagram>,
    reporter: Arc<dyn IngressRedirectPacketTooBigReporter>,
    packet: &[u8],
    key: SessionOwnershipKey,
    generation: FencedOwnershipGeneration,
) -> Result<IngressRedirectOperationOutcome, IngressRedirectError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    C: Clock + 'static,
{
    let session = Arc::new(
        establish_ingress_redirect_client(
            control_io,
            server_name,
            handshake,
            local,
            expected_peer,
        )
        .await?,
    );
    let (endpoint, _inbound_deliveries) = IngressRedirectEndpoint::start(
        session,
        ownership,
        datagram,
        reporter,
    )?;

    // The endpoint owns the operation after begin_redirect returns. Cancelling
    // wait, or dropping this handle, does not cancel or reseal the operation.
    let mut operation = endpoint.begin_redirect(packet, key, generation)?;
    let outcome = operation.wait().await;
    endpoint.shutdown().await?;
    Ok(outcome)
}

async fn handle_one_inbound<C>(
    deliveries: &mut IngressRedirectDeliveryReceiver,
    forward_endpoint: &IngressRedirectEndpoint<C>,
    target_generation: FencedOwnershipGeneration,
) -> Result<(), IngressRedirectError>
where
    C: Clock + 'static,
{
    // Run this independently for packets redirected *from* the peer.
    let outcome = deliveries.receive().await?;
    match outcome {
        IngressRedirectInboundOutcome::Delivered(packet) => {
            // Apply the packet only through the product's local ingress path.
            let _ = packet;
        }
        IngressRedirectInboundOutcome::Forwardable(packet) => {
            // Select another authenticated endpoint, then consume this
            // one-shot capability without exposing or resetting its packet.
            let mut operation =
                forward_endpoint.begin_forward(packet, target_generation)?;
            let _outcome = operation.wait().await;
        }
        IngressRedirectInboundOutcome::Rejected(packet) => {
            let _ = packet.receipt_code();
        }
    }
    Ok(())
}
```

One `IngressRedirectPeerSession` is permanently consumed by exactly one
`IngressRedirectEndpoint`. Any later start from the same session is rejected
with `EndpointAlreadyConsumed`, even after shutdown or drop; reusing it could
split authenticated receipts across independent pending maps. Reconnect with a
fresh authenticated session to replace an endpoint. Graceful shutdown moves
the endpoint from active to draining, rejects new operations, lets admitted
endpoint-owned operations finish, then stops and reaps the sole receive task.
The shutdown coordinator survives cancellation of a caller waiting on
`shutdown`. A receive-task failure is terminal and resolves pending operations.
Already committed inbound queue entries remain drainable after shutdown.

Queue admission is bounded independently by packet count and retained bytes.
`begin_redirect` and `begin_forward` synchronously admit and seal once, then
return a must-use `IngressRedirectOperation`. The endpoint retains queue,
pending-receipt, retry, and cleanup ownership; dropping the observation handle
does not cancel the operation. Its terminal observation distinguishes proven
`NotSent`, an `AuthenticatedReceipt`, and `DeliveryOutcomeUnknown`. One attempt
has one `receipt_timeout` shared by adapter send and receipt arrival; the
absolute retry horizon is exactly `(max_retries + 1) * receipt_timeout` and
cannot be extended by scheduling delays. A profile is rejected unless rotation
overlap covers that horizon, and an epoch too near expiry refuses a new seal.
Retries reuse the identical already-sealed datagram. The endpoint retains the
runtime handle captured by `start`, so admitted operations, packet-too-big
feedback, the receive loop, and shutdown remain attached to that runtime even
when a synchronous `begin_*` call occurs from a thread with no entered runtime.
Oversize feedback consumes the same packet/byte permit and the same absolute
deadline as normal sends; it cannot create an unbounded side queue.

Before cryptographic open or replay-window mutation, the receiver reserves a
slot in the manifest-bound receipt cache. A vacant identity is shed without a
receipt or application effect when the cache is full; the receiver never emits
an uncached rejection that it could not replay. After authentication it
reserves both byte and delivery-queue capacity, performs final validation,
seals and commits the exact receipt, and only then publishes the inbound outcome
or sends that receipt. Commit failure publishes and sends nothing. An exact
same-frame retry receives the committed byte-identical receipt without another
application publication; a same epoch/sequence carrying different bytes still
reaches authentication and replay rejection. Live entries are never evicted
for newer frames and expire at the earliest of the full retry horizon, the data
epoch, and the receipt-sealing epoch. The production capacity is 65,536 entries
and is configurable through `with_receipt_cache_entries`; it must cover at
least the packet queue and is capped at 1,048,576. Sustainable unique-frame
rate is `entries / receipt_retry_horizon`, while bursts cannot exceed `entries`
until an entry expires.

An authenticated `Delivered` receipt proves bounded local queue admission, not
a downstream application effect. Receipt retention does not shorten a queued
delivery capability: the latter remains bounded by its authenticated epoch and
fresh ownership evidence. Dequeue revalidates the exact current generation
before owner identity; stale or receiver-behind generations cannot be hidden by
an owner change. Metrics distinguish queue admission, materialized delivery,
and dequeue-time stale-capability rejection, and expose receipt-cache current,
peak, saturation, and commit-failure counters. The raw authenticated
frame/open/seal boundary is crate-private.

Immediate adapter backpressure and deterministic configuration, size, or
closure failures are not blindly retried. Ambiguous I/O or send timeout can
retry the exact sealed frame; if no later authenticated receipt resolves the
operation, the outcome remains unknown. Oversize packets are never fragmented
by this layer: the mandatory borrowed reporter receives the exact effective
original-packet MTU so the product can produce ICMP/PTB feedback. On Linux the
real UDP adapter sets and verifies IPv4/IPv6 `DO` path-MTU discovery, budgets
against the smaller of configured and kernel-reported PMTU, refreshes that
ceiling downward, and converts runtime `EMSGSIZE` into exact PTB feedback. The
last proven ceiling survives a transient refresh failure; the failed send
returns a typed I/O error instead of replacing that ceiling with zero or an
unproven value. The real UDP adapter fails closed on platforms where those
socket guarantees are not implemented; a platform adapter must provide
equivalent non-fragmenting semantics through `IngressRedirectDatagram`.

Every receive reclassifies the packet and performs a fresh lookup in the sole
`FencedOwnershipCache` authority. Delivery requires the exact local owner and
generation. Superseded generations and classification mismatches are terminal;
missing, stale, non-local, or receiver-behind evidence produces a typed,
one-time `ForwardableIngressRedirectPacket`. Only consuming that capability
through another endpoint's `begin_forward` can forward it, preserving and
incrementing its authenticated hop count. The public capability exposes only
its reason, hop bounds, and ownership key, not the packet bytes. Callers cannot
copy it or reset a forwarded packet to hop one.

AES-256-GCM data and receipt frames share a maximum of `2^23` new protected
frames per directional epoch. Successful peer opens have the same bound, and
known-epoch authentication failures are capped at `2^36`. The session exposes
fixed-cardinality headroom through `aead_usage_status`; warning thresholds and
hard exhaustion request a fresh authenticated epoch, while hard exhaustion
fails closed with `AeadUsageExhausted`. Integrity-only HMAC mode does not claim
AES-GCM invocation counters and reports no AEAD headroom. Its private
HMAC-SHA-256 composition zeroizes normalized keys, pads, digest outputs, and
hash state; public APIs never expose raw redirect keys.

Certificate and trust rotation uses a new full mTLS connection and a new
exporter epoch. The receiver stages the new epoch before either sender cuts
over; current/previous acceptance is bounded by the configured overlap, peer
certificate expiry, local certificate expiry, and maximum authentication age.
The maximum age must be strictly greater than both the overlap and the fixed
45-second staging horizon. Rotation and reconciliation operations are
serialized per session. A new stage is rejected while a pending or live
previous receive epoch exists; expired pending/previous epochs are purged before
status, match, stage, activation, or reconciliation decisions. Initial
establishment performs a final authentication-lifetime check after the
peer-visible acknowledgement; expiry there retires the unreturned session as
`InitialOutcomeUnknown`.
`RotationOutcomeUnknown` retains reconcilable state and requires one of the
authenticated `reconcile_ingress_redirect_*` operations on a fresh connection.
`InitialOutcomeUnknown` returns no session: discard local state, use the
product's connection lifecycle to retire or replace any potentially installed
remote association, and only then attempt a fresh full TLS establishment. A
one-sided peer installation is not readiness evidence; blind immediate retry
is not the recovery contract. Initial establishment owns an armed cancellation
guard from the first peer-visible control operation until final admission, so
cancelling any handshake boundary cannot leak a usable half-installed local
session. Integration tests rotate independent CA/leaf material A to B through
the A-only, A+B, mixed A/B, B/B, and B-only trust phases while exercising
bidirectional endpoint traffic and old-epoch overlap.

Threat model: an unauthenticated network attacker cannot forge a peer, change
the authenticated route/fence/hop metadata, replay outside the bounded window,
or inject a packet into the delivery queue. A holder of an admitted peer
credential remains trusted for exactly its authenticated identity, owner,
endpoint, routing domains, profile, and epoch lifetime; compromise can inject
packets within that contract. Credential issuance/revocation, network
isolation, peer membership, route selection, ICMP policy, and application
dataplane effects remain deployment responsibilities.

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
