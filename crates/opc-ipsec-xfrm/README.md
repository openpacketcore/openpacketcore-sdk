# opc-ipsec-xfrm

## Purpose

`opc-ipsec-xfrm` is the safe Rust control surface for Linux XFRM IPsec state in
OpenPacketCore. It models Security Associations, Security Policies, replay
state, algorithms, key material, Linux backends, mocks, unsupported backends,
and rollback-aware composite operations.

The crate does not implement IKE negotiation, ESP packet processing, namespace
creation/switching, product SA/SPD policy, or deployment defaults. It can bind
backend execution to a calling thread's already-selected Linux network
namespace.

## Network-namespace binding

`LinuxXfrmBackend::bind_current_network_namespace` captures the calling
thread's current network namespace as an opaque device/inode identity and
starts a dedicated actor thread that inherits it. Invoke the binding method on
the thread that has already entered the intended namespace; the SDK does not
call `setns(2)` or select a namespace path.

```rust,no_run
use opc_ipsec_xfrm::{LinuxXfrmBackend, XfrmBackend};

# async fn example() -> Result<(), opc_ipsec_xfrm::XfrmError> {
let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
let capability = backend.probe().await?;
# let _ = capability;
# Ok(())
# }
```

All SA, policy, capability-probe, relocation, and fixed-DSCP work then runs on
that actor. The 64-entry queue applies bounded backpressure. Cancellation while
waiting for queue admission submits nothing; after admission, the actor drains
the operation even when the caller drops its future. Losing the reply to an
admitted mutation is reported as `StateIndeterminate` (`ALLOCSPI` included),
while a lost read/probe reply is `Unavailable`. Dropping the final backend clone
closes the queue and lets the detached actor drain without blocking `Drop`.

## API Shape

- `XfrmBackend`: async port for SPI allocation, SA
  install/query/rekey/relocation/removal, policy install/rekey/remove, and
  capability probing.
- `LinuxXfrmBackend`: safe adapter over `NETLINK_XFRM` through
  `opc-linux-xfrm-sys`.
- `NamespaceBoundLinuxXfrmBackend`: cloneable bounded actor that keeps every
  Linux XFRM operation in one captured network namespace.
- `MockXfrmBackend`: deterministic in-memory backend with operation capture,
  a source-compatible separate `MockSaRelocation` log, and failure injection.
- `UnsupportedXfrmBackend`: trait-compatible unsupported backend.
- Model exports include `IpAddress`, `XfrmSelector`, `XfrmId`, `SaParameters`,
  `PolicyParameters`, `XfrmTemplate`, `InstallSaRequest`,
  `InstallPolicyRequest`, `QuerySaRequest`, `SaState`, `SaReplayState`,
  `SaRelocationSelector`, `SaRelocationIdentity`, `SaRelocationEncap`,
  `SaRelocationDirection`, `RelocateSaRequest`,
  `XfrmRequestId`, `UdpEncap`, `UdpEncapError`, `XfrmMark`, `DscpCodepoint`,
  `LifetimeConfig`, and `XfrmProbe`.
- Algorithm/key exports include `Algorithm`, `AuthAlgorithm`, `AeadAlgorithm`,
  `KeyMaterial`, and Linux XFRM algorithm-name constants.
- Composite helpers include `install_sa_policy_with_rollback`,
  `install_bidirectional_sa_policy_with_rollback`, `rekey_sa_policy`, and
  `remove_policy_sa`.
- `XfrmStagedInstall` is the cancellation-safe counterpart of
  `install_sa_policy_with_rollback`. Its consuming `run(self, ...)` receiver
  makes one runner an affine, compiler-enforced invariant, while a
  caller-cloned `XfrmInstallJournal` survives cancellation. `run` accepts an
  `Arc` backend and, on first poll, moves the operation into an owned Tokio
  worker. Dropping the observing future therefore cannot detach a Linux
  `spawn_blocking` mutation and race cleanup; the journal remains live until
  the backend operation actually returns. An acknowledged install can be
  transferred to product teardown with `journal.commit()`. Otherwise the
  journal returns a generation-bound
  `XfrmInstallRecoveryPlan`; recovery requires an explicit `Owned`, `Absent`,
  `Foreign`, or `Indeterminate` classification for every exact SA/policy
  candidate and is serialized across journal clones. Recovery also runs in an
  owned worker, so dropping its observer cannot let a same-identity replacement
  overtake an issued removal. If either owned worker terminates abnormally, its
  guard records `SupervisionLost` and permanently rejects in-process recovery:
  a detached blocking syscall may still complete after the async worker is
  gone. A fresh process must re-establish namespace-wide XFRM writer exclusion
  and authoritative readback before deciding how to handle residue. Matching
  readback alone cannot distinguish an identical foreign replacement. Both
  supervised APIs require a live Tokio runtime and otherwise return a typed,
  redaction-safe runtime error.
- `XfrmStagedObjectInstall` is the single-object counterpart of
  `XfrmStagedInstall` for exact SA-only and policy-only installs: an SA that
  intentionally reuses an existing shared policy, or an additional policy
  direction for one SA. Its typed `XfrmObjectInstallRequest` supervises one
  operation without inventing a dummy companion mutation, under the same
  rules as the composite boundary: affine one-run execution, an owned Tokio
  worker after first poll, a caller-cloned `XfrmObjectInstallJournal`, an
  explicit `Acquired`/`Indeterminate`/`SupervisionLost` ownership state, and
  generation-bound classified recovery of the single exact
  `XfrmObjectRemovalRequest` candidate. An observed `AlreadyExists`
  rejection authorizes no removal of the pre-existing object; an unobserved
  result requires explicit `Owned`/`Absent`/`Foreign` classification under
  caller-held writer exclusion before any removal, and worker loss
  permanently disables in-process commit and recovery.
- `InstalledOutboundSaBinding` is an opaque, unforgeable direction authority
  for one exact ESP SA and its sole outbound allow-policy. The only fresh mint
  is `XfrmStagedInstall::run_and_commit_outbound_sa_policy`, after both kernel
  acknowledgements and journal commit. After process loss,
  `NamespaceBoundLinuxXfrmBackend::recover_installed_outbound_sa_binding`
  performs actor-local `GETPOLICY` followed by `GETSA` before minting a new
  binding. Both paths reject inbound/block policies, mismatched selectors,
  marks or interface IDs, ambiguous templates, and unsupported kernel
  attributes. A wildcard template SPI is accepted only when the template and
  SA carry the same nonzero request ID.
- With feature `ikev2`, the crate also exports Child SA KEYMAT and negotiation
  mappers from `opc-proto-ikev2` into explicit XFRM install requests.
  `Ikev2ChildSaXfrmOptions` can carry one shared request ID and exact
  directional initial NAT-T templates without changing the established public
  request struct.

## Opaque outbound-SA binding

Use the binding-returning staged path when later work must prove that an SA is
the outbound member of an installed SA/policy pair:

```rust,no_run
use std::sync::Arc;

use opc_ipsec_xfrm::{
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend,
    OutboundSaBindingError, XfrmCompositeInstallRequest, XfrmStagedInstall,
};

async fn install_outbound(
    backend: Arc<NamespaceBoundLinuxXfrmBackend>,
    request: XfrmCompositeInstallRequest,
) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
    XfrmStagedInstall::new(request)
        .run_and_commit_outbound_sa_policy(backend)
        .await
}
```

Persist `binding.id().to_bytes()` only as a correlation value. An
`OutboundSaBindingId` is deliberately constructible from persisted bytes and
is never authority by itself; the live opaque binding and fresh actor-local
validation remain mandatory. Restart recovery uses retained install intent:

```rust,no_run
use opc_ipsec_xfrm::{
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend,
    OutboundSaBindingError, XfrmCompositeInstallRequest,
};

async fn recover_outbound(
    backend: &NamespaceBoundLinuxXfrmBackend,
    request: XfrmCompositeInstallRequest,
) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
    backend
        .recover_installed_outbound_sa_binding(request)
        .await
}
```

The binding and its stable ID are key-free: they retain algorithm identity and
key lengths, but never key bytes or key-derived hashes. This avoids creating a
second long-lived key-custody path alongside the product's HKMS integration.
At every recovery/use boundary, the supplied zeroizing `SaParameters` key
material is compared in constant time with key bytes from the zeroizing GETSA
response; those bytes are never copied into the binding, ID, logs, or errors.
The product remains responsible for key custody and for supplying the intended
SA parameters.

Linux lockdown can redact every GETSA key byte to zero without marking the
response. That wire shape is indistinguishable from intentionally configured
all-zero key material. The SDK therefore never falls back to algorithm shape:
either case fails closed with
`xfrm_outbound_sa_binding_key_readback_unavailable`. Fresh staged issuance
performs exact readback before journal commit or binding mint, so this failure
leaves a caller-held journal clone in the recoverable `Complete` state and
returns no authority. Recovery/use fails with the same code. Deployments whose
kernel lockdown policy redacts XFRM secrets cannot use this exact binding (and
the counter-repin operations gated by it) unless the platform provides readable
exact GETSA key material; product startup/readiness should surface this stable
capability failure.

Linux ESN SAs encode the fixed one-byte replay window as zero, as required by
the XFRM UAPI, and carry the complete window in `XFRMA_REPLAY_ESN_VAL` only.
Readback rejects mixed, duplicated, or flag-inconsistent replay
representations. Dynamic counters and last-used timestamps are permitted, but
unmodeled semantic SA or policy attributes fail closed.

## Sealed outbound ESP counter authority

Same-SPI failover must use
`NamespaceBoundLinuxXfrmBackend::apply_and_read_back_outbound_esp_counter`.
The production API accepts only the live `InstalledOutboundSaBinding`, its
exact `OutboundSaBindingId`, a durable `EspCounterResumeBinding`, and transient
exact SA parameters. It has no caller-selectable direction and is not exposed
through `XfrmBackend` or the mock backend. The durable ID intentionally remains
stable when identical state is recovered in another namespace. Before using a
receipt, the coordinator must therefore derive an `OutboundEspCounterTarget`
from its intended live binding and supply that opaque, process-local target to
proof validation. A receipt from another actor or network namespace is rejected
before the foreign backend is queried, even when every durable field is equal.

`EspCounterResumeBinding::new` takes the **next** ESP sequence number the
successor is allowed to emit. Linux GETSA replay state reports the last
assigned sequence, so the actor compares and, when necessary, writes
`requested_next - 1`. Legacy replay accepts the remaining 32-bit sequence
space; ESN uses the full 64-bit value. Exhausted or ambiguous state fails
closed. The actor uses the dedicated Linux `XFRM_MSG_NEWAE` replay-state UAPI,
not a generic SA replacement:

- an observed value above the requested floor returns typed `AlreadyAdvanced`
  without mutation;
- an equal value performs exact final readback and returns an idempotent
  receipt without mutation; and
- a lower value advances once, then requires exact policy, SA, transient-key,
  replay-mode, and counter readback before returning a receipt.

The namespace actor drains admitted work even if the observing future is
dropped. Exact retry after a lost reply therefore recovers the applied value
without issuing a second update. Receipts have no public constructor, expose
no topology or counter values, expire after 30 seconds, and are retained in a
bounded 1,024-entry actor-local registry. Generic SA or policy mutations
invalidate the registry before they execute, including when the mutation later
fails.

```rust,no_run
use opc_ipsec_xfrm::{
    EspCounterProofRequirement, EspCounterResumeApplyRequest,
    EspCounterResumeBinding, EspCounterResumeProofSet,
    InstalledOutboundSaBinding, NamespaceBoundLinuxXfrmBackend, SaParameters,
};

async fn apply_counter(
    backend: &NamespaceBoundLinuxXfrmBackend,
    authority: &InstalledOutboundSaBinding,
    operation_id: u128,
    fence_generation: u64,
    requested_next: u64,
    exact_sa: SaParameters,
) -> Result<(), opc_ipsec_xfrm::EspCounterResumeError> {
    let target = authority.outbound_esp_counter_target();
    let binding = EspCounterResumeBinding::new(
        operation_id,
        fence_generation,
        authority.id(),
        requested_next,
    )?;
    let receipt = backend
        .apply_and_read_back_outbound_esp_counter(
            authority,
            authority.id(),
            EspCounterResumeApplyRequest::new(binding, exact_sa),
        )
        .await?;
    EspCounterResumeProofSet::single(receipt)
        .validate_counter_proof(
            &target,
            binding,
            EspCounterProofRequirement::BeforeOwnershipCommit,
        )
        .await
}
```

The successor SA must remain quiescent and unpublished until the receipt is
validated immediately before its required ownership/publication boundary.
Products must preserve exclusive XFRM writer authority; packet emission or a
second raw-netlink writer between preflight and receipt validation violates
this contract.

After process loss and an already-committed ownership grant,
`recover_committed_outbound_esp_counter` performs read-only exact validation
and accepts a live counter at or above the durable floor. Its receipt is
structurally limited to `EspCounterProofRequirement::CommittedRecovery`; it
cannot authorize a new ownership fence. A product may use that proof while
resuming publication only after it independently proves that the exact
ownership fence was committed before process loss. This separation prevents an
advanced live SA from being reinterpreted as fresh pre-commit authority while
retaining crash recovery after fencing but before steering.

## Usage

```rust,no_run
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
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
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
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

## Authenticated-only ESP and ENCR_NULL

With the `ikev2` feature,
`Ikev2ChildSaCryptoProfile::new_authenticated_only` derives no encryption or
salt octets and the mapper emits separate Linux auth and NULL-crypt slots. The
Linux adapter uses the kernel's canonical `ecb(cipher_null)` transform with a
zero-bit key, exposed as `XFRM_ENCR_NULL` and `Algorithm::null()`. This is an
adapter representation required by the XFRM UAPI; it does not fabricate an
IKEv2 encryption key or alter the negotiated ENCR_NULL transform.

The encoder accepts an empty key only for this exact NULL algorithm. It rejects
a non-empty NULL key, NULL without separate authentication, empty key material
for every other cipher, AEAD in the crypt slot, and ESP auth without an
explicit NULL cipher before sending a netlink mutation. Linux itself rejects
the latter raw shape with `EINVAL`.
Generic models and mocks may still describe other protocol shapes, but Linux
authenticated-only ESP callers must use `Algorithm::null()` or the IKEv2
mapper.

`tests/xfrm_auth_only_privileged.rs` creates a fresh local/peer namespace pair,
installs bidirectional authenticated-only tunnel SAs through the SDK, captures
a real ESP packet, and proves both valid delivery and integrity-failure
rejection of a tampered packet. It contains synthetic documentation-address
and private-address fixtures only; keys are test-only and never logged.

## Initial IKEv2 Child SA NAT-T mapping

The established `Ikev2ChildSaXfrmRequest` shape and
`build_xfrm_requests_from_ikev2_child_sa` remain the source-compatible
native-ESP boundary. To map an already validated NAT-T decision, use the one
general options entry point:

```rust,no_run
use std::error::Error;

use opc_ipsec_xfrm::{
    build_xfrm_requests_from_ikev2_child_sa_with_options, Ikev2ChildSaXfrmOptions,
    Ikev2ChildSaXfrmRequest, Ikev2ChildSaXfrmRequests, UdpEncap,
};

fn map_natt_child_sa(
    request: &Ikev2ChildSaXfrmRequest,
) -> Result<Ikev2ChildSaXfrmRequests, Box<dyn Error>> {
    let options = Ikev2ChildSaXfrmOptions::new().with_udp_encapsulation(
        // Peer-to-local: translated peer source port to local NAT-T port.
        UdpEncap::esp_in_udp(62_000, 4500),
        // Local-to-peer: local NAT-T port to translated peer destination.
        UdpEncap::esp_in_udp(4500, 62_000),
    )?;
    Ok(build_xfrm_requests_from_ikev2_child_sa_with_options(
        request, options,
    )?)
}
```

The options constructor rejects every type other than RFC 3948 ESP-in-UDP and
rejects zero ports with stable, value-free errors. The mapper carries each
validated template unchanged into its matching `SaParameters::encap`; it never
reverses ports. Default options keep both directions at `None` and preserve the
original native-ESP mapping exactly.

NAT detection, deciding whether encapsulation is required, and selecting
original or translated directional ports remain product-owned. This initial
mapping does not observe post-establishment rebinding or relocate an installed
SA; use the separately fenced relocation boundary only after authenticated
control-plane authorization and exact state reconciliation.

## Exact SA relocation

`XfrmBackend::relocate_sa` moves one query-proven tunnel-mode ESP SA to
authenticated control-plane-signalled outer addresses and replacement
ESP-in-UDP ports. The Linux backend uses the current-upstream
`XFRM_MSG_MIGRATE_STATE` UAPI, which looks up the existing state by
destination, SPI, protocol, family, and input mark. It deliberately does not
use the older `XFRM_MSG_MIGRATE` operation: that operation cannot identify one
SA by SPI and mark and therefore cannot satisfy this API's exact-identity
contract.

Build the optimistic-concurrency identity from a fresh query instead of
reconstructing it from remembered configuration:

```rust,no_run
use opc_ipsec_xfrm::{
    IpAddress, QuerySaRequest, RelocateSaRequest, SaRelocationDirection,
    SaRelocationEncap, UdpEncap, XfrmBackend,
};

async fn move_authenticated_sa(
    backend: &impl XfrmBackend,
    query: QuerySaRequest,
) -> Result<(), opc_ipsec_xfrm::XfrmError> {
    let current = backend.query_sa_relocation_identity(query).await?;
    backend
        .relocate_sa(RelocateSaRequest {
            current,
            new_source_address: IpAddress::Ipv4([198, 51, 100, 10]),
            new_destination: IpAddress::Ipv4([198, 51, 100, 20]),
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::Inbound,
        })
        .await
}
```

This is an authenticated control-plane primitive, not packet inference. A
consumer may call it only after an authenticated/signalled procedure such as
MOBIKE or an equivalent product-owned rebind decision has authorized the new
endpoints. The SDK never learns or trusts a replacement endpoint merely
because a packet arrived from it.

The `direction` field makes the current-upstream Linux safety contract
explicit. `Inbound` needs no temporary policy: the kernel atomically transfers
sequence and replay state, and there is no cleartext egress fallback.
`OutboundBlockPolicyInstalled` is an assertion by the caller that the required
outbound block is already active. For every outgoing SA, follow this exact
order while holding the namespace-wide XFRM writer lock:

1. Install a higher-precedence block policy for the affected selector.
2. Remove the old allow policy.
3. Call `relocate_sa` with `OutboundBlockPolicyInstalled`.
4. Install the replacement allow policy/template for the relocated SA.
5. Remove the temporary block policy only after the replacement is proven.

Keep the block installed when relocation returns `StateIndeterminate`; resolve
the SA and policy state before allowing traffic. Omitting this sequence can
allow outbound cleartext during policy/SA transition. With AES-GCM it can also
allow a repeated `(key, IV)` pair, which destroys the algorithm's security.
That IV risk is outbound-only because the peer controls IV generation for an
incoming SA. This sequence follows the upstream Linux
[`XFRM_MSG_MIGRATE_STATE` documentation](https://docs.kernel.org/networking/xfrm/xfrm_migrate_state.html).

### Cancel safety

`relocate_sa` is not cancellation-safe once its future has been polled. The
blocking netlink worker can continue after the Rust future is dropped, so do
not put relocation behind an aborting timeout and do not assume that dropping
the future cancels the kernel operation. Supervise and poll it to completion.
Treat task cancellation, caller disconnection, or process uncertainty as
`StateIndeterminate` operationally. Keep the outbound block policy and the
namespace-wide XFRM writer exclusion in place until the worker completes and
exact GETSA queries reconcile both the old and new tuples. If the process exits,
keep traffic fenced and perform that reconciliation during recovery before
releasing the block. Retry only after exact readback; relocation is not blindly
idempotent after process loss.

`SaRelocationEncap::Preserve` omits the kernel attribute and exactly inherits
either native ESP or the installed NAT-T ports. `Set` adds or replaces an
ESP-in-UDP template; `Remove` uses the upstream type-zero sentinel to return to
native ESP. Invalid or no-op transitions fail before mutation.

The fresh identity also carries every selector field that the migration UAPI
installs: both ports and masks, prefix lengths, protocol, interface index, and
UID. Preflight and readback compare those fields exactly. When the destination
identity changes, success additionally requires an exact query proving that the
old tuple is absent; an old tuple that is still present or cannot be parsed or
queried unambiguously returns `StateIndeterminate`. Encapsulation-only changes
at the same destination use the single exact resulting-state readback because
the old and target lookup identities are identical. IPv4 union padding and
selector reserved bytes must be canonical. The narrow SDK NAT-T model has no
original-address (`xfrm_encap_tmpl.oa`) representation, so a queried SA with a
nonzero original address is rejected before mutation instead of silently
zeroing it.

The operation changes one SA only. It does not migrate XFRM policies or their
templates. Consumers must coordinate any policy changes, including policies
whose templates pin an outer address or SPI, and must serialize all XFRM
writers in the network namespace. The preflight and post-mutation GETSA proofs
cannot exclude a concurrent external writer. This primitive alone is not a
claim of seamless mobility: kernel support, authenticated IKE control-plane
handling, peer behavior, policy coordination, and traffic evidence remain
required.

Linux stores an internal `UnknownUntilUse` state until
`XfrmBackend::sa_relocation_capability` is called. That method sends the
upstream-documented non-mutating `XFRM_MSG_MIGRATE_STATE` missing-SA probe. Its
non-zero SPI is paired with protocol zero, which Linux does not permit on an
installed SA, so the probe tuple cannot collide even in a live namespace. An
`ESRCH` response proves `Available`; `EINVAL` proves that the kernel predates
the message; and `ENOPROTOOPT` proves that the message is known but
`CONFIG_XFRM_MIGRATE` is disabled. Both unsupported responses report
`Missing`. After support is established, `EINVAL` from a real relocation stays
a real operation failure and never masquerades as old-kernel evidence.
Successful exact relocation/readback also records `Available`, while a real
`ENOPROTOOPT` records `Missing`. The kernel must carry the upstream
`XFRM_MSG_MIGRATE_STATE` UAPI; version-string inference is intentionally not
used. The mock backend provides deterministic relocation semantics, while
unsupported backends reject the operation. The new trait methods have defaults
and the existing `XfrmProbe` and `SaState` shapes are unchanged, so existing
backend implementations and struct literals remain source compatible. No
Cargo feature is required.

## Authenticated ESP peer observations

`EspPeerObservationBoundary` is the observation authority needed before an
RFC 7296 section 2.23 recovery can update an established ESP-in-UDP path. It
turns kernel-attributed ESP decap events into bounded, typed observations
keyed by exact SA identity and direction: when an observed inbound SA starts
arriving from a new outer source, the consumer drains exactly one
`EspPeerObservation` retaining only the minimum routing facts (address
family, ingress interface index, encapsulation source address and port,
monotonic per-SA generation, and an explicit loss status). After the consumer
applies its own authenticated path update, `update_current_source` rebases
the boundary. The boundary never applies or infers a relocation.

An observation is only as strong as its trust anchor. The boundary accepts
solely `EspPeerEventProvenance::PostFinalReplayAccepted` events: the kernel
ESP decap path verified packet integrity (ICV or AEAD) and the packet won the
final anti-replay advance on the exact SA named by the event. Stock Linux
`XFRM_MSG_MAPPING` does not meet that contract — it is emitted post-ICV but
before the final replay recheck (a concurrent duplicate can emit it and still
lose replay), its `GFP_ATOMIC` producer loss is invisible to receivers, and it
carries no ingress ifindex, ESP sequence, lookup mark, or XFRM `if_id`. The
crate therefore ships the boundary, the provenance contract
(`EspPeerObservationSource`), and `ScriptedEspPeerObservationSource` for
replay of captured or synthetic events (gated behind the `testkit` cargo
feature so production builds cannot mint unverified events), but no
stock-kernel event source. This is a partial landing of the observation
authority: shipping a conformant platform event source remains tracked
follow-up work.
Registration is refused for crypt-only SAs: post-decrypt delivery without
integrity is not authentication.

The boundary rejects foreign-scope, unknown-SA, cross-SA, wrong-direction,
family-mismatched, malformed, interface-scope-less, stale-cursor, and
post-teardown events with value-free rejection labels. Memory is bounded: one
outstanding observation per SA (a further distinct source closes the slot
fail-closed with an explicit `OverflowClosed` status until drained) and a
capacity-bounded registry. Teardown drains and removes all per-SA state and
returns an exact termination record. `Debug`/`Display` for every observation
type print only labels and non-sensitive metadata — never addresses, ports,
SPIs, marks, or interface identities.

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
- Linux SA encoding validates and computes the complete UAPI body size before
  copying authentication, encryption, or AEAD keys. Algorithm temporaries, the
  fixed-capacity SA body, and the complete netlink request are zeroizing
  buffers; the destination allocation cannot grow after its first key copy.
  This covers the transient userspace UAPI copy only—kernel key custody remains
  platform-owned.
- The configured netlink receive size is a hard bound. A consumed oversized
  reply after a mutation returns `StateIndeterminate` with the original
  operation; an oversized read returns typed `ResponseTooLarge`. Neither path
  retries the already-consumed datagram.
- Linux mutation requires kernel XFRM support and effective `CAP_NET_ADMIN`.
- Exact SA relocation additionally requires the upstream
  `XFRM_MSG_MIGRATE_STATE` UAPI and product-owned authenticated endpoint and
  policy coordination.
- Fixed outer DSCP additionally requires bpffs, kernel BTF, `CAP_BPF` (or
  `CAP_SYS_ADMIN`), one configured tc egress attachment per SWu interface, and
  a globally reserved seven-bit skb-mark window.
- `query_sa` returns replay/lifetime/statistics and the exact generic/combined
  output mark, but never key material.
- The `ikev2` feature maps validated Child SA intent to XFRM requests; it does
  not run IKE, allocate SPIs, enable ENCR_NULL in an allowlist, or choose
  product policy. Caller-owned NAT detection and port selection may be passed
  as validated directional initial ESP-in-UDP options.
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
# Requires named-netns support, iproute2, ping, tcpdump with EN10MB capture,
# Linux XFRM, and effective CAP_NET_ADMIN/CAP_NET_RAW. The in-memory capture
# proves the first emitted ESP SPI/sequence and is neither logged nor saved.
sudo OPC_XFRM_RUN_NAMESPACE_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_namespace_bound_privileged -- --ignored --nocapture
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_dscp_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_RELOCATION_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --test xfrm_relocation_privileged -- --ignored --nocapture'
sudo unshare -n -- bash -lc 'ip link set lo up && OPC_XFRM_RUN_AUTH_ONLY_PRIVILEGED=1 cargo test -p opc-ipsec-xfrm --features ikev2 --test xfrm_auth_only_privileged -- --ignored --nocapture'
```
