//! Safe Linux XFRM IPsec backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for XFRM SA/policy lifecycle operations,
//! a deterministic mock backend for tests, an unsupported-platform backend, and
//! redaction-safe error types. SA parameters can carry an independent Linux
//! lookup mark and a masked post-transform output mark; the latter is applied
//! to inbound/decrypt SAs as well as outbound SAs. With the `ikev2` feature,
//! `Ikev2ChildSaXfrmOptions` carries caller-validated directional initial
//! ESP-in-UDP templates through the typed Child-SA mapper; NAT detection and
//! translated-port selection remain caller-owned. An exact single-SA
//! relocation primitive uses the current-upstream Linux
//! `XFRM_MSG_MIGRATE_STATE` UAPI after validating a query-proven current-state
//! snapshot. It relocates SA state only: callers own authenticated endpoint
//! signalling, policy-template coordination, and namespace-wide writer
//! serialization. Outgoing relocation requires the upstream temporary-block
//! policy sequence, made explicit by [`SaRelocationDirection`], to prevent
//! cleartext fallback and AES-GCM IV reuse; incoming relocation does not. The
//! relocation future is not cancellation-safe once polled: callers must keep
//! safety fences in place and perform exact old/new tuple reconciliation before
//! retrying or releasing writer exclusion after cancellation or process loss.
//! The crate never infers relocation from packet source addresses and deliberately
//! does not implement IKE, ESP processing, namespace creation/switching, or
//! deployment policy. [`LinuxXfrmBackend::bind_current_network_namespace`]
//! can pin backend execution to the calling thread's already-selected network
//! namespace without exposing its filesystem identity.
//! Fixed-DSCP users that must recover durable state before opening external
//! egress authority can use [`LinuxXfrmBackend::with_deferred_dscp_marking`].
//! That constructor validates and retains configuration without loading,
//! pinning, attaching, adopting, or changing tc/eBPF state; namespace binding,
//! including atomic durable-store binding, preserves the same effect-free
//! boundary. [`NamespaceBoundLinuxXfrmBackend::activate_dscp_marking`] later
//! performs activation on that exact actor. Until success is deliverable,
//! every DSCP-bearing SA mutation fails closed while durable recovery and
//! unmarked operations remain available. A clean deferred rejection of a
//! prepared durable SA returns its exact authority through
//! [`XfrmObjectInstallRunError::into_retry_authority`].
//!
//! [`XfrmStagedInstall::run_and_commit_outbound_sa_policy`] issues an opaque,
//! key-free [`InstalledOutboundSaBinding`] only after an exact ESP SA plus sole
//! outbound allow-policy is acknowledged and committed. After process loss,
//! [`NamespaceBoundLinuxXfrmBackend::recover_installed_outbound_sa_binding`]
//! reissues that authority only after actor-local `GETPOLICY` and `GETSA`
//! validation. [`OutboundSaBindingId`] is safe to persist for correlation but
//! is never authority. Kernel key bytes stay in zeroizing readback buffers and
//! are compared in constant time with transient caller-supplied key material;
//! neither the live binding nor its ID retains keys or key-derived hashes.
//! Kernel-lockdown GETSA key redaction and intentionally all-zero key material
//! are indistinguishable, so both fail closed before fresh mint or recovery
//! with `xfrm_outbound_sa_binding_key_readback_unavailable`; algorithm shape is
//! never accepted as a substitute for exact key proof.
//! Before Linux SA encoding copies any key byte, the backend validates every
//! variable attribute and computes the complete checked UAPI body length. The
//! algorithm temporaries, fixed-capacity SA body, and complete netlink request
//! are zeroizing buffers, so no secret-bearing destination allocation grows
//! during encoding. This guarantee covers the transient userspace UAPI copy;
//! kernel key custody remains platform-owned.
//!
//! For single-object work whose consumer bookkeeping must survive process
//! loss, `LinuxXfrmBackend::bind_current_network_namespace_with_object_recovery`
//! authenticates and permanently leases one `XfrmObjectInstallRecoveryStore`
//! on the namespace actor before returning any mutation-capable backend handle.
//! `NamespaceBoundLinuxXfrmBackend::prepare_durable_object_install` persists
//! authenticated `Prepared` truth and returns an affine, process-local
//! [`XfrmObjectInstallAdmissionAuthority`] before any effect is admitted. The
//! consumer first durably records poll admission, then
//! `NamespaceBoundLinuxXfrmBackend::run_durable_object_install` consumes that
//! exact actor-, store-, correlation-, generation-, and request-bound authority
//! and persists `Issuing` before any possible backend mutation. Immediately
//! beforehand, the actor witnesses the exact deletion identity and stores that
//! presence as a durable pre-effect proof in the same record. An absence proof
//! permits effect admission; a conflict proof admits no effect. The
//! consumer finalizes only after its adoption decision is durable; otherwise
//! restart recovery treats `Prepared` as authoritative no-mutation, removes
//! residue solely from authenticated, epoch-current acquisition authority, and
//! reconciles `Issuing`/`Indeterminate` records from their pre-effect proof
//! plus a fresh exact readback. Linux has no conditional SA/policy delete, so
//! an unresolved `Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted`
//! record blocks every later cooperating actor mutation. Deployments must
//! exclude all raw or independently stored XFRM writers in that namespace and
//! keep the proof key in durable secret configuration. Store records retain
//! independent keyed fingerprints of the deletion identity and complete install
//! request, but no request identity values or key material; public diagnostics
//! remain value-free. The leased root is trusted authoritative non-rollback
//! storage under the documented POSIX crash model. A deployment whose storage
//! can restore an older complete authenticated snapshot needs an external
//! monotonic witness.
//!
//! Exact SA relocation receives the same durable, crash-recoverable boundary
//! through a separate self-contained store family.
//! `LinuxXfrmBackend::bind_current_network_namespace_with_sa_relocation_recovery`
//! (or the combined object-and-relocation constructor) authenticates and
//! permanently leases one `XfrmSaRelocationRecoveryStore` on the same
//! namespace actor before any mutation-capable handle is returned.
//! `NamespaceBoundLinuxXfrmBackend::prepare_sa_relocation` persists
//! authenticated `Prepared` truth and returns an affine
//! [`XfrmSaRelocationAdmissionAuthority`];
//! `NamespaceBoundLinuxXfrmBackend::run_durable_sa_relocation` witnesses the
//! old and target identities as a durable pre-effect proof, persists
//! `Issuing`, and only then admits the single `relocate_sa` effect,
//! publishing `Relocated`, `NoMutation`, or `Indeterminate` before returning.
//! There is no finalize/adoption call: a terminal `Relocated` record is the
//! durable proof that the consumer continues on the new addresses. After
//! process loss, `NamespaceBoundLinuxXfrmBackend::recover_durable_sa_relocation`
//! classifies unresolved records from their proof plus fresh exact readbacks
//! and deletes only a proved owned residue through the exact target deletion
//! identity; prepared records retire as authoritative no-mutation, terminal
//! proof is returned idempotently, and unreadable, stale-epoch, or
//! inconsistent records stay fail-closed. Every unresolved relocation phase,
//! including `Prepared`, gates all later cooperating mutations in the
//! namespace, and the install and relocation stores gate each other. Relocation
//! records use an independent format with no compatibility path, migration
//! bridge, or unconditional-delete escape hatch; their diagnostics remain
//! value-free like the install boundary.
//!
//! A dependency-ordered group of XFRM objects receives that same durable
//! boundary as one transaction through a third self-contained store family.
//! `LinuxXfrmBackend::bind_current_network_namespace_with_object_roster_recovery`
//! is the recommended constructor;
//! `bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery`
//! binds all three families while a deployment still migrates. Either
//! authenticates and permanently leases one `XfrmObjectRosterRecoveryStore` on
//! the namespace actor before any mutation-capable handle is returned.
//! `NamespaceBoundLinuxXfrmBackend::prepare_durable_object_roster` binds the
//! complete ordered roster into one authenticated `Prepared` record before any
//! effect: the group identity, every member's durable identity and generation,
//! every exact install request, and one ordered keyed digest over all of them.
//! It returns an affine [`XfrmObjectRosterAdmissionAuthority`], and
//! `NamespaceBoundLinuxXfrmBackend::run_durable_object_roster` consumes that
//! authority in a single actor command that applies the members in the
//! caller-declared order, publishing each member's exact absence proof before
//! that member's own effect and burning the roster's one writer epoch at
//! `Prepared` to `Issuing`. The group is all-or-nothing: a pre-existing object
//! at any member identity is authoritative no-mutation with zero effects, and a
//! divergence after at least one acquisition reverse-compensates exactly the
//! acquired prefix and terminates as `RolledBack`. Roster records retain only
//! opaque group and member correlation, phases, proof codes, incarnations, the
//! epoch, and independent proof-keyed fingerprints of each member's exact
//! deletion identity and complete install request; no request identity value or
//! key material is persisted or rendered. After process loss the consumer calls
//! exactly one of
//! `NamespaceBoundLinuxXfrmBackend::adopt_durable_object_roster`, which commits
//! a converged `Applied` roster additively without deleting anything, or
//! `NamespaceBoundLinuxXfrmBackend::recover_durable_object_roster`, which
//! retires it as owned residue. That call must come before any other namespace
//! mutation: an intervening ordinary mutation burns the writer epoch every
//! absence proof depends on and leaves the record retained for product repair.
//! Every unresolved roster phase gates all later cooperating mutations in the
//! namespace and both other durable families, and an unresolved install or
//! relocation record gates rosters. Every one of those gates is screened before
//! the run consumes anything, so a blocked run returns its exact affine
//! authority through `XfrmObjectRosterRunError::into_retry_authority` and
//! succeeds later unchanged. Missing, malformed, duplicated, reordered,
//! substituted, stale-epoch, wrong-namespace, and wrong-incarnation roster
//! state fails closed, and handles, outcomes, errors, and diagnostics stay
//! value-free. The leased root carries the same trusted, non-rollback storage
//! obligation as the install boundary; because records hold fingerprints rather
//! than values, adopting or recovering a roster requires the consumer to have
//! durably retained every member request, including its key material. A
//! finalized roster retains one terminal idempotence record but no unresolved
//! cleanup authority; the next cooperating prepare or epoch advance prunes it
//! deterministically. Automatic roster recovery of an `Absent` witness followed
//! by a present object is valid only while the deployment excludes raw or
//! independently stored XFRM writers from the namespace. The SDK epoch orders
//! cooperating actor writes only, not that external fence: otherwise identical
//! ownership is observationally ambiguous and Linux deletion is unconditional.
//!
//! Same-SPI successor activation uses
//! [`NamespaceBoundLinuxXfrmBackend::apply_and_read_back_outbound_esp_counter`].
//! The sealed actor validates the opaque outbound binding, reads the kernel's
//! last-assigned sequence, advances only through Linux `XFRM_MSG_NEWAE`, and
//! performs exact post-readback before issuing an opaque, bounded receipt. It
//! never rolls an already-advanced SA backward. The successor must remain
//! quiescent and unpublished until the receipt crosses its required proof
//! boundary. Proof validation additionally requires an opaque process-local
//! target derived from the intended live binding, so an otherwise identical
//! receipt from another actor or network namespace cannot satisfy the
//! boundary. A separate read-only committed-recovery API can rebuild evidence
//! after process loss. That evidence cannot authorize a new ownership fence;
//! resuming publication also requires independent proof that the exact fence
//! was already committed before process loss.
//!
//! Raw Linux netlink work stays in [`opc_linux_xfrm_sys`]; this crate is safe
//! Rust and never performs `unsafe` operations.
//!
//! `LinuxEspPeerObservationMonitor` exposes the complementary observation
//! authority for NAT rebinding: bounded, typed observations when an
//! established inbound ESP-in-UDP SA starts arriving from a new outer source,
//! keyed by exact SA identity and direction. An observation is only as strong
//! as its trust anchor. Stock Linux `XFRM_MSG_MAPPING` fires after integrity
//! verification but before the final replay decision and has no loss signal,
//! so it cannot satisfy that contract. The production monitor instead owns a
//! committed CO-RE source attached to the final replay-decision and XFRM
//! lifecycle hooks. It admits only an exact GETSA-proven, replay-enabled,
//! integrity/AEAD-protected, non-offloaded inbound ESP-in-UDP SA, binds scope
//! to the network namespace, accounts producer loss, and fails closed on
//! lifecycle or link-authority loss. Registration, authenticated rebaseline,
//! and teardown use staged, quiescent transactions so cancellation cannot
//! silently publish an unverified baseline. Observations retain only minimum
//! routing facts, are bounded per SA with explicit fail-closed overflow,
//! terminate exactly at teardown, and are value-free in diagnostics.

#![forbid(unsafe_code)]

pub mod backend;
pub mod composite;
mod counter_resume;
mod dscp;
#[cfg(unix)]
mod durable_install;
#[cfg(unix)]
mod durable_object;
#[cfg(unix)]
mod durable_relocation;
#[cfg(unix)]
mod durable_relocation_flow;
#[cfg(unix)]
mod durable_roster;
#[cfg(unix)]
mod durable_roster_flow;
pub mod error;
#[cfg(feature = "ikev2")]
pub mod ikev2;
pub mod linux;
pub mod mock;
pub mod model;
mod namespace;
mod observation;
mod outbound_binding;
pub mod staged;
pub mod staged_object;
pub mod unsupported;

pub use backend::XfrmBackend;
pub use composite::{
    install_bidirectional_sa_policy_with_rollback, install_sa_policy_with_rollback,
    rekey_sa_policy, remove_policy_sa, XfrmBidirectionalInstallError,
    XfrmBidirectionalInstallOutcome, XfrmCompositeInstallError, XfrmCompositeInstallRequest,
    XfrmCompositeOperation, XfrmCompositeOutcome, XFRM_COMPOSITE_INSTALL_ORDER,
    XFRM_COMPOSITE_INSTALL_ROLLBACK_ORDER, XFRM_COMPOSITE_REKEY_ORDER, XFRM_COMPOSITE_REMOVE_ORDER,
};
pub use counter_resume::{
    AppliedEspCounterReceipt, EspCounterProofRequirement, EspCounterPublicationGuard,
    EspCounterResumeApplyRequest, EspCounterResumeBinding, EspCounterResumeError,
    EspCounterResumeProofSet, EspCounterResumeRecoveryRequest, OutboundEspCounterTarget,
    OutboundEspCounterTargetSet, ESP_COUNTER_RECEIPT_MAX_AGE, MAX_ESP_COUNTER_PROOF_SET_SIZE,
    MAX_ESP_COUNTER_RECEIPTS, MAX_ESP_COUNTER_TARGET_SET_SIZE,
};
pub use dscp::{
    LinuxXfrmDscpMarkingConfig, DEFAULT_XFRM_DSCP_BPFFS_PIN_ROOT, DEFAULT_XFRM_DSCP_TC_PRIORITY,
};
#[cfg(unix)]
pub use durable_install::{XfrmObjectInstallDurableOutcome, XfrmObjectInstallRestartOutcome};
#[cfg(unix)]
pub use durable_object::{
    XfrmObjectInstallDurableError, XfrmObjectInstallDurablePhase,
    XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
    XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey,
    XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES,
};
#[cfg(unix)]
pub use durable_relocation::{
    XfrmSaRelocationDurableError, XfrmSaRelocationDurablePhase,
    XfrmSaRelocationOperationGeneration, XfrmSaRelocationOperationId,
    XfrmSaRelocationRecoveryHandle, XfrmSaRelocationRecoveryProofKey,
    XfrmSaRelocationRecoveryStore, XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES,
};
#[cfg(unix)]
pub use durable_relocation_flow::{XfrmSaRelocationDurableOutcome, XfrmSaRelocationRestartOutcome};
#[cfg(unix)]
pub use durable_roster::{
    XfrmObjectRosterAdjacentProof, XfrmObjectRosterDurableError, XfrmObjectRosterDurablePhase,
    XfrmObjectRosterGroupId, XfrmObjectRosterMemberPhase, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRecoveryProofKey,
    XfrmObjectRosterRecoveryStore, XfrmObjectRosterSweepProof, XFRM_OBJECT_ROSTER_MAX_MEMBERS,
    XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
};
#[cfg(unix)]
pub use durable_roster_flow::{
    XfrmObjectRosterDurableOutcome, XfrmObjectRosterMemberDisposition,
    XfrmObjectRosterMemberDispositions, XfrmObjectRosterMemberRequest, XfrmObjectRosterRequest,
    XfrmObjectRosterRequestError, XfrmObjectRosterRestartOutcome,
};
pub use error::XfrmError;
#[cfg(feature = "ikev2")]
pub use ikev2::{
    build_xfrm_requests_from_ikev2_child_sa, build_xfrm_requests_from_ikev2_child_sa_with_options,
    build_xfrm_requests_from_ikev2_child_sa_with_request_id, derive_child_sa_xfrm_keys,
    derive_initial_child_sa_xfrm_keys, Ikev2ChildSaDirectionalXfrmKeys,
    Ikev2ChildSaInvalidNonceDiagnostic, Ikev2ChildSaKeyMaterialDiagnostic,
    Ikev2ChildSaKeyMaterialError, Ikev2ChildSaNonceRole, Ikev2ChildSaXfrmError,
    Ikev2ChildSaXfrmKeys, Ikev2ChildSaXfrmOptions, Ikev2ChildSaXfrmOptionsError,
    Ikev2ChildSaXfrmRequest, Ikev2ChildSaXfrmRequests, IKEV2_SECURITY_PROTOCOL_ID_ESP, IPPROTO_ESP,
};
pub use linux::{LinuxXfrmBackend, LinuxXfrmBackendConfig};
pub use mock::{MockOperation, MockSaRelocation, MockXfrmBackend};
pub use model::{
    AeadAlgorithm, Algorithm, AllocateSpiRequest, AuthAlgorithm, ExactRemovePolicyRequest,
    InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    LifetimeCurrent, PolicyParameters, QueryPolicyRequest, QuerySaRequest, RekeyPolicyRequest,
    RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest, SaParameters,
    SaRelocationDirection, SaRelocationEncap, SaRelocationIdentity, SaRelocationSelector,
    SaReplayState, SaState, SaStatistics, SpiAllocation, UdpEncap, UdpEncapError, XfrmAction,
    XfrmBackendKind, XfrmCapability, XfrmDirection, XfrmId, XfrmLookupMark, XfrmLookupMarkError,
    XfrmMark, XfrmMode, XfrmProbe, XfrmRequestId, XfrmSelector, XfrmTemplate, UDP_ENCAP_ESPINUDP,
    XFRM_AEAD_RFC4106_GCM_AES, XFRM_AUTH_HMAC_SHA1, XFRM_AUTH_HMAC_SHA256, XFRM_AUTH_HMAC_SHA384,
    XFRM_AUTH_HMAC_SHA512, XFRM_ENCR_CBC_AES, XFRM_ENCR_NULL,
};
pub use namespace::{NamespaceBoundLinuxXfrmBackend, LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY};
#[cfg(unix)]
pub use namespace::{
    XfrmObjectInstallAdmissionAuthority, XfrmObjectInstallRunError, XfrmObjectRecoveryBindError,
    XfrmObjectRosterAdmissionAuthority, XfrmObjectRosterEffectQuiesced, XfrmObjectRosterRunError,
    XfrmSaRelocationAdmissionAuthority, XfrmSaRelocationRunError,
};
pub use observation::{
    EspPeerAddressFamily, EspPeerIngestTally, EspPeerObservation, EspPeerObservationEpoch,
    EspPeerObservationKey, EspPeerObservationLoss, EspPeerObservationRejection,
    EspPeerObservationSourceTerminal, EspPeerObservationTeardown,
    DEFAULT_ESP_PEER_OBSERVATION_CAPACITY,
};
#[cfg(target_os = "linux")]
pub use observation::{
    LinuxEspPeerObservationConfig, LinuxEspPeerObservationHandle, LinuxEspPeerObservationMonitor,
};
pub use opc_types::DscpCodepoint;
pub use outbound_binding::{
    InstalledOutboundSaBinding, OutboundSaBindingError, OutboundSaBindingId,
};
pub use staged::{
    XfrmIndeterminateOperations, XfrmInstallCommitError, XfrmInstallJournal, XfrmInstallObject,
    XfrmInstallOwnership, XfrmInstallRecoveryClassification, XfrmInstallRecoveryError,
    XfrmInstallRecoveryPlan, XfrmResidueClassification, XfrmStagedInstall,
    XfrmStagedInstallRunError,
};
pub use staged_object::{
    XfrmObjectInstallCommitError, XfrmObjectInstallJournal, XfrmObjectInstallOwnership,
    XfrmObjectInstallRecoveryClassification, XfrmObjectInstallRecoveryError,
    XfrmObjectInstallRecoveryPlan, XfrmObjectInstallRequest, XfrmObjectRemovalRequest,
    XfrmStagedObjectInstall, XfrmStagedObjectInstallRunError,
};
pub use unsupported::UnsupportedXfrmBackend;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::model::{
        Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
        LifetimeConfig, PolicyParameters, RekeyPolicyRequest, RekeySaRequest, RemovePolicyRequest,
        RemoveSaRequest, SaParameters, XfrmAction, XfrmBackendKind, XfrmDirection, XfrmId,
        XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
    };
    use crate::XfrmBackend;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn sample_selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50)
    }

    fn sample_sa_parameters() -> SaParameters {
        SaParameters {
            selector: sample_selector(),
            id: XfrmId {
                destination: ipv4(10, 0, 0, 2),
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: ipv4(10, 0, 0, 1),
            request_id: None,
            auth: Some((
                AuthAlgorithm::hmac_sha256(96),
                KeyMaterial::new(vec![0xab; 32]),
            )),
            crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 32]))),
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
        }
    }

    fn sample_policy_parameters() -> PolicyParameters {
        PolicyParameters {
            selector: sample_selector(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: XfrmId {
                    destination: ipv4(10, 0, 0, 2),
                    spi: 0x1234_5678,
                    protocol: 50,
                },
                source_address: ipv4(10, 0, 0, 1),
                request_id: None,
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: None,
        }
    }

    #[tokio::test]
    async fn mock_backend_lifecycle_round_trip() {
        let backend = MockXfrmBackend::new();

        let allocate = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: 0xffff_ffff,
        };
        let spi = backend.allocate_spi(allocate).await.unwrap();
        assert_eq!(spi.spi, 0x100);

        let params = sample_sa_parameters();
        backend
            .install_sa(InstallSaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        backend
            .rekey_sa(RekeySaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        backend
            .remove_sa(RemoveSaRequest {
                destination: params.id.destination,
                protocol: params.id.protocol,
                spi: params.id.spi,
                mark: params.mark,
            })
            .await
            .unwrap();

        let policy = sample_policy_parameters();
        backend
            .install_policy(InstallPolicyRequest {
                parameters: policy.clone(),
            })
            .await
            .unwrap();

        backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: policy.clone(),
            })
            .await
            .unwrap();

        backend
            .remove_policy(RemovePolicyRequest {
                selector: policy.selector.clone(),
                direction: policy.direction,
                mark: policy.mark,
            })
            .await
            .unwrap();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, XfrmBackendKind::Mock);
        assert!(probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);

        assert_eq!(backend.operations().len(), 8);
    }

    #[tokio::test]
    async fn sa_request_with_key_material_does_not_leak_in_error() {
        let backend = MockXfrmBackend::new();
        backend.set_failure(XfrmError::NotFound);
        let params = sample_sa_parameters();
        let err = backend
            .install_sa(InstallSaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap_err();
        let debug = format!("{err:?}");
        let display = err.to_string();
        assert!(
            !debug.contains("ab") && !debug.contains("cd"),
            "debug leaked key material: {debug}"
        );
        assert!(
            !display.contains("ab") && !display.contains("cd"),
            "display leaked key material: {display}"
        );
    }

    #[tokio::test]
    async fn unsupported_backend_is_trait_object_safe() {
        let backend: Box<dyn XfrmBackend> = Box::new(UnsupportedXfrmBackend::new());
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe, XfrmProbe::unsupported());
    }
}
