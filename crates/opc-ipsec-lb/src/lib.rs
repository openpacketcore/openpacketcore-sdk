//! Pure IPsec/IKE SWu load-balancing primitives for OpenPacketCore.
//!
//! This crate owns the reusable, kernel-independent contract for steering SWu
//! traffic by IKE/ESP SPI without ever handling IPsec key material. Product
//! crates compose these primitives with XDP/NIC backends and live failover
//! evidence; this crate keeps kernel-independent conformance deterministic and
//! CI-provable.
//!
//! Routed multi-ingress deployments can use [`SessionOwnershipKey`] to bind
//! every IKE/ESP lookup to its public destination and routing domain, then use
//! [`RendezvousSelector::select_owner`] with an explicit membership generation.
//! Initial-IKE promotion carries the selected owner forward without rehashing.
//! These identities contain packet metadata only and never SA key material.
//! [`classify_keyless_ingress_packet`] extracts those identities from bounded,
//! borrowed IPv4/IPv6 headers, including native ESP, NAT-T, IKEv2 SKF, and
//! supported ICMP error quotes. It does not accept keys or decrypt payloads.
//!
//! VIP advertisement is protocol-neutral: callers can gate any management or
//! dataplane VIP on their own election, quorum, health, and monotonic fence
//! evidence without coupling that signal to IPsec SA ownership.
//! Routed ingress deployments can use [`PrefixAdvertiserService`] to carry
//! bounded exact-host-prefix intent to an established routing stack. The
//! production [`BirdControlSocketAdapter`] owns a foreground BIRD process
//! through a fail-closed Linux lifecycle boundary, while BGP/BFD policy and
//! application-health admission remain product responsibilities.
//!
//! Same-SPI re-pin keeps counter-based ESP/IKE AEAD evidence distinct from IKE
//! encrypt-then-MAC suites that generate a fresh independent CSPRNG IV for each
//! protected message. Random-IV evidence is valid only for IKE and never
//! carries placeholder counter fields; ownership fencing, key custody, SA
//! identity, and inbound anti-replay evidence remain mandatory in both modes.
//! [`SessionRePinCoordinator`] composes those exact single-SA transitions into
//! one bounded durable IKE/default-ESP/dedicated-ESP saga. It converges forward
//! after partial monotonic commits and returns whole-session success only after
//! every ordered SA has durably completed fencing and steering. The session
//! journal neither proves that caller-declared counters were applied nor
//! changes the existing encrypted session-payload/HKMS boundary. After
//! product-owned teardown, an exact terminal identity can be retired to a
//! fenced encrypted tombstone that blocks stale recreation for the fixed
//! seven-day bounded retry horizon.

#![forbid(unsafe_code)]

pub mod bgp;
pub mod classifier;
pub mod cookie;
pub mod error;
pub mod external_lb;
pub mod failover;
pub mod mock;
pub mod model;
pub mod offload;
pub mod ownership;
pub mod ports;
pub mod redirect;
pub mod repin;
pub mod routing;
pub mod selector;
pub mod session;
pub mod session_repin;
pub mod spi;
pub mod unsupported;
pub mod vip;
pub mod xdp;

pub use bgp::{BgpRouteVipAdvertiser, BgpRouteVipAdvertiserConfig};
pub use classifier::{
    classify_keyless_ingress_packet, classify_swu_packet, EspFragmentPosture,
    IngressEncapsulationKind, IngressIdentityProvenance, IngressPacketIdentity,
    IngressUnclassifiableReason, IpFragment, KeylessIngressClassification, KeylessIngressMatch,
    ObservedOuterSource, QuotedEspIdentity, SwuClassification, SwuClassifierConfig, SwuPacket,
    MAX_INGRESS_IPV6_EXTENSION_HEADERS,
};
pub use cookie::{
    CookieKey, CookieSlot, IkeCookie, IkeCookieDecision, IkeCookieGate, IkeCookiePolicy,
    IkeCookieRequest,
};
pub use error::IpsecLbError;
pub use external_lb::ExternalLbVipAdvertiser;
pub use failover::{
    AntiReplayResume, IvResumeDecision, SendIvCounter, SendIvCounterMode, SendIvForwardJump,
    MAX_ESP_SEND_IV_FORWARD_JUMP, MIN_SEND_IV_FORWARD_JUMP,
};
pub use mock::{
    MockOwnershipFencer, MockOwnershipSource, MockRePinAuditSink, MockSteeringBackend,
    MockSteeringOperation, MockVipAdvertiser, MockVipOperation,
};
pub use model::{
    ClusterNode, IpAddress, SaId, ShardId, SteerAction, SteerKey, SteeringBackendKind,
    SteeringProbe, SteeringRule, VipAdvertisement, VipAdvertiserKind, VipProbe,
};
pub use offload::NicOffloadSecurityPosture;
pub use ownership::{
    DestinationContext, EligibleOwnershipMembers, EspEncapsulationKind, EspOwnershipKey, EspSpi,
    EstablishedIkeOwnershipKey, IkeSpi, InitialExchangeDiscriminator, InitialIkeOwnershipKey,
    MembershipGeneration, OuterSourceTuple, OwnerSelection, OwnershipCollision, OwnershipKeyError,
    OwnershipKeyKind, OwnershipKeyPromotion, OwnershipSelectionError, RoutingDomainTag,
    SessionOwnershipKey, MAX_ELIGIBLE_OWNERS, OWNERSHIP_KEY_ENCODING_VERSION,
    OWNERSHIP_KEY_MAX_ENCODED_BYTES,
};
pub use ports::{
    OwnershipFencer, OwnershipSource, RePinAuditSink, SpiAllocator, SteeringBackend, VipAdvertiser,
};
pub use redirect::{
    establish_ingress_redirect_client, establish_ingress_redirect_server,
    ingress_redirect_client_tls_config, ingress_redirect_server_tls_config,
    reconcile_ingress_redirect_client, reconcile_ingress_redirect_server,
    rotate_ingress_redirect_client, rotate_ingress_redirect_server, DeliveredIngressRedirectPacket,
    ForwardableIngressRedirectPacket, InMemoryIngressRedirectDatagram,
    IngressRedirectAeadUsageStatus, IngressRedirectAuthenticationStatus,
    IngressRedirectConfigError, IngressRedirectDatagram, IngressRedirectDatagramError,
    IngressRedirectDeliveryReceiver, IngressRedirectEndpoint,
    IngressRedirectEndpointMetricsSnapshot, IngressRedirectError, IngressRedirectInboundOutcome,
    IngressRedirectMetricsSnapshot, IngressRedirectMtuBudget, IngressRedirectNotSentReason,
    IngressRedirectOperation, IngressRedirectOperationOutcome, IngressRedirectPacketTooBigEvent,
    IngressRedirectPacketTooBigReportError, IngressRedirectPacketTooBigReporter,
    IngressRedirectPeerExpectation, IngressRedirectPeerManifest, IngressRedirectPeerSession,
    IngressRedirectProfile, IngressRedirectProtectionEpoch, IngressRedirectReceiptCode,
    IngressRedirectRotationStatus, IngressRedirectSecurityMode, RejectedIngressRedirectPacket,
    UdpIngressRedirectDatagram, DEFAULT_INGRESS_REDIRECT_SECURITY_MODE,
    INGRESS_REDIRECT_CONTROL_ALPN,
};
pub use repin::{
    ForwardingProof, IkeRandomIvAttestation, OwnershipFence, OwnershipFenceGrant,
    OwnershipFenceRequest, OwnershipRetryProof, OwnershipSnapshot, OwnershipTransitionFingerprint,
    OwnershipTransitionId, RePinAuditEvent, RePinAuditEventKind, RePinCoordinator, RePinError,
    RePinOutcome, RePinPartialFailure, RePinRequest, RePinRetryStage, ResumeKeySource,
    SameSpiOutboundIvResume, SameSpiResume,
};
pub use routing::{
    AdvertisedPrefix, AdvertisementLease, AdvertisementSetApplyResult, AdvertisementSetDisposition,
    ApplyGate, BirdAdapterConfig, BirdControlSocketAdapter, BirdDomainBinding, BirdProcessConfig,
    ConformanceFakeRoutingStack, FakeApplyFailure, HostPrefix, LeaseGeneration, ObservationGate,
    PathHealth, PeerIdentity, PeerObservation, PeerSessionChangeReason, PeerSessionState,
    PrefixAdvertisementState, PrefixAdvertiserConfig, PrefixAdvertiserService, PrefixApplyOutcome,
    PrefixReconcileReport, PrefixRejectReason, PrefixStatusSnapshot, PrefixWithdrawReason,
    ReconcileDisposition, RecordedAdvertisementApply, RecordedStackMutation, RoutingEvent,
    RoutingEventKind, RoutingProcessSupervision, RoutingStackAdapter, RoutingStackKind,
    RoutingStackProbe, WithdrawGate, MAX_ADVERTISED_PREFIXES_PER_DOMAIN,
    MAX_ADVERTISEMENT_ROUTING_DOMAINS, MAX_ROUTING_MUTATION_DURATION, MAX_ROUTING_PEERS_PER_DOMAIN,
    MAX_ROUTING_PEERS_TOTAL, MAX_ROUTING_PEER_NAME_LEN,
};
pub use selector::{
    measure_disruption, RendezvousSelector, SelectionKey, ShardDisruption, ShardSet,
};
pub use session::{
    SessionOwnershipKeyResolver, SessionOwnershipKeyspace, SessionStoreOwnershipFencer,
    SessionStoreOwnershipSource,
};
pub use session_repin::{
    MockSessionRePinJournal, SessionRePinCheckpoint, SessionRePinCoordinator, SessionRePinError,
    SessionRePinIdentity, SessionRePinJournal, SessionRePinOperationId, SessionRePinOutcome,
    SessionRePinPhase, SessionRePinPlan, SessionRePinPlanFingerprint,
    SessionRePinRetirementDisposition, SessionRePinRetirementOutcome, SessionRePinSessionId,
    SessionRePinStatus, SessionStoreRePinJournal, MAX_SESSION_REPIN_SAS, MIN_SESSION_REPIN_SAS,
    SESSION_REPIN_JOURNAL_MAX_BYTES, SESSION_REPIN_RETIREMENT_RETENTION,
};
pub use spi::{
    EntropySource, FixedEntropy, RekeyRequest, SpiAllocationRequest, SpiKind, SystemEntropy,
    TaggedSpi, TaggedSpiAllocator, TaggedSpiLayout,
};
pub use unsupported::{
    UnsupportedOwnershipSource, UnsupportedSteeringBackend, UnsupportedVipAdvertiser,
};
pub use vip::{LeadershipFence, VipOwnershipCoordinator, VipOwnershipIntent, VipOwnershipState};
pub use xdp::{
    HostXdpAttachMode, HostXdpRedirectHandoff, HostXdpSteeringBackend,
    HostXdpSteeringBackendConfig, XdpVerdictCounters,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn primitives_are_key_material_free_by_type_shape() {
        let probe = SteeringProbe::mock();
        assert!(probe.key_material_free);
        assert!(!format!("{:?}", SteerKey::EspSpi(0x1234_5678)).contains("key"));

        let coordinator = VipOwnershipCoordinator::new(
            VipAdvertisement {
                vip: IpAddress::V4([192, 0, 2, 40]),
                node: ClusterNode::new("control-a"),
            },
            ExternalLbVipAdvertiser::new(),
        );
        assert!(!format!("{coordinator:?}")
            .to_ascii_lowercase()
            .contains("key"));
    }
}
