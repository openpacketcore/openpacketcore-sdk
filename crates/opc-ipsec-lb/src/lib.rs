//! Pure IPsec/IKE SWu load-balancing primitives for OpenPacketCore.
//!
//! This crate owns the reusable, kernel-independent contract for steering SWu
//! traffic by IKE/ESP SPI without ever handling IPsec key material. Product
//! crates compose these primitives with XDP/NIC backends and live failover
//! evidence; this crate keeps kernel-independent conformance deterministic and
//! CI-provable.
//!
//! VIP advertisement is protocol-neutral: callers can gate any management or
//! dataplane VIP on their own election, quorum, health, and monotonic fence
//! evidence without coupling that signal to IPsec SA ownership.

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
pub mod ports;
pub mod repin;
pub mod selector;
pub mod session;
pub mod spi;
pub mod unsupported;
pub mod vip;
pub mod xdp;

pub use bgp::{BgpRouteVipAdvertiser, BgpRouteVipAdvertiserConfig};
pub use classifier::{
    classify_swu_packet, EspFragmentPosture, IpFragment, SwuClassification, SwuClassifierConfig,
    SwuPacket,
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
pub use ports::{
    OwnershipFencer, OwnershipSource, RePinAuditSink, SpiAllocator, SteeringBackend, VipAdvertiser,
};
pub use repin::{
    ForwardingProof, OwnershipFence, OwnershipFenceGrant, OwnershipFenceRequest,
    OwnershipRetryProof, OwnershipSnapshot, OwnershipTransitionFingerprint, OwnershipTransitionId,
    RePinAuditEvent, RePinAuditEventKind, RePinCoordinator, RePinError, RePinOutcome,
    RePinPartialFailure, RePinRequest, RePinRetryStage, ResumeKeySource, SameSpiResume,
};
pub use selector::{
    measure_disruption, RendezvousSelector, SelectionKey, ShardDisruption, ShardSet,
};
pub use session::{
    SessionOwnershipKeyResolver, SessionOwnershipKeyspace, SessionStoreOwnershipFencer,
    SessionStoreOwnershipSource,
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
    HostXdpClusterChannelSecurity, HostXdpSteeringBackend, HostXdpSteeringBackendConfig,
    HostXdpTagTarget, HostXdpTarget,
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
