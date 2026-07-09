//! Pure IPsec/IKE SWu load-balancing primitives for OpenPacketCore.
//!
//! This crate owns the reusable, kernel-independent contract for steering SWu
//! traffic by IKE/ESP SPI without ever handling IPsec key material. Product
//! crates compose these primitives with XDP/NIC backends and live failover
//! evidence; this crate keeps kernel-independent conformance deterministic and
//! CI-provable.

#![forbid(unsafe_code)]

pub mod classifier;
pub mod cookie;
pub mod error;
pub mod failover;
pub mod mock;
pub mod model;
pub mod ports;
pub mod selector;
pub mod spi;
pub mod unsupported;

pub use classifier::{
    classify_swu_packet, EspFragmentPosture, IpFragment, SwuClassification, SwuClassifierConfig,
    SwuPacket,
};
pub use cookie::{CookieKey, CookieSlot, IkeCookie, IkeCookieGate};
pub use error::IpsecLbError;
pub use failover::{AntiReplayResume, IvResumeDecision, SendIvCounter};
pub use mock::{
    MockOwnershipSource, MockSteeringBackend, MockSteeringOperation, MockVipAdvertiser,
    MockVipOperation,
};
pub use model::{
    ClusterNode, IpAddress, SaId, ShardId, SteerAction, SteerKey, SteeringBackendKind,
    SteeringProbe, SteeringRule, VipAdvertisement, VipAdvertiserKind, VipProbe,
};
pub use ports::{OwnershipSource, SpiAllocator, SteeringBackend, VipAdvertiser};
pub use selector::{
    measure_disruption, RendezvousSelector, SelectionKey, ShardDisruption, ShardSet,
};
pub use spi::{
    EntropySource, FixedEntropy, RekeyRequest, SpiAllocationRequest, SpiKind, SystemEntropy,
    TaggedSpi, TaggedSpiAllocator, TaggedSpiLayout,
};
pub use unsupported::{
    UnsupportedOwnershipSource, UnsupportedSteeringBackend, UnsupportedVipAdvertiser,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn primitives_are_key_material_free_by_type_shape() {
        let probe = SteeringProbe::mock();
        assert!(probe.key_material_free);
        assert!(!format!("{:?}", SteerKey::EspSpi(0x1234_5678)).contains("key"));
    }
}
