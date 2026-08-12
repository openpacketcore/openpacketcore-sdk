use opc_gtpu_dataplane::{
    GtpPdpContext, GtpVersion, GtpuCapability, GtpuDataplaneBackend, GtpuSessionDeviceId,
    GtpuSessionEntry, GtpuSessionGroup, GtpuSessionGroupId, GtpuSourcePortPolicy,
    GtpuTrafficProofAuthority, GtpuTrafficProofAuthorityStore, GtpuUplinkSourcePortPolicy,
    MockGtpuDataplaneBackend, Teid, TrafficContinuityPolicy, UnsupportedGtpuDataplaneBackend,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn authority() -> GtpuTrafficProofAuthority {
    let context = GtpPdpContext {
        local_teid: Teid::new(1).unwrap(),
        peer_teid: Teid::new(2).unwrap(),
        ms_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        link_ifindex: 7,
        downlink_source_port_policy: GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
    };
    let group = GtpuSessionGroup::new(
        GtpuSessionGroupId::new([1; 16]).unwrap(),
        GtpuSessionDeviceId::new([2; 16]).unwrap(),
        vec![GtpuSessionEntry::new(context, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))).unwrap()],
    )
    .unwrap();
    let policy = TrafficContinuityPolicy::new(
        2,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(1),
        4,
    )
    .unwrap();
    GtpuTrafficProofAuthority::new(group, 1, 1, 1, policy).unwrap()
}

#[test]
fn red_structural_and_mock_backends_cannot_claim_production_traffic_proof() {
    let mock = MockGtpuDataplaneBackend::new();
    let unsupported = UnsupportedGtpuDataplaneBackend::new();

    assert_eq!(
        mock.gtpu_traffic_proof_capability(),
        GtpuCapability::Missing
    );
    assert_eq!(
        unsupported.gtpu_traffic_proof_capability(),
        GtpuCapability::Missing
    );
}

#[tokio::test]
async fn mock_and_unsupported_backends_cannot_mint_a_proof() {
    let mock = MockGtpuDataplaneBackend::new();
    let unsupported = UnsupportedGtpuDataplaneBackend::new();

    let mock_store = GtpuTrafficProofAuthorityStore::new(authority());
    assert!(mock
        .begin_gtpu_traffic_proof(mock_store.lease().await)
        .await
        .is_err());
    let unsupported_store = GtpuTrafficProofAuthorityStore::new(authority());
    assert!(unsupported
        .begin_gtpu_traffic_proof(unsupported_store.lease().await)
        .await
        .is_err());
}
