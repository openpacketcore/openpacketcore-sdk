//! Peer TEID zero: TS 29.281 section 5.1 backward compatibility.
//!
//! These tests exercise the software/model boundary. Linux kernel-GTP and tc
//! forwarding are exercised separately by the privileged native suites.

use bytes::BytesMut;
use opc_gtpu_dataplane::n3::{N3Qfi, N3UplinkEncapsulation, ReceivedN3UplinkTnl};
use opc_gtpu_dataplane::{
    GtpPdpContext, GtpVersion, GtpuDataplaneBackend, GtpuSourcePortPolicy,
    GtpuUplinkSourcePortPolicy, MockGtpuDataplaneBackend, PdpContextLocalTeidSelector,
    PdpContextReadback, PdpContextSelector, PeerTeid, Teid,
};

fn peer_teid_zero_context() -> GtpPdpContext {
    GtpPdpContext {
        local_teid: Teid::new(0x1122_3344).expect("local TEID must be nonzero"),
        peer_teid: PeerTeid::ZERO,
        ms_address: "10.45.0.2".parse().expect("inner address"),
        peer_address: "192.0.2.10".parse().expect("peer address"),
        link_ifindex: 7,
        downlink_source_port_policy: GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        downlink_inner_mtu: None,
    }
}

/// The acceptance regression: install a PDP context whose peer TEID is the
/// TS 29.281 section 5.1 all-zero value, read it back, and prove the outgoing
/// G-PDU encoder stamps TEID zero.
#[tokio::test]
async fn installed_peer_teid_zero_encapsulates_with_teid_zero() {
    let backend = MockGtpuDataplaneBackend::new();
    let desired = peer_teid_zero_context();
    backend
        .install_pdp_context(desired.clone())
        .await
        .expect("peer TEID zero must install on a supporting backend");

    let selector = PdpContextSelector::LocalTeid(
        PdpContextLocalTeidSelector::from_context(&desired).expect("local selector"),
    );
    let PdpContextReadback::Present(installed) =
        backend.read_pdp_context(selector).await.expect("readback")
    else {
        panic!("installed context must read back");
    };
    assert_eq!(installed.peer_teid, PeerTeid::ZERO);
    assert!(installed.peer_teid.is_zero());

    let tunnel = ReceivedN3UplinkTnl::new(installed.peer_address, installed.peer_teid)
        .expect("zero peer TEID is admitted");
    let insertion = N3UplinkEncapsulation::new(tunnel, N3Qfi::new(9).expect("QFI"));
    let mut wire = BytesMut::new();
    insertion
        .encode_gpdu(&[0xde, 0xad], &mut wire, 64)
        .expect("encode");

    // GTP-U header: flags(1), type(1), length(2), TEID(4). The TEID field is
    // the four octets at offset 4 and must be all zeros.
    assert_eq!(&wire[4..8], &[0, 0, 0, 0]);
    assert_eq!(&wire[..4], &[0x34, 0xff, 0x00, 0x0a]);
    assert_eq!(insertion.tunnel().teid(), PeerTeid::ZERO);
}

/// A zero peer TEID is a property of the peer/outgoing direction only: the
/// local TEID type still refuses zero.
#[test]
fn peer_teid_zero_does_not_relax_local_teid() {
    assert_eq!(Teid::new(0), None);
    assert_eq!(PeerTeid::new(0), PeerTeid::ZERO);
    assert_ne!(PeerTeid::new(0), PeerTeid::new(1));
    assert_eq!(
        PeerTeid::from(Teid::new(0x1122_3344).expect("nonzero")),
        PeerTeid::new(0x1122_3344)
    );
    assert_eq!(
        GtpPdpContext {
            peer_teid: PeerTeid::ZERO,
            ..peer_teid_zero_context()
        }
        .peer_teid
        .get(),
        0
    );
}

#[test]
fn received_n3_uplink_tunnel_accepts_existing_nonzero_teid_callers() {
    let teid = Teid::new(0x1122_3344).expect("nonzero");
    let tunnel = ReceivedN3UplinkTnl::new("192.0.2.10".parse().unwrap(), teid)
        .expect("existing nonzero TEID callers remain source compatible");
    assert_eq!(tunnel.teid(), PeerTeid::from(teid));
}
