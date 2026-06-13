//! End-to-end PFCP exchange test between the reference SMF and a fake UPF.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use opc_proto_pfcp::ie::{CauseValue, TypedIe};
use opc_proto_pfcp::{Header, InformationElement, MessageType, OwnedMessage};
use opc_protocol::{DecodeContext, Encode, EncodeContext, OwnedDecode};
use smf_reference::{
    build_create_far, build_create_pdr, build_create_qer, build_remove_pdr,
    build_session_report_request, build_update_far, Smf, SmfConfig,
};
use tokio::net::UdpSocket;

fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

fn decode_typed_ie(ie_type: u16, value: &[u8]) -> TypedIe {
    let mut buf = BytesMut::new();
    buf.put_u16(ie_type);
    buf.put_u16(value.len() as u16);
    buf.put_slice(value);
    let (_, typed) = TypedIe::decode(&buf, DecodeContext::default(), 0).expect("decode typed ie");
    typed
}

fn encode_typed_ie(typed: TypedIe) -> InformationElement {
    InformationElement::from_typed(&typed).expect("typed ie encodes to raw ie")
}

const SMF_N4: &str = "127.0.0.1:18805";
const FAKE_UPF: &str = "127.0.0.1:18806";

fn test_config(n4: &str, instance: &str) -> SmfConfig {
    SmfConfig {
        n4_addr: n4.parse().expect("valid address"),
        upf_addr: FAKE_UPF.parse().expect("valid address"),
        nrf_uri: "http://127.0.0.1:18800".to_string(),
        plmn: opc_types::PlmnId::new("001", "01").expect("valid plmn"),
        s_nssai: opc_types::Snssai::with_sd(1, "010203").expect("valid snssai"),
        instance_id: opc_types::NfInstanceId::new(instance).expect("valid instance id"),
    }
}

async fn wait_for_udp(addr: &str) -> UdpSocket {
    let socket = UdpSocket::bind(addr).await.expect("bind fake upf");
    // Wait for the SMF to bind before sending.
    tokio::time::sleep(Duration::from_millis(100)).await;
    socket
}

fn encode_message(msg: &OwnedMessage) -> Bytes {
    let mut buf = BytesMut::new();
    msg.encode(&mut buf, EncodeContext::default())
        .expect("encode");
    buf.freeze()
}

async fn send_recv(
    socket: &UdpSocket,
    peer: SocketAddr,
    msg: &OwnedMessage,
) -> (SocketAddr, OwnedMessage) {
    let (from, _bytes, decoded) = send_recv_raw(socket, peer, msg).await;
    (from, decoded)
}

async fn send_recv_raw(
    socket: &UdpSocket,
    peer: SocketAddr,
    msg: &OwnedMessage,
) -> (SocketAddr, Bytes, OwnedMessage) {
    let bytes = encode_message(msg);
    socket.send_to(&bytes, peer).await.expect("send");

    let mut buf = vec![0u8; 65535];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv");

    let raw = Bytes::copy_from_slice(&buf[..len]);
    let decoded =
        OwnedMessage::decode_owned(raw.clone(), DecodeContext::default()).expect("decode");
    (from, raw, decoded)
}

async fn recv_message(socket: &UdpSocket) -> (SocketAddr, Bytes, OwnedMessage) {
    let mut buf = vec![0u8; 65535];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("recv timeout")
        .expect("recv");
    let raw = Bytes::copy_from_slice(&buf[..len]);
    let decoded =
        OwnedMessage::decode_owned(raw.clone(), DecodeContext::default()).expect("decode");
    (from, raw, decoded)
}

fn expect_typed_ie(msg: &OwnedMessage, ie_type: u16) -> TypedIe {
    let ie = msg
        .ies
        .iter()
        .find(|ie| ie.ie_type == ie_type)
        .unwrap_or_else(|| panic!("expected IE type {ie_type}"));
    decode_typed_ie(ie.ie_type, &ie.value)
}

#[tokio::test]
async fn pfcp_association_session_lifecycle() {
    init_tracing();
    let config = test_config(SMF_N4, "smf-ref-pfcp");
    println!("starting smf for pfcp test");
    let smf = tokio::time::timeout(Duration::from_secs(5), Smf::start(config))
        .await
        .expect("smf start does not time out")
        .expect("smf starts");
    println!("smf started");

    let upf = wait_for_udp(FAKE_UPF).await;
    println!("fake upf bound");
    let smf_addr: SocketAddr = SMF_N4.parse().expect("smf address");

    // 1. Association Setup Request
    let assoc_req = OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: false,
            message_type: MessageType::AssociationSetupRequest as u8,
            length: 0,
            seid: None,
            sequence_number: 100,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![],
    };
    let (_, assoc_resp) = send_recv(&upf, smf_addr, &assoc_req).await;
    println!("association response received: {assoc_resp:?}");
    assert_eq!(
        assoc_resp.header.message_type,
        MessageType::AssociationSetupResponse as u8
    );
    assert_eq!(assoc_resp.header.sequence_number, 100);
    assert!(find_cause(&assoc_resp, CauseValue::RequestAccepted));

    // 2. Session Establishment Request with typed Create PDR/FAR and raw QER.
    let create_pdr = build_create_pdr(1, 100, 1).expect("create pdr");
    let create_far = build_create_far(1, false, true, Some(1)).expect("create far");
    let create_qer = build_create_qer(1, 5).expect("create qer");

    let session_est = OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionEstablishmentRequest as u8,
            length: 0,
            seid: Some(0),
            sequence_number: 101,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![
            encode_typed_ie(create_pdr),
            encode_typed_ie(create_far),
            encode_typed_ie(create_qer),
        ],
    };

    println!("sending session establishment request");
    let (_, est_resp) = send_recv(&upf, smf_addr, &session_est).await;
    println!("session establishment response received: {est_resp:?}");
    assert_eq!(
        est_resp.header.message_type,
        MessageType::SessionEstablishmentResponse as u8
    );
    assert!(est_resp.header.s);
    assert_eq!(est_resp.header.sequence_number, 101);
    assert!(find_cause(&est_resp, CauseValue::RequestAccepted));

    // Verify the F-SEID in the response decodes as the typed IE we expect.
    let fseid_ie = est_resp
        .ies
        .iter()
        .find(|ie| ie.ie_type == opc_proto_pfcp::IeType::FSeid as u16)
        .expect("F-SEID IE present");
    let typed_fseid = decode_typed_ie(fseid_ie.ie_type, &fseid_ie.value);
    if let TypedIe::FSeid(fseid) = typed_fseid {
        assert_eq!(fseid.seid, 1);
        assert!(fseid.v4);
        assert_eq!(fseid.ipv4, Some([127, 0, 0, 1]));
    } else {
        panic!("expected F-SEID typed IE");
    }

    // 3. Session Modification Request (SMF-initiated with typed IEs).
    let update_far = build_update_far(1, 1).expect("update far");
    let remove_pdr = build_remove_pdr(1).expect("remove pdr");
    let mut mod_req = opc_proto_pfcp::session_modification_request(102, 1);
    mod_req.ies.push(encode_typed_ie(update_far));
    mod_req.ies.push(encode_typed_ie(remove_pdr));

    smf.send_pfcp(mod_req.clone())
        .expect("send modification request");
    let (from, raw, decoded) = recv_message(&upf).await;
    assert_eq!(from, smf_addr);
    assert_eq!(
        decoded.header.message_type,
        MessageType::SessionModificationRequest as u8
    );
    assert_eq!(decoded.header.sequence_number, 102);
    assert_eq!(decoded.header.seid, Some(1));
    assert_eq!(
        encode_message(&decoded),
        raw,
        "modification request round-trips byte-exact"
    );

    if let TypedIe::UpdateFar(u) =
        expect_typed_ie(&decoded, opc_proto_pfcp::IeType::UpdateFar as u16)
    {
        let far_id = u
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::FarId(f) = m {
                    Some(f.value)
                } else {
                    None
                }
            })
            .expect("Update FAR contains FAR ID");
        assert_eq!(far_id, 1);
        let fwd = u
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::UpdateForwardingParameters(fp) = m {
                    Some(fp)
                } else {
                    None
                }
            })
            .expect("Update FAR contains Update Forwarding Parameters");
        let dst_iface = fwd
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::DestinationInterface(di) = m {
                    Some(di.value)
                } else {
                    None
                }
            })
            .expect("Update Forwarding Parameters contains Destination Interface");
        assert_eq!(dst_iface, 1);
    } else {
        panic!("expected Update FAR typed IE");
    }

    if let TypedIe::RemovePdr(r) =
        expect_typed_ie(&decoded, opc_proto_pfcp::IeType::RemovePdr as u16)
    {
        assert_eq!(r.pdr_id.value, 1);
    } else {
        panic!("expected Remove PDR typed IE");
    }

    // 4. Session Report Request (fake UPF-initiated with typed Usage Report).
    let report_req =
        build_session_report_request(103, 1, 1, 7, 1_000_000, 60).expect("session report request");
    let (_, report_raw, report_resp) = send_recv_raw(&upf, smf_addr, &report_req).await;
    assert_eq!(
        report_resp.header.message_type,
        MessageType::SessionReportResponse as u8
    );
    assert_eq!(report_resp.header.sequence_number, 103);
    assert_eq!(report_resp.header.seid, Some(1));
    assert_eq!(
        encode_message(&report_resp),
        report_raw,
        "session report response round-trips byte-exact"
    );
    assert!(find_cause(&report_resp, CauseValue::RequestAccepted));

    // Verify the report request itself round-trips and contains the Usage Report.
    let report_req_encoded = encode_message(&report_req);
    let report_req_decoded =
        OwnedMessage::decode_owned(report_req_encoded.clone(), DecodeContext::default())
            .expect("decode report request");
    assert_eq!(
        encode_message(&report_req_decoded),
        report_req_encoded,
        "session report request round-trips byte-exact"
    );

    if let TypedIe::ReportType(rt) = expect_typed_ie(
        &report_req_decoded,
        opc_proto_pfcp::IeType::ReportType as u16,
    ) {
        assert!(rt.usage_report);
        assert!(!rt.downlink_data_report);
    } else {
        panic!("expected Report Type typed IE");
    }

    if let TypedIe::UsageReport(ur) = expect_typed_ie(
        &report_req_decoded,
        opc_proto_pfcp::IeType::UsageReport as u16,
    ) {
        let urr_id = ur
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::UrrId(u) = m {
                    Some(u.value)
                } else {
                    None
                }
            })
            .expect("Usage Report contains URR ID");
        assert_eq!(urr_id, 1);
        let ur_seqn = ur
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::UrSeqn(s) = m {
                    Some(s.value)
                } else {
                    None
                }
            })
            .expect("Usage Report contains UR-SEQN");
        assert_eq!(ur_seqn, 7);
        let total_volume = ur
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::VolumeMeasurement(v) = m {
                    v.total_volume
                } else {
                    None
                }
            })
            .expect("Usage Report contains total volume");
        assert_eq!(total_volume, 1_000_000);
        let duration = ur
            .members
            .iter()
            .find_map(|m| {
                if let TypedIe::DurationMeasurement(d) = m {
                    Some(d.seconds)
                } else {
                    None
                }
            })
            .expect("Usage Report contains duration");
        assert_eq!(duration, 60);
    } else {
        panic!("expected Usage Report typed IE");
    }

    // 5. Session Deletion Request
    let del_req = OwnedMessage {
        header: Header {
            version: 1,
            spare: 0,
            fo: false,
            mp: false,
            s: true,
            message_type: MessageType::SessionDeletionRequest as u8,
            length: 0,
            seid: Some(1),
            sequence_number: 104,
            message_priority: None,
            spare_octet: 0,
        },
        ies: vec![],
    };
    let (_, del_resp) = send_recv(&upf, smf_addr, &del_req).await;
    assert_eq!(
        del_resp.header.message_type,
        MessageType::SessionDeletionResponse as u8
    );
    assert!(find_cause(&del_resp, CauseValue::RequestAccepted));

    // 6. Heartbeat exchange and timeout handling.
    let hb_req = opc_proto_pfcp::heartbeat_request(200);
    let (_, hb_resp) = send_recv(&upf, smf_addr, &hb_req).await;
    assert_eq!(
        hb_resp.header.message_type,
        MessageType::HeartbeatResponse as u8
    );
    assert_eq!(hb_resp.header.sequence_number, 200);

    smf.shutdown().await;
}

#[tokio::test]
async fn session_store_round_trip() {
    init_tracing();
    let config = test_config("127.0.0.1:18815", "smf-ref-store");
    println!("starting smf for store test");
    let smf = tokio::time::timeout(Duration::from_secs(5), Smf::start(config))
        .await
        .expect("smf start does not time out")
        .expect("smf starts");
    println!("smf started, creating session");

    let seid = smf.create_session().await.expect("create session");
    let record = smf.get_session(seid).await.expect("get session");
    assert!(record.is_some(), "session record should exist");
    let record = record.unwrap();
    assert_eq!(record.local_seid, seid);
    assert_eq!(record.pdr_ids, vec![1]);
    assert_eq!(record.far_ids, vec![1]);
    assert_eq!(record.qer_ids, vec![1]);

    smf.shutdown().await;
}

fn find_cause(msg: &OwnedMessage, expected: CauseValue) -> bool {
    msg.ies
        .iter()
        .filter(|ie| ie.ie_type == opc_proto_pfcp::IeType::Cause as u16)
        .any(|ie| {
            let typed = decode_typed_ie(ie.ie_type, &ie.value);
            matches!(typed, TypedIe::Cause(c) if c.value == expected)
        })
}
