use std::error::Error;

use opc_evidence::{
    compute_digest, AttachProcedureEvidence, AttachProcedureResult, AttachStep, AttachStepResult,
    KernelDataplaneEvidence, PacketCoreEvidencePack, PacketCoreMessageDirection,
    PacketCoreProtocolEvidence, PACKET_CORE_SCHEMA_VERSION,
};
use opc_ipsec_xfrm::{
    build_xfrm_requests_from_ikev2_child_sa, install_sa_policy_with_rollback, Algorithm,
    AuthAlgorithm, Ikev2ChildSaXfrmKeys, Ikev2ChildSaXfrmRequest, IpAddress, KeyMaterial,
    LifetimeConfig, MockOperation, MockXfrmBackend, XfrmDirection, XfrmMode,
    IKEV2_SECURITY_PROTOCOL_ID_ESP,
};
use opc_proto_diameter::apps::swm::{
    build_eap_response_identity, build_swm_diameter_eap_answer_for, build_swm_diameter_eap_request,
    derive_unauthenticated_emergency_msk, emergency_nai, parse_swm_diameter_eap_answer_envelope,
    parse_swm_diameter_eap_request, parse_swm_diameter_eap_request_envelope, AuthRequestType,
    SwmDiameterEapAnswer, SwmDiameterEapRequest, SwmDiameterResult,
    SwmEmergencyAuthorizationEvidence, SwmEmergencyAuthorizationPath, SwmEmergencyServices,
    SwmTerminalInformation, APPLICATION_ID as SWM_APPLICATION_ID, COMMAND_DIAMETER_EAP,
};
use opc_proto_diameter::Message as DiameterMessage;
use opc_proto_gtpv2c::{
    MessageDirection as Gtpv2cDirection, MessageType as Gtpv2cMessageType,
    Procedure as Gtpv2cProcedure, S2bMessage,
};
use opc_proto_ikev2::{
    build_ike_auth_authentication_payload, build_ike_auth_identification_payload,
    build_ikev2_device_identity_request, build_ikev2_device_identity_response,
    compute_ike_auth_shared_key_mic, decode_ikev2_device_identity_notify,
    derive_ike_sa_init_key_material, Ikev2AuthenticationPayloadBuild, Ikev2ChildSaNegotiation,
    Ikev2DeviceIdentity, Ikev2DeviceIdentityNotify, Ikev2DeviceIdentityType, Ikev2DhGroup,
    Ikev2EncryptionAlgorithm, Ikev2IdentificationPayloadBuild, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2NotifyPayload, Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile,
    Ikev2TrafficSelectorBuild, IKEV2_AUTH_METHOD_SHARED_KEY_MIC, IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_protocol::{DecodeContext, EncodeContext};
use opc_testbed::simulators::epc::{
    DiameterApplication, DiameterMessageView, DiameterPeerSimulator, DiameterPeerState,
    PeerMessageDirection, PgwS2bSimulator, PgwS2bState, S2bMessageView, S2bProcedure,
};
use opc_types::{Imei, Imei15};
use time::OffsetDateTime;

struct Gtpv2cS2bView<'a>(S2bMessage<'a>);

impl S2bMessageView for Gtpv2cS2bView<'_> {
    fn procedure(&self) -> S2bProcedure {
        match self.0.as_view().map(|view| view.procedure) {
            Some(Gtpv2cProcedure::Echo) => S2bProcedure::Echo,
            Some(Gtpv2cProcedure::CreateSession) => S2bProcedure::CreateSession,
            Some(Gtpv2cProcedure::ModifyBearer) => S2bProcedure::ModifyBearer,
            Some(Gtpv2cProcedure::DeleteSession) => S2bProcedure::DeleteSession,
            Some(Gtpv2cProcedure::UpdateSession) => S2bProcedure::UpdateSession,
            Some(Gtpv2cProcedure::CreateBearer | Gtpv2cProcedure::DeleteBearer) => {
                S2bProcedure::Unsupported(self.0.message_type().as_u8())
            }
            None => S2bProcedure::Unsupported(self.0.message_type().as_u8()),
        }
    }

    fn direction(&self) -> PeerMessageDirection {
        match self.0.as_view().map(|view| view.direction) {
            Some(Gtpv2cDirection::Request) => PeerMessageDirection::Request,
            Some(Gtpv2cDirection::Response) => PeerMessageDirection::Response,
            None => direction_from_raw_gtpv2c_header(self.0.message_type()),
        }
    }

    fn sequence_number(&self) -> u32 {
        if let Some(view) = self.0.as_view() {
            return view.header.sequence_number;
        }
        self.0
            .as_raw()
            .map(|message| message.header.sequence_number)
            .unwrap_or(0)
    }

    fn teid(&self) -> Option<u32> {
        if let Some(view) = self.0.as_view() {
            return view.header.teid;
        }
        self.0.as_raw().and_then(|message| message.header.teid)
    }

    fn raw_preserving_view(&self) -> bool {
        if let Some(view) = self.0.as_view() {
            return !view.raw_ies.is_empty();
        }
        self.0
            .as_raw()
            .map(|message| !message.raw_ies.is_empty())
            .unwrap_or(false)
    }
}

fn direction_from_raw_gtpv2c_header(message_type: Gtpv2cMessageType) -> PeerMessageDirection {
    match message_type {
        Gtpv2cMessageType::EchoResponse
        | Gtpv2cMessageType::CreateSessionResponse
        | Gtpv2cMessageType::ModifyBearerResponse
        | Gtpv2cMessageType::DeleteSessionResponse
        | Gtpv2cMessageType::CreateBearerResponse
        | Gtpv2cMessageType::DeleteBearerResponse
        | Gtpv2cMessageType::UpdateBearerResponse => PeerMessageDirection::Response,
        _ => PeerMessageDirection::Request,
    }
}

#[derive(Debug)]
struct DiameterSdkView {
    command_code: u32,
    application_id: u32,
    direction: PeerMessageDirection,
    has_session_id: bool,
}

impl DiameterMessageView for DiameterSdkView {
    fn command_code(&self) -> u32 {
        self.command_code
    }

    fn application_id(&self) -> u32 {
        self.application_id
    }

    fn direction(&self) -> PeerMessageDirection {
        self.direction
    }

    fn has_session_id(&self) -> bool {
        self.has_session_id
    }
}

#[tokio::test]
async fn epdg_sdk_protocol_xfrm_testbed_and_evidence_components_compose(
) -> Result<(), Box<dyn Error>> {
    let mut pgw = PgwS2bSimulator::new("pgw-s2b");
    let s2b_bytes = include_bytes!(
        "../../opc-proto-gtpv2c/tests/fixtures/spec/create_session_request_s2b_subset.bin"
    );
    let (tail, s2b_message) = S2bMessage::decode(s2b_bytes, pgw.decode_profile.context)?;
    assert!(tail.is_empty());
    let s2b_event = pgw.handle_sdk_message(&Gtpv2cS2bView(s2b_message))?;
    assert_eq!(s2b_event.procedure, S2bProcedure::CreateSession);
    assert_eq!(pgw.state, PgwS2bState::SessionCreated);
    assert_eq!(pgw.active_sessions, 1);

    let mut diameter = DiameterPeerSimulator::new("aaa-swm");
    let der = build_swm_diameter_eap_request(
        &SwmDiameterEapRequest {
            session_id: "sess;swm;redacted".into(),
            auth_application_id: SWM_APPLICATION_ID.get(),
            origin_host: "epdg.redacted.example".into(),
            origin_realm: "visited.redacted.example".into(),
            destination_realm: "home.redacted.example".into(),
            destination_host: Some("aaa.redacted.example".into()),
            user_name: Some("ue-redacted".into()),
            auth_request_type: AuthRequestType::AuthorizeAuthenticate,
            eap_payload: vec![0x02, 0x17, 0x00, 0x04].into(),
            emergency_services: None,
            terminal_information: None,
            state_avps: vec![b"opaque-redacted-state".to_vec()],
        },
        0x1111_2222,
        0x3333_4444,
        EncodeContext::default(),
    )?;
    let der_message = DiameterMessage {
        header: der.header.clone(),
        raw_avps: &der.raw_avps,
        tail: &[],
    };
    let parsed_der = parse_swm_diameter_eap_request(&der_message, DecodeContext::default())?;
    let diameter_view = DiameterSdkView {
        command_code: der_message.header.command_code.get(),
        application_id: der_message.header.application_id.get(),
        direction: if der_message.header.flags.is_request() {
            PeerMessageDirection::Request
        } else {
            PeerMessageDirection::Response
        },
        has_session_id: !parsed_der.session_id.as_ref().is_empty(),
    };
    let diameter_event = diameter.handle_sdk_message(&diameter_view)?;
    assert_eq!(diameter_event.command_code, COMMAND_DIAMETER_EAP.get());
    assert_eq!(diameter_event.application, DiameterApplication::Swm);
    assert_eq!(diameter.state, DiameterPeerState::ApplicationMessageSeen);
    assert_eq!(diameter.session_messages, 1);

    let xfrm_requests = build_xfrm_requests_from_ikev2_child_sa(&Ikev2ChildSaXfrmRequest {
        negotiation: Ikev2ChildSaNegotiation {
            proposal_number: 1,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
            initiator_spi: 0x1020_3040_u32.to_be_bytes().to_vec(),
            transforms: Vec::new(),
            initiator_traffic_selector: ikev2_ipv4_selector([10, 10, 0, 10]),
            responder_traffic_selector: ikev2_ipv4_selector([10, 20, 0, 20]),
        },
        local_tunnel_address: IpAddress::Ipv4([192, 0, 2, 10]),
        remote_tunnel_address: IpAddress::Ipv4([198, 51, 100, 20]),
        responder_spi: 0x5060_7080,
        inbound: xfrm_keys(0xab),
        outbound: xfrm_keys(0xcd),
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        policy_priority: 20_000,
    })?;
    assert_eq!(
        xfrm_requests.inbound_policy.parameters.direction,
        XfrmDirection::In
    );
    assert_eq!(
        xfrm_requests.outbound_policy.parameters.direction,
        XfrmDirection::Out
    );

    let backend = MockXfrmBackend::new();
    for composite in xfrm_requests.composite_installs() {
        let outcome = install_sa_policy_with_rollback(&backend, composite).await?;
        assert!(outcome.applied);
        assert!(!outcome.partial_state_possible);
    }
    let operations = backend.operations();
    assert_eq!(operations.len(), 4);
    assert!(matches!(operations[0], MockOperation::InstallSa { .. }));
    assert!(matches!(operations[1], MockOperation::InstallPolicy { .. }));
    assert!(matches!(operations[2], MockOperation::InstallSa { .. }));
    assert!(matches!(operations[3], MockOperation::InstallPolicy { .. }));

    let evidence = PacketCoreEvidencePack {
        schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
        pack_id: "epdg-sdk-composition".to_string(),
        generated_at: OffsetDateTime::UNIX_EPOCH,
        generated_by: "opc-testbed".to_string(),
        experimental: true,
        protocol_evidence: vec![
            PacketCoreProtocolEvidence {
                schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
                evidence_id: "s2b-create-session".to_string(),
                protocol: "GTPv2-C S2b".to_string(),
                scenario: "epdg attach composition".to_string(),
                message_direction: PacketCoreMessageDirection::ControlPlane,
                payload_summary: "S2b create-session request fixture".to_string(),
                payload_digest: compute_digest(s2b_bytes),
                conformance_tags: vec!["sdk-compose".to_string()],
                requirements: vec!["REQ-EPDG-SDK-COMPOSE".to_string()],
                fixture_source: "SDK spec fixture".to_string(),
                fixture_provenance: "spec-authored fixture retained by protocol crate".to_string(),
                captured_at: None,
                notes: None,
            },
            PacketCoreProtocolEvidence {
                schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
                evidence_id: "swm-der".to_string(),
                protocol: "Diameter SWm".to_string(),
                scenario: "epdg attach composition".to_string(),
                message_direction: PacketCoreMessageDirection::ControlPlane,
                payload_summary: "SWm DER request with redacted EAP payload".to_string(),
                payload_digest: compute_digest(&der.raw_avps),
                conformance_tags: vec!["sdk-compose".to_string()],
                requirements: vec!["REQ-EPDG-SDK-COMPOSE".to_string()],
                fixture_source: "SDK generated message".to_string(),
                fixture_provenance: "built and parsed by SWm helpers".to_string(),
                captured_at: None,
                notes: None,
            },
        ],
        attach_evidence: vec![AttachProcedureEvidence {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            evidence_id: "epdg-attach-redacted".to_string(),
            procedure: "epdg attach composition".to_string(),
            result: AttachProcedureResult::Success,
            steps: vec![
                AttachStep {
                    name: "s2b-create-session".to_string(),
                    result: AttachStepResult::Success,
                    message_digest: Some(compute_digest(s2b_bytes)),
                    notes: None,
                },
                AttachStep {
                    name: "diameter-swm-der".to_string(),
                    result: AttachStepResult::Success,
                    message_digest: Some(compute_digest(&der.raw_avps)),
                    notes: None,
                },
                AttachStep {
                    name: "xfrm-install".to_string(),
                    result: AttachStepResult::Success,
                    message_digest: None,
                    notes: Some(
                        "redacted Child SA install requests accepted by mock backend".into(),
                    ),
                },
            ],
            ue_identifier_redacted: "<redacted>".to_string(),
            session_id_redacted: Some("<redacted>".to_string()),
            serving_node: "epdg-redacted".to_string(),
            timestamp: OffsetDateTime::UNIX_EPOCH,
            duration_ms: Some(42),
            requirements: vec!["REQ-EPDG-SDK-COMPOSE".to_string()],
            notes: Some("SDK-only composition evidence with generated redacted inputs".to_string()),
        }],
        kernel_dataplane_evidence: vec![KernelDataplaneEvidence {
            schema_version: PACKET_CORE_SCHEMA_VERSION.to_string(),
            evidence_id: "xfrm-redacted".to_string(),
            interface_name: "ipsec-redacted".to_string(),
            xfrm_state_count: 2,
            xfrm_policy_count: 2,
            routing_entries: 0,
            iptables_rules: 0,
            nftables_rules: 0,
            observed_packets: 0,
            dropped_packets: 0,
            counters: vec![],
            xfrm_state_summary: vec![
                "redacted inbound child-sa state".to_string(),
                "redacted outbound child-sa state".to_string(),
            ],
            timestamp: OffsetDateTime::UNIX_EPOCH,
            requirements: vec!["REQ-EPDG-SDK-COMPOSE".to_string()],
            notes: Some("mock backend install evidence; no raw endpoints or indexes".to_string()),
        }],
    };
    evidence.validate_redaction()?;

    Ok(())
}

#[test]
fn epdg_unauthenticated_emergency_identity_recovery_components_compose(
) -> Result<(), Box<dyn Error>> {
    let imei = Imei15::new("490154203237518")?;
    let emergency_imsi_nai = "0234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org";
    let eap_identity = build_eap_response_identity(0x17, emergency_imsi_nai.as_bytes())?;
    let mut initial_request = SwmDiameterEapRequest {
        session_id: "sess;swm;emergency".into(),
        auth_application_id: SWM_APPLICATION_ID.get(),
        origin_host: "epdg.redacted.example".into(),
        origin_realm: "visited.redacted.example".into(),
        destination_realm: "home.redacted.example".into(),
        destination_host: Some("aaa.redacted.example".into()),
        user_name: Some(emergency_imsi_nai.into()),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: eap_identity.into(),
        emergency_services: Some(SwmEmergencyServices::emergency_indication()),
        terminal_information: None,
        state_avps: Vec::new(),
    };
    let initial_owned = build_swm_diameter_eap_request(
        &initial_request,
        0x1000_0001,
        0x2000_0001,
        EncodeContext::default(),
    )?;
    let initial_message = DiameterMessage {
        header: initial_owned.header.clone(),
        raw_avps: &initial_owned.raw_avps,
        tail: &[],
    };
    let initial_request_envelope =
        parse_swm_diameter_eap_request_envelope(&initial_message, DecodeContext::conservative())?;
    initial_request = initial_request_envelope.request().clone();

    let identity_answer = SwmDiameterEapAnswer {
        session_id: initial_request.session_id.clone(),
        auth_application_id: SWM_APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Experimental {
            vendor_id: opc_proto_diameter::apps::VENDOR_ID_3GPP,
            code: opc_proto_diameter::apps::swm::DIAMETER_ERROR_USER_UNKNOWN,
        },
        origin_host: "aaa.redacted.example".into(),
        origin_realm: "home.redacted.example".into(),
        user_name: None,
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: None,
        eap_payload: None,
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
    };
    let identity_owned = build_swm_diameter_eap_answer_for(
        &initial_request_envelope,
        &identity_answer,
        EncodeContext::default(),
    )?;
    let identity_message = DiameterMessage {
        header: identity_owned.header.clone(),
        raw_avps: &identity_owned.raw_avps,
        tail: &[],
    };
    let identity_answer_envelope =
        parse_swm_diameter_eap_answer_envelope(&identity_message, DecodeContext::conservative())?;
    assert!(identity_answer_envelope
        .answer()
        .result
        .requests_emergency_identity_recovery());

    let device_request = build_ikev2_device_identity_request(Ikev2DeviceIdentityType::Imei)?;
    let device_request = Ikev2NotifyPayload::decode_body(&device_request)?;
    assert_eq!(
        decode_ikev2_device_identity_notify(device_request)?,
        Ikev2DeviceIdentityNotify::Request(Ikev2DeviceIdentityType::Imei)
    );
    let device_response =
        build_ikev2_device_identity_response(&Ikev2DeviceIdentity::Imei(imei.clone()))?;
    let device_response = Ikev2NotifyPayload::decode_body(&device_response)?;
    let recovered = decode_ikev2_device_identity_notify(device_response)?;
    let recovered_imei = match recovered {
        Ikev2DeviceIdentityNotify::Response(Ikev2DeviceIdentity::Imei(value)) => value,
        _ => panic!("IMEI DEVICE_IDENTITY response must remain typed"),
    };

    let mut retry_request = initial_request.clone();
    retry_request.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&recovered_imei),
        software_version: None,
    });
    let retry_owned = build_swm_diameter_eap_request(
        &retry_request,
        0x1000_0003,
        0x2000_0003,
        EncodeContext::default(),
    )?;
    let retry_message = DiameterMessage {
        header: retry_owned.header.clone(),
        raw_avps: &retry_owned.raw_avps,
        tail: &[],
    };
    let retry_request_envelope =
        parse_swm_diameter_eap_request_envelope(&retry_message, DecodeContext::conservative())?;
    let retry_request = retry_request_envelope.request();

    let derived_msk = derive_unauthenticated_emergency_msk(&imei);
    let final_answer = SwmDiameterEapAnswer {
        session_id: retry_request.session_id.clone(),
        auth_application_id: SWM_APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(2001),
        origin_host: "aaa.redacted.example".into(),
        origin_realm: "home.redacted.example".into(),
        user_name: None,
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: Some(emergency_nai(&imei).into()),
        eap_payload: Some(vec![0x03, 0x17, 0x00, 0x04].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: Some(derived_msk.as_bytes().to_vec().into()),
    };
    let final_owned = build_swm_diameter_eap_answer_for(
        &retry_request_envelope,
        &final_answer,
        EncodeContext::default(),
    )?;
    let final_message = DiameterMessage {
        header: final_owned.header.clone(),
        raw_avps: &final_owned.raw_avps,
        tail: &[],
    };
    let final_answer_envelope =
        parse_swm_diameter_eap_answer_envelope(&final_message, DecodeContext::conservative())?;
    let initial_exchange = initial_request_envelope.correlate_answer(identity_answer_envelope)?;
    let retry_exchange = retry_request_envelope.correlate_answer(final_answer_envelope)?;

    let evidence = SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
        initial_exchange,
        retry_exchange,
        &imei,
    )?;
    assert_eq!(
        evidence.path(),
        SwmEmergencyAuthorizationPath::RecoveredDeviceIdentity
    );

    let profile = Ikev2SaInitCryptoProfile::new(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    );
    let key_material = derive_ike_sa_init_key_material(
        profile,
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )?;
    let identity_body = build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: emergency_nai(&imei).into_bytes(),
    })?;
    let auth_data = compute_ike_auth_shared_key_mic(
        profile,
        &key_material,
        Ikev2IkeAuthSignedOctets {
            peer: Ikev2IkeAuthPeer::Initiator,
            ike_sa_init_message: b"first-ike-sa-init-request-wire-bytes",
            peer_nonce: &[0x77; 32],
            identity_payload_body: &identity_body,
        },
        evidence.msk().as_bytes(),
    )?;
    let auth_body = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data,
    })?;
    assert_eq!(auth_body[0], IKEV2_AUTH_METHOD_SHARED_KEY_MIC);

    Ok(())
}

fn ikev2_ipv4_selector(address: [u8; 4]) -> Ikev2TrafficSelectorBuild {
    Ikev2TrafficSelectorBuild {
        ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
        ip_protocol_id: 0,
        start_port: 0,
        end_port: u16::MAX,
        start_address: address.to_vec(),
        end_address: address.to_vec(),
    }
}

fn xfrm_keys(seed: u8) -> Ikev2ChildSaXfrmKeys {
    Ikev2ChildSaXfrmKeys::new(
        Some((
            AuthAlgorithm::new("hmac-sha256", 128),
            KeyMaterial::new(vec![seed; 32]),
        )),
        Some((
            Algorithm::new("rfc4106(gcm(aes))"),
            KeyMaterial::new(vec![seed; 20]),
        )),
    )
}
