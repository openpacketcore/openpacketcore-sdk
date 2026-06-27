mod testbed_common;
use opc_proto_gtpv2c::{
    MessageDirection as Gtpv2cDirection, MessageType as Gtpv2cMessageType,
    Procedure as Gtpv2cProcedure, S2bMessage,
};
use opc_testbed::simulators::amf::{AmfSimulator, AmfState};
use opc_testbed::simulators::epc::{
    DiameterApplication, DiameterMessageView, DiameterPeerSimulator, DiameterPeerState,
    PeerMessageDirection, PgwS2bSimulator, PgwS2bState, S2bMessageView, S2bProcedure,
};
use opc_testbed::simulators::smf::{SmfSimulator, SmfState};
use opc_testbed::simulators::upf::{UpfSimulator, UpfState};
use opc_testbed::simulators::Simulator;
use testbed_common::*;

struct Gtpv2cS2bView<'a>(S2bMessage<'a>);

impl S2bMessageView for Gtpv2cS2bView<'_> {
    fn procedure(&self) -> S2bProcedure {
        match self.0.as_view().map(|view| view.procedure) {
            Some(Gtpv2cProcedure::Echo) => S2bProcedure::Echo,
            Some(Gtpv2cProcedure::CreateSession) => S2bProcedure::CreateSession,
            Some(Gtpv2cProcedure::ModifyBearer) => S2bProcedure::ModifyBearer,
            Some(Gtpv2cProcedure::DeleteSession) => S2bProcedure::DeleteSession,
            Some(Gtpv2cProcedure::UpdateSession) => S2bProcedure::UpdateSession,
            None => S2bProcedure::Unsupported(self.0.message_type().as_u8()),
        }
    }

    fn direction(&self) -> PeerMessageDirection {
        match self.0.as_view().map(|view| view.direction) {
            Some(Gtpv2cDirection::Request) => PeerMessageDirection::Request,
            Some(Gtpv2cDirection::Response) => PeerMessageDirection::Response,
            None => match self.0.message_type() {
                Gtpv2cMessageType::EchoResponse
                | Gtpv2cMessageType::CreateSessionResponse
                | Gtpv2cMessageType::ModifyBearerResponse
                | Gtpv2cMessageType::DeleteSessionResponse
                | Gtpv2cMessageType::UpdateBearerResponse => PeerMessageDirection::Response,
                _ => PeerMessageDirection::Request,
            },
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

#[derive(Debug)]
struct FakeDiameterFrame {
    command_code: u32,
    application_id: u32,
    direction: PeerMessageDirection,
    has_session_id: bool,
}

impl DiameterMessageView for FakeDiameterFrame {
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

fn decode_s2b_fixture<'a>(bytes: &'a [u8], sim: &PgwS2bSimulator) -> Gtpv2cS2bView<'a> {
    let (_, message) = S2bMessage::decode(bytes, sim.decode_profile.context)
        .expect("S2b fixture decodes through opc-proto-gtpv2c");
    Gtpv2cS2bView(message)
}

#[test]
fn fake_simulator_state_and_steps() {
    let mut sim = FakeSimulator::new("fake-nrf", Fidelity::Stub);
    assert_eq!(sim.get_state("state"), Some("INITIAL"));

    sim.handle_step("registration")
        .expect("registration step ok");
    assert_eq!(sim.get_state("state"), Some("REGISTERED"));

    sim.set_state("foo.bar", "baz");
    assert_eq!(sim.get_state("foo.bar"), Some("baz"));
}

#[test]
fn fake_simulator_from_spec_rejects_non_fake() {
    let spec = NfSpec {
        image: None,
        simulator: Some("nrf-basic".into()),
    };
    let err = FakeSimulator::from_spec("nrf-1", &spec).expect_err("non-fake must fail");
    assert!(err.to_string().contains("unsupported simulator"));
    assert!(err.to_string().contains("nrf-basic"));
}

#[test]
fn fake_simulator_from_spec_rejects_none() {
    let spec = NfSpec {
        image: None,
        simulator: None,
    };
    let err = FakeSimulator::from_spec("nrf", &spec).expect_err("missing simulator must fail");
    assert!(err.to_string().contains("no simulator specified"));
    assert!(err.to_string().contains("nrf"));
}

#[test]
fn fake_simulator_handle_step_rejects_unknown_kind() {
    let mut sim = FakeSimulator::new("fake-nrf", Fidelity::Stub);
    let err = sim
        .handle_step("deregistration")
        .expect_err("unknown step must fail");
    assert!(err.to_string().contains("unknown step kind"));
    assert!(err.to_string().contains("deregistration"));
}

#[test]
fn amf_simulator_happy_path() {
    let mut sim = AmfSimulator::new("amf-test");
    assert_eq!(sim.state, AmfState::BootstrapPending);

    sim.state = AmfState::Ready;

    let step = Step::SendNgap {
        from: "gnb".to_string(),
        to: "amf-test".to_string(),
        message: "registration".to_string(),
    };
    sim.handle_step(&step).unwrap();
    assert_eq!(sim.state, AmfState::Registered);
    assert!(sim.subscriber_context_created);

    let step_sess = Step::SendNgap {
        from: "gnb".to_string(),
        to: "amf-test".to_string(),
        message: "session".to_string(),
    };
    sim.handle_step(&step_sess).unwrap();
    assert_eq!(sim.state, AmfState::SessionActive);

    let step_conf = Step::SendNgap {
        from: "operator".to_string(),
        to: "amf-test".to_string(),
        message: "config".to_string(),
    };
    sim.handle_step(&step_conf).unwrap();
    assert_eq!(sim.config_version, "1.1.0");
}

#[test]
fn amf_simulator_nrf_dependency_failure() {
    let mut sim = AmfSimulator::new("amf-test");
    sim.state = AmfState::Ready;

    let step_fail = Step::PeerUnavailable {
        target: "amf-test".to_string(),
    };
    sim.handle_step(&step_fail).unwrap();
    assert_eq!(sim.state, AmfState::AlarmActive);
    assert!(!sim.nrf_connected);
    assert!(sim.alarm_emitted);
    assert_eq!(sim.transient_peer_failures, 1);

    let step_reg = Step::SendNgap {
        from: "gnb".to_string(),
        to: "amf-test".to_string(),
        message: "registration".to_string(),
    };
    assert!(sim.handle_step(&step_reg).is_err());

    let step_recover = Step::SendNgap {
        from: "operator".to_string(),
        to: "amf-test".to_string(),
        message: "recover".to_string(),
    };
    sim.handle_step(&step_recover).unwrap();
    assert_eq!(sim.state, AmfState::Registered);
    assert!(sim.nrf_connected);
    assert!(!sim.alarm_emitted);
}

#[test]
fn amf_simulator_invalid_transitions_fail_closed() {
    let mut sim = AmfSimulator::new("amf-test");
    sim.state = AmfState::Ready;

    let step_sess = Step::SendNgap {
        from: "gnb".to_string(),
        to: "amf-test".to_string(),
        message: "session".to_string(),
    };
    assert!(sim.handle_step(&step_sess).is_err());
    assert_ne!(sim.state, AmfState::SessionActive);
}

#[test]
fn smf_simulator_happy_path() {
    let mut sim = SmfSimulator::new("smf-test");
    assert_eq!(sim.state, SmfState::Idle);

    let step_est = Step::SendNgap {
        from: "amf".to_string(),
        to: "smf-test".to_string(),
        message: "establish:owner=amf-1:fence=5".to_string(),
    };
    sim.handle_step(&step_est).unwrap();
    assert_eq!(sim.state, SmfState::SessionEstablished);
    assert_eq!(sim.lease_owner, Some("amf-1".to_string()));
    assert_eq!(sim.current_fence, 5);

    let step_mod = Step::SendNgap {
        from: "amf".to_string(),
        to: "smf-test".to_string(),
        message: "modify".to_string(),
    };
    sim.handle_step(&step_mod).unwrap();
    assert_eq!(sim.state, SmfState::SessionModified);

    let step_rel = Step::SendNgap {
        from: "amf".to_string(),
        to: "smf-test".to_string(),
        message: "release".to_string(),
    };
    sim.handle_step(&step_rel).unwrap();
    assert_eq!(sim.state, SmfState::SessionReleased);
    assert!(sim.lease_owner.is_none());
}

#[test]
fn smf_simulator_stale_fence_rejection() {
    let mut sim = SmfSimulator::new("smf-test");

    let step_est = Step::SendNgap {
        from: "amf".to_string(),
        to: "smf-test".to_string(),
        message: "establish:owner=amf-1:fence=5".to_string(),
    };
    sim.handle_step(&step_est).unwrap();

    let step_stale = Step::SendNgap {
        from: "amf".to_string(),
        to: "smf-test".to_string(),
        message: "establish:owner=amf-1:fence=4".to_string(),
    };
    assert!(sim.handle_step(&step_stale).is_err());
    assert_eq!(sim.state, SmfState::StaleFenceRejected);
}

#[test]
fn upf_simulator_association_and_alarms() {
    let mut sim = UpfSimulator::new("upf-test");
    assert_eq!(sim.state, UpfState::Idle);

    let step_assoc = Step::SendNgap {
        from: "smf".to_string(),
        to: "upf-test".to_string(),
        message: "associate".to_string(),
    };
    sim.handle_step(&step_assoc).unwrap();
    assert_eq!(sim.state, UpfState::Associated);
    assert!(sim.association_active);

    let step_flow = Step::SendNgap {
        from: "smf".to_string(),
        to: "upf-test".to_string(),
        message: "flow".to_string(),
    };
    for _ in 0..11 {
        sim.handle_step(&step_flow).unwrap();
    }
    assert!(sim.flow_counter > sim.flow_threshold);
    assert!(sim.alarm_active);
}

#[test]
fn upf_simulator_dataplane_preflight_failure() {
    let mut sim = UpfSimulator::new("upf-test");

    let step_fail = Step::DependencyTimeout {
        target: "upf-test".to_string(),
    };
    sim.handle_step(&step_fail).unwrap();
    assert_eq!(sim.state, UpfState::PreflightFailed);
    assert!(!sim.dataplane_ready);

    let step_assoc = Step::SendNgap {
        from: "smf".to_string(),
        to: "upf-test".to_string(),
        message: "associate".to_string(),
    };
    assert!(sim.handle_step(&step_assoc).is_err());
}

#[test]
fn pgw_s2b_simulator_accepts_sdk_gtpv2c_decoded_messages() {
    let mut sim = PgwS2bSimulator::new("pgw-s2b");
    let echo = decode_s2b_fixture(
        include_bytes!("../../opc-proto-gtpv2c/tests/fixtures/spec/echo_request_recovery.bin"),
        &sim,
    );
    let echo_event = sim
        .handle_sdk_message(&echo)
        .expect("PGW S2b accepts SDK-decoded echo request");
    assert_eq!(echo_event.procedure, S2bProcedure::Echo);
    assert_eq!(sim.state, PgwS2bState::EchoSeen);
    assert_eq!(
        sim.get_state("sdk_protocol_profile").as_deref(),
        Some("opc-protocol+s2b-procedure-aware")
    );

    let create = decode_s2b_fixture(
        include_bytes!(
            "../../opc-proto-gtpv2c/tests/fixtures/spec/create_session_request_s2b_subset.bin"
        ),
        &sim,
    );
    let create_event = sim
        .handle_sdk_message(&create)
        .expect("PGW S2b accepts SDK-decoded create-session request");
    assert_eq!(create_event.procedure, S2bProcedure::CreateSession);
    assert_eq!(sim.state, PgwS2bState::SessionCreated);
    assert_eq!(sim.active_sessions, 1);
    assert_eq!(sim.accepted_messages, 2);
    assert!(sim.raw_preserving_messages >= 2);
}

#[test]
fn pgw_s2b_simulator_rejects_state_changing_request_without_session() {
    let mut sim = PgwS2bSimulator::new("pgw-s2b");
    let modify = decode_s2b_fixture(
        include_bytes!(
            "../../opc-proto-gtpv2c/tests/fixtures/spec/modify_bearer_request_bearer_context.bin"
        ),
        &sim,
    );
    let err = sim
        .handle_sdk_message(&modify)
        .expect_err("modify before create must fail closed");
    assert!(err
        .to_string()
        .contains("requires an active synthetic session"));
    assert_eq!(sim.state, PgwS2bState::MalformedRejected);
    assert_eq!(sim.rejected_messages, 1);
}

#[test]
fn pgw_s2b_unavailable_fault_persists_until_restart() {
    let mut sim = PgwS2bSimulator::new("pgw-s2b");
    let create = decode_s2b_fixture(
        include_bytes!(
            "../../opc-proto-gtpv2c/tests/fixtures/spec/create_session_request_s2b_subset.bin"
        ),
        &sim,
    );

    sim.mark_peer_unavailable();
    for expected_rejections in 1..=2 {
        let err = sim
            .handle_sdk_message(&create)
            .expect_err("unavailable PGW must reject every decoded S2b message");
        assert!(err.to_string().contains("unavailable"));
        assert_eq!(sim.state, PgwS2bState::PeerUnavailable);
        assert_eq!(sim.rejected_messages, expected_rejections);
        assert_eq!(sim.accepted_messages, 0);
    }

    sim.restart();
    sim.handle_sdk_message(&create)
        .expect("PGW accepts decoded S2b message after restart");
    assert_eq!(sim.state, PgwS2bState::SessionCreated);
    assert_eq!(sim.accepted_messages, 1);
}

#[test]
fn diameter_peer_simulator_records_sdk_decoded_interface_messages() {
    let mut sim = DiameterPeerSimulator::new("aaa-hss");
    let cer = FakeDiameterFrame {
        command_code: 257,
        application_id: 0,
        direction: PeerMessageDirection::Request,
        has_session_id: false,
    };
    let event = sim
        .handle_sdk_message(&cer)
        .expect("Diameter peer accepts SDK-decoded CER metadata");
    assert_eq!(event.application, DiameterApplication::Base);
    assert_eq!(event.state, DiameterPeerState::CapabilitiesExchanged);
    assert_eq!(sim.capability_messages, 1);

    let gx = FakeDiameterFrame {
        command_code: 272,
        application_id: 16_777_238,
        direction: PeerMessageDirection::Request,
        has_session_id: true,
    };
    let event = sim
        .handle_sdk_message(&gx)
        .expect("Diameter peer accepts SDK-decoded Gx metadata");
    assert_eq!(event.application, DiameterApplication::Gx);
    assert_eq!(sim.state, DiameterPeerState::ApplicationMessageSeen);
    assert_eq!(sim.session_messages, 1);
    assert_eq!(
        sim.get_state("sdk_protocol_profile").as_deref(),
        Some("opc-protocol+diameter-transport-neutral")
    );
}

#[test]
fn diameter_peer_unavailable_fault_persists_until_restart() {
    let mut sim = DiameterPeerSimulator::new("aaa-hss");
    let cer = FakeDiameterFrame {
        command_code: 257,
        application_id: 0,
        direction: PeerMessageDirection::Request,
        has_session_id: false,
    };

    sim.mark_peer_unavailable();
    for expected_rejections in 1..=2 {
        let err = sim
            .handle_sdk_message(&cer)
            .expect_err("unavailable Diameter peer must reject every decoded message");
        assert!(err.to_string().contains("unavailable"));
        assert_eq!(sim.state, DiameterPeerState::PeerUnavailable);
        assert_eq!(sim.rejected_messages, expected_rejections);
        assert_eq!(sim.accepted_messages, 0);
    }

    sim.restart();
    sim.handle_sdk_message(&cer)
        .expect("Diameter peer accepts decoded metadata after restart");
    assert_eq!(sim.state, DiameterPeerState::CapabilitiesExchanged);
    assert_eq!(sim.accepted_messages, 1);
}

#[test]
fn simulator_factory_accepts_epc_epdg_skeleton_names() {
    let pgw_spec = NfSpec {
        image: None,
        simulator: Some("pgw-s2b".into()),
    };
    let pgw = Simulator::from_spec("pgw", &pgw_spec).expect("pgw-s2b simulator constructed");
    assert_eq!(pgw.get_state("state").as_deref(), Some("IDLE"));

    let diameter_spec = NfSpec {
        image: None,
        simulator: Some("diameter-peer".into()),
    };
    let diameter =
        Simulator::from_spec("aaa", &diameter_spec).expect("diameter simulator constructed");
    assert_eq!(diameter.get_state("state").as_deref(), Some("IDLE"));
}

#[test]
fn epc_epdg_simulator_factory_fault_steps_are_fail_closed() {
    for simulator in ["pgw-s2b", "diameter-peer"] {
        let spec = NfSpec {
            image: None,
            simulator: Some(simulator.to_string()),
        };
        let mut sim = Simulator::from_spec(simulator, &spec).expect("simulator constructed");

        sim.handle_step(&Step::PeerUnavailable {
            target: simulator.to_string(),
        })
        .expect("peer-unavailable fault injection succeeds");
        assert_eq!(sim.get_state("state").as_deref(), Some("PEER_UNAVAILABLE"));

        sim.handle_step(&Step::ProcessRestart {
            target: simulator.to_string(),
        })
        .expect("process restart clears unavailable state");
        assert_eq!(sim.get_state("state").as_deref(), Some("IDLE"));

        let malformed = sim
            .handle_step(&Step::MalformedResponse {
                target: simulator.to_string(),
            })
            .expect_err("malformed response records a decode failure");
        assert!(malformed.to_string().contains("SDK decode failed"));
        assert_eq!(
            sim.get_state("state").as_deref(),
            Some("MALFORMED_REJECTED")
        );

        sim.handle_step(&Step::ProcessRestart {
            target: simulator.to_string(),
        })
        .expect("process restart clears malformed state");
        let send_ngap = sim
            .handle_step(&Step::SendNgap {
                from: "peer".to_string(),
                to: simulator.to_string(),
                message: "registration".to_string(),
            })
            .expect_err("EPC/ePDG simulators require SDK-decoded protocol views");
        assert!(send_ngap.to_string().contains("requires SDK-decoded"));
    }
}

#[test]
fn epc_epdg_simulator_fixture_manifest_records_protocol_provenance() {
    let manifest = include_str!("fixtures/epc_epdg_simulator_manifest.json");
    let value: serde_json::Value =
        serde_json::from_str(manifest).expect("simulator fixture manifest is valid JSON");
    let packets = value["packets"]
        .as_array()
        .expect("manifest packets are an array");
    assert!(packets
        .iter()
        .any(|packet| packet["sdk_protocol_crate"] == "opc-proto-gtpv2c"
            && packet["provenance"] == "spec-authored"));
    let interfaces = value["interfaces"]
        .as_array()
        .expect("manifest interfaces are an array");
    assert!(interfaces.iter().any(
        |interface| interface["id"] == "diameter-peer-decoded-message"
            && interface["parser_policy"] == "sdk-protocol-crate-only"
    ));
}
