mod testbed_common;
use opc_testbed::simulators::amf::{AmfSimulator, AmfState};
use opc_testbed::simulators::smf::{SmfSimulator, SmfState};
use opc_testbed::simulators::upf::{UpfSimulator, UpfState};
use testbed_common::*;

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
