use std::num::NonZeroU64;

use opc_proto_diameter::base::{
    APPLICATION_ID_COMMON_MESSAGES, INBAND_SECURITY_ID_NO_INBAND_SECURITY, INBAND_SECURITY_ID_TLS,
    RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED, RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
    RESULT_CODE_DIAMETER_SUCCESS,
};
use opc_proto_diameter::dictionary::CommandKind;
use opc_proto_diameter::peer::{
    negotiate_capabilities, parse_capabilities_exchange_answer, peer_answer_flags,
    peer_request_flags, PeerCapabilityAnswerPreparationError, PeerCapabilityBoundaryError,
    PeerCommandAdmissionError, PeerCommandClass, PeerMessageDirection, PeerProcedure,
    PeerProtectionError, PeerProtectionFailure, PeerProtectionMechanism, PeerProtectionPolicy,
    PeerProtectionRequirement, PeerProtectionSequence, PeerProtectionState, PeerSession,
    PeerSessionBindingError, PeerSessionBlocker, PeerSessionBoundError, PeerSessionGeneration,
    PeerSessionPolicy, PeerSessionState,
};
use opc_proto_diameter::peer::{
    AnswerDiagnostics, CapabilitiesExchangeAnswer, CapabilitiesExchangeErrorAnswer,
    DeviceWatchdogAnswer, DeviceWatchdogRequest, DisconnectCause, DisconnectPeerAnswer,
    DisconnectPeerRequest, HostIpAddress, PeerCapabilities, PeerIdentity,
};
use opc_proto_diameter::{ApplicationId, CommandCode, CommandFlags, Header, Message, VendorId};
use opc_protocol::{BorrowDecode, DecodeContext, EncodeContext};

const APP_ID: ApplicationId = ApplicationId::new(16_777_264);

fn generation(value: u64) -> PeerSessionGeneration {
    match NonZeroU64::new(value) {
        Some(value) => PeerSessionGeneration::new(value),
        None => panic!("test generation must be nonzero"),
    }
}

fn capabilities(host: &str, security_ids: Vec<u32>) -> PeerCapabilities {
    let mut capabilities = PeerCapabilities::new(
        PeerIdentity::new(host, "example.invalid"),
        vec![HostIpAddress::ipv4([192, 0, 2, 10])],
        VendorId::new(10415),
        "test-peer",
    );
    capabilities.auth_application_ids = vec![APP_ID];
    capabilities.inband_security_ids = security_ids;
    capabilities
}

fn tls_session(local_security_ids: Vec<u32>) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities("local.example.invalid", local_security_ids),
        PeerSessionPolicy::default().accept_application(APP_ID),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_tls_tcp()),
    )
}

fn dtls_session(local_security_ids: Vec<u32>) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities("local.example.invalid", local_security_ids),
        PeerSessionPolicy::default().accept_application(APP_ID),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_dtls_sctp()),
    )
}

fn direct_tls_session(local_security_ids: Vec<u32>) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities("local.example.invalid", local_security_ids),
        PeerSessionPolicy::default().accept_application(APP_ID),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_tls_tcp()),
    )
}

fn direct_dtls_session(local_security_ids: Vec<u32>) -> PeerSession {
    PeerSession::with_policy_and_protection(
        capabilities("local.example.invalid", local_security_ids),
        PeerSessionPolicy::default().accept_application(APP_ID),
        PeerProtectionPolicy::Require(PeerProtectionRequirement::direct_dtls_sctp()),
    )
}

fn cer(hop: u32, end: u32) -> Header {
    Header::new(
        peer_request_flags(PeerProcedure::CapabilitiesExchange),
        PeerProcedure::CapabilitiesExchange.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn cea(hop: u32, end: u32) -> Header {
    Header::new(
        peer_answer_flags(PeerProcedure::CapabilitiesExchange, false),
        PeerProcedure::CapabilitiesExchange.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn answer(remote: PeerCapabilities) -> CapabilitiesExchangeAnswer {
    CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        capabilities: remote,
        diagnostics: AnswerDiagnostics::default(),
    }
}

fn local_answer(result_code: u32, security_ids: Vec<u32>) -> CapabilitiesExchangeAnswer {
    CapabilitiesExchangeAnswer {
        result_code,
        capabilities: capabilities("local.example.invalid", security_ids),
        diagnostics: AnswerDiagnostics::default(),
    }
}

fn decode_message(wire: &[u8]) -> Message<'_> {
    let (tail, message) = match Message::decode(wire, DecodeContext::default()) {
        Ok(decoded) => decoded,
        Err(error) => panic!("CEA framing failed: {error}"),
    };
    assert!(tail.is_empty());
    message
}

fn app_request() -> Header {
    Header::new(
        CommandFlags::request(true),
        CommandCode::new(268),
        APP_ID,
        0x100,
        0x200,
    )
}

fn watchdog_request() -> Header {
    watchdog_request_with_ids(0x300, 0x400)
}

fn watchdog_request_with_ids(hop: u32, end: u32) -> Header {
    Header::new(
        peer_request_flags(PeerProcedure::DeviceWatchdog),
        PeerProcedure::DeviceWatchdog.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn watchdog_answer_header() -> Header {
    watchdog_answer_header_with_ids(0x300, 0x400)
}

fn watchdog_answer_header_with_ids(hop: u32, end: u32) -> Header {
    Header::new(
        peer_answer_flags(PeerProcedure::DeviceWatchdog, false),
        PeerProcedure::DeviceWatchdog.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn disconnect_request() -> Header {
    disconnect_request_with_ids(0x500, 0x600)
}

fn disconnect_request_with_ids(hop: u32, end: u32) -> Header {
    Header::new(
        peer_request_flags(PeerProcedure::DisconnectPeer),
        PeerProcedure::DisconnectPeer.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn disconnect_answer_header() -> Header {
    disconnect_answer_header_with_ids(0x500, 0x600)
}

fn disconnect_answer_header_with_ids(hop: u32, end: u32) -> Header {
    Header::new(
        peer_answer_flags(PeerProcedure::DisconnectPeer, false),
        PeerProcedure::DisconnectPeer.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        hop,
        end,
    )
}

fn watchdog_answer() -> DeviceWatchdogAnswer {
    DeviceWatchdogAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        origin_state_id: None,
        diagnostics: AnswerDiagnostics::default(),
    }
}

fn disconnect_peer_request() -> DisconnectPeerRequest {
    DisconnectPeerRequest {
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        disconnect_cause: DisconnectCause::Busy,
        origin_state_id: None,
    }
}

fn disconnect_peer_answer() -> DisconnectPeerAnswer {
    DisconnectPeerAnswer {
        result_code: RESULT_CODE_DIAMETER_SUCCESS,
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        origin_state_id: None,
        diagnostics: AnswerDiagnostics::default(),
    }
}

fn initiator_pending(
    connection: PeerSessionGeneration,
) -> (PeerSession, opc_proto_diameter::peer::PeerProtectionPending) {
    let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("connection generation failed: {error}");
    }
    let request_header = cer(11, 22);
    if let Err(error) = session.capabilities_request_sent_on(connection, &request_header) {
        panic!("CER boundary failed: {error}");
    }
    let answer_header = cea(11, 22);
    if let Err(error) = session.observe_capabilities_answer_on(
        connection,
        &answer_header,
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("CEA boundary failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("TLS protection must be pending"),
    };
    (session, pending)
}

fn protected_session(connection: PeerSessionGeneration) -> PeerSession {
    let (mut session, pending) = initiator_pending(connection);
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("TLS attestation failed: {error}");
    }
    session
}

#[test]
fn initiator_tls_blocks_all_diameter_until_exact_attestation() {
    let connection = generation(1);
    let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("connection generation failed: {error}");
    }
    let request_header = cer(11, 22);
    let admission =
        match session.admit_message(connection, PeerMessageDirection::Outbound, &request_header) {
            Ok(admission) => admission,
            Err(error) => panic!("CER admission failed: {error}"),
        };
    assert_eq!(admission.command(), PeerCommandClass::CapabilitiesExchange);
    assert!(!admission.is_protected());
    if let Err(error) = session.capabilities_request_sent_on(connection, &request_header) {
        panic!("CER transition failed: {error}");
    }

    for header in [app_request(), watchdog_request(), disconnect_request()] {
        assert!(session
            .admit_message(connection, PeerMessageDirection::Inbound, &header)
            .is_err());
    }

    let answer_header = cea(11, 22);
    assert!(session
        .admit_message(connection, PeerMessageDirection::Inbound, &answer_header)
        .is_ok());
    if let Err(error) = session.observe_capabilities_answer_on(
        connection,
        &answer_header,
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("CEA transition failed: {error}");
    }

    assert_eq!(session.state(), PeerSessionState::CapabilitiesPending);
    assert!(!session.readiness().traffic_ready);
    let readiness = session.protection_readiness();
    assert_eq!(readiness.state(), PeerProtectionState::Pending);
    assert_eq!(
        readiness.sequence(),
        Some(PeerProtectionSequence::InbandAfterCapabilities)
    );
    assert!(!readiness.protected_ready());
    assert!(!readiness.traffic_permitted());
    for header in [cer(33, 44), cea(33, 44), app_request(), watchdog_request()] {
        assert_eq!(
            session.admit_message(connection, PeerMessageDirection::Inbound, &header),
            Err(PeerCommandAdmissionError::ProtectionNotReady {
                command: PeerCommandClass::from_header(&header),
                protection_state: PeerProtectionState::Pending,
            })
        );
    }
    assert!(session.watchdog_request_sent().is_err());

    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("pending protection token missing"),
    };
    let transition = match session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        Ok(transition) => transition,
        Err(error) => panic!("TLS attestation failed: {error}"),
    };
    assert_eq!(transition.state(), PeerProtectionState::Protected);
    assert!(transition.protection().protected_ready());
    assert!(transition.session().traffic_ready);
    assert_eq!(session.state(), PeerSessionState::Negotiated);

    let admission =
        match session.admit_message(connection, PeerMessageDirection::Inbound, &app_request()) {
            Ok(admission) => admission,
            Err(error) => panic!("protected app admission failed: {error}"),
        };
    assert_eq!(admission.command(), PeerCommandClass::Application);
    assert_eq!(admission.direction(), PeerMessageDirection::Inbound);
    assert!(admission.is_protected());
    assert_eq!(admission.mechanism(), Some(PeerProtectionMechanism::TlsTcp));
}

#[test]
fn watchdog_probe_retains_application_readiness_and_requires_exact_answer_ids() {
    let connection = generation(50);
    let stale_connection = generation(49);
    let mut session = protected_session(connection);
    let request_header = watchdog_request_with_ids(0x301, 0x401);

    let transition = match session.watchdog_request_sent_on(connection, &request_header) {
        Ok(transition) => transition,
        Err(error) => panic!("watchdog request boundary failed: {error}"),
    };
    assert_eq!(transition.state, PeerSessionState::WatchdogProbing);
    assert!(transition.readiness.probing);
    assert!(transition.readiness.traffic_ready);
    assert!(session.protection_readiness().traffic_permitted());
    for direction in [
        PeerMessageDirection::Inbound,
        PeerMessageDirection::Outbound,
    ] {
        if let Err(error) = session.admit_message(connection, direction, &app_request()) {
            panic!("application traffic was blocked during watchdog probe: {error}");
        }
    }

    let probing_snapshot = session.snapshot();
    assert_eq!(
        session.observe_watchdog_answer_on(
            stale_connection,
            &watchdog_answer_header_with_ids(0x301, 0x401),
            &watchdog_answer(),
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    for mismatched_header in [
        watchdog_answer_header_with_ids(0x302, 0x401),
        watchdog_answer_header_with_ids(0x301, 0x402),
    ] {
        assert_eq!(
            session.observe_watchdog_answer_on(connection, &mismatched_header, &watchdog_answer(),),
            Err(PeerSessionBoundError::TransactionMismatch {
                operation: "observe_watchdog_answer",
            })
        );
        assert_eq!(session.snapshot(), probing_snapshot);
    }

    let answer_header = watchdog_answer_header_with_ids(0x301, 0x401);
    let transition =
        match session.observe_watchdog_answer_on(connection, &answer_header, &watchdog_answer()) {
            Ok(transition) => transition,
            Err(error) => panic!("exact watchdog answer was rejected: {error}"),
        };
    assert_eq!(transition.state, PeerSessionState::Negotiated);
    assert!(transition.readiness.traffic_ready);
    assert_eq!(
        session.observe_watchdog_answer_on(connection, &answer_header, &watchdog_answer()),
        Err(PeerSessionBoundError::TransactionMismatch {
            operation: "observe_watchdog_answer",
        })
    );

    let next_request = watchdog_request_with_ids(0x303, 0x403);
    if let Err(error) = session.watchdog_request_sent_on(connection, &next_request) {
        panic!("next watchdog transaction failed: {error}");
    }
    let transition = match session.watchdog_missed_on(connection) {
        Ok(transition) => transition,
        Err(error) => panic!("watchdog miss boundary failed: {error}"),
    };
    assert_eq!(transition.state, PeerSessionState::Degraded);
    assert!(!transition.readiness.traffic_ready);
    assert!(!session.protection_readiness().traffic_permitted());
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Inbound, &app_request(),),
        Err(PeerCommandAdmissionError::SessionNotReady {
            command: PeerCommandClass::Application,
            state: PeerSessionState::Degraded,
        })
    );
    assert_eq!(
        session.watchdog_missed_on(connection),
        Err(PeerSessionBoundError::TransactionMismatch {
            operation: "watchdog_missed",
        })
    );
}

#[test]
fn watchdog_suspect_retains_exact_dwa_and_peer_activity_resets_grace() {
    let connection = generation(52);
    let mut session = protected_session(connection);
    let request = watchdog_request_with_ids(0x321, 0x421);
    session
        .watchdog_request_sent_on(connection, &request)
        .unwrap_or_else(|error| panic!("watchdog request failed: {error}"));

    let suspect = session
        .watchdog_suspect_on(connection)
        .unwrap_or_else(|error| panic!("suspect transition failed: {error}"));
    assert_eq!(suspect.state, PeerSessionState::Degraded);
    assert!(!suspect.readiness.traffic_ready);
    assert_eq!(session.snapshot().missed_watchdogs, 1);
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Inbound, &app_request()),
        Err(PeerCommandAdmissionError::SessionNotReady {
            command: PeerCommandClass::Application,
            state: PeerSessionState::Degraded,
        })
    );

    session
        .watchdog_peer_activity_on(connection)
        .unwrap_or_else(|error| panic!("peer activity reset failed: {error}"));
    assert_eq!(session.state(), PeerSessionState::WatchdogProbing);
    assert!(session.snapshot().readiness.traffic_ready);
    assert_eq!(session.snapshot().missed_watchdogs, 0);
    assert_eq!(
        session.observe_watchdog_answer_on(
            connection,
            &watchdog_answer_header_with_ids(0x321, 0x422),
            &watchdog_answer(),
        ),
        Err(PeerSessionBoundError::TransactionMismatch {
            operation: "observe_watchdog_answer",
        })
    );

    let exact = session
        .observe_watchdog_answer_on(
            connection,
            &watchdog_answer_header_with_ids(0x321, 0x421),
            &watchdog_answer(),
        )
        .unwrap_or_else(|error| panic!("late exact DWA failed: {error}"));
    assert_eq!(exact.state, PeerSessionState::Negotiated);
    assert!(exact.readiness.traffic_ready);
}

#[test]
fn stray_watchdog_answers_fail_closed_without_mutating_peer_state() {
    let connection = generation(51);
    let mut session = protected_session(connection);
    let snapshot = session.snapshot();

    assert_eq!(
        session.observe_watchdog_answer_on(
            connection,
            &watchdog_answer_header_with_ids(0x311, 0x411),
            &watchdog_answer(),
        ),
        Err(PeerSessionBoundError::TransactionMismatch {
            operation: "observe_watchdog_answer",
        })
    );
    assert_eq!(session.snapshot(), snapshot);
    assert_eq!(
        PeerSessionBoundError::TransactionMismatch {
            operation: "observe_watchdog_answer",
        }
        .as_str(),
        "diameter_peer_lifecycle_transaction_mismatch"
    );
}

#[test]
fn disconnect_answers_require_both_ids_for_local_and_peer_initiated_transactions() {
    let local_connection = generation(52);
    let mut local_session = protected_session(local_connection);
    let local_request_header = disconnect_request_with_ids(0x501, 0x601);
    if let Err(error) = local_session.disconnect_request_sent_on(
        local_connection,
        &local_request_header,
        DisconnectCause::Busy,
    ) {
        panic!("local DPR boundary failed: {error}");
    }
    let disconnecting_snapshot = local_session.snapshot();
    for mismatched_header in [
        disconnect_answer_header_with_ids(0x502, 0x601),
        disconnect_answer_header_with_ids(0x501, 0x602),
    ] {
        assert_eq!(
            local_session.observe_disconnect_answer_on(
                local_connection,
                &mismatched_header,
                &disconnect_peer_answer(),
            ),
            Err(PeerSessionBoundError::TransactionMismatch {
                operation: "observe_disconnect_answer",
            })
        );
        assert_eq!(local_session.snapshot(), disconnecting_snapshot);
    }
    let local_answer_header = disconnect_answer_header_with_ids(0x501, 0x601);
    if let Err(error) = local_session.observe_disconnect_answer_on(
        local_connection,
        &local_answer_header,
        &disconnect_peer_answer(),
    ) {
        panic!("exact local DPA boundary failed: {error}");
    }
    assert_eq!(local_session.state(), PeerSessionState::Reconnecting);
    assert!(local_session
        .observe_disconnect_answer_on(
            local_connection,
            &local_answer_header,
            &disconnect_peer_answer(),
        )
        .is_err());

    let peer_connection = generation(53);
    let mut peer_session = protected_session(peer_connection);
    let peer_request_header = disconnect_request_with_ids(0x511, 0x611);
    if let Err(error) = peer_session.observe_disconnect_request_on(
        peer_connection,
        &peer_request_header,
        &disconnect_peer_request(),
    ) {
        panic!("peer DPR boundary failed: {error}");
    }
    let draining_snapshot = peer_session.snapshot();
    for mismatched_header in [
        disconnect_answer_header_with_ids(0x512, 0x611),
        disconnect_answer_header_with_ids(0x511, 0x612),
    ] {
        assert_eq!(
            peer_session.disconnect_answer_sent_on(
                peer_connection,
                &mismatched_header,
                &disconnect_peer_answer(),
            ),
            Err(PeerSessionBoundError::TransactionMismatch {
                operation: "disconnect_answer_sent",
            })
        );
        assert_eq!(peer_session.snapshot(), draining_snapshot);
    }
    let peer_answer_header = disconnect_answer_header_with_ids(0x511, 0x611);
    if let Err(error) = peer_session.disconnect_answer_sent_on(
        peer_connection,
        &peer_answer_header,
        &disconnect_peer_answer(),
    ) {
        panic!("exact peer DPA boundary failed: {error}");
    }
    assert_eq!(peer_session.state(), PeerSessionState::Reconnecting);
    assert!(peer_session
        .disconnect_answer_sent_on(
            peer_connection,
            &peer_answer_header,
            &disconnect_peer_answer(),
        )
        .is_err());
}

#[test]
fn responder_prepares_one_exact_typed_cea_before_handshake_pending() {
    let connection = generation(2);
    let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("connection generation failed: {error}");
    }
    let request_header = cer(101, 202);
    if let Err(error) = session.capabilities_request_received_on(
        connection,
        &request_header,
        capabilities("remote.example.invalid", vec![INBAND_SECURITY_ID_TLS]),
    ) {
        panic!("CER receive failed: {error}");
    }
    assert!(session.pending_protection().is_none());
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );

    let committed_answer = local_answer(RESULT_CODE_DIAMETER_SUCCESS, vec![INBAND_SECURITY_ID_TLS]);
    let answer_header = cea(101, 202);
    let before_prepare = session.snapshot();
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Outbound, &cea(101, 203),),
        Err(PeerCommandAdmissionError::SessionNotReady {
            command: PeerCommandClass::CapabilitiesExchange,
            state: PeerSessionState::CapabilitiesPending,
        })
    );
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Outbound, &answer_header,),
        Err(PeerCommandAdmissionError::SessionNotReady {
            command: PeerCommandClass::CapabilitiesExchange,
            state: PeerSessionState::CapabilitiesPending,
        })
    );
    assert_eq!(session.snapshot(), before_prepare);
    assert_eq!(
        session.prepare_capabilities_answer_on(
            connection,
            &local_answer(
                RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
                vec![INBAND_SECURITY_ID_TLS],
            ),
            EncodeContext::default(),
        ),
        Err(PeerCapabilityAnswerPreparationError::Boundary(
            PeerCapabilityBoundaryError::AnswerOutcomeMismatch,
        ))
    );
    assert_eq!(
        session.prepare_capabilities_answer_on(
            connection,
            &local_answer(
                RESULT_CODE_DIAMETER_SUCCESS,
                vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY],
            ),
            EncodeContext::default(),
        ),
        Err(PeerCapabilityAnswerPreparationError::Boundary(
            PeerCapabilityBoundaryError::AnswerSecurityMismatch,
        ))
    );
    assert_eq!(session.snapshot(), before_prepare);
    let emission = match session.prepare_capabilities_answer_on(
        connection,
        &committed_answer,
        EncodeContext::default(),
    ) {
        Ok(emission) => emission,
        Err(error) => panic!("CEA preparation failed: {error}"),
    };
    let emission_debug = format!("{emission:?}");
    assert!(emission_debug.contains("<redacted>"));
    assert!(!emission_debug.contains("local.example.invalid"));
    let emitted_message = decode_message(emission.as_bytes());
    assert_eq!(
        emitted_message.header.hop_by_hop_identifier,
        answer_header.hop_by_hop_identifier
    );
    assert_eq!(
        emitted_message.header.end_to_end_identifier,
        answer_header.end_to_end_identifier
    );
    assert_eq!(emitted_message.header.flags, answer_header.flags);
    let emitted_answer =
        match parse_capabilities_exchange_answer(&emitted_message, DecodeContext::default()) {
            Ok(answer) => answer,
            Err(error) => panic!("prepared CEA parse failed: {error}"),
        };
    assert_eq!(emitted_answer, committed_answer);
    let mut contradictory_wire = emission.as_bytes().to_vec();
    contradictory_wire[4] |= CommandFlags::ERROR;
    let contradictory_message = decode_message(&contradictory_wire);
    assert!(
        parse_capabilities_exchange_answer(&contradictory_message, DecodeContext::default(),)
            .is_err()
    );
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::Pending
    );
    assert_eq!(
        session.prepare_capabilities_answer_on(
            connection,
            &committed_answer,
            EncodeContext::default(),
        ),
        Err(PeerCapabilityAnswerPreparationError::Boundary(
            PeerCapabilityBoundaryError::TransactionMismatch,
        ))
    );
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Outbound, &answer_header),
        Err(PeerCommandAdmissionError::ProtectionNotReady {
            command: PeerCommandClass::CapabilitiesExchange,
            protection_state: PeerProtectionState::Pending,
        })
    );
}

#[test]
fn inbound_cea_error_bit_must_match_result_family_before_transaction_consumption() {
    let success_generation = generation(29);
    let mut success_session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = success_session.begin_connection_generation(success_generation) {
        panic!("success generation failed: {error}");
    }
    if let Err(error) =
        success_session.capabilities_request_sent_on(success_generation, &cer(601, 602))
    {
        panic!("success CER failed: {error}");
    }
    let success_answer = answer(capabilities(
        "remote.example.invalid",
        vec![INBAND_SECURITY_ID_TLS],
    ));
    let success_with_error_bit = Header::new(
        peer_answer_flags(PeerProcedure::CapabilitiesExchange, true),
        PeerProcedure::CapabilitiesExchange.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        601,
        602,
    );
    let success_snapshot = success_session.snapshot();
    assert_eq!(
        success_session.observe_capabilities_answer_on(
            success_generation,
            &success_with_error_bit,
            &success_answer,
        ),
        Err(PeerCapabilityBoundaryError::AnswerErrorBitMismatch)
    );
    assert_eq!(success_session.snapshot(), success_snapshot);
    if let Err(error) = success_session.observe_capabilities_answer_on(
        success_generation,
        &cea(601, 602),
        &success_answer,
    ) {
        panic!("corrected success CEA failed: {error}");
    }

    let protocol_error_generation = generation(32);
    let mut protocol_error_session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) =
        protocol_error_session.begin_connection_generation(protocol_error_generation)
    {
        panic!("protocol-error generation failed: {error}");
    }
    if let Err(error) = protocol_error_session
        .capabilities_request_sent_on(protocol_error_generation, &cer(603, 604))
    {
        panic!("protocol-error CER failed: {error}");
    }
    let protocol_error_answer = CapabilitiesExchangeErrorAnswer {
        result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        diagnostics: AnswerDiagnostics::default(),
    };
    let protocol_error_snapshot = protocol_error_session.snapshot();
    assert_eq!(
        protocol_error_session.observe_capabilities_protocol_error_answer_on(
            protocol_error_generation,
            &cea(603, 604),
            &protocol_error_answer,
        ),
        Err(PeerCapabilityBoundaryError::AnswerErrorBitMismatch)
    );
    assert_eq!(protocol_error_session.snapshot(), protocol_error_snapshot);
    let protocol_error_header = Header::new(
        peer_answer_flags(PeerProcedure::CapabilitiesExchange, true),
        PeerProcedure::CapabilitiesExchange.command_code(),
        APPLICATION_ID_COMMON_MESSAGES,
        603,
        604,
    );
    if let Err(error) = protocol_error_session.observe_capabilities_protocol_error_answer_on(
        protocol_error_generation,
        &protocol_error_header,
        &protocol_error_answer,
    ) {
        panic!("corrected protocol-error CEA failed: {error}");
    }
    assert_eq!(protocol_error_session.state(), PeerSessionState::Failed);
}

#[test]
fn opposite_capability_role_requires_transport_election_and_a_new_generation() {
    for initiator_first in [true, false] {
        let losing_connection = generation(if initiator_first { 3 } else { 4 });
        let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
        if let Err(error) = session.begin_connection_generation(losing_connection) {
            panic!("connection generation failed: {error}");
        }
        if initiator_first {
            if let Err(error) =
                session.capabilities_request_sent_on(losing_connection, &cer(10, 20))
            {
                panic!("outbound CER failed: {error}");
            }
            let before_conflict = session.snapshot();
            assert_eq!(
                session.capabilities_request_received_on(
                    losing_connection,
                    &cer(30, 40),
                    capabilities("remote.example.invalid", vec![INBAND_SECURITY_ID_TLS]),
                ),
                Err(PeerCapabilityBoundaryError::ConflictingTransaction)
            );
            assert_eq!(session.snapshot(), before_conflict);
        } else {
            if let Err(error) = session.capabilities_request_received_on(
                losing_connection,
                &cer(30, 40),
                capabilities("remote.example.invalid", vec![INBAND_SECURITY_ID_TLS]),
            ) {
                panic!("inbound CER failed: {error}");
            }
            let before_conflict = session.snapshot();
            assert_eq!(
                session.capabilities_request_sent_on(losing_connection, &cer(10, 20)),
                Err(PeerCapabilityBoundaryError::ConflictingTransaction)
            );
            assert_eq!(session.snapshot(), before_conflict);
        }

        let winning_connection = generation(if initiator_first { 103 } else { 104 });
        if let Err(error) = session.begin_connection_generation(winning_connection) {
            panic!("winning connection generation failed: {error}");
        }
        if let Err(error) = session.capabilities_request_received_on(
            winning_connection,
            &cer(50, 60),
            capabilities("remote.example.invalid", vec![INBAND_SECURITY_ID_TLS]),
        ) {
            panic!("winner CER receive failed: {error}");
        }
        if let Err(error) = session.prepare_capabilities_answer_on(
            winning_connection,
            &local_answer(RESULT_CODE_DIAMETER_SUCCESS, vec![INBAND_SECURITY_ID_TLS]),
            EncodeContext::default(),
        ) {
            panic!("winner CEA preparation failed: {error}");
        }
        assert_eq!(
            session.protection_readiness().state(),
            PeerProtectionState::Pending
        );
        assert!(session.pending_protection().is_some());
    }
}

#[test]
fn current_wrong_mechanism_and_handshake_failures_are_terminal() {
    let (mut wrong, pending) = initiator_pending(generation(5));
    assert_eq!(
        wrong.attest_mutually_authenticated_protection(
            &pending,
            PeerProtectionMechanism::Unprotected,
        ),
        Err(PeerProtectionError::MechanismMismatch {
            expected: PeerProtectionMechanism::TlsTcp,
            actual: PeerProtectionMechanism::Unprotected,
        })
    );
    assert_eq!(wrong.state(), PeerSessionState::Failed);
    assert_eq!(
        wrong.protection_readiness().failure(),
        Some(PeerProtectionFailure::DowngradeRejected)
    );
    assert!(!wrong.readiness().traffic_ready);
    assert!(matches!(
        wrong.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp,),
        Err(PeerProtectionError::NotPending { .. })
    ));

    let (mut failed, pending) = initiator_pending(generation(6));
    let transition = match failed
        .fail_pending_protection(&pending, PeerProtectionFailure::PeerAuthenticationFailed)
    {
        Ok(transition) => transition,
        Err(error) => panic!("failure attestation rejected: {error}"),
    };
    assert_eq!(transition.state(), PeerProtectionState::Failed);
    assert_eq!(
        transition.protection().failure(),
        Some(PeerProtectionFailure::PeerAuthenticationFailed)
    );
    assert!(!transition.session().traffic_ready);
}

#[test]
fn inband_security_id_one_keeps_tls_and_dtls_transport_attestation_distinct() {
    let connection = generation(7);
    let mut wrong_transport = dtls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = wrong_transport.begin_connection_generation(connection) {
        panic!("DTLS connection generation failed: {error}");
    }
    if let Err(error) = wrong_transport.capabilities_request_sent_on(connection, &cer(71, 72)) {
        panic!("DTLS CER failed: {error}");
    }
    if let Err(error) = wrong_transport.observe_capabilities_answer_on(
        connection,
        &cea(71, 72),
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("DTLS CEA failed: {error}");
    }
    let pending = match wrong_transport.pending_protection() {
        Some(pending) => pending,
        None => panic!("DTLS protection must be pending"),
    };
    assert_eq!(pending.mechanism(), PeerProtectionMechanism::DtlsSctp);
    assert_eq!(
        pending.sequence(),
        PeerProtectionSequence::InbandAfterCapabilities
    );
    assert_eq!(
        wrong_transport
            .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp),
        Err(PeerProtectionError::MechanismMismatch {
            expected: PeerProtectionMechanism::DtlsSctp,
            actual: PeerProtectionMechanism::TlsTcp,
        })
    );
    assert_eq!(wrong_transport.state(), PeerSessionState::Failed);

    let connection = generation(70);
    let mut exact_transport = dtls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = exact_transport.begin_connection_generation(connection) {
        panic!("exact DTLS generation failed: {error}");
    }
    if let Err(error) = exact_transport.capabilities_request_sent_on(connection, &cer(73, 74)) {
        panic!("exact DTLS CER failed: {error}");
    }
    if let Err(error) = exact_transport.observe_capabilities_answer_on(
        connection,
        &cea(73, 74),
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("exact DTLS CEA failed: {error}");
    }
    let pending = match exact_transport.pending_protection() {
        Some(pending) => pending,
        None => panic!("exact DTLS protection must be pending"),
    };
    if let Err(error) = exact_transport
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::DtlsSctp)
    {
        panic!("exact DTLS attestation failed: {error}");
    }
    assert!(exact_transport.protection_readiness().protected_ready());
    assert_eq!(
        exact_transport.protection_readiness().mechanism(),
        Some(PeerProtectionMechanism::DtlsSctp)
    );
}

#[test]
fn omitted_inband_security_has_exact_rfc_default_for_both_capability_roles() {
    let cases = [
        (
            vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY],
            vec![INBAND_SECURITY_ID_TLS],
            false,
        ),
        (vec![], vec![INBAND_SECURITY_ID_TLS], false),
        (vec![], vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY], true),
        (vec![], vec![], true),
    ];

    for (index, (local_ids, remote_ids, has_default_common)) in cases.into_iter().enumerate() {
        let local = capabilities("local.example.invalid", local_ids.clone());
        let remote = capabilities("remote.example.invalid", remote_ids.clone());
        let negotiated = negotiate_capabilities(&local, &remote);
        assert_eq!(
            negotiated.inband_security_ids,
            if has_default_common {
                vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY]
            } else {
                vec![]
            }
        );

        let policy = if has_default_common {
            PeerProtectionPolicy::CompatibilityUnprotected
        } else {
            PeerProtectionPolicy::Require(PeerProtectionRequirement::inband_tls_tcp())
        };
        let expected_result = if has_default_common {
            RESULT_CODE_DIAMETER_SUCCESS
        } else {
            RESULT_CODE_DIAMETER_NO_COMMON_SECURITY
        };

        let mut initiator = PeerSession::with_policy_and_protection(
            local.clone(),
            PeerSessionPolicy::default().accept_application(APP_ID),
            policy,
        );
        let initiator_generation = generation(200 + index as u64);
        if let Err(error) = initiator.begin_connection_generation(initiator_generation) {
            panic!("initiator generation failed: {error}");
        }
        if let Err(error) = initiator.capabilities_request_sent_on(initiator_generation, &cer(1, 2))
        {
            panic!("initiator CER failed: {error}");
        }
        let remote_answer = CapabilitiesExchangeAnswer {
            result_code: expected_result,
            capabilities: remote.clone(),
            diagnostics: AnswerDiagnostics::default(),
        };
        if let Err(error) = initiator.observe_capabilities_answer_on(
            initiator_generation,
            &cea(1, 2),
            &remote_answer,
        ) {
            panic!("initiator CEA failed: {error}");
        }
        assert_eq!(
            initiator.state(),
            if has_default_common {
                PeerSessionState::Negotiated
            } else {
                PeerSessionState::Failed
            }
        );

        let mut responder = PeerSession::with_policy_and_protection(
            local,
            PeerSessionPolicy::default().accept_application(APP_ID),
            policy,
        );
        let responder_generation = generation(300 + index as u64);
        if let Err(error) = responder.begin_connection_generation(responder_generation) {
            panic!("responder generation failed: {error}");
        }
        if let Err(error) =
            responder.capabilities_request_received_on(responder_generation, &cer(3, 4), remote)
        {
            panic!("responder CER failed: {error}");
        }
        assert_eq!(
            responder
                .last_capability_projection()
                .map(|projection| projection.result_code),
            Some(expected_result)
        );
        if let Err(error) = responder.prepare_capabilities_answer_on(
            responder_generation,
            &local_answer(expected_result, local_ids),
            EncodeContext::default(),
        ) {
            panic!("responder CEA preparation failed: {error}");
        }
        assert_eq!(
            responder.state(),
            if has_default_common {
                PeerSessionState::Negotiated
            } else {
                PeerSessionState::Failed
            }
        );
    }
}

#[test]
fn reconnect_rejects_late_capability_success_and_failure_without_poisoning() {
    let old_connection = generation(8);
    let (mut session, old_pending) = initiator_pending(old_connection);
    if let Err(error) = session.schedule_reconnect_on(old_connection) {
        panic!("old connection reconnect failed: {error}");
    }
    let new_connection = generation(9);
    if let Err(error) = session.begin_connection_generation(new_connection) {
        panic!("new connection generation failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(new_connection, &cer(9, 10)) {
        panic!("new CER failed: {error}");
    }

    assert_eq!(
        session.observe_capabilities_answer_on(
            old_connection,
            &cea(11, 22),
            &answer(capabilities(
                "old.example.invalid",
                vec![INBAND_SECURITY_ID_TLS],
            )),
        ),
        Err(PeerCapabilityBoundaryError::StaleGeneration)
    );
    assert_eq!(
        session.attest_mutually_authenticated_protection(
            &old_pending,
            PeerProtectionMechanism::TlsTcp,
        ),
        Err(PeerProtectionError::StaleSessionGeneration)
    );
    assert_eq!(
        session.fail_pending_protection(&old_pending, PeerProtectionFailure::HandshakeFailed),
        Err(PeerProtectionError::StaleSessionGeneration)
    );
    assert_eq!(session.state(), PeerSessionState::CapabilitiesPending);
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );

    if let Err(error) = session.observe_capabilities_answer_on(
        new_connection,
        &cea(9, 10),
        &answer(capabilities(
            "new.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("new CEA failed: {error}");
    }
    let new_pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("new pending token missing"),
    };
    if let Err(error) = session
        .attest_mutually_authenticated_protection(&new_pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("new attestation failed: {error}");
    }
    assert!(session.readiness().traffic_ready);
}

#[test]
fn loser_generation_and_generation_reuse_cannot_affect_winner() {
    let loser = generation(10);
    let winner = generation(11);
    let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(loser) {
        panic!("loser bind failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(loser, &cer(10, 10)) {
        panic!("loser CER failed: {error}");
    }
    if let Err(error) = session.begin_connection_generation(winner) {
        panic!("winner bind failed: {error}");
    }
    assert_eq!(
        session.capabilities_request_received_on(
            loser,
            &cer(20, 20),
            capabilities("loser.example.invalid", vec![INBAND_SECURITY_ID_TLS],),
        ),
        Err(PeerCapabilityBoundaryError::StaleGeneration)
    );
    assert_eq!(
        session.begin_connection_generation(winner),
        Err(PeerSessionBindingError::GenerationNotAdvanced)
    );
    assert_eq!(
        session.begin_connection_generation(loser),
        Err(PeerSessionBindingError::GenerationNotAdvanced)
    );
    assert_eq!(session.state(), PeerSessionState::Idle);
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );
}

#[test]
fn required_tls_prefers_tls_and_zero_only_returns_5017_without_error_bit() {
    let connection = generation(12);
    let mut preferred = tls_session(vec![
        INBAND_SECURITY_ID_NO_INBAND_SECURITY,
        INBAND_SECURITY_ID_TLS,
    ]);
    if let Err(error) = preferred.begin_connection_generation(connection) {
        panic!("preferred bind failed: {error}");
    }
    if let Err(error) = preferred.capabilities_request_received_on(
        connection,
        &cer(1, 1),
        capabilities(
            "remote.example.invalid",
            vec![
                INBAND_SECURITY_ID_NO_INBAND_SECURITY,
                INBAND_SECURITY_ID_TLS,
            ],
        ),
    ) {
        panic!("preferred CER failed: {error}");
    }
    assert_eq!(
        preferred.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );
    let preferred_answer = local_answer(
        RESULT_CODE_DIAMETER_SUCCESS,
        vec![
            INBAND_SECURITY_ID_NO_INBAND_SECURITY,
            INBAND_SECURITY_ID_TLS,
        ],
    );
    if let Err(error) = preferred.prepare_capabilities_answer_on(
        connection,
        &preferred_answer,
        EncodeContext::default(),
    ) {
        panic!("preferred CEA preparation failed: {error}");
    }
    assert_eq!(
        preferred.protection_readiness().mechanism(),
        Some(PeerProtectionMechanism::TlsTcp)
    );

    let mut rejected = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    let rejected_connection = generation(13);
    if let Err(error) = rejected.begin_connection_generation(rejected_connection) {
        panic!("rejected bind failed: {error}");
    }
    if let Err(error) = rejected.capabilities_request_received_on(
        rejected_connection,
        &cer(2, 2),
        capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY],
        ),
    ) {
        panic!("rejected CER boundary failed: {error}");
    }
    let projection = match rejected.last_capability_projection() {
        Some(projection) => projection,
        None => panic!("rejected projection missing"),
    };
    assert_eq!(
        projection.result_code,
        RESULT_CODE_DIAMETER_NO_COMMON_SECURITY
    );
    assert_eq!(rejected.state(), PeerSessionState::Failed);
    assert!(!opc_proto_diameter::peer::result_code_requires_error_bit(
        RESULT_CODE_DIAMETER_NO_COMMON_SECURITY
    ));
    let failure_answer_header = cea(2, 2);
    assert_eq!(
        rejected.admit_message(
            rejected_connection,
            PeerMessageDirection::Outbound,
            &failure_answer_header,
        ),
        Err(PeerCommandAdmissionError::ProtectionNotReady {
            command: PeerCommandClass::CapabilitiesExchange,
            protection_state: PeerProtectionState::Failed,
        })
    );
    let failure_answer = local_answer(
        RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
        vec![INBAND_SECURITY_ID_TLS],
    );
    let failure_emission = match rejected.prepare_capabilities_answer_on(
        rejected_connection,
        &failure_answer,
        EncodeContext::default(),
    ) {
        Ok(emission) => emission,
        Err(error) => panic!("5017 CEA preparation failed: {error}"),
    };
    let failure_message = decode_message(failure_emission.as_bytes());
    assert!(!failure_message.header.flags.is_error());
    assert_eq!(failure_message.header.hop_by_hop_identifier, 2);
    assert_eq!(failure_message.header.end_to_end_identifier, 2);
    let parsed_failure =
        match parse_capabilities_exchange_answer(&failure_message, DecodeContext::default()) {
            Ok(answer) => answer,
            Err(error) => panic!("5017 CEA parse failed: {error}"),
        };
    assert_eq!(
        parsed_failure.result_code,
        RESULT_CODE_DIAMETER_NO_COMMON_SECURITY
    );
    assert_eq!(
        parsed_failure.capabilities.inband_security_ids,
        vec![INBAND_SECURITY_ID_TLS]
    );
    assert_eq!(parsed_failure, failure_answer);
    assert_eq!(rejected.state(), PeerSessionState::Failed);
    assert_eq!(
        rejected.prepare_capabilities_answer_on(
            rejected_connection,
            &failure_answer,
            EncodeContext::default(),
        ),
        Err(PeerCapabilityAnswerPreparationError::Boundary(
            PeerCapabilityBoundaryError::TransactionMismatch,
        ))
    );
}

#[test]
fn legacy_cleartext_remains_ready_but_never_protected() {
    let local = capabilities(
        "local.example.invalid",
        vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY],
    );
    let mut session = PeerSession::with_policy(
        local,
        PeerSessionPolicy::default().accept_application(APP_ID),
    );
    let connection = generation(14);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("cleartext bind failed: {error}");
    }
    let _transition = session.capabilities_request_sent();
    let _transition = session.observe_capabilities_answer(&answer(capabilities(
        "remote.example.invalid",
        vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY],
    )));
    assert_eq!(session.state(), PeerSessionState::Negotiated);
    assert!(session.readiness().traffic_ready);
    let protection = session.protection_readiness();
    assert_eq!(protection.state(), PeerProtectionState::Unprotected);
    assert_eq!(
        protection.mechanism(),
        Some(PeerProtectionMechanism::Unprotected)
    );
    assert!(!protection.protected_ready());
    assert!(protection.traffic_permitted());
    assert!(session.protection_evidence().is_none());
    let admission =
        match session.admit_message(connection, PeerMessageDirection::Outbound, &app_request()) {
            Ok(admission) => admission,
            Err(error) => panic!("cleartext app admission failed: {error}"),
        };
    assert!(!admission.is_protected());
    assert_eq!(admission.protection_generation(), None);
}

#[test]
fn legacy_tls_evidence_fails_closed_and_clone_cannot_copy_authority() {
    let mut unbound = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    let _transition = unbound.capabilities_request_sent();
    let transition = unbound.observe_capabilities_answer(&answer(capabilities(
        "remote.example.invalid",
        vec![INBAND_SECURITY_ID_TLS],
    )));
    assert_eq!(transition.state, PeerSessionState::Failed);
    assert_eq!(
        unbound.protection_readiness().failure(),
        Some(PeerProtectionFailure::UnboundCapabilityEvidence)
    );

    let capability_connection = generation(16);
    let mut capability_pending = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = capability_pending.begin_connection_generation(capability_connection) {
        panic!("capability-pending bind failed: {error}");
    }
    if let Err(error) =
        capability_pending.capabilities_request_sent_on(capability_connection, &cer(41, 42))
    {
        panic!("capability-pending CER failed: {error}");
    }
    let capability_clone = capability_pending.clone();
    assert_eq!(capability_clone.state(), PeerSessionState::Failed);
    assert!(capability_clone.pending_protection().is_none());
    assert!(!capability_clone.readiness().traffic_ready);
    if let Err(error) = capability_pending.observe_capabilities_answer_on(
        capability_connection,
        &cea(41, 42),
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("original capability completion failed: {error}");
    }
    assert!(capability_pending.pending_protection().is_some());

    let (mut pending_session, pending) = initiator_pending(generation(15));
    let pending_clone = pending_session.clone();
    assert_eq!(pending_clone.state(), PeerSessionState::Failed);
    assert!(pending_clone.pending_protection().is_none());
    assert!(!pending_clone.readiness().traffic_ready);
    if let Err(error) = pending_session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("original attestation failed: {error}");
    }
    let protected_clone = pending_session.clone();
    assert_eq!(protected_clone.state(), PeerSessionState::Failed);
    assert!(!protected_clone.protection_readiness().protected_ready());
    assert!(!protected_clone.readiness().traffic_ready);
}

#[test]
fn duplicate_completion_and_redacted_diagnostics_fail_safely() {
    let secret_generation = generation(424_242);
    let (mut session, pending) = initiator_pending(secret_generation);
    let pending_debug = format!("{pending:?}");
    let readiness_debug = format!("{:?}", session.protection_readiness());
    let session_debug = format!("{session:?}");
    for debug in [&pending_debug, &readiness_debug, &session_debug] {
        assert!(!debug.contains("424242"));
        assert!(!debug.contains("remote.example.invalid"));
        assert!(!debug.contains("192.0.2.10"));
    }
    assert!(pending_debug.contains("<redacted>"));

    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("first completion failed: {error}");
    }
    assert!(matches!(
        session
            .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp,),
        Err(PeerProtectionError::NotPending { .. })
    ));
    assert!(matches!(
        session.fail_pending_protection(&pending, PeerProtectionFailure::HandshakeFailed),
        Err(PeerProtectionError::NotPending { .. })
    ));
    assert!(session.readiness().traffic_ready);

    let error = PeerCommandAdmissionError::StaleGeneration;
    assert_eq!(format!("{error}"), "diameter_peer_command_stale_generation");
    assert_eq!(
        format!("{:?}", secret_generation),
        "PeerSessionGeneration(<redacted>)"
    );
    assert_eq!(CommandKind::Request, app_request().flags.command_kind());
}

#[test]
fn pending_control_commands_and_connection_ending_paths_revoke_readiness() {
    let pending_generation = generation(20);
    let (mut pending_session, _pending) = initiator_pending(pending_generation);
    let watchdog = DeviceWatchdogRequest {
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        origin_state_id: None,
    };
    let pending_snapshot = pending_session.snapshot();
    assert_eq!(
        pending_session.observe_watchdog_request_on(
            pending_generation,
            &watchdog_request(),
            &watchdog,
        ),
        Err(PeerSessionBoundError::CommandNotAdmitted {
            operation: "observe_watchdog_request",
            reason: PeerCommandAdmissionError::ProtectionNotReady {
                command: PeerCommandClass::DeviceWatchdog,
                protection_state: PeerProtectionState::Pending,
            },
        })
    );
    assert_eq!(pending_session.snapshot(), pending_snapshot);
    assert_eq!(
        pending_session.protection_readiness().state(),
        PeerProtectionState::Pending
    );

    let reconnect_generation = generation(21);
    let mut reconnect = protected_session(reconnect_generation);
    if let Err(error) = reconnect.schedule_reconnect_on(reconnect_generation) {
        panic!("reconnect boundary failed: {error}");
    }
    assert!(!reconnect.protection_readiness().protected_ready());
    assert!(!reconnect.readiness().traffic_ready);

    let backoff_generation = generation(22);
    let mut backoff = protected_session(backoff_generation);
    if let Err(error) = backoff.enter_backoff_on(backoff_generation) {
        panic!("backoff boundary failed: {error}");
    }
    assert!(!backoff.protection_readiness().protected_ready());

    let local_disconnect_generation = generation(23);
    let mut local_disconnect = protected_session(local_disconnect_generation);
    if let Err(error) = local_disconnect.disconnect_request_sent_on(
        local_disconnect_generation,
        &disconnect_request(),
        DisconnectCause::Busy,
    ) {
        panic!("local disconnect boundary failed: {error}");
    }
    assert!(!local_disconnect.protection_readiness().protected_ready());
    let local_answer = disconnect_peer_answer();
    if let Err(error) = local_disconnect.observe_disconnect_answer_on(
        local_disconnect_generation,
        &disconnect_answer_header(),
        &local_answer,
    ) {
        panic!("local disconnect answer boundary failed: {error}");
    }

    let remote_disconnect_generation = generation(24);
    let mut remote_disconnect = protected_session(remote_disconnect_generation);
    let request = disconnect_peer_request();
    if let Err(error) = remote_disconnect.observe_disconnect_request_on(
        remote_disconnect_generation,
        &disconnect_request(),
        &request,
    ) {
        panic!("remote disconnect boundary failed: {error}");
    }
    assert!(!remote_disconnect.protection_readiness().protected_ready());
    let remote_answer = disconnect_peer_answer();
    if let Err(error) = remote_disconnect.disconnect_answer_sent_on(
        remote_disconnect_generation,
        &disconnect_answer_header(),
        &remote_answer,
    ) {
        panic!("remote disconnect answer boundary failed: {error}");
    }

    let failed_generation = generation(26);
    let mut failed = protected_session(failed_generation);
    if let Err(error) = failed.fail_on(failed_generation, PeerSessionBlocker::SessionFailed) {
        panic!("failure boundary failed: {error}");
    }
    assert!(!failed.protection_readiness().protected_ready());
    assert!(!failed.readiness().traffic_ready);

    let (mut interrupted, pending) = initiator_pending(generation(27));
    let transition = match interrupted
        .fail_pending_protection(&pending, PeerProtectionFailure::HandshakeFailed)
    {
        Ok(transition) => transition,
        Err(error) => panic!("handshake interruption failed: {error}"),
    };
    assert_eq!(
        transition.protection().failure(),
        Some(PeerProtectionFailure::HandshakeFailed)
    );
    assert!(!transition.protection().protected_ready());
}

#[test]
fn capability_only_phase_rejects_every_lifecycle_message_without_mutation() {
    let connection = generation(28);
    let mut session = tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("connection generation failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(connection, &cer(91, 92)) {
        panic!("CER boundary failed: {error}");
    }
    assert_eq!(session.state(), PeerSessionState::CapabilitiesPending);
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );

    let snapshot = session.snapshot();
    let rejection = |operation: &'static str, command| PeerSessionBoundError::CommandNotAdmitted {
        operation,
        reason: PeerCommandAdmissionError::SessionNotReady {
            command,
            state: PeerSessionState::CapabilitiesPending,
        },
    };
    let watchdog_request_value = DeviceWatchdogRequest {
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        origin_state_id: None,
    };
    let watchdog_answer_value = watchdog_answer();
    let disconnect_request_value = disconnect_peer_request();
    let disconnect_answer_value = disconnect_peer_answer();

    assert_eq!(
        session.watchdog_request_sent_on(connection, &watchdog_answer_header()),
        Err(PeerSessionBoundError::InvalidPeerHeader {
            operation: "watchdog_request_sent",
        })
    );
    assert_eq!(
        session.watchdog_request_sent_on(connection, &watchdog_request()),
        Err(rejection(
            "watchdog_request_sent",
            PeerCommandClass::DeviceWatchdog,
        ))
    );
    assert_eq!(
        session.observe_watchdog_request_on(
            connection,
            &watchdog_request(),
            &watchdog_request_value,
        ),
        Err(rejection(
            "observe_watchdog_request",
            PeerCommandClass::DeviceWatchdog,
        ))
    );
    assert_eq!(
        session.observe_watchdog_answer_on(
            connection,
            &watchdog_answer_header(),
            &watchdog_answer_value,
        ),
        Err(rejection(
            "observe_watchdog_answer",
            PeerCommandClass::DeviceWatchdog,
        ))
    );
    assert_eq!(
        session.disconnect_request_sent_on(
            connection,
            &disconnect_request(),
            DisconnectCause::Busy,
        ),
        Err(rejection(
            "disconnect_request_sent",
            PeerCommandClass::DisconnectPeer,
        ))
    );
    assert_eq!(
        session.observe_disconnect_request_on(
            connection,
            &disconnect_request(),
            &disconnect_request_value,
        ),
        Err(rejection(
            "observe_disconnect_request",
            PeerCommandClass::DisconnectPeer,
        ))
    );
    assert_eq!(
        session.disconnect_answer_sent_on(
            connection,
            &disconnect_answer_header(),
            &disconnect_answer_value,
        ),
        Err(rejection(
            "disconnect_answer_sent",
            PeerCommandClass::DisconnectPeer,
        ))
    );
    assert_eq!(
        session.observe_disconnect_answer_on(
            connection,
            &disconnect_answer_header(),
            &disconnect_answer_value,
        ),
        Err(rejection(
            "observe_disconnect_answer",
            PeerCommandClass::DisconnectPeer,
        ))
    );
    assert_eq!(session.snapshot(), snapshot);
    assert_eq!(session.state(), PeerSessionState::CapabilitiesPending);
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::NotNegotiated
    );
}

#[test]
fn stale_and_unbound_lifecycle_events_cannot_mutate_the_winning_generation() {
    let stale_generation = generation(30);
    let current_generation = generation(31);
    let mut session = protected_session(stale_generation);
    if let Err(error) = session.begin_connection_generation(current_generation) {
        panic!("current connection generation failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(current_generation, &cer(81, 82)) {
        panic!("current CER failed: {error}");
    }
    if let Err(error) = session.observe_capabilities_answer_on(
        current_generation,
        &cea(81, 82),
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("current CEA failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("current protection token missing"),
    };
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("current protection attestation failed: {error}");
    }

    let watchdog_request_value = DeviceWatchdogRequest {
        identity: PeerIdentity::new("remote.example.invalid", "example.invalid"),
        origin_state_id: None,
    };
    let watchdog_answer_value = watchdog_answer();
    let disconnect_request_value = disconnect_peer_request();
    let disconnect_answer_value = disconnect_peer_answer();
    let winner_snapshot = session.snapshot();
    let winner_readiness = session.protection_readiness();
    let winner_evidence = session.protection_evidence();

    assert_eq!(
        session.watchdog_request_sent_on(stale_generation, &watchdog_request()),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.observe_watchdog_request_on(
            stale_generation,
            &watchdog_request(),
            &watchdog_request_value,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.observe_watchdog_answer_on(
            stale_generation,
            &watchdog_answer_header(),
            &watchdog_answer_value,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.watchdog_missed_on(stale_generation),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.disconnect_request_sent_on(
            stale_generation,
            &disconnect_request(),
            DisconnectCause::Busy,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.observe_disconnect_request_on(
            stale_generation,
            &disconnect_request(),
            &disconnect_request_value,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.disconnect_answer_sent_on(
            stale_generation,
            &disconnect_answer_header(),
            &disconnect_answer_value,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.observe_disconnect_answer_on(
            stale_generation,
            &disconnect_answer_header(),
            &disconnect_answer_value,
        ),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.schedule_reconnect_on(stale_generation),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.enter_backoff_on(stale_generation),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.backoff_elapsed_on(stale_generation),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(
        session.fail_on(stale_generation, PeerSessionBlocker::SessionFailed),
        Err(PeerSessionBoundError::StaleGeneration)
    );
    assert_eq!(session.snapshot(), winner_snapshot);
    assert_eq!(session.protection_readiness(), winner_readiness);
    assert_eq!(session.protection_evidence(), winner_evidence);

    assert!(session.watchdog_request_sent().is_err());
    let _transition = session.observe_watchdog_request(&watchdog_request_value);
    assert!(session
        .observe_watchdog_answer(&watchdog_answer_value)
        .is_err());
    assert!(session.watchdog_missed().is_err());
    let _transition = session.disconnect_request_sent(DisconnectCause::Busy);
    let _transition = session.observe_disconnect_request(&disconnect_request_value);
    let _transition = session.disconnect_answer_sent(&disconnect_answer_value);
    let _transition = session.observe_disconnect_answer(&disconnect_answer_value);
    let _transition = session.schedule_reconnect();
    let _transition = session.enter_backoff();
    let _transition = session.backoff_elapsed();
    let _transition = session.fail(PeerSessionBlocker::SessionFailed);
    assert_eq!(session.snapshot(), winner_snapshot);
    assert_eq!(session.protection_readiness(), winner_readiness);
    assert_eq!(session.protection_evidence(), winner_evidence);
}

#[test]
fn pending_protection_token_is_bound_to_its_owning_session() {
    let connection = generation(28);
    let (_owner, owner_pending) = initiator_pending(connection);
    let (mut other, other_pending) = initiator_pending(connection);

    assert_eq!(
        other.attest_mutually_authenticated_protection(
            &owner_pending,
            PeerProtectionMechanism::TlsTcp,
        ),
        Err(PeerProtectionError::StaleSessionGeneration)
    );
    assert_eq!(
        other.protection_readiness().state(),
        PeerProtectionState::Pending
    );
    assert!(!other.readiness().traffic_ready);

    if let Err(error) = other
        .attest_mutually_authenticated_protection(&other_pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("owning-session attestation failed: {error}");
    }
    assert!(other.protection_readiness().protected_ready());
}

#[test]
fn generation_bound_cer_methods_cannot_bypass_pending_handshake_gate() {
    let connection = generation(29);
    let (mut session, pending) = initiator_pending(connection);

    assert_eq!(
        session.capabilities_request_sent_on(connection, &cer(30, 31)),
        Err(PeerCapabilityBoundaryError::InvalidSessionState)
    );
    assert_eq!(
        session.capabilities_request_received_on(
            connection,
            &cer(32, 33),
            capabilities("remote.example.invalid", vec![INBAND_SECURITY_ID_TLS]),
        ),
        Err(PeerCapabilityBoundaryError::InvalidSessionState)
    );
    assert_eq!(
        session.protection_readiness().state(),
        PeerProtectionState::Pending
    );
    assert_eq!(session.pending_protection().as_ref(), Some(&pending));

    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("attestation after rejected CER bypass failed: {error}");
    }
    assert!(session.readiness().traffic_ready);
}

#[test]
fn protection_requirements_retain_mechanism_and_sequence() {
    let cases = [
        (
            PeerProtectionRequirement::direct_tls_tcp(),
            PeerProtectionMechanism::TlsTcp,
            PeerProtectionSequence::DirectBeforeCapabilities,
            "require_direct_tls_tcp",
        ),
        (
            PeerProtectionRequirement::inband_tls_tcp(),
            PeerProtectionMechanism::TlsTcp,
            PeerProtectionSequence::InbandAfterCapabilities,
            "require_inband_tls_tcp",
        ),
        (
            PeerProtectionRequirement::direct_dtls_sctp(),
            PeerProtectionMechanism::DtlsSctp,
            PeerProtectionSequence::DirectBeforeCapabilities,
            "require_direct_dtls_sctp",
        ),
        (
            PeerProtectionRequirement::inband_dtls_sctp(),
            PeerProtectionMechanism::DtlsSctp,
            PeerProtectionSequence::InbandAfterCapabilities,
            "require_inband_dtls_sctp",
        ),
    ];

    for (requirement, mechanism, sequence, policy_name) in cases {
        assert_eq!(requirement.mechanism(), mechanism);
        assert_eq!(requirement.sequence(), sequence);
        let policy = PeerProtectionPolicy::Require(requirement);
        assert_eq!(policy.requirement(), Some(requirement));
        assert_eq!(policy.as_str(), policy_name);
    }
}

#[test]
fn direct_generation_binds_protection_before_any_diameter() {
    let connection = generation(30);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct connection generation failed: {error}");
    }

    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing at connection bind"),
    };
    assert_eq!(pending.mechanism(), PeerProtectionMechanism::TlsTcp);
    assert_eq!(
        pending.sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert_eq!(session.state(), PeerSessionState::Idle);
    assert!(!session.readiness().traffic_ready);
    assert_eq!(
        session.protection_readiness().sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Outbound, &cer(301, 302)),
        Err(PeerCommandAdmissionError::ProtectionNotReady {
            command: PeerCommandClass::CapabilitiesExchange,
            protection_state: PeerProtectionState::Pending,
        })
    );
    assert_eq!(
        session.capabilities_request_sent_on(connection, &cer(301, 302)),
        Err(PeerCapabilityBoundaryError::InvalidSessionState)
    );
}

#[test]
fn direct_attestation_does_not_complete_capability_readiness() {
    let connection = generation(31);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct connection generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    let transition = match session
        .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        Ok(transition) => transition,
        Err(error) => panic!("direct TLS attestation failed: {error}"),
    };

    assert_eq!(transition.state(), PeerProtectionState::Protected);
    assert!(transition.protection().protected_ready());
    assert!(!transition.protection().traffic_permitted());
    assert_eq!(transition.session().state, PeerSessionState::Idle);
    assert!(!transition.session().traffic_ready);
    assert_eq!(
        transition.protection().sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
    assert_eq!(
        session.admit_message(connection, PeerMessageDirection::Outbound, &app_request()),
        Err(PeerCommandAdmissionError::SessionNotReady {
            command: PeerCommandClass::Application,
            state: PeerSessionState::Idle,
        })
    );
    assert!(session.protection_evidence().is_some_and(|evidence| {
        evidence.sequence() == PeerProtectionSequence::DirectBeforeCapabilities
    }));
}

#[test]
fn direct_initiator_allows_cer_only_then_unlocks_application_traffic() {
    let connection = generation(32);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct TLS attestation failed: {error}");
    }

    let request_header = cer(321, 322);
    let cer_admission =
        match session.admit_message(connection, PeerMessageDirection::Outbound, &request_header) {
            Ok(admission) => admission,
            Err(error) => panic!("protected CER admission failed: {error}"),
        };
    assert!(cer_admission.is_protected());
    assert_eq!(
        cer_admission.sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
    if let Err(error) = session.capabilities_request_sent_on(connection, &request_header) {
        panic!("protected CER transition failed: {error}");
    }
    assert!(session.protection_readiness().protected_ready());
    assert!(!session.protection_readiness().traffic_permitted());

    if let Err(error) = session.observe_capabilities_answer_on(
        connection,
        &cea(321, 322),
        &answer(capabilities("remote.example.invalid", Vec::new())),
    ) {
        panic!("direct CEA transition failed: {error}");
    }
    assert_eq!(session.state(), PeerSessionState::Negotiated);
    assert!(session.readiness().traffic_ready);
    assert!(session.protection_readiness().traffic_permitted());
    let app_admission =
        match session.admit_message(connection, PeerMessageDirection::Outbound, &app_request()) {
            Ok(admission) => admission,
            Err(error) => panic!("direct application admission failed: {error}"),
        };
    assert!(app_admission.is_protected());
    assert_eq!(
        app_admission.sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
}

#[test]
fn direct_responder_does_not_require_or_renegotiate_inband_security() {
    let connection = generation(33);
    let mut session = direct_tls_session(vec![41]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct responder generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct responder protection token missing"),
    };
    let protection_generation = pending.protection_generation();
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct responder attestation failed: {error}");
    }

    let request_header = cer(331, 332);
    let transition = match session.capabilities_request_received_on(
        connection,
        &request_header,
        capabilities("remote.example.invalid", vec![42]),
    ) {
        Ok(transition) => transition,
        Err(error) => panic!("direct CER receive failed: {error}"),
    };
    assert_eq!(
        transition.readiness.state,
        PeerSessionState::CapabilitiesPending
    );
    let projection = match session.last_capability_projection() {
        Some(projection) => projection,
        None => panic!("direct capability projection missing"),
    };
    assert!(projection.accepted);
    assert!(projection.accepted_inband_security_common);
    assert!(!projection
        .blockers
        .contains(&PeerSessionBlocker::AcceptedInbandSecurityMissing));

    let emission = match session.prepare_capabilities_answer_on(
        connection,
        &local_answer(RESULT_CODE_DIAMETER_SUCCESS, vec![43]),
        EncodeContext::default(),
    ) {
        Ok(emission) => emission,
        Err(error) => panic!("direct CEA preparation failed: {error}"),
    };
    assert!(emission.readiness().traffic_ready);
    assert_eq!(session.state(), PeerSessionState::Negotiated);
    assert!(session.pending_protection().is_none());
    assert_eq!(
        session
            .protection_evidence()
            .map(|evidence| evidence.protection_generation()),
        Some(protection_generation)
    );
}

#[test]
fn direct_inband_security_id_one_does_not_start_a_second_handshake() {
    let connection = generation(330);
    let mut session = direct_tls_session(vec![INBAND_SECURITY_ID_TLS]);
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    let protection_generation = pending.protection_generation();
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct attestation failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(connection, &cer(3301, 3302)) {
        panic!("direct CER failed: {error}");
    }
    if let Err(error) = session.observe_capabilities_answer_on(
        connection,
        &cea(3301, 3302),
        &answer(capabilities(
            "remote.example.invalid",
            vec![INBAND_SECURITY_ID_TLS],
        )),
    ) {
        panic!("direct CEA failed: {error}");
    }

    assert!(session.pending_protection().is_none());
    let evidence = match session.protection_evidence() {
        Some(evidence) => evidence,
        None => panic!("direct evidence was lost"),
    };
    assert_eq!(evidence.protection_generation(), protection_generation);
    assert_eq!(
        evidence.sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert_eq!(
        session.protection_readiness().sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
    let admission =
        match session.admit_message(connection, PeerMessageDirection::Inbound, &app_request()) {
            Ok(admission) => admission,
            Err(error) => panic!("direct app admission failed: {error}"),
        };
    assert_eq!(
        admission.sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
}

#[test]
fn direct_dtls_is_typed_and_wrong_mechanism_fails_closed() {
    let connection = generation(34);
    let mut session = direct_dtls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct DTLS generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct DTLS protection token missing"),
    };
    assert_eq!(pending.mechanism(), PeerProtectionMechanism::DtlsSctp);
    assert_eq!(
        pending.sequence(),
        PeerProtectionSequence::DirectBeforeCapabilities
    );
    assert_eq!(
        session
            .attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp,),
        Err(PeerProtectionError::MechanismMismatch {
            expected: PeerProtectionMechanism::DtlsSctp,
            actual: PeerProtectionMechanism::TlsTcp,
        })
    );
    assert_eq!(session.state(), PeerSessionState::Failed);
    assert_eq!(
        session.protection_readiness().sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
}

#[test]
fn reconnect_rejects_stale_direct_attestation_without_poisoning_current_attempt() {
    let first = generation(35);
    let second = generation(36);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(first) {
        panic!("first direct generation failed: {error}");
    }
    let old_pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("first direct token missing"),
    };
    if let Err(error) = session.begin_connection_generation(second) {
        panic!("second direct generation failed: {error}");
    }
    let current_pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("second direct token missing"),
    };

    assert_eq!(
        session.attest_mutually_authenticated_protection(
            &old_pending,
            PeerProtectionMechanism::TlsTcp,
        ),
        Err(PeerProtectionError::StaleSessionGeneration)
    );
    assert_eq!(
        session.pending_protection().as_ref(),
        Some(&current_pending)
    );
    if let Err(error) = session
        .attest_mutually_authenticated_protection(&current_pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("current direct attestation failed: {error}");
    }
    assert_eq!(session.state(), PeerSessionState::Idle);
    assert!(session.protection_readiness().protected_ready());
    assert!(!session.readiness().traffic_ready);
}

#[test]
fn direct_pre_capability_lifecycle_commands_fail_without_revoking_evidence() {
    let connection = generation(37);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct attestation failed: {error}");
    }
    let evidence = session.protection_evidence();

    assert!(matches!(
        session.watchdog_request_sent_on(connection, &watchdog_request()),
        Err(PeerSessionBoundError::CommandNotAdmitted { .. })
    ));
    assert_eq!(session.state(), PeerSessionState::Idle);
    assert_eq!(session.protection_evidence(), evidence);
    assert!(session.protection_readiness().protected_ready());
    assert!(!session.readiness().traffic_ready);
}

#[test]
fn direct_capability_failure_revokes_pre_capability_protection() {
    let connection = generation(38);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct attestation failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(connection, &cer(381, 382)) {
        panic!("direct CER failed: {error}");
    }
    let rejected = CapabilitiesExchangeAnswer {
        result_code: RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
        capabilities: capabilities("remote.example.invalid", Vec::new()),
        diagnostics: AnswerDiagnostics::default(),
    };
    if let Err(error) =
        session.observe_capabilities_answer_on(connection, &cea(381, 382), &rejected)
    {
        panic!("direct rejected CEA boundary failed: {error}");
    }

    assert_eq!(session.state(), PeerSessionState::Failed);
    assert!(!session.protection_readiness().protected_ready());
    assert!(!session.readiness().traffic_ready);
    assert!(session.protection_evidence().is_none());
    assert_eq!(
        session.protection_readiness().sequence(),
        Some(PeerProtectionSequence::DirectBeforeCapabilities)
    );
}

#[test]
fn direct_cer_retransmission_preserves_one_attested_generation() {
    let connection = generation(39);
    let mut session = direct_tls_session(Vec::new());
    if let Err(error) = session.begin_connection_generation(connection) {
        panic!("direct generation failed: {error}");
    }
    let pending = match session.pending_protection() {
        Some(pending) => pending,
        None => panic!("direct protection token missing"),
    };
    if let Err(error) =
        session.attest_mutually_authenticated_protection(&pending, PeerProtectionMechanism::TlsTcp)
    {
        panic!("direct attestation failed: {error}");
    }
    let evidence = session.protection_evidence();
    let request_header = cer(391, 392);
    if let Err(error) = session.capabilities_request_sent_on(connection, &request_header) {
        panic!("initial direct CER failed: {error}");
    }
    if let Err(error) = session.capabilities_request_sent_on(connection, &request_header) {
        panic!("retransmitted direct CER failed: {error}");
    }
    assert_eq!(
        session.capabilities_request_sent_on(connection, &cer(393, 394)),
        Err(PeerCapabilityBoundaryError::ConflictingTransaction)
    );
    assert_eq!(session.protection_evidence(), evidence);
    assert!(session.protection_readiness().protected_ready());
    assert!(!session.readiness().traffic_ready);
}
