//! Public composition evidence for origin-scoped End-to-End identifiers.

use std::collections::HashSet;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{self, AuthRequestType};
use opc_proto_diameter::avp::dictionary::{Redacted, Sensitive};
use opc_proto_diameter::end_to_end::{
    DiameterEndToEndIdentifierAuthority, DiameterEndToEndIdentifierAuthorityAttestation,
    DiameterEndToEndIdentifierClock, DiameterEndToEndIdentifierClockError,
    DiameterEndToEndIdentifierConfig, DiameterEndToEndIdentifierTime,
};
use opc_proto_diameter::OwnedMessage;
use opc_protocol::{Encode, EncodeContext};

const ORIGIN_HOST: &str = "epdg.identifier.private.invalid";
const ORIGIN_REALM: &str = "visited.identifier.private.invalid";
const PEER_HOST: &str = "aaa.identifier.private.invalid";
const PEER_REALM: &str = "home.identifier.private.invalid";
const SESSION_ID: &str = "session;identifier-authority";
const USER_NAME: &str = "subscriber@identifier.private.invalid";

#[derive(Debug)]
struct ExampleClock {
    unix_seconds: AtomicU64,
    monotonic_seconds: AtomicU64,
}

impl ExampleClock {
    fn new(unix_seconds: u64) -> Self {
        Self {
            unix_seconds: AtomicU64::new(unix_seconds),
            monotonic_seconds: AtomicU64::new(0),
        }
    }

    fn enter_next_second(&self) {
        self.unix_seconds.fetch_add(1, Ordering::SeqCst);
        self.monotonic_seconds.fetch_add(1, Ordering::SeqCst);
    }
}

impl DiameterEndToEndIdentifierClock for ExampleClock {
    fn now(&self) -> Result<DiameterEndToEndIdentifierTime, DiameterEndToEndIdentifierClockError> {
        Ok(DiameterEndToEndIdentifierTime::new(
            self.unix_seconds.load(Ordering::SeqCst),
            Duration::from_secs(self.monotonic_seconds.load(Ordering::SeqCst)),
        ))
    }
}

fn expected_peer(host: &str, realm: &str) -> swm::SwmExpectedAnswerPeer {
    expected_peer_on(NonZeroU64::MIN, host, realm)
}

fn expected_peer_on(connection: NonZeroU64, host: &str, realm: &str) -> swm::SwmExpectedAnswerPeer {
    swm::SwmExpectedAnswerPeer::direct(
        swm::SwmDiameterConnectionToken::new(connection),
        host,
        realm,
    )
}

fn wire(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("public request must encode");
    wire.to_vec()
}

#[test]
fn der_str_asr_rar_and_aar_respect_origin_scoped_authorities() {
    let clock = Arc::new(ExampleClock::new(1_000_000));
    let config = DiameterEndToEndIdentifierConfig::new(8).expect("bounded test capacity");
    let epdg_authority = DiameterEndToEndIdentifierAuthority::with_clock(
        config,
        Arc::clone(&clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
        DiameterEndToEndIdentifierAuthorityAttestation::
            attest_single_origin_owner_with_faithful_clocks(ORIGIN_HOST)
            .expect("valid ePDG Origin-Host"),
    )
    .expect("ePDG authority initialization");
    let aaa_authority = DiameterEndToEndIdentifierAuthority::with_clock(
        config,
        Arc::clone(&clock) as Arc<dyn DiameterEndToEndIdentifierClock>,
        DiameterEndToEndIdentifierAuthorityAttestation::
            attest_single_origin_owner_with_faithful_clocks(PEER_HOST)
            .expect("valid AAA Origin-Host"),
    )
    .expect("AAA authority initialization");
    clock.enter_next_second();

    let der_request = swm::SwmDiameterEapRequest {
        session_id: Redacted::from(SESSION_ID.to_owned()),
        auth_application_id: swm::APPLICATION_ID.get(),
        origin_host: Redacted::from(ORIGIN_HOST.to_owned()),
        origin_realm: Redacted::from(ORIGIN_REALM.to_owned()),
        destination_realm: Redacted::from(PEER_REALM.to_owned()),
        destination_host: Some(Redacted::from(PEER_HOST.to_owned())),
        user_name: Some(Redacted::from(USER_NAME.to_owned())),
        rat_type: None,
        service_selection: None,
        mip6_feature_vector: None,
        qos_capability: None,
        visited_network_identifier: None,
        aaa_failure_indication: None,
        supported_features: Vec::new(),
        ue_local_ip_address: None,
        oc_supported_features: None,
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: Redacted::from(vec![0x02, 0x01, 0x00, 0x04]),
        emergency_services: None,
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: Vec::new(),
        route_records: Vec::new(),
        extensions: Default::default(),
    };
    let der_identity = epdg_authority
        .allocate()
        .expect("DER receives one affine identity");
    let mut der = swm::SwmDiameterEapRequestEnvelope::for_originating_request(
        der_request,
        0x1000_0001,
        der_identity,
        expected_peer(PEER_HOST, PEER_REALM),
    )
    .expect("typed DER Origin-Host matches its authority");
    let der_transaction = der.transaction();
    let der_initial = swm::build_swm_diameter_eap_request_envelope(&der, EncodeContext::default())
        .expect("retained DER composes with authority identity");
    let der_retry = swm::build_swm_diameter_eap_request_envelope(&der, EncodeContext::default())
        .expect("ordinary DER retry reuses retained envelope");
    assert_eq!(wire(&der_initial), wire(&der_retry));
    let failover_hop_by_hop_identifier = 0x2000_0001;
    der.mark_for_failover_retransmission(
        failover_hop_by_hop_identifier,
        expected_peer_on(
            NonZeroU64::new(2).expect("nonzero synthetic connection"),
            PEER_HOST,
            PEER_REALM,
        ),
    );
    assert_eq!(
        der.transaction().end_to_end_identifier(),
        der_transaction.end_to_end_identifier()
    );
    assert_eq!(
        der.transaction().hop_by_hop_identifier(),
        failover_hop_by_hop_identifier
    );
    assert!(der.is_potentially_retransmitted());
    let der_failover = swm::build_swm_diameter_eap_request_envelope(&der, EncodeContext::default())
        .expect("failover DER rebuilds from retained envelope");
    assert_eq!(
        der_failover.header.end_to_end_identifier,
        der_transaction.end_to_end_identifier()
    );
    assert_eq!(
        der_failover.header.hop_by_hop_identifier,
        failover_hop_by_hop_identifier
    );
    assert!(der_failover.header.flags.is_potentially_retransmitted());

    let str_request = swm::SwmSessionTerminationRequest {
        session_id: Sensitive::from(SESSION_ID.to_owned()),
        origin_host: Redacted::from(ORIGIN_HOST.to_owned()),
        origin_realm: Redacted::from(ORIGIN_REALM.to_owned()),
        destination_realm: Redacted::from(PEER_REALM.to_owned()),
        destination_host: Some(Redacted::from(PEER_HOST.to_owned())),
        termination_cause: swm::SwmTerminationCause::Logout,
        user_name: Sensitive::from(USER_NAME.to_owned()),
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let str_identity = epdg_authority
        .allocate()
        .expect("STR receives one affine identity");
    let str_envelope = swm::SwmSessionTerminationRequestEnvelope::for_originating_request(
        str_request,
        0x1000_0002,
        str_identity,
        expected_peer(PEER_HOST, PEER_REALM),
    )
    .expect("typed STR Origin-Host matches its authority");
    let str_transaction = str_envelope.transaction();
    let str_initial =
        swm::build_swm_session_termination_request(&str_envelope, EncodeContext::default())
            .expect("STR composes with authority identity");
    let str_retry =
        swm::build_swm_session_termination_request(&str_envelope, EncodeContext::default())
            .expect("STR retry reuses retained transaction");
    assert_eq!(wire(&str_initial), wire(&str_retry));

    let asr_request = swm::SwmAbortSessionRequest {
        session_id: Redacted::from(SESSION_ID.to_owned()),
        origin_host: Redacted::from(PEER_HOST.to_owned()),
        origin_realm: Redacted::from(PEER_REALM.to_owned()),
        destination_realm: Redacted::from(ORIGIN_REALM.to_owned()),
        destination_host: Redacted::from(ORIGIN_HOST.to_owned()),
        user_name: Redacted::from(USER_NAME.to_owned()),
        auth_session_state: Some(swm::SwmAuthSessionState::StateMaintained),
        origin_state_id: None,
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let asr_identity = aaa_authority
        .allocate()
        .expect("ASR receives one affine identity");
    let asr_envelope = swm::SwmAbortSessionRequestEnvelope::for_originating_request(
        asr_request,
        0x1000_0003,
        asr_identity,
        expected_peer(ORIGIN_HOST, ORIGIN_REALM),
    )
    .expect("typed ASR Origin-Host matches its authority");
    let asr_transaction = asr_envelope.transaction();
    let asr_initial = swm::build_swm_abort_session_request(&asr_envelope, EncodeContext::default())
        .expect("ASR composes with authority identity");
    let asr_retry = swm::build_swm_abort_session_request(&asr_envelope, EncodeContext::default())
        .expect("ASR retry reuses retained transaction");
    assert_eq!(wire(&asr_initial), wire(&asr_retry));

    let rar_request = swm::SwmReAuthRequest {
        session_id: Redacted::from(SESSION_ID.to_owned()),
        origin_host: Redacted::from(PEER_HOST.to_owned()),
        origin_realm: Redacted::from(PEER_REALM.to_owned()),
        destination_realm: Redacted::from(ORIGIN_REALM.to_owned()),
        destination_host: Redacted::from(ORIGIN_HOST.to_owned()),
        re_auth_request_type: swm::SwmReAuthRequestType::AuthorizeOnly,
        user_name: Redacted::from(USER_NAME.to_owned()),
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let rar_identity = aaa_authority
        .allocate()
        .expect("RAR receives one affine identity");
    let rar_envelope = swm::SwmReAuthRequestEnvelope::for_originating_request(
        rar_request,
        0x1000_0004,
        rar_identity,
        expected_peer(ORIGIN_HOST, ORIGIN_REALM),
    )
    .expect("typed RAR Origin-Host matches its authority");
    let rar_transaction = rar_envelope.transaction();
    let rar_initial = swm::build_swm_re_auth_request(&rar_envelope, EncodeContext::default())
        .expect("RAR composes with authority identity");
    let rar_retry = swm::build_swm_re_auth_request(&rar_envelope, EncodeContext::default())
        .expect("RAR retry reuses retained transaction");
    assert_eq!(wire(&rar_initial), wire(&rar_retry));

    let aar_request = swm::SwmAuthorizationRequest {
        session_id: Redacted::from(SESSION_ID.to_owned()),
        origin_host: Redacted::from(ORIGIN_HOST.to_owned()),
        origin_realm: Redacted::from(ORIGIN_REALM.to_owned()),
        destination_realm: Redacted::from(PEER_REALM.to_owned()),
        destination_host: Some(Redacted::from(PEER_HOST.to_owned())),
        user_name: Redacted::from(USER_NAME.to_owned()),
        auth_request_type: AuthRequestType::AuthorizeOnly,
        authorization_lifetime: None,
        auth_grace_period: None,
        aar_flags: None,
        ue_local_ip_address: None,
        high_priority_access_info: None,
        drmp: None,
        route_records: Vec::new(),
        additional_avps: Vec::new(),
    };
    let aar_identity = epdg_authority
        .allocate()
        .expect("AAR receives one affine identity");
    let aar_envelope = swm::SwmAuthorizationRequestEnvelope::for_originating_request(
        aar_request,
        0x1000_0005,
        aar_identity,
        expected_peer(PEER_HOST, PEER_REALM),
    )
    .expect("typed AAR Origin-Host matches its authority");
    let aar_transaction = aar_envelope.transaction();
    let aar_initial = swm::build_swm_authorization_request(&aar_envelope, EncodeContext::default())
        .expect("AAR composes with authority identity");
    let aar_retry = swm::build_swm_authorization_request(&aar_envelope, EncodeContext::default())
        .expect("AAR retry reuses retained transaction");
    assert_eq!(wire(&aar_initial), wire(&aar_retry));

    let epdg_identifiers = [
        der_transaction.end_to_end_identifier(),
        str_transaction.end_to_end_identifier(),
        aar_transaction.end_to_end_identifier(),
    ];
    let aaa_identifiers = [
        asr_transaction.end_to_end_identifier(),
        rar_transaction.end_to_end_identifier(),
    ];
    assert_eq!(
        epdg_identifiers.into_iter().collect::<HashSet<_>>().len(),
        3
    );
    assert_eq!(aaa_identifiers.into_iter().collect::<HashSet<_>>().len(), 2);
    assert_eq!(
        der_transaction.end_to_end_identifier(),
        asr_transaction.end_to_end_identifier()
    );
    assert_eq!(
        format!("{der_transaction:?}"),
        "SwmDiameterTransaction(<redacted>)"
    );

    let wrong_origin_identity = epdg_authority
        .allocate()
        .expect("mismatch evidence receives an affine identity");
    assert!(matches!(
        swm::SwmReAuthRequestEnvelope::for_originating_request(
            rar_envelope.request().clone(),
            0x1000_0006,
            wrong_origin_identity,
            expected_peer(ORIGIN_HOST, ORIGIN_REALM),
        ),
        Err(opc_proto_diameter::end_to_end::DiameterEndToEndIdentifierError::OriginHostMismatch)
    ));
}
