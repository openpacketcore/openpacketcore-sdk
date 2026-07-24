//! Independent deterministic evidence for loss-safe pending-request failover
//! transactions (RFC 6733 §5.1, §5.5.4, §3).
//!
//! Every test drives fake transports: the tests themselves decide which writes
//! succeed, which connections fail, and which answers arrive, while the table
//! under test owns wire correctness, correlation, and at-most-once completion.
//! Clocks are injected and advanced manually; no test sleeps.

#![cfg(feature = "app-swm")]

use std::collections::HashMap;
use std::num::{NonZeroU128, NonZeroU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmDiameterEapAnswer, SwmDiameterEapRequest,
    SwmDiameterEapRequestEnvelope, SwmDiameterResult, SwmDiameterTransaction,
};
use opc_proto_diameter::transaction::{
    AlternateRoutability, AnswerDisposition, AnswerRejectionReason, AttemptFailure, CompletionKind,
    CompletionTokenValue, DiameterConnectionToken, FailoverError, IndeterminateReason,
    PendingRequestClock, PendingRequestTable, PendingRequestTableConfig, SnapshotRestoreError,
    TrackError, TransactionAccessError, TransactionCompletion, UndeliverableReason,
};
use opc_proto_diameter::{Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

const CONNECTION_A: DiameterConnectionToken = conn(1);
const CONNECTION_B: DiameterConnectionToken = conn(2);
const CONNECTION_C: DiameterConnectionToken = conn(3);
const CONNECTION_D: DiameterConnectionToken = conn(4);
const HBH_A: u32 = 0xA0_00;
const HBH_B: u32 = 0xB0_00;
const HBH_C: u32 = 0xC0_00;
const HBH_D: u32 = 0xD0_00;
const SESSION_ID: &str = "session;private;failover-349";
const EPDG_HOST: &str = "epdg.private.invalid";
const EPDG_REALM: &str = "visited.private.invalid";
const AAA_HOST: &str = "aaa.private.invalid";
const AAA_REALM: &str = "home.private.invalid";
const EAP_RESPONSE: [u8; 5] = [0x02, 0x35, 0x00, 0x05, 0x01];
const EAP_REQUEST: [u8; 5] = [0x01, 0x36, 0x00, 0x05, 0x01];

const fn conn(value: u64) -> DiameterConnectionToken {
    match NonZeroU64::new(value) {
        Some(value) => DiameterConnectionToken::new(value),
        None => panic!("connection token must be nonzero"),
    }
}

fn token(value: u128) -> CompletionTokenValue {
    match NonZeroU128::new(value) {
        Some(value) => CompletionTokenValue::new(value),
        None => panic!("completion token must be nonzero"),
    }
}

#[derive(Debug, Default)]
struct ManualClock(Mutex<Duration>);

impl ManualClock {
    fn advance(&self, by: Duration) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard += by;
    }
}

impl PendingRequestClock for ManualClock {
    fn now(&self) -> Duration {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct Harness {
    table: PendingRequestTable,
    clock: Arc<ManualClock>,
}

fn harness() -> Harness {
    harness_with(PendingRequestTableConfig::default())
}

fn harness_with(config: PendingRequestTableConfig) -> Harness {
    let clock = Arc::new(ManualClock::default());
    let table = PendingRequestTable::new(config, clock.clone()).expect("valid config");
    Harness { table, clock }
}

impl Harness {
    fn with_connections(&mut self) -> &mut Self {
        self.table
            .add_connection(CONNECTION_A, HBH_A)
            .expect("connection A");
        self.table
            .add_connection(CONNECTION_B, HBH_B)
            .expect("connection B");
        self.table
            .add_connection(CONNECTION_C, HBH_C)
            .expect("connection C");
        self.table
            .add_connection(CONNECTION_D, HBH_D)
            .expect("connection D");
        self
    }
}

fn der_facts() -> SwmDiameterEapRequest {
    SwmDiameterEapRequest {
        session_id: SESSION_ID.to_owned().into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        origin_host: EPDG_HOST.to_owned().into(),
        origin_realm: EPDG_REALM.to_owned().into(),
        destination_realm: AAA_REALM.to_owned().into(),
        destination_host: None,
        user_name: Some("subscriber-private@example.invalid".to_owned().into()),
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
        eap_payload: EAP_RESPONSE.to_vec().into(),
        emergency_services: None,
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: Vec::new(),
        route_records: Vec::new(),
        extensions: Default::default(),
    }
}

fn build_der(end_to_end: u32, fixed_destination: bool) -> OwnedMessage {
    let mut facts = der_facts();
    if fixed_destination {
        facts.destination_host = Some(AAA_HOST.to_owned().into());
    }
    swm::build_swm_diameter_eap_request(&facts, 0, end_to_end, EncodeContext::default())
        .expect("DER must encode")
}

fn dea_facts(result: u32) -> SwmDiameterEapAnswer {
    SwmDiameterEapAnswer {
        session_id: SESSION_ID.to_owned().into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(result),
        origin_host: AAA_HOST.to_owned().into(),
        origin_realm: AAA_REALM.to_owned().into(),
        user_name: None,
        mip6_feature_vector: None,
        supported_features: Vec::new(),
        oc_supported_features: None,
        oc_olr: None,
        load_reports: Vec::new(),
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: None,
        subscriber_authorization: Default::default(),
        session_timeout: None,
        multi_round_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(EAP_REQUEST.to_vec().into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
        extensions: Default::default(),
    }
}

fn build_dea(hop_by_hop: u32, end_to_end: u32, result: u32) -> OwnedMessage {
    swm::build_swm_diameter_eap_answer(
        &dea_facts(result),
        hop_by_hop,
        end_to_end,
        EncodeContext::default(),
    )
    .expect("DEA must encode")
}

fn encode(message: &OwnedMessage) -> BytesMut {
    let mut out = BytesMut::new();
    message
        .encode(&mut out, EncodeContext::default())
        .expect("message must encode");
    out
}

fn parse_answer_envelope(answer: &OwnedMessage) -> swm::SwmDiameterEapAnswerEnvelope {
    let bytes = encode(answer);
    let (_, message) =
        Message::decode(&bytes, DecodeContext::conservative()).expect("message must decode");
    swm::parse_swm_diameter_eap_answer_envelope(&message, DecodeContext::conservative())
        .expect("DEA envelope must parse")
}

/// Count how many completions a sequence of dispositions carried.
fn completions(dispositions: &[AnswerDisposition]) -> usize {
    dispositions
        .iter()
        .filter(|disposition| matches!(disposition, AnswerDisposition::Completed(_)))
        .count()
}

#[test]
fn loss_before_write_failover_alternate_succeeds() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0001, false), CONNECTION_A, token(1))
        .expect("track");
    let first_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    assert_eq!(first_wire.header.hop_by_hop_identifier, HBH_A);
    assert!(!first_wire.header.flags.is_potentially_retransmitted());

    // The transport proves the request never left; the write failed before
    // any byte was sent.
    let attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    harness
        .table
        .record_attempt_failure(tracked.value(), attempt, AttemptFailure::BeforeWrite)
        .expect("classify");

    let alternate = harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    assert!(alternate.is_retransmission());
    assert_eq!(alternate.hop_by_hop_identifier(), HBH_B);
    let alternate_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    assert!(alternate_wire.header.flags.is_potentially_retransmitted());
    assert_eq!(
        alternate_wire.header.end_to_end_identifier,
        first_wire.header.end_to_end_identifier
    );
    assert_eq!(alternate_wire.raw_avps, first_wire.raw_avps);

    let answer = build_dea(alternate.hop_by_hop_identifier(), 0xE2E0_0001, 2001);
    let disposition = harness.table.correlate_answer(CONNECTION_B, answer);
    let completion = match disposition {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected completion, got {other:?}"),
    };
    assert_eq!(completion.kind(), CompletionKind::Answered);
    assert_eq!(completion.token().generation(), 1);
    assert_eq!(completion.token().value(), tracked.value());
}

#[test]
fn loss_after_complete_write_failover_alternate_succeeds() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0002, false), CONNECTION_A, token(2))
        .expect("track");
    let attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    // The complete request was written, then the association dropped before
    // the answer arrived: the peer may have applied it.
    harness
        .table
        .record_attempt_failure(
            tracked.value(),
            attempt,
            AttemptFailure::TransportLostAfterWrite,
        )
        .expect("classify");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0002, 2001)),
        // A late answer on the failed path is recognized but never completes.
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0002, 2001)),
    ];
    assert_eq!(completions(&dispositions), 1);
    assert!(matches!(dispositions[1], AnswerDisposition::LateAnswer(_)));
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.completion_kind(), Some(CompletionKind::Answered));
    assert_eq!(view.late_answer_count(), 1);
}

#[test]
fn partial_unknown_write_records_uncertain_disposition() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0003, false), CONNECTION_A, token(3))
        .expect("track");
    let attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    // A torn stream after a partial write: whether the peer received a whole
    // request is unknowable.
    let evidence = harness
        .table
        .record_attempt_failure(tracked.value(), attempt, AttemptFailure::UncertainWrite)
        .expect("classify");
    assert_eq!(evidence.disposition().as_str(), "failed_uncertain_write");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let disposition = harness
        .table
        .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0003, 2001));
    assert!(matches!(disposition, AnswerDisposition::Completed(_)));
    // The outcome was still delivered; only the consumer can reconcile the
    // possibly duplicated first write through server-side E2E deduplication.
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(
        view.attempts()[0].disposition().as_str(),
        "failed_uncertain_write"
    );
}

#[test]
fn every_alternate_attempt_preserves_wire_identity() {
    let mut harness = harness();
    harness.with_connections();
    let canonical = build_der(0xE2E0_0004, false);
    let tracked = harness
        .table
        .track(canonical.clone(), CONNECTION_A, token(4))
        .expect("track");
    let original_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    let first_attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    harness
        .table
        .record_attempt_failure(tracked.value(), first_attempt, AttemptFailure::BeforeWrite)
        .expect("classify");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover B");
    let second_attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[1]
        .attempt_id();
    harness
        .table
        .record_attempt_failure(
            tracked.value(),
            second_attempt,
            AttemptFailure::UncertainWrite,
        )
        .expect("classify");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover C");
    let third_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");

    // Every alternate attempt: T=1, exact original End-to-End and Origin-Host,
    // Hop-by-Hop unique on its own connection, semantic AVPs byte-identical.
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.attempts().len(), 3);
    let hop_by_hops: Vec<u32> = view
        .attempts()
        .iter()
        .map(|attempt| attempt.hop_by_hop_identifier())
        .collect();
    assert_eq!(hop_by_hops, vec![HBH_A, HBH_B, HBH_C]);
    for attempt in view.attempts().iter().skip(1) {
        assert!(attempt.is_retransmission());
    }
    assert!(view.has_origin_host(EPDG_HOST));
    assert!(!view.has_origin_host(AAA_HOST));
    assert_eq!(view.end_to_end_identifier(), 0xE2E0_0004);
    assert_eq!(third_wire.raw_avps, original_wire.raw_avps);
    assert_eq!(third_wire.raw_avps, canonical.raw_avps);
    assert!(third_wire.header.flags.is_potentially_retransmitted());
    assert_eq!(third_wire.header.end_to_end_identifier, 0xE2E0_0004);
    assert_eq!(
        third_wire.header.command_code,
        original_wire.header.command_code
    );
    assert_eq!(
        third_wire.header.application_id,
        original_wire.header.application_id
    );
}

#[test]
fn alternate_failure_then_second_alternate_succeeds() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0005, false), CONNECTION_A, token(5))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover B");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_B, AttemptFailure::TransportLostAfterWrite),
        1
    );
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover C");
    let disposition = harness
        .table
        .correlate_answer(CONNECTION_C, build_dea(HBH_C, 0xE2E0_0005, 2001));
    assert!(matches!(disposition, AnswerDisposition::Completed(_)));
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.attempts().len(), 3);
    assert_eq!(view.attempts()[2].disposition().as_str(), "answered");
}

#[test]
fn retry_exhaustion_produces_typed_completion() {
    let config = PendingRequestTableConfig {
        max_attempts_per_transaction: 2,
        ..PendingRequestTableConfig::default()
    };
    let mut harness = harness_with(config);
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0006, false), CONNECTION_A, token(6))
        .expect("track");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover B");
    let error = match harness.table.failover(
        tracked.value(),
        CONNECTION_C,
        AlternateRoutability::RealmRouted,
    ) {
        Ok(_) => panic!("attempt bound must be enforced"),
        Err(error) => error,
    };
    assert_eq!(error, FailoverError::AttemptLimitReached);
    let completion = harness
        .table
        .finish_exhausted(tracked.value())
        .expect("finish");
    assert_eq!(completion.kind(), CompletionKind::Exhausted);
    assert_eq!(completion.token().generation(), 1);
    // Answers after exhaustion are bounded evidence, never a completion.
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0006, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0006, 2001)),
    ];
    assert_eq!(completions(&dispositions), 0);
    assert!(dispositions
        .iter()
        .all(|disposition| matches!(disposition, AnswerDisposition::LateAnswer(_))));
}

#[test]
fn late_original_answer_after_alternate_completion_is_evidence_only() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0007, false), CONNECTION_A, token(7))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::UncertainWrite),
        1
    );
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let mut callback_count = 0usize;
    if matches!(
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0007, 2001)),
        AnswerDisposition::Completed(_)
    ) {
        callback_count += 1;
    }
    // The original path delivers a late duplicate answer.
    if matches!(
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0007, 2001)),
        AnswerDisposition::Completed(_)
    ) {
        callback_count += 1;
    }
    assert_eq!(callback_count, 1);
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.late_answer_count(), 1);
}

#[test]
fn late_alternate_answer_after_original_completion_is_evidence_only() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0008, false), CONNECTION_A, token(8))
        .expect("track");
    // Fail over while the original attempt is still in flight; the original
    // answer wins the race.
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0008, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0008, 2001)),
    ];
    assert_eq!(completions(&dispositions), 1);
    assert!(matches!(dispositions[1], AnswerDisposition::LateAnswer(_)));
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.attempts()[0].disposition().as_str(), "answered");
    assert!(view.attempts()[1].disposition().is_in_flight());
}

#[test]
fn duplicated_and_simultaneous_answers_complete_at_most_once() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0009, false), CONNECTION_A, token(9))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    // "Simultaneous" answers on both connections are serialized by the
    // synchronous API; duplicates on the same connection are the same shape.
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0009, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0009, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0009, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0009, 2001)),
    ];
    assert_eq!(completions(&dispositions), 1);
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.late_answer_count(), 3);
}

#[test]
fn reordered_answers_complete_on_the_first_validated_answer() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_000A, false), CONNECTION_A, token(10))
        .expect("track");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    // The alternate answer is observed first; the original arriving later is
    // reordered evidence only.
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_000A, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_000A, 2001)),
    ];
    assert_eq!(completions(&dispositions), 1);
    assert!(matches!(dispositions[1], AnswerDisposition::LateAnswer(_)));
}

#[test]
fn mismatched_answers_are_rejected_without_completing() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_000B, false), CONNECTION_A, token(11))
        .expect("track");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    // Wrong End-to-End: matches the attempt but cannot be its answer.
    let wrong_e2e = harness
        .table
        .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xDEAD_BEEF, 2001));
    match wrong_e2e {
        AnswerDisposition::Rejected(rejection) => {
            assert_eq!(rejection.reason, AnswerRejectionReason::EndToEndMismatch);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    // An unknown Hop-by-Hop is not correlated at all.
    let unknown = harness
        .table
        .correlate_answer(CONNECTION_B, build_dea(0xFFFF, 0xE2E0_000B, 2001));
    assert!(matches!(unknown, AnswerDisposition::Unmatched(_)));
    assert_eq!(harness.table.unmatched_answer_count(), 1);
    // A request-flipped message on the answer path is rejected too.
    let mut flipped = build_dea(HBH_B, 0xE2E0_000B, 2001);
    flipped.header.flags = opc_proto_diameter::CommandFlags::request(true);
    let not_an_answer = harness.table.correlate_answer(CONNECTION_B, flipped);
    assert!(matches!(not_an_answer, AnswerDisposition::Rejected(_)));
    // The transaction is still pending and completes with the valid answer.
    let disposition = harness
        .table
        .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_000B, 2001));
    assert!(matches!(disposition, AnswerDisposition::Completed(_)));
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.rejected_answer_count(), 2);
}

#[test]
fn swm_eap_multi_round_stays_sticky_across_failover() {
    let mut harness = harness();
    harness.with_connections();
    let canonical = build_der(0xE2E0_000C, false);
    let tracked = harness
        .table
        .track(canonical.clone(), CONNECTION_A, token(12))
        .expect("track");
    let original_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    let alternate = harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let alternate_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    // Failover never manufactures an EAP packet or a new application request:
    // the alternate carries the byte-identical canonical request including
    // the original EAP-Response payload.
    assert_eq!(alternate_wire.raw_avps, original_wire.raw_avps);
    assert!(alternate_wire
        .raw_avps
        .windows(EAP_RESPONSE.len())
        .any(|window| window == EAP_RESPONSE));

    let mut completions = Vec::new();
    if let AnswerDisposition::Completed(completion) = harness.table.correlate_answer(
        CONNECTION_B,
        build_dea(alternate.hop_by_hop_identifier(), 0xE2E0_000C, 1001),
    ) {
        completions.push(completion);
    }
    // A duplicated DEA and a late DEA on the failed path advance nothing.
    for duplicate in [
        harness.table.correlate_answer(
            CONNECTION_B,
            build_dea(alternate.hop_by_hop_identifier(), 0xE2E0_000C, 1001),
        ),
        harness.table.correlate_answer(
            CONNECTION_A,
            build_dea(
                original_wire.header.hop_by_hop_identifier,
                0xE2E0_000C,
                1001,
            ),
        ),
    ] {
        assert!(matches!(duplicate, AnswerDisposition::LateAnswer(_)));
    }
    assert_eq!(completions.len(), 1);

    // The single validated answer advances the SWm EAP exchange exactly once:
    // it correlates with the completing attempt's identifiers.
    let answer = match &completions[0] {
        TransactionCompletion::Answered {
            answer, attempt, ..
        } => {
            assert_eq!(
                attempt.hop_by_hop_identifier(),
                alternate.hop_by_hop_identifier()
            );
            answer.clone()
        }
        other => panic!("expected answer completion, got {other:?}"),
    };
    let answer_message = parse_answer_envelope(&answer);
    let exchange = SwmDiameterEapRequestEnvelope::for_outbound(
        der_facts(),
        SwmDiameterTransaction::new(alternate.hop_by_hop_identifier(), 0xE2E0_000C),
    )
    .correlate_answer(answer_message)
    .expect("the validated answer correlates on the completing attempt");
    assert_eq!(
        exchange
            .answer()
            .eap_payload
            .as_ref()
            .map(|p| p.as_ref().to_vec()),
        Some(EAP_REQUEST.to_vec())
    );

    // Sticky: the same answer cannot correlate as the superseded first
    // attempt; failover moved the transaction, not the EAP exchange.
    let stale_envelope = parse_answer_envelope(&answer);
    let stale = SwmDiameterEapRequestEnvelope::for_outbound(
        der_facts(),
        SwmDiameterTransaction::new(original_wire.header.hop_by_hop_identifier, 0xE2E0_000C),
    )
    .correlate_answer(stale_envelope);
    assert!(stale.is_err());
}

#[test]
fn snapshot_restore_retransmits_pending_with_t_and_stable_identity() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_000D, false), CONNECTION_A, token(13))
        .expect("track");
    let original_wire = harness
        .table
        .attempt_wire_message(tracked.value())
        .expect("wire");
    let snapshot = harness.table.snapshot();

    // Simulate crash + restart: a fresh table restores the pending record.
    let clock = Arc::new(ManualClock::default());
    let mut restored = PendingRequestTable::restore(
        snapshot.as_bytes(),
        PendingRequestTableConfig::default(),
        clock,
    )
    .expect("restore");
    restored
        .add_connection(CONNECTION_C, HBH_C)
        .expect("connection C");
    let attempt = restored
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("restored retransmission");
    assert!(attempt.is_retransmission());
    assert_eq!(attempt.hop_by_hop_identifier(), HBH_C);
    let wire = restored
        .attempt_wire_message(tracked.value())
        .expect("wire");
    assert!(wire.header.flags.is_potentially_retransmitted());
    assert_eq!(wire.header.end_to_end_identifier, 0xE2E0_000D);
    assert_eq!(wire.raw_avps, original_wire.raw_avps);
    let view = restored.transaction(tracked.value()).expect("view");
    assert_eq!(view.completion_token(), tracked);
    assert!(view.has_origin_host(EPDG_HOST));
}

#[test]
fn restored_delivery_is_at_least_once_and_durable_claim_dedups() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_000E, false), CONNECTION_A, token(14))
        .expect("track");
    // The consumer durably snapshots before the answer arrives.
    let snapshot = harness.table.snapshot();

    // Live path: the answer completes the transaction once.
    let first = harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_000E, 2001));
    let first_completion = match first {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected completion, got {other:?}"),
    };

    // Crash after the consumer claimed but did not durably acknowledge the
    // delivery; the pending snapshot is restored and retransmitted.
    let clock = Arc::new(ManualClock::default());
    let mut restored = PendingRequestTable::restore(
        snapshot.as_bytes(),
        PendingRequestTableConfig::default(),
        clock,
    )
    .expect("restore");
    restored
        .add_connection(CONNECTION_C, HBH_C)
        .expect("connection C");
    restored
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("restored retransmission");
    // The server answers the retransmission (E2E duplicate detection returns
    // the cached answer); the completion is delivered a second time.
    let second = restored.correlate_answer(CONNECTION_C, build_dea(HBH_C, 0xE2E0_000E, 2001));
    let second_completion = match second {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected completion, got {other:?}"),
    };
    // At-least-once: both deliveries carry the same stable identity.
    assert_eq!(first_completion.token(), second_completion.token());
    assert_eq!(first_completion.token().generation(), 1);

    // Without a durable protocol the consumer would apply both. With a
    // compare-and-set claim on (token, generation), exactly one applies.
    let mut durable_claims: HashMap<(u128, u64), bool> = HashMap::new();
    let mut applied = 0usize;
    for completion in [first_completion, second_completion] {
        let key = (
            completion.token().value().get(),
            completion.token().generation(),
        );
        if durable_claims.insert(key, true).is_none() {
            applied += 1;
        }
    }
    assert_eq!(applied, 1);
}

#[test]
fn restore_rejects_stale_and_malformed_snapshots() {
    let mut harness = harness();
    harness.with_connections();
    harness
        .table
        .track(build_der(0xE2E0_000F, false), CONNECTION_A, token(15))
        .expect("track");
    let snapshot = harness.table.snapshot();
    let bytes = snapshot.as_bytes().to_vec();

    let mut stale = bytes.clone();
    stale[5] = 0x63;
    assert_eq!(
        PendingRequestTable::restore(
            &stale,
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default())
        )
        .err(),
        Some(SnapshotRestoreError::UnsupportedVersion)
    );
    let truncated = &bytes[..bytes.len() - 3];
    assert!(PendingRequestTable::restore(
        truncated,
        PendingRequestTableConfig::default(),
        Arc::new(ManualClock::default())
    )
    .is_err());
    let mut garbage = bytes.clone();
    garbage.extend_from_slice(&[0xAA, 0xBB]);
    assert_eq!(
        PendingRequestTable::restore(
            &garbage,
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default())
        )
        .err(),
        Some(SnapshotRestoreError::Malformed)
    );
    // Snapshot bytes are sensitive: the canonical request is recoverable from
    // them, which is exactly why consumers must encrypt them at rest.
    assert!(bytes
        .windows(SESSION_ID.len())
        .any(|window| window == SESSION_ID.as_bytes()));
    let debug = format!("{:?}", snapshot);
    assert!(!debug.contains(SESSION_ID));
}

#[test]
fn fixed_destination_without_alternate_is_typed_undeliverable() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0010, true), CONNECTION_A, token(16))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    // A realm-routed alternate cannot serve the pinned Destination-Host.
    let error = match harness.table.failover(
        tracked.value(),
        CONNECTION_B,
        AlternateRoutability::RealmRouted,
    ) {
        Ok(_) => panic!("fixed destination requires a caller assertion"),
        Err(error) => error,
    };
    assert_eq!(error, FailoverError::FixedDestinationRequiresAssertion);
    // The destination is never silently dropped or rewritten — even after the
    // only attempt failed, its exact recorded bytes retain Destination-Host.
    let first_attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    let wire = harness
        .table
        .wire_message_for_attempt(tracked.value(), first_attempt)
        .expect("wire");
    assert!(wire
        .raw_avps
        .windows(AAA_HOST.len())
        .any(|window| window == AAA_HOST.as_bytes()));
    let completion = harness
        .table
        .finish_undeliverable(
            tracked.value(),
            UndeliverableReason::FixedDestinationNoAlternate,
        )
        .expect("finish");
    match completion {
        TransactionCompletion::Undeliverable {
            reason,
            attempts,
            token,
        } => {
            assert_eq!(reason, UndeliverableReason::FixedDestinationNoAlternate);
            assert_eq!(attempts, 1);
            assert_eq!(token.generation(), 1);
        }
        other => panic!("expected undeliverable, got {other:?}"),
    }
    // With a caller assertion, the same fixed destination may fail over.
    let second = harness
        .table
        .track(build_der(0xE2E0_0011, true), CONNECTION_A, token(17))
        .expect("track");
    harness
        .table
        .failover(
            second.value(),
            CONNECTION_B,
            AlternateRoutability::DestinationAsserted,
        )
        .expect("asserted alternate");
    let wire = harness
        .table
        .attempt_wire_message(second.value())
        .expect("wire");
    assert!(wire.header.flags.is_potentially_retransmitted());
    assert!(wire
        .raw_avps
        .windows(AAA_HOST.len())
        .any(|window| window == AAA_HOST.as_bytes()));
}

#[test]
fn no_alternate_routable_is_typed_undeliverable() {
    let mut harness = harness();
    harness
        .table
        .add_connection(CONNECTION_A, HBH_A)
        .expect("connection A");
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0012, false), CONNECTION_A, token(18))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    // No alternate connection exists at all.
    let error = match harness.table.failover(
        tracked.value(),
        CONNECTION_B,
        AlternateRoutability::RealmRouted,
    ) {
        Ok(_) => panic!("unknown alternate must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error, FailoverError::UnknownConnection);
    let completion = harness
        .table
        .finish_undeliverable(tracked.value(), UndeliverableReason::NoAlternateRoutable)
        .expect("finish");
    assert_eq!(completion.kind(), CompletionKind::Undeliverable);
    // An indeterminate outcome is likewise typed when the write disposition
    // cannot be proven and the caller stops trying.
    let second = harness
        .table
        .track(build_der(0xE2E0_0013, false), CONNECTION_A, token(19))
        .expect("track");
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::UncertainWrite),
        1
    );
    let completion = harness
        .table
        .finish_indeterminate(
            second.value(),
            IndeterminateReason::UncertainWriteDisposition,
        )
        .expect("finish");
    assert_eq!(completion.kind(), CompletionKind::Indeterminate);
}

#[test]
fn bounded_tables_and_completion_retention() {
    let config = PendingRequestTableConfig {
        max_pending_transactions: 2,
        max_retained_completions: 1,
        ..PendingRequestTableConfig::default()
    };
    let mut harness = harness_with(config);
    harness.with_connections();
    let first = harness
        .table
        .track(build_der(0xE2E0_0014, false), CONNECTION_A, token(20))
        .expect("track");
    let second = harness
        .table
        .track(build_der(0xE2E0_0015, false), CONNECTION_A, token(21))
        .expect("track");
    assert_eq!(
        harness
            .table
            .track(build_der(0xE2E0_0016, false), CONNECTION_A, token(22))
            .err(),
        Some(TrackError::TableFull)
    );
    // Complete both; the retention bound evicts the oldest completion.
    harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0014, 2001));
    harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A + 1, 0xE2E0_0015, 2001));
    assert_eq!(harness.table.retained_completed_count(), 1);
    assert_eq!(harness.table.evicted_completion_count(), 1);
    // The evicted transaction no longer recognizes its attempts.
    let evicted = harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0014, 2001));
    assert!(matches!(evicted, AnswerDisposition::Unmatched(_)));
    // The retained one still suppresses duplicates.
    let retained = harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A + 1, 0xE2E0_0015, 2001));
    assert!(matches!(retained, AnswerDisposition::LateAnswer(_)));
    // Retiring a completed record frees a pending slot only after retirement;
    // pending slots are separate from retained completions.
    assert!(harness.table.retire(second.value()));
    assert!(!harness.table.retire(first.value()));
    assert_eq!(harness.table.retained_completed_count(), 0);
}

#[test]
fn deterministic_clocks_drive_attempt_evidence() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0018, false), CONNECTION_A, token(24))
        .expect("track");
    harness.clock.advance(Duration::from_millis(40));
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    harness.clock.advance(Duration::from_millis(5));
    harness
        .table
        .correlate_answer(CONNECTION_B, build_dea(HBH_B, 0xE2E0_0018, 2001));
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.attempts()[0].started_at(), Duration::ZERO);
    assert_eq!(view.attempts()[1].started_at(), Duration::from_millis(40));
    assert_eq!(
        view.attempts()[1].ended_at(),
        Some(Duration::from_millis(45))
    );
    // A caller policy ("fail over after 40ms without an answer") is testable
    // without real time; the primitive only records the injected evidence.
}

#[test]
fn dropping_a_completion_never_re_arms_the_transaction() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0017, false), CONNECTION_A, token(23))
        .expect("track");
    // The completion is delivered and immediately dropped by the caller:
    // cancellation cannot split the terminal transition from the delivery.
    drop(
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0017, 2001)),
    );
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.completion_kind(), Some(CompletionKind::Answered));
    assert_eq!(view.completion_token().generation(), 1);
    // No subsequent answer or finish can produce another completion.
    let dispositions = vec![
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0017, 2001)),
        harness
            .table
            .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0017, 2001)),
    ];
    assert_eq!(completions(&dispositions), 0);
    assert_eq!(
        harness.table.finish_exhausted(tracked.value()).err(),
        Some(TransactionAccessError::NotPending)
    );
    assert_eq!(
        harness
            .table
            .failover(
                tracked.value(),
                CONNECTION_B,
                AlternateRoutability::RealmRouted
            )
            .err(),
        Some(FailoverError::NotPending)
    );
    // The completion token remains the stable identity of the delivered
    // completion for the consumer's durable claim/ack protocol.
    let view = harness.table.transaction(tracked.value()).expect("view");
    assert_eq!(view.completion_token().value(), tracked.value());
    assert_eq!(view.completion_token().generation(), 1);
}
