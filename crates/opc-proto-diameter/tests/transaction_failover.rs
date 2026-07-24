//! Independent deterministic evidence for loss-safe pending-request failover
//! transactions (RFC 6733 §5.1, §5.5.4, §3).
//!
//! Every test drives fake transports: the tests themselves decide which writes
//! succeed, which connections fail, and which answers arrive, while the table
//! under test owns wire correctness, correlation, and at-most-once completion.
//! Clocks are injected and advanced manually; no test sleeps.

#![cfg(feature = "app-swm")]

use std::num::{NonZeroU128, NonZeroU64};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmDiameterEapAnswer, SwmDiameterEapRequest,
    SwmDiameterEapRequestEnvelope, SwmDiameterResult, SwmDiameterTransaction,
};
use opc_proto_diameter::end_to_end::{
    DiameterEndToEndIdentifierAuthority, DiameterEndToEndIdentifierAuthorityAttestation,
    DiameterEndToEndIdentifierClock, DiameterEndToEndIdentifierClockError,
    DiameterEndToEndIdentifierConfig, DiameterEndToEndIdentifierTime,
};
use opc_proto_diameter::transaction::{
    AlternateRoutability, AnswerDisposition, AnswerRejectionReason, AttemptFailure,
    CommittedPendingSnapshot, CompletionClaimValue, CompletionDeliveryError,
    CompletionDeliveryRecord, CompletionKind, CompletionTokenValue, ConnectionTableError,
    DiameterConnectionToken, FailoverError, IndeterminateReason, PendingRequestClock,
    PendingRequestTable, PendingRequestTableConfig, PendingSnapshotCheckpoint,
    PendingSnapshotEpoch, PendingSnapshotRevision, PendingTableSnapshot, SnapshotRestoreError,
    TrackError, TransactionAccessError, TransactionCompletion, UndeliverableReason,
};
use opc_proto_diameter::{CommandFlags, Message, OwnedMessage};
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
const SNAPSHOT_EPOCH: PendingSnapshotEpoch = PendingSnapshotEpoch::new(NonZeroU128::MIN);

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

fn checkpoint(revision: u64) -> PendingSnapshotCheckpoint {
    PendingSnapshotCheckpoint::new(
        SNAPSHOT_EPOCH,
        PendingSnapshotRevision::new(NonZeroU64::new(revision).expect("nonzero revision")),
    )
}

fn snapshot_at(table: &mut PendingRequestTable, revision: u64) -> PendingTableSnapshot {
    let snapshot = table
        .snapshot(checkpoint(revision))
        .expect("snapshot must encode");
    table
        .confirm_snapshot_committed(snapshot.checkpoint())
        .expect("snapshot must be committed");
    snapshot
}

fn commit_next(table: &mut PendingRequestTable) -> CommittedPendingSnapshot {
    let revision = table
        .latest_emitted_snapshot()
        .map_or(1, |checkpoint| checkpoint.revision().get() + 1);
    let _snapshot = snapshot_at(table, revision);
    table.committed_snapshot().expect("committed proof")
}

fn dispatch(table: &mut PendingRequestTable, token: CompletionTokenValue) -> OwnedMessage {
    let committed = commit_next(table);
    table
        .take_attempt_dispatch(token, committed)
        .map(|dispatch| dispatch.into_parts().1)
        .expect("attempt must dispatch once")
}

fn restore_snapshot(snapshot: &PendingTableSnapshot) -> PendingRequestTable {
    PendingRequestTable::restore(
        snapshot.as_bytes(),
        snapshot.checkpoint(),
        PendingRequestTableConfig::default(),
        Arc::new(ManualClock::default()),
    )
    .expect("snapshot must restore")
}

fn acknowledged_delivery(completion: &TransactionCompletion) -> CompletionDeliveryRecord {
    let ready = CompletionDeliveryRecord::new(SNAPSHOT_EPOCH, completion.token())
        .expect("terminal completion creates delivery record");
    let claim_value =
        CompletionClaimValue::new(NonZeroU128::new(0xCA11).expect("nonzero claim value"));
    let (claimed, claim) = ready.claim(claim_value).expect("ready record is claimable");
    claimed
        .acknowledge(claim)
        .expect("current claim is acknowledgeable")
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
    let table =
        PendingRequestTable::new(config, clock.clone(), SNAPSHOT_EPOCH).expect("valid config");
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
    let first_wire = dispatch(&mut harness.table, tracked.value());
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
    let alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    let attempt = harness
        .table
        .transaction(tracked.value())
        .expect("view")
        .attempts()[0]
        .attempt_id();
    harness
        .table
        .record_attempt_write_success(tracked.value(), attempt)
        .expect("record complete write");
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
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let original_wire = dispatch(&mut harness.table, tracked.value());
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
    let _second_wire = dispatch(&mut harness.table, tracked.value());
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
    let third_wire = dispatch(&mut harness.table, tracked.value());

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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    let _first_alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _second_alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover B");
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let original_wire = dispatch(&mut harness.table, tracked.value());
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
    let alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let original_wire = dispatch(&mut harness.table, tracked.value());
    let snapshot = snapshot_at(&mut harness.table, 2);

    // Simulate crash + restart: a fresh table restores the pending record.
    let mut restored = restore_snapshot(&snapshot);
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
    let wire = dispatch(&mut restored, tracked.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    // The consumer durably snapshots before the answer arrives.
    let snapshot = snapshot_at(&mut harness.table, 2);

    // Live path: the answer completes the transaction once.
    let first = harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_000E, 2001));
    let first_completion = match first {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected completion, got {other:?}"),
    };
    let ready = CompletionDeliveryRecord::new(SNAPSHOT_EPOCH, first_completion.token())
        .expect("terminal completion delivery record");
    // Persist the fixed-width record atomically with a redaction-safe,
    // replayable application intent. In production the intent includes the
    // encrypted outcome needed to resume the exact downstream operation.
    let durable_intent = b"advance-one-eap-round".to_vec();
    let mut durable_record = ready.encode().as_bytes().to_vec();

    // Crash before the outcome is acknowledged: the still-authoritative old
    // pending snapshot may deliver the same terminal identity again.
    let mut restored = restore_snapshot(&snapshot);
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
    let _restored_wire = dispatch(&mut restored, tracked.value());
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

    // Both deliveries race from the same durable Ready bytes. Only one exact
    // compare-and-swap can win.
    let claim_a = CompletionClaimValue::new(NonZeroU128::new(0xA).expect("nonzero claim A"));
    let claim_b = CompletionClaimValue::new(NonZeroU128::new(0xB).expect("nonzero claim B"));
    let observed_ready =
        CompletionDeliveryRecord::decode(&durable_record).expect("decode Ready after crash");
    let (candidate_a, proof_a) = observed_ready.claim(claim_a).expect("claim A");
    let (candidate_b, _) = observed_ready.claim(claim_b).expect("claim B candidate");
    let expected_ready = durable_record.clone();
    if durable_record == expected_ready {
        durable_record = candidate_a.encode().as_bytes().to_vec();
    }
    assert_ne!(durable_record, candidate_b.encode().as_bytes());

    // Crash while Claimed is explicitly unfinished. A new owner fences the
    // old claim with a higher generation and resumes the persisted intent.
    assert_eq!(durable_intent, b"advance-one-eap-round");
    let recovered_claim =
        CompletionDeliveryRecord::decode(&durable_record).expect("decode Claimed after crash");
    let (reclaimed, proof_b) = recovered_claim.reclaim(claim_b).expect("reclaim");
    durable_record = reclaimed.encode().as_bytes().to_vec();
    assert_eq!(
        reclaimed.acknowledge(proof_a).err(),
        Some(CompletionDeliveryError::StaleClaim)
    );

    // Apply to an idempotent sink keyed by the epoch-namespaced completion
    // identity. Then crash after effect but before Ack.
    let mut effect_attempts = 1usize;
    let mut applied_keys = vec![reclaimed.key()];
    let after_effect_before_ack = durable_record.clone();

    // Recovery must retry Claimed rather than skip it. The sink sees a second
    // attempt but suppresses the duplicate effect by the durable key.
    let recovered_after_effect = CompletionDeliveryRecord::decode(&after_effect_before_ack)
        .expect("decode post-effect Claimed");
    let claim_c = CompletionClaimValue::new(NonZeroU128::new(0xC).expect("nonzero claim C"));
    let (reclaimed_again, proof_c) = recovered_after_effect
        .reclaim(claim_c)
        .expect("second reclaim");
    durable_record = reclaimed_again.encode().as_bytes().to_vec();
    assert_eq!(
        CompletionDeliveryRecord::decode(&durable_record),
        Ok(reclaimed_again)
    );
    effect_attempts += 1;
    if !applied_keys.contains(&reclaimed_again.key()) {
        applied_keys.push(reclaimed_again.key());
    }
    let acknowledged = reclaimed_again
        .acknowledge(proof_c)
        .expect("acknowledge current claim");
    durable_record = acknowledged.encode().as_bytes().to_vec();
    assert_eq!(effect_attempts, 2);
    assert_eq!(applied_keys.len(), 1);
    assert_eq!(
        CompletionDeliveryRecord::decode(&durable_record),
        Ok(acknowledged)
    );
    assert_eq!(proof_b.generation().get(), 2);

    // If the process again restores the old pending head, the durable Ack is
    // reconciled before re-arm, so no network request or side effect repeats.
    let mut recovered_table = restore_snapshot(&snapshot);
    assert_eq!(
        recovered_table.reconcile_acknowledged(acknowledged),
        Ok(true)
    );
    assert_eq!(recovered_table.pending_count(), 0);
}

#[test]
fn restore_rejects_stale_and_malformed_snapshots() {
    let mut harness = harness();
    harness.with_connections();
    harness
        .table
        .track(build_der(0xE2E0_000F, false), CONNECTION_A, token(15))
        .expect("track");
    let snapshot = snapshot_at(&mut harness.table, 1);
    let bytes = snapshot.as_bytes().to_vec();

    let mut stale = bytes.clone();
    stale[5] = 0x63;
    assert_eq!(
        PendingRequestTable::restore(
            &stale,
            checkpoint(1),
            PendingRequestTableConfig::default(),
            Arc::new(ManualClock::default())
        )
        .err(),
        Some(SnapshotRestoreError::UnsupportedVersion)
    );
    let truncated = &bytes[..bytes.len() - 3];
    assert!(PendingRequestTable::restore(
        truncated,
        checkpoint(1),
        PendingRequestTableConfig::default(),
        Arc::new(ManualClock::default())
    )
    .is_err());
    let mut garbage = bytes.clone();
    garbage.extend_from_slice(&[0xAA, 0xBB]);
    assert_eq!(
        PendingRequestTable::restore(
            &garbage,
            checkpoint(1),
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
    let wire = dispatch(&mut harness.table, tracked.value());
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
    // The destination is never silently dropped or rewritten: the consumed
    // dispatch retained Destination-Host byte-for-byte.
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
    harness
        .table
        .acknowledge_completion_delivery(acknowledged_delivery(&completion))
        .expect("acknowledge undeliverable completion");
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
    let wire = dispatch(&mut harness.table, second.value());
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
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
    harness
        .table
        .acknowledge_completion_delivery(acknowledged_delivery(&completion))
        .expect("acknowledge undeliverable completion");
    // An indeterminate outcome is likewise typed when the write disposition
    // cannot be proven and the caller stops trying.
    let second = harness
        .table
        .track(build_der(0xE2E0_0013, false), CONNECTION_A, token(19))
        .expect("track");
    let _second_wire = dispatch(&mut harness.table, second.value());
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
    let _first_wire = dispatch(&mut harness.table, first.value());
    let _second_wire = dispatch(&mut harness.table, second.value());
    // Complete and durably acknowledge both. Unacknowledged work is never
    // evicted; once acknowledged, the ordinary late-answer retention bound
    // evicts the oldest completion.
    let first_completion = match harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A, 0xE2E0_0014, 2001))
    {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected first completion, got {other:?}"),
    };
    harness
        .table
        .acknowledge_completion_delivery(acknowledged_delivery(&first_completion))
        .expect("acknowledge first completion");
    let second_completion = match harness
        .table
        .correlate_answer(CONNECTION_A, build_dea(HBH_A + 1, 0xE2E0_0015, 2001))
    {
        AnswerDisposition::Completed(completion) => completion,
        other => panic!("expected second completion, got {other:?}"),
    };
    harness
        .table
        .acknowledge_completion_delivery(acknowledged_delivery(&second_completion))
        .expect("acknowledge second completion");
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
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    harness.clock.advance(Duration::from_millis(40));
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let _alternate_wire = dispatch(&mut harness.table, tracked.value());
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
    let _wire = dispatch(&mut harness.table, tracked.value());
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

#[test]
fn restore_rejects_recycled_connection_tokens() {
    // The reviewers' probe: track on A, fail over to B, snapshot, restore,
    // then re-register a recycled token with an overlapping Hop-by-Hop seed.
    // Before the fix this silently allocated a duplicate Hop-by-Hop on one
    // connection; it must now fail typed.
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0020, false), CONNECTION_A, token(30))
        .expect("track");
    harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let snapshot = snapshot_at(&mut harness.table, 1);
    let mut restored = restore_snapshot(&snapshot);
    for recycled in [CONNECTION_A, CONNECTION_B] {
        assert_eq!(
            restored.add_connection(recycled, 0).err(),
            Some(ConnectionTableError::DuplicateConnection)
        );
    }
    // A fresh lifetime works and the restored record retransmits with T=1.
    restored
        .add_connection(CONNECTION_C, HBH_C)
        .expect("fresh connection");
    let attempt = restored
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("re-arm");
    assert!(attempt.is_retransmission());
    let wire = dispatch(&mut restored, tracked.value());
    assert!(wire.header.flags.is_potentially_retransmitted());
    // After the record completes and is retired, the historical tokens become
    // registerable again.
    let completion =
        match restored.correlate_answer(CONNECTION_C, build_dea(HBH_C, 0xE2E0_0020, 2001)) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
    restored
        .acknowledge_completion_delivery(acknowledged_delivery(&completion))
        .expect("acknowledge completion");
    assert!(restored.retire(tracked.value()));
    restored
        .add_connection(CONNECTION_A, HBH_A)
        .expect("token reusable once unreferenced");
}

#[test]
fn connection_lifetimes_recycle_without_exhausting_the_table() {
    let config = PendingRequestTableConfig {
        max_connections: 2,
        ..PendingRequestTableConfig::default()
    };
    let mut harness = harness_with(config);
    // Sixty-four full lifetimes — registration, traffic, loss, cleanup — fit
    // in two slots because retired connections release theirs.
    for cycle in 0..64_u64 {
        let primary = conn(100 + cycle * 2);
        let alternate = conn(101 + cycle * 2);
        harness
            .table
            .add_connection(primary, 1)
            .expect("add primary");
        harness
            .table
            .add_connection(alternate, 1)
            .expect("add alternate");
        let tracked = harness
            .table
            .track(
                build_der(0xE3E0_0000 + cycle as u32 * 2, false),
                primary,
                token(1000 + cycle as u128 * 2),
            )
            .expect("track");
        harness.table.close_connection(primary).expect("close");
        // The pending record still references the closed lifetime.
        assert_eq!(
            harness.table.retire_connection(primary).err(),
            Some(ConnectionTableError::ConnectionInUse)
        );
        harness
            .table
            .failover(
                tracked.value(),
                alternate,
                AlternateRoutability::RealmRouted,
            )
            .expect("failover");
        let _alternate_wire = dispatch(&mut harness.table, tracked.value());
        let completion = match harness.table.correlate_answer(
            alternate,
            build_dea(1, 0xE3E0_0000 + cycle as u32 * 2, 2001),
        ) {
            AnswerDisposition::Completed(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        };
        harness
            .table
            .acknowledge_completion_delivery(acknowledged_delivery(&completion))
            .expect("acknowledge completion");
        assert!(harness.table.retire(tracked.value()));
        harness.table.close_connection(alternate).expect("close");
        harness
            .table
            .retire_connection(primary)
            .expect("retire primary");
        harness
            .table
            .retire_connection(alternate)
            .expect("retire alternate");
        assert_eq!(harness.table.connection_count(), 0);
    }
    assert_eq!(harness.table.retained_completed_count(), 0);
}

#[test]
fn track_rejects_already_retransmitted_requests() {
    let mut harness = harness();
    harness.with_connections();
    let mut retransmitted = build_der(0xE2E0_0021, false);
    retransmitted.header.flags = CommandFlags::from_bits(
        retransmitted.header.flags.bits() | CommandFlags::POTENTIALLY_RETRANSMITTED,
    );
    assert_eq!(
        harness
            .table
            .track(retransmitted, CONNECTION_A, token(31))
            .err(),
        Some(TrackError::AlreadyRetransmitted)
    );
    // An ordinary request with the same identifiers tracks cleanly; the
    // rejected attempt had no side effects.
    harness
        .table
        .track(build_der(0xE2E0_0021, false), CONNECTION_A, token(31))
        .expect("track");
    let wire = dispatch(&mut harness.table, token(31));
    assert!(!wire.header.flags.is_potentially_retransmitted());
}

#[test]
fn restored_records_rearm_before_sending() {
    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(0xE2E0_0022, false), CONNECTION_A, token(32))
        .expect("track");
    let snapshot = snapshot_at(&mut harness.table, 1);
    let mut restored = restore_snapshot(&snapshot);
    // The restored in-flight attempt belongs to a dead connection lifetime;
    // serving its pre-crash T-clear bytes would violate the RFC 6733 §5.5.4
    // boot rule, so the table refuses until the record is re-armed.
    let committed = restored.committed_snapshot().expect("committed proof");
    assert_eq!(
        restored
            .take_attempt_dispatch(tracked.value(), committed)
            .err(),
        Some(TransactionAccessError::NoLiveAttempt)
    );
    restored
        .add_connection(CONNECTION_C, HBH_C)
        .expect("fresh connection");
    restored
        .failover(
            tracked.value(),
            CONNECTION_C,
            AlternateRoutability::RealmRouted,
        )
        .expect("re-arm");
    let wire = dispatch(&mut restored, tracked.value());
    assert!(wire.header.flags.is_potentially_retransmitted());
    assert_eq!(wire.header.end_to_end_identifier, 0xE2E0_0022);
}

/// Deterministic wall/monotonic clock for the E2E identifier authority.
#[derive(Debug)]
struct AuthorityClock {
    unix_seconds: AtomicU64,
    monotonic_seconds: AtomicU64,
}

impl AuthorityClock {
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

impl DiameterEndToEndIdentifierClock for AuthorityClock {
    fn now(&self) -> Result<DiameterEndToEndIdentifierTime, DiameterEndToEndIdentifierClockError> {
        Ok(DiameterEndToEndIdentifierTime::new(
            self.unix_seconds.load(Ordering::SeqCst),
            Duration::from_secs(self.monotonic_seconds.load(Ordering::SeqCst)),
        ))
    }
}

#[test]
fn authority_allocated_identity_survives_failover() {
    // Composition contract: the origin-scoped authority allocates exactly one
    // affine End-to-End identity per logical request; the table is the
    // retention point that preserves it across failover and never allocates.
    let clock = Arc::new(AuthorityClock::new(1_800_000_010));
    let authority = DiameterEndToEndIdentifierAuthority::with_clock(
        DiameterEndToEndIdentifierConfig::default(),
        clock.clone(),
        DiameterEndToEndIdentifierAuthorityAttestation::attest_single_origin_owner_with_faithful_clocks(EPDG_HOST)
            .expect("attestation"),
    )
    .expect("authority");
    // The restart fence quarantines allocation until the wall clock enters
    // the next second after authority construction.
    clock.enter_next_second();
    let end_to_end = authority
        .allocate()
        .expect("allocate")
        .into_u32_for_origin_host(EPDG_HOST)
        .expect("origin match");

    let mut harness = harness();
    harness.with_connections();
    let tracked = harness
        .table
        .track(build_der(end_to_end, false), CONNECTION_A, token(40))
        .expect("track");
    let _initial_wire = dispatch(&mut harness.table, tracked.value());
    assert_eq!(
        harness
            .table
            .fail_connection_attempts(CONNECTION_A, AttemptFailure::TransportLostAfterWrite),
        1
    );
    let attempt = harness
        .table
        .failover(
            tracked.value(),
            CONNECTION_B,
            AlternateRoutability::RealmRouted,
        )
        .expect("failover");
    let wire = dispatch(&mut harness.table, tracked.value());
    assert!(wire.header.flags.is_potentially_retransmitted());
    assert_eq!(wire.header.end_to_end_identifier, end_to_end);
    let disposition = harness.table.correlate_answer(
        CONNECTION_B,
        build_dea(attempt.hop_by_hop_identifier(), end_to_end, 2001),
    );
    match disposition {
        AnswerDisposition::Completed(completion) => {
            assert_eq!(completion.kind(), CompletionKind::Answered);
            assert_eq!(completion.token().generation(), 1);
        }
        other => panic!("expected completion, got {other:?}"),
    }

    // The authority never reissues the retained identifier to a second
    // request, and the table accepts the distinct allocation.
    let second = authority
        .allocate()
        .expect("allocate")
        .into_u32_for_origin_host(EPDG_HOST)
        .expect("origin match");
    assert_ne!(second, end_to_end);
    harness
        .table
        .track(build_der(second, false), CONNECTION_A, token(41))
        .expect("distinct allocation tracks");

    // An identity allocated for one Origin-Host cannot be consumed under
    // another; the table never performs this check because it never sees the
    // scope fingerprint — allocation remains the authority's boundary.
    let foreign = authority.allocate().expect("allocate");
    assert!(foreign.into_u32_for_origin_host(AAA_HOST).is_err());
}
