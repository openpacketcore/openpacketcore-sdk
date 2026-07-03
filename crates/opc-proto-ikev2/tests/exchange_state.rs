use opc_proto_ikev2::{
    Header, HeaderFlags, Ikev2ExchangeBoundaryState, Ikev2ExchangeDecision,
    Ikev2ExchangeInvalidReason, Ikev2ExchangeRequest, Ikev2ExchangeTracker, PayloadType,
    EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT,
    EXCHANGE_TYPE_INFORMATIONAL, IKEV2_EXCHANGE_RETRANSMISSION_WINDOW,
};

fn request_header(exchange_type: u8, responder_spi: u64, message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        responder_spi,
        PayloadType::NoNext,
        exchange_type,
        HeaderFlags::from_bits(true, false, false),
        message_id,
    )
}

fn response_header(exchange_type: u8, responder_spi: u64, message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        responder_spi,
        PayloadType::NoNext,
        exchange_type,
        HeaderFlags::from_bits(true, true, false),
        message_id,
    )
}

#[test]
fn exchange_tracker_binds_responder_spi_and_dedupes_retransmission() {
    let responder_spi = 0x8877_6655_4433_2211;
    let mut tracker = Ikev2ExchangeTracker::new();

    let sa_init = tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));
    assert_eq!(sa_init.decision, Ikev2ExchangeDecision::NewRequest);
    assert_eq!(sa_init.decision.as_str(), "new_request");
    assert_eq!(sa_init.state, Ikev2ExchangeBoundaryState::SaInitObserved);
    assert!(sa_init.sequence_valid);

    let auth = tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_AUTH, responder_spi, 1));
    assert_eq!(auth.decision, Ikev2ExchangeDecision::ResponderSpiBound);
    assert_eq!(auth.state, Ikev2ExchangeBoundaryState::ResponderSpiBound);
    assert!(auth.responder_spi_bound);
    assert_eq!(auth.highest_message_id, Some(1));

    let retransmission =
        tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_AUTH, responder_spi, 1));
    assert_eq!(
        retransmission.decision,
        Ikev2ExchangeDecision::Retransmission
    );
    assert!(retransmission.retransmission);
    assert!(retransmission.sequence_valid);
    assert_eq!(retransmission.observed_request_count, 2);
    assert_eq!(retransmission.retransmission_count, 1);

    let snapshot = tracker.snapshot();
    assert_eq!(
        snapshot.responder_spi.map(|spi| spi.get()),
        Some(responder_spi)
    );
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains(&responder_spi.to_string()));
    assert!(!debug.contains("8877665544332211"));
}

#[test]
fn exchange_tracker_rejects_message_id_gap_and_reuse() {
    let responder_spi = 0x8877_6655_4433_2211;
    let mut gap_tracker = Ikev2ExchangeTracker::new();
    gap_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));

    let gap = gap_tracker.observe_header(&request_header(
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        responder_spi,
        3,
    ));
    assert_eq!(gap.decision, Ikev2ExchangeDecision::InvalidSequence);
    assert_eq!(gap.state, Ikev2ExchangeBoundaryState::SequenceInvalid);
    assert_eq!(
        gap.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::MessageIdGap)
    );
    assert_eq!(
        gap.invalid_reason.map(Ikev2ExchangeInvalidReason::as_str),
        Some("message_id_gap")
    );
    assert!(!gap.sequence_valid);

    let mut reuse_tracker = Ikev2ExchangeTracker::new();
    reuse_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));
    reuse_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_AUTH, responder_spi, 1));
    let reused = reuse_tracker.observe_header(&request_header(
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        responder_spi,
        1,
    ));
    assert_eq!(
        reused.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::MessageIdReusedForDifferentRequest)
    );
    assert_eq!(reused.invalid_sequence_count, 1);
}

#[test]
fn exchange_tracker_rejects_responder_spi_missing_and_mismatch() {
    let mut missing_tracker = Ikev2ExchangeTracker::new();
    missing_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));
    let missing = missing_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_AUTH, 0, 1));
    assert_eq!(missing.decision, Ikev2ExchangeDecision::InvalidSequence);
    assert_eq!(
        missing.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::ResponderSpiMissing)
    );

    let responder_spi = 0x8877_6655_4433_2211;
    let other_responder_spi = 0x1111_2222_3333_4444;
    let mut mismatch_tracker = Ikev2ExchangeTracker::new();
    mismatch_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));
    mismatch_tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_AUTH, responder_spi, 1));

    let mismatch = mismatch_tracker.observe_header(&request_header(
        EXCHANGE_TYPE_INFORMATIONAL,
        other_responder_spi,
        2,
    ));
    assert_eq!(
        mismatch.decision,
        Ikev2ExchangeDecision::ResponderSpiMismatch
    );
    assert_eq!(
        mismatch.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::ResponderSpiMismatch)
    );
    assert!(mismatch.responder_spi_mismatch);
    assert_eq!(mismatch.responder_spi_mismatch_count, 1);
}

#[test]
fn exchange_tracker_rejects_non_request_and_bad_initial_boundaries() {
    let response = response_header(EXCHANGE_TYPE_IKE_AUTH, 0x8877_6655_4433_2211, 1);
    let response_error = match Ikev2ExchangeRequest::from_header(&response) {
        Ok(value) => panic!("response header unexpectedly became request: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(response_error, Ikev2ExchangeInvalidReason::ResponseFlagSet);

    let unknown = request_header(250, 0, 0);
    let unknown_error = match Ikev2ExchangeRequest::from_header(&unknown) {
        Ok(value) => panic!("unknown exchange unexpectedly became request: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(
        unknown_error,
        Ikev2ExchangeInvalidReason::UnsupportedExchangeType
    );

    let mut tracker = Ikev2ExchangeTracker::new();
    let post_before_init = tracker.observe_header(&request_header(
        EXCHANGE_TYPE_IKE_AUTH,
        0x8877_6655_4433_2211,
        1,
    ));
    assert_eq!(
        post_before_init.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::PostSaInitBeforeSaInit)
    );

    let mut tracker = Ikev2ExchangeTracker::new();
    let sa_init_bad_id = tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 1));
    assert_eq!(
        sa_init_bad_id.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::SaInitMessageIdNonZero)
    );

    let mut tracker = Ikev2ExchangeTracker::new();
    let sa_init_bad_spi = tracker.observe_header(&request_header(
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x8877_6655_4433_2211,
        0,
    ));
    assert_eq!(
        sa_init_bad_spi.invalid_reason,
        Some(Ikev2ExchangeInvalidReason::SaInitResponderSpiNonZero)
    );
}

#[test]
fn exchange_tracker_retains_bounded_retransmission_window() {
    let responder_spi = 0x8877_6655_4433_2211;
    let mut tracker = Ikev2ExchangeTracker::new();
    tracker.observe_header(&request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0));

    for message_id in 1..=100 {
        let projection = tracker.observe_header(&request_header(
            EXCHANGE_TYPE_INFORMATIONAL,
            responder_spi,
            message_id,
        ));
        assert!(projection.sequence_valid);
        assert!(projection.observed_request_count <= IKEV2_EXCHANGE_RETRANSMISSION_WINDOW);
    }

    let snapshot = tracker.snapshot();
    assert_eq!(
        snapshot.observed_request_count,
        IKEV2_EXCHANGE_RETRANSMISSION_WINDOW
    );
    assert_eq!(snapshot.highest_message_id, Some(100));
}
