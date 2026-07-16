//! Complete SDK-side handling of PGW-triggered dedicated-bearer procedures.
//!
//! Product policy, Child-SA installation/deletion, and EBI/TEID/SPI allocation
//! deliberately remain application responsibilities. Those side effects are
//! invoked only for `Dispatch`; `Pending` and `Replay` never repeat them.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    correlate_create_bearer_response, correlate_delete_bearer_response, s2b_create_bearer_response,
    s2b_delete_bearer_response, CauseValue, EpsBearerId, FullyQualifiedTeid, Gtpv2cMonotonicMillis,
    Gtpv2cPeerToken, Gtpv2cTriggeredCompletion, Gtpv2cTriggeredRequestDisposition,
    Gtpv2cTriggeredTransactions, OwnedMessage, S2bCreateBearerResponse, S2bCreateBearerResult,
    S2bDeleteBearerResponse, S2bDeleteBearerResponseBody, S2bDeleteBearerResult, S2bMessage,
    INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext};
use std::io::{Error as IoError, ErrorKind};

const RESPONSE_TEID: u32 = 0x5060_7080;
const CREATE_REQUEST: &[u8] =
    include_bytes!("../tests/fixtures/spec/create_bearer_request_s2b.bin");
const DELETE_REQUEST: &[u8] =
    include_bytes!("../tests/fixtures/spec/delete_bearer_request_dedicated.bin");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let peer = Gtpv2cPeerToken::new(7);
    let mut transactions = Gtpv2cTriggeredTransactions::default();

    handle_create(&mut transactions, peer)?;
    handle_delete(&mut transactions, peer)?;
    Ok(())
}

fn handle_create(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded_request = Bytes::from_static(CREATE_REQUEST);
    let key = match transactions.observe_request(
        peer,
        encoded_request.clone(),
        RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(1_000),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => key,
        _ => return Err(invalid_data("first Create Bearer request did not dispatch").into()),
    };

    let request_message = decode_s2b(&encoded_request)?;
    let request_view = request_message
        .as_view()
        .ok_or_else(|| invalid_data("Create Bearer request used raw fallback"))?;
    let request = request_view.create_bearer_request()?;

    // The application validates policy, allocates EBI/TEID/SPI, and establishes
    // one non-rekey Child SA using each context's typed TFT and QoS. This
    // single-context example records the resulting application allocations.
    let context = request
        .bearer_contexts
        .first()
        .ok_or_else(|| invalid_data("Create Bearer request had no context"))?;
    let response = S2bCreateBearerResponse {
        sequence_number: request.sequence_number,
        teid: RESPONSE_TEID,
        message_priority: request.message_priority,
        cause: CauseValue::RequestAccepted,
        bearer_contexts: vec![S2bCreateBearerResult::Accepted {
            ebi: EpsBearerId { value: 6 },
            epdg_f_teid: FullyQualifiedTeid {
                interface_type: INTERFACE_TYPE_S2B_U_EPDG_GTP_U,
                teid: 0x3000_0001,
                ipv4: Some([192, 0, 2, 21]),
                ipv6: None,
            },
            pgw_f_teid: context.pgw_f_teid.clone(),
            additional_ies: Vec::new(),
        }],
        additional_ies: Vec::new(),
    };
    correlate_create_bearer_response(&request, &response)?;
    let encoded_response = encode(&s2b_create_bearer_response(response)?)?;
    transactions.commit_response(
        key,
        Gtpv2cTriggeredCompletion::Accepted(encoded_response.clone()),
        Gtpv2cMonotonicMillis::new(1_001),
        DecodeContext::default(),
    )?;

    match transactions.observe_request(
        peer,
        encoded_request,
        RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(1_002),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Replay { response, .. }
            if response == encoded_response =>
        {
            Ok(())
        }
        _ => Err(invalid_data("Create Bearer retransmission did not replay exactly").into()),
    }
}

fn handle_delete(
    transactions: &mut Gtpv2cTriggeredTransactions,
    peer: Gtpv2cPeerToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded_request = Bytes::from_static(DELETE_REQUEST);
    let key = match transactions.observe_request(
        peer,
        encoded_request.clone(),
        RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(2_000),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Dispatch(key) => key,
        _ => return Err(invalid_data("first Delete Bearer request did not dispatch").into()),
    };

    let request_message = decode_s2b(&encoded_request)?;
    let request_view = request_message
        .as_view()
        .ok_or_else(|| invalid_data("Delete Bearer request used raw fallback"))?;
    let request = request_view.delete_bearer_request()?;

    // The application deletes each ePDG-owned Child SA once. It reports the
    // outcome per EBI; the protocol layer validates the response correlation.
    let response = S2bDeleteBearerResponse {
        sequence_number: request.sequence_number,
        teid: RESPONSE_TEID,
        message_priority: request.message_priority,
        cause: CauseValue::RequestAcceptedPartially,
        body: S2bDeleteBearerResponseBody::Dedicated(vec![
            S2bDeleteBearerResult {
                ebi: EpsBearerId { value: 6 },
                cause: CauseValue::RequestAccepted,
                additional_ies: Vec::new(),
            },
            S2bDeleteBearerResult {
                ebi: EpsBearerId { value: 7 },
                cause: CauseValue::ContextNotFound,
                additional_ies: Vec::new(),
            },
        ]),
        additional_ies: Vec::new(),
    };
    correlate_delete_bearer_response(&request, &response)?;
    let encoded_response = encode(&s2b_delete_bearer_response(response)?)?;
    transactions.commit_response(
        key,
        Gtpv2cTriggeredCompletion::PartiallyAccepted(encoded_response.clone()),
        Gtpv2cMonotonicMillis::new(2_001),
        DecodeContext::default(),
    )?;

    match transactions.observe_request(
        peer,
        encoded_request,
        RESPONSE_TEID,
        Gtpv2cMonotonicMillis::new(2_002),
        DecodeContext::default(),
    )? {
        Gtpv2cTriggeredRequestDisposition::Replay { response, .. }
            if response == encoded_response =>
        {
            Ok(())
        }
        _ => Err(invalid_data("Delete Bearer retransmission did not replay exactly").into()),
    }
}

fn decode_s2b(encoded: &[u8]) -> Result<S2bMessage<'_>, Box<dyn std::error::Error>> {
    let (tail, message) = S2bMessage::decode(encoded, DecodeContext::default())?;
    if tail.is_empty() {
        Ok(message)
    } else {
        Err(invalid_data("GTPv2-C message left trailing bytes").into())
    }
}

fn encode(message: &OwnedMessage) -> Result<Bytes, Box<dyn std::error::Error>> {
    let mut encoded = BytesMut::new();
    message.encode(&mut encoded, EncodeContext::default())?;
    Ok(encoded.freeze())
}

fn invalid_data(message: &'static str) -> IoError {
    IoError::new(ErrorKind::InvalidData, message)
}
