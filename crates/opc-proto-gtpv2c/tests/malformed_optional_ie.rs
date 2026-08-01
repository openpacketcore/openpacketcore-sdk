//! TS 29.274 clause 7.7.7/7.7.8 presence-keyed malformed-IE discard evidence.
//!
//! Clauses 7.7.7 (invalid length) and 7.7.8 (semantically incorrect) split
//! receiver behaviour on *presence*: a malformed Mandatory or verifiable
//! Conditional IE fails the message and earns an error response, while a
//! malformed Optional IE "shall discard this IE, but shall treat the rest of
//! the message as if this IE was absent and continue processing". The profiled
//! S2b receiver resolves presence from the receive grammar keyed on
//! `(procedure, direction, scope, ie_type, instance)` and discards only the
//! presence-O slots; Mandatory, Conditional and unresolvable slots fail closed.
//!
//! The optional slots under test, verified against the presence columns of
//! TS 29.274 V18.8.0:
//! - IP Address (74), Create Session Request top level, instance 3 (ePDG IP),
//!   Table 7.2.1-1. Instance 0 is UE Local IP Address, presence CO.
//! - Bearer TFT (84), Create Session Request Bearer Context, instance 0,
//!   Table 7.2.1-1. The same IE is Mandatory in the Create Bearer Request
//!   Bearer Context, Table 7.2.3-2.
//! - PCO (78), Create Bearer Request top level and Bearer Context, instance 0,
//!   Tables 7.2.3-1 and 7.2.3-2. In the Delete Session Request PCO is C/CO,
//!   Table 7.2.9.1-1.
//! - Bearer Context (93), Delete Bearer Request top level, instance 0 ("Failed
//!   Bearer Contexts"), Table 7.2.9.2-1.
//! - F-TEID (87), Delete Session Request top level, instance 0 (Sender
//!   F-TEID), Table 7.2.9.1-1: presence O on the S2b row.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, s2b_delete_session_request, EpsBearerId, IpAddress, RawIe,
    S2bDeleteSessionContext, S2bDeleteSessionRequest, S2bMessage, S2bUeEndpoint, TypedIe,
    TypedIeValue, IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_TFT, IE_TYPE_EBI, IE_TYPE_F_TEID,
    IE_TYPE_IP_ADDRESS, IE_TYPE_PCO,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

const CREATE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_request_s2b_subset.bin");
const CREATE_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_bearer_request_s2b.bin");
const DELETE_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_bearer_request_dedicated.bin");
const DELETE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_session_request_linked_ebi.bin");

/// Every validation level this crate exposes for a typed decode. The profiled
/// receiver owns `(procedure, direction)` and the grammar at all three, so
/// clauses 7.7.7/7.7.8 reach the same presence-keyed disposition at each.
const TYPED_LEVELS: &[ValidationLevel] = &[
    ValidationLevel::Structural,
    ValidationLevel::Strict,
    ValidationLevel::ProcedureAware,
];

fn level_context(level: ValidationLevel) -> DecodeContext {
    DecodeContext {
        validation_level: level,
        ..DecodeContext::default()
    }
}

/// Encode one raw IE as a TS 29.274 clause 5.5 TLIV: type, two-octet length,
/// instance (low nibble of the fourth octet), then the value.
fn raw_ie_bytes(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("test IE value fits u16");
    let mut encoded = vec![ie_type];
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.push(instance & 0x0f);
    encoded.extend_from_slice(value);
    encoded
}

/// Append an IE to a complete message and repair the clause 5.5 length field,
/// which excludes the first four octets.
fn with_extra_ie(message: &[u8], ie: &[u8]) -> Vec<u8> {
    let mut extended = message.to_vec();
    extended.extend_from_slice(ie);
    let declared = u16::from_be_bytes([extended[2], extended[3]]);
    let widened = declared
        .checked_add(u16::try_from(ie.len()).expect("appended IE fits u16"))
        .expect("extended message length fits u16");
    extended[2..4].copy_from_slice(&widened.to_be_bytes());
    extended
}

/// Splice an IE in as the *first* IE of a complete message, ahead of every IE
/// the fixture carries, and repair the clause 5.5 length field.
///
/// Appending puts the injected IE last, where a discard that also abandoned the
/// rest of the sequence would be invisible. Every fixture IE follows this one,
/// so "continue processing" has something left to decode.
fn with_leading_ie(message: &[u8], ie: &[u8]) -> Vec<u8> {
    // TS 29.274 clause 5.5: twelve-octet header when the TEID flag is set.
    const HEADER_LEN: usize = 12;
    let mut spliced = message[..HEADER_LEN].to_vec();
    spliced.extend_from_slice(ie);
    spliced.extend_from_slice(&message[HEADER_LEN..]);
    let declared = u16::from_be_bytes([spliced[2], spliced[3]]);
    let widened = declared
        .checked_add(u16::try_from(ie.len()).expect("spliced IE fits u16"))
        .expect("extended message length fits u16");
    spliced[2..4].copy_from_slice(&widened.to_be_bytes());
    spliced
}

/// Splice a member IE in as the *first* member of the first top-level Bearer
/// Context (instance 0), repairing both the container's length and the message
/// length. Lets a malformed member be placed at the `BearerContext(0)` scope the
/// presence resolver keys on, ahead of the members the fixture already carries.
fn with_nested_ie_in_bearer_context(message: &[u8], member: &[u8]) -> Vec<u8> {
    const HEADER_LEN: usize = 12;
    let mut cursor = HEADER_LEN;
    let bearer_value_offset = loop {
        assert!(
            cursor + 4 <= message.len(),
            "fixture must carry a top-level Bearer Context"
        );
        let length = usize::from(u16::from_be_bytes([
            message[cursor + 1],
            message[cursor + 2],
        ]));
        if message[cursor] == IE_TYPE_BEARER_CONTEXT && message[cursor + 3] & 0x0f == 0 {
            break cursor + 4;
        }
        cursor += 4 + length;
    };

    let mut spliced = message[..bearer_value_offset].to_vec();
    spliced.extend_from_slice(member);
    spliced.extend_from_slice(&message[bearer_value_offset..]);

    // Widen the Bearer Context length (two octets after its type octet).
    let bearer_header = bearer_value_offset - 4;
    let container_len =
        u16::from_be_bytes([spliced[bearer_header + 1], spliced[bearer_header + 2]]);
    let member_len = u16::try_from(member.len()).expect("member fits u16");
    spliced[bearer_header + 1..bearer_header + 3].copy_from_slice(
        &container_len
            .checked_add(member_len)
            .expect("u16")
            .to_be_bytes(),
    );

    // Widen the message length field.
    let declared = u16::from_be_bytes([spliced[2], spliced[3]]);
    spliced[2..4].copy_from_slice(
        &declared
            .checked_add(member_len)
            .expect("message length fits u16")
            .to_be_bytes(),
    );
    spliced
}

/// The typed projection the profiled receiver produces for `message`.
///
/// `S2bMessage::decode` resolves the receiver profile, so it is the layer
/// entitled to apply the clause 7.7.8 discard; assertions about that
/// disposition are made here rather than on the grammarless sequence decoder.
fn typed_ies<'a>(message: &'a [u8], level: ValidationLevel, what: &str) -> Vec<TypedIe<'a>> {
    let (_, decoded) = S2bMessage::decode(message, level_context(level))
        .unwrap_or_else(|error| panic!("the receiver rejected {what}: {error:?}"));
    decoded
        .as_view()
        .unwrap_or_else(|| panic!("no typed view for {what}"))
        .ies
        .clone()
}

/// True if any IE (top level or nested in a Bearer Context) has this type.
fn contains_type_anywhere(ies: &[TypedIe<'_>], ie_type: u8) -> bool {
    ies.iter().any(|ie| {
        ie.ie_type() == ie_type
            || matches!(&ie.value, TypedIeValue::BearerContext(context)
                if context.members.iter().any(|member| member.ie_type() == ie_type))
    })
}

/// TS 29.274 Table 7.2.1-1 gives IP Address presence O at instance 3 (ePDG IP
/// Address) of the Create Session Request. A malformed value there is discarded
/// and the rest of the request decodes, at every validation level. Instance 0
/// is the CO UE Local IP Address and is covered by the negative test below.
#[test]
fn a_malformed_epdg_ip_address_is_discarded_and_the_rest_of_the_request_decodes() {
    // Three octets: neither the four of IPv4 nor the sixteen of IPv6, so the
    // clause 8.13 value decoder reports the length inconsistency.
    let malformed = raw_ie_bytes(IE_TYPE_IP_ADDRESS, 3, &[192, 0, 2]);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        assert!(
            pristine.len() >= 10,
            "{level:?} baseline projection is too small to be evidence"
        );
        let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed ePDG IP Address at instance 3 under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !decoded
                .iter()
                .any(|ie| ie.ie_type() == IE_TYPE_IP_ADDRESS && ie.instance == 3),
            "{what} surfaced"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// TS 29.274 Table 7.2.1-1 gives Bearer TFT presence O inside the Create
/// Session Request Bearer Context. A malformed TFT nested there is discarded
/// while the container's other members still decode, at every level.
#[test]
fn a_malformed_bearer_tft_in_a_create_session_bearer_context_is_discarded() {
    // Zero-length value: the TFT decoder cannot read its operation octet.
    let malformed = raw_ie_bytes(IE_TYPE_BEARER_TFT, 0, &[]);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        let message = with_nested_ie_in_bearer_context(CREATE_SESSION_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed Bearer TFT in the Bearer Context under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !contains_type_anywhere(&decoded, IE_TYPE_BEARER_TFT),
            "{what} surfaced"
        );
        // The fixture's Bearer Context carries an EBI the discard must leave
        // intact; equality against the pristine projection proves the whole
        // container survived "as if this IE was absent".
        assert!(
            contains_type_anywhere(&decoded, IE_TYPE_EBI),
            "{what} lost the sibling EBI"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// The clause 7.7.8 discard is keyed on a value-decode failure, and the Bearer
/// TFT sub-codec (TS 24.008 via `opc-proto-tft`) reports a syntactically
/// out-of-range TFT as [`DecodeErrorCode::Structural`] rather than `Truncated`
/// or `InvalidLength`. The discard gate admits `Structural` for exactly this
/// reason, so a syntactically invalid TFT at the presence-O Create Session
/// Request Bearer Context slot is discarded too -- not only a short one. The
/// sibling test above exercises the `Truncated` arm; this one pins the
/// `Structural` arm so it cannot silently rot back into inertness.
#[test]
fn a_syntactically_invalid_bearer_tft_at_an_optional_slot_is_discarded_as_structural() {
    // The operation nibble claims a create-new TFT carrying fifteen packet
    // filters; the value ends before any filter can be read, so the TS 24.008
    // sub-codec reports a syntactically invalid TFT, which
    // `bearer_tft_decode_error` maps to `Structural` rather than `Truncated`.
    let malformed = raw_ie_bytes(IE_TYPE_BEARER_TFT, 0, &[0x2f, 0x00]);

    // The value must actually surface as `Structural`, or this test would not
    // be exercising the gate arm it claims to pin. The profile-less decoder
    // fails closed with the very code the value decoder raises.
    let code = decode_typed_ie_sequence(&malformed, level_context(ValidationLevel::Structural), 0)
        .expect_err("a syntactically invalid TFT must fail closed without a profile")
        .code()
        .clone();
    assert!(
        matches!(code, DecodeErrorCode::Structural { .. }),
        "the malformed TFT surfaced as {code:?}, not Structural; this test would not pin the Structural discard arm"
    );

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        let message = with_nested_ie_in_bearer_context(CREATE_SESSION_REQUEST_FIXTURE, &malformed);
        let what =
            format!("a syntactically invalid Bearer TFT in the Bearer Context under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !contains_type_anywhere(&decoded, IE_TYPE_BEARER_TFT),
            "{what} surfaced"
        );
        assert!(
            contains_type_anywhere(&decoded, IE_TYPE_EBI),
            "{what} lost the sibling EBI"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// TS 29.274 Table 7.2.3-1 gives PCO presence O at the top level of the Create
/// Bearer Request. A malformed top-level PCO is discarded and the rest of the
/// request decodes, at every level.
#[test]
fn a_malformed_pco_in_a_create_bearer_request_top_level_is_discarded() {
    // Zero-length value: clause 8.15 PCO needs at least a configuration octet.
    let malformed = raw_ie_bytes(IE_TYPE_PCO, 0, &[]);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_BEARER_REQUEST_FIXTURE, *level, "the bare fixture");
        assert!(
            pristine.len() >= 2,
            "{level:?} baseline projection is too small to be evidence"
        );
        let message = with_leading_ie(CREATE_BEARER_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed top-level PCO under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !decoded
                .iter()
                .any(|ie| ie.ie_type() == IE_TYPE_PCO && ie.instance == 0),
            "{what} surfaced"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// TS 29.274 Table 7.2.3-2 gives PCO presence O inside the Create Bearer
/// Request Bearer Context. A malformed nested PCO is discarded while the
/// container's other members still decode, at every level.
#[test]
fn a_malformed_pco_in_a_create_bearer_request_bearer_context_is_discarded() {
    let malformed = raw_ie_bytes(IE_TYPE_PCO, 0, &[]);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_BEARER_REQUEST_FIXTURE, *level, "the bare fixture");
        let message = with_nested_ie_in_bearer_context(CREATE_BEARER_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed nested PCO under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !contains_type_anywhere(&decoded, IE_TYPE_PCO),
            "{what} surfaced"
        );
        // The fixture's Bearer Context carries a (mandatory) Bearer TFT the
        // discard of the optional PCO must leave intact.
        assert!(
            contains_type_anywhere(&decoded, IE_TYPE_BEARER_TFT),
            "{what} lost the sibling Bearer TFT"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// TS 29.274 Table 7.2.9.2-1 gives Bearer Context presence O at the top level
/// of the Delete Bearer Request (the "Failed Bearer Contexts" IE). When a
/// member inside it is malformed -- here a zero-length EBI, which is Mandatory
/// in that subordinate table -- the whole grouped IE is discarded and the rest
/// of the request decodes, at every level.
#[test]
fn a_malformed_failed_bearer_context_in_a_delete_bearer_request_is_discarded() {
    // A Bearer Context whose only member is a zero-length (malformed) EBI. The
    // member is Mandatory, so its failure is not discarded nested; it fails the
    // container's value decode, and the optional container is then discarded.
    let member = raw_ie_bytes(IE_TYPE_EBI, 0, &[]);
    let malformed = raw_ie_bytes(IE_TYPE_BEARER_CONTEXT, 0, &member);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(DELETE_BEARER_REQUEST_FIXTURE, *level, "the bare fixture");
        assert!(
            pristine.len() >= 2,
            "{level:?} baseline projection is too small to be evidence"
        );
        let message = with_leading_ie(DELETE_BEARER_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed Failed Bearer Contexts under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !decoded
                .iter()
                .any(|ie| ie.ie_type() == IE_TYPE_BEARER_CONTEXT && ie.instance == 0),
            "{what} surfaced"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// TS 29.274 Table 7.2.9.1-1 carries three interface-conditioned rows for
/// F-TEID instance 0 (Sender F-TEID) of the Delete Session Request; on the S2b
/// profile the applicable row is "S5/S8 and S2a/S2b", presence O. A malformed
/// Sender F-TEID is discarded and the rest of the request decodes, at every
/// level.
#[test]
fn a_malformed_sender_f_teid_in_a_delete_session_request_is_discarded() {
    // Zero-length value: clause 8.22 F-TEID needs at least the flags octet.
    let malformed = raw_ie_bytes(IE_TYPE_F_TEID, 0, &[]);

    for level in TYPED_LEVELS {
        let pristine = typed_ies(DELETE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        assert!(
            pristine.len() >= 2,
            "{level:?} baseline projection is too small to be evidence"
        );
        let message = with_leading_ie(DELETE_SESSION_REQUEST_FIXTURE, &malformed);
        let what = format!("a malformed Sender F-TEID under {level:?}");
        let decoded = typed_ies(&message, *level, &what);
        assert!(
            !decoded
                .iter()
                .any(|ie| ie.ie_type() == IE_TYPE_F_TEID && ie.instance == 0),
            "{what} surfaced"
        );
        assert_eq!(
            decoded, pristine,
            "{what} disturbed the rest of the message"
        );
    }
}

/// Presence varies by slot, which is why the discard keys on the slot rather
/// than the IE type. TS 29.274 Table 7.2.3-2 makes Bearer TFT *Mandatory* inside
/// the Create Bearer Request Bearer Context (it is Optional only in the Create
/// Session Request Bearer Context, Table 7.2.1-1). A malformed one here must
/// still fail the whole message, at every level.
#[test]
fn a_malformed_mandatory_bearer_tft_in_a_create_bearer_request_still_fails() {
    // The fixture's Bearer Context carries the sole Bearer TFT (type 84); flip
    // its operation octet to claim fifteen packet filters so the value runs out
    // of octets. Corrupting in place keeps it the only (84, 0), so the failure
    // is the clause 7.7.7 Mandatory path rather than a duplicate resolution.
    let mut corrupted = CREATE_BEARER_REQUEST_FIXTURE.to_vec();
    let tft_value = corrupted
        .windows(4)
        .position(|window| window[0] == IE_TYPE_BEARER_TFT && window[3] & 0x0f == 0)
        .expect("fixture carries a Bearer TFT")
        + 4;
    corrupted[tft_value] = 0x2f;

    for level in TYPED_LEVELS {
        let error = S2bMessage::decode(&corrupted, level_context(*level))
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted a malformed mandatory Bearer TFT"));
        assert!(
            matches!(
                error.code(),
                DecodeErrorCode::Truncated
                    | DecodeErrorCode::InvalidLength { .. }
                    | DecodeErrorCode::Structural { .. }
            ),
            "{level:?} produced {:?} rather than a malformed-value error",
            error.code()
        );
    }
}

/// TS 29.274 Table 7.2.9.1-1 makes PCO Conditional (C/CO) in the Delete Session
/// Request. A malformed Conditional IE fails closed: clause 7.7.7 owes the error
/// response for a verifiable Conditional IE, and where verifiability is
/// uncertain failing closed is the safe conformant choice. Every level fails.
#[test]
fn a_malformed_conditional_pco_in_a_delete_session_request_still_fails() {
    let malformed = raw_ie_bytes(IE_TYPE_PCO, 0, &[]);
    let message = with_leading_ie(DELETE_SESSION_REQUEST_FIXTURE, &malformed);

    for level in TYPED_LEVELS {
        let error = S2bMessage::decode(&message, level_context(*level))
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted a malformed conditional PCO"));
        assert!(
            matches!(
                error.code(),
                DecodeErrorCode::Truncated
                    | DecodeErrorCode::InvalidLength { .. }
                    | DecodeErrorCode::Structural { .. }
            ),
            "{level:?} produced {:?} rather than a malformed-value error",
            error.code()
        );
    }
}

/// TS 29.274 Table 7.2.1-1 makes IP Address instance 0 (UE Local IP Address)
/// Conditional (CO) in the Create Session Request -- only instance 3 (ePDG IP)
/// is Optional there. A malformed instance-0 IP Address fails closed at every
/// level, proving the discard keys on the slot's presence, not the IE type.
#[test]
fn a_malformed_conditional_ue_ip_address_in_a_create_session_request_still_fails() {
    // Three octets: wrong octet count, the same malformed value the optional
    // instance-3 test discards. Here the slot is CO, so it must fail instead.
    let malformed = raw_ie_bytes(IE_TYPE_IP_ADDRESS, 0, &[192, 0, 2]);
    let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &malformed);

    for level in TYPED_LEVELS {
        let error = S2bMessage::decode(&message, level_context(*level))
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted a malformed conditional UE IP Address"));
        assert!(
            matches!(
                error.code(),
                DecodeErrorCode::Truncated
                    | DecodeErrorCode::InvalidLength { .. }
                    | DecodeErrorCode::Structural { .. }
            ),
            "{level:?} produced {:?} rather than a malformed-value error",
            error.code()
        );
    }
}

/// The profile-less public decoders receive no procedure, direction or grammar,
/// so they cannot resolve presence and fail closed on a malformed IE even when
/// that IE sits at a slot the profiled receiver treats as Optional. Pinned for
/// a malformed PCO (Optional at the Create Bearer Request slots above).
#[test]
fn the_profile_less_decoder_fails_closed_on_a_malformed_optional_slot_ie() {
    let wire = raw_ie_bytes(IE_TYPE_PCO, 0, &[]);

    for level in TYPED_LEVELS {
        let error = decode_typed_ie_sequence(&wire, level_context(*level), 0).expect_err(&format!(
            "{level:?} must fail closed without a receiver profile"
        ));
        assert!(
            matches!(
                error.code(),
                DecodeErrorCode::Truncated
                    | DecodeErrorCode::InvalidLength { .. }
                    | DecodeErrorCode::Structural { .. }
            ),
            "{level:?} produced {:?} rather than a malformed-value error",
            error.code()
        );
        let typed_error = TypedIe::decode_sequence(&wire, level_context(*level))
            .expect_err(&format!("{level:?} decode_sequence must fail closed too"));
        assert_eq!(
            typed_error, error,
            "{level:?} diverged between the two profile-less entry points"
        );
    }
}

/// Clauses 7.7.7 and 7.7.8 bind "the receiver of a GTP signalling message" and
/// license nothing on the send path. The canonical builder's self-check keeps
/// rejecting a malformed IE even at a presence-O slot: a caller who hands in
/// malformed Sender F-TEID octets gets a build error rather than a message that
/// carries them with the IE quietly missing from the typed view. The Sender
/// F-TEID is Optional on the S2b Delete Session Request (Table 7.2.9.1-1), so
/// this is exactly the slot the profiled receiver discards -- and the sender
/// still rejects.
#[test]
fn the_canonical_builder_rejects_a_malformed_optional_slot_ie() {
    let malformed = TypedIe {
        instance: 0,
        value: TypedIeValue::Raw(RawIe {
            ie_type: IE_TYPE_F_TEID,
            instance: 0,
            spare: 0,
            value: &[],
        }),
    };
    let mut request = delete_session_request();
    request.additional_ies.push(malformed);
    let error = s2b_delete_session_request(request)
        .expect_err("the builder must not emit a malformed Sender F-TEID");
    assert!(
        format!("{error:?}").contains("Truncated"),
        "the builder rejected for the wrong reason: {error:?}"
    );
}

/// "As if this IE was absent" reaches the clause 7.7.10 duplicate bookkeeping
/// too: a discarded IE that kept its `(type, instance)` slot would make the
/// next genuine IE at that key look like a repeat. The S2b receive profile
/// forces `DuplicateIePolicy::First`, so a discarded IE that held its key would
/// drop the genuine ePDG IP Address that follows. Splicing the malformed one
/// ahead of the genuine one -- the on-path shape -- must retain exactly the
/// genuine IE and fabricate no duplicate evidence.
#[test]
fn a_discarded_optional_ie_leaves_no_duplicate_bookkeeping_trace() {
    let mut injected = raw_ie_bytes(IE_TYPE_IP_ADDRESS, 3, &[192, 0, 2]);
    injected.extend_from_slice(&raw_ie_bytes(IE_TYPE_IP_ADDRESS, 3, &[192, 0, 2, 7]));
    let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &injected);

    let ctx = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    let (_, decoded) = S2bMessage::decode_with_diagnostics(&message, ctx)
        .expect("a spliced malformed ePDG IP Address must not fail the receive");

    let ies = &decoded.message().as_view().expect("typed view").ies;
    let found: Vec<&TypedIe<'_>> = ies
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_IP_ADDRESS && ie.instance == 3)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "the genuine ePDG IP Address was suppressed by the discarded one"
    );
    let TypedIeValue::IpAddress(IpAddress::Ipv4(octets)) = &found[0].value else {
        panic!("the surviving ePDG IP Address is not the typed value");
    };
    assert_eq!(
        *octets,
        [192, 0, 2, 7],
        "the genuine value was not retained"
    );

    assert!(
        decoded.diagnostics().is_empty(),
        "a clause 7.7.8 discard fabricated duplicate evidence: {:?}",
        decoded.diagnostics()
    );
}

/// Clause 7.7.8 discards the IE from the typed view but says nothing about the
/// octets a forwarding or logging caller kept. Raw-preserving encode blits the
/// parsed IE region, so the malformed IE must still come back byte-exact -- and
/// that is checkable at all, because the decode no longer fails before encode.
#[test]
fn a_discarded_optional_ie_is_still_byte_exact_under_raw_preserving_encode() {
    let message = with_extra_ie(
        CREATE_SESSION_REQUEST_FIXTURE,
        &raw_ie_bytes(IE_TYPE_IP_ADDRESS, 3, &[192, 0, 2]),
    );
    for level in TYPED_LEVELS {
        let (tail, decoded) = S2bMessage::decode(&message, level_context(*level))
            .unwrap_or_else(|error| panic!("{level:?} rejected the discarded IE: {error:?}"));
        let parsed = &message[..message.len() - tail.len()];
        let mut raw_preserving = BytesMut::new();
        decoded
            .encode(
                &mut raw_preserving,
                EncodeContext {
                    raw_preserving: true,
                    ..EncodeContext::default()
                },
            )
            .expect("raw-preserving encode succeeds");
        assert_eq!(
            raw_preserving.as_ref(),
            parsed,
            "{level:?} did not preserve the discarded IE's octets"
        );
    }
}

/// A Delete Session Request carrier built by this crate's own canonical builder
/// for the sender-side reject test. The builder admits a caller-supplied Sender
/// F-TEID (instance 0) as an additional IE -- it is table-admitted and not
/// profile-owned -- so the malformed-value reject, not the additional-IE gate,
/// is what stops a malformed one.
fn delete_session_request() -> S2bDeleteSessionRequest<'static> {
    S2bDeleteSessionRequest {
        sequence_number: 0x010204,
        teid: 0x5566_7788,
        linked_ebi: EpsBearerId { value: 5 },
        context: S2bDeleteSessionContext {
            release_cause: None,
            indication: None,
            pco: None,
            wlan_location: None,
            wlan_location_timestamp: None,
            ue_endpoint: S2bUeEndpoint::without_nat(IpAddress::Ipv4([198, 51, 100, 40])),
        },
        additional_ies: Vec::new(),
    }
}
