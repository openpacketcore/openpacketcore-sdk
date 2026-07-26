//! TS 29.274 clause 8.107 Node Identifier (IE 176) evidence.
//!
//! On S2b the IE appears only as the 3GPP AAA Server Identifier of Table
//! 7.2.1-1: presence O, Create Session Request, top level, instance 0.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_header, decode_typed_ie_sequence, s2b_create_session_request,
    s2b_delete_session_request, s2b_delete_session_response, s2b_ue_ipsec_tunnel_update_request,
    AccessPointName, BearerContext, CauseValue, EpsBearerId, FullyQualifiedTeid, IpAddress,
    Message, NodeIdentifier, NodeIdentifierError, PdnAddressAllocation, PlmnId, RatType,
    RatTypeValue, RawIe, S2bCreateSessionContext, S2bCreateSessionIdentity,
    S2bCreateSessionRequest, S2bDeleteSessionContext, S2bDeleteSessionRequest,
    S2bDeleteSessionResponse, S2bMessage, S2bUeEndpoint, S2bUeIpsecTunnelUpdateEndpoint,
    S2bUeIpsecTunnelUpdateRequest, SelectionMode, SelectionModeValue, ServingNetwork, TbcdDigits,
    TypedIe, TypedIeValue, IE_TYPE_NODE_IDENTIFIER, INTERFACE_TYPE_S2B_EPDG_GTP_C,
    MAX_NODE_IDENTIFIER_FIELD_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, SpecRef, UnknownIePolicy,
    ValidationLevel,
};

const CREATE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_request_s2b_subset.bin");
const CREATE_SESSION_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_response_s2b_subset.bin");
const DELETE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_session_request_linked_ebi.bin");

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn structural_context() -> DecodeContext {
    DecodeContext::default()
}

fn node_identifier_ie(instance: u8, name: &[u8], realm: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(u8::try_from(name.len()).expect("test Node Name fits one octet"));
    value.extend_from_slice(name);
    value.push(u8::try_from(realm.len()).expect("test Node Realm fits one octet"));
    value.extend_from_slice(realm);
    raw_ie(instance, &value)
}

fn raw_ie(instance: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("test IE value fits u16");
    let mut encoded = vec![IE_TYPE_NODE_IDENTIFIER];
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.push(instance & 0x0f);
    encoded.extend_from_slice(value);
    encoded
}

/// Append an IE to a complete message and repair the TS 29.274 clause 5.5
/// length field, which excludes the first four octets.
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

fn encode_ie(ie: &TypedIe<'_>) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    ie.encode(&mut encoded, EncodeContext::default())
        .expect("typed Node Identifier encodes");
    encoded.to_vec()
}

/// A complete Node Identifier carries a Diameter Identity as a length-prefixed
/// Node Name followed by a length-prefixed Node Realm, and its Debug surface
/// names no operator infrastructure.
#[test]
fn complete_node_identifier_codec_is_typed_bounded_and_redacted() {
    let value = NodeIdentifier::new(b"aaa.example.net".to_vec(), b"example.net".to_vec())
        .expect("well-formed Node Identifier constructs");
    assert_eq!(value.name(), b"aaa.example.net");
    assert_eq!(value.realm(), b"example.net");

    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::NodeIdentifier(value.clone()),
    };
    let expected = node_identifier_ie(0, b"aaa.example.net", b"example.net");
    assert_eq!(encode_ie(&ie), expected);

    let decoded = decode_typed_ie_sequence(&expected, procedure_context(), 0)
        .expect("well-formed Node Identifier decodes");
    assert_eq!(decoded, vec![ie]);

    let debug = format!("{value:?}");
    assert!(!debug.contains("aaa.example.net"));
    assert!(!debug.contains("example.net"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("name_len: 15"));
    assert!(debug.contains("realm_len: 11"));
}

/// Redaction has to hold on the surface a caller actually logs. Pinning it only
/// on the innermost `NodeIdentifier` would let the enclosing `TypedIeValue`,
/// `TypedIe`, or `S2bMessage` arm print the peer AAA server's Origin-Host and
/// Origin-Realm in cleartext while the suite stayed green.
#[test]
fn node_identifier_stays_redacted_through_every_enclosing_debug_surface() {
    let value = NodeIdentifier::new(b"aaa.example.net".to_vec(), b"example.net".to_vec())
        .expect("well-formed Node Identifier constructs");
    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::NodeIdentifier(value),
    };

    let message = with_extra_ie(
        CREATE_SESSION_REQUEST_FIXTURE,
        &node_identifier_ie(0, b"aaa.example.net", b"example.net"),
    );
    let (_, decoded_message) =
        S2bMessage::decode(&message, procedure_context()).expect("carrier message decodes");

    let surfaces: &[(&str, String)] = &[
        ("TypedIeValue", format!("{:?}", ie.value)),
        ("TypedIe", format!("{ie:?}")),
        ("S2bMessage", format!("{decoded_message:?}")),
    ];
    for (label, rendered) in surfaces {
        assert!(
            !rendered.contains("aaa.example.net"),
            "{label} Debug leaked the Node Name"
        );
        assert!(
            !rendered.contains("example.net"),
            "{label} Debug leaked the Node Realm"
        );
        assert!(
            rendered.contains("<redacted>"),
            "{label} Debug dropped the redaction marker"
        );
    }
}

/// Clause 8.107 requires a non-zero length only for its SGSN Identifier and
/// MME Identifier cases. The 3GPP AAA Server Identifier case this profile
/// receives carries no such sentence, and the encoding has no discriminator
/// that would let a decoder tell the cases apart, so an empty Node Name or
/// Node Realm must decode rather than fail.
#[test]
fn node_identifier_accepts_every_length_boundary_the_spec_permits() {
    // Literal 255, not the crate constant: a test that derives its boundary
    // from the value under test cannot detect that value being narrowed.
    let maximum_name = vec![b'n'; 255];
    let maximum_realm = vec![b'r'; 255];
    let cases: &[(&str, &[u8], &[u8])] = &[
        ("both empty", b"", b""),
        ("empty name", b"", b"example.net"),
        ("empty realm", b"aaa.example.net", b""),
        ("single octet each", b"a", b"n"),
        ("maximum lengths", &maximum_name, &maximum_realm),
    ];

    for (label, name, realm) in cases {
        let value =
            NodeIdentifier::new(name.to_vec(), realm.to_vec()).expect("boundary case constructs");
        let ie = TypedIe {
            instance: 0,
            value: TypedIeValue::NodeIdentifier(value),
        };
        let wire = node_identifier_ie(0, name, realm);
        assert_eq!(encode_ie(&ie), wire, "{label} did not encode canonically");
        let decoded = decode_typed_ie_sequence(&wire, procedure_context(), 0)
            .unwrap_or_else(|error| panic!("{label} did not decode: {error:?}"));
        assert_eq!(decoded, vec![ie], "{label} did not round-trip");
    }
}

/// Figure 8.107-1 gives each length field one octet, so the validated
/// constructor is what keeps encoding infallible without a truncating cast.
#[test]
fn node_identifier_constructor_enforces_the_one_octet_length_bound() {
    // The bound comes from Figure 8.107-1's one-octet length field, so it is
    // exactly 255 rather than a crate-chosen number.
    assert_eq!(MAX_NODE_IDENTIFIER_FIELD_LEN, 255);

    let over_long = vec![b'x'; 256];
    assert_eq!(
        NodeIdentifier::new(over_long.clone(), b"example.net".to_vec()),
        Err(NodeIdentifierError::NodeNameTooLong)
    );
    assert_eq!(
        NodeIdentifier::new(b"aaa.example.net".to_vec(), over_long),
        Err(NodeIdentifierError::NodeRealmTooLong)
    );
    assert_eq!(
        NodeIdentifierError::NodeNameTooLong.as_str(),
        "gtpv2c_node_identifier_name_too_long"
    );
    assert_eq!(
        NodeIdentifierError::NodeRealmTooLong.as_str(),
        "gtpv2c_node_identifier_realm_too_long"
    );

    // `Display` is public API and is what reaches a log line, so it is pinned
    // to the same stable code rather than left to the `as_str` assertions.
    assert_eq!(
        NodeIdentifierError::NodeNameTooLong.to_string(),
        "gtpv2c_node_identifier_name_too_long"
    );
    assert_eq!(
        NodeIdentifierError::NodeRealmTooLong.to_string(),
        "gtpv2c_node_identifier_realm_too_long"
    );
}

/// Round-trip proofs in this file lean on `assert_eq!(decoded, vec![ie])`, so
/// equality has to actually compare both subfields. A name-only comparison
/// would silently weaken every one of them.
#[test]
fn node_identifier_equality_compares_both_subfields() {
    let base = NodeIdentifier::new(b"a".to_vec(), b"x".to_vec()).expect("base constructs");
    assert_eq!(
        base,
        NodeIdentifier::new(b"a".to_vec(), b"x".to_vec()).expect("identical constructs")
    );
    assert_ne!(
        base,
        NodeIdentifier::new(b"a".to_vec(), b"y".to_vec()).expect("differing realm constructs")
    );
    assert_ne!(
        base,
        NodeIdentifier::new(b"b".to_vec(), b"x".to_vec()).expect("differing name constructs")
    );
}

/// A declared subfield length that runs past the end of the IE value, or an
/// absent length octet, is the malformed length pair this typed decoder
/// exists to reject instead of surfacing as an opaque preserved IE.
///
/// The reported offset is absolute and follows one rule: the position of the
/// offending subfield's own `Length` octet. The IE header is four octets, so
/// the Node Name length octet of a sequence-leading IE sits at absolute 4.
#[test]
fn node_identifier_rejects_a_malformed_length_pair() {
    const NAME_LENGTH_OCTET: usize = 4;
    let cases: &[(&str, &[u8], usize)] = &[
        ("zero-length value", &[], NAME_LENGTH_OCTET),
        ("name length octet only", &[0x00], NAME_LENGTH_OCTET + 1),
        (
            "realm length octet absent",
            &[0x03, b'a', b'a', b'a'],
            NAME_LENGTH_OCTET + 4,
        ),
        (
            "name length overruns the value",
            &[0x09, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'],
            NAME_LENGTH_OCTET,
        ),
        (
            "realm length overruns the remainder",
            &[0x03, b'a', b'a', b'a', 0x09, b'o', b'r', b'g'],
            NAME_LENGTH_OCTET + 4,
        ),
        (
            "name length overruns an empty remainder",
            &[0x01],
            NAME_LENGTH_OCTET,
        ),
    ];

    for (label, value, expected_offset) in cases {
        let wire = raw_ie(0, value);
        let error = decode_typed_ie_sequence(&wire, procedure_context(), 0)
            .expect_err(&format!("{label} must be rejected"));
        assert!(
            matches!(error.code(), DecodeErrorCode::Truncated),
            "{label} produced {:?} rather than Truncated",
            error.code()
        );
        assert_eq!(
            error.offset(),
            *expected_offset,
            "{label} reported the wrong absolute offset"
        );
        assert_eq!(
            error.spec_ref(),
            Some(&SpecRef::new("3gpp", "TS29274", "8.2")),
            "{label} dropped the spec reference"
        );
    }
}

/// The deliberate divergence from clauses 7.7.7 and 7.7.8 has to be pinned
/// where it actually bites: at the message boundary. Two peer-controlled octets
/// in an optional IE reject an otherwise-valid Create Session Request at every
/// validation level. That is the intended behaviour today, and this test is
/// what makes a silent change to it -- in either direction -- fail.
///
/// It also measures the radius the CHANGELOG and CONFORMANCE entries claim:
/// only `ProcedureAware` runs the clause 7.7.9 instance filter, so outside it
/// every instance 0-15 fails, not just the instance Table 7.2.1-1 lists.
#[test]
fn a_malformed_node_identifier_fails_the_whole_create_session_request() {
    // Node Name length 0x09 inside a two-octet value: well-formed IE framing,
    // malformed clause 8.107 content.
    fn reject(message: &[u8], level: ValidationLevel, what: &str) {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let error = S2bMessage::decode(message, ctx)
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted {what}"));
        assert!(
            matches!(error.code(), DecodeErrorCode::Truncated),
            "{level:?} produced {:?} rather than Truncated for {what}",
            error.code()
        );
    }

    let instance_zero = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &raw_ie(0, &[0x09, b'a']));
    for level in [
        ValidationLevel::Structural,
        ValidationLevel::ProcedureAware,
        ValidationLevel::Strict,
    ] {
        reject(
            &instance_zero,
            level,
            "a malformed instance-0 Node Identifier",
        );
    }

    for instance in 0u8..16 {
        let message = with_extra_ie(
            CREATE_SESSION_REQUEST_FIXTURE,
            &raw_ie(instance, &[0x09, b'a']),
        );
        for level in [ValidationLevel::Structural, ValidationLevel::Strict] {
            reject(
                &message,
                level,
                &format!("a malformed Node Identifier at instance {instance}"),
            );
        }
    }
}

/// The divergence reaches nested scopes too. Outside `ProcedureAware` the typed
/// decoder recurses into a Bearer Context with no receive filter, so a
/// malformed Node Identifier nested there fails the whole message decode -- a
/// message clause 7.7.9 would have processed with the IE simply discarded.
#[test]
fn a_nested_malformed_node_identifier_fails_the_whole_message() {
    let inner = raw_ie(0, &[0x09, b'a']);
    let mut bearer_value = vec![73, 0, 1, 0, 5];
    bearer_value.extend_from_slice(&inner);
    let length = u16::try_from(bearer_value.len()).expect("bearer context fits u16");
    let mut bearer = vec![93];
    bearer.extend_from_slice(&length.to_be_bytes());
    bearer.push(0);
    bearer.extend_from_slice(&bearer_value);

    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &bearer);
    for level in [ValidationLevel::Structural, ValidationLevel::Strict] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let error = S2bMessage::decode(&message, ctx)
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted a nested malformed Node Identifier"));
        assert!(
            matches!(error.code(), DecodeErrorCode::Truncated),
            "{level:?} produced {:?} rather than Truncated",
            error.code()
        );
    }
}

/// Clause 7.7.9 disposition is resolved before the value is typed, so a Node
/// Identifier at an instance Table 7.2.1-1 does not list is discarded without
/// its malformed value ever reaching the typed decoder. This is the mirror of
/// the instance-0 rejection above and is what bounds the divergence.
#[test]
fn a_malformed_node_identifier_at_an_unlisted_instance_is_discarded_not_rejected() {
    let malformed = raw_ie(5, &[0x09, b'a']);
    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &malformed);
    let (_, decoded) = S2bMessage::decode(&message, procedure_context())
        .expect("instance 5 must be discarded under clause 7.7.9, not rejected");
    let ies = &decoded.as_view().expect("Create Session Request view").ies;
    assert!(
        !ies.iter().any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
        "the discarded instance must not surface"
    );
}

/// Table 7.2.1-1 lists the 3GPP AAA Server Identifier once, so the receive rule
/// bounds it to a single occurrence. Without this the bound is the only part of
/// the new rule nothing constrains, and a peer could inject duplicates.
#[test]
fn create_session_request_bounds_node_identifier_to_one_occurrence() {
    let ie = node_identifier_ie(0, b"aaa.example.net", b"example.net");
    let mut message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &ie);
    message = with_extra_ie(&message, &ie);

    let decoded = S2bMessage::decode(&message, procedure_context());
    match decoded {
        Ok((_, decoded)) => {
            let ies = &decoded.as_view().expect("Create Session Request view").ies;
            let count = ies
                .iter()
                .filter(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER)
                .count();
            assert_eq!(
                count, 1,
                "Table 7.2.1-1 lists one 3GPP AAA Server Identifier, so at most one may survive"
            );
        }
        Err(error) => panic!("duplicate Node Identifier must resolve, not fail: {error:?}"),
    }
}

/// Table 8.1-1 marks 176 Extendable and Figure 8.107-1 reserves octets
/// (q+1) to (n+4) for later releases, so clause 8.1 requires a legacy receiver
/// to ignore them rather than reject the IE. Canonical encoding emits only the
/// understood prefix; raw-preserving message encoding keeps the suffix.
#[test]
fn node_identifier_ignores_release_extension_octets_but_preserves_them_raw() {
    let mut extended_value = vec![0x03, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'];
    extended_value.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let extended = raw_ie(0, &extended_value);

    let decoded = decode_typed_ie_sequence(&extended, procedure_context(), 0)
        .expect("an extended Node Identifier must decode");
    let TypedIeValue::NodeIdentifier(value) = &decoded[0].value else {
        panic!("extended Node Identifier did not decode as a typed value");
    };
    assert_eq!(value.name(), b"aaa");
    assert_eq!(value.realm(), b"org");

    // Canonical encoding drops the suffix this Release 18 view does not model.
    assert_eq!(
        encode_ie(&decoded[0]),
        node_identifier_ie(0, b"aaa", b"org")
    );

    // Raw-preserving message encoding keeps the received octets byte-exact.
    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &extended);
    let (_, decoded_message) =
        S2bMessage::decode(&message, procedure_context()).expect("carrier message decodes");
    let mut raw_preserving = BytesMut::new();
    decoded_message
        .encode(
            &mut raw_preserving,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving encode succeeds");
    assert_eq!(raw_preserving.as_ref(), message.as_slice());
}

/// `UnknownIePolicy` keys off the typed-IE support list, which is a separate
/// table from the receive grammar. A Node Identifier that is typed under
/// `Preserve` but dropped under `Drop` would be an unadvertised inconsistency,
/// so all three policies are pinned.
#[test]
fn node_identifier_is_supported_under_every_unknown_ie_policy() {
    let wire = node_identifier_ie(0, b"aaa.example.net", b"example.net");
    for policy in [
        UnknownIePolicy::Drop,
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Reject,
    ] {
        let ctx = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::default()
        };
        let decoded = decode_typed_ie_sequence(&wire, ctx, 0)
            .unwrap_or_else(|error| panic!("{policy:?} must not fail a supported IE: {error:?}"));
        assert_eq!(decoded.len(), 1, "{policy:?} dropped a supported IE");
        assert!(
            matches!(&decoded[0].value, TypedIeValue::NodeIdentifier(_)),
            "{policy:?} did not produce the typed value"
        );
    }
}

/// Table 7.2.1-1 admits Node Identifier only at Create Session Request, top
/// level, instance 0. Every other instance is a known-but-unexpected IE that
/// clause 7.7.9 discards while the rest of the request continues.
#[test]
fn create_session_request_admits_node_identifier_only_at_instance_zero() {
    for instance in 0u8..16 {
        let ie = node_identifier_ie(instance, b"aaa.example.net", b"example.net");
        let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &ie);
        let (_, decoded) = S2bMessage::decode(&message, procedure_context())
            .unwrap_or_else(|error| panic!("instance {instance} must not fail decode: {error:?}"));
        let ies = &decoded.as_view().expect("Create Session Request view").ies;
        let found: Vec<&TypedIe<'_>> = ies
            .iter()
            .filter(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER)
            .collect();

        if instance == 0 {
            assert_eq!(found.len(), 1, "instance 0 must be admitted");
            assert!(
                matches!(&found[0].value, TypedIeValue::NodeIdentifier(_)),
                "instance 0 must decode to the typed value, not a raw fallback"
            );
        } else {
            assert!(
                found.is_empty(),
                "instance {instance} must be discarded under clause 7.7.9"
            );
        }
    }
}

/// TS 29.274 lists Node Identifier on no other message this profile models.
/// Its remaining rows are the SGSN, MME, SCEF, and IWK-SCEF identifiers of the
/// clause 7.3 S3/S10/S16 mobility messages, which are out of scope here.
#[test]
fn other_s2b_procedures_discard_node_identifier_as_known_unexpected() {
    let carriers: &[(&str, &[u8])] = &[
        ("Create Session Response", CREATE_SESSION_RESPONSE_FIXTURE),
        ("Delete Session Request", DELETE_SESSION_REQUEST_FIXTURE),
    ];

    for (label, fixture) in carriers {
        let ie = node_identifier_ie(0, b"aaa.example.net", b"example.net");
        let message = with_extra_ie(fixture, &ie);
        let (_, decoded) = S2bMessage::decode(&message, procedure_context())
            .unwrap_or_else(|error| panic!("{label} must still decode: {error:?}"));
        let ies = &decoded.as_view().expect("typed view").ies;
        assert!(
            !ies.iter().any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
            "{label} must discard Node Identifier under clause 7.7.9"
        );
    }
}

/// Structural decode is not procedure aware, so it types the IE wherever it
/// appears. This pins that the typed decoder, not the receive grammar, is what
/// rejects a malformed value.
#[test]
fn structural_decode_types_node_identifier_outside_the_receive_grammar() {
    let ie = node_identifier_ie(4, b"aaa.example.net", b"example.net");
    let message = with_extra_ie(DELETE_SESSION_REQUEST_FIXTURE, &ie);
    let (_, decoded) =
        Message::decode(&message, structural_context()).expect("structural decode succeeds");
    let typed = decode_typed_ie_sequence(decoded.raw_ies, structural_context(), 0)
        .expect("structural typed decode succeeds");
    assert!(typed.iter().any(|ie| matches!(
        &ie.value,
        TypedIeValue::NodeIdentifier(value) if value.realm() == b"example.net"
    )));

    let malformed = with_extra_ie(DELETE_SESSION_REQUEST_FIXTURE, &raw_ie(4, &[0x09, b'a']));
    let (_, decoded) =
        Message::decode(&malformed, structural_context()).expect("structural decode succeeds");
    let error = decode_typed_ie_sequence(decoded.raw_ies, structural_context(), 0)
        .expect_err("a malformed Node Identifier is rejected at Structural too");
    assert!(matches!(error.code(), DecodeErrorCode::Truncated));
}

/// A Node Identifier nested inside a Bearer Context has no subordinate table
/// row, so the receive grammar resolves no scope for it and discards it.
#[test]
fn nested_node_identifier_is_discarded_rather_than_preserved() {
    let inner = node_identifier_ie(0, b"aaa.example.net", b"example.net");
    let mut bearer_value = vec![73, 0, 1, 0, 5];
    bearer_value.extend_from_slice(&inner);
    let length = u16::try_from(bearer_value.len()).expect("bearer context fits u16");
    let mut bearer = vec![93];
    bearer.extend_from_slice(&length.to_be_bytes());
    bearer.push(0);
    bearer.extend_from_slice(&bearer_value);

    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &bearer);
    let (_, decoded) =
        S2bMessage::decode(&message, procedure_context()).expect("carrier message decodes");
    let ies = &decoded.as_view().expect("typed view").ies;
    let nested_types: Vec<u8> = ies
        .iter()
        .filter_map(|ie| match &ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .flat_map(|context| context.members.iter().map(TypedIe::ie_type))
        .collect();
    assert!(
        !nested_types.contains(&IE_TYPE_NODE_IDENTIFIER),
        "a nested Node Identifier must not be admitted"
    );
}

fn raw_node_identifier_ie(instance: u8) -> TypedIe<'static> {
    TypedIe {
        instance,
        value: TypedIeValue::Raw(RawIe {
            ie_type: IE_TYPE_NODE_IDENTIFIER,
            instance,
            spare: 0,
            value: &[0x03, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'],
        }),
    }
}

fn create_session_request() -> S2bCreateSessionRequest<'static> {
    S2bCreateSessionRequest {
        sequence_number: 0x010203,
        identity: S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010123456789")),
        rat_type: RatType {
            value: RatTypeValue::Wlan,
        },
        serving_network: ServingNetwork {
            plmn: PlmnId::new("001", "01"),
        },
        sender_f_teid: FullyQualifiedTeid {
            interface_type: INTERFACE_TYPE_S2B_EPDG_GTP_C,
            teid: 0x1020_3040,
            ipv4: Some([192, 0, 2, 1]),
            ipv6: None,
        },
        apn: AccessPointName::new(vec!["ims".to_string()]),
        selection_mode: SelectionMode {
            value: SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified,
        },
        paa: PdnAddressAllocation::dynamic_ipv4(),
        bearer_context: BearerContext {
            members: vec![TypedIe {
                instance: 0,
                value: TypedIeValue::EpsBearerId(EpsBearerId { value: 5 }),
            }],
        },
        context: S2bCreateSessionContext::default(),
        additional_ies: Vec::new(),
    }
}

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

/// Admitting IE 176 into the receive grammar also narrows the sender profile,
/// because the builders gate caller-supplied additional IEs on the same
/// disposition. A raw Node Identifier was previously accepted on every S2b
/// request at every instance; Table 7.2.1-1 places it on exactly one.
#[test]
fn builders_admit_a_caller_supplied_node_identifier_only_where_the_table_lists_it() {
    for instance in 0u8..16 {
        let mut request = create_session_request();
        request
            .additional_ies
            .push(raw_node_identifier_ie(instance));
        let built = s2b_create_session_request(request);
        if instance == 0 {
            assert!(
                built.is_ok(),
                "Table 7.2.1-1 instance 0 must remain emittable"
            );
        } else {
            assert!(
                built.is_err(),
                "instance {instance} is not listed and must be rejected"
            );
        }
    }

    for instance in 0u8..16 {
        let mut delete = delete_session_request();
        delete.additional_ies.push(raw_node_identifier_ie(instance));
        assert!(
            s2b_delete_session_request(delete).is_err(),
            "Delete Session Request does not list Node Identifier at instance {instance}"
        );

        let update = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
            sequence_number: 0x010205,
            teid: 0x1122_3344,
            wlan_location: None,
            wlan_location_timestamp: None,
            endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
            additional_ies: vec![raw_node_identifier_ie(instance)],
        });
        assert!(
            update.is_err(),
            "Modify Bearer Request does not list Node Identifier at instance {instance}"
        );
    }
}

/// Only the request builders gate `additional_ies`. The response builders
/// validate under `S2bDecodePurpose::CanonicalBuilder`, which skips the clause
/// 7.7.9 receive filter, so they still emit a raw IE 176 at an instance this
/// crate's own procedure-aware receiver discards. That looseness is
/// pre-existing and applies to every known IE; it is pinned here so the README
/// and CONFORMANCE sentences scoping the claim to request builders stay honest.
#[test]
fn response_builders_do_not_gate_a_caller_supplied_node_identifier() {
    let built = s2b_delete_session_response(S2bDeleteSessionResponse {
        sequence_number: 0x01_0206,
        teid: 0x1122_3344,
        cause: CauseValue::RequestAccepted,
        additional_ies: vec![raw_node_identifier_ie(7)],
    })
    .expect("the response builder gates no additional IE");

    let mut encoded = BytesMut::new();
    built
        .encode(&mut encoded, EncodeContext::default())
        .expect("built response encodes");
    assert!(
        encoded
            .as_ref()
            .windows(4)
            .any(|window| window == [IE_TYPE_NODE_IDENTIFIER, 0x00, 0x08, 0x07]),
        "the response builder did not emit the ungated IE 176 at instance 7"
    );

    let (_, decoded) = S2bMessage::decode(encoded.as_ref(), procedure_context())
        .expect("the emitted response decodes");
    let ies = &decoded.as_view().expect("typed view").ies;
    assert!(
        !ies.iter().any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
        "the crate emits an IE its own procedure-aware receiver discards"
    );
}

/// The emitted instance-0 Node Identifier must survive a procedure-aware
/// decode as the typed value, closing the loop between sender and receiver.
#[test]
fn an_emitted_node_identifier_decodes_back_to_the_typed_value() {
    let mut request = create_session_request();
    request.additional_ies.push(raw_node_identifier_ie(0));
    let built = s2b_create_session_request(request).expect("instance 0 builds");

    let mut encoded = BytesMut::new();
    built
        .encode(&mut encoded, EncodeContext::default())
        .expect("built request encodes");

    let (_, decoded) =
        S2bMessage::decode(encoded.as_ref(), procedure_context()).expect("built request decodes");
    let ies = &decoded.as_view().expect("typed view").ies;
    let found = ies
        .iter()
        .find(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER)
        .expect("emitted Node Identifier survives receive");
    let TypedIeValue::NodeIdentifier(value) = &found.value else {
        panic!("emitted Node Identifier decoded as a raw fallback");
    };
    assert_eq!(value.name(), b"aaa");
    assert_eq!(value.realm(), b"org");
}

/// The header helper keeps the injected-message construction honest: the
/// carrier fixtures must really be the procedures this test claims.
#[test]
fn carrier_fixtures_are_the_messages_this_evidence_claims() {
    let cases: &[(&[u8], u8)] = &[
        (CREATE_SESSION_REQUEST_FIXTURE, 32),
        (CREATE_SESSION_RESPONSE_FIXTURE, 33),
        (DELETE_SESSION_REQUEST_FIXTURE, 36),
    ];
    for (fixture, message_type) in cases {
        let (_, header) = decode_header(fixture, structural_context()).expect("header decodes");
        assert_eq!(header.message_type, *message_type);
    }
}
