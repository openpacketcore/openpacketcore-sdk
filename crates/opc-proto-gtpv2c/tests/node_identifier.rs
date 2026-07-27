//! TS 29.274 clause 8.107 Node Identifier (IE 176) evidence.
//!
//! On S2b the IE appears only as the 3GPP AAA Server Identifier of Table
//! 7.2.1-1: presence O, Create Session Request, top level, instance 0.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_header, decode_typed_ie_sequence, s2b_create_session_request,
    s2b_delete_session_request, s2b_delete_session_response, s2b_ue_ipsec_tunnel_update_request,
    AccessPointName, BearerContext, CauseValue, EpsBearerId, FullyQualifiedTeid, Gtpv2cOffendingIe,
    Gtpv2cProtocolErrorKind, IpAddress, Message, NodeIdentifier, NodeIdentifierError,
    PdnAddressAllocation, PlmnId, RatType, RatTypeValue, RawIe, S2bCreateSessionContext,
    S2bCreateSessionIdentity, S2bCreateSessionRequest, S2bDeleteSessionContext,
    S2bDeleteSessionRequest, S2bDeleteSessionResponse, S2bMessage, S2bUeEndpoint,
    S2bUeIpsecTunnelUpdateEndpoint, S2bUeIpsecTunnelUpdateRequest, SelectionMode,
    SelectionModeValue, ServingNetwork, TbcdDigits, TypedIe, TypedIeValue, IE_TYPE_F_TEID,
    IE_TYPE_IMSI, IE_TYPE_NODE_IDENTIFIER, INTERFACE_TYPE_S2B_EPDG_GTP_C,
    MAX_NODE_IDENTIFIER_FIELD_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    SpecRef, UnknownIePolicy, ValidationLevel,
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

/// Splice an IE in as the *first* IE of a complete message, ahead of every IE
/// the fixture carries, and repair the clause 5.5 length field.
///
/// Appending puts the injected IE last, where a discard that also abandoned the
/// rest of the sequence would be invisible. Every fixture IE follows this one,
/// so "continue processing" has something left to fail on.
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

/// Every malformed clause 8.107 length pair this decoder recognises.
///
/// Shared by the value-decoder offset evidence and the clause 7.7.8 discard
/// evidence so the two cannot drift apart: a case the discard path stops
/// covering would have to be deleted from here, where the value decoder still
/// pins it.
///
/// The offset is absolute and follows one rule: the position of the offending
/// subfield's own `Length` octet. The IE header is four octets, so the Node
/// Name length octet of a sequence-leading IE sits at absolute 4.
const MALFORMED_LENGTH_PAIRS: &[(&str, &[u8], usize)] = &[
    ("zero-length value", &[], 4),
    ("name length octet only", &[0x00], 5),
    ("realm length octet absent", &[0x03, b'a', b'a', b'a'], 8),
    (
        "name length overruns the value",
        &[0x09, b'a', b'a', b'a', 0x03, b'o', b'r', b'g'],
        4,
    ),
    (
        "realm length overruns the remainder",
        &[0x03, b'a', b'a', b'a', 0x09, b'o', b'r', b'g'],
        8,
    ),
    ("name length overruns an empty remainder", &[0x01], 4),
];

/// A declared subfield length that runs past the end of the IE value, or an
/// absent length octet, is the malformed length pair this typed decoder
/// detects instead of surfacing as an opaque preserved IE.
///
/// The detection is pinned on `TypedIe::decode_from_raw`, the single-IE
/// conversion whose documented contract is that it cannot represent a
/// deliberate omission and therefore still returns the error. It is also the
/// surface the canonical builder's sender-side self-check runs on. The
/// sequence decoders apply TS 29.274 clause 7.7.8 to the same failure and
/// discard the IE instead; that is pinned separately below.
#[test]
fn node_identifier_value_decode_reports_the_malformed_length_pair() {
    for (label, value, expected_offset) in MALFORMED_LENGTH_PAIRS {
        let raw = RawIe {
            ie_type: IE_TYPE_NODE_IDENTIFIER,
            instance: 0,
            spare: 0,
            value,
        };
        let error = TypedIe::decode_from_raw(raw, procedure_context(), 0, 0)
            .expect_err(&format!("{label} must be detected"));
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

/// The profile-less sequence decoders fail closed on a malformed IE 176.
///
/// Both TS 29.274 clauses that license a discard condition it on the IE's
/// *presence*, which is a Table 7.2.x-1 fact about one procedure and one
/// direction. Clause 7.7.7, quoted in this crate's `CONFORMANCE.md`, is
/// explicit: the IE "shall be discarded and if the IE was received as a
/// Mandatory IE or a verifiable Conditional IE in a Request message, an
/// appropriate error response with Cause IE value set to "Invalid length"
/// together with the type and instance of the offending IE shall be returned
/// to the sender." Clause 7.7.8 states the optional half.
///
/// `decode_typed_ie_sequence` and `TypedIe::decode_sequence` resolve no
/// procedure, no direction, and no message type. They therefore cannot
/// establish the presence the discard is conditioned on, and a discard would
/// destroy the "type and instance of the offending IE" the clause requires an
/// error response to carry. They fail closed instead, and hand the caller
/// exactly the identity the response needs. The clause 7.7.8 discard remains
/// available where presence *is* resolved: `S2bMessage::decode`, pinned below.
///
/// The IE framing is deliberately well formed and only the clause 8.107
/// subfield length pair is inconsistent. A TLIV whose declared Length overruns
/// the buffer fails in the raw iterator, which already fails closed, and would
/// not exercise this path at all.
#[test]
fn a_malformed_node_identifier_fails_the_profile_less_sequence_decode() {
    let follower = node_identifier_ie(1, b"aaa", b"org");

    for (label, value, expected_offset) in MALFORMED_LENGTH_PAIRS {
        for instance in 0u8..16 {
            let mut wire = raw_ie(instance, value);
            wire.extend_from_slice(&follower);

            for (surface, decoded) in [
                (
                    "decode_typed_ie_sequence",
                    decode_typed_ie_sequence(&wire, procedure_context(), 0),
                ),
                (
                    "TypedIe::decode_sequence",
                    TypedIe::decode_sequence(&wire, procedure_context()),
                ),
            ] {
                let error = match decoded {
                    Ok(ies) => panic!(
                        "{surface} discarded {label} at instance {instance}, returning {ies:?}, \
                         instead of failing closed"
                    ),
                    Err(error) => error,
                };

                // The two codes the clause 8.107 value decoder raises. Both
                // are the "Invalid length" disposition clause 7.7.7 names.
                assert!(
                    matches!(
                        error.code(),
                        DecodeErrorCode::Truncated | DecodeErrorCode::InvalidLength { .. }
                    ),
                    "{surface}: {label} at instance {instance} produced {:?}",
                    error.code()
                );
                assert_eq!(
                    error.offset(),
                    *expected_offset,
                    "{surface}: {label} at instance {instance} reported the wrong offset"
                );
                assert_eq!(
                    error.spec_ref(),
                    Some(&SpecRef::new("3gpp", "TS29274", "8.2")),
                    "{surface}: {label} at instance {instance} dropped the spec reference"
                );

                // "together with the type and instance of the offending IE".
                assert_eq!(
                    error.offending_ie(),
                    Some((IE_TYPE_NODE_IDENTIFIER, instance)),
                    "{surface}: {label} at instance {instance} did not name the offending IE"
                );

                // The identity is sufficient to build the response the clause
                // names, using only public API. That is the whole point of
                // failing closed rather than discarding: a discard leaves the
                // caller nothing to put in the Cause IE.
                let (ie_type, offending_instance) =
                    error.offending_ie().expect("offending IE identity");
                let offending = Gtpv2cOffendingIe::new(ie_type, offending_instance)
                    .expect("a four-bit instance is a valid offending-IE identity");
                assert_eq!(
                    Gtpv2cProtocolErrorKind::InvalidIeLength(offending).cause(),
                    CauseValue::InvalidLength
                );
            }
        }
    }
}

/// TS 29.274 clause 7.7.8: "The receiver of a GTP signalling message including
/// an optional information element with a Value that is not in the range
/// defined for this information element value shall discard this IE, but shall
/// treat the rest of the message as if this IE was absent and continue
/// processing." Node Identifier is presence O on its only row in this profile,
/// so every malformed length pair is discarded rather than failing the message.
///
/// The discard is pinned on `S2bMessage::decode`, the surface that resolves a
/// procedure and direction and therefore knows the Table 7.2.1-1 presence the
/// clause conditions the discard on. The profile-less sequence decoders cannot
/// establish that presence and fail closed instead, which is pinned above.
///
/// This is the *shape* axis of the discard evidence -- every entry in
/// `MALFORMED_LENGTH_PAIRS`, at the one instance Table 7.2.1-1 lists. The
/// *instance* axis, all sixteen of them for one shape, is pinned separately by
/// `a_malformed_node_identifier_is_discarded_and_the_rest_of_the_request_decodes`.
///
/// "The rest of the message" is the half of the requirement a bare `is_ok()`
/// would miss, so the projection is compared against the pristine fixture
/// rather than merely checked for the absence of IE 176.
#[test]
fn every_malformed_length_pair_is_discarded_on_the_s2b_receive_path() {
    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        assert!(
            pristine.len() >= 10,
            "{level:?} baseline projection is too small to be evidence: {}",
            pristine.len()
        );

        for (label, value, _) in MALFORMED_LENGTH_PAIRS {
            // Spliced ahead of every fixture IE, so a discard that also
            // abandoned the remaining sequence would lose all of them.
            let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &raw_ie(0, value));
            let decoded = typed_ies(&message, *level, label);
            assert!(
                !decoded
                    .iter()
                    .any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
                "{level:?} surfaced {label}"
            );
            assert_eq!(
                decoded, pristine,
                "{level:?} did not process the rest of the message as if {label} was absent"
            );
        }
    }
}

/// Every duplicate policy `DecodeContext` exposes. Clause 7.7.8 conditions the
/// discard on nothing but the IE's presence, so a caller's clause 7.7.10
/// duplicate policy must not change whether a malformed optional IE is
/// discarded -- only what happens to IEs that were actually retained.
const DUPLICATE_POLICIES: &[DuplicateIePolicy] = &[
    DuplicateIePolicy::Reject,
    DuplicateIePolicy::First,
    DuplicateIePolicy::Last,
];

fn duplicate_policy_context(policy: DuplicateIePolicy, level: ValidationLevel) -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: policy,
        validation_level: level,
        ..DecodeContext::default()
    }
}

/// TS 29.274 clause 7.7.8 requires the rest of the message to be treated "as if
/// this IE was absent". Absent means absent from the clause 7.7.10 duplicate
/// bookkeeping too, not merely from the returned sequence: a discarded IE that
/// still held its `(type, instance)` slot would make the next genuine IE at
/// that key look like a repeat, and there is no repeat -- the wire carries one
/// interpretable Node Identifier.
///
/// Instance 0 is load-bearing and is what separates this from the discard tests
/// above, which all put the follower at instance 1 where no key collision is
/// possible. Instance 0 is the only instance Table 7.2.1-1 lists for the 3GPP
/// AAA Server Identifier, so it is the only key where a spliced malformed IE
/// can collide with a real one -- which is exactly what an on-path attacker
/// would splice.
///
/// `DuplicateIePolicy::Reject` is the decisive case: it is what
/// `DecodeContext::conservative()`, documented as "conservative defaults
/// suitable for untrusted network input", selects.
///
/// Driven through `S2bMessage::decode`, which is where the clause 7.7.8
/// discard lives now that the profile-less decoders fail closed. At
/// `ProcedureAware` the S2b receive path selects `DuplicateIePolicy::First`
/// itself, as clause 7.7.10 is a receiver rule; at `Structural` and `Strict`
/// the caller's policy is the one in force. The assertion is the same under
/// all of them: the genuine Node Identifier survives.
#[test]
fn a_discarded_node_identifier_does_not_occupy_its_duplicate_slot() {
    let carrier = built_create_session_request();

    for (label, value, _) in MALFORMED_LENGTH_PAIRS {
        // Malformed first, genuine second, both at instance 0: the only key
        // where a spliced IE can collide with a real one.
        let mut injected = raw_ie(0, value);
        injected.extend_from_slice(&node_identifier_ie(0, b"aaa", b"org"));
        let message = with_leading_ie(&carrier, &injected);

        for policy in DUPLICATE_POLICIES {
            for level in TYPED_LEVELS {
                let what = format!("{label} under {policy:?}/{level:?}");
                let decoded =
                    typed_ies_with(&message, duplicate_policy_context(*policy, *level), &what);
                assert_surviving_node_identifier(&decoded, &what);
            }
        }

        // The documented untrusted-input preset, asserted by name rather than
        // by reconstructing its fields, so a change to the preset is caught.
        let what = format!("{label} under conservative()");
        let decoded = typed_ies_with(&message, DecodeContext::conservative(), &what);
        assert_surviving_node_identifier(&decoded, &what);
    }
}

/// The peer-controlled denial of service clause 7.7.8 exists to remove is not
/// only reachable with one malformed IE. Two malformed Node Identifiers at the
/// same key are two discards, not a duplicate: nothing was retained, so there
/// is nothing for clause 7.7.10 to be about. Without this, `Reject` still
/// failed the whole message for four peer-supplied octets instead of two.
#[test]
fn repeated_malformed_node_identifiers_at_one_key_are_all_discarded() {
    for (label, value, _) in MALFORMED_LENGTH_PAIRS {
        let mut injected = raw_ie(0, value);
        injected.extend_from_slice(&raw_ie(0, value));
        injected.extend_from_slice(&raw_ie(0, value));
        let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &injected);
        let pristine = typed_ies(
            CREATE_SESSION_REQUEST_FIXTURE,
            ValidationLevel::Strict,
            "the bare fixture",
        );

        for policy in DUPLICATE_POLICIES {
            let what = format!("three copies of {label} under {policy:?}");
            let decoded = typed_ies_with(
                &message,
                duplicate_policy_context(*policy, ValidationLevel::Strict),
                &what,
            );
            assert!(
                !decoded
                    .iter()
                    .any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
                "{what}: retained a Node Identifier from three malformed IEs"
            );
            assert_eq!(
                decoded, pristine,
                "{what}: did not process the rest of the message as if all three were absent"
            );
        }
    }
}

/// The boundary in the other direction. Once an occurrence has been *retained*,
/// a later one at the same key is a genuine clause 7.7.10 repeat and the
/// caller's duplicate policy governs it -- clause 7.7.8 discards the malformed
/// IE from the typed view, it does not erase the retained one's slot. This
/// pins that the discard did not turn every duplicate into a silent drop.
///
/// Duplicate detection runs *before* the value decode, so under `Reject` the
/// repeat fails the message on its key alone and the malformed value is never
/// reached. That is why this case still reports `DuplicateIe` rather than the
/// value-level error, on this path and on the profile-less one alike.
#[test]
fn a_retained_node_identifier_still_makes_a_later_one_a_duplicate() {
    let mut injected = node_identifier_ie(0, b"aaa", b"org");
    injected.extend_from_slice(&raw_ie(0, &[0x09, b'a']));
    let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &injected);
    let strict = ValidationLevel::Strict;

    let rejected = S2bMessage::decode(
        &message,
        duplicate_policy_context(DuplicateIePolicy::Reject, strict),
    )
    .expect_err("a second occurrence at a retained key is a clause 7.7.10 repeat");
    assert_eq!(*rejected.code(), DecodeErrorCode::DuplicateIe);

    for policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
        let what = format!("the repeat under {policy:?}");
        let decoded = typed_ies_with(&message, duplicate_policy_context(policy, strict), &what);
        assert_surviving_node_identifier(&decoded, &what);
    }
}

/// Every validation level this crate exposes for a typed decode. Clause 7.7.8
/// states one receiver rule and conditions it on nothing but the IE's
/// presence, so all three must reach the same disposition.
///
/// `Structural` verifies lengths and container structure, which the IE framing
/// still does; `Strict` enforces "field cardinality, enum ranges, and critical
/// IE rules", and clause 7.7.8 *is* the range rule for an optional IE -- it
/// says discard, so enforcing it means discarding, not exceeding it;
/// `ProcedureAware` additionally runs the clause 7.7.9 instance filter, which
/// discards the IE even earlier. None of the three is documented as a mode a
/// caller opts into knowing it is stricter than TS 29.274.
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

fn typed_ies<'a>(message: &'a [u8], level: ValidationLevel, what: &str) -> Vec<TypedIe<'a>> {
    typed_ies_with(message, level_context(level), what)
}

/// The same S2b receive projection under a caller-supplied context, for the
/// tests whose axis is `DecodeContext` rather than the validation level.
fn typed_ies_with<'a>(message: &'a [u8], ctx: DecodeContext, what: &str) -> Vec<TypedIe<'a>> {
    let (_, decoded) = S2bMessage::decode(message, ctx)
        .unwrap_or_else(|error| panic!("the S2b receive path rejected {what}: {error:?}"));
    decoded
        .as_view()
        .unwrap_or_else(|| panic!("no typed view for {what}"))
        .ies
        .clone()
}

/// A Create Session Request carrying only IEs this crate types.
///
/// The committed fixture deliberately includes a private IE that
/// `UnknownIePolicy::Reject` -- and therefore `DecodeContext::conservative()`
/// -- fails on for reasons that have nothing to do with clause 7.7.8. Building
/// the carrier from the crate's own builder keeps those two presets on the
/// axis actually under test.
fn built_create_session_request() -> Vec<u8> {
    let built =
        s2b_create_session_request(create_session_request()).expect("the built request is valid");
    let mut encoded = BytesMut::new();
    built
        .encode(&mut encoded, EncodeContext::default())
        .expect("built request encodes");
    encoded.to_vec()
}

/// Exactly one Node Identifier survived, and it is the interpretable one.
///
/// Asserted by value rather than by count alone: a decoder that surfaced the
/// malformed occupant instead of the genuine IE would satisfy a bare count.
fn assert_surviving_node_identifier(ies: &[TypedIe<'_>], what: &str) {
    let found: Vec<&TypedIe<'_>> = ies
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{what}: the genuine Node Identifier did not survive alone, got {found:?}"
    );
    assert_eq!(found[0].instance, 0, "{what}: wrong instance survived");
    let TypedIeValue::NodeIdentifier(value) = &found[0].value else {
        panic!("{what}: the surviving Node Identifier is not typed");
    };
    assert_eq!(value.name(), b"aaa", "{what}: wrong Node Name survived");
    assert_eq!(value.realm(), b"org", "{what}: wrong Node Realm survived");
}

/// TS 29.274 clause 7.7.8, on an optional IE with an out-of-range Value: the
/// receiver "shall discard this IE, but shall treat the rest of the message as
/// if this IE was absent and continue processing", and "All semantically
/// incorrect optional information elements in a GTP signalling message shall be
/// treated as not present in the message." Table 7.2.1-1 gives Node Identifier
/// presence O, so two peer-controlled octets must not cost the whole message.
///
/// Both halves of the requirement are asserted: the IE is absent, *and* the
/// typed projection is identical to the one the same fixture yields without the
/// injected IE. Equality against the pristine projection is what proves "as if
/// this IE was absent"; an `is_ok()` check would pass on a decoder that dropped
/// every IE.
#[test]
fn a_malformed_node_identifier_is_discarded_and_the_rest_of_the_request_decodes() {
    // Node Name length 0x09 inside a two-octet value: well-formed IE framing,
    // malformed clause 8.107 content.
    const MALFORMED: &[u8] = &[0x09, b'a'];

    for level in TYPED_LEVELS {
        let pristine = typed_ies(CREATE_SESSION_REQUEST_FIXTURE, *level, "the bare fixture");
        // Guard the comparison itself: an empty or near-empty baseline would
        // make the equality assertions below vacuous.
        assert!(
            pristine.len() >= 10,
            "{level:?} baseline projection is too small to be evidence: {}",
            pristine.len()
        );
        assert!(
            pristine.iter().any(|ie| ie.ie_type() == IE_TYPE_IMSI),
            "{level:?} baseline lost the IMSI"
        );
        assert!(
            pristine
                .iter()
                .any(|ie| matches!(&ie.value, TypedIeValue::FullyQualifiedTeid(teid) if teid.teid == 0x1122_3344)),
            "{level:?} baseline lost the sender F-TEID"
        );
        assert!(
            pristine.iter().any(|ie| matches!(
                &ie.value,
                TypedIeValue::BearerContext(context)
                    if context.members.iter().any(|member| matches!(
                        &member.value,
                        TypedIeValue::EpsBearerId(ebi) if ebi.value == 5
                    ))
            )),
            "{level:?} baseline lost the Bearer Context EBI"
        );

        for instance in 0u8..16 {
            // Spliced in ahead of every fixture IE, so a discard that also
            // abandoned the remaining sequence would lose all of them.
            let message =
                with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &raw_ie(instance, MALFORMED));
            let what = format!("a malformed Node Identifier at instance {instance}");
            let decoded = typed_ies(&message, *level, &what);
            assert!(
                !decoded
                    .iter()
                    .any(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER),
                "{level:?} surfaced {what}"
            );
            assert_eq!(
                decoded, pristine,
                "{level:?} did not process the rest of the message as if {what} was absent"
            );
        }
    }
}

/// The discard has to reach nested scopes, because the typed decoder recurses
/// into a Bearer Context with the same policy. A malformed Node Identifier
/// nested there is discarded and its enclosing container still decodes with its
/// own members intact.
#[test]
fn a_nested_malformed_node_identifier_is_discarded_and_its_container_decodes() {
    // The malformed member comes first and the EBI after it, so a discard that
    // abandoned the rest of the container would lose the EBI asserted below.
    let mut bearer_value = raw_ie(0, &[0x09, b'a']);
    bearer_value.extend_from_slice(&[73, 0, 1, 0, 5]);
    let length = u16::try_from(bearer_value.len()).expect("bearer context fits u16");
    let mut bearer = vec![93];
    bearer.extend_from_slice(&length.to_be_bytes());
    bearer.push(0);
    bearer.extend_from_slice(&bearer_value);

    // Instance 1: the fixture already carries a Bearer Context at instance 0,
    // so a second one there would be resolved by the duplicate policy rather
    // than by the clause 7.7.8 discard under test.
    bearer[3] = 1;

    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &bearer);
    for level in TYPED_LEVELS {
        let decoded = typed_ies(&message, *level, "a nested malformed Node Identifier");
        let nested: Vec<&TypedIe<'_>> = decoded
            .iter()
            .filter(|ie| ie.instance == 1)
            .filter_map(|ie| match &ie.value {
                TypedIeValue::BearerContext(context) => Some(context),
                _ => None,
            })
            .flat_map(|context| context.members.iter())
            .collect();

        assert!(
            !nested
                .iter()
                .any(|member| member.ie_type() == IE_TYPE_NODE_IDENTIFIER),
            "{level:?} surfaced a nested malformed Node Identifier"
        );
        assert!(
            nested.iter().any(|member| matches!(
                &member.value,
                TypedIeValue::EpsBearerId(ebi) if ebi.value == 5
            )),
            "{level:?} lost the sibling EBI the container must still carry"
        );
    }
}

/// The discard must not reach an IE whose presence makes it the receiver's job
/// to reject. Clauses 7.7.7 and 7.7.8 split on presence: an optional IE is
/// discarded, but a Mandatory or verifiable Conditional one "shall be
/// considered an error" and earns an "Invalid length" or "Mandatory IE
/// incorrect" response. Sender F-TEID is presence M on Table 7.2.1-1, so
/// corrupting it must still fail the whole decode at every level.
#[test]
fn a_malformed_mandatory_ie_still_fails_the_whole_message() {
    // Clear the V6 flag on the instance-0 F-TEID: the declared 25-octet value
    // then carries nine octets of addressing plus sixteen the decoder has no
    // field for, which is `InvalidLength`, not a framing error.
    let mut corrupted = CREATE_SESSION_REQUEST_FIXTURE.to_vec();
    let flags = ie_value_offset(&corrupted, IE_TYPE_F_TEID, 0).expect("fixture carries an F-TEID");
    assert_eq!(corrupted[flags], 0xde, "fixture F-TEID flags moved");
    corrupted[flags] = 0x9e;

    for level in TYPED_LEVELS {
        let error = S2bMessage::decode(&corrupted, level_context(*level))
            .err()
            .unwrap_or_else(|| panic!("{level:?} accepted a malformed mandatory F-TEID"));
        assert!(
            matches!(error.code(), DecodeErrorCode::InvalidLength { .. }),
            "{level:?} produced {:?} rather than InvalidLength",
            error.code()
        );
    }
}

/// Absolute offset of the first octet of the value of the first IE with this
/// type and instance, walking the TLIV region the same way the decoder does.
fn ie_value_offset(message: &[u8], ie_type: u8, instance: u8) -> Option<usize> {
    // TS 29.274 clause 5.5: the GTPv2-C header is twelve octets when the TEID
    // flag is set, which every message in this file's fixtures sets.
    let mut cursor = 12usize;
    while cursor + 4 <= message.len() {
        let length = usize::from(u16::from_be_bytes([
            message[cursor + 1],
            message[cursor + 2],
        ]));
        if message[cursor] == ie_type && message[cursor + 3] & 0x0f == instance {
            return Some(cursor + 4);
        }
        cursor += 4 + length;
    }
    None
}

/// Clause 7.7.8 discards the IE but says nothing about the octets a forwarding
/// or logging caller kept. Raw-preserving encode blits the parsed IE region, so
/// the malformed IE must still come back byte-exact -- and that is now
/// checkable at all, because the decode no longer fails before the encode runs.
#[test]
fn a_discarded_node_identifier_is_still_byte_exact_under_raw_preserving_encode() {
    let message = with_extra_ie(CREATE_SESSION_REQUEST_FIXTURE, &raw_ie(0, &[0x09, b'a']));
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

/// The S2b receive profile forces `DuplicateIePolicy::First` for clause 7.7.10,
/// so a discarded IE that kept its key would not fail the message -- it would
/// fail open: the genuine 3GPP AAA Server Identifier that follows would be
/// dropped, and `S2bReceiveDiagnostics` would report a duplicate that the wire
/// does not contain. A caller reading that diagnostic would be told the wrong
/// cause about a field naming operator AAA infrastructure.
///
/// The malformed IE is spliced *ahead* of the genuine one, which is the shape
/// an on-path attacker would use: six octets in front of the real IE.
#[test]
fn a_discarded_node_identifier_neither_suppresses_nor_fabricates_evidence() {
    let mut injected = raw_ie(0, &[0x09, b'a']);
    injected.extend_from_slice(&node_identifier_ie(0, b"aaa", b"org"));
    let message = with_leading_ie(CREATE_SESSION_REQUEST_FIXTURE, &injected);

    let (_, decoded) = S2bMessage::decode_with_diagnostics(&message, procedure_context())
        .expect("a spliced malformed Node Identifier must not fail the receive");

    let ies = &decoded
        .message()
        .as_view()
        .expect("Create Session Request view")
        .ies;
    let found: Vec<&TypedIe<'_>> = ies
        .iter()
        .filter(|ie| ie.ie_type() == IE_TYPE_NODE_IDENTIFIER)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "the genuine Node Identifier was suppressed by the discarded one"
    );
    let TypedIeValue::NodeIdentifier(value) = &found[0].value else {
        panic!("the surviving Node Identifier is not typed");
    };
    assert_eq!(value.name(), b"aaa");
    assert_eq!(value.realm(), b"org");

    assert!(
        decoded.diagnostics().is_empty(),
        "a clause 7.7.8 discard fabricated duplicate evidence: {:?}",
        decoded.diagnostics()
    );
}

/// `UnknownIePolicy` is a separate axis from clause 7.7.8. A malformed IE 176
/// is a *known* IE with an out-of-range value, not an unknown IE, so `Reject`
/// -- documented as rejecting "messages containing unknown IEs" -- must not
/// turn the clause 7.7.8 discard back into a failure.
///
/// The genuine Node Identifier is spliced in alongside the malformed one so
/// each policy has a retained IE to be judged on. The carrier is built rather
/// than the committed fixture, because that fixture carries a private IE which
/// `Reject` fails on for reasons unrelated to clause 7.7.8 -- that would test
/// the carrier, not the rule.
#[test]
fn a_malformed_node_identifier_is_discarded_under_every_unknown_ie_policy() {
    let carrier = built_create_session_request();
    let mut injected = raw_ie(0, &[0x09, b'a']);
    injected.extend_from_slice(&node_identifier_ie(0, b"aaa", b"org"));
    let message = with_leading_ie(&carrier, &injected);

    for policy in [
        UnknownIePolicy::Drop,
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Reject,
    ] {
        let ctx = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::default()
        };
        let what = format!("a malformed Node Identifier under {policy:?}");
        let decoded = typed_ies_with(&message, ctx, &what);
        assert_surviving_node_identifier(&decoded, &what);

        let pristine = typed_ies_with(&carrier, ctx, "the bare carrier");
        let without_node_identifier: Vec<TypedIe<'_>> = decoded
            .iter()
            .filter(|ie| ie.ie_type() != IE_TYPE_NODE_IDENTIFIER)
            .cloned()
            .collect();
        assert_eq!(
            without_node_identifier, pristine,
            "{what}: the rest of the message was not processed as if it was absent"
        );
    }
}

/// Clauses 7.7.7 and 7.7.8 bind "the receiver of a GTP signalling message".
/// They license nothing on the send path, so the builders' self-check keeps
/// rejecting: a caller who hands in malformed IE 176 octets gets a build error
/// rather than a message that carries them with the IE quietly missing from the
/// typed view. This is the boundary that stops the receiver fix over-reaching.
#[test]
fn builders_still_reject_a_malformed_caller_supplied_node_identifier() {
    let malformed = TypedIe {
        instance: 0,
        value: TypedIeValue::Raw(RawIe {
            ie_type: IE_TYPE_NODE_IDENTIFIER,
            instance: 0,
            spare: 0,
            value: &[0x09, b'a'],
        }),
    };
    let mut request = create_session_request();
    request.additional_ies.push(malformed);
    assert!(
        s2b_create_session_request(request).is_err(),
        "the builder must not emit a malformed Node Identifier"
    );
}

/// The sender-side reject boundary must hold one level down as well.
/// `BearerContext::members` is a public `Vec<TypedIe>`, so a caller can put a
/// malformed IE 176 inside a grouped IE without going through
/// `additional_ies`. The nested decode receives the same `IeDecodePolicy` as
/// the top level, and that is only checkable with a nested case: forcing
/// `MalformedOptionalIePolicy::Discard` on the nested `BearerContext` call
/// otherwise leaves the whole suite green, because nothing exercises it.
#[test]
fn builders_still_reject_a_malformed_node_identifier_inside_a_bearer_context() {
    let mut request = create_session_request();
    request.bearer_context.members.push(TypedIe {
        instance: 0,
        value: TypedIeValue::Raw(RawIe {
            ie_type: IE_TYPE_NODE_IDENTIFIER,
            instance: 0,
            spare: 0,
            value: &[0x09, b'a'],
        }),
    });
    assert!(
        s2b_create_session_request(request).is_err(),
        "the builder must not emit a malformed Node Identifier nested in a Bearer Context"
    );
}

/// The malformed-value reject is not scoped to the request builders. Every S2b
/// builder routes through `build_s2b_profile_message`, whose self-check runs
/// under `S2bDecodePurpose::CanonicalBuilder`, so a response builder rejects
/// the same octets. Pinned because the README states the boundary as the
/// builders' rather than the request builders' -- and that sentence is only
/// true if a response builder really does reject.
#[test]
fn response_builders_also_reject_a_malformed_node_identifier() {
    let built = s2b_delete_session_response(S2bDeleteSessionResponse {
        sequence_number: 0x01_0206,
        teid: 0x1122_3344,
        cause: CauseValue::RequestAccepted,
        additional_ies: vec![TypedIe {
            instance: 0,
            value: TypedIeValue::Raw(RawIe {
                ie_type: IE_TYPE_NODE_IDENTIFIER,
                instance: 0,
                spare: 0,
                value: &[0x09, b'a'],
            }),
        }],
    });
    let error = built.expect_err("a response builder must not emit malformed IE 176 octets");
    assert!(
        format!("{error:?}").contains("Truncated"),
        "the response builder rejected for the wrong reason: {error:?}"
    );
}

/// Clause 7.7.9 disposition is resolved before the value is typed, so a Node
/// Identifier at an instance Table 7.2.1-1 does not list never reaches the
/// typed decoder at all. Both clauses now end in a discard, so this pins the
/// ordering rather than a difference in outcome: an unlisted instance is
/// dropped by the receive grammar, not by clause 7.7.8.
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
/// appears: a well-formed value surfaces even at an instance the S2b receive
/// grammar does not list.
///
/// The malformed half pins the other side of the same fact. Because this path
/// is not procedure aware it has resolved no presence, so it does not apply
/// the clause 7.7.8 discard -- it fails closed and names the offending IE.
/// The validation level is not the axis that decides this; the entry point is.
/// `S2bMessage::decode` discards at `Structural` too, which is pinned by
/// `every_malformed_length_pair_is_discarded_on_the_s2b_receive_path`.
#[test]
fn structural_decode_types_node_identifier_outside_the_receive_grammar() {
    let (_, bare) = Message::decode(DELETE_SESSION_REQUEST_FIXTURE, structural_context())
        .expect("structural decode succeeds");
    let baseline = decode_typed_ie_sequence(bare.raw_ies, structural_context(), 0)
        .expect("structural typed decode succeeds");
    assert!(
        !baseline.is_empty(),
        "the baseline projection must carry IEs for the comparison to mean anything"
    );

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
    let error = decode_typed_ie_sequence(decoded.raw_ies, structural_context(), 0).expect_err(
        "the profile-less decoder cannot establish presence and must fail closed at Structural",
    );
    assert!(
        matches!(
            error.code(),
            DecodeErrorCode::Truncated | DecodeErrorCode::InvalidLength { .. }
        ),
        "unexpected code {:?}",
        error.code()
    );
    assert_eq!(
        error.offending_ie(),
        Some((IE_TYPE_NODE_IDENTIFIER, 4)),
        "the failure did not name the offending IE and instance"
    );

    // The well-formed baseline is still what the same path returns without the
    // malformed IE, so the failure above is attributable to that IE alone.
    let (_, pristine) = Message::decode(DELETE_SESSION_REQUEST_FIXTURE, structural_context())
        .expect("structural decode succeeds");
    assert_eq!(
        decode_typed_ie_sequence(pristine.raw_ies, structural_context(), 0)
            .expect("the unmodified fixture still decodes"),
        baseline
    );
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

/// Only the request builders gate `additional_ies` by *instance*. The response
/// builders validate under `S2bDecodePurpose::CanonicalBuilder`, which skips
/// the clause 7.7.9 receive filter, so they still emit a raw IE 176 at an
/// instance this crate's own procedure-aware receiver discards. That looseness
/// is pre-existing and applies to every known IE; it is pinned here so the
/// README and CONFORMANCE sentences scoping the *instance* claim to request
/// builders stay honest. The malformed-*value* reject is a separate axis and is
/// not so scoped -- see the response-builder test below.
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
