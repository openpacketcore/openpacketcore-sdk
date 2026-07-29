#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmAaaFailureIndication, SwmDiameterEapAgentDeliveryFailure,
    SwmDiameterEapAnswer, SwmDiameterEapAnswerEnvelope, SwmDiameterEapRequest,
    SwmDiameterEapRequestEnvelope, SwmDiameterResult, SwmDiameterTransaction,
    SwmEmergencyAuthorizationError, SwmEmergencyAuthorizationEvidence, SwmEmergencyServices,
    SwmHighPriorityAccessInfo, SwmMip6AgentInfo, SwmQosCapability, SwmQosProfileTemplate,
    SwmTerminalInformation, SwmVisitedNetworkIdentifier, AVP_AUTH_REQUEST_TYPE, AVP_EAP_PAYLOAD,
};
use opc_proto_diameter::apps::VENDOR_ID_3GPP;
use opc_proto_diameter::base;
use opc_proto_diameter::{
    AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, Encode,
    EncodeContext, EncodeErrorCode, UnknownIePolicy,
};
use opc_types::{Imei, Imei15};

const HOP_BY_HOP: u32 = 0x1122_3344;
const END_TO_END: u32 = 0x5566_7788;
const UNKNOWN_CODE: AvpCode = AvpCode::new(900_001);
const OTHER_UNKNOWN_CODE: AvpCode = AvpCode::new(900_002);
const FOREIGN_VENDOR: VendorId = VendorId::new(42_424);

#[derive(Clone, Copy)]
enum Role {
    Request,
    Answer,
}

fn raw_avp(code: AvpCode, flags: u8, vendor_id: Option<VendorId>, value: &[u8]) -> Vec<u8> {
    assert_eq!(flags & AvpFlags::VENDOR != 0, vendor_id.is_some());
    let header_len = if vendor_id.is_some() { 12 } else { 8 };
    let length = header_len + value.len();
    assert!(length <= 0x00ff_ffff);

    let mut encoded = Vec::with_capacity((length + 3) & !3);
    encoded.extend_from_slice(&code.get().to_be_bytes());
    encoded.push(flags);
    encoded.extend_from_slice(&[
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ]);
    if let Some(vendor_id) = vendor_id {
        encoded.extend_from_slice(&vendor_id.get().to_be_bytes());
    }
    encoded.extend_from_slice(value);
    encoded.resize((length + 3) & !3, 0);
    encoded
}

fn base_avps(role: Role) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut append = |avp: Vec<u8>| raw.extend_from_slice(&avp);
    append(raw_avp(
        base::AVP_SESSION_ID,
        AvpFlags::MANDATORY,
        None,
        b"synthetic-session",
    ));
    append(raw_avp(
        base::AVP_AUTH_APPLICATION_ID,
        AvpFlags::MANDATORY,
        None,
        &swm::APPLICATION_ID.get().to_be_bytes(),
    ));
    match role {
        Role::Request => {
            append(raw_avp(
                base::AVP_ORIGIN_HOST,
                AvpFlags::MANDATORY,
                None,
                b"epdg.synthetic.example",
            ));
            append(raw_avp(
                base::AVP_ORIGIN_REALM,
                AvpFlags::MANDATORY,
                None,
                b"visited.synthetic.example",
            ));
            append(raw_avp(
                base::AVP_DESTINATION_REALM,
                AvpFlags::MANDATORY,
                None,
                b"home.synthetic.example",
            ));
            append(raw_avp(
                AVP_AUTH_REQUEST_TYPE,
                AvpFlags::MANDATORY,
                None,
                &3_u32.to_be_bytes(),
            ));
            append(raw_avp(
                AVP_EAP_PAYLOAD,
                AvpFlags::MANDATORY,
                None,
                &[2, 7, 0, 5, 1],
            ));
        }
        Role::Answer => {
            append(raw_avp(
                AVP_AUTH_REQUEST_TYPE,
                AvpFlags::MANDATORY,
                None,
                &3_u32.to_be_bytes(),
            ));
            append(raw_avp(
                base::AVP_RESULT_CODE,
                AvpFlags::MANDATORY,
                None,
                &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
            ));
            append(raw_avp(
                base::AVP_ORIGIN_HOST,
                AvpFlags::MANDATORY,
                None,
                b"aaa.synthetic.example",
            ));
            append(raw_avp(
                base::AVP_ORIGIN_REALM,
                AvpFlags::MANDATORY,
                None,
                b"home.synthetic.example",
            ));
            append(raw_avp(
                AVP_EAP_PAYLOAD,
                AvpFlags::MANDATORY,
                None,
                &[3, 7, 0, 4],
            ));
        }
    }
    raw
}

fn fixture(role: Role, extensions: &[Vec<u8>]) -> (Vec<u8>, usize) {
    let mut raw = base_avps(role);
    let first_extension_offset = 20 + raw.len();
    for extension in extensions {
        raw.extend_from_slice(extension);
    }
    let header = match role {
        Role::Request => Header::new(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
        Role::Answer => Header::new(
            CommandFlags::answer(true, false),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
    };
    let message = OwnedMessage {
        header,
        raw_avps: Bytes::from(raw),
    };
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic fixture must encode");
    (wire.to_vec(), first_extension_offset)
}

fn parsed_request_envelope(
    extensions: &[Vec<u8>],
    ctx: DecodeContext,
) -> SwmDiameterEapRequestEnvelope {
    let (wire, _) = fixture(Role::Request, extensions);
    swm::parse_swm_diameter_eap_request_envelope(&decode_fixture(&wire), ctx)
        .expect("synthetic DER extensions must parse")
}

fn qos_profile_with_extension(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut profile = raw_avp(
        base::AVP_VENDOR_ID,
        AvpFlags::MANDATORY,
        None,
        &0_u32.to_be_bytes(),
    );
    profile.extend_from_slice(&raw_avp(
        swm::AVP_QOS_PROFILE_ID,
        AvpFlags::MANDATORY,
        None,
        &0_u32.to_be_bytes(),
    ));
    profile.extend_from_slice(&raw_avp(code, flags, None, value));
    raw_avp(
        swm::AVP_QOS_PROFILE_TEMPLATE,
        AvpFlags::MANDATORY,
        None,
        &profile,
    )
}

fn qos_capability_with_profile_extension(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    let profile = qos_profile_with_extension(code, flags, value);
    raw_avp(swm::AVP_QOS_CAPABILITY, AvpFlags::MANDATORY, None, &profile)
}

fn qos_capability_with_extension(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut capability = qos_profile_with_extension(UNKNOWN_CODE, 0, b"profile-stable");
    capability.extend_from_slice(&raw_avp(code, flags, None, value));
    raw_avp(
        swm::AVP_QOS_CAPABILITY,
        AvpFlags::MANDATORY,
        None,
        &capability,
    )
}

fn qos_capability_with_nested_extensions(
    profile_extension_value: &[u8],
    capability_extension_value: &[u8],
) -> Vec<u8> {
    let mut capability = qos_profile_with_extension(UNKNOWN_CODE, 0, profile_extension_value);
    capability.extend_from_slice(&raw_avp(
        OTHER_UNKNOWN_CODE,
        0,
        None,
        capability_extension_value,
    ));
    raw_avp(
        swm::AVP_QOS_CAPABILITY,
        AvpFlags::MANDATORY,
        None,
        &capability,
    )
}

fn supported_features_with_extension(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut features = raw_avp(
        base::AVP_VENDOR_ID,
        AvpFlags::MANDATORY,
        None,
        &VENDOR_ID_3GPP.get().to_be_bytes(),
    );
    features.extend_from_slice(&raw_avp(
        swm::AVP_FEATURE_LIST_ID,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    ));
    features.extend_from_slice(&raw_avp(
        swm::AVP_FEATURE_LIST,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &0_u32.to_be_bytes(),
    ));
    features.extend_from_slice(&raw_avp(code, flags, None, value));
    raw_avp(
        swm::AVP_SUPPORTED_FEATURES,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &features,
    )
}

fn oc_supported_features_with_extension(code: AvpCode, flags: u8, value: &[u8]) -> Vec<u8> {
    raw_avp(
        swm::AVP_OC_SUPPORTED_FEATURES,
        0,
        None,
        &raw_avp(code, flags, None, value),
    )
}

fn decode_fixture(wire: &[u8]) -> Message<'_> {
    let framing = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::First,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        max_ies: 512,
        max_message_len: 256 * 1024,
        ..DecodeContext::default()
    };
    let (tail, message) = Message::decode(wire, framing).expect("valid synthetic Diameter framing");
    assert!(tail.is_empty());
    message
}

fn context(
    unknown_ie_policy: UnknownIePolicy,
    duplicate_ie_policy: DuplicateIePolicy,
) -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        unknown_ie_policy,
        duplicate_ie_policy,
        ..DecodeContext::default()
    }
}

type Metadata = (u32, Option<u32>, u8, usize);

fn metadata(
    role: Role,
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<Vec<Metadata>, DecodeError> {
    let avps = match role {
        Role::Request => swm::parse_swm_diameter_eap_request(message, ctx)?
            .extensions
            .metadata()
            .map(|metadata| {
                (
                    metadata.code().get(),
                    metadata.vendor_id().map(VendorId::get),
                    metadata.flags().bits(),
                    metadata.value_len(),
                )
            })
            .collect(),
        Role::Answer => swm::parse_swm_diameter_eap_answer(message, ctx)?
            .extensions
            .metadata()
            .map(|metadata| {
                (
                    metadata.code().get(),
                    metadata.vendor_id().map(VendorId::get),
                    metadata.flags().bits(),
                    metadata.value_len(),
                )
            })
            .collect(),
    };
    Ok(avps)
}

fn rebuild(role: Role, message: &Message<'_>, ctx: DecodeContext) -> OwnedMessage {
    match role {
        Role::Request => {
            let request = swm::parse_swm_diameter_eap_request(message, ctx)
                .expect("DER with retained extensions must parse");
            swm::build_swm_diameter_eap_request(
                &request,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("parsed DER extensions must rebuild")
        }
        Role::Answer => {
            let answer = swm::parse_swm_diameter_eap_answer(message, ctx)
                .expect("DEA with retained extensions must parse");
            swm::build_swm_diameter_eap_answer(
                &answer,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("parsed DEA extensions must rebuild")
        }
    }
}

#[test]
fn preserve_retains_redacted_metadata_and_replays_exact_values_at_the_trailing_wildcard() {
    let secret = b"secret-extension-value";
    let vendor_value = b"opaque-vendor-value";
    let extensions = [
        raw_avp(UNKNOWN_CODE, AvpFlags::PROTECTED, None, secret),
        raw_avp(
            OTHER_UNKNOWN_CODE,
            AvpFlags::VENDOR,
            Some(FOREIGN_VENDOR),
            vendor_value,
        ),
    ];
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);

    for role in [Role::Request, Role::Answer] {
        let (wire, _) = fixture(role, &extensions);
        let message = decode_fixture(&wire);
        assert_eq!(
            metadata(role, &message, preserve).expect("optional extensions must be retained"),
            vec![
                (UNKNOWN_CODE.get(), None, AvpFlags::PROTECTED, secret.len()),
                (
                    OTHER_UNKNOWN_CODE.get(),
                    Some(FOREIGN_VENDOR.get()),
                    AvpFlags::VENDOR,
                    vendor_value.len(),
                ),
            ]
        );

        let typed_debug = match role {
            Role::Request => format!(
                "{:?}",
                swm::parse_swm_diameter_eap_request(&message, preserve).expect("DER extensions")
            ),
            Role::Answer => format!(
                "{:?}",
                swm::parse_swm_diameter_eap_answer(&message, preserve).expect("DEA extensions")
            ),
        };
        assert!(!typed_debug.contains("secret-extension-value"));
        assert!(!typed_debug.contains("opaque-vendor-value"));

        let rebuilt = rebuild(role, &message, preserve);
        let rebuilt_message = Message {
            header: rebuilt.header.clone(),
            raw_avps: &rebuilt.raw_avps,
            tail: &[],
        };
        let replayed = rebuilt_message
            .avps(context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last))
            .collect::<Result<Vec<_>, _>>()
            .expect("rebuilt AVPs are well formed");
        let trailing = &replayed[replayed.len() - 2..];
        assert_eq!(trailing[0].header.code, UNKNOWN_CODE);
        assert_eq!(trailing[0].header.flags.bits(), AvpFlags::PROTECTED);
        assert_eq!(trailing[0].header.vendor_id, None);
        assert_eq!(trailing[0].value, secret);
        assert_eq!(trailing[1].header.code, OTHER_UNKNOWN_CODE);
        assert_eq!(trailing[1].header.flags.bits(), AvpFlags::VENDOR);
        assert_eq!(trailing[1].header.vendor_id, Some(FOREIGN_VENDOR));
        assert_eq!(trailing[1].value, vendor_value);
    }
}

#[test]
fn public_extension_iteration_yields_only_copyable_value_free_metadata() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<swm::SwmDiameterEapExtensionMetadata>();

    let extension = raw_avp(UNKNOWN_CODE, 0, None, b"not-exposed-by-metadata-api");
    let (wire, _) = fixture(Role::Request, &[extension]);
    let request = swm::parse_swm_diameter_eap_request(
        &decode_fixture(&wire),
        context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last),
    )
    .expect("extension metadata");
    let metadata = request
        .extensions
        .metadata()
        .next()
        .expect("one metadata record");
    let copied = metadata;
    assert_eq!(copied, metadata);
    assert_eq!(copied.code(), UNKNOWN_CODE);
    assert_eq!(copied.value_len(), b"not-exposed-by-metadata-api".len());
    assert!(!format!("{copied:?}").contains("not-exposed-by-metadata-api"));
}

#[test]
fn preserve_drop_reject_and_unknown_m_bit_are_distinct_for_der_and_dea() {
    let optional = raw_avp(UNKNOWN_CODE, 0, None, b"optional");
    let mandatory = raw_avp(UNKNOWN_CODE, AvpFlags::MANDATORY, None, b"mandatory");

    for role in [Role::Request, Role::Answer] {
        let (wire, offset) = fixture(role, std::slice::from_ref(&optional));
        let message = decode_fixture(&wire);
        assert_eq!(
            metadata(
                role,
                &message,
                context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last),
            )
            .expect("Preserve accepts optional unknown AVPs")
            .len(),
            1
        );
        assert!(metadata(
            role,
            &message,
            context(UnknownIePolicy::Drop, DuplicateIePolicy::Last),
        )
        .expect("Drop accepts and discards optional unknown AVPs")
        .is_empty());
        let rejected = metadata(
            role,
            &message,
            context(UnknownIePolicy::Reject, DuplicateIePolicy::Last),
        )
        .expect_err("Reject must refuse an optional unknown AVP");
        assert_eq!(rejected.code(), &DecodeErrorCode::UnknownCriticalIe);
        assert_eq!(rejected.offset(), offset);

        let (mandatory_wire, mandatory_offset) = fixture(role, std::slice::from_ref(&mandatory));
        let mandatory_message = decode_fixture(&mandatory_wire);
        let rejected = metadata(
            role,
            &mandatory_message,
            context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last),
        )
        .expect_err("an unknown M-bit AVP always fails");
        assert_eq!(rejected.code(), &DecodeErrorCode::UnknownCriticalIe);
        assert_eq!(rejected.offset(), mandatory_offset);
    }
}

#[test]
fn foreign_vendor_collision_stays_unmodeled_while_modeled_exact_keys_stay_out() {
    let collision = raw_avp(
        AVP_EAP_PAYLOAD,
        AvpFlags::VENDOR,
        Some(FOREIGN_VENDOR),
        b"foreign-code-collision",
    );
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Reject);

    for role in [Role::Request, Role::Answer] {
        let (wire, _) = fixture(role, std::slice::from_ref(&collision));
        let message = decode_fixture(&wire);
        let retained = metadata(role, &message, preserve)
            .expect("vendor-aware collision must remain an optional unknown AVP");
        assert_eq!(
            retained,
            vec![(
                AVP_EAP_PAYLOAD.get(),
                Some(FOREIGN_VENDOR.get()),
                AvpFlags::VENDOR,
                b"foreign-code-collision".len(),
            )]
        );
    }
}

#[test]
fn duplicate_reject_is_enforced_even_when_unknown_values_are_dropped() {
    let first = raw_avp(UNKNOWN_CODE, 0, None, b"first");
    let second = raw_avp(UNKNOWN_CODE, 0, None, b"second");
    let extensions = [first.clone(), second.clone()];

    for role in [Role::Request, Role::Answer] {
        let (wire, first_offset) = fixture(role, &extensions);
        let message = decode_fixture(&wire);
        let rejected = metadata(
            role,
            &message,
            context(UnknownIePolicy::Drop, DuplicateIePolicy::Reject),
        )
        .expect_err("Drop must not bypass duplicate rejection");
        assert_eq!(rejected.code(), &DecodeErrorCode::DuplicateIe);
        assert_eq!(rejected.offset(), first_offset + first.len());

        for duplicate_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
            let preserve = context(UnknownIePolicy::Preserve, duplicate_policy);
            assert_eq!(
                metadata(role, &message, preserve)
                    .expect("First/Last retain wildcard repetitions")
                    .len(),
                2
            );
            let rebuilt = rebuild(role, &message, preserve);
            let rebuilt_message = Message {
                header: rebuilt.header.clone(),
                raw_avps: &rebuilt.raw_avps,
                tail: &[],
            };
            let replayed = rebuilt_message
                .avps(preserve)
                .collect::<Result<Vec<_>, _>>()
                .expect("replayed duplicates are framed");
            let trailing = &replayed[replayed.len() - 2..];
            assert_eq!(trailing[0].value, b"first");
            assert_eq!(trailing[1].value, b"second");
        }

        let distinct_vendor = raw_avp(
            UNKNOWN_CODE,
            AvpFlags::VENDOR,
            Some(FOREIGN_VENDOR),
            b"same-code-different-key",
        );
        let (wire, _) = fixture(role, &[first.clone(), distinct_vendor]);
        let message = decode_fixture(&wire);
        assert!(metadata(
            role,
            &message,
            context(UnknownIePolicy::Drop, DuplicateIePolicy::Reject),
        )
        .expect("vendor-aware keys are distinct")
        .is_empty());
    }
}

#[test]
fn each_role_accepts_exactly_128_retained_extensions_and_rejects_the_129th() {
    let extensions = (0..129_u32)
        .map(|index| raw_avp(AvpCode::new(910_000 + index), 0, None, &index.to_be_bytes()))
        .collect::<Vec<_>>();
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);

    for role in [Role::Request, Role::Answer] {
        let (wire, _) = fixture(role, &extensions[..128]);
        assert_eq!(
            metadata(role, &decode_fixture(&wire), preserve)
                .expect("128 retained extensions fit")
                .len(),
            128
        );

        let (wire, first_offset) = fixture(role, &extensions);
        let rejected = metadata(role, &decode_fixture(&wire), preserve)
            .expect_err("the 129th retained extension must fail");
        assert_eq!(rejected.code(), &DecodeErrorCode::IeCountExceeded);
        let prior_len = extensions[..128].iter().map(Vec::len).sum::<usize>();
        assert_eq!(rejected.offset(), first_offset + prior_len);
    }
}

#[test]
fn cumulative_retained_bytes_are_checked_before_copying() {
    let first = raw_avp(UNKNOWN_CODE, 0, None, b"12345678");
    let second = raw_avp(OTHER_UNKNOWN_CODE, 0, None, b"abcdefgh");
    assert_eq!(first.len(), 16);
    assert_eq!(second.len(), 16);

    for role in [Role::Request, Role::Answer] {
        let (wire, first_offset) = fixture(role, &[first.clone(), second.clone()]);
        let message = decode_fixture(&wire);
        let mut bounded = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
        bounded.max_message_len = 31;
        let rejected = metadata(role, &message, bounded)
            .expect_err("the second copy exceeds the cumulative retained-byte budget");
        assert_eq!(rejected.code(), &DecodeErrorCode::MessageLengthExceeded);
        assert_eq!(rejected.offset(), first_offset + first.len());
    }
}

#[test]
fn malformed_extension_framing_fails_before_retention() {
    for role in [Role::Request, Role::Answer] {
        let (mut wire, offset) = fixture(role, &[]);
        wire.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0]);
        let length = wire.len();
        wire[1] = ((length >> 16) & 0xff) as u8;
        wire[2] = ((length >> 8) & 0xff) as u8;
        wire[3] = (length & 0xff) as u8;
        let header_ctx = DecodeContext {
            validation_level: opc_protocol::ValidationLevel::HeaderOnly,
            max_message_len: 256 * 1024,
            ..DecodeContext::default()
        };
        let (tail, message) = Message::decode(&wire, header_ctx)
            .expect("header-only decode intentionally defers AVP framing");
        assert!(tail.is_empty());
        let rejected = metadata(
            role,
            &message,
            context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last),
        )
        .expect_err("truncated trailing AVP must fail");
        assert_eq!(rejected.code(), &DecodeErrorCode::Truncated);
        assert_eq!(rejected.offset(), offset);
    }
}

#[test]
fn empty_sealed_collections_preserve_the_prior_der_and_dea_bytes() {
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
    for role in [Role::Request, Role::Answer] {
        let (wire, _) = fixture(role, &[]);
        let message = decode_fixture(&wire);
        assert!(metadata(role, &message, preserve)
            .expect("legacy-shaped message parses")
            .is_empty());
        let rebuilt = rebuild(role, &message, preserve);
        let mut rebuilt_wire = BytesMut::new();
        rebuilt
            .encode(&mut rebuilt_wire, EncodeContext::default())
            .expect("legacy-shaped message rebuilds");
        assert_eq!(rebuilt_wire.as_ref(), wire.as_slice());
    }
}

#[test]
fn der_replay_and_request_binding_reject_same_shape_top_level_extension_drift() {
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
    let parse_envelope = |value: &[u8]| {
        let extension = raw_avp(UNKNOWN_CODE, 0, None, value);
        let (wire, _) = fixture(Role::Request, &[extension]);
        swm::parse_swm_diameter_eap_request_envelope(&decode_fixture(&wire), preserve)
            .expect("DER with one retained extension")
    };
    let retained = parse_envelope(b"der-extension-alpha");
    let changed = parse_envelope(b"der-extension-bravo");
    assert_eq!(
        retained, changed,
        "public metadata equality must not expose same-shape extension bytes"
    );
    assert!(
        !retained.same_replay_payload(&changed),
        "DER replay must use the private exact retained-extension comparator"
    );

    let gateway = SwmMip6AgentInfo::new(
        vec!["192.0.2.10".parse().expect("synthetic IPv4 address")],
        None,
        None,
    )
    .expect("synthetic serving gateway");
    let bound = swm::SwmRequestBoundDeaGatewayContext::chained_s2b_s8(&retained, gateway);
    let (answer_wire, _) = fixture(Role::Answer, &[]);
    let answer = swm::parse_swm_diameter_eap_answer(&decode_fixture(&answer_wire), preserve)
        .expect("synthetic success DEA");
    swm::build_swm_diameter_eap_answer_for_with_gateway_context(
        &changed,
        &answer,
        &bound,
        EncodeContext::default(),
    )
    .expect_err("request binding must reject same-length retained extension drift");
}

#[test]
fn der_class_is_uncomparable_at_every_reachable_retained_extension_depth() {
    const CLASS_BINDING_REASON: &str =
        "SWm agent delivery failure cannot bind a DER containing opaque Class";
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
    let class_alpha = b"opaque-class-alpha";
    let class_bravo = b"opaque-class-bravo";
    assert_eq!(class_alpha.len(), class_bravo.len());

    let cases = [
        (
            "top-level",
            raw_avp(base::AVP_CLASS, 0, None, class_alpha),
            raw_avp(base::AVP_CLASS, 0, None, class_bravo),
        ),
        (
            "top-level protected and M-clear",
            raw_avp(base::AVP_CLASS, AvpFlags::PROTECTED, None, class_alpha),
            raw_avp(base::AVP_CLASS, AvpFlags::PROTECTED, None, class_bravo),
        ),
        (
            "QoS-Capability",
            qos_capability_with_extension(base::AVP_CLASS, 0, class_alpha),
            qos_capability_with_extension(base::AVP_CLASS, 0, class_bravo),
        ),
        (
            "QoS-Profile-Template",
            qos_capability_with_profile_extension(base::AVP_CLASS, 0, class_alpha),
            qos_capability_with_profile_extension(base::AVP_CLASS, 0, class_bravo),
        ),
        (
            "Supported-Features",
            supported_features_with_extension(base::AVP_CLASS, 0, class_alpha),
            supported_features_with_extension(base::AVP_CLASS, 0, class_bravo),
        ),
        (
            "OC-Supported-Features",
            oc_supported_features_with_extension(base::AVP_CLASS, 0, class_alpha),
            oc_supported_features_with_extension(base::AVP_CLASS, 0, class_bravo),
        ),
    ];

    for (site, retained_extension, changed_extension) in cases {
        let retained = parsed_request_envelope(std::slice::from_ref(&retained_extension), preserve);
        let matching = parsed_request_envelope(&[retained_extension], preserve);
        let changed = parsed_request_envelope(&[changed_extension], preserve);
        assert_eq!(
            retained, changed,
            "{site} public equality must remain opaque and metadata-only"
        );
        for candidate in [&matching, &changed] {
            assert_eq!(
                retained.compare_replay_payload(candidate),
                swm::SwmReplayPayloadComparison::OpaqueClassUncomparable,
                "{site} must guard before comparing Class bytes"
            );
            assert!(
                !retained.same_replay_payload(candidate),
                "{site} boolean compatibility API must fail closed"
            );
        }
    }

    let top_level_alpha =
        parsed_request_envelope(&[raw_avp(base::AVP_CLASS, 0, None, class_alpha)], preserve);
    let top_level_bravo =
        parsed_request_envelope(&[raw_avp(base::AVP_CLASS, 0, None, class_bravo)], preserve);
    for request in [&top_level_alpha, &top_level_bravo] {
        let error = swm::SwmDiameterEapGenericErrorAnswer::new_agent_delivery_failure_for(
            request,
            SwmDiameterEapAgentDeliveryFailure::UnableToDeliver,
            "dra.synthetic.example".to_owned(),
            "routing.synthetic.example".to_owned(),
        )
        .expect_err("Class-bearing DER must not enter a public digest binding");
        assert_eq!(
            error.code(),
            &EncodeErrorCode::Structural {
                reason: CLASS_BINDING_REASON,
            }
        );
        let diagnostic = format!("{error:?} {error}");
        for secret in [class_alpha.as_slice(), class_bravo.as_slice()] {
            assert!(
                !diagnostic
                    .as_bytes()
                    .windows(secret.len())
                    .any(|part| part == secret),
                "binding diagnostics must stay value-free"
            );
        }
    }
}

#[test]
fn der_class_free_nested_extensions_remain_exact_for_replay_and_binding() {
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
    let extension_alpha = b"nested-extension-alpha";
    let extension_bravo = b"nested-extension-bravo";
    assert_eq!(extension_alpha.len(), extension_bravo.len());
    let cases = [
        (
            "QoS-Capability",
            qos_capability_with_extension(OTHER_UNKNOWN_CODE, 0, extension_alpha),
            qos_capability_with_extension(OTHER_UNKNOWN_CODE, 0, extension_bravo),
        ),
        (
            "QoS-Profile-Template",
            qos_capability_with_profile_extension(UNKNOWN_CODE, 0, extension_alpha),
            qos_capability_with_profile_extension(UNKNOWN_CODE, 0, extension_bravo),
        ),
        (
            "Supported-Features",
            supported_features_with_extension(UNKNOWN_CODE, 0, extension_alpha),
            supported_features_with_extension(UNKNOWN_CODE, 0, extension_bravo),
        ),
        (
            "OC-Supported-Features",
            oc_supported_features_with_extension(UNKNOWN_CODE, 0, extension_alpha),
            oc_supported_features_with_extension(UNKNOWN_CODE, 0, extension_bravo),
        ),
    ];
    let (answer_wire, _) = fixture(Role::Answer, &[]);
    let answer = swm::parse_swm_diameter_eap_answer(&decode_fixture(&answer_wire), preserve)
        .expect("synthetic success DEA");

    for (site, retained_extension, changed_extension) in cases {
        let retained = parsed_request_envelope(&[retained_extension], preserve);
        let changed = parsed_request_envelope(&[changed_extension], preserve);
        assert_eq!(
            retained, changed,
            "{site} public equality deliberately exposes metadata only"
        );
        assert_eq!(
            retained.compare_replay_payload(&changed),
            swm::SwmReplayPayloadComparison::Different,
            "{site} replay binding must compare retained bytes exactly"
        );
        assert!(!retained.same_replay_payload(&changed));

        let gateway = SwmMip6AgentInfo::new(
            vec!["192.0.2.10".parse().expect("synthetic IPv4 address")],
            None,
            None,
        )
        .expect("synthetic serving gateway");
        let bound = swm::SwmRequestBoundDeaGatewayContext::chained_s2b_s8(&retained, gateway);
        swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &changed,
            &answer,
            &bound,
            EncodeContext::default(),
        )
        .expect_err("{site} request binding must reject same-shape retained-byte drift");
    }
}

#[test]
fn emergency_retry_preserves_extensions_and_all_non_terminal_access_context() {
    let imei = Imei15::new("490154203237518").expect("synthetic valid IMEI");
    let initial_identity = "0234150999999999@sos.nai.epc.mnc015.mcc234.3gppnetwork.org";
    let preserve = context(UnknownIePolicy::Preserve, DuplicateIePolicy::Last);
    let initial_extension = raw_avp(UNKNOWN_CODE, 0, None, b"initial-retry-context");
    let (wire, _) = fixture(Role::Request, &[initial_extension]);
    let mut initial = swm::parse_swm_diameter_eap_request(&decode_fixture(&wire), preserve)
        .expect("initial recovery DER with extension");
    initial.user_name = Some(initial_identity.to_owned().into());
    initial.auth_request_type = AuthRequestType::AuthorizeAuthenticate;
    initial.eap_payload = swm::build_eap_response_identity(0x17, initial_identity.as_bytes())
        .expect("bounded synthetic EAP identity")
        .into();
    initial.emergency_services = Some(SwmEmergencyServices::emergency_indication());
    let qos_profile_alpha = b"qos-profile-alpha";
    let qos_profile_bravo = b"qos-profile-bravo";
    let qos_capability_alpha = b"qos-capability-alpha";
    let qos_capability_bravo = b"qos-capability-bravo";
    let supported_alpha = b"supported-child-alpha";
    let supported_bravo = b"supported-child-bravo";
    let oc_alpha = b"oc-feature-child-alpha";
    let oc_bravo = b"oc-feature-child-bravo";
    for (alpha, bravo) in [
        (qos_profile_alpha.as_slice(), qos_profile_bravo.as_slice()),
        (
            qos_capability_alpha.as_slice(),
            qos_capability_bravo.as_slice(),
        ),
        (supported_alpha.as_slice(), supported_bravo.as_slice()),
        (oc_alpha.as_slice(), oc_bravo.as_slice()),
    ] {
        assert_eq!(alpha.len(), bravo.len());
    }
    let nested_initial = parsed_request_envelope(
        &[
            qos_capability_with_nested_extensions(qos_profile_alpha, qos_capability_alpha),
            supported_features_with_extension(UNKNOWN_CODE, 0, supported_alpha),
            oc_supported_features_with_extension(UNKNOWN_CODE, 0, oc_alpha),
        ],
        preserve,
    );
    initial.qos_capability = nested_initial.request().qos_capability.clone();
    initial.supported_features = nested_initial.request().supported_features.clone();
    initial.oc_supported_features = nested_initial.request().oc_supported_features.clone();

    let (answer_wire, _) = fixture(Role::Answer, &[]);
    let mut identity_answer =
        swm::parse_swm_diameter_eap_answer(&decode_fixture(&answer_wire), preserve)
            .expect("synthetic identity-recovery DEA");
    identity_answer.session_id = initial.session_id.clone();
    identity_answer.result = SwmDiameterResult::Experimental {
        vendor_id: opc_proto_diameter::apps::VENDOR_ID_3GPP,
        code: swm::DIAMETER_ERROR_USER_UNKNOWN,
    };
    identity_answer.eap_payload = None;
    identity_answer.eap_reissued_payload = None;
    identity_answer.eap_master_session_key = None;

    let mut final_answer =
        swm::parse_swm_diameter_eap_answer(&decode_fixture(&answer_wire), preserve)
            .expect("synthetic successful DEA");
    final_answer.session_id = initial.session_id.clone();
    final_answer.result = SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS);
    final_answer.eap_payload = Some(vec![3, 0x17, 0, 4].into());
    final_answer.eap_reissued_payload = None;
    final_answer.eap_master_session_key = Some(
        swm::derive_unauthenticated_emergency_msk(&imei)
            .as_bytes()
            .to_vec()
            .into(),
    );
    final_answer.mobile_node_identifier = Some(swm::emergency_nai(&imei).into());

    let mut valid_retry = initial.clone();
    valid_retry.terminal_information = Some(SwmTerminalInformation {
        imei: Imei::from(&imei),
        software_version: None,
    });

    let verify = |initial_request: &SwmDiameterEapRequest, retry: &SwmDiameterEapRequest| {
        let initial_exchange = SwmDiameterEapRequestEnvelope::for_outbound(
            initial_request.clone(),
            SwmDiameterTransaction::new(1, 2),
        )
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            identity_answer.clone(),
            SwmDiameterTransaction::new(1, 2),
        ))?;
        let retry_exchange = SwmDiameterEapRequestEnvelope::for_outbound(
            retry.clone(),
            SwmDiameterTransaction::new(3, 4),
        )
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            final_answer.clone(),
            SwmDiameterTransaction::new(3, 4),
        ))?;
        SwmEmergencyAuthorizationEvidence::verify_after_identity_recovery(
            initial_exchange,
            retry_exchange,
            &imei,
        )
    };

    verify(&initial, &valid_retry)
        .expect("adding only Terminal-Information preserves retry identity");

    enum Mutation {
        QosCapability,
        QosCapabilityExtension,
        QosProfileExtension,
        SupportedFeaturesExtension,
        OcSupportedFeaturesExtension,
        VisitedNetworkIdentifier,
        AaaFailureIndication,
        HighPriorityAccessInfo,
        RetainedExtension,
    }

    let changed_extension = raw_avp(UNKNOWN_CODE, 0, None, b"changed-retry-context");
    let (changed_wire, _) = fixture(Role::Request, &[changed_extension]);
    let changed_extensions =
        swm::parse_swm_diameter_eap_request(&decode_fixture(&changed_wire), preserve)
            .expect("second parser-populated extension collection")
            .extensions;
    let qos_capability_changed = parsed_request_envelope(
        &[qos_capability_with_nested_extensions(
            qos_profile_alpha,
            qos_capability_bravo,
        )],
        preserve,
    )
    .request()
    .qos_capability
    .clone()
    .expect("parser-populated QoS capability");
    let qos_profile_changed = parsed_request_envelope(
        &[qos_capability_with_nested_extensions(
            qos_profile_bravo,
            qos_capability_alpha,
        )],
        preserve,
    )
    .request()
    .qos_capability
    .clone()
    .expect("parser-populated QoS capability");
    let supported_features_changed = parsed_request_envelope(
        &[supported_features_with_extension(
            UNKNOWN_CODE,
            0,
            supported_bravo,
        )],
        preserve,
    )
    .request()
    .supported_features
    .clone();
    let oc_supported_features_changed = parsed_request_envelope(
        &[oc_supported_features_with_extension(
            UNKNOWN_CODE,
            0,
            oc_bravo,
        )],
        preserve,
    )
    .request()
    .oc_supported_features
    .clone();

    for mutation in [
        Mutation::QosCapability,
        Mutation::QosCapabilityExtension,
        Mutation::QosProfileExtension,
        Mutation::SupportedFeaturesExtension,
        Mutation::OcSupportedFeaturesExtension,
        Mutation::VisitedNetworkIdentifier,
        Mutation::AaaFailureIndication,
        Mutation::HighPriorityAccessInfo,
        Mutation::RetainedExtension,
    ] {
        let mut changed = valid_retry.clone();
        match mutation {
            Mutation::QosCapability => {
                changed.qos_capability = Some(
                    SwmQosCapability::new(vec![SwmQosProfileTemplate::ietf_diameter()])
                        .expect("one synthetic QoS profile"),
                );
            }
            Mutation::QosCapabilityExtension => {
                changed.qos_capability = Some(qos_capability_changed.clone());
            }
            Mutation::QosProfileExtension => {
                changed.qos_capability = Some(qos_profile_changed.clone());
            }
            Mutation::SupportedFeaturesExtension => {
                changed.supported_features = supported_features_changed.clone();
            }
            Mutation::OcSupportedFeaturesExtension => {
                changed.oc_supported_features = oc_supported_features_changed.clone();
            }
            Mutation::VisitedNetworkIdentifier => {
                changed.visited_network_identifier = Some(
                    SwmVisitedNetworkIdentifier::new("001", "01").expect("synthetic test PLMN"),
                );
            }
            Mutation::AaaFailureIndication => {
                changed.aaa_failure_indication =
                    Some(SwmAaaFailureIndication::previously_assigned_server_unavailable());
            }
            Mutation::HighPriorityAccessInfo => {
                changed.high_priority_access_info = Some(SwmHighPriorityAccessInfo::configured());
            }
            Mutation::RetainedExtension => {
                changed.extensions = changed_extensions.clone();
            }
        }
        assert_eq!(
            verify(&initial, &changed).expect_err("retry context mutation must fail closed"),
            SwmEmergencyAuthorizationError::RetryRequestMismatch
        );
    }

    let class_alpha = raw_avp(base::AVP_CLASS, 0, None, b"opaque-class-alpha");
    let class_bravo = raw_avp(base::AVP_CLASS, 0, None, b"opaque-class-bravo");
    let class_alpha = parsed_request_envelope(&[class_alpha], preserve)
        .request()
        .extensions
        .clone();
    let class_bravo = parsed_request_envelope(&[class_bravo], preserve)
        .request()
        .extensions
        .clone();
    let mut class_initial = initial.clone();
    class_initial.extensions = class_alpha.clone();
    let mut class_matching_retry = valid_retry.clone();
    class_matching_retry.extensions = class_alpha;
    let mut class_nonmatching_retry = valid_retry;
    class_nonmatching_retry.extensions = class_bravo;
    for retry in [&class_matching_retry, &class_nonmatching_retry] {
        assert_eq!(
            verify(&class_initial, retry)
                .expect_err("Class-bearing emergency retries must fail without byte comparison"),
            SwmEmergencyAuthorizationError::RetryRequestMismatch
        );
    }
}

#[allow(dead_code)]
fn public_models_remain_nameable_with_empty_sealed_collections(
    request: SwmDiameterEapRequest,
    answer: SwmDiameterEapAnswer,
) {
    let _ = (request.extensions.is_empty(), answer.extensions.is_empty());
}
