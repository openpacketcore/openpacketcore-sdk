#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmAaaFailureIndication, SwmDiameterEapAnswer,
    SwmDiameterEapAnswerEnvelope, SwmDiameterEapRequest, SwmDiameterEapRequestEnvelope,
    SwmDiameterResult, SwmDiameterTransaction, SwmEmergencyAuthorizationError,
    SwmEmergencyAuthorizationEvidence, SwmEmergencyServices, SwmHighPriorityAccessInfo,
    SwmQosCapability, SwmQosProfileTemplate, SwmTerminalInformation, SwmVisitedNetworkIdentifier,
    AVP_AUTH_REQUEST_TYPE, AVP_EAP_PAYLOAD,
};
use opc_proto_diameter::base;
use opc_proto_diameter::{
    AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, Encode,
    EncodeContext, UnknownIePolicy,
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

    let verify = |retry: &SwmDiameterEapRequest| {
        let initial_exchange = SwmDiameterEapRequestEnvelope::for_outbound(
            initial.clone(),
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

    verify(&valid_retry).expect("adding only Terminal-Information preserves retry identity");

    enum Mutation {
        QosCapability,
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

    for mutation in [
        Mutation::QosCapability,
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
            verify(&changed).expect_err("retry context mutation must fail closed"),
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
