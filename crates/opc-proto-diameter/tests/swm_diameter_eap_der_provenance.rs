#![cfg(feature = "app-swm")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmAaaFailureIndication, SwmConditionalValue, SwmConditionalValueSource,
    SwmDerAccessContext, SwmDerAccessContextErrorCode, SwmDerAccessContextField,
    SwmDiameterEapRequest, SwmEmergencyServices, SwmHighPriorityAccessInfo, SwmMip6FeatureVector,
    SwmOcSupportedFeatures, SwmQosCapability, SwmQosProfileTemplate, SwmRatType,
    SwmRequestedSupportedFeatures, SwmTerminalInformation, SwmVisitedNetworkIdentifier,
};
use opc_proto_diameter::avp::dictionary::Redacted;
use opc_proto_diameter::{Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use opc_types::Imei;

const HOP_BY_HOP: u32 = 0x1020_3040;
const END_TO_END: u32 = 0x5060_7080;
const APN: &str = "ims.synthetic.invalid";
const IMEI: &str = "490154203237518";

fn sample_request() -> SwmDiameterEapRequest {
    SwmDiameterEapRequest {
        session_id: "session;synthetic;der-provenance".into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        origin_host: "epdg.synthetic.invalid".into(),
        origin_realm: "visited.synthetic.invalid".into(),
        destination_realm: "home.synthetic.invalid".into(),
        destination_host: Some("aaa.synthetic.invalid".into()),
        user_name: Some("anonymous@synthetic.invalid".into()),
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
        eap_payload: vec![0x02, 0x2b, 0x00, 0x05, 0x01].into(),
        emergency_services: None,
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: Vec::new(),
        route_records: Vec::new(),
        extensions: Default::default(),
    }
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    message
        .encode(&mut bytes, EncodeContext::default())
        .expect("synthetic message encodes");
    bytes.to_vec()
}

fn parse(bytes: &[u8]) -> SwmDiameterEapRequest {
    let (tail, message) =
        Message::decode(bytes, DecodeContext::conservative()).expect("synthetic message decodes");
    assert!(tail.is_empty());
    swm::parse_swm_diameter_eap_request(&message, DecodeContext::conservative())
        .expect("synthetic DER parses")
}

fn qos() -> SwmQosCapability {
    SwmQosCapability::new(vec![SwmQosProfileTemplate::ietf_diameter()])
        .expect("one QoS profile is valid")
}

fn visited() -> SwmVisitedNetworkIdentifier {
    SwmVisitedNetworkIdentifier::new("001", "01").expect("synthetic PLMN is valid")
}

fn terminal() -> SwmTerminalInformation {
    SwmTerminalInformation {
        imei: Imei::new(IMEI).expect("synthetic IMEI is valid"),
        software_version: Some("01".into()),
    }
}

fn conditional<T>(source: SwmConditionalValueSource, value: T) -> SwmConditionalValue<T> {
    match source {
        SwmConditionalValueSource::LocallyConfigured => {
            SwmConditionalValue::LocallyConfigured(value)
        }
        SwmConditionalValueSource::UeProvided => SwmConditionalValue::UeProvided(value),
        SwmConditionalValueSource::AaaDerived => SwmConditionalValue::AaaDerived(value),
    }
}

fn assert_context_error(
    context: SwmDerAccessContext,
    expected_code: SwmDerAccessContextErrorCode,
    expected_field: SwmDerAccessContextField,
) {
    let request = sample_request();
    let unchanged = request.clone();
    let error = swm::build_swm_diameter_eap_request_with_access_context(
        &request,
        context,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect_err("invalid access context must fail closed")
    .context_error()
    .expect("failure occurs before encoding");
    assert_eq!(error.code(), expected_code);
    assert_eq!(error.field(), expected_field);
    assert_eq!(
        request, unchanged,
        "failure must not mutate the caller input"
    );
    let debug = format!("{error:?}");
    assert!(!debug.contains(APN));
    assert!(!debug.contains(IMEI));
}

#[test]
fn all_non_emergency_context_sources_round_trip_and_remain_redacted() {
    for address in [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 47)),
    ] {
        let context = SwmDerAccessContext {
            rat_type: SwmConditionalValue::UeProvided(SwmRatType::Wlan),
            service_selection: SwmConditionalValue::UeProvided(APN.into()),
            mip6_feature_vector: SwmConditionalValue::LocallyConfigured(
                SwmMip6FeatureVector::gtpv2_only(),
            ),
            qos_capability: SwmConditionalValue::LocallyConfigured(qos()),
            visited_network_identifier: SwmConditionalValue::LocallyConfigured(visited()),
            aaa_failure_indication: SwmConditionalValue::AaaDerived(
                SwmAaaFailureIndication::previously_assigned_server_unavailable(),
            ),
            supported_features: SwmConditionalValue::LocallyConfigured(vec![
                SwmRequestedSupportedFeatures::swm_discovery(),
            ]),
            ue_local_ip_address: SwmConditionalValue::UeProvided(address),
            oc_supported_features: SwmConditionalValue::LocallyConfigured(
                SwmOcSupportedFeatures::loss(),
            ),
            terminal_information: SwmConditionalValue::UeProvided(terminal()),
            emergency_services: SwmConditionalValue::Absent,
            high_priority_access_info: SwmConditionalValue::UeProvided(
                SwmHighPriorityAccessInfo::configured(),
            ),
        };
        let context_debug = format!("{context:?}");
        assert!(!context_debug.contains(APN));
        assert!(!context_debug.contains(IMEI));
        assert!(!context_debug.contains(&address.to_string()));

        let built = swm::build_swm_diameter_eap_request_with_access_context(
            &sample_request(),
            context,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("all correctly sourced ordinary DER fields build");
        let snapshot = built.source_snapshot();
        assert_eq!(
            snapshot.rat_type(),
            Some(SwmConditionalValueSource::UeProvided)
        );
        assert_eq!(
            snapshot.service_selection(),
            Some(SwmConditionalValueSource::UeProvided)
        );
        assert_eq!(
            snapshot.mip6_feature_vector(),
            Some(SwmConditionalValueSource::LocallyConfigured)
        );
        assert_eq!(
            snapshot.qos_capability(),
            Some(SwmConditionalValueSource::LocallyConfigured)
        );
        assert_eq!(
            snapshot.visited_network_identifier(),
            Some(SwmConditionalValueSource::LocallyConfigured)
        );
        assert_eq!(
            snapshot.aaa_failure_indication(),
            Some(SwmConditionalValueSource::AaaDerived)
        );
        assert_eq!(
            snapshot.supported_features(),
            Some(SwmConditionalValueSource::LocallyConfigured)
        );
        assert_eq!(
            snapshot.ue_local_ip_address(),
            Some(SwmConditionalValueSource::UeProvided)
        );
        assert_eq!(
            snapshot.oc_supported_features(),
            Some(SwmConditionalValueSource::LocallyConfigured)
        );
        assert_eq!(
            snapshot.terminal_information(),
            Some(SwmConditionalValueSource::UeProvided)
        );
        assert_eq!(snapshot.emergency_services(), None);
        assert_eq!(
            snapshot.high_priority_access_info(),
            Some(SwmConditionalValueSource::UeProvided)
        );

        let parsed = parse(&encode(built.message()));
        assert_eq!(&parsed, built.request());
        assert_eq!(parsed.ue_local_ip_address, Some(address));
        let debug = format!("{built:?} {parsed:?}");
        assert!(!debug.contains(APN));
        assert!(!debug.contains(IMEI));
        assert!(!debug.contains(&address.to_string()));
        assert!(!debug.contains("mnc001"));
    }
}

#[test]
fn emergency_and_virtual_rat_use_their_exact_allowed_sources() {
    let built = swm::build_swm_diameter_eap_request_with_access_context(
        &sample_request(),
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::LocallyConfigured(SwmRatType::Virtual),
            emergency_services: SwmConditionalValue::UeProvided(
                SwmEmergencyServices::emergency_indication(),
            ),
            ..SwmDerAccessContext::default()
        },
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("emergency context builds");
    assert_eq!(
        built.source_snapshot().rat_type(),
        Some(SwmConditionalValueSource::LocallyConfigured)
    );
    assert_eq!(
        built.source_snapshot().emergency_services(),
        Some(SwmConditionalValueSource::UeProvided)
    );
    let parsed = parse(&encode(built.message()));
    assert_eq!(parsed.rat_type, Some(SwmRatType::Virtual));
    assert_eq!(
        parsed.emergency_services,
        Some(SwmEmergencyServices::emergency_indication())
    );
    assert!(parsed.service_selection.is_none());

    let future_rat = swm::build_swm_diameter_eap_request_with_access_context(
        &sample_request(),
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::UeProvided(SwmRatType::Other(99)),
            ..SwmDerAccessContext::default()
        },
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("observed future RAT values retain UE provenance");
    assert_eq!(
        parse(&encode(future_rat.message())).rat_type,
        Some(SwmRatType::Other(99))
    );
}

#[test]
fn rat_type_aliases_cannot_bypass_checked_provenance() {
    for alias in [SwmRatType::Other(0), SwmRatType::Other(1)] {
        for source in [
            SwmConditionalValueSource::LocallyConfigured,
            SwmConditionalValueSource::UeProvided,
            SwmConditionalValueSource::AaaDerived,
        ] {
            assert_context_error(
                SwmDerAccessContext {
                    rat_type: conditional(source, alias),
                    ..SwmDerAccessContext::default()
                },
                SwmDerAccessContextErrorCode::NonCanonicalValue,
                SwmDerAccessContextField::RatType,
            );
        }
    }
}

#[test]
fn every_wrong_source_is_rejected_for_every_context_field() {
    const SOURCES: [SwmConditionalValueSource; 3] = [
        SwmConditionalValueSource::LocallyConfigured,
        SwmConditionalValueSource::UeProvided,
        SwmConditionalValueSource::AaaDerived,
    ];

    macro_rules! reject_wrong_sources {
        ($member:ident, $value:expr, $allowed:expr, $field:expr) => {{
            let allowed = $allowed;
            for source in SOURCES.into_iter().filter(|source| *source != allowed) {
                let mut context = SwmDerAccessContext::default();
                context.$member = conditional(source, $value.clone());
                assert_context_error(
                    context,
                    SwmDerAccessContextErrorCode::InvalidProvenance,
                    $field,
                );
            }
        }};
    }

    reject_wrong_sources!(
        service_selection,
        Redacted::new(APN.to_owned()),
        SwmConditionalValueSource::UeProvided,
        SwmDerAccessContextField::ServiceSelection
    );
    reject_wrong_sources!(
        mip6_feature_vector,
        SwmMip6FeatureVector::gtpv2_only(),
        SwmConditionalValueSource::LocallyConfigured,
        SwmDerAccessContextField::Mip6FeatureVector
    );
    reject_wrong_sources!(
        qos_capability,
        qos(),
        SwmConditionalValueSource::LocallyConfigured,
        SwmDerAccessContextField::QosCapability
    );
    reject_wrong_sources!(
        visited_network_identifier,
        visited(),
        SwmConditionalValueSource::LocallyConfigured,
        SwmDerAccessContextField::VisitedNetworkIdentifier
    );
    reject_wrong_sources!(
        aaa_failure_indication,
        SwmAaaFailureIndication::previously_assigned_server_unavailable(),
        SwmConditionalValueSource::AaaDerived,
        SwmDerAccessContextField::AaaFailureIndication
    );
    reject_wrong_sources!(
        supported_features,
        vec![SwmRequestedSupportedFeatures::swm_discovery()],
        SwmConditionalValueSource::LocallyConfigured,
        SwmDerAccessContextField::SupportedFeatures
    );
    reject_wrong_sources!(
        ue_local_ip_address,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47)),
        SwmConditionalValueSource::UeProvided,
        SwmDerAccessContextField::UeLocalIpAddress
    );
    reject_wrong_sources!(
        oc_supported_features,
        SwmOcSupportedFeatures::loss(),
        SwmConditionalValueSource::LocallyConfigured,
        SwmDerAccessContextField::OcSupportedFeatures
    );
    reject_wrong_sources!(
        terminal_information,
        terminal(),
        SwmConditionalValueSource::UeProvided,
        SwmDerAccessContextField::TerminalInformation
    );
    reject_wrong_sources!(
        emergency_services,
        SwmEmergencyServices::emergency_indication(),
        SwmConditionalValueSource::UeProvided,
        SwmDerAccessContextField::EmergencyServices
    );
    reject_wrong_sources!(
        high_priority_access_info,
        SwmHighPriorityAccessInfo::configured(),
        SwmConditionalValueSource::UeProvided,
        SwmDerAccessContextField::HighPriorityAccessInfo
    );

    for context in [
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::LocallyConfigured(SwmRatType::Wlan),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::LocallyConfigured(SwmRatType::Other(99)),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::UeProvided(SwmRatType::Virtual),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::AaaDerived(SwmRatType::Wlan),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::AaaDerived(SwmRatType::Virtual),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContext {
            rat_type: SwmConditionalValue::AaaDerived(SwmRatType::Other(99)),
            ..SwmDerAccessContext::default()
        },
    ] {
        assert_context_error(
            context,
            SwmDerAccessContextErrorCode::InvalidProvenance,
            SwmDerAccessContextField::RatType,
        );
    }
}

#[test]
fn every_prepopulated_context_field_is_rejected() {
    macro_rules! reject_prepopulated {
        ($member:ident, $value:expr, $field:expr) => {{
            let mut request = sample_request();
            request.$member = $value;
            let unchanged = request.clone();
            let error = swm::build_swm_diameter_eap_request_with_access_context(
                &request,
                SwmDerAccessContext::default(),
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect_err("prepopulated conditional field must fail closed")
            .context_error()
            .expect("prepopulation fails before encoding");
            assert_eq!(
                error.code(),
                SwmDerAccessContextErrorCode::PrepopulatedField
            );
            assert_eq!(error.field(), $field);
            assert_eq!(request, unchanged);
        }};
    }

    reject_prepopulated!(
        rat_type,
        Some(SwmRatType::Wlan),
        SwmDerAccessContextField::RatType
    );
    reject_prepopulated!(
        service_selection,
        Some(APN.into()),
        SwmDerAccessContextField::ServiceSelection
    );
    reject_prepopulated!(
        mip6_feature_vector,
        Some(SwmMip6FeatureVector::gtpv2_only()),
        SwmDerAccessContextField::Mip6FeatureVector
    );
    reject_prepopulated!(
        qos_capability,
        Some(qos()),
        SwmDerAccessContextField::QosCapability
    );
    reject_prepopulated!(
        visited_network_identifier,
        Some(visited()),
        SwmDerAccessContextField::VisitedNetworkIdentifier
    );
    reject_prepopulated!(
        aaa_failure_indication,
        Some(SwmAaaFailureIndication::previously_assigned_server_unavailable()),
        SwmDerAccessContextField::AaaFailureIndication
    );
    reject_prepopulated!(
        supported_features,
        vec![SwmRequestedSupportedFeatures::swm_discovery()],
        SwmDerAccessContextField::SupportedFeatures
    );
    reject_prepopulated!(
        ue_local_ip_address,
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 47))),
        SwmDerAccessContextField::UeLocalIpAddress
    );
    reject_prepopulated!(
        oc_supported_features,
        Some(SwmOcSupportedFeatures::loss()),
        SwmDerAccessContextField::OcSupportedFeatures
    );
    reject_prepopulated!(
        terminal_information,
        Some(terminal()),
        SwmDerAccessContextField::TerminalInformation
    );
    reject_prepopulated!(
        emergency_services,
        Some(SwmEmergencyServices::emergency_indication()),
        SwmDerAccessContextField::EmergencyServices
    );
    reject_prepopulated!(
        high_priority_access_info,
        Some(SwmHighPriorityAccessInfo::configured()),
        SwmDerAccessContextField::HighPriorityAccessInfo
    );
}

#[test]
fn invalid_presence_semantics_fail_closed_with_stable_codes() {
    assert_context_error(
        SwmDerAccessContext {
            supported_features: SwmConditionalValue::LocallyConfigured(Vec::new()),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContextErrorCode::EmptySupportedFeatures,
        SwmDerAccessContextField::SupportedFeatures,
    );
    assert_context_error(
        SwmDerAccessContext {
            emergency_services: SwmConditionalValue::UeProvided(SwmEmergencyServices::new(false)),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContextErrorCode::InactiveIndication,
        SwmDerAccessContextField::EmergencyServices,
    );
    assert_context_error(
        SwmDerAccessContext {
            high_priority_access_info: SwmConditionalValue::UeProvided(
                SwmHighPriorityAccessInfo::from_value(0),
            ),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContextErrorCode::InactiveIndication,
        SwmDerAccessContextField::HighPriorityAccessInfo,
    );
    assert_context_error(
        SwmDerAccessContext {
            service_selection: SwmConditionalValue::UeProvided(APN.into()),
            emergency_services: SwmConditionalValue::UeProvided(
                SwmEmergencyServices::emergency_indication(),
            ),
            ..SwmDerAccessContext::default()
        },
        SwmDerAccessContextErrorCode::ContradictoryValues,
        SwmDerAccessContextField::ServiceSelection,
    );
}

#[test]
fn all_absent_context_is_byte_identical_and_has_an_empty_snapshot() {
    let request = sample_request();
    let ordinary = swm::build_swm_diameter_eap_request(
        &request,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("ordinary DER builds");
    let checked = swm::build_swm_diameter_eap_request_with_access_context(
        &request,
        SwmDerAccessContext::default(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("all-absent checked DER builds");
    assert_eq!(encode(&ordinary), encode(checked.message()));
    let snapshot = checked.source_snapshot();
    assert_eq!(snapshot.rat_type(), None);
    assert_eq!(snapshot.service_selection(), None);
    assert_eq!(snapshot.mip6_feature_vector(), None);
    assert_eq!(snapshot.qos_capability(), None);
    assert_eq!(snapshot.visited_network_identifier(), None);
    assert_eq!(snapshot.aaa_failure_indication(), None);
    assert_eq!(snapshot.supported_features(), None);
    assert_eq!(snapshot.ue_local_ip_address(), None);
    assert_eq!(snapshot.oc_supported_features(), None);
    assert_eq!(snapshot.terminal_information(), None);
    assert_eq!(snapshot.emergency_services(), None);
    assert_eq!(snapshot.high_priority_access_info(), None);
}
