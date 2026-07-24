use opc_proto_ikev2::{
    build_create_child_sa_rekey_response_payloads, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_notify_payload, Header, HeaderFlags, Ikev2ChildSaRekeyCurrentTrafficSelectors,
    Ikev2ChildSaRekeyPeerErrorInvalidReason, Ikev2ChildSaRekeyPeerErrorKind,
    Ikev2ChildSaRekeyResponseBoundary, Ikev2ChildSaRekeyResponseError,
    Ikev2ChildSaRekeyResponsePayloadRole, Ikev2CreateChildSaRekeyRequestBuild,
    Ikev2CreateChildSaRekeyResponseBuild, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2KeyExchangePayloadBuild,
    Ikev2NoncePayloadBuild, Ikev2NotifyPayloadBuild, Ikev2PrfAlgorithm, Ikev2SaPayloadBuild,
    Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild,
    Ikev2TrafficSelectorPayloadBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_INFORMATIONAL, IKEV2_NOTIFY_CHILD_SA_NOT_FOUND, IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
    IKEV2_NOTIFY_INVALID_MESSAGE_ID, IKEV2_NOTIFY_INVALID_SYNTAX, IKEV2_NOTIFY_NO_ADDITIONAL_SAS,
    IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED,
    IKEV2_NOTIFY_TEMPORARY_FAILURE, IKEV2_NOTIFY_TS_UNACCEPTABLE, IKEV2_SECURITY_PROTOCOL_ID_ESP,
    IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_protocol::{DecodeContext, UnknownIePolicy};

const OLD_INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const OLD_RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const MESSAGE_ID: u32 = 17;
const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_DH: u8 = 4;
const TRANSFORM_TYPE_ESN: u8 = 5;
const ENCR_AES_GCM_16: u16 = 20;
const DH_MODP_2048: u16 = 14;
const ESN_NONE: u16 = 0;
const ESN: u16 = 1;
const KEY_LENGTH_ATTRIBUTE: u16 = 14;

fn request_header() -> Header {
    Header::new(
        OLD_INITIATOR_SPI,
        OLD_RESPONDER_SPI,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        HeaderFlags::from_bits(true, false, false),
        MESSAGE_ID,
    )
}

fn response_header() -> Header {
    Header::new(
        OLD_INITIATOR_SPI,
        OLD_RESPONDER_SPI,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        HeaderFlags::from_bits(false, true, false),
        MESSAGE_ID,
    )
}

fn aead_transform(key_bits: u16) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type: TRANSFORM_TYPE_ENCR,
        transform_id: ENCR_AES_GCM_16,
        attributes: vec![Ikev2TransformAttributeBuild {
            attribute_type: KEY_LENGTH_ATTRIBUTE,
            value: Ikev2TransformAttributeBuildValue::Tv(key_bits),
        }],
    }
}

fn transform_offer(pfs: bool) -> Vec<Ikev2SaTransformBuild> {
    let mut transforms = vec![
        aead_transform(128),
        Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_ESN,
            transform_id: ESN_NONE,
            attributes: Vec::new(),
        },
    ];
    if pfs {
        transforms.push(Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: DH_MODP_2048,
            attributes: Vec::new(),
        });
    }
    transforms
}

fn tsi_offer() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: vec![192, 0, 2, 10],
            end_address: vec![192, 0, 2, 20],
        }],
    }
}

fn tsr_offer() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: vec![198, 51, 100, 10],
            end_address: vec![198, 51, 100, 20],
        }],
    }
}

fn request_build(pfs: bool) -> Ikev2CreateChildSaRekeyRequestBuild {
    Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        rekeyed_spi: vec![0x21, 0x22, 0x23, 0x24],
        security_association: Ikev2SaPayloadBuild {
            proposals: vec![Ikev2SaProposalBuild {
                proposal_number: 1,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                spi: vec![0x31, 0x32, 0x33, 0x34],
                transforms: transform_offer(pfs),
            }],
        },
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x41; 32],
        },
        key_exchange: pfs.then(|| Ikev2KeyExchangePayloadBuild {
            dh_group: DH_MODP_2048,
            key_exchange_data: vec![0x22; Ikev2DhGroup::Modp2048.public_value_len()],
        }),
        traffic_selectors_initiator: tsi_offer(),
        traffic_selectors_responder: tsr_offer(),
    }
}

fn selected_tsi() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 17,
            start_port: 4_500,
            end_port: 4_500,
            start_address: vec![192, 0, 2, 12],
            end_address: vec![192, 0, 2, 12],
        }],
    }
}

fn selected_tsr() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 17,
            start_port: 4_500,
            end_port: 4_500,
            start_address: vec![198, 51, 100, 12],
            end_address: vec![198, 51, 100, 12],
        }],
    }
}

fn ipv4_tsi_selector(
    protocol: u8,
    start_port: u16,
    end_port: u16,
    start_address: u8,
    end_address: u8,
) -> Ikev2TrafficSelectorBuild {
    Ikev2TrafficSelectorBuild {
        ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
        ip_protocol_id: protocol,
        start_port,
        end_port,
        start_address: vec![192, 0, 2, start_address],
        end_address: vec![192, 0, 2, end_address],
    }
}

fn current_traffic_selectors() -> Ikev2ChildSaRekeyCurrentTrafficSelectors {
    Ikev2ChildSaRekeyCurrentTrafficSelectors::new(selected_tsi(), selected_tsr())
}

fn response_entries(
    request: &Ikev2CreateChildSaRekeyRequestBuild,
    responder_spi: Vec<u8>,
) -> Vec<Ikev2IkeAuthPayloadBuild> {
    response_entries_with_traffic_selectors(request, responder_spi, selected_tsi(), selected_tsr())
}

fn response_entries_with_traffic_selectors(
    request: &Ikev2CreateChildSaRekeyRequestBuild,
    responder_spi: Vec<u8>,
    traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
) -> Vec<Ikev2IkeAuthPayloadBuild> {
    build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
        security_association: Ikev2SaPayloadBuild {
            proposals: vec![Ikev2SaProposalBuild {
                proposal_number: 1,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                spi: responder_spi,
                transforms: request.security_association.proposals[0].transforms.clone(),
            }],
        },
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x51; 32],
        },
        key_exchange: request.key_exchange.as_ref().map(|key_exchange| {
            Ikev2KeyExchangePayloadBuild {
                dh_group: key_exchange.dh_group,
                key_exchange_data: vec![0x33; Ikev2DhGroup::Modp2048.public_value_len()],
            }
        }),
        traffic_selectors_initiator,
        traffic_selectors_responder,
    })
    .expect("synthetic response is encodable")
    .into_payloads()
}

fn chain(entries: &[Ikev2IkeAuthPayloadBuild]) -> (PayloadType, bytes::Bytes) {
    build_ike_auth_cleartext_payload_chain(entries).expect("synthetic response chain")
}

fn notify_entry(
    notify_message_type: u16,
    protocol_id: u8,
    spi: Vec<u8>,
    notification_data: Vec<u8>,
) -> Ikev2IkeAuthPayloadBuild {
    Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
            protocol_id,
            spi,
            notify_message_type,
            notification_data,
        })
        .expect("synthetic Notify body"),
    }
}

fn new_boundary(request: Ikev2CreateChildSaRekeyRequestBuild) -> Ikev2ChildSaRekeyResponseBoundary {
    Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request,
        current_traffic_selectors(),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("valid retained request")
}

#[test]
fn accepts_valid_no_pfs_response_in_payload_order_independent_form() {
    let request = request_build(false);
    let mut entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    entries.swap(0, 3);
    entries.swap(1, 2);
    let (first, bytes) = chain(&entries);
    let mut boundary = new_boundary(request);
    assert_eq!(boundary.initiator_nonce(), [0x41; 32]);
    let boundary_debug = format!("{boundary:?}");
    assert!(!boundary_debug.contains("49, 50, 51, 52"));
    assert!(!boundary_debug.contains("65, 65, 65"));

    let response = boundary
        .commit_response(&response_header(), first, &bytes)
        .expect("valid no-PFS response");

    assert_eq!(
        response.replacement_initiator_spi(),
        [0x31, 0x32, 0x33, 0x34]
    );
    assert_eq!(
        response.replacement_responder_spi(),
        [0x61, 0x62, 0x63, 0x64]
    );
    assert_eq!(
        response.profile().encryption(),
        Ikev2EncryptionAlgorithm::AesGcm16_128
    );
    assert_eq!(response.profile().integrity(), None);
    assert_eq!(response.pfs_group(), None);
    assert!(!response.extended_sequence_numbers());
    assert!(response.key_exchange().is_none());
    assert_eq!(response.nonce().nonce, [0x51; 32]);
    assert_eq!(response.traffic_selectors_initiator().selectors.len(), 1);
    assert_eq!(response.traffic_selectors_responder().selectors.len(), 1);
    assert!(boundary.terminal_committed());

    let debug = format!("{response:?}");
    assert!(!debug.contains("192.0.2"));
    assert!(!debug.contains("198.51.100"));
    assert!(!debug.contains("97, 98, 99, 100"));
    assert!(debug.contains("replacement_responder_spi_len"));
}

#[test]
fn accepts_valid_pfs_response_and_validates_public_value() {
    let mut request = request_build(true);
    request.security_association.proposals[0]
        .transforms
        .iter_mut()
        .find(|transform| transform.transform_type == TRANSFORM_TYPE_ESN)
        .expect("ESN offer")
        .transform_id = ESN;
    let entries = response_entries(&request, vec![0x71, 0x72, 0x73, 0x74]);
    let (first, bytes) = chain(&entries);
    let mut boundary = new_boundary(request);
    let mut fragmented_response_header = response_header();
    fragmented_response_header.next_payload = PayloadType::EncryptedFragment.as_u8();

    let response = boundary
        .commit_response(&fragmented_response_header, first, &bytes)
        .expect("valid reassembled SKF PFS response");

    assert_eq!(response.pfs_group(), Some(Ikev2DhGroup::Modp2048));
    assert!(response.extended_sequence_numbers());
    let key_exchange = response.key_exchange().expect("PFS response carries KEr");
    assert_eq!(key_exchange.dh_group, DH_MODP_2048);
    assert_eq!(
        key_exchange.key_exchange_data.len(),
        Ikev2DhGroup::Modp2048.public_value_len()
    );
}

#[test]
fn rejects_message_id_old_spi_response_flag_and_sender_mismatch_without_commit() {
    let request = request_build(false);
    let entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let (first, bytes) = chain(&entries);
    let mut boundary = new_boundary(request);

    let mut wrong_message_id = response_header();
    wrong_message_id.message_id += 1;
    assert_eq!(
        boundary
            .commit_response(&wrong_message_id, first, &bytes)
            .expect_err("wrong Message ID"),
        Ikev2ChildSaRekeyResponseError::MessageIdMismatch
    );
    assert!(!boundary.terminal_committed());

    let mut wrong_spi = response_header();
    wrong_spi.responder_spi ^= 1;
    assert_eq!(
        boundary
            .commit_response(&wrong_spi, first, &bytes)
            .expect_err("wrong old IKE SPI"),
        Ikev2ChildSaRekeyResponseError::IkeSpiMismatch
    );

    let mut request_flag = response_header();
    request_flag.flags = HeaderFlags::from_bits(false, false, false);
    assert_eq!(
        boundary
            .commit_response(&request_flag, first, &bytes)
            .expect_err("response flag is mandatory"),
        Ikev2ChildSaRekeyResponseError::ResponseFlagMissing
    );

    let mut wrong_sender = response_header();
    wrong_sender.flags = HeaderFlags::from_bits(true, true, false);
    assert_eq!(
        boundary
            .commit_response(&wrong_sender, first, &bytes)
            .expect_err("response sender must be the opposite IKE endpoint"),
        Ikev2ChildSaRekeyResponseError::InitiatorFlagMismatch
    );

    let mut wrong_outer_payload = response_header();
    wrong_outer_payload.next_payload = PayloadType::SecurityAssociation.as_u8();
    assert_eq!(
        boundary
            .commit_response(&wrong_outer_payload, first, &bytes)
            .expect_err("outer response must name SK"),
        Ikev2ChildSaRekeyResponseError::OuterPayloadNotEncrypted {
            actual: PayloadType::SecurityAssociation.as_u8(),
        }
    );
    assert!(!boundary.terminal_committed());
}

#[test]
fn mandatory_ignore_semantics_normalize_reject_and_unknown_critical_fails_closed() {
    let request = request_build(false);
    let mut entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    entries.insert(
        0,
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
                protocol_id: 7,
                spi: Vec::new(),
                notify_message_type: 60_000,
                notification_data: vec![0x91],
            })
            .expect("unknown status notify"),
        },
    );
    entries.insert(
        0,
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::VendorId,
            body: vec![0xaa, 0xbb],
        },
    );
    let (_, bytes) = chain(&entries);
    let first = PayloadType::Unknown(250);

    let mut preserve_boundary = new_boundary(request.clone());
    let preserved = preserve_boundary
        .commit_response(&response_header(), first, &bytes)
        .expect("default policy preserves ignorable extensions");
    assert_eq!(preserved.unknown_noncritical_payloads().len(), 1);
    assert_eq!(preserved.unrecognized_notifies().len(), 1);
    assert_eq!(
        preserved.unknown_noncritical_payloads()[0].payload_type,
        250
    );
    assert_eq!(
        preserved.unknown_noncritical_payloads()[0].body,
        [0xaa, 0xbb]
    );

    let mut drop_context = DecodeContext::conservative();
    drop_context.unknown_ie_policy = UnknownIePolicy::Drop;
    let mut drop_boundary = new_boundary(request.clone());
    let dropped = drop_boundary
        .commit_response_with_context(&response_header(), first, &bytes, drop_context)
        .expect("drop policy discards ignorable extensions");
    assert!(dropped.unknown_noncritical_payloads().is_empty());
    assert!(dropped.unrecognized_notifies().is_empty());

    let mut reject_context = DecodeContext::conservative();
    reject_context.unknown_ie_policy = UnknownIePolicy::Reject;
    let mut reject_boundary = new_boundary(request.clone());
    let normalized = reject_boundary
        .commit_response_with_context(&response_header(), first, &bytes, reject_context)
        .expect("Reject is normalized to Preserve for RFC-mandated ignore classes");
    assert_eq!(normalized.unknown_noncritical_payloads().len(), 1);
    assert_eq!(normalized.unrecognized_notifies().len(), 1);
    assert!(reject_boundary.terminal_committed());

    let (_, bytes) = chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::VendorId,
        body: vec![0xcc],
    }]);
    let mut critical_bytes = bytes.to_vec();
    critical_bytes[1] |= 0x80;
    let mut critical_boundary = new_boundary(request);
    assert_eq!(
        critical_boundary
            .commit_response(
                &response_header(),
                PayloadType::Unknown(250),
                &critical_bytes,
            )
            .expect_err("unknown critical payload fails closed"),
        Ikev2ChildSaRekeyResponseError::UnknownCriticalPayload
    );
    assert!(!critical_boundary.terminal_committed());
}

#[test]
fn rejects_missing_duplicate_and_malformed_required_payloads() {
    let request = request_build(false);
    let entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);

    let missing = entries
        .iter()
        .filter(|entry| entry.payload_type != PayloadType::Nonce)
        .cloned()
        .collect::<Vec<_>>();
    let (first, bytes) = chain(&missing);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("missing nonce"),
        Ikev2ChildSaRekeyResponseError::MissingPayload {
            role: Ikev2ChildSaRekeyResponsePayloadRole::Nonce,
        }
    );

    let mut duplicate = entries.clone();
    duplicate.push(
        entries
            .iter()
            .find(|entry| entry.payload_type == PayloadType::SecurityAssociation)
            .expect("SA entry")
            .clone(),
    );
    let (first, bytes) = chain(&duplicate);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("duplicate SA"),
        Ikev2ChildSaRekeyResponseError::DuplicatePayload {
            role: Ikev2ChildSaRekeyResponsePayloadRole::SecurityAssociation,
        }
    );

    let mut malformed = entries;
    malformed
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::Nonce)
        .expect("nonce entry")
        .body
        .truncate(15);
    let (first, bytes) = chain(&malformed);
    assert!(matches!(
        new_boundary(request)
            .commit_response(&response_header(), first, &bytes)
            .expect_err("short nonce"),
        Ikev2ChildSaRekeyResponseError::Nonce(_)
    ));
}

#[test]
fn enforces_prf_specific_initiator_and_responder_nonce_floors() {
    let mut short_ni_request = request_build(false);
    short_ni_request.nonce.nonce = vec![0x41; 16];
    assert_eq!(
        Ikev2ChildSaRekeyResponseBoundary::new(
            &request_header(),
            short_ni_request,
            current_traffic_selectors(),
            Ikev2PrfAlgorithm::HmacSha2_512,
        )
        .expect_err("SHA-512 requires a nonce of at least 32 octets"),
        Ikev2ChildSaRekeyResponseError::InitiatorNonceTooShortForPrf {
            actual: 16,
            minimum: 32,
        }
    );

    let request = request_build(false);
    let mut entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    entries
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::Nonce)
        .expect("nonce entry")
        .body
        .truncate(16);
    let (first, bytes) = chain(&entries);
    let mut boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request,
        current_traffic_selectors(),
        Ikev2PrfAlgorithm::HmacSha2_512,
    )
    .expect("32-octet Ni satisfies SHA-512");
    assert_eq!(
        boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("short Nr must not commit"),
        Ikev2ChildSaRekeyResponseError::ResponderNonceTooShortForPrf {
            actual: 16,
            minimum: 32,
        }
    );
    assert!(!boundary.terminal_committed());
}

#[test]
fn rejects_unoffered_or_invalid_selection_and_requires_explicit_esn() {
    let mut request = request_build(false);
    request.security_association.proposals[0]
        .transforms
        .insert(1, aead_transform(256));

    let response_build = Ikev2CreateChildSaRekeyResponseBuild {
        security_association: Ikev2SaPayloadBuild {
            proposals: vec![Ikev2SaProposalBuild {
                proposal_number: 1,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                spi: vec![0x61, 0x62, 0x63, 0x64],
                transforms: vec![
                    aead_transform(192),
                    Ikev2SaTransformBuild {
                        transform_type: TRANSFORM_TYPE_ESN,
                        transform_id: ESN_NONE,
                        attributes: Vec::new(),
                    },
                ],
            }],
        },
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x51; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: selected_tsi(),
        traffic_selectors_responder: selected_tsr(),
    };
    let unoffered_entries = build_create_child_sa_rekey_response_payloads(&response_build)
        .expect("unoffered selection remains structurally encodable")
        .into_payloads();
    let (first, bytes) = chain(&unoffered_entries);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("unoffered encryption key length"),
        Ikev2ChildSaRekeyResponseError::ProposalNotOffered
    );

    let response_without_esn =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: vec![aead_transform(128)],
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: selected_tsi(),
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("missing ESN remains syntactically encodable")
        .into_payloads();
    let (first, bytes) = chain(&response_without_esn);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("SN/ESN transform type is mandatory for ESP"),
        Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid
    );

    let mut missing_esn_offer = request.clone();
    missing_esn_offer.security_association.proposals[0]
        .transforms
        .retain(|transform| transform.transform_type != TRANSFORM_TYPE_ESN);
    assert_eq!(
        Ikev2ChildSaRekeyResponseBoundary::new(
            &request_header(),
            missing_esn_offer,
            current_traffic_selectors(),
            Ikev2PrfAlgorithm::HmacSha2_256,
        )
        .expect_err("request ESP offer must carry an explicit SN/ESN transform"),
        Ikev2ChildSaRekeyResponseError::RequestOfferInvalid
    );

    let mut duplicate_esn = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let duplicate_sa =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: vec![
                        aead_transform(128),
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_ESN,
                            transform_id: ESN_NONE,
                            attributes: Vec::new(),
                        },
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_ESN,
                            transform_id: ESN,
                            attributes: Vec::new(),
                        },
                    ],
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: selected_tsi(),
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("duplicate alternatives remain syntactically encodable");
    duplicate_esn
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::SecurityAssociation)
        .expect("SA entry")
        .body = duplicate_sa.security_association.body;
    let (first, bytes) = chain(&duplicate_esn);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("a response must select exactly one SN/ESN transform"),
        Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid
    );

    let invalid_esn =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: vec![
                        aead_transform(128),
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_ESN,
                            transform_id: 2,
                            attributes: Vec::new(),
                        },
                    ],
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: selected_tsi(),
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("invalid ESN remains syntactically encodable")
        .into_payloads();
    let (first, bytes) = chain(&invalid_esn);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("unknown SN/ESN transform ID"),
        Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid
    );

    let invalid =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: vec![Ikev2SaTransformBuild {
                        transform_type: TRANSFORM_TYPE_ESN,
                        transform_id: ESN_NONE,
                        attributes: Vec::new(),
                    }],
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: selected_tsi(),
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("missing encryption remains structurally encodable")
        .into_payloads();
    let (first, bytes) = chain(&invalid);
    assert_eq!(
        new_boundary(request)
            .commit_response(&response_header(), first, &bytes)
            .expect_err("response omitted mandatory encryption"),
        Ikev2ChildSaRekeyResponseError::SelectedProposalInvalid
    );
}

#[test]
fn rejects_zero_and_wrong_length_replacement_spi() {
    let request = request_build(false);
    for (spi, expected) in [
        (
            vec![0, 0, 0, 0],
            Ikev2ChildSaRekeyResponseError::ReplacementSpiZero,
        ),
        (
            vec![1, 2, 3],
            Ikev2ChildSaRekeyResponseError::ReplacementSpiLengthInvalid { actual: 3 },
        ),
    ] {
        let entries = response_entries(&request, spi);
        let (first, bytes) = chain(&entries);
        assert_eq!(
            new_boundary(request.clone())
                .commit_response(&response_header(), first, &bytes)
                .expect_err("invalid replacement SPI"),
            expected
        );
    }
}

#[test]
fn rejects_ke_group_and_public_value_mismatch() {
    let request = request_build(true);
    let entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);

    let mut wrong_group = entries.clone();
    let ke = wrong_group
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::KeyExchange)
        .expect("KE entry");
    ke.body[..2].copy_from_slice(&19_u16.to_be_bytes());
    let (first, bytes) = chain(&wrong_group);
    assert_eq!(
        new_boundary(request.clone())
            .commit_response(&response_header(), first, &bytes)
            .expect_err("wrong KEr group"),
        Ikev2ChildSaRekeyResponseError::KeyExchangeGroupMismatch
    );

    let mut invalid_value = entries;
    let ke = invalid_value
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::KeyExchange)
        .expect("KE entry");
    ke.body[4..].fill(0);
    let (first, bytes) = chain(&invalid_value);
    assert!(matches!(
        new_boundary(request)
            .commit_response(&response_header(), first, &bytes)
            .expect_err("invalid all-zero KEr"),
        Ikev2ChildSaRekeyResponseError::KeyExchangeValueInvalid(_)
    ));
}

#[test]
fn rejects_widened_traffic_selectors() {
    let request = request_build(false);
    let mut entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let widened =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: transform_offer(false),
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild {
                selectors: vec![Ikev2TrafficSelectorBuild {
                    ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                    ip_protocol_id: 0,
                    start_port: 0,
                    end_port: u16::MAX,
                    start_address: vec![192, 0, 2, 1],
                    end_address: vec![192, 0, 2, 30],
                }],
            },
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("widened TS is structurally encodable");
    entries
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::TrafficSelectorInitiator)
        .expect("TSi entry")
        .body = widened.traffic_selectors_initiator.body;
    let (first, bytes) = chain(&entries);

    assert_eq!(
        new_boundary(request)
            .commit_response(&response_header(), first, &bytes)
            .expect_err("widened TSi"),
        Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorsNotOffered
    );
}

#[test]
fn enforces_current_selector_floor_at_construction_and_response() {
    let mut narrow_request_tsi = request_build(false);
    narrow_request_tsi.traffic_selectors_initiator = selected_tsi();
    assert_eq!(
        Ikev2ChildSaRekeyResponseBoundary::new(
            &request_header(),
            narrow_request_tsi,
            Ikev2ChildSaRekeyCurrentTrafficSelectors::new(tsi_offer(), selected_tsr()),
            Ikev2PrfAlgorithm::HmacSha2_256,
        )
        .expect_err("request TSi must cover the current Child SA"),
        Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorOfferNarrowerThanCurrent
    );

    let mut narrow_request_tsr = request_build(false);
    narrow_request_tsr.traffic_selectors_responder = selected_tsr();
    assert_eq!(
        Ikev2ChildSaRekeyResponseBoundary::new(
            &request_header(),
            narrow_request_tsr,
            Ikev2ChildSaRekeyCurrentTrafficSelectors::new(selected_tsi(), tsr_offer()),
            Ikev2PrfAlgorithm::HmacSha2_256,
        )
        .expect_err("request TSr must cover the current Child SA"),
        Ikev2ChildSaRekeyResponseError::ResponderTrafficSelectorOfferNarrowerThanCurrent
    );

    let request = request_build(false);
    let entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let (first, bytes) = chain(&entries);
    let mut tsi_boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request.clone(),
        Ikev2ChildSaRekeyCurrentTrafficSelectors::new(tsi_offer(), selected_tsr()),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("request offer covers current selectors");
    assert_eq!(
        tsi_boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("response TSi cannot narrow the current Child SA"),
        Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorsNarrowerThanCurrent
    );
    assert!(!tsi_boundary.terminal_committed());

    let response_with_full_tsi =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                    spi: vec![0x61, 0x62, 0x63, 0x64],
                    transforms: transform_offer(false),
                }],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x51; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: tsi_offer(),
            traffic_selectors_responder: selected_tsr(),
        })
        .expect("synthetic response")
        .into_payloads();
    let (first, bytes) = chain(&response_with_full_tsi);
    let mut tsr_boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request,
        Ikev2ChildSaRekeyCurrentTrafficSelectors::new(tsi_offer(), tsr_offer()),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("request offer covers current selectors");
    assert_eq!(
        tsr_boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("response TSr cannot narrow the current Child SA"),
        Ikev2ChildSaRekeyResponseError::ResponderTrafficSelectorsNarrowerThanCurrent
    );
    assert!(!tsr_boundary.terminal_committed());
}

#[test]
fn selector_union_coverage_is_honored_at_construction_and_response() {
    let full_tsi = Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![ipv4_tsi_selector(6, 1_000, 2_000, 10, 20)],
    };
    let split_address_tsi = Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![
            ipv4_tsi_selector(6, 1_000, 2_000, 10, 15),
            ipv4_tsi_selector(6, 1_000, 2_000, 16, 20),
        ],
    };
    let mut split_request = request_build(false);
    split_request.traffic_selectors_initiator = split_address_tsi;
    let mut split_request_boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        split_request.clone(),
        Ikev2ChildSaRekeyCurrentTrafficSelectors::new(full_tsi.clone(), selected_tsr()),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("adjacent request entries collectively cover the current selector");
    let entries = response_entries_with_traffic_selectors(
        &split_request,
        vec![0x61, 0x62, 0x63, 0x64],
        full_tsi.clone(),
        selected_tsr(),
    );
    let (first, bytes) = chain(&entries);
    split_request_boundary
        .commit_response(&response_header(), first, &bytes)
        .expect("one response rectangle is covered by the split request union");

    let request = request_build(false);
    let split_port_tsi = Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![
            ipv4_tsi_selector(6, 1_000, 1_499, 10, 20),
            ipv4_tsi_selector(6, 1_500, 2_000, 10, 20),
        ],
    };
    let entries = response_entries_with_traffic_selectors(
        &request,
        vec![0x61, 0x62, 0x63, 0x64],
        split_port_tsi,
        selected_tsr(),
    );
    let (first, bytes) = chain(&entries);
    let mut split_response_boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request.clone(),
        Ikev2ChildSaRekeyCurrentTrafficSelectors::new(full_tsi.clone(), selected_tsr()),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("request covers current selector");
    split_response_boundary
        .commit_response(&response_header(), first, &bytes)
        .expect("adjacent response entries collectively cover the current selector");

    let port_gap_tsi = Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![
            ipv4_tsi_selector(6, 1_000, 1_499, 10, 20),
            ipv4_tsi_selector(6, 1_501, 2_000, 10, 20),
        ],
    };
    let entries = response_entries_with_traffic_selectors(
        &request,
        vec![0x61, 0x62, 0x63, 0x64],
        port_gap_tsi,
        selected_tsr(),
    );
    let (first, bytes) = chain(&entries);
    let mut gap_boundary = Ikev2ChildSaRekeyResponseBoundary::new(
        &request_header(),
        request,
        Ikev2ChildSaRekeyCurrentTrafficSelectors::new(full_tsi, selected_tsr()),
        Ikev2PrfAlgorithm::HmacSha2_256,
    )
    .expect("request covers current selector");
    assert_eq!(
        gap_boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("one-port response gap must fail closed"),
        Ikev2ChildSaRekeyResponseError::InitiatorTrafficSelectorsNarrowerThanCurrent
    );
    assert!(!gap_boundary.terminal_committed());
}

#[test]
fn malformed_protocol_wildcard_response_fails_without_commit() {
    let request = request_build(false);
    let mut entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let tsi = entries
        .iter_mut()
        .find(|entry| entry.payload_type == PayloadType::TrafficSelectorInitiator)
        .expect("TSi entry");
    assert!(tsi.body.len() > 11);
    tsi.body[5] = 0;
    let (first, bytes) = chain(&entries);
    let mut boundary = new_boundary(request);

    assert_eq!(
        boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("protocol zero with UDP/4500 ports is malformed"),
        Ikev2ChildSaRekeyResponseError::TrafficSelectors(
            Ikev2IkeAuthPayloadError::TrafficSelectorPortRangeInvalid
        )
    );
    assert!(!boundary.terminal_committed());
}

#[test]
fn lone_error_notify_is_typed_terminal_and_partial_error_is_rejected() {
    let request = request_build(false);
    let error_entry = notify_entry(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, 0, Vec::new(), Vec::new());
    let (first, bytes) = chain(std::slice::from_ref(&error_entry));
    let mut boundary = new_boundary(request.clone());

    let error = boundary
        .commit_response(&response_header(), first, &bytes)
        .expect_err("peer rejection");
    let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
        panic!("expected typed peer error");
    };
    assert_eq!(
        peer_error.notify_message_type(),
        IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN
    );
    assert_eq!(
        peer_error.kind(),
        Ikev2ChildSaRekeyPeerErrorKind::NoProposalChosen
    );
    assert_eq!(peer_error.protocol_id(), 0);
    assert!(peer_error.spi().is_empty());
    assert!(peer_error.notification_data().is_empty());
    assert_eq!(peer_error.suggested_dh_group(), None);
    assert!(boundary.terminal_committed());
    assert_eq!(
        boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("terminal error cannot commit twice"),
        Ikev2ChildSaRekeyResponseError::TerminalResponseAlreadyCommitted
    );

    let mut mixed = vec![error_entry];
    mixed.extend(response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]));
    let (first, bytes) = chain(&mixed);
    let mut mixed_boundary = new_boundary(request);
    assert_eq!(
        mixed_boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("error cannot ride with partial success"),
        Ikev2ChildSaRekeyResponseError::ErrorResponseMixedWithPayloads
    );
    assert!(!mixed_boundary.terminal_committed());
}

#[test]
fn accepts_only_context_valid_known_rekey_errors_and_retains_actionable_data() {
    for (notify_message_type, expected_kind) in [
        (
            IKEV2_NOTIFY_INVALID_SYNTAX,
            Ikev2ChildSaRekeyPeerErrorKind::InvalidSyntax,
        ),
        (
            IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
            Ikev2ChildSaRekeyPeerErrorKind::NoProposalChosen,
        ),
        (
            IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED,
            Ikev2ChildSaRekeyPeerErrorKind::SinglePairRequired,
        ),
        (
            IKEV2_NOTIFY_NO_ADDITIONAL_SAS,
            Ikev2ChildSaRekeyPeerErrorKind::NoAdditionalSas,
        ),
        (
            IKEV2_NOTIFY_TS_UNACCEPTABLE,
            Ikev2ChildSaRekeyPeerErrorKind::TrafficSelectorsUnacceptable,
        ),
        (
            IKEV2_NOTIFY_TEMPORARY_FAILURE,
            Ikev2ChildSaRekeyPeerErrorKind::TemporaryFailure,
        ),
    ] {
        let (first, bytes) = chain(&[notify_entry(
            notify_message_type,
            99,
            Vec::new(),
            Vec::new(),
        )]);
        let mut boundary = new_boundary(request_build(false));
        let error = boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("valid known peer error");
        let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
            panic!("expected typed peer error");
        };
        assert_eq!(peer_error.kind(), expected_kind);
        assert_eq!(peer_error.protocol_id(), 99);
        assert!(boundary.terminal_committed());
    }

    let (first, bytes) = chain(&[notify_entry(
        IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
        71,
        Vec::new(),
        19_u16.to_be_bytes().to_vec(),
    )]);
    let mut pfs_boundary = new_boundary(request_build(true));
    let error = pfs_boundary
        .commit_response(&response_header(), first, &bytes)
        .expect_err("valid INVALID_KE_PAYLOAD");
    let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
        panic!("expected typed INVALID_KE_PAYLOAD");
    };
    assert_eq!(
        peer_error.kind(),
        Ikev2ChildSaRekeyPeerErrorKind::InvalidKePayload
    );
    assert_eq!(peer_error.suggested_dh_group(), Some(19));
    assert_eq!(peer_error.notification_data(), 19_u16.to_be_bytes());
    assert!(pfs_boundary.terminal_committed());

    let (first, bytes) = chain(&[notify_entry(
        IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        vec![0x21, 0x22, 0x23, 0x24],
        Vec::new(),
    )]);
    let mut missing_boundary = new_boundary(request_build(false));
    let error = missing_boundary
        .commit_response(&response_header(), first, &bytes)
        .expect_err("correlated CHILD_SA_NOT_FOUND");
    let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
        panic!("expected typed CHILD_SA_NOT_FOUND");
    };
    assert_eq!(
        peer_error.kind(),
        Ikev2ChildSaRekeyPeerErrorKind::ChildSaNotFound
    );
    assert_eq!(peer_error.spi(), [0x21, 0x22, 0x23, 0x24]);
    assert!(missing_boundary.terminal_committed());
}

#[test]
fn rejects_prohibited_or_malformed_known_errors_without_committing() {
    for (entry, expected_reason) in [
        (
            notify_entry(
                IKEV2_NOTIFY_INVALID_MESSAGE_ID,
                0,
                Vec::new(),
                MESSAGE_ID.to_be_bytes().to_vec(),
            ),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::TypeNotAllowed,
        ),
        (
            notify_entry(
                IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
                0,
                vec![1, 2, 3, 4],
                Vec::new(),
            ),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::SpiShape,
        ),
        (
            notify_entry(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, 0, Vec::new(), vec![1]),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::NotificationDataShape,
        ),
        (
            notify_entry(
                IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
                2,
                vec![0x21, 0x22, 0x23, 0x24],
                Vec::new(),
            ),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::ProtocolId,
        ),
        (
            notify_entry(
                IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
                IKEV2_SECURITY_PROTOCOL_ID_ESP,
                vec![0x21, 0x22, 0x23],
                Vec::new(),
            ),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::SpiShape,
        ),
        (
            notify_entry(
                IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
                IKEV2_SECURITY_PROTOCOL_ID_ESP,
                vec![0x21, 0x22, 0x23, 0x25],
                Vec::new(),
            ),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::SpiMismatch,
        ),
    ] {
        let notify_message_type = u16::from_be_bytes([entry.body[2], entry.body[3]]);
        let (first, bytes) = chain(&[entry]);
        let mut boundary = new_boundary(request_build(false));
        assert_eq!(
            boundary
                .commit_response(&response_header(), first, &bytes)
                .expect_err("invalid known error must not commit"),
            Ikev2ChildSaRekeyResponseError::InvalidPeerErrorNotify {
                notify_message_type,
                reason: expected_reason,
            }
        );
        assert!(!boundary.terminal_committed());
    }

    for (request, data, expected_reason) in [
        (
            request_build(false),
            19_u16.to_be_bytes().to_vec(),
            Ikev2ChildSaRekeyPeerErrorInvalidReason::RequestContext,
        ),
        (
            request_build(true),
            vec![0, 19, 0],
            Ikev2ChildSaRekeyPeerErrorInvalidReason::NotificationDataShape,
        ),
        (
            request_build(true),
            vec![0, 0],
            Ikev2ChildSaRekeyPeerErrorInvalidReason::NotificationDataValue,
        ),
    ] {
        let (first, bytes) = chain(&[notify_entry(
            IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
            0,
            Vec::new(),
            data,
        )]);
        let mut boundary = new_boundary(request);
        assert_eq!(
            boundary
                .commit_response(&response_header(), first, &bytes)
                .expect_err("invalid INVALID_KE_PAYLOAD must not commit"),
            Ikev2ChildSaRekeyResponseError::InvalidPeerErrorNotify {
                notify_message_type: IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
                reason: expected_reason,
            }
        );
        assert!(!boundary.terminal_committed());
    }
}

#[test]
fn unknown_error_is_terminal_retains_bounded_evidence_and_redacts_debug() {
    const UNKNOWN_ERROR: u16 = 12_345;
    let (first, bytes) = chain(&[notify_entry(
        UNKNOWN_ERROR,
        77,
        vec![0xaa, 0xbb, 0xcc],
        vec![0xde, 0xad, 0xbe, 0xef],
    )]);
    let mut boundary = new_boundary(request_build(false));
    let error = boundary
        .commit_response(&response_header(), first, &bytes)
        .expect_err("unknown error range fails the request terminally");
    let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
        panic!("expected typed unknown peer error");
    };
    assert_eq!(peer_error.kind(), Ikev2ChildSaRekeyPeerErrorKind::Unknown);
    assert_eq!(peer_error.notify_message_type(), UNKNOWN_ERROR);
    assert_eq!(peer_error.spi(), [0xaa, 0xbb, 0xcc]);
    assert_eq!(peer_error.notification_data(), [0xde, 0xad, 0xbe, 0xef]);
    let debug = format!("{peer_error:?}");
    assert!(debug.contains("spi_len"));
    assert!(debug.contains("notification_data_len"));
    assert!(!debug.contains("170, 187, 204"));
    assert!(!debug.contains("222, 173, 190, 239"));
    assert!(boundary.terminal_committed());
}

#[test]
fn ignorable_extensions_do_not_change_error_terminal_semantics() {
    let entries = vec![
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::VendorId,
            body: vec![0xa1, 0xa2],
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::VendorId,
            body: vec![0xb1, 0xb2],
        },
        notify_entry(60_000, 9, Vec::new(), vec![0xc1]),
        notify_entry(IKEV2_NOTIFY_TEMPORARY_FAILURE, 8, Vec::new(), Vec::new()),
    ];
    let (_, bytes) = chain(&entries);
    let first = PayloadType::Unknown(250);

    for policy in [
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Drop,
        UnknownIePolicy::Reject,
    ] {
        let mut context = DecodeContext::conservative();
        context.unknown_ie_policy = policy;
        let mut boundary = new_boundary(request_build(false));
        let error = boundary
            .commit_response_with_context(&response_header(), first, &bytes, context)
            .expect_err("valid error remains terminal beside ignorable extensions");
        let Ikev2ChildSaRekeyResponseError::PeerErrorNotify(peer_error) = error else {
            panic!("expected typed peer error");
        };
        assert_eq!(
            peer_error.kind(),
            Ikev2ChildSaRekeyPeerErrorKind::TemporaryFailure
        );
        assert!(boundary.terminal_committed());
    }
}

#[test]
fn valid_success_cannot_commit_twice_and_wrong_exchange_does_not_poison_state() {
    let request = request_build(false);
    let entries = response_entries(&request, vec![0x61, 0x62, 0x63, 0x64]);
    let (first, bytes) = chain(&entries);
    let mut boundary = new_boundary(request);

    let mut wrong_exchange = response_header();
    wrong_exchange.exchange_type = EXCHANGE_TYPE_INFORMATIONAL;
    assert_eq!(
        boundary
            .commit_response(&wrong_exchange, first, &bytes)
            .expect_err("wrong exchange"),
        Ikev2ChildSaRekeyResponseError::WrongExchangeType {
            actual: EXCHANGE_TYPE_INFORMATIONAL,
        }
    );
    assert!(!boundary.terminal_committed());

    boundary
        .commit_response(&response_header(), first, &bytes)
        .expect("first exact response commits");
    assert_eq!(
        boundary
            .commit_response(&response_header(), first, &bytes)
            .expect_err("replay cannot commit twice"),
        Ikev2ChildSaRekeyResponseError::TerminalResponseAlreadyCommitted
    );
}
