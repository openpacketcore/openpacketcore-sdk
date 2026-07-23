use opc_proto_eap::{
    EapAkaCombinationError, EapAkaError, EapAkaIdentityRequest, EapAkaMethod,
    EapAkaNotificationPhase, EapAkaPacket, EapAkaPacketKind, EapAkaSubtype, EapCode,
    EAP_AKA_MAX_ATTRIBUTES, EAP_AKA_MAX_KDF_ATTRIBUTES,
};

const REQUEST: u8 = 1;
const RESPONSE: u8 = 2;
const AKA: u8 = 23;
const AKA_PRIME: u8 = 50;

fn packet(code: u8, method: u8, subtype: u8, attributes: &[Vec<u8>]) -> Vec<u8> {
    let len = 8 + attributes.iter().map(Vec::len).sum::<usize>();
    let mut output = Vec::with_capacity(len);
    output.extend_from_slice(&[code, 9]);
    output.extend_from_slice(&(len as u16).to_be_bytes());
    output.extend_from_slice(&[method, subtype, 0, 0]);
    for attribute in attributes {
        output.extend_from_slice(attribute);
    }
    output
}

fn fixed(attribute_type: u8, length_units: u8) -> Vec<u8> {
    let mut attribute = vec![0; usize::from(length_units) * 4];
    attribute[0] = attribute_type;
    attribute[1] = length_units;
    for value in &mut attribute[4..] {
        *value = 0xa5;
    }
    attribute
}

fn marker(attribute_type: u8, value: u16) -> Vec<u8> {
    vec![
        attribute_type,
        1,
        value.to_be_bytes()[0],
        value.to_be_bytes()[1],
    ]
}

fn actual_text(attribute_type: u8, value: &[u8]) -> Vec<u8> {
    let padded = (value.len() + 3) & !3;
    let mut attribute = vec![0; 4 + padded];
    attribute[0] = attribute_type;
    attribute[1] = ((4 + padded) / 4) as u8;
    attribute[2..4].copy_from_slice(&(value.len() as u16).to_be_bytes());
    attribute[4..4 + value.len()].copy_from_slice(value);
    attribute
}

fn res(bit_len: u16) -> Vec<u8> {
    let value_len = usize::from(bit_len).div_ceil(8);
    let padded = (value_len + 3) & !3;
    let mut attribute = vec![0; 4 + padded];
    attribute[0] = 3;
    attribute[1] = ((4 + padded) / 4) as u8;
    attribute[2..4].copy_from_slice(&bit_len.to_be_bytes());
    attribute[4..4 + value_len].fill(0x80);
    attribute
}

fn full_aka_challenge_request() -> Vec<u8> {
    packet(REQUEST, AKA, 1, &[fixed(1, 5), fixed(2, 5), fixed(11, 5)])
}

fn full_aka_prime_challenge_request(kdfs: &[u16]) -> Vec<u8> {
    let mut attributes = vec![fixed(1, 5), fixed(2, 5)];
    attributes.extend(kdfs.iter().copied().map(|value| marker(24, value)));
    attributes.push(actual_text(23, b"WLAN"));
    attributes.push(fixed(11, 5));
    packet(REQUEST, AKA_PRIME, 1, &attributes)
}

fn assert_error(packet: &[u8], expected: EapAkaError) {
    assert_eq!(
        EapAkaPacket::parse(packet).expect_err("packet must fail"),
        expected
    );
}

#[test]
fn projects_full_aka_challenge_request_without_auth_claim() {
    let packet = full_aka_challenge_request();
    let parsed = EapAkaPacket::parse(&packet).expect("synthetic packet is valid");
    assert_eq!(parsed.code(), EapCode::Request);
    assert_eq!(parsed.identifier(), 9);
    assert_eq!(parsed.method(), EapAkaMethod::Aka);
    assert_eq!(parsed.subtype(), EapAkaSubtype::Challenge);
    assert_eq!(parsed.attribute_count(), 3);
    let EapAkaPacketKind::ChallengeRequest(evidence) = parsed.kind() else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.kdf_count(), 0);
    assert_eq!(evidence.preferred_kdf(), None);
    assert!(!evidence.has_kdf_input());
}

#[test]
fn projects_aka_prime_challenge_and_kdf_reoffer_shape() {
    let packet = full_aka_prime_challenge_request(&[1, 2, 1]);
    let parsed = EapAkaPacket::parse(&packet).expect("synthetic packet is valid");
    let EapAkaPacketKind::ChallengeRequest(evidence) = parsed.kind() else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.kdf_count(), 3);
    assert_eq!(evidence.preferred_kdf(), Some(1));
    assert_eq!(evidence.kdfs().as_slice(), &[1, 2, 1]);
    assert!(evidence.has_kdf_reoffer_shape());
    assert!(evidence.has_kdf_input());
}

#[test]
fn enforces_bounded_kdf_evidence() {
    let exact_bound = (1..=EAP_AKA_MAX_KDF_ATTRIBUTES as u16).collect::<Vec<_>>();
    let packet = full_aka_prime_challenge_request(&exact_bound);
    let parsed = EapAkaPacket::parse(&packet).expect("the exact KDF evidence bound is accepted");
    let EapAkaPacketKind::ChallengeRequest(evidence) = parsed.kind() else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.kdfs().as_slice(), exact_bound);

    let beyond_bound = (1..=(EAP_AKA_MAX_KDF_ATTRIBUTES as u16 + 1)).collect::<Vec<_>>();
    assert_error(
        &full_aka_prime_challenge_request(&beyond_bound),
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::TooManyKdfAttributes,
        },
    );
}

#[test]
fn challenge_attributes_are_order_independent_and_bidding_reserved_bits_are_ignored() {
    let reordered = packet(
        REQUEST,
        AKA,
        1,
        &[fixed(11, 5), marker(136, 0x8123), fixed(2, 5), fixed(1, 5)],
    );
    let EapAkaPacketKind::ChallengeRequest(evidence) = EapAkaPacket::parse(&reordered)
        .expect("valid attributes are order independent")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.bidding_supports_aka_prime(), Some(true));

    let prime_reordered = packet(
        REQUEST,
        AKA_PRIME,
        1,
        &[
            fixed(11, 5),
            actual_text(23, b"WLAN"),
            fixed(2, 5),
            marker(24, 1),
            marker(24, 2),
            fixed(1, 5),
        ],
    );
    let EapAkaPacketKind::ChallengeRequest(evidence) = EapAkaPacket::parse(&prime_reordered)
        .expect("AKA-prime attributes are order independent")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.kdfs().as_slice(), &[1, 2]);
    assert_eq!(evidence.preferred_kdf(), Some(1));
}

#[test]
fn distinguishes_kdf_negotiation_from_full_challenge_response() {
    let negotiation = packet(RESPONSE, AKA_PRIME, 1, &[marker(24, 2)]);
    let parsed = EapAkaPacket::parse(&negotiation).expect("negotiation is valid");
    let EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(evidence) = parsed.kind() else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.claimed_kdf(), 2);

    let full = packet(RESPONSE, AKA_PRIME, 1, &[res(64), fixed(11, 5)]);
    assert!(matches!(
        EapAkaPacket::parse(&full)
            .expect("full response is valid")
            .kind(),
        EapAkaPacketKind::FullChallengeResponse(_)
    ));
}

#[test]
fn projects_coherent_aka_prime_kdf_negotiation_sequence() {
    let initial = full_aka_prime_challenge_request(&[1, 2]);
    let EapAkaPacketKind::ChallengeRequest(initial) = EapAkaPacket::parse(&initial)
        .expect("initial offer is valid")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(initial.kdfs().as_slice(), &[1, 2]);
    assert!(!initial.has_kdf_reoffer_shape());

    let negotiation = packet(RESPONSE, AKA_PRIME, 1, &[marker(24, 2)]);
    let EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(negotiation) =
        EapAkaPacket::parse(&negotiation)
            .expect("alternative selection is valid")
            .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(negotiation.claimed_kdf(), 2);

    let reoffer = full_aka_prime_challenge_request(&[2, 1, 2]);
    let EapAkaPacketKind::ChallengeRequest(reoffer) = EapAkaPacket::parse(&reoffer)
        .expect("prepended selected alternative is valid")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(reoffer.kdfs().as_slice(), &[2, 1, 2]);
    assert!(reoffer.has_kdf_reoffer_shape());

    let full = packet(RESPONSE, AKA_PRIME, 1, &[res(64), fixed(11, 5)]);
    assert!(matches!(
        EapAkaPacket::parse(&full)
            .expect("full response after negotiation is valid")
            .kind(),
        EapAkaPacketKind::FullChallengeResponse(_)
    ));
}

#[test]
fn kdf_negotiation_ignores_unknown_skippable_attributes() {
    let negotiation = packet(RESPONSE, AKA_PRIME, 1, &[marker(24, 2), fixed(200, 1)]);
    let parsed = EapAkaPacket::parse(&negotiation).expect("unknown skippable is ignored");
    assert_eq!(parsed.unknown_skippable_count(), 1);
    assert!(matches!(
        parsed.kind(),
        EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(_)
    ));
}

#[test]
fn projects_sync_failure_for_both_methods() {
    let aka = packet(RESPONSE, AKA, 4, &[fixed(4, 4)]);
    assert!(matches!(
        EapAkaPacket::parse(&aka)
            .expect("AKA sync failure is valid")
            .kind(),
        EapAkaPacketKind::SynchronizationFailure {
            kdfs,
            kdf_reoffer_shape: false
        } if kdfs.is_empty()
    ));

    let prime = packet(RESPONSE, AKA_PRIME, 4, &[fixed(4, 4), marker(24, 1)]);
    assert!(matches!(
        EapAkaPacket::parse(&prime)
            .expect("AKA-prime sync failure is valid")
            .kind(),
        EapAkaPacketKind::SynchronizationFailure {
            kdfs,
            kdf_reoffer_shape: false
        } if kdfs.as_slice() == [1]
    ));
}

#[test]
fn projects_identity_request_and_response_without_identity_value() {
    let request = packet(REQUEST, AKA, 5, &[fixed(17, 1)]);
    assert!(matches!(
        EapAkaPacket::parse(&request)
            .expect("identity request is valid")
            .kind(),
        EapAkaPacketKind::IdentityRequest {
            requested: EapAkaIdentityRequest::FullAuthentication
        }
    ));

    let response = packet(
        RESPONSE,
        AKA_PRIME,
        5,
        &[actual_text(14, b"synthetic-user@example.invalid")],
    );
    let parsed = EapAkaPacket::parse(&response).expect("identity response is valid");
    assert!(matches!(parsed.kind(), EapAkaPacketKind::IdentityResponse));
    let debug = format!("{parsed:?}");
    assert!(!debug.contains("synthetic-user"));
    assert!(!debug.contains("example.invalid"));
}

#[test]
fn rejects_nul_octets_in_identity_and_kdf_input_text() {
    let identity = packet(RESPONSE, AKA, 5, &[actual_text(14, b"synthetic-user\0")]);
    assert_error(
        &identity,
        EapAkaError::NulInTextValue { attribute_type: 14 },
    );

    let kdf_input = packet(
        REQUEST,
        AKA_PRIME,
        1,
        &[
            fixed(1, 5),
            fixed(2, 5),
            marker(24, 1),
            actual_text(23, b"WL\0AN"),
            fixed(11, 5),
        ],
    );
    assert_error(
        &kdf_input,
        EapAkaError::NulInTextValue { attribute_type: 23 },
    );
}

#[test]
fn projects_protected_success_notification_and_ack() {
    let challenge_request = packet(
        REQUEST,
        AKA_PRIME,
        1,
        &[
            fixed(1, 5),
            marker(135, 0),
            fixed(2, 5),
            marker(24, 1),
            actual_text(23, b"WLAN"),
            fixed(11, 5),
        ],
    );
    let EapAkaPacketKind::ChallengeRequest(challenge_request) =
        EapAkaPacket::parse(&challenge_request)
            .expect("result-indication offer is valid")
            .kind()
    else {
        panic!("unexpected evidence");
    };
    assert!(challenge_request.has_result_indication());

    let challenge_response = packet(
        RESPONSE,
        AKA_PRIME,
        1,
        &[marker(135, 0), res(64), fixed(11, 5)],
    );
    let EapAkaPacketKind::FullChallengeResponse(challenge_response) =
        EapAkaPacket::parse(&challenge_response)
            .expect("result-indication acceptance is valid")
            .kind()
    else {
        panic!("unexpected evidence");
    };
    assert!(challenge_response.has_result_indication());

    let request = packet(REQUEST, AKA_PRIME, 12, &[marker(12, 32_768), fixed(11, 5)]);
    let parsed = EapAkaPacket::parse(&request).expect("notification is valid");
    let EapAkaPacketKind::NotificationRequest(evidence) = parsed.kind() else {
        panic!("unexpected evidence");
    };
    assert_eq!(
        evidence.phase(),
        EapAkaNotificationPhase::AfterAuthentication
    );
    assert!(!evidence.indicates_failure());
    assert!(evidence.is_protected_success_candidate());

    let ack = packet(RESPONSE, AKA_PRIME, 12, &[fixed(11, 5)]);
    let EapAkaPacketKind::NotificationResponse(evidence) = EapAkaPacket::parse(&ack)
        .expect("notification acknowledgement is valid")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert!(evidence.has_mac());
    assert!(!evidence.has_encrypted_data());
}

#[test]
fn projects_fast_reauthentication_outer_envelopes() {
    let attributes = [fixed(129, 5), fixed(130, 5), fixed(11, 5)];
    let request = packet(REQUEST, AKA_PRIME, 13, &attributes);
    let response = packet(RESPONSE, AKA_PRIME, 13, &attributes);
    assert!(matches!(
        EapAkaPacket::parse(&request)
            .expect("reauth request is valid")
            .kind(),
        EapAkaPacketKind::ReauthenticationRequest { .. }
    ));
    assert!(matches!(
        EapAkaPacket::parse(&response)
            .expect("reauth response is valid")
            .kind(),
        EapAkaPacketKind::ReauthenticationResponse { .. }
    ));
}

#[test]
fn projects_auth_reject_and_client_error() {
    let reject = packet(RESPONSE, AKA, 2, &[]);
    assert!(matches!(
        EapAkaPacket::parse(&reject)
            .expect("auth reject is valid")
            .kind(),
        EapAkaPacketKind::AuthenticationReject
    ));

    let client_error = packet(RESPONSE, AKA, 14, &[marker(22, 0)]);
    assert!(matches!(
        EapAkaPacket::parse(&client_error)
            .expect("client error is valid")
            .kind(),
        EapAkaPacketKind::ClientError { code: 0 }
    ));
}

#[test]
fn rejects_duplicate_singletons_and_illegal_kdf_duplicates() {
    let duplicate_mac = packet(
        REQUEST,
        AKA,
        1,
        &[fixed(1, 5), fixed(2, 5), fixed(11, 5), fixed(11, 5)],
    );
    assert_error(
        &duplicate_mac,
        EapAkaError::DuplicateSingletonAttribute { attribute_type: 11 },
    );

    let invalid_kdf = full_aka_prime_challenge_request(&[1, 1]);
    assert_error(
        &invalid_kdf,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidKdfDuplicate,
        },
    );
}

#[test]
fn rejects_incomplete_or_mixed_aka_prime_challenge_shapes() {
    let missing_input = packet(
        REQUEST,
        AKA_PRIME,
        1,
        &[fixed(1, 5), fixed(2, 5), marker(24, 2), fixed(11, 5)],
    );
    assert_error(
        &missing_input,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::KdfInputMissing,
        },
    );

    let non_leading_one_without_input = packet(
        REQUEST,
        AKA_PRIME,
        1,
        &[
            fixed(1, 5),
            fixed(2, 5),
            marker(24, 2),
            marker(24, 1),
            fixed(11, 5),
        ],
    );
    assert_error(
        &non_leading_one_without_input,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::KdfInputMissing,
        },
    );

    let mixed = packet(
        RESPONSE,
        AKA_PRIME,
        1,
        &[marker(24, 2), res(64), fixed(11, 5)],
    );
    assert_error(
        &mixed,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::KdfNegotiationMixedWithAuthentication,
        },
    );
}

#[test]
fn rejects_reserved_kdf_zero_but_retains_future_numeric_kdfs() {
    let reserved = packet(RESPONSE, AKA_PRIME, 1, &[marker(24, 0)]);
    assert_error(
        &reserved,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::ReservedKdf,
        },
    );

    let future = packet(RESPONSE, AKA_PRIME, 1, &[marker(24, 65_535)]);
    let EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(evidence) = EapAkaPacket::parse(&future)
        .expect("future nonzero KDF remains numeric structural evidence")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert_eq!(evidence.claimed_kdf(), 65_535);
}

#[test]
fn enforces_notification_phase_semantics() {
    let impossible = packet(REQUEST, AKA, 12, &[marker(12, 0xc000)]);
    assert_error(
        &impossible,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidNotificationPhase,
        },
    );

    let protected_pre_auth = packet(REQUEST, AKA, 12, &[marker(12, 0x4000), fixed(11, 5)]);
    assert_error(
        &protected_pre_auth,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::PreAuthenticationNotificationMacPresent,
        },
    );

    let encrypted_pre_auth = packet(
        REQUEST,
        AKA,
        12,
        &[marker(12, 0x4000), fixed(129, 5), fixed(130, 5)],
    );
    let EapAkaPacketKind::NotificationRequest(evidence) = EapAkaPacket::parse(&encrypted_pre_auth)
        .expect("RFC attribute table permits paired encrypted data")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert!(evidence.has_encrypted_data());

    let encrypted_ack = packet(RESPONSE, AKA, 12, &[fixed(129, 5), fixed(130, 5)]);
    let EapAkaPacketKind::NotificationResponse(evidence) = EapAkaPacket::parse(&encrypted_ack)
        .expect("a stateless ack cannot infer the request P bit")
        .kind()
    else {
        panic!("unexpected evidence");
    };
    assert!(!evidence.has_mac());
    assert!(evidence.has_encrypted_data());

    let missing_post_auth_mac = packet(REQUEST, AKA, 12, &[marker(12, 0)]);
    assert!(matches!(
        EapAkaPacket::parse(&missing_post_auth_mac),
        Err(EapAkaError::MissingAttribute {
            attribute_type: 11,
            ..
        })
    ));
}

#[test]
fn rejects_incomplete_encryption_pair_and_bad_encrypted_length() {
    let one_half = packet(
        REQUEST,
        AKA,
        1,
        &[fixed(1, 5), fixed(2, 5), fixed(11, 5), fixed(129, 5)],
    );
    assert_error(
        &one_half,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::EncryptionPairIncomplete,
        },
    );

    let bad_encrypted = packet(
        REQUEST,
        AKA,
        1,
        &[fixed(1, 5), fixed(2, 5), fixed(11, 5), fixed(130, 2)],
    );
    assert!(matches!(
        EapAkaPacket::parse(&bad_encrypted),
        Err(EapAkaError::InvalidAttributeLength {
            attribute_type: 130,
            ..
        })
    ));
}

#[test]
fn rejects_bad_res_lengths_and_padding() {
    let too_short = packet(RESPONSE, AKA, 1, &[res(24), fixed(11, 5)]);
    assert_error(
        &too_short,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidResBitLength,
        },
    );

    let mut bad_padding = res(33);
    bad_padding[8] = 1;
    let packet = packet(RESPONSE, AKA, 1, &[bad_padding, fixed(11, 5)]);
    assert_error(
        &packet,
        EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidResPadding,
        },
    );
}

#[test]
fn rejects_malformed_eap_and_attribute_framing() {
    assert!(matches!(
        EapAkaPacket::parse(&[1, 0, 0, 7, AKA, 1, 0]),
        Err(EapAkaError::PacketTooShort { .. })
    ));

    let mut mismatch = full_aka_challenge_request();
    mismatch[3] -= 1;
    assert!(matches!(
        EapAkaPacket::parse(&mismatch),
        Err(EapAkaError::LengthMismatch { .. })
    ));

    let zero = packet(REQUEST, AKA, 5, &[vec![10, 0, 0, 0]]);
    assert!(matches!(
        EapAkaPacket::parse(&zero),
        Err(EapAkaError::ZeroLengthAttribute { .. })
    ));

    let mut truncated = packet(REQUEST, AKA, 5, &[fixed(10, 1)]);
    truncated[9] = 2;
    assert!(matches!(
        EapAkaPacket::parse(&truncated),
        Err(EapAkaError::AttributeTruncated { .. })
    ));
}

#[test]
fn rejects_illegal_direction_and_known_attribute_placement() {
    let request_reject = packet(REQUEST, AKA, 2, &[]);
    assert!(matches!(
        EapAkaPacket::parse(&request_reject),
        Err(EapAkaError::InvalidDirection { .. })
    ));

    let nested_counter_at_top_level = packet(REQUEST, AKA, 13, &[fixed(19, 1)]);
    assert!(matches!(
        EapAkaPacket::parse(&nested_counter_at_top_level),
        Err(EapAkaError::ProhibitedAttribute {
            attribute_type: 19,
            ..
        })
    ));
}

#[test]
fn rejects_unknown_mandatory_and_counts_unknown_skippable() {
    let mandatory = packet(RESPONSE, AKA, 2, &[fixed(25, 1)]);
    assert!(matches!(
        EapAkaPacket::parse(&mandatory),
        Err(EapAkaError::UnknownMandatoryAttribute {
            attribute_type: 25,
            ..
        })
    ));

    let skippable = packet(RESPONSE, AKA, 2, &[fixed(200, 1), fixed(201, 2)]);
    let parsed = EapAkaPacket::parse(&skippable).expect("unknown skippable attributes are valid");
    assert_eq!(parsed.attribute_count(), 2);
    assert_eq!(parsed.unknown_skippable_count(), 2);
}

#[test]
fn bounds_attribute_count() {
    let accepted = vec![fixed(200, 1); EAP_AKA_MAX_ATTRIBUTES];
    assert!(EapAkaPacket::parse(&packet(RESPONSE, AKA, 2, &accepted)).is_ok());

    let rejected = vec![fixed(200, 1); EAP_AKA_MAX_ATTRIBUTES + 1];
    assert_error(
        &packet(RESPONSE, AKA, 2, &rejected),
        EapAkaError::TooManyAttributes {
            maximum: EAP_AKA_MAX_ATTRIBUTES,
        },
    );
}

#[test]
fn errors_and_debug_are_redaction_safe() {
    let identity = b"never-print-this-identity@example.invalid";
    let mut malformed = actual_text(14, identity);
    let last = malformed.len() - 1;
    malformed[last] = 1;
    let packet = packet(RESPONSE, AKA, 5, &[malformed]);
    let error = EapAkaPacket::parse(&packet).expect_err("padding must be zero");
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("never-print"));
    assert!(!diagnostic.contains("example.invalid"));
    assert_eq!(error.code(), "eap_aka_nonzero_attribute_padding");
}
