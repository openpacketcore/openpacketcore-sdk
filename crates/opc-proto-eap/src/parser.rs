use crate::{
    EapAkaChallengeRequestEvidence, EapAkaCombinationError, EapAkaError,
    EapAkaFullChallengeResponseEvidence, EapAkaIdentityRequest, EapAkaKdfList,
    EapAkaKdfNegotiationEvidence, EapAkaMethod, EapAkaNotificationAckEvidence,
    EapAkaNotificationEvidence, EapAkaNotificationPhase, EapAkaPacket, EapAkaPacketKind,
    EapAkaSubtype, EapCode, EAP_AKA_HEADER_LEN, EAP_AKA_MAX_ATTRIBUTES, EAP_AKA_MAX_KDF_ATTRIBUTES,
};

const AT_RAND: u8 = 1;
const AT_AUTN: u8 = 2;
const AT_RES: u8 = 3;
const AT_AUTS: u8 = 4;
const AT_PADDING: u8 = 6;
const AT_NONCE_MT: u8 = 7;
const AT_PERMANENT_ID_REQ: u8 = 10;
const AT_MAC: u8 = 11;
const AT_NOTIFICATION: u8 = 12;
const AT_ANY_ID_REQ: u8 = 13;
const AT_IDENTITY: u8 = 14;
const AT_VERSION_LIST: u8 = 15;
const AT_SELECTED_VERSION: u8 = 16;
const AT_FULLAUTH_ID_REQ: u8 = 17;
const AT_COUNTER: u8 = 19;
const AT_COUNTER_TOO_SMALL: u8 = 20;
const AT_NONCE_S: u8 = 21;
const AT_CLIENT_ERROR_CODE: u8 = 22;
const AT_KDF_INPUT: u8 = 23;
const AT_KDF: u8 = 24;
const AT_IV: u8 = 129;
const AT_ENCR_DATA: u8 = 130;
const AT_NEXT_PSEUDONYM: u8 = 132;
const AT_NEXT_REAUTH_ID: u8 = 133;
const AT_CHECKCODE: u8 = 134;
const AT_RESULT_IND: u8 = 135;
const AT_BIDDING: u8 = 136;

#[derive(Default)]
struct Attributes {
    count: usize,
    unknown_skippable_count: usize,
    rand: bool,
    autn: bool,
    res: bool,
    auts: bool,
    permanent_id_req: bool,
    mac: bool,
    notification: Option<u16>,
    any_id_req: bool,
    identity: bool,
    fullauth_id_req: bool,
    client_error_code: Option<u16>,
    kdf_input: bool,
    kdf_values: [u16; EAP_AKA_MAX_KDF_ATTRIBUTES],
    kdf_count: usize,
    iv: bool,
    encrypted_data: bool,
    checkcode: bool,
    result_indication: bool,
    bidding: Option<bool>,
}

pub(crate) fn parse(packet: &[u8]) -> Result<EapAkaPacket<'_>, EapAkaError> {
    if packet.len() < EAP_AKA_HEADER_LEN {
        return Err(EapAkaError::PacketTooShort {
            actual: packet.len(),
            minimum: EAP_AKA_HEADER_LEN,
        });
    }

    let code = match packet[0] {
        1 => EapCode::Request,
        2 => EapCode::Response,
        actual => return Err(EapAkaError::UnsupportedCode { actual }),
    };
    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if declared != packet.len() {
        return Err(EapAkaError::LengthMismatch {
            declared,
            actual: packet.len(),
        });
    }
    let method = match packet[4] {
        23 => EapAkaMethod::Aka,
        50 => EapAkaMethod::AkaPrime,
        actual => return Err(EapAkaError::UnsupportedMethod { actual }),
    };
    let subtype = match packet[5] {
        1 => EapAkaSubtype::Challenge,
        2 => EapAkaSubtype::AuthenticationReject,
        4 => EapAkaSubtype::SynchronizationFailure,
        5 => EapAkaSubtype::Identity,
        12 => EapAkaSubtype::Notification,
        13 => EapAkaSubtype::Reauthentication,
        14 => EapAkaSubtype::ClientError,
        actual => return Err(EapAkaError::UnsupportedSubtype { actual }),
    };
    if packet[6] != 0 || packet[7] != 0 {
        return Err(EapAkaError::ReservedFieldNonZero);
    }
    validate_direction(code, subtype)?;

    let mut attributes = Attributes::default();
    let mut offset = EAP_AKA_HEADER_LEN;
    while offset < packet.len() {
        let remaining = packet.len() - offset;
        if remaining < 2 {
            return Err(EapAkaError::AttributeHeaderTruncated { offset, remaining });
        }
        let attribute_type = packet[offset];
        let length_units = packet[offset + 1];
        if length_units == 0 {
            return Err(EapAkaError::ZeroLengthAttribute {
                attribute_type,
                offset,
            });
        }
        let attribute_len = usize::from(length_units) * 4;
        if attribute_len > remaining {
            return Err(EapAkaError::AttributeTruncated {
                attribute_type,
                offset,
                declared: attribute_len,
                remaining,
            });
        }
        attributes.count += 1;
        if attributes.count > EAP_AKA_MAX_ATTRIBUTES {
            return Err(EapAkaError::TooManyAttributes {
                maximum: EAP_AKA_MAX_ATTRIBUTES,
            });
        }

        let attribute = &packet[offset..offset + attribute_len];
        parse_attribute(
            &mut attributes,
            attribute_type,
            attribute,
            offset,
            code,
            method,
            subtype,
        )?;
        offset += attribute_len;
    }

    validate_encryption_pair(&attributes)?;
    let kind = validate_packet(code, method, subtype, &attributes)?;

    Ok(EapAkaPacket {
        packet,
        code,
        identifier: packet[1],
        method,
        subtype,
        attribute_count: attributes.count as u16,
        unknown_skippable_count: attributes.unknown_skippable_count as u16,
        kind,
    })
}

fn validate_direction(code: EapCode, subtype: EapAkaSubtype) -> Result<(), EapAkaError> {
    let valid = match subtype {
        EapAkaSubtype::Challenge
        | EapAkaSubtype::Identity
        | EapAkaSubtype::Notification
        | EapAkaSubtype::Reauthentication => true,
        EapAkaSubtype::AuthenticationReject
        | EapAkaSubtype::SynchronizationFailure
        | EapAkaSubtype::ClientError => code == EapCode::Response,
    };
    if valid {
        Ok(())
    } else {
        Err(EapAkaError::InvalidDirection {
            code: code.as_u8(),
            subtype: subtype.as_u8(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_attribute(
    attributes: &mut Attributes,
    attribute_type: u8,
    attribute: &[u8],
    offset: usize,
    code: EapCode,
    method: EapAkaMethod,
    subtype: EapAkaSubtype,
) -> Result<(), EapAkaError> {
    if !is_known_attribute(attribute_type) {
        if attribute_type < 128 {
            return Err(EapAkaError::UnknownMandatoryAttribute {
                attribute_type,
                offset,
            });
        }
        attributes.unknown_skippable_count += 1;
        return Ok(());
    }
    if !attribute_allowed(code, method, subtype, attribute_type) {
        return Err(EapAkaError::ProhibitedAttribute {
            attribute_type,
            code: code.as_u8(),
            subtype: subtype.as_u8(),
        });
    }

    match attribute_type {
        AT_RAND => {
            validate_fixed_length(attribute_type, attribute, 20)?;
            set_once(&mut attributes.rand, attribute_type)
        }
        AT_AUTN => {
            validate_fixed_length(attribute_type, attribute, 20)?;
            set_once(&mut attributes.autn, attribute_type)
        }
        AT_RES => {
            validate_res(attribute)?;
            set_once(&mut attributes.res, attribute_type)
        }
        AT_AUTS => {
            validate_fixed_length(attribute_type, attribute, 16)?;
            set_once(&mut attributes.auts, attribute_type)
        }
        AT_PERMANENT_ID_REQ => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once(&mut attributes.permanent_id_req, attribute_type)
        }
        AT_MAC => {
            validate_fixed_length(attribute_type, attribute, 20)?;
            set_once(&mut attributes.mac, attribute_type)
        }
        AT_NOTIFICATION => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once_value(
                &mut attributes.notification,
                u16::from_be_bytes([attribute[2], attribute[3]]),
                attribute_type,
            )
        }
        AT_ANY_ID_REQ => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once(&mut attributes.any_id_req, attribute_type)
        }
        AT_IDENTITY => {
            validate_actual_text(attribute_type, attribute, false)?;
            set_once(&mut attributes.identity, attribute_type)
        }
        AT_FULLAUTH_ID_REQ => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once(&mut attributes.fullauth_id_req, attribute_type)
        }
        AT_CLIENT_ERROR_CODE => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once_value(
                &mut attributes.client_error_code,
                u16::from_be_bytes([attribute[2], attribute[3]]),
                attribute_type,
            )
        }
        AT_KDF_INPUT => {
            validate_actual_text(attribute_type, attribute, false)?;
            set_once(&mut attributes.kdf_input, attribute_type)
        }
        AT_KDF => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            if attributes.kdf_count == EAP_AKA_MAX_KDF_ATTRIBUTES {
                return Err(EapAkaError::InvalidAttributeCombination {
                    reason: EapAkaCombinationError::TooManyKdfAttributes,
                });
            }
            let kdf = u16::from_be_bytes([attribute[2], attribute[3]]);
            if kdf == 0 {
                return Err(EapAkaError::InvalidAttributeCombination {
                    reason: EapAkaCombinationError::ReservedKdf,
                });
            }
            attributes.kdf_values[attributes.kdf_count] = kdf;
            attributes.kdf_count += 1;
            Ok(())
        }
        AT_IV => {
            validate_fixed_length(attribute_type, attribute, 20)?;
            set_once(&mut attributes.iv, attribute_type)
        }
        AT_ENCR_DATA => {
            validate_encrypted_data(attribute)?;
            set_once(&mut attributes.encrypted_data, attribute_type)
        }
        AT_CHECKCODE => {
            validate_checkcode(method, attribute)?;
            set_once(&mut attributes.checkcode, attribute_type)
        }
        AT_RESULT_IND => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            set_once(&mut attributes.result_indication, attribute_type)
        }
        AT_BIDDING => {
            validate_fixed_length(attribute_type, attribute, 4)?;
            let value = u16::from_be_bytes([attribute[2], attribute[3]]);
            set_once_value(&mut attributes.bidding, value & 0x8000 != 0, attribute_type)
        }
        AT_PADDING | AT_NONCE_MT | AT_VERSION_LIST | AT_SELECTED_VERSION | AT_COUNTER
        | AT_COUNTER_TOO_SMALL | AT_NONCE_S | AT_NEXT_PSEUDONYM | AT_NEXT_REAUTH_ID => {
            Err(EapAkaError::ProhibitedAttribute {
                attribute_type,
                code: code.as_u8(),
                subtype: subtype.as_u8(),
            })
        }
        _ => Ok(()),
    }
}

fn is_known_attribute(attribute_type: u8) -> bool {
    matches!(
        attribute_type,
        AT_RAND
            | AT_AUTN
            | AT_RES
            | AT_AUTS
            | AT_PADDING
            | AT_NONCE_MT
            | AT_PERMANENT_ID_REQ
            | AT_MAC
            | AT_NOTIFICATION
            | AT_ANY_ID_REQ
            | AT_IDENTITY
            | AT_VERSION_LIST
            | AT_SELECTED_VERSION
            | AT_FULLAUTH_ID_REQ
            | AT_COUNTER
            | AT_COUNTER_TOO_SMALL
            | AT_NONCE_S
            | AT_CLIENT_ERROR_CODE
            | AT_KDF_INPUT
            | AT_KDF
            | AT_IV
            | AT_ENCR_DATA
            | AT_NEXT_PSEUDONYM
            | AT_NEXT_REAUTH_ID
            | AT_CHECKCODE
            | AT_RESULT_IND
            | AT_BIDDING
    )
}

fn attribute_allowed(
    code: EapCode,
    method: EapAkaMethod,
    subtype: EapAkaSubtype,
    attribute_type: u8,
) -> bool {
    match (subtype, code) {
        (EapAkaSubtype::Challenge, EapCode::Request) => {
            matches!(
                attribute_type,
                AT_RAND | AT_AUTN | AT_MAC | AT_IV | AT_ENCR_DATA | AT_CHECKCODE | AT_RESULT_IND
            ) || (method == EapAkaMethod::AkaPrime
                && matches!(attribute_type, AT_KDF_INPUT | AT_KDF))
                || (method == EapAkaMethod::Aka && attribute_type == AT_BIDDING)
        }
        (EapAkaSubtype::Challenge, EapCode::Response) => {
            matches!(
                attribute_type,
                AT_RES | AT_MAC | AT_IV | AT_ENCR_DATA | AT_CHECKCODE | AT_RESULT_IND
            ) || (method == EapAkaMethod::AkaPrime && attribute_type == AT_KDF)
        }
        (EapAkaSubtype::AuthenticationReject, EapCode::Response) => false,
        (EapAkaSubtype::SynchronizationFailure, EapCode::Response) => {
            attribute_type == AT_AUTS
                || (method == EapAkaMethod::AkaPrime && attribute_type == AT_KDF)
        }
        (EapAkaSubtype::Identity, EapCode::Request) => matches!(
            attribute_type,
            AT_PERMANENT_ID_REQ | AT_ANY_ID_REQ | AT_FULLAUTH_ID_REQ
        ),
        (EapAkaSubtype::Identity, EapCode::Response) => attribute_type == AT_IDENTITY,
        (EapAkaSubtype::Notification, EapCode::Request) => matches!(
            attribute_type,
            AT_NOTIFICATION | AT_MAC | AT_IV | AT_ENCR_DATA
        ),
        (EapAkaSubtype::Notification, EapCode::Response) => {
            matches!(attribute_type, AT_MAC | AT_IV | AT_ENCR_DATA)
        }
        (EapAkaSubtype::Reauthentication, _) => matches!(
            attribute_type,
            AT_MAC | AT_IV | AT_ENCR_DATA | AT_CHECKCODE | AT_RESULT_IND
        ),
        (EapAkaSubtype::ClientError, EapCode::Response) => attribute_type == AT_CLIENT_ERROR_CODE,
        _ => false,
    }
}

fn validate_fixed_length(
    attribute_type: u8,
    attribute: &[u8],
    expected: usize,
) -> Result<(), EapAkaError> {
    if attribute.len() == expected {
        Ok(())
    } else {
        Err(EapAkaError::InvalidAttributeLength {
            attribute_type,
            actual: attribute.len(),
        })
    }
}

fn validate_actual_text(
    attribute_type: u8,
    attribute: &[u8],
    allow_empty: bool,
) -> Result<(), EapAkaError> {
    if attribute.len() < 4 {
        return Err(EapAkaError::InvalidAttributeLength {
            attribute_type,
            actual: attribute.len(),
        });
    }
    let actual = usize::from(u16::from_be_bytes([attribute[2], attribute[3]]));
    let available = attribute.len() - 4;
    if (!allow_empty && actual == 0) || actual > available {
        return Err(EapAkaError::InvalidActualValueLength {
            attribute_type,
            actual,
            available,
        });
    }
    let padded = actual.checked_add(3).map(|value| value & !3).ok_or(
        EapAkaError::InvalidActualValueLength {
            attribute_type,
            actual,
            available,
        },
    )?;
    if attribute.len() != 4 + padded {
        return Err(EapAkaError::InvalidActualValueLength {
            attribute_type,
            actual,
            available,
        });
    }
    let text = &attribute[4..4 + actual];
    if std::str::from_utf8(text).is_err() {
        return Err(EapAkaError::InvalidUtf8 { attribute_type });
    }
    if text.contains(&0) {
        return Err(EapAkaError::NulInTextValue { attribute_type });
    }
    if attribute[4 + actual..].iter().any(|byte| *byte != 0) {
        return Err(EapAkaError::NonzeroAttributePadding { attribute_type });
    }
    Ok(())
}

fn validate_res(attribute: &[u8]) -> Result<(), EapAkaError> {
    if attribute.len() < 8 {
        return Err(EapAkaError::InvalidAttributeLength {
            attribute_type: AT_RES,
            actual: attribute.len(),
        });
    }
    let bit_len = usize::from(u16::from_be_bytes([attribute[2], attribute[3]]));
    if !(32..=128).contains(&bit_len) {
        return Err(EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidResBitLength,
        });
    }
    let byte_len = bit_len.div_ceil(8);
    let padded = (byte_len + 3) & !3;
    if attribute.len() != 4 + padded {
        return Err(EapAkaError::InvalidAttributeLength {
            attribute_type: AT_RES,
            actual: attribute.len(),
        });
    }
    if !bit_len.is_multiple_of(8) {
        let unused_bits = 8 - (bit_len % 8);
        let unused_mask = (1_u8 << unused_bits) - 1;
        if attribute[4 + byte_len - 1] & unused_mask != 0 {
            return Err(EapAkaError::InvalidAttributeCombination {
                reason: EapAkaCombinationError::InvalidResPadding,
            });
        }
    }
    if attribute[4 + byte_len..].iter().any(|byte| *byte != 0) {
        return Err(EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidResPadding,
        });
    }
    Ok(())
}

fn validate_encrypted_data(attribute: &[u8]) -> Result<(), EapAkaError> {
    if attribute.len() >= 20 && (attribute.len() - 4).is_multiple_of(16) {
        Ok(())
    } else {
        Err(EapAkaError::InvalidAttributeLength {
            attribute_type: AT_ENCR_DATA,
            actual: attribute.len(),
        })
    }
}

fn validate_checkcode(method: EapAkaMethod, attribute: &[u8]) -> Result<(), EapAkaError> {
    let full_len = match method {
        EapAkaMethod::Aka => 24,
        EapAkaMethod::AkaPrime => 36,
    };
    if attribute.len() == 4 || attribute.len() == full_len {
        Ok(())
    } else {
        Err(EapAkaError::InvalidAttributeLength {
            attribute_type: AT_CHECKCODE,
            actual: attribute.len(),
        })
    }
}

fn set_once(slot: &mut bool, attribute_type: u8) -> Result<(), EapAkaError> {
    if *slot {
        Err(EapAkaError::DuplicateSingletonAttribute { attribute_type })
    } else {
        *slot = true;
        Ok(())
    }
}

fn set_once_value<T>(
    slot: &mut Option<T>,
    value: T,
    attribute_type: u8,
) -> Result<(), EapAkaError> {
    if slot.is_some() {
        Err(EapAkaError::DuplicateSingletonAttribute { attribute_type })
    } else {
        *slot = Some(value);
        Ok(())
    }
}

fn validate_encryption_pair(attributes: &Attributes) -> Result<(), EapAkaError> {
    if attributes.iv == attributes.encrypted_data {
        Ok(())
    } else {
        Err(EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::EncryptionPairIncomplete,
        })
    }
}

fn validate_packet(
    code: EapCode,
    method: EapAkaMethod,
    subtype: EapAkaSubtype,
    attributes: &Attributes,
) -> Result<EapAkaPacketKind, EapAkaError> {
    match (subtype, code) {
        (EapAkaSubtype::Challenge, EapCode::Request) => {
            validate_challenge_request(method, attributes)
        }
        (EapAkaSubtype::Challenge, EapCode::Response) => {
            validate_challenge_response(method, attributes)
        }
        (EapAkaSubtype::AuthenticationReject, EapCode::Response) => {
            Ok(EapAkaPacketKind::AuthenticationReject)
        }
        (EapAkaSubtype::SynchronizationFailure, EapCode::Response) => {
            require(attributes.auts, AT_AUTS, code, subtype)?;
            let kdf_reoffer_shape = if method == EapAkaMethod::AkaPrime {
                require(attributes.kdf_count > 0, AT_KDF, code, subtype)?;
                validate_kdf_list(attributes)?
            } else {
                false
            };
            Ok(EapAkaPacketKind::SynchronizationFailure {
                kdfs: kdf_list(attributes),
                kdf_reoffer_shape,
            })
        }
        (EapAkaSubtype::Identity, EapCode::Request) => {
            let selectors = usize::from(attributes.permanent_id_req)
                + usize::from(attributes.any_id_req)
                + usize::from(attributes.fullauth_id_req);
            if selectors != 1 {
                return Err(EapAkaError::InvalidAttributeCombination {
                    reason: EapAkaCombinationError::IdentityRequestNotExclusive,
                });
            }
            let requested = if attributes.permanent_id_req {
                EapAkaIdentityRequest::Permanent
            } else if attributes.any_id_req {
                EapAkaIdentityRequest::Any
            } else {
                EapAkaIdentityRequest::FullAuthentication
            };
            Ok(EapAkaPacketKind::IdentityRequest { requested })
        }
        (EapAkaSubtype::Identity, EapCode::Response) => {
            require(attributes.identity, AT_IDENTITY, code, subtype)?;
            Ok(EapAkaPacketKind::IdentityResponse)
        }
        (EapAkaSubtype::Notification, EapCode::Request) => {
            validate_notification_request(attributes, code, subtype)
        }
        (EapAkaSubtype::Notification, EapCode::Response) => Ok(
            EapAkaPacketKind::NotificationResponse(EapAkaNotificationAckEvidence {
                mac_present: attributes.mac,
                encrypted_data_present: attributes.encrypted_data,
            }),
        ),
        (EapAkaSubtype::Reauthentication, EapCode::Request) => {
            require(attributes.mac, AT_MAC, code, subtype)?;
            require(attributes.iv, AT_IV, code, subtype)?;
            require(attributes.encrypted_data, AT_ENCR_DATA, code, subtype)?;
            Ok(EapAkaPacketKind::ReauthenticationRequest {
                result_indication_present: attributes.result_indication,
            })
        }
        (EapAkaSubtype::Reauthentication, EapCode::Response) => {
            require(attributes.mac, AT_MAC, code, subtype)?;
            require(attributes.iv, AT_IV, code, subtype)?;
            require(attributes.encrypted_data, AT_ENCR_DATA, code, subtype)?;
            Ok(EapAkaPacketKind::ReauthenticationResponse {
                result_indication_present: attributes.result_indication,
            })
        }
        (EapAkaSubtype::ClientError, EapCode::Response) => {
            let error_code = attributes
                .client_error_code
                .ok_or(EapAkaError::MissingAttribute {
                    attribute_type: AT_CLIENT_ERROR_CODE,
                    code: code.as_u8(),
                    subtype: subtype.as_u8(),
                })?;
            Ok(EapAkaPacketKind::ClientError { code: error_code })
        }
        _ => Err(EapAkaError::InvalidDirection {
            code: code.as_u8(),
            subtype: subtype.as_u8(),
        }),
    }
}

fn validate_challenge_request(
    method: EapAkaMethod,
    attributes: &Attributes,
) -> Result<EapAkaPacketKind, EapAkaError> {
    let code = EapCode::Request;
    let subtype = EapAkaSubtype::Challenge;
    require(attributes.rand, AT_RAND, code, subtype)?;
    require(attributes.autn, AT_AUTN, code, subtype)?;
    require(attributes.mac, AT_MAC, code, subtype)?;

    let kdf_reoffer_shape = if method == EapAkaMethod::AkaPrime {
        require(attributes.kdf_count > 0, AT_KDF, code, subtype)?;
        let reoffer = validate_kdf_list(attributes)?;
        if !attributes.kdf_input {
            return Err(EapAkaError::InvalidAttributeCombination {
                reason: EapAkaCombinationError::KdfInputMissing,
            });
        }
        reoffer
    } else {
        false
    };
    Ok(EapAkaPacketKind::ChallengeRequest(
        EapAkaChallengeRequestEvidence {
            kdfs: kdf_list(attributes),
            kdf_reoffer_shape,
            kdf_input_present: attributes.kdf_input,
            result_indication_present: attributes.result_indication,
            encrypted_data_present: attributes.encrypted_data,
            bidding_supports_aka_prime: attributes.bidding,
        },
    ))
}

fn validate_challenge_response(
    method: EapAkaMethod,
    attributes: &Attributes,
) -> Result<EapAkaPacketKind, EapAkaError> {
    let code = EapCode::Response;
    let subtype = EapAkaSubtype::Challenge;
    if method == EapAkaMethod::AkaPrime && attributes.kdf_count > 0 {
        let recognized_count = attributes.count - attributes.unknown_skippable_count;
        if attributes.kdf_count != 1 || recognized_count != 1 {
            return Err(EapAkaError::InvalidAttributeCombination {
                reason: EapAkaCombinationError::KdfNegotiationMixedWithAuthentication,
            });
        }
        return Ok(EapAkaPacketKind::AkaPrimeKdfNegotiationResponse(
            EapAkaKdfNegotiationEvidence {
                claimed_kdf: attributes.kdf_values[0],
            },
        ));
    }
    require(attributes.res, AT_RES, code, subtype)?;
    require(attributes.mac, AT_MAC, code, subtype)?;
    Ok(EapAkaPacketKind::FullChallengeResponse(
        EapAkaFullChallengeResponseEvidence {
            result_indication_present: attributes.result_indication,
            encrypted_data_present: attributes.encrypted_data,
        },
    ))
}

fn validate_notification_request(
    attributes: &Attributes,
    code: EapCode,
    subtype: EapAkaSubtype,
) -> Result<EapAkaPacketKind, EapAkaError> {
    let notification = attributes
        .notification
        .ok_or(EapAkaError::MissingAttribute {
            attribute_type: AT_NOTIFICATION,
            code: code.as_u8(),
            subtype: subtype.as_u8(),
        })?;
    let failure = notification & 0x8000 == 0;
    let phase = if notification & 0x4000 == 0 {
        EapAkaNotificationPhase::AfterAuthentication
    } else {
        EapAkaNotificationPhase::BeforeAuthentication
    };
    if phase == EapAkaNotificationPhase::BeforeAuthentication && !failure {
        return Err(EapAkaError::InvalidAttributeCombination {
            reason: EapAkaCombinationError::InvalidNotificationPhase,
        });
    }
    match phase {
        EapAkaNotificationPhase::AfterAuthentication => {
            require(attributes.mac, AT_MAC, code, subtype)?;
        }
        EapAkaNotificationPhase::BeforeAuthentication => {
            if attributes.mac {
                return Err(EapAkaError::InvalidAttributeCombination {
                    reason: EapAkaCombinationError::PreAuthenticationNotificationMacPresent,
                });
            }
        }
    }
    Ok(EapAkaPacketKind::NotificationRequest(
        EapAkaNotificationEvidence {
            code: notification,
            phase,
            failure,
            encrypted_data_present: attributes.encrypted_data,
        },
    ))
}

fn kdf_list(attributes: &Attributes) -> EapAkaKdfList {
    EapAkaKdfList {
        values: attributes.kdf_values,
        len: attributes.kdf_count as u8,
    }
}

fn validate_kdf_list(attributes: &Attributes) -> Result<bool, EapAkaError> {
    let values = &attributes.kdf_values[..attributes.kdf_count];
    let mut duplicate_found = false;
    for (left_index, left) in values.iter().enumerate() {
        for (right_index, right) in values.iter().enumerate().skip(left_index + 1) {
            if left != right {
                continue;
            }
            let legal_reoffer_pair = values.len() >= 3
                && left_index == 0
                && right_index >= 2
                && *left == values[0]
                && !duplicate_found;
            if !legal_reoffer_pair {
                return Err(EapAkaError::InvalidAttributeCombination {
                    reason: EapAkaCombinationError::InvalidKdfDuplicate,
                });
            }
            duplicate_found = true;
        }
    }
    Ok(duplicate_found)
}

fn require(
    present: bool,
    attribute_type: u8,
    code: EapCode,
    subtype: EapAkaSubtype,
) -> Result<(), EapAkaError> {
    if present {
        Ok(())
    } else {
        Err(EapAkaError::MissingAttribute {
            attribute_type,
            code: code.as_u8(),
            subtype: subtype.as_u8(),
        })
    }
}
