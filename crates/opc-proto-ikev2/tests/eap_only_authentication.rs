use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    decode_ike_auth_cleartext_payloads, decode_ikev2_eap_only_authentication_notify,
    Ikev2EapOnlyAuthenticationError, Ikev2EapOnlyAuthenticationNotifyError,
    Ikev2IkeAuthPayloadBuild, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild, PayloadType,
    IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
};

const EAP_ONLY_TYPE_BYTES: [u8; 2] = IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION.to_be_bytes();
const CANONICAL: [u8; 4] = [0, 0, EAP_ONLY_TYPE_BYTES[0], EAP_ONLY_TYPE_BYTES[1]];
const NONZERO_PROTOCOL: [u8; 4] = [3, 0, EAP_ONLY_TYPE_BYTES[0], EAP_ONLY_TYPE_BYTES[1]];
const NONEMPTY_SPI: [u8; 5] = [0, 1, EAP_ONLY_TYPE_BYTES[0], EAP_ONLY_TYPE_BYTES[1], 0xa5];
const NONEMPTY_DATA: [u8; 5] = [0, 0, EAP_ONLY_TYPE_BYTES[0], EAP_ONLY_TYPE_BYTES[1], 0x5a];
const UNRELATED: [u8; 4] = [0, 0, 0x40, 0x04];

fn cleartext_chain(notify_bodies: &[&[u8]]) -> (PayloadType, Vec<u8>) {
    let payloads: Vec<_> = notify_bodies
        .iter()
        .map(|body| Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: body.to_vec(),
        })
        .collect();
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&payloads).expect("synthetic Notify chain");
    (first, bytes.to_vec())
}

#[test]
fn canonical_notify_classifier_and_aggregate_accept_exact_rfc5998_shape() {
    let notify = Ikev2NotifyPayload::decode_body(&CANONICAL).expect("canonical Notify");
    let marker = decode_ikev2_eap_only_authentication_notify(notify).expect("canonical validation");
    assert!(marker.is_some());

    let (first, bytes) = cleartext_chain(&[&CANONICAL]);
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert!(decoded
        .eap_only_authentication()
        .expect("canonical aggregate")
        .is_some());
    assert_eq!(decoded.notifies[0].protocol_id, 0);
    assert_eq!(decoded.notifies[0].spi, &[]);
    assert_eq!(decoded.notifies[0].notification_data, &[]);
}

#[test]
fn canonical_builder_emits_exact_four_octet_rfc5998_body() {
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::eap_only_authentication())
        .expect("canonical builder");
    assert_eq!(body, CANONICAL);
}

#[test]
fn unrelated_notify_is_absent_not_malformed() {
    let notify = Ikev2NotifyPayload::decode_body(&UNRELATED).expect("unrelated Notify");
    assert_eq!(
        decode_ikev2_eap_only_authentication_notify(notify),
        Ok(None)
    );

    let (first, bytes) = cleartext_chain(&[&UNRELATED]);
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert_eq!(decoded.eap_only_authentication(), Ok(None));
}

#[test]
fn nonzero_protocol_id_is_typed_malformed_and_raw_notify_is_preserved() {
    let notify = Ikev2NotifyPayload::decode_body(&NONZERO_PROTOCOL).expect("structural Notify");
    assert_eq!(
        decode_ikev2_eap_only_authentication_notify(notify),
        Err(Ikev2EapOnlyAuthenticationNotifyError::ProtocolIdNonzero)
    );

    let (first, bytes) = cleartext_chain(&[&NONZERO_PROTOCOL]);
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert_eq!(decoded.notifies[0].protocol_id, 3);
    assert_eq!(
        decoded.eap_only_authentication(),
        Err(Ikev2EapOnlyAuthenticationError::Malformed {
            reason: Ikev2EapOnlyAuthenticationNotifyError::ProtocolIdNonzero,
        })
    );
}

#[test]
fn nonzero_spi_size_and_nonempty_spi_are_typed_malformed() {
    let decoded = Ikev2NotifyPayload::decode_body(&NONEMPTY_SPI).expect("structural Notify");
    assert_eq!(decoded.spi, &[0xa5]);
    assert_eq!(
        decode_ikev2_eap_only_authentication_notify(decoded),
        Err(Ikev2EapOnlyAuthenticationNotifyError::SpiSizeNonzero)
    );
    let (first, bytes) = cleartext_chain(&[&NONEMPTY_SPI]);
    let aggregate = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert_eq!(
        aggregate.eap_only_authentication(),
        Err(Ikev2EapOnlyAuthenticationError::Malformed {
            reason: Ikev2EapOnlyAuthenticationNotifyError::SpiSizeNonzero,
        })
    );

    let inconsistent_public_view = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
        spi: &[0xa5],
        notification_data: &[],
    };
    assert_eq!(
        decode_ikev2_eap_only_authentication_notify(inconsistent_public_view),
        Err(Ikev2EapOnlyAuthenticationNotifyError::SpiNonempty)
    );
}

#[test]
fn nonempty_notification_data_is_typed_malformed_and_preserved() {
    let notify = Ikev2NotifyPayload::decode_body(&NONEMPTY_DATA).expect("structural Notify");
    assert_eq!(notify.notification_data, &[0x5a]);
    assert_eq!(
        decode_ikev2_eap_only_authentication_notify(notify),
        Err(Ikev2EapOnlyAuthenticationNotifyError::NotificationDataNonempty)
    );

    let (first, bytes) = cleartext_chain(&[&NONEMPTY_DATA]);
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert_eq!(decoded.notifies[0].notification_data, &[0x5a]);
    assert_eq!(
        decoded.eap_only_authentication(),
        Err(Ikev2EapOnlyAuthenticationError::Malformed {
            reason: Ikev2EapOnlyAuthenticationNotifyError::NotificationDataNonempty,
        })
    );
}

#[test]
fn duplicate_canonical_notifies_fail_closed_with_counts() {
    let (first, bytes) = cleartext_chain(&[&CANONICAL, &CANONICAL]);
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert_eq!(
        decoded.eap_only_authentication(),
        Err(Ikev2EapOnlyAuthenticationError::Duplicate {
            occurrences: 2,
            valid_occurrences: 2,
            malformed_occurrences: 0,
            first_malformed_reason: None,
        })
    );
}

#[test]
fn mixed_valid_and_malformed_duplicates_fail_closed_in_both_orders() {
    for bodies in [
        [&CANONICAL[..], &NONZERO_PROTOCOL[..]],
        [&NONZERO_PROTOCOL[..], &CANONICAL[..]],
    ] {
        let (first, bytes) = cleartext_chain(&bodies);
        let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
        assert_eq!(
            decoded.eap_only_authentication(),
            Err(Ikev2EapOnlyAuthenticationError::Duplicate {
                occurrences: 2,
                valid_occurrences: 1,
                malformed_occurrences: 1,
                first_malformed_reason: Some(
                    Ikev2EapOnlyAuthenticationNotifyError::ProtocolIdNonzero,
                ),
            })
        );
    }
}

#[test]
fn diagnostics_expose_only_codes_reasons_and_counts() {
    assert_eq!(
        Ikev2EapOnlyAuthenticationNotifyError::ProtocolIdNonzero.as_str(),
        "ike_eap_only_authentication_protocol_id_nonzero"
    );
    assert_eq!(
        Ikev2EapOnlyAuthenticationNotifyError::SpiSizeNonzero.as_str(),
        "ike_eap_only_authentication_spi_size_nonzero"
    );
    assert_eq!(
        Ikev2EapOnlyAuthenticationNotifyError::SpiNonempty.as_str(),
        "ike_eap_only_authentication_spi_nonempty"
    );
    assert_eq!(
        Ikev2EapOnlyAuthenticationNotifyError::NotificationDataNonempty.as_str(),
        "ike_eap_only_authentication_notification_data_nonempty"
    );

    let error = Ikev2EapOnlyAuthenticationError::Duplicate {
        occurrences: 2,
        valid_occurrences: 1,
        malformed_occurrences: 1,
        first_malformed_reason: Some(
            Ikev2EapOnlyAuthenticationNotifyError::NotificationDataNonempty,
        ),
    };
    assert_eq!(
        error.to_string(),
        "ike_auth_eap_only_authentication_duplicate"
    );
    let debug = format!("{error:?}");
    assert!(debug.contains("NotificationDataNonempty"));
    assert!(debug.contains("valid_occurrences: 1"));
    assert!(!debug.contains("a55a"));
    assert!(!debug.contains("peer"));

    let raw = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 2,
        notify_message_type: IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
        spi: &[0xa5, 0x5a],
        notification_data: &[0xde, 0xad],
    };
    let raw_debug = format!("{raw:?}");
    assert!(raw_debug.contains("spi_len: 2"));
    assert!(raw_debug.contains("notification_data_len: 2"));
    assert!(!raw_debug.contains("a5"));
    assert!(!raw_debug.contains("de"));
}

#[test]
#[allow(deprecated)]
fn compatibility_booleans_are_canonical_and_duplicate_safe() {
    let canonical = Ikev2NotifyPayload::decode_body(&CANONICAL).expect("canonical Notify");
    let malformed =
        Ikev2NotifyPayload::decode_body(&NONZERO_PROTOCOL).expect("malformed type Notify");
    assert!(canonical.is_eap_only_authentication());
    assert!(!malformed.is_eap_only_authentication());

    let (first, bytes) = cleartext_chain(&[&CANONICAL, &CANONICAL]);
    let duplicate = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert!(!duplicate.eap_only_authentication_requested());

    let (first, bytes) = cleartext_chain(&[&CANONICAL]);
    let valid = decode_ike_auth_cleartext_payloads(first, &bytes).expect("IKE_AUTH decode");
    assert!(valid.eap_only_authentication_requested());
}
