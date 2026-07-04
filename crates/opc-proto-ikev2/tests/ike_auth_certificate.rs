use opc_proto_ikev2::{
    build_ike_auth_certificate_payload, build_ike_auth_certreq_payload,
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    decode_ike_auth_cleartext_payloads, Ikev2CertificatePayload, Ikev2CertificatePayloadBuild,
    Ikev2CertificateRequestPayload, Ikev2CertificateRequestPayloadBuild, Ikev2IkeAuthBuildError,
    Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2NotifyPayloadBuild, PayloadType,
    IKEV2_CERT_ENCODING_X509_SIGNATURE, IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
    IKEV2_NOTIFY_PROTOCOL_ID_NONE,
};

const RSA_CERT_DER: &[u8] = include_bytes!("data/rsa2048_cert.der");

#[test]
fn certificate_payload_round_trips_through_chain() {
    let body = build_ike_auth_certificate_payload(&Ikev2CertificatePayloadBuild {
        cert_encoding: IKEV2_CERT_ENCODING_X509_SIGNATURE,
        cert_data: RSA_CERT_DER.to_vec(),
    })
    .expect("CERT build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Certificate,
        body,
    }])
    .expect("CERT chain");

    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("CERT decode");
    assert_eq!(decoded.certificates.len(), 1);
    let certificate = decoded.certificates[0];
    assert_eq!(
        certificate.cert_encoding,
        IKEV2_CERT_ENCODING_X509_SIGNATURE
    );
    assert_eq!(certificate.cert_data, RSA_CERT_DER);
}

#[test]
fn certreq_payload_round_trips_with_and_without_ca_data() {
    for ca_data in [Vec::new(), vec![0xab; 40]] {
        let body = build_ike_auth_certreq_payload(&Ikev2CertificateRequestPayloadBuild {
            cert_encoding: IKEV2_CERT_ENCODING_X509_SIGNATURE,
            ca_data: ca_data.clone(),
        })
        .expect("CERTREQ build");
        let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::CertificateRequest,
            body,
        }])
        .expect("CERTREQ chain");

        let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("CERTREQ decode");
        assert_eq!(decoded.certificate_requests.len(), 1);
        let request = decoded.certificate_requests[0];
        assert_eq!(request.cert_encoding, IKEV2_CERT_ENCODING_X509_SIGNATURE);
        assert_eq!(request.ca_data, ca_data.as_slice());
    }
}

#[test]
fn truncated_certificate_payload_fails_closed() {
    assert_eq!(
        Ikev2CertificatePayload::decode_body(&[]),
        Err(Ikev2IkeAuthPayloadError::CertificateTooShort)
    );
    assert_eq!(
        Ikev2CertificateRequestPayload::decode_body(&[]),
        Err(Ikev2IkeAuthPayloadError::CertificateRequestTooShort)
    );
}

#[test]
fn certificate_with_zero_encoding_fails_closed() {
    assert_eq!(
        Ikev2CertificatePayload::decode_body(&[0, 0xde, 0xad]),
        Err(Ikev2IkeAuthPayloadError::InvalidCertificateEncoding)
    );
    assert_eq!(
        Ikev2CertificateRequestPayload::decode_body(&[0]),
        Err(Ikev2IkeAuthPayloadError::InvalidCertificateEncoding)
    );
    assert_eq!(
        build_ike_auth_certificate_payload(&Ikev2CertificatePayloadBuild {
            cert_encoding: 0,
            cert_data: vec![1],
        }),
        Err(Ikev2IkeAuthBuildError::InvalidCertificateEncoding)
    );
    assert_eq!(
        build_ike_auth_certreq_payload(&Ikev2CertificateRequestPayloadBuild {
            cert_encoding: 0,
            ca_data: Vec::new(),
        }),
        Err(Ikev2IkeAuthBuildError::InvalidCertificateEncoding)
    );
}

#[test]
fn certificate_with_empty_data_fails_closed() {
    assert_eq!(
        Ikev2CertificatePayload::decode_body(&[IKEV2_CERT_ENCODING_X509_SIGNATURE]),
        Err(Ikev2IkeAuthPayloadError::CertificateDataEmpty)
    );
    assert_eq!(
        build_ike_auth_certificate_payload(&Ikev2CertificatePayloadBuild {
            cert_encoding: IKEV2_CERT_ENCODING_X509_SIGNATURE,
            cert_data: Vec::new(),
        }),
        Err(Ikev2IkeAuthBuildError::CertificateDataEmpty)
    );
}

#[test]
fn certificate_debug_reports_lengths_only() {
    let view = Ikev2CertificatePayload::decode_body(&[
        IKEV2_CERT_ENCODING_X509_SIGNATURE,
        0xde,
        0xad,
        0xbe,
        0xef,
    ])
    .expect("CERT view");
    let debug = format!("{view:?}");
    assert!(debug.contains("cert_data_len"));
    assert!(!debug.contains("de"));
}

#[test]
fn eap_only_authentication_notify_round_trips() {
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        spi: Vec::new(),
        notify_message_type: IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION,
        notification_data: Vec::new(),
    })
    .expect("EAP_ONLY notify build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .expect("EAP_ONLY chain");

    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("EAP_ONLY decode");
    assert_eq!(decoded.notifies.len(), 1);
    assert!(decoded.notifies[0].is_eap_only_authentication());
    assert!(decoded.eap_only_authentication_requested());
}

#[test]
fn absent_eap_only_authentication_notify_reads_false() {
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        spi: Vec::new(),
        notify_message_type: 16_388,
        notification_data: vec![0u8; 20],
    })
    .expect("notify build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .expect("notify chain");

    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("notify decode");
    assert!(!decoded.eap_only_authentication_requested());
}
