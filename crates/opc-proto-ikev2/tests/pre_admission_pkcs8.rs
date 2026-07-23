use opc_crypto_provider::{CryptoCapability, IkeSignatureAlgorithm};
use opc_proto_ikev2::{
    inspect_ikev2_signature_key_pkcs8_der, Ikev2CryptoRequirements,
    Ikev2PreAdmissionInspectionError, IKEV2_PRE_ADMISSION_LEAF_CERTIFICATE_DER_MAX_LEN,
    IKEV2_PRE_ADMISSION_PKCS8_DER_MAX_LEN,
};

const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P256_CERT_DER: &[u8] = include_bytes!("data/p256_cert.der");
const P384_PKCS8_DER: &[u8] = include_bytes!("data/p384_pkcs8.der");
const P384_SPKI_DER: &[u8] = include_bytes!("data/p384_spki.der");
const RSA2048_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");

// These static key/SPKI/certificate fixtures predate this inspection boundary
// (they entered in PR #72). Their key-to-SPKI and certificate-to-SPKI
// relationships were independently rechecked with OpenSSL 3.2.6:
//
// `openssl pkey -inform DER -in <key.der> -pubout -outform DER`
// `openssl x509 -inform DER -in p256_cert.der -pubkey -noout |
//  openssl pkey -pubin -outform DER`
//
// The resulting SPKI SHA-256 values are P-256
// `83f794bb7a5ca656145f3e1d6ac2de890ee85cc88225ea0f3f98a50f81eba37e`
// and P-384
// `6537c2dad98ba45ff8a32b79583512dfb673cab7338c02e67b5528082f64b43a`.
#[test]
fn p256_and_p384_vectors_return_exact_requirements_and_canonical_spki() {
    for (pkcs8_der, spki_der, expected_algorithm) in [
        (
            P256_PKCS8_DER,
            P256_SPKI_DER,
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
        ),
        (
            P384_PKCS8_DER,
            P384_SPKI_DER,
            IkeSignatureAlgorithm::EcdsaP384Sha2_384,
        ),
    ] {
        let inspection =
            inspect_ikev2_signature_key_pkcs8_der(pkcs8_der).expect("independent key vector");
        assert_eq!(inspection.requirement().algorithm(), expected_algorithm);
        assert_eq!(
            inspection.public_key_identity().algorithm(),
            expected_algorithm
        );
        assert_eq!(
            inspection.public_key_identity().as_spki_der(),
            spki_der,
            "RustCrypto canonical SPKI must match the independent fixture"
        );

        let mut requirements = Ikev2CryptoRequirements::new();
        inspection.requirement().apply_to(&mut requirements);
        let capabilities = requirements.required_capabilities();
        assert!(capabilities.contains(CryptoCapability::IkeSignature));
        assert!(capabilities.contains(CryptoCapability::Zeroization));
    }
}

#[test]
fn inspection_succeeds_without_module_and_retains_only_public_identity() {
    let mut configured_der = P256_PKCS8_DER.to_vec();
    let inspection = inspect_ikev2_signature_key_pkcs8_der(&configured_der)
        .expect("pre-admission inspection does not require a module");

    configured_der.fill(0);
    drop(configured_der);
    assert_eq!(
        inspection.public_key_identity().as_spki_der(),
        P256_SPKI_DER
    );
    assert_eq!(
        format!("{inspection:?}"),
        "Ikev2SignatureKeyInspection { requirement: \
         Ikev2SignatureGenerationRequirement { algorithm: EcdsaP256Sha2_256 }, \
         public_key_identity: Ikev2SignaturePublicKeyIdentity { \
         algorithm: \"ecdsa_p256_sha2_256\", spki_der_len: 91 } }"
    );
    assert_eq!(inspection.to_string(), "ecdsa_p256_sha2_256");
}

#[test]
fn exact_leaf_certificate_spki_match_is_fail_closed() {
    let p256 =
        inspect_ikev2_signature_key_pkcs8_der(P256_PKCS8_DER).expect("P-256 fixture inspects");
    p256.require_leaf_certificate_spki_match(P256_CERT_DER)
        .expect("independent P-256 certificate matches");

    let p384 =
        inspect_ikev2_signature_key_pkcs8_der(P384_PKCS8_DER).expect("P-384 fixture inspects");
    assert_eq!(
        p384.require_leaf_certificate_spki_match(P256_CERT_DER),
        Err(Ikev2PreAdmissionInspectionError::LeafCertificateSpkiMismatch)
    );

    let mut trailing = P256_CERT_DER.to_vec();
    trailing.push(0);
    assert_eq!(
        p256.require_leaf_certificate_spki_match(&trailing),
        Err(Ikev2PreAdmissionInspectionError::LeafCertificateTrailingData)
    );
    assert_eq!(
        p256.require_leaf_certificate_spki_match(&[]),
        Err(Ikev2PreAdmissionInspectionError::LeafCertificateEmpty)
    );
    assert_eq!(
        p256.require_leaf_certificate_spki_match(&[0x30, 0x01, 0x00]),
        Err(Ikev2PreAdmissionInspectionError::LeafCertificateMalformed)
    );
    assert_eq!(
        p256.require_leaf_certificate_spki_match(&vec![
            0;
            IKEV2_PRE_ADMISSION_LEAF_CERTIFICATE_DER_MAX_LEN
                + 1
        ]),
        Err(Ikev2PreAdmissionInspectionError::LeafCertificateTooLarge)
    );
}

#[test]
fn pkcs8_resource_and_exact_der_failures_have_stable_codes() {
    assert_inspection_error(&[], Ikev2PreAdmissionInspectionError::Pkcs8Empty);
    assert_inspection_error(
        &vec![0; IKEV2_PRE_ADMISSION_PKCS8_DER_MAX_LEN + 1],
        Ikev2PreAdmissionInspectionError::Pkcs8TooLarge,
    );
    assert_inspection_error(
        &[0x30, 0x01, 0x00],
        Ikev2PreAdmissionInspectionError::Pkcs8Malformed,
    );

    let mut trailing = P256_PKCS8_DER.to_vec();
    trailing.push(0);
    assert_inspection_error(
        &trailing,
        Ikev2PreAdmissionInspectionError::Pkcs8TrailingData,
    );
}

#[test]
fn algorithm_first_classification_distinguishes_unsupported_and_malformed() {
    assert_inspection_error(
        RSA2048_PKCS8_DER,
        Ikev2PreAdmissionInspectionError::UnsupportedAlgorithm,
    );

    let mut unsupported_curve = P256_PKCS8_DER.to_vec();
    assert_eq!(unsupported_curve.get(26), Some(&0x07));
    unsupported_curve[26] = 0x08;
    assert_inspection_error(
        &unsupported_curve,
        Ikev2PreAdmissionInspectionError::UnsupportedAlgorithm,
    );

    let mut malformed_parameters = P256_PKCS8_DER.to_vec();
    assert_eq!(malformed_parameters.get(17), Some(&0x06));
    malformed_parameters[17] = 0x04;
    assert_inspection_error(
        &malformed_parameters,
        Ikev2PreAdmissionInspectionError::Pkcs8AlgorithmParametersMalformed,
    );

    let mut malformed_supported_key = P256_PKCS8_DER.to_vec();
    assert_eq!(
        malformed_supported_key.get(34..36),
        Some([0x04, 0x20].as_slice())
    );
    malformed_supported_key[36..68].fill(0);
    assert_inspection_error(
        &malformed_supported_key,
        Ikev2PreAdmissionInspectionError::Pkcs8KeyMalformed,
    );
}

#[test]
fn errors_are_stable_and_never_format_input_material() {
    let mut malformed_supported_key = P256_PKCS8_DER.to_vec();
    malformed_supported_key[36..68].fill(0);
    let error = inspect_ikev2_signature_key_pkcs8_der(&malformed_supported_key)
        .expect_err("zero scalar is invalid");
    assert_eq!(error.as_str(), "ikev2_pre_admission_pkcs8_key_malformed");
    assert_eq!(error.to_string(), "ikev2_pre_admission_pkcs8_key_malformed");
    assert_eq!(format!("{error:?}"), "Pkcs8KeyMalformed");

    let private_prefix = P256_PKCS8_DER[36..44]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(!error.to_string().contains(&private_prefix));
    assert!(!format!("{error:?}").contains(&private_prefix));
}

fn assert_inspection_error(input: &[u8], expected: Ikev2PreAdmissionInspectionError) {
    assert_eq!(inspect_ikev2_signature_key_pkcs8_der(input), Err(expected));
}
