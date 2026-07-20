//! Byte-for-byte parity proofs for `Ikev2SoftwareCryptoOperations` against
//! the pre-existing IKEv2 algorithm code paths, asserted on RFC known-answer
//! vectors rather than on whatever either implementation happens to emit.

use opc_crypto_provider::{
    CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm, IkeDhGroup, IkeDhKeyPair,
    IkeDiffieHellmanOperations, IkeEncryptionOperations, IkeIntegrityAlgorithm,
    IkeIntegrityOperations, IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm,
    IkeSignatureOperations,
};
use opc_proto_ikev2::{
    build_ike_auth_identification_payload, compute_ike_auth_signature,
    derive_ike_sa_init_key_material, seal_ikev2_sa_init_protected_payload,
    verify_ike_auth_signature, Ikev2AuthenticationPayload, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2EphemeralDhKey, Ikev2IdentificationPayloadBuild, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm,
    Ikev2ProtectedPayloadDirection, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
    Ikev2SignatureAuthKey, Ikev2SoftwareCryptoOperations, ProtectedPayloadKind,
    ProtectedPayloadSealContext, IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
    RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256, RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384,
};

mod support;

const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P384_PKCS8_DER: &[u8] = include_bytes!("data/p384_pkcs8.der");
const P384_SPKI_DER: &[u8] = include_bytes!("data/p384_spki.der");

const OPERATIONS: Ikev2SoftwareCryptoOperations = Ikev2SoftwareCryptoOperations::new();

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid test hex fixture"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sequence(start: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|offset| start.wrapping_add(offset as u8))
        .collect()
}

#[test]
fn software_prf_matches_rfc4868_prf_one_known_answers_for_all_three_widths() {
    // RFC 4868 PRF-1 (key = 20 x 0x0b, data = "Hi There"); the SHA-512 case
    // is also RFC 4231 test case 1.
    let key = [0x0b; 20];
    let cases = [
        (
            IkePrfAlgorithm::HmacSha2_256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            IkePrfAlgorithm::HmacSha2_384,
            concat!(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c",
                "faea9ea9076ede7f4af152e8b2fa9cb6"
            ),
        ),
        (
            IkePrfAlgorithm::HmacSha2_512,
            concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ),
        ),
    ];
    for (algorithm, expected) in cases {
        let output = OPERATIONS
            .prf(algorithm, &key, b"Hi There")
            .expect("RFC 4868 PRF-1 computes");
        assert_eq!(output.len(), algorithm.output_len());
        assert_eq!(&*output, decode_hex(expected).as_slice(), "{algorithm}");
    }
}

#[test]
fn software_prf_hashes_an_oversized_key_first_per_rfc4868_prf_five() {
    let key = [0xaa; 131];
    let output = OPERATIONS
        .prf(
            IkePrfAlgorithm::HmacSha2_512,
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        )
        .expect("RFC 4868 PRF-5 computes");
    assert_eq!(
        &*output,
        decode_hex(concat!(
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        ))
        .as_slice()
    );
}

#[test]
fn software_prf_rejects_an_empty_key_without_exposing_a_provider_source() {
    let error = OPERATIONS
        .prf(IkePrfAlgorithm::HmacSha2_256, &[], b"data")
        .expect_err("empty PRF key must fail closed");
    assert_eq!(error.code(), CryptoOperationErrorCode::InvalidKeyLength);
    assert_eq!(error.as_str(), "crypto_op_invalid_key_length");
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(format!("{error}"), "crypto_op_invalid_key_length");
    assert_eq!(
        format!("{error:?}"),
        "CryptoOperationError { code: \"crypto_op_invalid_key_length\" }"
    );
}

#[test]
fn software_prf_plus_reproduces_the_independent_sha512_ike_sa_kdf_vector_byte_for_byte() {
    support::ensure_ike_crypto();

    // The same independently generated (OpenSSL 3) RFC 7296 section 2.13/2.14
    // vector that pins `derive_ike_sa_init_key_material`, replayed through
    // the trait `prf`/`prf_plus` primitives and cross-checked against the
    // existing derivation path.
    let initiator_nonce: Vec<u8> = (0x00..0x20).collect();
    let responder_nonce: Vec<u8> = (0xa0..0xc0).collect();
    let shared_secret: Vec<u8> = (0x00..=0xff).collect();
    let initiator_spi = [1, 2, 3, 4, 5, 6, 7, 8];
    let responder_spi = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

    let mut nonce_seed = initiator_nonce.clone();
    nonce_seed.extend_from_slice(&responder_nonce);
    let skeyseed = OPERATIONS
        .prf(IkePrfAlgorithm::HmacSha2_512, &nonce_seed, &shared_secret)
        .expect("SKEYSEED computes");
    assert_eq!(
        &*skeyseed,
        decode_hex(concat!(
            "be6bee7f3a87542831303538d74f1d0f3a0a43476538969db0ec73b87ca2e732",
            "9246e4c25cfc6d20dff6081d6305e18d2b0bf073ecef0b8b97354a865faf0374"
        ))
        .as_slice()
    );

    let mut key_seed = nonce_seed.clone();
    key_seed.extend_from_slice(&initiator_spi);
    key_seed.extend_from_slice(&responder_spi);
    // SK_d(64) SK_ai(64) SK_ar(64) SK_ei(32) SK_er(32) SK_pi(64) SK_pr(64).
    let key_stream = OPERATIONS
        .prf_plus(IkePrfAlgorithm::HmacSha2_512, &skeyseed, &key_seed, 384)
        .expect("prf+ key stream computes");
    let expected_stream = decode_hex(concat!(
        // SK_d
        "3a6780f9b7988b52b3640daa79e5b31254c8626ef3a8d5a99ea2a9eaa2d16b8b",
        "729b3469ef799357a90ce554942c209bf192c8f39295b727a9eb1681a097f89e",
        // SK_ai
        "77f1ee6d2350595a0de2a98b516ad4d7271c6ead856cdd0b41cff6cbe70378c6",
        "4dd8d0f6ddc99175e5d24b280ff06533aa5b1e2883480a55bdf00c91c5965eed",
        // SK_ar
        "19973371058ed48a8aca918ea0ca6558db708cf43dedc71346087d26571312c2",
        "3804aa1862746430c0831684b6f2d0609835a49860704d9de9603633e3f30652",
        // SK_ei
        "e8d7681465f7bb4b2a38526b8d6d9e85b07f4d02038a30cc629af84f1beea3d1",
        // SK_er
        "05bbff5bbdb0e310ca533a87326779a8438d70b699d27514ef0bffe69d286405",
        // SK_pi
        "5f5ca92e01d475e94bcf891d030ad5375af225315d7a0538416dd5e6fa9b3c92",
        "a91ac1f1745ad930d43985490e04ce2031503ba369809d3ce5fd812fe762c54e",
        // SK_pr
        "ab498746f6e2f55fd41801101a531174d6f0e5bc7a0b50bb5b205cec3717176c",
        "bd2cdf6ffe4de67d396d83877e958c214fe84e6766788041bc906d90bbeea9eb",
    ));
    assert_eq!(&*key_stream, expected_stream.as_slice());

    // Cross-check against the pre-existing derivation code path.
    let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    )
    .expect("valid vector profile");
    let material = derive_ike_sa_init_key_material(
        profile,
        initiator_spi,
        responder_spi,
        &initiator_nonce,
        &responder_nonce,
        &shared_secret,
        None,
    )
    .expect("existing derivation path succeeds");
    assert_eq!(material.skeyseed(), &*skeyseed);
    assert_eq!(material.sk_d(), &key_stream[..64]);
    assert_eq!(material.sk_ai(), &key_stream[64..128]);
    assert_eq!(material.sk_ar(), &key_stream[128..192]);
    assert_eq!(material.sk_ei(), &key_stream[192..224]);
    assert_eq!(material.sk_er(), &key_stream[224..256]);
    assert_eq!(material.sk_pi(), &key_stream[256..320]);
    assert_eq!(material.sk_pr(), &key_stream[320..384]);
}

#[test]
fn software_prf_plus_enforces_the_rfc7296_255_block_limit() {
    let limit = 255 * IkePrfAlgorithm::HmacSha2_256.output_len();
    let at_limit = OPERATIONS
        .prf_plus(IkePrfAlgorithm::HmacSha2_256, &[0x0b; 32], b"seed", limit)
        .expect("exactly 255 blocks is permitted");
    assert_eq!(at_limit.len(), limit);

    let error = OPERATIONS
        .prf_plus(
            IkePrfAlgorithm::HmacSha2_256,
            &[0x0b; 32],
            b"seed",
            limit + 1,
        )
        .expect_err("more than 255 blocks must fail closed");
    assert_eq!(
        error.code(),
        CryptoOperationErrorCode::OutputLengthUnsupported
    );
    assert_eq!(error.as_str(), "crypto_op_output_length_unsupported");
}

#[test]
fn software_integrity_checksums_match_rfc4868_truncated_known_answers() {
    // RFC 4868 AUTH-1 vectors (key length = PRF output length, data =
    // "Hi There"), truncated to the negotiated ICV length. The message is
    // split across the prefix/suffix parts to pin the concatenation contract.
    let cases = [
        (
            IkeIntegrityAlgorithm::HmacSha2_256_128,
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7",
        ),
        (
            IkeIntegrityAlgorithm::HmacSha2_384_192,
            concat!(
                "b6a8d5636f5c6a7224f9977dcf7ee6c7fb6d0c48cbdee9737a959796489bddbc",
                "4c5df61d5b3297b4fb68dab9f1b582c2"
            ),
        ),
        (
            IkeIntegrityAlgorithm::HmacSha2_512_256,
            concat!(
                "637edc6e01dce7e6742a99451aae82df23da3e92439e590e43e761b33e910fb8",
                "ac2878ebd5803f6f0b61dbce5e251ff8789a4722c1be65aea45fd464e89f8f5b"
            ),
        ),
    ];
    for (algorithm, full_mac_hex) in cases {
        let key = vec![0x0b; algorithm.key_len()];
        let expected_icv = &decode_hex(full_mac_hex)[..algorithm.icv_len()];
        let split = OPERATIONS
            .compute_integrity_checksum(algorithm, &key, b"Hi ", b"There")
            .expect("RFC 4868 AUTH checksum computes");
        assert_eq!(&*split, expected_icv, "{algorithm}");
        let single = OPERATIONS
            .compute_integrity_checksum(algorithm, &key, b"Hi There", b"")
            .expect("single-part checksum computes");
        assert_eq!(&*single, expected_icv, "{algorithm}");
        OPERATIONS
            .verify_integrity_checksum(algorithm, &key, b"Hi There", expected_icv)
            .expect("matching checksum verifies");
    }
}

#[test]
fn software_integrity_verification_fails_closed_and_keeps_the_constant_time_contract() {
    // The implementation delegates to the pre-existing helper whose
    // comparison uses `subtle::ConstantTimeEq`; every rejection collapses to
    // one authentication-failed code so the error reveals nothing about
    // which octet differed.
    let algorithm = IkeIntegrityAlgorithm::HmacSha2_512_256;
    let key = vec![0x0b; algorithm.key_len()];
    let mut icv = OPERATIONS
        .compute_integrity_checksum(algorithm, &key, b"Hi There", b"")
        .expect("checksum computes")
        .to_vec();

    icv[31] ^= 0x01;
    let tampered = OPERATIONS
        .verify_integrity_checksum(algorithm, &key, b"Hi There", &icv)
        .expect_err("tampered checksum must fail");
    assert_eq!(
        tampered.code(),
        CryptoOperationErrorCode::AuthenticationFailed
    );
    assert_eq!(tampered.as_str(), "crypto_op_authentication_failed");

    icv[31] ^= 0x01;
    let truncated = OPERATIONS
        .verify_integrity_checksum(algorithm, &key, b"Hi There", &icv[..16])
        .expect_err("wrong-length checksum must fail identically");
    assert_eq!(
        truncated.code(),
        CryptoOperationErrorCode::AuthenticationFailed
    );

    let bad_key = OPERATIONS
        .verify_integrity_checksum(algorithm, &key[..16], b"Hi There", &icv)
        .expect_err("wrong-length key must fail closed");
    assert_eq!(bad_key.code(), CryptoOperationErrorCode::InvalidKeyLength);
}

#[test]
fn software_cbc_encryption_and_integrity_reproduce_the_independent_openssl_message_vector() {
    // The complete-message AES-256-CBC/HMAC-SHA-512 vector generated
    // independently with OpenSSL that also pins the existing seal path in
    // tests/protected_payload_encrypt_then_mac.rs, reproduced here from the
    // trait primitives: prefix(32) || IV(16) || ciphertext(16) || ICV(32).
    let expected = decode_hex(concat!(
        "010203040506070811121314151617182e202308000000010000006023000044",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "20c0fc6c0a479a0c6c084eae4dc1b303",
        "f247045d7dbfa00fea352a456097fd6db341db4b46adda5e55e2f1963953462b"
    ));
    let sk_ei = sequence(0x40, 32);
    let sk_ai = sequence(0x00, 64);
    let iv = &expected[32..48];
    // Inner payload plus the shortest RFC 7296 block-aligning padding and
    // the Pad Length octet.
    let mut plaintext = vec![0, 0, 0, 8, 1, 2, 3, 4];
    plaintext.extend_from_slice(&[0; 7]);
    plaintext.push(7);

    let ciphertext = OPERATIONS
        .encrypt_cbc(IkeCbcAlgorithm::AesCbc256, &sk_ei, iv, &plaintext)
        .expect("independent CBC vector encrypts");
    assert_eq!(ciphertext.as_slice(), &expected[48..64]);

    let icv = OPERATIONS
        .compute_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha2_512_256,
            &sk_ai,
            &expected[..32],
            &expected[32..64],
        )
        .expect("independent vector ICV computes");
    assert_eq!(&*icv, &expected[64..96]);
    OPERATIONS
        .verify_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha2_512_256,
            &sk_ai,
            &expected[..64],
            &expected[64..96],
        )
        .expect("independent vector ICV verifies");

    let decrypted = OPERATIONS
        .decrypt_cbc(IkeCbcAlgorithm::AesCbc256, &sk_ei, iv, &expected[48..64])
        .expect("independent CBC vector decrypts");
    assert_eq!(&*decrypted, plaintext.as_slice());
}

#[test]
fn software_cbc_rejects_misaligned_input_and_wrong_iv_or_key_lengths() {
    let key = sequence(0x40, 32);
    let iv = [0xa0; 16];

    let misaligned = OPERATIONS
        .encrypt_cbc(IkeCbcAlgorithm::AesCbc256, &key, &iv, &[0x00; 15])
        .expect_err("misaligned plaintext must fail closed");
    assert_eq!(
        misaligned.code(),
        CryptoOperationErrorCode::InvalidInputLength
    );
    assert_eq!(misaligned.as_str(), "crypto_op_invalid_input_length");

    let empty = OPERATIONS
        .decrypt_cbc(IkeCbcAlgorithm::AesCbc256, &key, &iv, &[])
        .expect_err("empty ciphertext must fail closed");
    assert_eq!(empty.code(), CryptoOperationErrorCode::InvalidInputLength);

    let short_iv = OPERATIONS
        .encrypt_cbc(IkeCbcAlgorithm::AesCbc256, &key, &iv[..8], &[0x00; 16])
        .expect_err("short IV must fail closed");
    assert_eq!(
        short_iv.code(),
        CryptoOperationErrorCode::InvalidInputLength
    );

    let short_key = OPERATIONS
        .encrypt_cbc(IkeCbcAlgorithm::AesCbc256, &key[..16], &iv, &[0x00; 16])
        .expect_err("wrong-length key must fail closed");
    assert_eq!(short_key.code(), CryptoOperationErrorCode::InvalidKeyLength);
}

#[test]
fn software_aead_seal_matches_gcm_spec_known_answers_for_all_key_sizes() {
    // Test cases 4, 10, and 16 from McGrew & Viega, "The Galois/Counter Mode
    // of Operation (GCM)" (the AES-GCM specification submitted to NIST),
    // with the 12-octet IV split into the RFC 4106 salt (4) and the RFC 5282
    // explicit IV (8) exactly as IKEv2 forms the nonce.
    let plaintext = decode_hex(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    ));
    let associated_data = decode_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let iv = decode_hex("cafebabefacedbaddecaf888");
    let (salt, explicit_iv) = iv.split_at(4);
    let cases = [
        (
            IkeAeadAlgorithm::AesGcm16_128,
            "feffe9928665731c6d6a8f9467308308",
            concat!(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e",
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47"
            ),
        ),
        (
            IkeAeadAlgorithm::AesGcm16_192,
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            concat!(
                "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c",
                "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
                "2519498e80f1478f37ba55bd6d27618c"
            ),
        ),
        (
            IkeAeadAlgorithm::AesGcm16_256,
            concat!(
                "feffe9928665731c6d6a8f9467308308",
                "feffe9928665731c6d6a8f9467308308"
            ),
            concat!(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
                "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b"
            ),
        ),
    ];
    for (algorithm, key_hex, ciphertext_and_tag_hex) in cases {
        let key = decode_hex(key_hex);
        let sealed = OPERATIONS
            .seal_aead(
                algorithm,
                &key,
                salt,
                explicit_iv,
                &associated_data,
                &plaintext,
            )
            .expect("GCM spec vector seals");
        let mut expected = explicit_iv.to_vec();
        expected.extend_from_slice(&decode_hex(ciphertext_and_tag_hex));
        assert_eq!(sealed, expected, "{algorithm}");

        let opened = OPERATIONS
            .open_aead(algorithm, &key, salt, &associated_data, &sealed)
            .expect("GCM spec vector opens");
        assert_eq!(&*opened, plaintext.as_slice(), "{algorithm}");
    }
}

fn aead_profile(encryption: Ikev2EncryptionAlgorithm) -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        encryption,
    )
    .expect("valid AEAD parity profile")
}

fn established_material(profile: Ikev2SaInitCryptoProfile) -> Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    let prf_len = profile.prf().output_len();
    let integrity_len = profile.integrity_key_len();
    let encryption_len = profile.encryption().key_material_len();
    Ikev2SaInitKeyMaterial::from_established_keys(
        profile,
        false,
        &sequence(0xc0, prf_len),
        &sequence(0x00, integrity_len),
        &sequence(0x80, integrity_len),
        &sequence(0x40, encryption_len),
        &sequence(0xa0, encryption_len),
        &sequence(0x20, prf_len),
        &sequence(0x60, prf_len),
    )
    .expect("valid established parity key material")
}

/// Final outer message prefix (IKE header plus `SK` generic payload header)
/// with correct length fields, matching the shape used by the existing
/// protected-payload tests.
fn sk_message_prefix(crypto_body_len: usize) -> Vec<u8> {
    let payload_len = u16::try_from(4 + crypto_body_len).expect("payload length fits u16");
    let message_len = u32::try_from(28 + usize::from(payload_len)).expect("length fits u32");
    let mut prefix = Vec::with_capacity(32);
    prefix.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    prefix.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    prefix.push(46); // next payload: Encrypted (SK)
    prefix.push(0x20); // version 2.0
    prefix.push(35); // exchange type: IKE_AUTH
    prefix.push(0x08); // flags: initiator
    prefix.extend_from_slice(&1_u32.to_be_bytes()); // message ID
    prefix.extend_from_slice(&message_len.to_be_bytes());
    prefix.push(35); // first inner payload
    prefix.push(0);
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    prefix
}

#[test]
fn software_aead_seal_is_byte_identical_to_the_existing_protected_payload_seal_path() {
    let inner_payload = [0, 0, 0, 8, 1, 2, 3, 4];
    let padding_len = 3_u8;
    let explicit_iv = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7];
    let cases = [
        (
            Ikev2EncryptionAlgorithm::AesGcm16_128,
            IkeAeadAlgorithm::AesGcm16_128,
        ),
        (
            Ikev2EncryptionAlgorithm::AesGcm16_192,
            IkeAeadAlgorithm::AesGcm16_192,
        ),
        (
            Ikev2EncryptionAlgorithm::AesGcm16_256,
            IkeAeadAlgorithm::AesGcm16_256,
        ),
    ];
    for (encryption, algorithm) in cases {
        let profile = aead_profile(encryption);
        let material = established_material(profile);
        let crypto_body_len = 8 + inner_payload.len() + usize::from(padding_len) + 1 + 16;
        let prefix = sk_message_prefix(crypto_body_len);
        let existing = seal_ikev2_sa_init_protected_payload(
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &prefix,
            },
            &inner_payload,
            padding_len,
            explicit_iv,
        )
        .expect("existing AEAD seal path succeeds");

        let mut plaintext = inner_payload.to_vec();
        plaintext.extend_from_slice(&[0, 0, 0]);
        plaintext.push(padding_len);
        let (key, salt) = material
            .sk_ei()
            .split_at(profile.encryption().encryption_key_len());
        let sealed = OPERATIONS
            .seal_aead(algorithm, key, salt, &explicit_iv, &prefix, &plaintext)
            .expect("software AEAD seal succeeds");
        assert_eq!(sealed.as_slice(), existing.as_ref(), "{algorithm}");

        let opened = OPERATIONS
            .open_aead(algorithm, key, salt, &prefix, &sealed)
            .expect("software AEAD open succeeds");
        assert_eq!(&*opened, plaintext.as_slice(), "{algorithm}");
    }
}

#[test]
fn software_aead_open_rejects_tampering_and_bad_lengths_with_stable_codes() {
    let algorithm = IkeAeadAlgorithm::AesGcm16_128;
    let key = [0x11; 16];
    let salt = [0x22; 4];
    let explicit_iv = [0x33; 8];
    let sealed = OPERATIONS
        .seal_aead(algorithm, &key, &salt, &explicit_iv, b"aad", b"plaintext")
        .expect("seal succeeds");

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let error = OPERATIONS
        .open_aead(algorithm, &key, &salt, b"aad", &tampered)
        .expect_err("tampered tag must fail closed");
    assert_eq!(error.code(), CryptoOperationErrorCode::AuthenticationFailed);
    assert_eq!(error.as_str(), "crypto_op_authentication_failed");

    let wrong_aad = OPERATIONS
        .open_aead(algorithm, &key, &salt, b"other-aad", &sealed)
        .expect_err("wrong AAD must fail closed");
    assert_eq!(
        wrong_aad.code(),
        CryptoOperationErrorCode::AuthenticationFailed
    );

    let short_body = OPERATIONS
        .open_aead(algorithm, &key, &salt, b"aad", &sealed[..12])
        .expect_err("short body must fail closed");
    assert_eq!(
        short_body.code(),
        CryptoOperationErrorCode::InvalidInputLength
    );

    let bad_salt = OPERATIONS
        .open_aead(algorithm, &key, &salt[..2], b"aad", &sealed)
        .expect_err("wrong salt length must fail closed");
    assert_eq!(
        bad_salt.code(),
        CryptoOperationErrorCode::InvalidInputLength
    );

    let bad_iv = OPERATIONS
        .seal_aead(algorithm, &key, &salt, &explicit_iv[..4], b"aad", b"plain")
        .expect_err("wrong explicit IV length must fail closed");
    assert_eq!(bad_iv.code(), CryptoOperationErrorCode::InvalidInputLength);

    let bad_key = OPERATIONS
        .seal_aead(algorithm, &key[..8], &salt, &explicit_iv, b"aad", b"plain")
        .expect_err("wrong key length must fail closed");
    assert_eq!(bad_key.code(), CryptoOperationErrorCode::InvalidKeyLength);
}

#[test]
fn software_dh_round_trips_through_opaque_handles_and_matches_the_existing_path_for_all_groups() {
    support::ensure_ike_crypto();
    let cases = [
        (IkeDhGroup::Modp2048, Ikev2DhGroup::Modp2048),
        (IkeDhGroup::Ecp256, Ikev2DhGroup::Ecp256),
        (IkeDhGroup::Ecp384, Ikev2DhGroup::Ecp384),
        (IkeDhGroup::Ecp521, Ikev2DhGroup::Ecp521),
    ];
    for (group, existing_group) in cases {
        let handle = OPERATIONS
            .generate_keypair(group)
            .expect("software keypair generates");
        assert_eq!(handle.group(), group);
        assert_eq!(handle.public_value().len(), group.public_value_len());

        // The peer side runs the pre-existing code path, so agreement
        // succeeding with equal secrets proves wire-format parity.
        let peer =
            Ikev2EphemeralDhKey::generate(existing_group).expect("existing-path keypair generates");
        let handle_shared = handle
            .agree(peer.public_value())
            .expect("software side agrees");
        let peer_shared = peer
            .agree(handle.public_value())
            .expect("existing side agrees");
        assert_eq!(&*handle_shared, &*peer_shared, "{group}");
        assert_eq!(handle_shared.len(), group.shared_secret_len(), "{group}");
    }
}

#[test]
fn software_dh_rejects_malformed_peer_values_and_keeps_handle_debug_redaction_safe() {
    let handle = OPERATIONS
        .generate_keypair(IkeDhGroup::Ecp256)
        .expect("software keypair generates");

    let short = vec![0_u8; IkeDhGroup::Ecp256.public_value_len() - 1];
    let error = handle
        .agree(&short)
        .expect_err("short peer value must fail closed");
    assert_eq!(error.code(), CryptoOperationErrorCode::InvalidPeerPublicKey);
    assert_eq!(error.as_str(), "crypto_op_invalid_peer_public_key");

    let zeros = vec![0_u8; IkeDhGroup::Ecp256.public_value_len()];
    let error = handle
        .agree(&zeros)
        .expect_err("all-zero peer value must fail closed");
    assert_eq!(error.code(), CryptoOperationErrorCode::InvalidPeerPublicKey);

    let debug = format!("{handle:?}");
    assert!(debug.contains("ecp_256"));
    assert!(debug.contains("public_value_len"));
    assert!(debug.len() < 128);
    assert!(!debug.contains(&encode_hex(&handle.public_value()[..8])));
}

fn signature_profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid signature parity profile")
}

fn signature_key_material() -> Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        signature_profile(),
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .expect("signature parity key material")
}

const SA_INIT_RESPONSE: &[u8] = &[0x5a; 96];
const PEER_NONCE: &[u8] = &[0x66; 32];

fn identity_payload_body() -> Vec<u8> {
    build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"epdg.test.openpacketcore".to_vec(),
    })
    .expect("IDr body")
}

/// Reconstruct the RFC 7296 responder signed octets
/// (`RealMessage2 | NonceIData | MACedIDForR`) through the trait PRF, which
/// also cross-checks the PRF against the IKE_AUTH transcript path.
fn responder_signed_octets(material: &Ikev2SaInitKeyMaterial, identity: &[u8]) -> Vec<u8> {
    let macked_id = OPERATIONS
        .prf(IkePrfAlgorithm::HmacSha2_256, material.sk_pr(), identity)
        .expect("MACedIDForR computes");
    let mut signed =
        Vec::with_capacity(SA_INIT_RESPONSE.len() + PEER_NONCE.len() + macked_id.len());
    signed.extend_from_slice(SA_INIT_RESPONSE);
    signed.extend_from_slice(PEER_NONCE);
    signed.extend_from_slice(&macked_id);
    signed
}

#[test]
fn software_ecdsa_signatures_are_byte_identical_to_the_existing_ike_auth_signature_path() {
    let identity = identity_payload_body();
    let material = signature_key_material();
    let octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: SA_INIT_RESPONSE,
        peer_nonce: PEER_NONCE,
        identity_payload_body: &identity,
    };
    let signed = responder_signed_octets(&material, &identity);

    struct EcdsaParityCase {
        algorithm: IkeSignatureAlgorithm,
        pkcs8_der: &'static [u8],
        spki_der: &'static [u8],
        algorithm_identifier: &'static [u8],
    }
    let cases = [
        EcdsaParityCase {
            algorithm: IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            pkcs8_der: P256_PKCS8_DER,
            spki_der: P256_SPKI_DER,
            algorithm_identifier: &RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256,
        },
        EcdsaParityCase {
            algorithm: IkeSignatureAlgorithm::EcdsaP384Sha2_384,
            pkcs8_der: P384_PKCS8_DER,
            spki_der: P384_SPKI_DER,
            algorithm_identifier: &RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384,
        },
    ];
    for EcdsaParityCase {
        algorithm,
        pkcs8_der,
        spki_der,
        algorithm_identifier,
    } in cases
    {
        // Existing path: RFC 7427 framed AUTH data over the same transcript.
        let existing_key = match algorithm {
            IkeSignatureAlgorithm::EcdsaP256Sha2_256 => {
                Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(pkcs8_der).expect("P-256 key")
            }
            _ => Ikev2SignatureAuthKey::ecdsa_p384_pkcs8_der(pkcs8_der).expect("P-384 key"),
        };
        let auth_data =
            compute_ike_auth_signature(signature_profile(), &material, octets, &existing_key)
                .expect("existing signature path signs");
        assert_eq!(usize::from(auth_data[0]), algorithm_identifier.len());
        let existing_signature = &auth_data[1 + algorithm_identifier.len()..];

        // Software path: RFC 6979 deterministic ECDSA makes the raw
        // signatures byte-comparable.
        let signing_key = OPERATIONS
            .load_signing_key(algorithm, pkcs8_der)
            .expect("software signing key loads");
        assert_eq!(signing_key.algorithm(), algorithm);
        assert_eq!(signing_key.rsa_modulus_len(), None);
        let signature = signing_key.sign(&signed).expect("software path signs");
        assert_eq!(signature.as_slice(), existing_signature, "{algorithm}");

        OPERATIONS
            .verify_signature(algorithm, spki_der, &signed, &signature)
            .expect("software path verifies its signature");

        // The framed software signature is accepted by the existing
        // verifier over the same transcript.
        let mut framed = vec![u8::try_from(algorithm_identifier.len()).expect("length fits u8")];
        framed.extend_from_slice(algorithm_identifier);
        framed.extend_from_slice(&signature);
        assert_eq!(framed, auth_data);
        verify_ike_auth_signature(
            signature_profile(),
            &material,
            octets,
            &opc_proto_ikev2::Ikev2SignaturePublicKey::from_spki_der(spki_der)
                .expect("SPKI parses"),
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &framed,
            },
        )
        .expect("existing verifier accepts the software signature");
    }
}

#[test]
fn software_signature_verification_fails_closed_with_stable_codes() {
    let material = signature_key_material();
    let identity = identity_payload_body();
    let signed = responder_signed_octets(&material, &identity);
    let signing_key = OPERATIONS
        .load_signing_key(IkeSignatureAlgorithm::EcdsaP256Sha2_256, P256_PKCS8_DER)
        .expect("software signing key loads");
    let signature = signing_key.sign(&signed).expect("software path signs");

    let mut tampered = signed.clone();
    tampered[0] ^= 0x01;
    let error = OPERATIONS
        .verify_signature(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            P256_SPKI_DER,
            &tampered,
            &signature,
        )
        .expect_err("tampered transcript must fail");
    assert_eq!(
        error.code(),
        CryptoOperationErrorCode::SignatureVerificationFailed
    );
    assert_eq!(error.as_str(), "crypto_op_signature_verification_failed");

    let garbage = OPERATIONS
        .verify_signature(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            P256_SPKI_DER,
            &signed,
            &[0x00; 8],
        )
        .expect_err("garbage signature DER must fail");
    assert_eq!(
        garbage.code(),
        CryptoOperationErrorCode::SignatureEncodingInvalid
    );

    let mismatch = OPERATIONS
        .verify_signature(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            P384_SPKI_DER,
            &signed,
            &signature,
        )
        .expect_err("wrong key type must fail closed");
    assert_eq!(
        mismatch.code(),
        CryptoOperationErrorCode::SignatureKeyMismatch
    );

    let bad_spki = OPERATIONS
        .verify_signature(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            &[0x00; 16],
            &signed,
            &signature,
        )
        .expect_err("garbage SPKI must fail closed");
    assert_eq!(
        bad_spki.code(),
        CryptoOperationErrorCode::InvalidVerificationKey
    );

    let bad_key = OPERATIONS
        .load_signing_key(IkeSignatureAlgorithm::EcdsaP256Sha2_256, &[0x00; 16])
        .expect_err("garbage PKCS#8 must fail closed");
    assert_eq!(bad_key.code(), CryptoOperationErrorCode::InvalidSigningKey);
}

#[cfg(not(feature = "rsa-signing"))]
#[test]
fn software_rsa_signing_is_unavailable_without_the_rsa_signing_feature() {
    let error = OPERATIONS
        .load_signing_key(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256, &[0x00; 16])
        .expect_err("RSA signing must fail closed without the feature");
    assert_eq!(error.code(), CryptoOperationErrorCode::UnsupportedAlgorithm);
    assert_eq!(error.as_str(), "crypto_op_unsupported_algorithm");
}

#[cfg(feature = "rsa-signing")]
mod rsa_signing {
    use super::*;
    use opc_proto_ikev2::Ikev2SignatureAuthMethod;

    const RSA_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");
    const RSA_SPKI_DER: &[u8] = include_bytes!("data/rsa2048_spki.der");

    #[test]
    fn software_rsa_signatures_are_byte_identical_to_the_existing_method_one_path() {
        let identity = identity_payload_body();
        let material = signature_key_material();
        let octets = Ikev2IkeAuthSignedOctets {
            peer: Ikev2IkeAuthPeer::Responder,
            ike_sa_init_message: SA_INIT_RESPONSE,
            peer_nonce: PEER_NONCE,
            identity_payload_body: &identity,
        };
        // Method 1 AUTH data is the raw RSASSA-PKCS1-v1_5 SHA-256 signature.
        let existing_key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
            Ikev2SignatureAuthMethod::RsaDigitalSignature,
            RSA_PKCS8_DER,
        )
        .expect("RSA key");
        let auth_data =
            compute_ike_auth_signature(signature_profile(), &material, octets, &existing_key)
                .expect("existing RSA path signs");
        assert_eq!(auth_data.len(), 256);

        let signed = responder_signed_octets(&material, &identity);
        let signing_key = OPERATIONS
            .load_signing_key(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256, RSA_PKCS8_DER)
            .expect("software RSA key loads");
        assert_eq!(signing_key.rsa_modulus_len(), Some(256));
        let signature = signing_key.sign(&signed).expect("software RSA path signs");
        assert_eq!(signature, auth_data);

        OPERATIONS
            .verify_signature(
                IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
                RSA_SPKI_DER,
                &signed,
                &signature,
            )
            .expect("software RSA verification succeeds");

        let mismatch = OPERATIONS
            .verify_signature(
                IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
                P256_SPKI_DER,
                &signed,
                &signature,
            )
            .expect_err("EC key against RSA algorithm must fail closed");
        assert_eq!(
            mismatch.code(),
            CryptoOperationErrorCode::SignatureKeyMismatch
        );
    }
}

#[test]
fn software_error_and_handle_rendering_is_redaction_safe() {
    let secret_key = [0xab; 5];
    let error = OPERATIONS
        .compute_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha2_256_128,
            &secret_key,
            b"prefix-secret-material",
            b"suffix-secret-material",
        )
        .expect_err("wrong-length key must fail");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error.to_string(), "crypto_op_invalid_key_length");
    assert!(!rendered.contains("abab"));
    assert!(!rendered.contains("171"));
    assert!(!rendered.contains("secret-material"));

    let signing_key = OPERATIONS
        .load_signing_key(IkeSignatureAlgorithm::EcdsaP256Sha2_256, P256_PKCS8_DER)
        .expect("software signing key loads");
    let debug = format!("{signing_key:?}");
    assert!(debug.contains("ecdsa_p256_sha2_256"));
    assert!(debug.len() < 128);
    assert!(!debug.contains(&encode_hex(&P256_PKCS8_DER[..8])));
}

#[test]
fn all_operation_traits_are_usable_behind_dyn_references() {
    let operations = Ikev2SoftwareCryptoOperations::new();
    let prf_operations: &dyn IkePrfOperations = &operations;
    let integrity_operations: &dyn IkeIntegrityOperations = &operations;
    let encryption_operations: &dyn IkeEncryptionOperations = &operations;
    let dh_operations: &dyn IkeDiffieHellmanOperations = &operations;
    let signature_operations: &dyn IkeSignatureOperations = &operations;

    let prf_output = prf_operations
        .prf(IkePrfAlgorithm::HmacSha2_256, &[0x0b; 20], b"Hi There")
        .expect("dyn PRF works");
    assert_eq!(prf_output.len(), 32);

    let icv = integrity_operations
        .compute_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha2_256_128,
            &[0x0b; 32],
            b"Hi There",
            b"",
        )
        .expect("dyn integrity works");
    assert_eq!(icv.len(), 16);

    let sealed = encryption_operations
        .seal_aead(
            IkeAeadAlgorithm::AesGcm16_128,
            &[0x11; 16],
            &[0x22; 4],
            &[0x33; 8],
            b"aad",
            b"plaintext",
        )
        .expect("dyn AEAD works");
    let opened = encryption_operations
        .open_aead(
            IkeAeadAlgorithm::AesGcm16_128,
            &[0x11; 16],
            &[0x22; 4],
            b"aad",
            &sealed,
        )
        .expect("dyn AEAD opens");
    assert_eq!(&*opened, b"plaintext");

    let keypair: Box<dyn IkeDhKeyPair> = dh_operations
        .generate_keypair(IkeDhGroup::Ecp256)
        .expect("dyn DH works");
    assert_eq!(keypair.group(), IkeDhGroup::Ecp256);

    let error = signature_operations
        .load_signing_key(IkeSignatureAlgorithm::EcdsaP256Sha2_256, &[0x00; 4])
        .expect_err("dyn signature ops work");
    assert_eq!(error.code(), CryptoOperationErrorCode::InvalidSigningKey);
}
