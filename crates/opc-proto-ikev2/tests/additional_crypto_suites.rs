//! RFC 4434 section 2, RFC 5282 sections 3–5 and RFC 7634 section 4.
//! Expected octets were independently calculated with Python cryptography 49.0.0:
//! AES-ECB implements RFC 4434 XCBC/PRF+, AESCCM and ChaCha20Poly1305 protect
//! the synthetic IKE packet. SKEYSEED uses the first eight octets of each nonce.
use opc_crypto_provider::{IkePrfAlgorithm, IkePrfOperations};
use opc_proto_ikev2::*;
use opc_protocol::{BorrowDecode, DecodeContext};
mod support;
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn xcbc_and_additional_aead_suites_match_independent_ike_packets() {
    support::ensure_ike_crypto();
    let cases = [
        (28, None, 36, "80578ae4ed2bb176460e4f209a8c98c7497fda1a21747d481cee092e3b67cbdaecf77692136ccb5fca618782d776e60b3a5349f239ed92ae346ae7bc0c29db2630e2a22c9dd0a5e0fcdca11fa5570056caf43b3a5ba96365012196ff1f83a6d65a49dfb273526d9c21e295a35902d5e5e5365966825200c7", "111111111111111122222222222222222e202508000000070000004129000025000000000000000744e2cf8466a38169e0d385334f8175fb32ee60fe983b5c96f3"),
        (14, Some(128), 19, "80578ae4ed2bb176460e4f209a8c98c7497fda1a21747d481cee092e3b67cbdaecf77692136ccb5fca618782d776e60b3a5349f239ed92ae346ae7bc0c29db2630e2a22c9dd0a5e0fcdca11fa5570056caf43b3a5ba9", "111111111111111122222222222222222e20250800000007000000392900001d0000000000000007f7504c208a24103061c3953e35d1a128bd"),
        (14, Some(192), 27, "80578ae4ed2bb176460e4f209a8c98c7497fda1a21747d481cee092e3b67cbdaecf77692136ccb5fca618782d776e60b3a5349f239ed92ae346ae7bc0c29db2630e2a22c9dd0a5e0fcdca11fa5570056caf43b3a5ba96365012196ff1f83a6d65a49dfb27352", "111111111111111122222222222222222e20250800000007000000392900001d0000000000000007cdd201dea64683050bd25773ee7a969161"),
        (14, Some(256), 35, "80578ae4ed2bb176460e4f209a8c98c7497fda1a21747d481cee092e3b67cbdaecf77692136ccb5fca618782d776e60b3a5349f239ed92ae346ae7bc0c29db2630e2a22c9dd0a5e0fcdca11fa5570056caf43b3a5ba96365012196ff1f83a6d65a49dfb273526d9c21e295a35902d5e5e53659668252", "111111111111111122222222222222222e20250800000007000000392900001d0000000000000007e9b0a5d6658f09e65bf82928688a8ab72a"),
    ];
    for (transform, bits, directional, stream, packet) in cases {
        let profile = Ikev2SaInitCryptoProfile::from_transform_ids(4, 19, transform, bits, None)
            .expect("standard AEAD suite");
        assert!(profile.encryption().is_aead());
        assert_eq!(profile.encryption().key_length_attribute_bits(), bits);
        let keys = derive_ike_sa_init_key_material(
            Ikev2NonceLocalRole::Initiator,
            profile,
            [0x11; 8],
            [0x22; 8],
            &[0x33; 32],
            &[0x44; 32],
            &[0x55; 32],
            None,
        )
        .unwrap();
        assert_eq!(keys.skeyseed(), hex("c05cd52f3c70e22b1ad97281d05fb308"));
        assert!(keys.sk_ai().is_empty());
        assert!(keys.sk_ar().is_empty());
        assert_eq!(keys.sk_ei().len(), directional);
        assert_eq!(keys.sk_er().len(), directional);
        let actual = [
            keys.sk_d(),
            keys.sk_ei(),
            keys.sk_er(),
            keys.sk_pi(),
            keys.sk_pr(),
        ]
        .concat();
        assert_eq!(actual, hex(stream));
        let expected = hex(packet);
        assert_eq!(
            ikev2_aead_protected_body_len(profile.encryption(), 8, 0),
            Some(expected.len() - 32)
        );
        assert_eq!(
            ikev2_aead_protected_payload_len(profile.encryption(), 8, 0),
            Some(expected.len() - 28)
        );
        let sealed = seal_ikev2_sa_init_protected_payload(
            profile,
            &keys,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &expected[..32],
            },
            &hex("0000000800004000"),
            0,
            7u64.to_be_bytes(),
        )
        .unwrap();
        assert_eq!(sealed.as_ref(), &expected[32..]);
        let (_, message) = Message::decode(&expected, DecodeContext::default()).unwrap();
        let provider = Ikev2SaInitProtectedPayloadProvider::new(
            profile,
            &keys,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        );
        let opened =
            open_protected_payloads(&message, &expected, DecodeContext::default(), &provider)
                .unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].cleartext.as_ref(), hex("0000000800004000"));
        let mut altered_header = expected.clone();
        altered_header[23] ^= 1;
        let (_, altered) = Message::decode(&altered_header, DecodeContext::default()).unwrap();
        assert!(open_protected_payloads(
            &altered,
            &altered_header,
            DecodeContext::default(),
            &provider
        )
        .is_err());
        let mut tampered = expected.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let (_, message) = Message::decode(&tampered, DecodeContext::default()).unwrap();
        assert!(
            open_protected_payloads(&message, &tampered, DecodeContext::default(), &provider)
                .is_err()
        );
        assert!(
            Ikev2SaInitCryptoProfile::from_transform_ids(4, 19, transform, bits, Some(12)).is_err()
        );
    }
    assert!(Ikev2EncryptionAlgorithm::from_transform_id(28, Some(256)).is_err());
    assert!(Ikev2EncryptionAlgorithm::from_transform_id(14, None).is_err());
    assert!(Ikev2EncryptionAlgorithm::from_transform_id(14, Some(64)).is_err());
}

/// RFC 4434 section 2.1 and RFC 3566 section 4.6 publish full 128-bit outputs.
#[test]
fn xcbc_key_normalization_and_block_boundaries_match_rfc_vectors() {
    let provider = Ikev2SoftwareCryptoOperations::new();
    let message = hex("000102030405060708090a0b0c0d0e0f10111213");
    for (key, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "47f51b4564966215b8985c63055ed308",
        ),
        ("00010203040506070809", "0fa087af7d866e7653434e602fdde835"),
        (
            "000102030405060708090a0b0c0d0e0fedcb",
            "8cd3c93ae598a9803006ffb67c40e9e4",
        ),
    ] {
        let output = provider
            .prf(IkePrfAlgorithm::Aes128Xcbc, &hex(key), &message)
            .unwrap();
        assert_eq!(*output, hex(expected));
    }
    let key = hex("000102030405060708090a0b0c0d0e0f");
    for (len, expected) in [
        (0, "75f0251d528ac01c4573dfd584d79f29"),
        (3, "5b376580ae2f19afe7219ceef172756f"),
        (16, "d2a246fa349b68a79998a4394ff7a263"),
        (32, "f54f0ec8d2b9f3d36807734bd5283fd4"),
        (34, "becbb3bccdb518a30677d5481fb6b4d8"),
    ] {
        let message: Vec<u8> = (0..len).collect();
        let output = provider
            .prf(IkePrfAlgorithm::Aes128Xcbc, &key, &message)
            .unwrap();
        assert_eq!(*output, hex(expected));
    }
    let output = provider
        .prf(IkePrfAlgorithm::Aes128Xcbc, &key, &[0; 1000])
        .unwrap();
    assert_eq!(*output, hex("f0dafee895db30253761103b5d84528f"));
    assert_eq!(
        ikev2_aead_protected_body_len(Ikev2EncryptionAlgorithm::AesCbc128, 0, 0),
        None
    );
    assert_eq!(
        ikev2_aead_protected_body_len(Ikev2EncryptionAlgorithm::AesCcm8_128, usize::MAX, 0),
        None
    );
}
