//! Independent OpenSSL-backed AUTH fixtures from Python cryptography 49.0.0.
//! RFC 4754 section 7 uses fixed-width r||s; RFC 7427 section 3 uses DER;
//! RFC 8420 section 2 signs the full transcript with pure EdDSA.
//! P-521 scalar 7 and EdDSA repeated-byte seeds are synthetic test keys.
use opc_proto_ikev2::*;
mod support;
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::from_transform_ids(5, 19, 20, Some(128), None).unwrap()
}
fn keys() -> Ikev2SaInitKeyMaterial {
    Ikev2SaInitKeyMaterial::from_established_keys(
        profile(),
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x22; 20],
        &[0x33; 20],
        &[0x44; 32],
        &[0x55; 32],
    )
    .unwrap()
}
fn auth(method: u8, signature: &[u8]) -> Ikev2AuthenticationPayload<'_> {
    Ikev2AuthenticationPayload {
        auth_method: method,
        auth_data: signature,
    }
}
fn check_signature(
    method: u8,
    hash: Option<Ikev2SignatureHashAlgorithm>,
    public: &str,
    signature: &str,
) {
    support::ensure_ike_crypto();
    let authority = hash.map(support::responder_signature_hash_context);
    let (_, legacy_response) = support::signature_hash_exchange(None, None);
    let response = authority.as_ref().map_or(legacy_response.as_slice(), |a| {
        a.sa_init_response.as_slice()
    });
    let public =
        Ikev2SignaturePublicKey::from_spki_der(&hex(public)).expect("standard signature key");
    let signature = hex(signature);
    let identity = b"\x02\0\0\0peer.example";
    let octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: response,
        peer_nonce: support::TEST_INITIATOR_NONCE,
        identity_payload_body: identity,
    };
    let authorization = || authority.as_ref().map(|a| a.verification_authorization());
    verify_ike_auth_signature(
        profile(),
        &keys(),
        octets,
        &public,
        &auth(method, &signature),
        authorization(),
    )
    .expect("independent peer AUTH verifies");
    if method == 14 && signature[0] == 67 {
        // RFC 7427 Appendix A.4.3 includes the explicit default trailerField.
        let mut explicit_trailer = signature.clone();
        explicit_trailer[0] += 5;
        explicit_trailer[2] += 5;
        explicit_trailer[15] += 5;
        explicit_trailer.splice(68..68, [0xa3, 3, 2, 1, 1]);
        verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &auth(method, &explicit_trailer),
            authorization(),
        )
        .expect("RFC 7427 explicit trailer");
        // RFC 4055 also permits both SHA-2 AlgorithmIdentifier NULLs absent.
        let oid = signature[30];
        let salt = signature[67];
        let mut absent = hex(&format!("3f303d06092a864886f70d01010a3030a00d300b06096086480165030402{oid:02x}a11a301806092a864886f70d010108300b06096086480165030402{oid:02x}a2030201{salt:02x}"));
        absent.extend_from_slice(&signature[68..]);
        verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &auth(method, &absent),
            authorization(),
        )
        .expect("absent SHA-2 NULL parameters");
        for index in [60, 67] {
            let mut wrong = signature.clone();
            wrong[index] ^= 1;
            assert_eq!(
                verify_ike_auth_signature(
                    profile(),
                    &keys(),
                    octets,
                    &public,
                    &auth(method, &wrong),
                    authorization()
                ),
                Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported)
            );
        }
        // A duplicate salt-length field must not be skipped by the ASN.1 reader.
        let mut duplicate = signature.clone();
        duplicate[0] += 5;
        duplicate[2] += 5;
        duplicate[15] += 5;
        duplicate.splice(68..68, [0xa2, 3, 2, 1, salt]);
        assert!(verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &auth(method, &duplicate),
            authorization()
        )
        .is_err());
        let end = explicit_trailer[0] as usize;
        explicit_trailer[end] = 2;
        assert!(verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &auth(method, &explicit_trailer),
            authorization()
        )
        .is_err());
    }
    let mut changed = signature.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify_ike_auth_signature(
        profile(),
        &keys(),
        octets,
        &public,
        &auth(method, &changed),
        authorization()
    )
    .is_err());
    assert!(verify_ike_auth_signature(
        profile(),
        &keys(),
        octets,
        &public,
        &auth(method, &signature[..signature.len() - 1]),
        authorization()
    )
    .is_err());
    let altered = Ikev2IkeAuthSignedOctets {
        identity_payload_body: b"\x02\0\0\0other.example",
        ..octets
    };
    assert!(verify_ike_auth_signature(
        profile(),
        &keys(),
        altered,
        &public,
        &auth(method, &signature),
        authorization()
    )
    .is_err());
    if method == 14 {
        assert!(verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &auth(method, &signature),
            None
        )
        .is_err());
    }
}

#[test]
fn independent_ecdsa_method_9() {
    check_signature(9,None,"3059301306072a8648ce3d020106082a8648ce3d030107034200041622155fae5501d5fa76a360d84e64a573336f55b82b83ba3391cb67f5a551fce45491f77023082ac7361f6f953c33b962c8f20b99877f6c1e2e456556a01af0","b291b322da8c7ec390ff1b1482a7bf6fe3a4dbd49870bfd988240391f04aaa2799c9ccd2dbc211b303e9f985ecfc849b83fe21daa061488b1074df0d55825bfa");
}

#[test]
fn independent_ecdsa_method_10() {
    check_signature(10,None,"3076301006072a8648ce3d020106052b81040022036200045bb0d9ea295e7bc8cc3cd6dcc3d03487a6b16921b2b4fcceb64808c8a773d79d2ce18b25f685ba73c3e962b8bbf4c1517d8bffff5227bdefea557f9b2d16814128e7d5d39d9a4c23171ff86ed40ea988c2e962510e14b37df22a365fcb3e86c5","207be894adbad7b45d4bf224f5a63a3b9faee4793334380407bba1355a86ffdf2a6fc7c3aefbfb27c622a852a5eb3b84b7ce8c54436874f9896b85f36fdbde49a35c97136d9a6bc41a1a56969c9c818983ba706e8f0de7e860e89116ce0e8f96");
}

#[test]
fn independent_ecdsa_method_11() {
    check_signature(11,None,"30819b301006072a8648ce3d020106052b8104002303818600040056d5d1d99d5b7f6346eeb65fda0b073a0c5f22e0e8f5483228f018d2c2f7114c5d8c308d0abfc698d8c9a6df30dce3bbc46f953f50fdc2619a01cead882816ecd4003d2d1b7d9baaa2a110d1d8317a39d68478b5c582d02824f0dd71dbd98a26cbde556bd0f293cdec9e2b9523a34591ce1a5f9e76712a5ddefc7b5c6b8bc90525251b","00c9a16f8b2c58fb3a9c64c64ef007999a6be2ecd6d57100928c311f59441139fcdb1f064c2774167c31dc3bb14083f86b3248e2d028bd989ba3e9c93938c87424e60007e55e7019f4effbf58fd34833fb59a9b31b4133547315ad6e0fdcdae67cf4dbc65bccbbf55b4616a89199bedaa8d2f302331e2b370653ccb804c14cc1714414a9");
}

#[test]
fn independent_rsa_pss_sha256() {
    check_signature(14,Some(Ikev2SignatureHashAlgorithm::Sha2_256),"30820122300d06092a864886f70d01010105000382010f003082010a02820101009f9ef8b76c46b5c52dfb1f8448828a72ed6c95f5ebafc1ba5ce2acb573296507e04006fb4ea5e9d85ed668588550451bc4b01a68725d2554fe94d21b3daab6ee1d82fef897e986441145d7e046c3cc6a513959d55f3fff5ffad4f9c0d04a7f7d4c547802aaaf9e454697eeb1a5a1935385bd296584c24aaa70fe22afc4e3c987a128b902618f62a04032f316a2380db5be2fc1bb4c0b56835084342f8041f3c5f131ec88ae5d75cdfcd8d803292222336e8596a3b98a5e10c277a6a455fab9847fbbca198edf44fb6c2b47392f90e5e45e6813a0c9260bc31154a94166572a6f7c33369e7265e6c54fda76cdcf9d0afd77e8359234a34bf48e04acae44e4adf10203010001","43304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120816c5d8ab2281f62c401499a75ba2a59f2a8e9ef3c02a4d21e582cbcfeefe1a21cea6f5ddebe7e122d547d21f6f018ed4317cd88e375f22865cf6b0cf5454243dfb8ade5fc309d3fb5c6efa94584f88a3cf1f891b21b7df48763711e75be5085f90bfcde157f5ab3852ecc70d72a96fd457c2d512cee2b920a73911f14c29b120efc3641d832b9466bb7b86dbd4374d082857fa35c44e8ec475ced33699aaada2968cc65fef93f10af9a405fbae81e650d030f3680db363c7c970e756b52b00161b760a51c9382efc62f40e1580f068f9a18f378ee546401fb0543b42c502a66c60753e16a2e495d378c985beb25983d58e138a0720f5db9d77fa3a6bd4baaf2");
}

#[test]
fn independent_rsa_pss_sha384() {
    check_signature(14,Some(Ikev2SignatureHashAlgorithm::Sha2_384),"30820122300d06092a864886f70d01010105000382010f003082010a02820101009f9ef8b76c46b5c52dfb1f8448828a72ed6c95f5ebafc1ba5ce2acb573296507e04006fb4ea5e9d85ed668588550451bc4b01a68725d2554fe94d21b3daab6ee1d82fef897e986441145d7e046c3cc6a513959d55f3fff5ffad4f9c0d04a7f7d4c547802aaaf9e454697eeb1a5a1935385bd296584c24aaa70fe22afc4e3c987a128b902618f62a04032f316a2380db5be2fc1bb4c0b56835084342f8041f3c5f131ec88ae5d75cdfcd8d803292222336e8596a3b98a5e10c277a6a455fab9847fbbca198edf44fb6c2b47392f90e5e45e6813a0c9260bc31154a94166572a6f7c33369e7265e6c54fda76cdcf9d0afd77e8359234a34bf48e04acae44e4adf10203010001","43304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a2030201308fccbebc13b9fbcc76b459d3602d13fbdeff013269a99164fa48757a2d464c3bc170edf9c3c4abcc0bbad53f42c16571a4143187905c7925c911ee438f7ea43377bb0844416b373903436ea0d86dff47b92b1502608ae14abce983ceff117ec0640c145984231d648d1899c69f7fb187f6406e3470872c2b206a299781bd89eab6e76d2e482b8472ddbecc75398a8c39ce4129ccc43c3fa15740fd6478d57682d22ff6f3677f48c1508977ea9f8cc4528b0017f140ca7d0c11ea589527c41375bf7fd6c832f00b53ed47975a83faefa0dc9b13628c1e04641a7931858ef1a57b364153ff3bc5b29b6b101c2cf702290fe44f03ade71ce6f3f3d21cd5515c64db");
}

#[test]
fn independent_rsa_pss_sha512() {
    check_signature(14,Some(Ikev2SignatureHashAlgorithm::Sha2_512),"30820122300d06092a864886f70d01010105000382010f003082010a02820101009f9ef8b76c46b5c52dfb1f8448828a72ed6c95f5ebafc1ba5ce2acb573296507e04006fb4ea5e9d85ed668588550451bc4b01a68725d2554fe94d21b3daab6ee1d82fef897e986441145d7e046c3cc6a513959d55f3fff5ffad4f9c0d04a7f7d4c547802aaaf9e454697eeb1a5a1935385bd296584c24aaa70fe22afc4e3c987a128b902618f62a04032f316a2380db5be2fc1bb4c0b56835084342f8041f3c5f131ec88ae5d75cdfcd8d803292222336e8596a3b98a5e10c277a6a455fab9847fbbca198edf44fb6c2b47392f90e5e45e6813a0c9260bc31154a94166572a6f7c33369e7265e6c54fda76cdcf9d0afd77e8359234a34bf48e04acae44e4adf10203010001","43304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a2030201403b1c8be0157381dd3b190547af1687bcd8e2fd1d012ef533686ce4774e61bfbd3df422ff703923ebea14947b6fdedf940b80f54d5514da743a54cdd8b7f023b5b77a1b5722a0dacb8084b8291e54fa35a8ae0462dd9396d60a0359027396a1870b7f9df4898a46ceaaf8db47c4a58d8aa6794291c6a0ec6c82bd2cffb842c67ab3ed984e1f36228089a0303b0b72de97ff13f4f7220764b9d5628ad906328959d41c7442c185d427d43c888eae376043c8e215f21feeacdad56d2dd443ef41ae03d156a087f669a67b29081735532bd61faef9410df2e56a73343ce82728b952989337d84838913503481c6ddd831546a714de1d6b63d3e0f8e6565c08642db1");
}

#[test]
fn independent_ed25519() {
    check_signature(14,Some(Ikev2SignatureHashAlgorithm::Identity),"302a300506032b6570032100db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d","07300506032b65703dc861ffd17b878335f5e0c39b0c1cbc4789a42557515c27411c39a6f75a582000d0c0be8331a2440c5a3c62ca40c3685796ed67293de9d188520a47e1fdc503");
}

#[test]
fn independent_ed448() {
    check_signature(14,Some(Ikev2SignatureHashAlgorithm::Identity),"3043300506032b6571033a002601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00","07300506032b6571b3bb115d5aad6d9f85402ce5a6fd8df38387e7d2ad6c53d9b8ddf37c00fb1a0a1248fda90bef25a2ae9fa42a716155b19a09311de861511d0087c729c68e4de4fd53a0bd6550f4b584b684de1a5e5f684e1e541b99c7fd6353a9016101acccdf8d677069539f182153bd730270c787210500");
}

fn signing_round_trip(
    key: Ikev2SignatureAuthKey,
    public: &[u8],
    hash: Option<Ikev2SignatureHashAlgorithm>,
    expected_len: Option<usize>,
) {
    let authority = hash.map(support::responder_signature_hash_context);
    let (_, legacy_response) = support::signature_hash_exchange(None, None);
    let response = authority.as_ref().map_or(legacy_response.as_slice(), |a| {
        a.sa_init_response.as_slice()
    });
    let octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: response,
        peer_nonce: support::TEST_INITIATOR_NONCE,
        identity_payload_body: b"\x02\0\0\0peer.example",
    };
    let signature = compute_ike_auth_signature(
        profile(),
        &keys(),
        octets,
        &key,
        authority.as_ref().map(|a| a.signing_authorization()),
    )
    .unwrap();
    if let Some(expected) = expected_len {
        assert_eq!(signature.len(), expected);
    }
    let auth = Ikev2AuthenticationPayload {
        auth_method: key.method().as_u8(),
        auth_data: &signature,
    };
    let public = Ikev2SignaturePublicKey::from_spki_der(public).unwrap();
    verify_ike_auth_signature(
        profile(),
        &keys(),
        octets,
        &public,
        &auth,
        authority.as_ref().map(|a| a.verification_authorization()),
    )
    .unwrap();
    if let Some(authority) = authority.as_ref() {
        let local = authority
            .signing
            .authorize_local_auth_self_verification_with_signing_key(
                &authority.sa_init_request,
                &authority.sa_init_response,
                octets,
                &key,
                &public,
            )
            .unwrap();
        verify_local_ike_auth_signature(profile(), &keys(), &auth, local).unwrap();
        assert!(compute_ike_auth_signature(profile(), &keys(), octets, &key, None).is_err());
    } else {
        // DER framing is not an RFC 4754 signature.
        let der = match key.method() {
            Ikev2SignatureAuthMethod::EcdsaSha2_256 => {
                p256::ecdsa::Signature::from_slice(&signature)
                    .unwrap()
                    .to_der()
                    .as_bytes()
                    .to_vec()
            }
            Ikev2SignatureAuthMethod::EcdsaSha2_384 => {
                p384::ecdsa::Signature::from_slice(&signature)
                    .unwrap()
                    .to_der()
                    .as_bytes()
                    .to_vec()
            }
            Ikev2SignatureAuthMethod::EcdsaSha2_512 => {
                p521::ecdsa::Signature::from_slice(&signature)
                    .unwrap()
                    .to_der()
                    .as_bytes()
                    .to_vec()
            }
            _ => panic!("expected RFC 4754 key"),
        };
        assert!(verify_ike_auth_signature(
            profile(),
            &keys(),
            octets,
            &public,
            &Ikev2AuthenticationPayload {
                auth_method: auth.auth_method,
                auth_data: &der
            },
            None
        )
        .is_err());
    }
}

#[test]
fn signing_covers_legacy_ecdsa_and_method14_p521_eddsa() {
    support::ensure_ike_crypto();
    for (method, private, public, len) in [
        (
            Ikev2SignatureAuthMethod::EcdsaSha2_256,
            include_bytes!("data/p256_pkcs8.der").as_slice(),
            include_bytes!("data/p256_spki.der").as_slice(),
            64,
        ),
        (
            Ikev2SignatureAuthMethod::EcdsaSha2_384,
            include_bytes!("data/p384_pkcs8.der").as_slice(),
            include_bytes!("data/p384_spki.der").as_slice(),
            96,
        ),
        (
            Ikev2SignatureAuthMethod::EcdsaSha2_512,
            include_bytes!("data/p521_pkcs8.der").as_slice(),
            include_bytes!("data/p521_spki.der").as_slice(),
            132,
        ),
    ] {
        let key = Ikev2SignatureAuthKey::ecdsa_rfc4754_pkcs8_der(method, private).unwrap();
        signing_round_trip(key, public, None, Some(len));
    }
    signing_round_trip(
        Ikev2SignatureAuthKey::ecdsa_p521_pkcs8_der(include_bytes!("data/p521_pkcs8.der")).unwrap(),
        include_bytes!("data/p521_spki.der"),
        Some(Ikev2SignatureHashAlgorithm::Sha2_512),
        None,
    );
    signing_round_trip(
        Ikev2SignatureAuthKey::ed25519_pkcs8_der(include_bytes!("data/ed25519_pkcs8.der")).unwrap(),
        include_bytes!("data/ed25519_spki.der"),
        Some(Ikev2SignatureHashAlgorithm::Identity),
        Some(72),
    );
    signing_round_trip(
        Ikev2SignatureAuthKey::ed448_pkcs8_der(include_bytes!("data/ed448_pkcs8.der")).unwrap(),
        include_bytes!("data/ed448_spki.der"),
        Some(Ikev2SignatureHashAlgorithm::Identity),
        Some(122),
    );
    assert!(Ikev2SignatureAuthKey::ecdsa_rfc4754_pkcs8_der(
        Ikev2SignatureAuthMethod::EcdsaSha2_384,
        include_bytes!("data/p256_pkcs8.der")
    )
    .is_err());
    assert!(Ikev2SignatureAuthKey::ecdsa_rfc4754_pkcs8_der(
        Ikev2SignatureAuthMethod::DigitalSignature,
        include_bytes!("data/p256_pkcs8.der")
    )
    .is_err());
}

#[test]
fn eddsa_spki_rejects_parameters_unused_bits_trailing_and_weak_keys() {
    for public in [
        include_bytes!("data/ed25519_spki.der").as_slice(),
        include_bytes!("data/ed448_spki.der").as_slice(),
    ] {
        let mut with_null = public.to_vec();
        with_null[1] += 2;
        with_null[3] += 2;
        with_null.splice(9..9, [5, 0]);
        assert!(Ikev2SignaturePublicKey::from_spki_der(&with_null).is_err());
        let mut unused = public.to_vec();
        unused[11] = 1;
        assert!(Ikev2SignaturePublicKey::from_spki_der(&unused).is_err());
        let mut trailing = public.to_vec();
        trailing.push(0);
        assert!(Ikev2SignaturePublicKey::from_spki_der(&trailing).is_err());
        let mut identity = public.to_vec();
        identity[12..].fill(0);
        identity[12] = 1;
        assert!(Ikev2SignaturePublicKey::from_spki_der(&identity).is_err());
        assert!(Ikev2SignaturePublicKey::from_spki_der(&public[..public.len() - 1]).is_err());
    }
}

#[cfg(feature = "rsa-signing")]
#[test]
fn optional_rsa_pss_signing_covers_all_hashes_and_local_authority() {
    support::ensure_ike_crypto();
    for hash in [
        Ikev2SignatureHashAlgorithm::Sha2_256,
        Ikev2SignatureHashAlgorithm::Sha2_384,
        Ikev2SignatureHashAlgorithm::Sha2_512,
    ] {
        let key = Ikev2SignatureAuthKey::rsa_pss_pkcs8_der(
            hash,
            include_bytes!("data/rsa2048_pkcs8.der"),
        )
        .unwrap();
        signing_round_trip(
            key,
            include_bytes!("data/rsa2048_spki.der"),
            Some(hash),
            Some(324),
        );
    }
}

#[cfg(not(feature = "rsa-signing"))]
#[test]
fn default_build_excludes_rsa_pss_private_operations() {
    use opc_crypto_provider::{IkeSignatureAlgorithm, IkeSignatureOperations};
    let provider = Ikev2SoftwareCryptoOperations::new();
    for algorithm in [
        IkeSignatureAlgorithm::RsaPssSha2_256,
        IkeSignatureAlgorithm::RsaPssSha2_384,
        IkeSignatureAlgorithm::RsaPssSha2_512,
    ] {
        assert!(provider.supports_signature_verification(algorithm));
        assert!(!provider.supports_signature_generation(algorithm));
        assert!(provider
            .load_signing_key(algorithm, include_bytes!("data/rsa2048_pkcs8.der"))
            .is_err());
    }
}
