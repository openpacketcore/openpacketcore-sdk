#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn cbc_iv_key_is_separate_from_every_ike_key_and_child_keymat_for_test_nonces() {
    use crate::recovery::cbc_test_fixtures::{profiles, Fixture, DIRECTIONS};
    use crate::{derive_child_sa_key_material, Ikev2ChildSaCryptoProfile};
    for (index, profile) in profiles().enumerate() {
        let tag = 57000 + index as u64;
        let mut iv_keys = Vec::new();
        for direction in DIRECTIONS {
            let f = Fixture::new(profile, direction, tag);
            let recipe = Recipe::from_epoch(&f.epoch).unwrap();
            // Equal-size prefixes make this independent of output lengths.
            for key in [
                f.keys.sk_d(),
                f.keys.sk_ei(),
                f.keys.sk_er(),
                f.keys.sk_ai(),
                f.keys.sk_ar(),
                f.keys.sk_pi(),
                f.keys.sk_pr(),
            ] {
                assert_ne!(&recipe.iv_key[..16], &key[..16]);
            }
            for nonce in [0x11, 0x22, 0x80, 0xff] {
                let child = derive_child_sa_key_material(
                    Ikev2ChildSaCryptoProfile::new_encrypt_then_mac(
                        profile.prf(),
                        profile.encryption(),
                        profile.integrity().unwrap(),
                    ),
                    f.keys.sk_d(),
                    &[nonce; 64],
                    &[nonce ^ 0x55; 64],
                    None,
                )
                .unwrap();
                for key in [
                    child.initiator_to_responder_encryption(),
                    child.responder_to_initiator_encryption(),
                    child.initiator_to_responder_integrity(),
                    child.responder_to_initiator_integrity(),
                ] {
                    assert_ne!(&recipe.iv_key[..16], &key[..16]);
                }
            }
            iv_keys.push(recipe.iv_key);
        }
        assert_ne!(iv_keys[0], iv_keys[1]);
    }
}
use crate::Ikev2DhGroup;

#[test]
fn all_cbc_profile_triples_match_independent_frozen_keys_ivs_and_packets() {
    crate::test_support::ensure_ike_crypto();
    let mut rows = 0;
    let mut triples = std::collections::BTreeSet::new();
    for line in include_str!("../cbc_v1.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let encryption = match fields[0] {
            "128" => Encryption::AesCbc128,
            "192" => Encryption::AesCbc192,
            "256" => Encryption::AesCbc256,
            _ => panic!("frozen AES size"),
        };
        let integrity = Integrity::from_transform_id(fields[1].parse().unwrap()).unwrap();
        let prf = Prf::from_transform_id(fields[2].parse().unwrap()).unwrap();
        let profile = crate::Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            prf,
            Ikev2DhGroup::Modp2048,
            encryption,
            integrity,
        )
        .unwrap();
        if triples.insert((fields[0], fields[1], fields[2])) {
            crate::canonical::Ikev2CanonicalEmptyReplies::preflight_cbc(profile, Policy::default())
                .unwrap();
        }
        let sk_d = hex(fields[5]);
        let sk_e = hex(fields[6]);
        let sk_a = hex(fields[7]);
        let inputs = Inputs {
            initiator_spi: 0x0102_0304_0506_0708,
            responder_spi: 0x1112_1314_1516_1718,
            direction: if fields[3] == "I" {
                Direction::InitiatorToResponder
            } else {
                Direction::ResponderToInitiator
            },
            profile,
            sk_d: &sk_d,
            sk_e: &sk_e,
            sk_a: &sk_a,
        };
        let id = u32::from_str_radix(fields[4], 16).unwrap();
        let recipe = Recipe::new(inputs).unwrap();
        assert_eq!(recipe.iv_key.as_slice(), hex(fields[8]));
        let packet = recipe.seal(id).unwrap();
        assert_eq!(&packet[32..48], hex(fields[9]));
        assert_eq!(
            packet.as_slice(),
            hex(fields[10]),
            "profile/id: {:?}",
            &fields[..5]
        );
        assert_ordinary_encoder_parity(inputs, &packet);
        rows += 1;
    }
    assert_eq!(rows, 384);
    assert_eq!(triples.len(), 48);
}

fn assert_ordinary_encoder_parity(inputs: Inputs<'_>, packet: &[u8]) {
    use crate::{
        seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector,
        Ikev2SaInitKeyMaterial, ProtectedPayloadKind, ProtectedPayloadSealContext,
    };
    let receive_e = vec![0x3a; inputs.sk_e.len()];
    let receive_a = vec![0x7b; inputs.sk_a.len()];
    let (ei, er, ai, ar) = match inputs.direction {
        Direction::InitiatorToResponder => {
            (inputs.sk_e, &receive_e[..], inputs.sk_a, &receive_a[..])
        }
        Direction::ResponderToInitiator => {
            (&receive_e[..], inputs.sk_e, &receive_a[..], inputs.sk_a)
        }
    };
    let auth_key = vec![0x55; inputs.profile.prf().output_len()];
    let keys = Ikev2SaInitKeyMaterial::from_established_keys(
        inputs.profile,
        false,
        inputs.sk_d,
        ai,
        ar,
        ei,
        er,
        &auth_key,
        &auth_key,
    )
    .unwrap();
    let body = seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
        inputs.profile,
        &keys,
        inputs.direction,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &packet[..32],
        },
        &[],
        packet[32..48].try_into().unwrap(),
    )
    .unwrap();
    let mut ordinary = packet[..32].to_vec();
    ordinary.extend_from_slice(&body);
    assert_eq!(ordinary, packet, "complete ordinary-sealer parity");
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_self_consistent_wrong_iv_cannot_pass_the_canonical_release_check() {
    use crate::crypto_module::{
        execute_cbc_decrypt, execute_cbc_encrypt, execute_integrity_checksum,
        execute_integrity_verification,
    };
    crate::test_support::ensure_ike_crypto();
    let profile = crate::Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Prf::HmacSha2_256,
        Ikev2DhGroup::Modp2048,
        Encryption::AesCbc128,
        Integrity::HmacSha2_256_128,
    )
    .unwrap();
    let sk_d: Vec<_> = (0xd0..0xf0).collect();
    let sk_e: Vec<_> = (0..16).collect();
    let sk_a: Vec<_> = (0x80..0xa0).collect();
    let recipe = Recipe::new(Inputs {
        initiator_spi: 0x0102_0304_0506_0708,
        responder_spi: 0x1112_1314_1516_1718,
        direction: Direction::InitiatorToResponder,
        profile,
        sk_d: &sk_d,
        sk_e: &sk_e,
        sk_a: &sk_a,
    })
    .unwrap();
    let mut wrong = recipe.seal(0).unwrap();
    wrong[32] ^= 0x80;
    let mut plaintext = [0_u8; 16];
    plaintext[15] = 15;
    let ciphertext =
        execute_cbc_encrypt(profile.encryption(), &sk_e, &wrong[32..48], &plaintext).unwrap();
    wrong[48..64].copy_from_slice(&ciphertext);
    let mac =
        execute_integrity_checksum(Integrity::HmacSha2_256_128, &sk_a, &wrong[..64], &[]).unwrap();
    wrong[64..].copy_from_slice(&mac);
    execute_integrity_verification(
        Integrity::HmacSha2_256_128,
        &sk_a,
        &wrong[..64],
        &wrong[64..],
    )
    .unwrap();
    assert_eq!(
        execute_cbc_decrypt(profile.encryption(), &sk_e, &wrong[32..48], &wrong[48..64])
            .unwrap()
            .as_slice(),
        plaintext
    );
    assert_eq!(recipe.verify(0, &wrong), Err(Error::InvalidOutput));
}

#[test]
fn cbc_self_check_rejects_bit_faults_partial_macs_and_noncanonical_plaintext() {
    crate::test_support::ensure_ike_crypto();
    let sk_d = [0xd0; 32];
    let sk_e = [0x10; 16];
    let sk_a = [0xa0; 64];
    for integrity in [
        Integrity::HmacSha1_96,
        Integrity::HmacSha2_256_128,
        Integrity::HmacSha2_384_192,
        Integrity::HmacSha2_512_256,
    ] {
        let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            Prf::HmacSha2_256,
            Ikev2DhGroup::Modp2048,
            Encryption::AesCbc128,
            integrity,
        )
        .unwrap();
        let inputs = Inputs {
            initiator_spi: 1,
            responder_spi: 2,
            direction: Direction::InitiatorToResponder,
            profile,
            sk_d: &sk_d,
            sk_e: &sk_e,
            sk_a: &sk_a[..integrity.key_len()],
        };
        let recipe = Recipe::new(inputs).unwrap();
        let good = recipe.seal(0x1234_5678).unwrap();
        for bit in 0..good.len() * 8 {
            let mut bad = good.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                recipe.verify(0x1234_5678, &bad),
                Err(Error::InvalidOutput),
                "bit {bit}"
            );
        }
        for length in 0..good.len() {
            assert_eq!(
                recipe.verify(0x1234_5678, &good[..length]),
                Err(Error::InvalidOutput)
            );
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(recipe.verify(0x1234_5678, &long), Err(Error::InvalidOutput));

        // A valid HMAC over the wrong coverage cannot authenticate the packet.
        for (prefix, suffix) in [
            (&good[..28], &good[32..64]), // omitted SK header
            (&good[..32], &good[48..64]), // omitted IV
            (&good[..48], &good[64..64]), // omitted ciphertext
        ] {
            let mac = execute_integrity_checksum(integrity, inputs.sk_a, prefix, suffix).unwrap();
            let mut bad = good.clone();
            bad[64..].copy_from_slice(&mac);
            assert_eq!(recipe.verify(0x1234_5678, &bad), Err(Error::InvalidOutput));
        }

        // Authenticated, aligned IKE padding may be legal to a general receiver,
        // but every raw byte, including Pad Length, is frozen for this sender.
        for byte in 0..16 {
            let mut plaintext = [0_u8; 16];
            plaintext[15] = 15;
            plaintext[byte] ^= 1;
            let ciphertext =
                execute_cbc_encrypt(profile.encryption(), inputs.sk_e, &good[32..48], &plaintext)
                    .unwrap();
            let mut bad = good.clone();
            bad[48..64].copy_from_slice(&ciphertext);
            let mac = execute_integrity_checksum(integrity, inputs.sk_a, &bad[..64], &[]).unwrap();
            bad[64..].copy_from_slice(&mac);
            execute_integrity_verification(integrity, inputs.sk_a, &bad[..64], &bad[64..]).unwrap();
            assert_eq!(
                recipe.verify(0x1234_5678, &bad),
                Err(Error::InvalidOutput),
                "padding byte {byte}"
            );
        }
        let wrong_e = [0x40; 16];
        let wrong_a = [0x60; 64];
        for wrong in [
            Inputs {
                sk_e: &wrong_e,
                ..inputs
            },
            Inputs {
                sk_a: &wrong_a[..integrity.key_len()],
                ..inputs
            },
        ] {
            assert_eq!(
                Recipe::new(wrong).unwrap().verify(0x1234_5678, &good),
                Err(Error::InvalidOutput)
            );
        }
    }
}

#[test]
fn cbc_iv_key_changes_with_each_variable_derivation_field() {
    crate::test_support::ensure_ike_crypto();
    let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Prf::HmacSha2_256,
        Ikev2DhGroup::Modp2048,
        Encryption::AesCbc128,
        Integrity::HmacSha2_256_128,
    )
    .unwrap();
    let d = [0xd0; 64];
    let e = [0x10; 32];
    let a = [0xa0; 64];
    let inputs = Inputs {
        initiator_spi: 1,
        responder_spi: 2,
        direction: Direction::InitiatorToResponder,
        profile,
        sk_d: &d[..32],
        sk_e: &e[..16],
        sk_a: &a[..32],
    };
    let original = Recipe::new(inputs).unwrap().iv_key;
    let other_d = [0xd1; 32];
    for changed in [
        Inputs {
            initiator_spi: 3,
            ..inputs
        },
        Inputs {
            responder_spi: 3,
            ..inputs
        },
        Inputs {
            direction: Direction::ResponderToInitiator,
            ..inputs
        },
        Inputs {
            sk_d: &other_d,
            ..inputs
        },
    ] {
        assert_ne!(Recipe::new(changed).unwrap().iv_key, original);
    }
    for (encryption, integrity, prf) in [
        (
            Encryption::AesCbc192,
            Integrity::HmacSha2_256_128,
            Prf::HmacSha2_256,
        ),
        (
            Encryption::AesCbc128,
            Integrity::HmacSha2_512_256,
            Prf::HmacSha2_256,
        ),
        (
            Encryption::AesCbc128,
            Integrity::HmacSha2_256_128,
            Prf::HmacSha2_512,
        ),
    ] {
        let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            prf,
            Ikev2DhGroup::Modp2048,
            encryption,
            integrity,
        )
        .unwrap();
        let changed = Inputs {
            profile,
            sk_d: &d[..prf.output_len()],
            sk_e: &e[..encryption.key_material_len()],
            sk_a: &a[..integrity.key_len()],
            ..inputs
        };
        let changed_key = Recipe::new(changed).unwrap().iv_key;
        assert_ne!(&changed_key[..16], &original[..16]);
    }
}

#[test]
fn independent_cbc_prefix_check_rejects_authenticated_header_bit_faults() {
    crate::test_support::ensure_ike_crypto();
    let sk_d = [0xd0; 32];
    let sk_e = [0x10; 16];
    let sk_a = [0xa0; 64];
    for integrity in [
        Integrity::HmacSha1_96,
        Integrity::HmacSha2_256_128,
        Integrity::HmacSha2_384_192,
        Integrity::HmacSha2_512_256,
    ] {
        let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            Prf::HmacSha2_256,
            Ikev2DhGroup::Modp2048,
            Encryption::AesCbc128,
            integrity,
        )
        .unwrap();
        for direction in [
            Direction::InitiatorToResponder,
            Direction::ResponderToInitiator,
        ] {
            let recipe = Recipe::new(Inputs {
                initiator_spi: 1,
                responder_spi: 2,
                direction,
                profile,
                sk_d: &sk_d,
                sk_e: &sk_e,
                sk_a: &sk_a[..integrity.key_len()],
            })
            .unwrap();
            let good = recipe.seal(0x1234_5678).unwrap();
            for bit in 0..32 * 8 {
                let mut wrong = good.clone();
                wrong[bit / 8] ^= 1 << (bit % 8);
                let mac = execute_integrity_checksum(
                    integrity,
                    &sk_a[..integrity.key_len()],
                    &wrong[..64],
                    &[],
                )
                .unwrap();
                wrong[64..].copy_from_slice(&mac);
                execute_integrity_verification(
                    integrity,
                    &sk_a[..integrity.key_len()],
                    &wrong[..64],
                    &wrong[64..],
                )
                .unwrap();
                assert_eq!(
                    recipe.verify(0x1234_5678, &wrong),
                    Err(Error::InvalidOutput),
                    "authenticated prefix fault: {integrity:?} {direction:?} bit {bit}"
                );
            }
        }
    }
}
