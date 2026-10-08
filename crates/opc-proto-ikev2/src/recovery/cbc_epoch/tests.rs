#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption};

fn profile(bits: u16, integrity: u16, prf: u16) -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::from_transform_id(prf).unwrap(),
        Ikev2DhGroup::Modp2048,
        match bits {
            128 => Encryption::AesCbc128,
            192 => Encryption::AesCbc192,
            256 => Encryption::AesCbc256,
            _ => panic!("frozen CBC key size"),
        },
        Ikev2IntegrityAlgorithm::from_transform_id(integrity).unwrap(),
    )
    .unwrap()
}

fn pattern(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

struct Keys {
    d: Vec<u8>,
    ei: Vec<u8>,
    er: Vec<u8>,
    ai: Vec<u8>,
    ar: Vec<u8>,
}
impl Keys {
    fn new(profile: Ikev2SaInitCryptoProfile) -> Self {
        Self {
            d: pattern(0xd0, profile.prf().output_len()),
            ei: pattern(0, profile.encryption().key_material_len()),
            er: pattern(0x40, profile.encryption().key_material_len()),
            ai: pattern(0x80, profile.integrity_key_len()),
            ar: pattern(0x20, profile.integrity_key_len()),
        }
    }
    fn material(&self, profile: Ikev2SaInitCryptoProfile) -> Ikev2SaInitKeyMaterial {
        Ikev2SaInitKeyMaterial::from_established_keys(
            profile,
            false,
            &self.d,
            &self.ai,
            &self.ar,
            &self.ei,
            &self.er,
            &vec![0x99; profile.prf().output_len()],
            &vec![0xaa; profile.prf().output_len()],
        )
        .unwrap()
    }
}

fn inputs(
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
) -> Ikev2CbcEpochInputs<'_> {
    Ikev2CbcEpochInputs {
        initiator_spi: 0x0102_0304_0506_0708,
        responder_spi: 0x1112_1314_1516_1718,
        sending_direction: Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        profile,
        keys,
    }
}

fn fingerprint(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn all_cbc_epoch_profiles_roundtrip_and_match_frozen_fingerprints() {
    let mut rows = 0;
    for line in include_str!("../cbc_epoch_v1.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let profile = profile(
            fields[0].parse().unwrap(),
            fields[1].parse().unwrap(),
            fields[2].parse().unwrap(),
        );
        let material = Keys::new(profile).material(profile);
        let mut input = inputs(profile, &material);
        if fields[3] == "R" {
            input.sending_direction = Ikev2ProtectedPayloadDirection::ResponderToInitiator;
        }
        let fresh = Ikev2CbcEpochRecord::fresh(input).unwrap();
        let restored = Ikev2CbcEpochRecord::from_persisted(input, Some(1)).unwrap();
        assert_eq!(fresh, restored);
        assert_eq!(fresh.initiator_spi(), input.initiator_spi);
        assert_eq!(fresh.responder_spi(), input.responder_spi);
        assert_eq!(fresh.direction(), input.sending_direction);
        assert_eq!(fresh.encryption(), profile.encryption());
        assert_eq!(fresh.integrity(), profile.integrity().unwrap());
        assert_eq!(fresh.prf(), profile.prf());
        assert_eq!(fresh.canonical_format(), Some(1));
        assert_eq!(fresh.binding.ledger_key, fingerprint(fields[4]));
        assert_eq!(
            fresh.binding.canonical_binding,
            Some(fingerprint(fields[5]))
        );
        assert!(Arc::ptr_eq(&fresh.binding, &fresh.clone().binding));
        rows += 1;
    }
    assert_eq!(rows, 96);
}

#[test]
fn cbc_epoch_preserves_absent_and_every_unknown_marker_without_authority() {
    let profile = profile(128, 12, 5);
    let material = Keys::new(profile).material(profile);
    let input = inputs(profile, &material);
    let fresh = Ikev2CbcEpochRecord::fresh(input).unwrap();
    for marker in std::iter::once(None).chain((0..=u8::MAX).map(Some)) {
        let restored = Ikev2CbcEpochRecord::from_persisted(input, marker).unwrap();
        assert_eq!(restored.canonical_format(), marker);
        assert_eq!(restored.binding.ledger_key, fresh.binding.ledger_key);
        assert_eq!(
            restored.binding.canonical_binding.is_some(),
            marker == Some(1)
        );
        assert_eq!(restored == fresh, marker == Some(1));
    }
}

#[test]
fn cbc_epoch_rejects_invalid_spis_profile_and_each_key_width() {
    let profile = profile(128, 12, 5);
    let material = Keys::new(profile).material(profile);
    let valid = inputs(profile, &material);
    for (initiator_spi, responder_spi) in [(0, 1), (1, 0), (0, 0)] {
        let bad = Ikev2CbcEpochInputs {
            initiator_spi,
            responder_spi,
            ..valid
        };
        assert_eq!(
            Ikev2CbcEpochRecord::fresh(bad),
            Err(Ikev2WindowError::DomainMismatch)
        );
    }
    let gcm = Ikev2SaInitCryptoProfile::new_aead(
        profile.prf(),
        Ikev2DhGroup::Modp2048,
        Encryption::AesGcm16_128,
    )
    .unwrap();
    for other_profile in [
        gcm,
        self::profile(192, 12, 5),
        self::profile(128, 13, 5),
        self::profile(128, 12, 6),
    ] {
        let other_material = Keys::new(other_profile).material(other_profile);
        assert_eq!(
            Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
                profile: other_profile,
                ..valid
            }),
            Err(Ikev2WindowError::DomainMismatch),
        );
        assert_eq!(
            Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
                keys: &other_material,
                ..valid
            }),
            Err(Ikev2WindowError::DomainMismatch),
        );
    }
}

#[test]
fn cbc_epoch_refuses_either_equal_directional_key_pair() {
    for bits in [128, 192, 256] {
        for integrity in [2, 12, 13, 14] {
            for prf in [2, 5, 6, 7] {
                let profile = profile(bits, integrity, prf);
                for (same_e, same_a) in [(true, false), (false, true), (true, true)] {
                    let mut keys = Keys::new(profile);
                    if same_e {
                        keys.er = keys.ei.clone();
                    }
                    if same_a {
                        keys.ar = keys.ai.clone();
                    }
                    let material = keys.material(profile);
                    for direction in [
                        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
                        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
                    ] {
                        let input = Ikev2CbcEpochInputs {
                            sending_direction: direction,
                            ..inputs(profile, &material)
                        };
                        assert_eq!(
                            Ikev2CbcEpochRecord::fresh(input),
                            Err(Ikev2WindowError::DomainMismatch)
                        );
                        assert_eq!(
                            Ikev2CbcEpochRecord::from_persisted(input, None),
                            Err(Ikev2WindowError::DomainMismatch)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn cbc_epoch_binding_covers_each_raw_key_and_both_roles() {
    let profile = profile(256, 14, 7);
    for direction in [
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    ] {
        let material = Keys::new(profile).material(profile);
        let input = Ikev2CbcEpochInputs {
            sending_direction: direction,
            ..inputs(profile, &material)
        };
        let original = Ikev2CbcEpochRecord::fresh(input).unwrap();
        for index in 0..5 {
            let mut keys = Keys::new(profile);
            [
                &mut keys.d,
                &mut keys.ei,
                &mut keys.er,
                &mut keys.ai,
                &mut keys.ar,
            ][index][0] ^= 0x80;
            let changed_keys = keys.material(profile);
            let changed = Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
                keys: &changed_keys,
                ..input
            })
            .unwrap();
            assert_ne!(original, changed, "raw key {index}");
            assert_ne!(
                original.binding.canonical_binding, changed.binding.canonical_binding,
                "binding key {index}"
            );
            let send_changed = match direction {
                Ikev2ProtectedPayloadDirection::InitiatorToResponder => matches!(index, 1 | 3),
                Ikev2ProtectedPayloadDirection::ResponderToInitiator => matches!(index, 2 | 4),
            };
            assert_eq!(
                original.binding.ledger_key != changed.binding.ledger_key,
                send_changed
            );
        }
        // Preserve the same selected sending keys while reversing the original role.
        let mut swapped = Keys::new(profile);
        std::mem::swap(&mut swapped.ei, &mut swapped.er);
        std::mem::swap(&mut swapped.ai, &mut swapped.ar);
        let swapped_keys = swapped.material(profile);
        let other = Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
            keys: &swapped_keys,
            sending_direction: match direction {
                Ikev2ProtectedPayloadDirection::InitiatorToResponder => {
                    Ikev2ProtectedPayloadDirection::ResponderToInitiator
                }
                Ikev2ProtectedPayloadDirection::ResponderToInitiator => {
                    Ikev2ProtectedPayloadDirection::InitiatorToResponder
                }
            },
            ..input
        })
        .unwrap();
        assert_ne!(original, other);
        assert_ne!(
            original.binding.canonical_binding,
            other.binding.canonical_binding
        );
        assert_eq!(original.binding.ledger_key, other.binding.ledger_key);
    }
}

#[test]
fn cbc_epoch_binding_covers_metadata_and_ledger_excludes_non_sending_fields() {
    let profile = profile(128, 12, 5);
    let material = Keys::new(profile).material(profile);
    let input = inputs(profile, &material);
    let original = Ikev2CbcEpochRecord::fresh(input).unwrap();
    for changed in [
        Ikev2CbcEpochInputs {
            initiator_spi: input.initiator_spi ^ 1,
            ..input
        },
        Ikev2CbcEpochInputs {
            responder_spi: input.responder_spi ^ 1,
            ..input
        },
    ] {
        let changed = Ikev2CbcEpochRecord::fresh(changed).unwrap();
        assert_ne!(original, changed);
        assert_ne!(
            original.binding.canonical_binding,
            changed.binding.canonical_binding
        );
        assert_eq!(original.binding.ledger_key, changed.binding.ledger_key);
    }
    for (bits, integrity, prf) in [(192, 12, 5), (128, 13, 5), (128, 12, 7)] {
        let other_profile = self::profile(bits, integrity, prf);
        let keys = Keys::new(other_profile).material(other_profile);
        let changed = Ikev2CbcEpochRecord::fresh(inputs(other_profile, &keys)).unwrap();
        assert_ne!(original, changed);
        assert_ne!(
            original.binding.canonical_binding,
            changed.binding.canonical_binding
        );
        assert_eq!(
            original.binding.ledger_key == changed.binding.ledger_key,
            prf != 5
        );
    }
}

#[test]
fn cbc_epoch_equality_checks_raw_binding_even_with_identical_cached_indexes() {
    let profile = profile(256, 14, 7);
    let keys = Keys::new(profile).material(profile);
    let original = Ikev2CbcEpochRecord::fresh(inputs(profile, &keys)).unwrap();
    // Index equality is not permission to omit the full immutable binding check.
    for index in 0..12 {
        let mut changed = original.clone();
        let binding = Arc::make_mut(&mut changed.binding);
        match index {
            0 => binding.sk_d[0] ^= 0x80,
            1 => binding.sk_ei[0] ^= 0x80,
            2 => binding.sk_er[0] ^= 0x80,
            3 => binding.sk_ai[0] ^= 0x80,
            4 => binding.sk_ar[0] ^= 0x80,
            5 => binding.initiator_spi ^= 1,
            6 => binding.responder_spi ^= 1,
            7 => binding.direction = Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            8 => binding.encryption = Encryption::AesCbc192,
            9 => binding.integrity = Ikev2IntegrityAlgorithm::HmacSha2_384_192,
            10 => binding.prf = Ikev2PrfAlgorithm::HmacSha2_384,
            11 => binding.canonical_format = None,
            _ => unreachable!(),
        }
        assert_ne!(original, changed, "raw binding field {index}");
    }
}

#[test]
fn cbc_epoch_debug_is_opaque_and_clone_keeps_keys_alive() {
    let profile = profile(128, 12, 5);
    let keys = Keys::new(profile).material(profile);
    let original = Ikev2CbcEpochRecord::fresh(inputs(profile, &keys)).unwrap();
    let retained = original.clone();
    drop(original);
    drop(keys);
    assert_eq!(format!("{retained:?}"), "Ikev2CbcEpochRecord { .. }");
    assert_eq!(retained.binding.sk_d.as_slice(), pattern(0xd0, 32));
    assert_eq!(retained.binding.sk_ei.as_slice(), pattern(0, 16));
    assert_eq!(retained.binding.sk_er.as_slice(), pattern(0x40, 16));
    assert_eq!(retained.binding.sk_ai.as_slice(), pattern(0x80, 32));
    assert_eq!(retained.binding.sk_ar.as_slice(), pattern(0x20, 32));
}
