//! TS 33.401 V18.0.0 Annex C, reused by TS 33.501 §D.4.4/D.4.5.
//! Vector provenance is recorded in fixtures/nas_aes_33401.txt.
use bytes::Bytes;
use opc_key::{KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_proto_nas::{
    nea2_cipher, nia2_mac, AesNasSecurityAlgorithms, NasAesKey, NasAlgorithmInput,
    NasCipheringAlgorithm, NasConnectionId, NasCount, NasCountState, NasIntegrityAlgorithm,
    NasKeyUsage, NasSecurityAlgorithms, NasSecurityContext, NasSecurityDirection, NasSecurityError,
    SecurityHeaderType,
};
use opc_types::TenantId;

fn hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn direction(value: &str) -> NasSecurityDirection {
    match value {
        "0" => NasSecurityDirection::Uplink,
        "1" => NasSecurityDirection::Downlink,
        _ => panic!("invalid vector direction"),
    }
}
fn key(fill: u8) -> NasAesKey {
    NasAesKey::new(Zeroizing::new([fill; 16]))
}
fn handle(purpose: KeyPurpose) -> KeyHandle {
    KeyHandle::new(
        KeyId::new("synthetic-nas-key").unwrap(),
        purpose,
        TenantId::from_static("synthetic-tenant"),
        Zeroizing::new([0; 32]),
    )
}

#[test]
fn all_six_eea2_and_eight_eia2_published_test_sets() {
    let mut counts = [0; 2];
    for row in include_str!("fixtures/nas_aes_33401.txt")
        .lines()
        .filter(|r| !r.starts_with('#') && !r.is_empty())
    {
        let fields: Vec<_> = row.split('|').collect();
        assert_eq!(fields.len(), 9);
        let key = NasAesKey::new(Zeroizing::new(hex(fields[2]).try_into().unwrap()));
        let count = u32::from_str_radix(fields[3], 16).unwrap();
        let bearer = u8::from_str_radix(fields[4], 16).unwrap();
        let bits = fields[6].parse().unwrap();
        let params = NasAlgorithmInput::new(count, bearer, direction(fields[5]), bits).unwrap();
        let input = hex(fields[7]);
        let expected = hex(fields[8]);
        if fields[0] == "NEA2" {
            counts[0] += 1;
            let result = nea2_cipher(&key, params, &input).unwrap();
            assert_eq!(result.as_ref(), expected, "{} encryption", fields[1]);
            assert_eq!(
                nea2_cipher(&key, params, &result).unwrap().as_ref(),
                input,
                "{} decryption",
                fields[1]
            );
        } else {
            assert_eq!(fields[0], "NIA2");
            counts[1] += 1;
            assert_eq!(
                &nia2_mac(&key, params, &input).unwrap()[..],
                expected,
                "{} MAC",
                fields[1]
            );
        }
    }
    assert_eq!(counts, [6, 8]);
}

#[test]
fn length_and_bearer_are_validated_without_silent_truncation() {
    for bearer in 32..=255 {
        assert_eq!(
            NasAlgorithmInput::new(0, bearer, NasSecurityDirection::Uplink, 8).unwrap_err(),
            NasSecurityError::InvalidBearer
        );
    }
    assert!(NasAlgorithmInput::new(0, 0, NasSecurityDirection::Uplink, usize::MAX).is_err());
    for bits in [0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 129] {
        let params =
            NasAlgorithmInput::new(u32::MAX, 31, NasSecurityDirection::Downlink, bits).unwrap();
        let len = bits.div_ceil(8);
        let input = vec![0; len];
        assert!(nia2_mac(&key(0), params, &input).is_ok());
        assert!(nea2_cipher(&key(0), params, &input).is_ok());
        if len > 0 {
            assert_eq!(
                nia2_mac(&key(0), params, &input[..len - 1]).unwrap_err(),
                NasSecurityError::InvalidLength
            );
            assert_eq!(
                nea2_cipher(&key(0), params, &input[..len - 1]).unwrap_err(),
                NasSecurityError::InvalidLength
            );
        }
        assert!(nia2_mac(&key(0), params, &vec![0; len + 1]).is_err());
        assert!(nea2_cipher(&key(0), params, &vec![0; len + 1]).is_err());
    }
}

#[test]
fn unused_tail_bits_do_not_affect_mac_or_ciphertext() {
    for bits in 1usize..=257 {
        if bits.is_multiple_of(8) {
            continue;
        }
        let params =
            NasAlgorithmInput::new(0x12345678, 1, NasSecurityDirection::Uplink, bits).unwrap();
        let mut a = vec![0xa5; bits.div_ceil(8)];
        let last = a.len() - 1;
        let mask = 0xff << (8 - bits % 8);
        a[last] &= mask;
        let mut b = a.clone();
        b[last] |= !mask;
        assert_eq!(
            nia2_mac(&key(0x12), params, &a).unwrap(),
            nia2_mac(&key(0x12), params, &b).unwrap()
        );
        let ciphertext = nea2_cipher(&key(0x34), params, &a).unwrap();
        assert_eq!(ciphertext, nea2_cipher(&key(0x34), params, &b).unwrap());
        assert_eq!(ciphertext[last] & !mask, 0);
        assert_eq!(
            nea2_cipher(&key(0x34), params, &ciphertext)
                .unwrap()
                .as_ref(),
            a
        );
    }
}

#[test]
fn count_bearer_direction_and_each_message_bit_affect_integrity() {
    let original = NasAlgorithmInput::new(0, 1, NasSecurityDirection::Uplink, 64).unwrap();
    let message = [0; 8];
    let mac = nia2_mac(&key(0), original, &message).unwrap();
    for params in [
        NasAlgorithmInput::new(1, 1, NasSecurityDirection::Uplink, 64).unwrap(),
        NasAlgorithmInput::new(0, 2, NasSecurityDirection::Uplink, 64).unwrap(),
        NasAlgorithmInput::new(0, 1, NasSecurityDirection::Downlink, 64).unwrap(),
        NasAlgorithmInput::new(0, 1, NasSecurityDirection::Uplink, 63).unwrap(),
    ] {
        assert_ne!(mac, nia2_mac(&key(0), params, &message).unwrap());
    }
    for bit in 0..64 {
        let mut altered = message;
        altered[bit / 8] ^= 0x80 >> (bit % 8);
        assert_ne!(mac, nia2_mac(&key(0), original, &altered).unwrap());
    }
}

#[test]
fn provider_resolves_session_key_usage_and_matches_raw_primitives() {
    let resolver = |handle: &KeyHandle, usage: NasKeyUsage| {
        assert_eq!(handle.purpose(), KeyPurpose::Session);
        Ok(key(match usage {
            NasKeyUsage::Integrity(_) => 0x11,
            NasKeyUsage::Ciphering(_) => 0x22,
        }))
    };
    let provider = AesNasSecurityAlgorithms::new(resolver);
    let handle = handle(KeyPurpose::Session);
    let count = NasCount::new(0x1234, 0x56);
    let input = [0x56, 0x7e, 0, 0x43];
    let params = NasAlgorithmInput::new(0x123456, 2, NasSecurityDirection::Downlink, 32).unwrap();
    assert_eq!(
        provider
            .compute_mac(
                NasIntegrityAlgorithm::Nia2,
                &handle,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Downlink,
                &input
            )
            .unwrap(),
        nia2_mac(&key(0x11), params, &input).unwrap()
    );
    assert_eq!(
        provider
            .apply_cipher(
                NasCipheringAlgorithm::Nea2,
                &handle,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Downlink,
                &input
            )
            .unwrap(),
        nea2_cipher(&key(0x22), params, &input).unwrap()
    );
}

#[test]
fn provider_rejects_unsupported_algorithms_and_missing_or_wrong_purpose_keys() {
    let provider = AesNasSecurityAlgorithms::new(
        |_: &KeyHandle, _: NasKeyUsage| -> Result<NasAesKey, NasSecurityError> {
            Err(NasSecurityError::KeyUnavailable)
        },
    );
    let count = NasCount::new(0, 1);
    let session = handle(KeyPurpose::Session);
    let config = handle(KeyPurpose::Config);
    for algorithm in [
        NasIntegrityAlgorithm::Nia0,
        NasIntegrityAlgorithm::Nia1,
        NasIntegrityAlgorithm::Nia3,
    ] {
        assert_eq!(
            provider
                .compute_mac(
                    algorithm,
                    &session,
                    count,
                    NasConnectionId::NonThreeGpp,
                    NasSecurityDirection::Uplink,
                    &[]
                )
                .unwrap_err(),
            NasSecurityError::UnsupportedAlgorithm
        );
    }
    for algorithm in [NasCipheringAlgorithm::Nea1, NasCipheringAlgorithm::Nea3] {
        assert_eq!(
            provider
                .apply_cipher(
                    algorithm,
                    &session,
                    count,
                    NasConnectionId::NonThreeGpp,
                    NasSecurityDirection::Uplink,
                    &[]
                )
                .unwrap_err(),
            NasSecurityError::UnsupportedAlgorithm
        );
    }
    assert_eq!(
        provider
            .compute_mac(
                NasIntegrityAlgorithm::Nia2,
                &session,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Uplink,
                &[]
            )
            .unwrap_err(),
        NasSecurityError::KeyUnavailable
    );
    assert_eq!(
        provider
            .apply_cipher(
                NasCipheringAlgorithm::Nea2,
                &session,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Uplink,
                &[]
            )
            .unwrap_err(),
        NasSecurityError::KeyUnavailable
    );
    assert_eq!(
        provider
            .compute_mac(
                NasIntegrityAlgorithm::Nia2,
                &config,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Uplink,
                &[]
            )
            .unwrap_err(),
        NasSecurityError::KeyPurposeMismatch
    );
    assert_eq!(
        provider
            .apply_cipher(
                NasCipheringAlgorithm::Nea2,
                &config,
                count,
                NasConnectionId::NonThreeGpp,
                NasSecurityDirection::Uplink,
                &[]
            )
            .unwrap_err(),
        NasSecurityError::KeyPurposeMismatch
    );
}

#[test]
fn real_aes_context_protect_verify_tamper_and_replay() {
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, usage: NasKeyUsage| {
        Ok(key(match usage {
            NasKeyUsage::Integrity(_) => 0x11,
            NasKeyUsage::Ciphering(_) => 0x22,
        }))
    });
    let context = || {
        NasSecurityContext::new(
            NasIntegrityAlgorithm::Nia2,
            NasCipheringAlgorithm::Nea2,
            handle(KeyPurpose::Session),
            handle(KeyPurpose::Session),
            NasConnectionId::NonThreeGpp,
            NasCountState {
                next_transmit: Some(NasCount::new(0, 1)),
                highest_received: None,
            },
            NasCountState {
                next_transmit: Some(NasCount::new(0, 1)),
                highest_received: None,
            },
        )
        .unwrap()
    };
    let payload = Bytes::from_static(&[0x7e, 0, 0x43]);
    for sht in [
        SecurityHeaderType::IntegrityProtected,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        SecurityHeaderType::IntegrityProtectedNewContext,
        SecurityHeaderType::IntegrityProtectedAndCipheredNewContext,
    ] {
        let sender = context();
        let receiver = context();
        let envelope = sender
            .protect_payload(&provider, NasSecurityDirection::Uplink, sht, &payload)
            .unwrap();
        let mut altered = envelope.clone();
        altered.sequence_number ^= 1;
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Uplink, &altered)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
        let mut altered = envelope.clone();
        altered.mac[0] ^= 1;
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Uplink, &altered)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
        let mut altered = envelope.clone();
        altered.payload = Bytes::from_static(&[0, 0, 0]);
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Uplink, &altered)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Downlink, &envelope)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Uplink, &envelope)
                .unwrap()
                .payload,
            payload
        );
        assert_eq!(
            receiver
                .verify_and_decipher(&provider, NasSecurityDirection::Uplink, &envelope)
                .unwrap_err(),
            NasSecurityError::IntegrityCheckFailed
        );
    }
}

#[test]
fn aes_key_and_resolver_debug_never_reveal_secrets() {
    let secret = NasAesKey::new(Zeroizing::new(*b"secret-key-12345"));
    let provider =
        AesNasSecurityAlgorithms::new(move |_: &KeyHandle, _: NasKeyUsage| Ok(secret.clone()));
    for text in [format!("{:?}", key(0x41)), format!("{provider:?}")] {
        assert!(text.contains("redacted"));
        assert!(!text.contains("65, 65"));
        assert!(!text.contains("secret-key"));
    }
}

#[test]
fn protected_envelope_matches_independent_openssl_outputs() {
    // OpenSSL 3.5.7: enc -aes-128-ctr, key 22*16; mac CMAC,
    // cipher:AES-128-CBC, key 11*16. Counter is COUNT || bearer/direction
    // || 26 zeros || 64 zeros. MAC input is that prefix || SQN || ciphertext.
    // See CONFORMANCE.md for reproducible commands and synthetic input bytes.
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, usage: NasKeyUsage| {
        Ok(key(match usage {
            NasKeyUsage::Integrity(_) => 0x11,
            NasKeyUsage::Ciphering(_) => 0x22,
        }))
    });
    let ctx = NasSecurityContext::new(
        NasIntegrityAlgorithm::Nia2,
        NasCipheringAlgorithm::Nea2,
        handle(KeyPurpose::Session),
        handle(KeyPurpose::Session),
        NasConnectionId::NonThreeGpp,
        NasCountState {
            next_transmit: Some(NasCount::new(0, 1)),
            highest_received: None,
        },
        NasCountState {
            next_transmit: Some(NasCount::new(0, 1)),
            highest_received: None,
        },
    )
    .unwrap();
    for (direction, ciphertext, mac) in [
        (
            NasSecurityDirection::Uplink,
            [0x89, 0x1b, 0x5d],
            [0x55, 0xea, 0x2a, 0x24],
        ),
        (
            NasSecurityDirection::Downlink,
            [0xd6, 0xca, 0x5a],
            [0xf1, 0xca, 0x63, 0x4d],
        ),
    ] {
        let envelope = ctx
            .protect_payload(
                &provider,
                direction,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                &[0x7e, 0, 0x43],
            )
            .unwrap();
        assert_eq!(envelope.payload.as_ref(), ciphertext);
        assert_eq!(envelope.mac, mac);
    }
}

fn review_context(ciphering: NasCipheringAlgorithm) -> NasSecurityContext {
    NasSecurityContext::new(
        NasIntegrityAlgorithm::Nia2,
        ciphering,
        handle(KeyPurpose::Session),
        handle(KeyPurpose::Session),
        NasConnectionId::NonThreeGpp,
        NasCountState {
            next_transmit: Some(NasCount::new(0, 1)),
            highest_received: None,
        },
        NasCountState {
            next_transmit: Some(NasCount::new(0, 1)),
            highest_received: None,
        },
    )
    .unwrap()
}

#[test]
fn review_nia2_with_nea0_protects_and_verifies_in_both_directions() {
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, usage: NasKeyUsage| {
        assert_eq!(
            usage,
            NasKeyUsage::Integrity(NasIntegrityAlgorithm::Nia2),
            "NEA0 must not resolve a cipher key"
        );
        Ok(key(0x11))
    });
    for direction in [NasSecurityDirection::Uplink, NasSecurityDirection::Downlink] {
        let tx = review_context(NasCipheringAlgorithm::Nea0);
        let rx = review_context(NasCipheringAlgorithm::Nea0);
        let envelope = tx
            .protect_payload(
                &provider,
                direction,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                &[0x7e, 0, 0x43],
            )
            .unwrap();
        assert_eq!(envelope.payload.as_ref(), &[0x7e, 0, 0x43]);
        let expected = nia2_mac(
            &key(0x11),
            NasAlgorithmInput::new(1, 2, direction, 32).unwrap(),
            &[1, 0x7e, 0, 0x43],
        )
        .unwrap();
        assert_eq!(envelope.mac, expected);
        assert_eq!(
            rx.verify_and_decipher(&provider, direction, &envelope)
                .unwrap()
                .payload
                .as_ref(),
            &[0x7e, 0, 0x43]
        );
    }
}

#[test]
fn review_count_estimation_survives_loss_across_sequence_wrap() {
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| Ok(key(0x11)));
    for direction in [NasSecurityDirection::Uplink, NasSecurityDirection::Downlink] {
        let rx = review_context(NasCipheringAlgorithm::Nea2);
        for count in [
            NasCount::new(0, 0xfe),
            NasCount::new(1, 0),
            NasCount::new(2, 0),
        ] {
            let envelope = reference_envelope(count, direction, 2);
            assert_eq!(
                rx.verify_and_decipher(&provider, direction, &envelope)
                    .unwrap()
                    .count,
                count
            );
        }
    }
}

#[test]
fn review_transmit_count_cannot_repeat_through_a_clone() {
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| Ok(key(0x11)));
    let tx = review_context(NasCipheringAlgorithm::Nea2);
    let clone = tx.clone();
    let first = tx
        .protect_payload(
            &provider,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"same payload",
        )
        .unwrap();
    let next = clone
        .protect_payload(
            &provider,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"same payload",
        )
        .unwrap();
    assert_ne!(first.sequence_number, next.sequence_number);
    assert_ne!(
        first.payload, next.payload,
        "NEA2 keystream must not repeat"
    );
}

fn restored_context(
    connection: opc_proto_nas::NasConnectionId,
    state: opc_proto_nas::NasCountState,
) -> NasSecurityContext {
    NasSecurityContext::new(
        NasIntegrityAlgorithm::Nia2,
        NasCipheringAlgorithm::Nea2,
        handle(KeyPurpose::Session),
        handle(KeyPurpose::Session),
        connection,
        state,
        state,
    )
    .unwrap()
}

fn reference_envelope(
    count: NasCount,
    direction: NasSecurityDirection,
    bearer: u8,
) -> opc_proto_nas::SecurityProtected {
    let payload = nea2_cipher(
        &key(0x11),
        NasAlgorithmInput::new(count.as_u32(), bearer, direction, 24).unwrap(),
        &[0x7e, 0, 0x43],
    )
    .unwrap();
    let mut message = vec![count.sequence_number()];
    message.extend_from_slice(&payload);
    let mac = nia2_mac(
        &key(0x11),
        NasAlgorithmInput::new(count.as_u32(), bearer, direction, 32).unwrap(),
        &message,
    )
    .unwrap();
    opc_proto_nas::SecurityProtected {
        security_header_type: SecurityHeaderType::IntegrityProtectedAndCiphered,
        spare: 0,
        mac,
        sequence_number: count.sequence_number(),
        payload,
    }
}

#[test]
fn review_restored_full_counts_estimate_wrap_and_preserve_each_direction() {
    use opc_proto_nas::{NasConnectionId, NasCountState};
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| Ok(key(0x11)));
    let initial = NasCountState {
        next_transmit: Some(NasCount::new(3, 0xfd)),
        highest_received: Some(NasCount::new(7, 0xfe)),
    };
    let ctx = restored_context(NasConnectionId::NonThreeGpp, initial);
    for direction in [NasSecurityDirection::Uplink, NasSecurityDirection::Downlink] {
        assert_eq!(ctx.count_for(direction, 0).unwrap(), NasCount::new(8, 0));
        let incoming = reference_envelope(NasCount::new(8, 0), direction, 2);
        assert_eq!(
            ctx.verify_and_decipher(&provider, direction, &incoming)
                .unwrap()
                .count,
            NasCount::new(8, 0)
        );
        let out = ctx
            .protect_payload(
                &provider,
                direction,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                b"restored",
            )
            .unwrap();
        assert_eq!(out.sequence_number, 0xfd);
        assert_eq!(
            ctx.count_state(direction).unwrap(),
            NasCountState {
                next_transmit: Some(NasCount::new(3, 0xfe)),
                highest_received: Some(NasCount::new(8, 0))
            }
        );
    }
}

#[test]
fn review_one_provider_keeps_connection_and_algorithm_keys_distinct() {
    use opc_proto_nas::{NasConnectionId, NasCountState};
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, usage: NasKeyUsage| match usage {
        NasKeyUsage::Integrity(NasIntegrityAlgorithm::Nia2) => Ok(key(0x11)),
        NasKeyUsage::Ciphering(NasCipheringAlgorithm::Nea2) => Ok(key(0x22)),
        _ => Err(NasSecurityError::KeyUnavailable),
    });
    let a = restored_context(NasConnectionId::ThreeGpp, NasCountState::default());
    let b = restored_context(NasConnectionId::NonThreeGpp, NasCountState::default());
    let mut ciphertexts = Vec::new();
    for (ctx, bearer) in [(&a, 1), (&b, 2)] {
        assert_eq!(ctx.connection_id().as_bearer(), bearer);
        let wire = ctx
            .protect_payload(
                &provider,
                NasSecurityDirection::Uplink,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                &[0x7e, 0, 0x43],
            )
            .unwrap();
        assert_eq!(
            wire.payload,
            nea2_cipher(
                &key(0x22),
                NasAlgorithmInput::new(0, bearer, NasSecurityDirection::Uplink, 24).unwrap(),
                &[0x7e, 0, 0x43]
            )
            .unwrap()
        );
        let mut message = vec![0];
        message.extend_from_slice(&wire.payload);
        assert_eq!(
            wire.mac,
            nia2_mac(
                &key(0x11),
                NasAlgorithmInput::new(0, bearer, NasSecurityDirection::Uplink, 32).unwrap(),
                &message
            )
            .unwrap()
        );
        ciphertexts.push(wire.payload);
    }
    assert_ne!(ciphertexts[0], ciphertexts[1]);
}

#[test]
fn review_concurrent_clones_reserve_unique_transmit_counts() {
    use opc_proto_nas::{NasConnectionId, NasCountState};
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| Ok(key(0x11)));
    let ctx = restored_context(NasConnectionId::NonThreeGpp, NasCountState::default());
    let sequences = std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..16)
            .map(|_| {
                let clone = ctx.clone();
                let provider = &provider;
                scope.spawn(move || {
                    (0..8)
                        .map(|_| {
                            clone
                                .protect_payload(
                                    provider,
                                    NasSecurityDirection::Uplink,
                                    SecurityHeaderType::IntegrityProtectedAndCiphered,
                                    b"concurrent",
                                )
                                .unwrap()
                                .sequence_number
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        jobs.into_iter()
            .flat_map(|job| job.join().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
    });
    assert_eq!(sequences, (0..128).collect());
    assert_eq!(
        ctx.count_state(NasSecurityDirection::Uplink)
            .unwrap()
            .next_transmit,
        Some(NasCount::new(0, 128))
    );
    assert_eq!(
        ctx.count_state(NasSecurityDirection::Downlink).unwrap(),
        NasCountState::default()
    );
}

#[test]
fn review_transmit_failure_burns_count_and_exhaustion_never_wraps() {
    use opc_proto_nas::{NasConnectionId, NasCountState};
    let fail = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| {
        Err(NasSecurityError::KeyUnavailable)
    });
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, _: NasKeyUsage| Ok(key(0x11)));
    let ctx = restored_context(NasConnectionId::NonThreeGpp, NasCountState::default());
    assert_eq!(
        ctx.protect_payload(
            &fail,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"failure"
        )
        .unwrap_err(),
        NasSecurityError::KeyUnavailable
    );
    let next = ctx
        .protect_payload(
            &provider,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"retry",
        )
        .unwrap();
    assert_eq!(next.sequence_number, 1);
    let final_state = NasCountState {
        next_transmit: Some(NasCount::new(u16::MAX, u8::MAX)),
        highest_received: Some(NasCount::new(u16::MAX, u8::MAX)),
    };
    let last = restored_context(NasConnectionId::NonThreeGpp, final_state);
    assert_eq!(
        last.protect_payload(
            &provider,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"last"
        )
        .unwrap()
        .sequence_number,
        255
    );
    let exhausted = last.count_state(NasSecurityDirection::Uplink).unwrap();
    assert!(exhausted.next_transmit.is_none());
    assert_eq!(
        last.protect_payload(
            &provider,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            b"overflow"
        )
        .unwrap_err(),
        NasSecurityError::InvalidCount
    );
    assert_eq!(
        last.count_for(NasSecurityDirection::Uplink, 0).unwrap_err(),
        NasSecurityError::InvalidCount
    );
    let restored = restored_context(NasConnectionId::NonThreeGpp, exhausted);
    assert_eq!(
        restored
            .protect_payload(
                &provider,
                NasSecurityDirection::Uplink,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                b"restored exhausted"
            )
            .unwrap_err(),
        NasSecurityError::InvalidCount
    );
}

#[test]
fn review_failed_decipher_does_not_consume_receive_count() {
    use opc_proto_nas::{NasConnectionId, NasCountState};
    use std::sync::atomic::{AtomicBool, Ordering};
    let available = AtomicBool::new(false);
    let provider = AesNasSecurityAlgorithms::new(|_: &KeyHandle, usage: NasKeyUsage| {
        if matches!(usage, NasKeyUsage::Ciphering(_)) && !available.load(Ordering::SeqCst) {
            Err(NasSecurityError::KeyUnavailable)
        } else {
            Ok(key(0x11))
        }
    });
    let ctx = restored_context(NasConnectionId::NonThreeGpp, NasCountState::default());
    let envelope = reference_envelope(NasCount::new(0, 1), NasSecurityDirection::Uplink, 2);
    assert_eq!(
        ctx.verify_and_decipher(&provider, NasSecurityDirection::Uplink, &envelope)
            .unwrap_err(),
        NasSecurityError::KeyUnavailable
    );
    assert_eq!(
        ctx.count_state(NasSecurityDirection::Uplink)
            .unwrap()
            .highest_received,
        None
    );
    available.store(true, Ordering::SeqCst);
    assert_eq!(
        ctx.verify_and_decipher(&provider, NasSecurityDirection::Uplink, &envelope)
            .unwrap()
            .payload
            .as_ref(),
        &[0x7e, 0, 0x43]
    );
}
