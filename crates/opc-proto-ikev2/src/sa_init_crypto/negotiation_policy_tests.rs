#[path = "../../tests/support/nonce.rs"]
mod peer_nonce_fixture;

use super::*;
use crate::*;
use opc_crypto_provider::{IkeDhGroup, IkeDiffieHellmanOperations};
use opc_protocol::DecodeContext;

fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => panic!("synthetic fixture failed: {error:?}"),
    }
}

fn profile(prf: Ikev2PrfAlgorithm, group: Ikev2DhGroup) -> Ikev2SaInitCryptoProfile {
    ok(Ikev2SaInitCryptoProfile::new_aead(
        prf,
        group,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    ))
}

fn offer(groups: &[u16], prf: Ikev2PrfAlgorithm) -> Ikev2SaPayloadBuild {
    let mut transforms = vec![
        Ikev2SaTransformBuild {
            transform_type: 1,
            transform_id: 20,
            attributes: vec![Ikev2TransformAttributeBuild {
                attribute_type: 14,
                value: Ikev2TransformAttributeBuildValue::Tv(128),
            }],
        },
        Ikev2SaTransformBuild {
            transform_type: 2,
            transform_id: prf.transform_id(),
            attributes: vec![],
        },
    ];
    transforms.extend(groups.iter().map(|group| Ikev2SaTransformBuild {
        transform_type: 4,
        transform_id: *group,
        attributes: vec![],
    }));
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: 1,
            spi: vec![],
            transforms,
        }],
    }
}

#[test]
fn group_one_remains_executable_in_default_software_admission_and_checkpoints() {
    crate::test_support::ensure_ike_crypto();
    assert_eq!(
        ok(Ikev2DhGroup::from_transform_id(1)),
        Ikev2DhGroup::Modp768
    );
    let legacy = profile(Ikev2PrfAlgorithm::HmacSha2_512, Ikev2DhGroup::Modp768);
    assert!(legacy.validate_executable().is_ok());
    let key = ok(Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Modp768));
    assert_eq!(key.public_value().len(), 96);
    let operations = Ikev2SoftwareCryptoOperations::new();
    assert!(operations.supports_dh_group(IkeDhGroup::Modp768));
    assert!(operations.supports_dh_checkpoint(IkeDhGroup::Modp768));
    let mut original = ok(operations.generate_keypair(IkeDhGroup::Modp768));
    let public = original.public_value().to_vec();
    let checkpoint = ok(original.export_private_checkpoint());
    drop(original);
    let restored =
        ok(operations.import_keypair_checkpoint(IkeDhGroup::Modp768, &checkpoint, &public));
    assert_eq!(restored.public_value(), public);
    assert_eq!(
        &*ok(restored.agree(key.public_value())),
        &*ok(key.agree(&public))
    );
    assert!(format!("{legacy:?}").contains("Modp768"));
}

#[test]
fn transcript_nonce_floor_accepts_legacy_peers_for_every_prf_role_and_exchange() {
    crate::test_support::ensure_ike_crypto();
    for prf in [
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2PrfAlgorithm::HmacSha2_384,
        Ikev2PrfAlgorithm::HmacSha2_512,
    ] {
        let parent = profile(prf, Ikev2DhGroup::Modp768);
        let child =
            Ikev2ChildSaCryptoProfile::new_aead(prf, Ikev2EncryptionAlgorithm::AesGcm16_128);
        let sk_d = vec![0x44; prf.output_len()];
        for role in ["initiator", "responder"] {
            for length in [15, 16, 17, 24, 31, 32, 256, 257] {
                let peer = vec![0x11; length];
                let local = [0x22; 32];
                let (ni, nr): (&[u8], &[u8]) = if role == "initiator" {
                    (&peer, &local)
                } else {
                    (&local, &peer)
                };
                let mut results = vec![
                    derive_ike_sa_rekey_key_material(
                        if role == "initiator" {
                            Ikev2NonceLocalRole::Responder
                        } else {
                            Ikev2NonceLocalRole::Initiator
                        },
                        prf,
                        &sk_d,
                        parent,
                        [0x11; 8],
                        [0x22; 8],
                        ni,
                        nr,
                        &[0x33; 96],
                    )
                    .map(|_| ()),
                    derive_child_sa_key_material(
                        if role == "initiator" {
                            Ikev2NonceLocalRole::Responder
                        } else {
                            Ikev2NonceLocalRole::Initiator
                        },
                        child,
                        &sk_d,
                        ni,
                        nr,
                        None,
                    )
                    .map(|_| ()),
                ];
                for policy in [
                    Ikev2InitialExchangeNoncePolicy::Strict,
                    Ikev2InitialExchangeNoncePolicy::AllowLegacyInitiatorPrfHmacSha2_512Minimum,
                ] {
                    results.push(
                        derive_ike_sa_init_key_material_with_nonce_policy(
                            if role == "initiator" {
                                Ikev2NonceLocalRole::Responder
                            } else {
                                Ikev2NonceLocalRole::Initiator
                            },
                            parent,
                            [0x11; 8],
                            [0x22; 8],
                            ni,
                            nr,
                            &[0x33; 96],
                            None,
                            policy,
                        )
                        .map(|_| ()),
                    );
                    results.push(
                        derive_initial_child_sa_key_material(
                            if role == "initiator" {
                                Ikev2NonceLocalRole::Responder
                            } else {
                                Ikev2NonceLocalRole::Initiator
                            },
                            child,
                            &sk_d,
                            ni,
                            nr,
                            policy,
                        )
                        .map(|_| ()),
                    );
                }
                for result in results {
                    if (16..=256).contains(&length) {
                        assert!(result.is_ok(), "{prf:?}, {role}, {length}");
                    } else {
                        assert_eq!(
                            result,
                            Err(Ikev2SaInitCryptoError::InvalidNonceLength { role, len: length })
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn stronger_common_group_wins_even_when_group_one_policy_and_ke_come_first() {
    for stronger in [
        Ikev2DhGroup::Modp1024,
        Ikev2DhGroup::Modp2048,
        Ikev2DhGroup::Ecp256,
        Ikev2DhGroup::Ecp384,
        Ikev2DhGroup::Ecp521,
    ] {
        let prf = Ikev2PrfAlgorithm::HmacSha2_512;
        let legacy = profile(prf, Ikev2DhGroup::Modp768);
        let strong = profile(prf, stronger);
        let policy = ok(Ikev2SaInitNegotiationPolicy::new(vec![legacy, strong]));
        let encoded = ok(crate::sa_init::encode_sa_payload_build(&offer(
            &[1, stronger.transform_id()],
            prf,
        )));
        let mut payloads = Ikev2SaInitPayloads {
            security_association: ok(Ikev2SaPayload::decode_body(&encoded)),
            key_exchange: Ikev2KeyExchangePayload {
                dh_group: 1,
                key_exchange_data: &[2; 96],
            },
            nonce: Ikev2NoncePayload { nonce: &[3; 16] },
            notifies: vec![],
            vendor_ids: vec![],
            other_payload_count: 0,
        };
        assert_eq!(
            negotiate_ike_sa_init(&payloads, &policy),
            Err(Ikev2SaInitNegotiationError::KeyExchangeDhGroupMismatch {
                received: 1,
                preferred: stronger.transform_id()
            })
        );
        let public = vec![2; stronger.public_value_len()];
        payloads.key_exchange = Ikev2KeyExchangePayload {
            dh_group: stronger.transform_id(),
            key_exchange_data: &public,
        };
        assert_eq!(
            ok(negotiate_ike_sa_init(&payloads, &policy)).profile(),
            strong
        );
        let only_legacy = ok(Ikev2SaInitNegotiationPolicy::new(vec![legacy]));
        payloads.key_exchange = Ikev2KeyExchangePayload {
            dh_group: 1,
            key_exchange_data: &[2; 96],
        };
        assert_eq!(
            ok(negotiate_ike_sa_init(&payloads, &only_legacy)).profile(),
            legacy
        );
        let encoded = ok(crate::sa_init::encode_sa_payload_build(&offer(&[1], prf)));
        payloads.security_association = ok(Ikev2SaPayload::decode_body(&encoded));
        assert_eq!(
            ok(negotiate_ike_sa_init(&payloads, &policy)).profile(),
            legacy
        );
    }
}

#[test]
fn ike_rekey_prefers_stronger_common_group_for_either_original_ike_role() {
    let prf = Ikev2PrfAlgorithm::HmacSha2_512;
    let legacy = profile(prf, Ikev2DhGroup::Modp768);
    let strong = profile(prf, Ikev2DhGroup::Modp2048);
    let policy = ok(Ikev2SaInitNegotiationPolicy::new(vec![legacy, strong]));
    let mut offered = offer(&[1, 14], prf);
    offered.proposals[0].spi = vec![0x55; 8];
    for original_initiator in [false, true] {
        for group in [1, 14] {
            let entries = vec![
                Ikev2IkeAuthPayloadBuild {
                    payload_type: PayloadType::SecurityAssociation,
                    body: ok(build_ike_auth_sa_payload(&offered)),
                },
                Ikev2IkeAuthPayloadBuild {
                    payload_type: PayloadType::Nonce,
                    body: vec![0x11; 16],
                },
                Ikev2IkeAuthPayloadBuild {
                    payload_type: PayloadType::KeyExchange,
                    body: ok(crate::sa_init::encode_ke_payload_build(
                        &Ikev2KeyExchangePayloadBuild {
                            dh_group: group,
                            key_exchange_data: vec![2; if group == 1 { 96 } else { 256 }],
                        },
                    )),
                },
            ];
            let (first, wire) = ok(build_ike_auth_cleartext_payload_chain(&entries));
            let header = Header::new(
                11,
                22,
                PayloadType::Encrypted,
                EXCHANGE_TYPE_CREATE_CHILD_SA,
                HeaderFlags::from_bits(original_initiator, false, false),
                7,
            );
            let request = ok(decode_ike_sa_rekey_request(&header, first, &wire));
            if group == 1 {
                assert_eq!(
                    negotiate_ike_sa_rekey(&request, &policy),
                    Err(Ikev2SaInitNegotiationError::KeyExchangeDhGroupMismatch {
                        received: 1,
                        preferred: 14
                    })
                );
                assert_eq!(
                    ok(negotiate_ike_sa_rekey(
                        &request,
                        &ok(Ikev2SaInitNegotiationPolicy::new(vec![legacy]))
                    ))
                    .profile(),
                    legacy
                );
            } else {
                assert_eq!(
                    ok(negotiate_ike_sa_rekey(&request, &policy)).profile(),
                    strong
                );
            }
        }
    }
}

#[test]
fn initiator_offers_stronger_groups_first_and_keeps_group_one_fallback() {
    crate::test_support::ensure_ike_crypto();
    let prf = Ikev2PrfAlgorithm::HmacSha2_512;
    let legacy_key = ok(Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Modp768));
    for alternatives in [false, true] {
        let mut offered = offer(&[1], prf);
        if alternatives {
            offered = offer(&[1, 14], prf);
        } else {
            let mut stronger = offer(&[14], prf).proposals.remove(0);
            stronger.proposal_number = 2;
            offered.proposals.push(stronger);
        }
        let request = ok(build_ike_sa_init_request(
            11,
            &offered,
            &legacy_key,
            &[0x22; 32],
            &[],
        ));
        let message = request.message().as_borrowed();
        let wire = ok(decode_ike_sa_init_request_payloads(
            &message,
            DecodeContext::default(),
        ));
        let groups: Vec<_> = wire
            .security_association
            .proposals
            .iter()
            .flat_map(|p| &p.transforms)
            .filter(|t| t.transform_type == 4)
            .map(|t| t.transform_id)
            .collect();
        assert_eq!(groups, [14, 1]);
        let legacy = profile(prf, Ikev2DhGroup::Modp768);
        let selection = ok(negotiate_ike_sa_init(
            &wire,
            &ok(Ikev2SaInitNegotiationPolicy::new(vec![legacy])),
        ));
        let responder_key = ok(Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Modp768));
        let response = ok(build_ike_sa_init_response(
            &message.header,
            22,
            &Ikev2SaInitResponsePayloads {
                security_association: selection.response_security_association(),
                key_exchange: Ikev2KeyExchangePayloadBuild {
                    dh_group: 1,
                    key_exchange_data: responder_key.public_value().to_vec(),
                },
                nonce: Ikev2NoncePayloadBuild {
                    nonce: vec![0x33; 32],
                },
                notifies: vec![],
            },
        ));
        let mut response = response;
        response.raw_payloads = peer_nonce_fixture::replace_nonce(
            response.header.next_payload,
            &response.raw_payloads,
            &[0x33; 16],
        )
        .into();
        response.header.length =
            28 + u32::try_from(response.raw_payloads.len()).expect("fixture length");
        let accepted = ok(admit_ike_sa_init_response(
            &request,
            &response.as_borrowed(),
            DecodeContext::default(),
        ));
        assert!(
            matches!(accepted, Ikev2SaInitResponse::Accepted(ref a) if a.profile()==legacy && a.nonce().len()==16)
        );
    }
}

#[test]
fn local_initiator_nonce_floor_is_32_for_every_offered_prf() {
    crate::test_support::ensure_ike_crypto();
    let key = ok(Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Modp768));
    for prf in [
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2PrfAlgorithm::HmacSha2_384,
        Ikev2PrfAlgorithm::HmacSha2_512,
    ] {
        for len in [16, 24, 31] {
            assert_eq!(
                build_ike_sa_init_request(11, &offer(&[1], prf), &key, &vec![0x22; len], &[]).err(),
                Some(Ikev2SaInitInitiatorError::InvalidInitiatorNonce)
            );
        }
        assert!(build_ike_sa_init_request(11, &offer(&[1], prf), &key, &[0x22; 32], &[]).is_ok());
    }
}

#[test]
fn generated_nonces_use_admitted_entropy_and_satisfy_both_roles_and_exchanges() {
    crate::test_support::ensure_ike_crypto();
    for prf in [
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2PrfAlgorithm::HmacSha2_384,
        Ikev2PrfAlgorithm::HmacSha2_512,
    ] {
        for _role in ["initiator", "responder"] {
            for _exchange in ["initial", "rekey"] {
                let first = ok(Ikev2NoncePayloadBuild::generate(prf));
                let second = ok(Ikev2NoncePayloadBuild::generate(prf));
                assert!(first.nonce.len() >= 32);
                assert!(first.nonce.len() >= prf.output_len().div_ceil(2));
                assert_ne!(first.nonce, second.nonce);
            }
        }
    }
}

#[test]
fn ordered_policy_retains_a_legacy_only_rekey_initiator_offer() {
    let prf = Ikev2PrfAlgorithm::HmacSha2_512;
    let legacy = profile(prf, Ikev2DhGroup::Modp768);
    let strong = profile(prf, Ikev2DhGroup::Modp2048);
    for common in [vec![legacy], vec![legacy, strong]] {
        let policy = ok(Ikev2SaInitNegotiationPolicy::new(common));
        let preferred = policy.preferred_profiles()[0];
        assert_eq!(
            preferred,
            if policy.preferred_profiles().len() == 1 {
                legacy
            } else {
                strong
            }
        );
        let payloads = ok(build_ike_sa_rekey_request(&Ikev2IkeSaRekeyRequestBuild {
            profile: preferred,
            new_initiator_spi: [0x55; 8],
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x22; 32],
            },
            key_exchange: Ikev2KeyExchangePayloadBuild {
                dh_group: preferred.dh_group().transform_id(),
                key_exchange_data: vec![2; preferred.dh_group().public_value_len()],
            },
        }));
        for initiator_flag in [false, true] {
            let header = Header::new(
                11,
                22,
                PayloadType::Encrypted,
                EXCHANGE_TYPE_CREATE_CHILD_SA,
                HeaderFlags::from_bits(initiator_flag, false, false),
                7,
            );
            let request = ok(decode_ike_sa_rekey_request(
                &header,
                payloads.first_payload(),
                payloads.bytes(),
            ));
            assert_eq!(
                ok(negotiate_ike_sa_rekey(&request, &policy)).profile(),
                preferred
            );
        }
    }
}

#[test]
fn rekey_initiator_accepts_legacy_peer_nonce_and_generates_a_long_local_nonce() {
    crate::test_support::ensure_ike_crypto();
    let prf = Ikev2PrfAlgorithm::HmacSha2_512;
    for group in [Ikev2DhGroup::Modp768, Ikev2DhGroup::Modp2048] {
        let profile = profile(prf, group);
        let policy = ok(Ikev2SaInitNegotiationPolicy::new(vec![profile]));
        for original_initiator in [false, true] {
            let local = ok(Ikev2EphemeralDhKey::generate(group));
            let peer = ok(Ikev2EphemeralDhKey::generate(group));
            let nonce = ok(Ikev2NoncePayloadBuild::generate(prf));
            assert!(nonce.nonce.len() >= 32);
            let input = Ikev2IkeSaRekeyRequestBuild {
                profile,
                new_initiator_spi: [0x55; 8],
                nonce: nonce.clone(),
                key_exchange: Ikev2KeyExchangePayloadBuild {
                    dh_group: group.transform_id(),
                    key_exchange_data: local.public_value().to_vec(),
                },
            };
            let sent = ok(build_ike_sa_rekey_request(&input));
            let header = Header::new(
                11,
                22,
                PayloadType::Encrypted,
                EXCHANGE_TYPE_CREATE_CHILD_SA,
                HeaderFlags::from_bits(original_initiator, false, false),
                7,
            );
            let request = ok(decode_ike_sa_rekey_request(
                &header,
                sent.first_payload(),
                sent.bytes(),
            ));
            let negotiation = ok(negotiate_ike_sa_rekey(&request, &policy));
            let response = ok(build_ike_sa_rekey_response(&Ikev2IkeSaRekeyResponseBuild {
                negotiation,
                new_responder_spi: [0x66; 8],
                nonce: Ikev2NoncePayloadBuild {
                    nonce: vec![0x33; 32],
                },
                key_exchange: Ikev2KeyExchangePayloadBuild {
                    dh_group: group.transform_id(),
                    key_exchange_data: peer.public_value().to_vec(),
                },
            }));
            let header = Header::new(
                11,
                22,
                PayloadType::Encrypted,
                EXCHANGE_TYPE_CREATE_CHILD_SA,
                HeaderFlags::from_bits(!original_initiator, true, false),
                7,
            );
            let peer_wire = peer_nonce_fixture::replace_nonce(
                response.first_payload().as_u8(),
                response.bytes(),
                &[0x33; 16],
            );
            let context = Ikev2IkeSaRekeySentRequest {
                old_initiator_spi: 11,
                old_responder_spi: 22,
                profile,
            };
            let accepted = ok(decode_ike_sa_rekey_response(
                &header,
                &context,
                response.first_payload(),
                &peer_wire,
            ));
            assert_eq!(accepted.nonce().nonce.len(), 16);
            let material = ok(derive_ike_sa_rekey_key_material(
                crate::Ikev2NonceLocalRole::Initiator,
                prf,
                &[0x44; 64],
                profile,
                [0x55; 8],
                [0x66; 8],
                &nonce.nonce,
                accepted.nonce().nonce,
                &ok(local.agree(peer.public_value())),
            ));
            assert_eq!(material.sk_d().len(), 64);
            let mut short = peer_wire.clone();
            let nonce = ok(PayloadChain::new(response.first_payload(), &short)
                .iter()
                .find(|p| {
                    p.as_ref()
                        .is_ok_and(|p| p.payload_type == PayloadType::Nonce)
                })
                .ok_or("missing nonce"));
            let offset = ok(nonce).offset;
            short[offset + 2..offset + 4].copy_from_slice(&19u16.to_be_bytes());
            short.remove(offset + 19);
            assert!(matches!(
                decode_ike_sa_rekey_response(&header, &context, response.first_payload(), &short),
                Err(Ikev2IkeSaRekeyResponseError::Nonce(
                    Ikev2NoncePayloadError::NonceTooShort
                ))
            ));
        }
    }
}

#[test]
fn outgoing_initial_response_rejects_a_short_local_nonce() {
    let request = Header::new(
        11,
        0,
        PayloadType::SecurityAssociation,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    for len in [16, 24, 31, 32] {
        let result = build_ike_sa_init_response(
            &request,
            22,
            &Ikev2SaInitResponsePayloads {
                security_association: offer(&[1], Ikev2PrfAlgorithm::HmacSha2_512),
                key_exchange: Ikev2KeyExchangePayloadBuild {
                    dh_group: 1,
                    key_exchange_data: vec![2; 96],
                },
                nonce: Ikev2NoncePayloadBuild {
                    nonce: vec![3; len],
                },
                notifies: vec![],
            },
        );
        if len < 32 {
            assert_eq!(result, Err(Ikev2SaInitBuildError::NonceTooShort));
        } else {
            assert!(result.is_ok());
        }
    }
}

fn outgoing_rekey_fixture() -> Ikev2IkeSaRekeyRequestBuild {
    Ikev2IkeSaRekeyRequestBuild {
        profile: profile(Ikev2PrfAlgorithm::HmacSha2_512, Ikev2DhGroup::Modp768),
        new_initiator_spi: [0x55; 8],
        nonce: Ikev2NoncePayloadBuild { nonce: vec![3; 32] },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 1,
            key_exchange_data: vec![2; 96],
        },
    }
}

#[test]
fn outgoing_ike_rekey_request_rejects_a_short_local_nonce() {
    for len in [16, 24, 31, 32] {
        let mut input = outgoing_rekey_fixture();
        input.nonce.nonce.resize(len, 3);
        let result = build_ike_sa_rekey_request(&input);
        if len < 32 {
            assert_eq!(
                result,
                Err(Ikev2IkeSaRekeyRequestBuildError::Nonce(
                    Ikev2SaInitBuildError::NonceTooShort
                ))
            );
        } else {
            assert!(result.is_ok());
        }
    }
}

#[test]
fn outgoing_ike_rekey_response_rejects_a_short_local_nonce() {
    for original_initiator in [false, true] {
        let input = outgoing_rekey_fixture();
        let wire = ok(build_ike_sa_rekey_request(&input));
        let header = Header::new(
            11,
            22,
            PayloadType::Encrypted,
            EXCHANGE_TYPE_CREATE_CHILD_SA,
            HeaderFlags::from_bits(original_initiator, false, false),
            7,
        );
        let request = ok(decode_ike_sa_rekey_request(
            &header,
            wire.first_payload(),
            wire.bytes(),
        ));
        let policy = ok(Ikev2SaInitNegotiationPolicy::new(vec![input.profile]));
        for len in [16, 24, 31, 32] {
            let result = build_ike_sa_rekey_response(&Ikev2IkeSaRekeyResponseBuild {
                negotiation: ok(negotiate_ike_sa_rekey(&request, &policy)),
                new_responder_spi: [0x66; 8],
                nonce: Ikev2NoncePayloadBuild {
                    nonce: vec![4; len],
                },
                key_exchange: input.key_exchange.clone(),
            });
            if len < 32 {
                assert_eq!(
                    result,
                    Err(Ikev2IkeSaRekeyBuildError::Nonce(
                        Ikev2SaInitBuildError::NonceTooShort
                    ))
                );
            } else {
                assert!(result.is_ok());
            }
        }
    }
}

#[test]
fn key_derivation_rejects_short_local_nonces_in_each_exchange_role() {
    crate::test_support::ensure_ike_crypto();
    for prf in [
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2PrfAlgorithm::HmacSha2_384,
        Ikev2PrfAlgorithm::HmacSha2_512,
    ] {
        let parent = profile(prf, Ikev2DhGroup::Modp768);
        let child =
            Ikev2ChildSaCryptoProfile::new_aead(prf, Ikev2EncryptionAlgorithm::AesGcm16_128);
        let sk_d = vec![4; prf.output_len()];
        for local_initiator in [false, true] {
            for len in [16, 24, 31] {
                let local = vec![3; len];
                let peer = vec![5; 32];
                let (ni, nr, role) = if local_initiator {
                    (local.as_slice(), peer.as_slice(), "initiator")
                } else {
                    (peer.as_slice(), local.as_slice(), "responder")
                };
                let mut results = vec![
                    derive_ike_sa_init_key_material(
                        if local_initiator {
                            Ikev2NonceLocalRole::Initiator
                        } else {
                            Ikev2NonceLocalRole::Responder
                        },
                        parent,
                        [1; 8],
                        [2; 8],
                        ni,
                        nr,
                        &[2; 96],
                        None,
                    )
                    .map(|_| ()),
                    derive_ike_sa_rekey_key_material(
                        if local_initiator {
                            Ikev2NonceLocalRole::Initiator
                        } else {
                            Ikev2NonceLocalRole::Responder
                        },
                        prf,
                        &sk_d,
                        parent,
                        [1; 8],
                        [2; 8],
                        ni,
                        nr,
                        &[2; 96],
                    )
                    .map(|_| ()),
                    derive_child_sa_key_material(
                        if local_initiator {
                            Ikev2NonceLocalRole::Initiator
                        } else {
                            Ikev2NonceLocalRole::Responder
                        },
                        child,
                        &sk_d,
                        ni,
                        nr,
                        None,
                    )
                    .map(|_| ()),
                    derive_initial_child_sa_key_material(
                        if local_initiator {
                            Ikev2NonceLocalRole::Initiator
                        } else {
                            Ikev2NonceLocalRole::Responder
                        },
                        child,
                        &sk_d,
                        ni,
                        nr,
                        Ikev2InitialExchangeNoncePolicy::Strict,
                    )
                    .map(|_| ()),
                ];
                for policy in [
                    Ikev2InitialExchangeNoncePolicy::Strict,
                    Ikev2InitialExchangeNoncePolicy::AllowLegacyInitiatorPrfHmacSha2_512Minimum,
                ] {
                    let local_role = if local_initiator {
                        Ikev2NonceLocalRole::Initiator
                    } else {
                        Ikev2NonceLocalRole::Responder
                    };
                    results.push(
                        derive_ike_sa_init_key_material_with_nonce_policy(
                            local_role, parent, [1; 8], [2; 8], ni, nr, &[2; 96], None, policy,
                        )
                        .map(|_| ()),
                    );
                    results.push(
                        derive_initial_child_sa_key_material(
                            local_role, child, &sk_d, ni, nr, policy,
                        )
                        .map(|_| ()),
                    );
                }
                for result in results {
                    assert_eq!(
                        result,
                        Err(Ikev2SaInitCryptoError::InvalidNonceLength { role, len }),
                        "{prf:?} local {role}"
                    );
                }
            }
        }
    }
}
