//! Independent cryptographic evidence for the synthetic N3IWF key handoff.

use std::sync::OnceLock;

use opc_crypto_provider::ProviderPolicy;
use opc_n3iwf_fixtures::FixtureCatalog;
use opc_proto_ikev2::{
    build_ike_auth_authentication_payload, compute_ike_auth_shared_key_mic,
    derive_ike_sa_init_key_material, install_ikev2_software_crypto_module,
    verify_ike_auth_shared_key_mic, Ikev2AuthenticationPayload, Ikev2AuthenticationPayloadBuild,
    Ikev2CryptoRequirements, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2KeyExchangePayload, Ikev2NoncePayload, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SaPayload, Message, PayloadType,
};
use opc_protocol::{BorrowDecode, DecodeContext};
use serde_json::Value;

const SCOPE: &str = "ike-auth-known-answer";
const PROFILE: &str = "prf-hmac-sha256-aes-gcm16-256-ecp256";

#[test]
fn imported_consume_once_msk_matches_every_independent_auth_case() {
    use opc_proto_ikev2::protocol_key::{
        Ikev2ProtocolKeyAssociation, Ikev2ProtocolKeyError, Ikev2ProtocolKeyPurpose,
    };
    use std::num::NonZeroU64;
    use zeroize::Zeroizing;

    let reference = reference();
    let cases = reference["cases"].as_array().expect("reviewed cases");
    let initiator = Inputs::new(
        &cases
            .iter()
            .find(|case| case["name"] == "auth-initiator-known-answer")
            .expect("initiator case")["inputs"],
    );
    let responder = Inputs::new(
        &cases
            .iter()
            .find(|case| case["name"] == "auth-responder-known-answer")
            .expect("responder case")["inputs"],
    );
    let mut count = 0;
    for case in cases {
        let current = Inputs::new(&case["inputs"]);
        let association = Ikev2ProtocolKeyAssociation::new(NonZeroU64::new(1).unwrap());
        let operation = association
            .begin_ike_auth(
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
                profile(),
            )
            .unwrap();
        let key = operation.import(
            Ikev2ProtocolKeyPurpose::N3iwfMsk,
            Zeroizing::new(current.auth_key.clone()),
        );
        if case["reference_error"] == "authentication-key-empty" {
            assert_eq!(key.unwrap_err(), Ikev2ProtocolKeyError::InvalidKeyLength);
            count += 1;
            continue;
        }
        let key = key.expect("synthetic imported key");
        let (left, right) = match current.peer {
            Ikev2IkeAuthPeer::Initiator => (current.signed(), responder.signed()),
            Ikev2IkeAuthPeer::Responder => (initiator.signed(), current.signed()),
        };
        let auth = key
            .consume_ike_auth(&operation, &current.material, left, right, 4096)
            .expect("bounded AUTH derivation");
        let wire = octets(&case["wire_hex"]);
        let result = Ikev2AuthenticationPayload::decode_body(&wire)
            .map_err(|_| Ikev2ProtocolKeyError::AuthenticationFailed)
            .and_then(|payload| auth.verify(current.peer, &payload));
        assert_eq!(
            result.is_ok(),
            case["reference_error"].is_null(),
            "synthetic case {}",
            case["name"]
        );
        if result.is_ok() {
            assert!(
                auth.authentication_data(current.peer) == &wire[4..],
                "independent AUTH bytes"
            );
        }
        assert_eq!(
            key.consume_ike_auth(&operation, &current.material, left, right, 4096)
                .unwrap_err(),
            Ikev2ProtocolKeyError::Retired
        );
        count += 1;
    }
    assert_eq!(count, 30);
}

fn reference() -> Value {
    serde_json::from_str(include_str!("../oracles/ike-auth-sha256.json")).expect("reference")
}

fn octets(value: &Value) -> Vec<u8> {
    let value = value.as_str().expect("hex string");
    assert!(value.is_ascii() && value.len().is_multiple_of(2));
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).expect("hex"))
        .collect()
}

fn answer_octets(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .expect("known-answer octets")
        .iter()
        .map(|octet| u8::try_from(octet.as_u64().expect("unsigned octet")).expect("octet bound"))
        .collect()
}

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .expect("declared reference profile")
}

fn ensure_crypto() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let mut requirements = Ikev2CryptoRequirements::new();
        requirements
            .require_ike_sa_profile(profile())
            .expect("profile admission");
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        let _admission = install_ikev2_software_crypto_module(policy, requirements)
            .expect("test crypto admission");
    });
}

// Deliberately no Debug implementation: assertions print case names and
// constant errors, never the values carried across the key boundary.
struct Inputs {
    material: Ikev2SaInitKeyMaterial,
    peer: Ikev2IkeAuthPeer,
    message: Vec<u8>,
    nonce: Vec<u8>,
    identity: Vec<u8>,
    auth_key: Vec<u8>,
}

impl Inputs {
    fn new(value: &Value) -> Self {
        ensure_crypto();
        Self {
            material: derive_ike_sa_init_key_material(
                profile(),
                octets(&value["initiator_spi"])
                    .as_slice()
                    .try_into()
                    .expect("SPI size"),
                octets(&value["responder_spi"])
                    .as_slice()
                    .try_into()
                    .expect("SPI size"),
                &octets(&value["initiator_nonce"]),
                &octets(&value["responder_nonce"]),
                &octets(&value["dh_shared"]),
                None,
            )
            .expect("synthetic key derivation"),
            peer: match value["signing_peer"].as_str().expect("peer") {
                "initiator" => Ikev2IkeAuthPeer::Initiator,
                "responder" => Ikev2IkeAuthPeer::Responder,
                _ => panic!("unknown reference peer"),
            },
            message: octets(&value["ike_sa_init_message"]),
            nonce: octets(&value["peer_nonce"]),
            identity: octets(&value["identity_payload_body"]),
            auth_key: octets(&value["auth_keying_material"]),
        }
    }

    fn signed(&self) -> Ikev2IkeAuthSignedOctets<'_> {
        Ikev2IkeAuthSignedOctets {
            peer: self.peer,
            ike_sa_init_message: &self.message,
            peer_nonce: &self.nonce,
            identity_payload_body: &self.identity,
        }
    }

    fn verify(&self, wire: &[u8]) -> Result<(), &'static str> {
        let auth = Ikev2AuthenticationPayload::decode_body(wire).map_err(|error| error.as_str())?;
        verify_ike_auth_shared_key_mic(
            profile(),
            &self.material,
            self.signed(),
            &self.auth_key,
            &auth,
        )
        .map_err(|error| error.as_str())
    }
}

#[test]
fn protocol_key_subset_has_independent_auth_answers_for_both_peers() {
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "protocol-key")
        .expect("reviewed key fixture subset");
    for peer in ["initiator", "responder"] {
        assert!(
            catalog.manifests().any(|(manifest, _)| {
                manifest.validation_scope == "ike-auth-known-answer"
                    && manifest.case_class == "positive"
                    && manifest.context["auth_peer"] == peer
            }),
            "independent key-handoff AUTH answer missing for {peer}"
        );
    }
    for (manifest, _) in catalog.manifests() {
        assert!(matches!(
            manifest.validation_scope.as_str(),
            SCOPE | "handle-lifecycle-contract" | "protocol-key-lifecycle"
        ));
    }
}

#[test]
fn every_recorded_auth_answer_and_rejection_exercises_the_sdk() {
    let reference = reference();
    assert_eq!(reference["profile"], PROFILE);
    let cases = reference["cases"].as_array().expect("cases");
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "protocol-key")
        .expect("key catalog");
    let mut count = 0;
    for (manifest, wire) in catalog
        .manifests()
        .filter(|(m, _)| m.validation_scope == SCOPE)
    {
        count += 1;
        let name = manifest
            .sdk_fixture_id
            .split(".v1.")
            .nth(1)
            .expect("case name");
        let case = cases
            .iter()
            .find(|c| c["name"] == name)
            .expect("reference case");
        assert!(octets(&case["wire_hex"]) == wire, "{name}: published wire");
        assert!(
            manifest.context["inputs"] == case["inputs"],
            "{name}: published inputs"
        );
        assert_eq!(manifest.context["crypto_profile"], PROFILE);
        assert_eq!(manifest.context["sdk_custody_validation"], false);
        let inputs = Inputs::new(&manifest.context["inputs"]);
        let expected = match case["reference_error"].as_str() {
            None => Ok(()),
            Some("authentication-failed") => Err("ike_auth_verify_authentication_failed"),
            Some("authentication-data-length") => Err("ike_auth_verify_auth_data_length"),
            Some("authentication-too-short") => Err("ike_auth_auth_too_short"),
            Some("unsupported-authentication-method") => {
                Err("ike_auth_verify_unsupported_auth_method")
            }
            Some("authentication-key-empty") => Err("ike_auth_verify_auth_key_empty"),
            Some(_) => panic!("unreviewed reference error"),
        };
        assert_eq!(inputs.verify(wire), expected, "{name}");
        if manifest.case_class == "positive" {
            for (field, actual) in [
                ("skeyseed", inputs.material.skeyseed()),
                ("sk_d", inputs.material.sk_d()),
                ("sk_ai", inputs.material.sk_ai()),
                ("sk_ar", inputs.material.sk_ar()),
                ("sk_ei", inputs.material.sk_ei()),
                ("sk_er", inputs.material.sk_er()),
                ("sk_pi", inputs.material.sk_pi()),
                ("sk_pr", inputs.material.sk_pr()),
            ] {
                assert!(
                    actual == answer_octets(&reference["expected_octets"][field]),
                    "{name}: {field}"
                );
            }
            let mic = compute_ike_auth_shared_key_mic(
                profile(),
                &inputs.material,
                inputs.signed(),
                &inputs.auth_key,
            )
            .expect("AUTH calculation");
            let body = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
                auth_method: 2,
                auth_data: mic,
            })
            .expect("AUTH body");
            assert!(body == wire, "{name}: independent answer");
        }
    }
    assert_eq!(count, cases.len());
    assert_eq!(count, 30);
}

#[test]
fn complete_sa_init_inputs_decode_to_the_declared_profile() {
    let reference = reference();
    for case in reference["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|c| c["case_class"] == "positive")
    {
        let inputs = Inputs::new(&case["inputs"]);
        let peer = case["auth_peer"].as_str().expect("peer");
        let initiator = peer == "initiator";
        let (tail, message) =
            Message::decode(&inputs.message, DecodeContext::default()).expect("complete SA_INIT");
        assert!(tail.is_empty());
        assert_eq!(message.header.exchange_type, 34);
        assert_eq!(message.header.message_id, 0);
        assert_eq!(message.header.flags.initiator(), initiator);
        assert_eq!(message.header.flags.response(), !initiator);
        assert_eq!(message.header.responder_spi == 0, initiator);
        let payloads = message
            .payloads()
            .collect::<Result<Vec<_>, _>>()
            .expect("payload chain");
        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads[0].payload_type, PayloadType::SecurityAssociation);
        let sa = Ikev2SaPayload::decode(payloads[0]).expect("SA");
        assert_eq!(sa.proposals.len(), 1);
        assert_eq!(sa.proposals[0].protocol_id, 1);
        assert!(sa.proposals[0].spi.is_empty());
        let transforms = &sa.proposals[0].transforms;
        assert_eq!(
            transforms
                .iter()
                .map(|t| (t.transform_type, t.transform_id))
                .collect::<Vec<_>>(),
            [(1, 20), (2, 5), (4, 19)]
        );
        assert_eq!(transforms[0].attributes.len(), 1);
        assert_eq!(transforms[0].attributes[0].attribute_type, 14);
        assert!(matches!(
            transforms[0].attributes[0].value,
            opc_proto_ikev2::Ikev2TransformAttributeValue::Tv(256)
        ));
        assert!(transforms[1].attributes.is_empty() && transforms[2].attributes.is_empty());
        let ke = Ikev2KeyExchangePayload::decode(payloads[1]).expect("KE");
        assert_eq!(ke.dh_group, 19);
        assert!(ke.key_exchange_data == octets(&reference["public_values"][peer]));
        let nonce = Ikev2NoncePayload::decode(payloads[2]).expect("Nonce");
        assert!(
            nonce.nonce
                == octets(
                    &case["inputs"][if initiator {
                        "initiator_nonce"
                    } else {
                        "responder_nonce"
                    }]
                )
        );
    }
}

#[test]
fn ngap_security_key_placeholder_supplies_both_auth_known_answers() {
    let reference = reference();
    let ngap = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "ngap")
        .expect("NGAP catalog");
    let (_, wire) = ngap
        .manifests()
        .find(|(m, _)| {
            m.sdk_fixture_id
                == reference["ngap_fixture_id"]
                    .as_str()
                    .expect("handoff fixture")
        })
        .expect("initial context request");
    let pdu = opc_proto_ngap::decode(wire, DecodeContext::default()).expect("NGAP request");
    let opc_proto_ngap::PduKind::Initiating {
        message: opc_proto_ngap::Message::InitialContextSetupRequest(request),
        ..
    } = pdu.kind
    else {
        panic!("wrong key-handoff message")
    };
    let keys = request
        .protocol_ies
        .0
        .iter()
        .filter(|ie| ie.id == 94)
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 1);
    // The independent ASN.1 gate validates this fixed 256-bit SecurityKey
    // encoding. This passes its placeholder octets to the existing IKE API;
    // it does not claim a typed or consume-once key import implementation.
    let key = keys[0].value.as_bytes();
    assert!(key == [0u8; 32]);
    for case in reference["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|c| c["case_class"] == "positive")
    {
        let inputs = Inputs::new(&case["inputs"]);
        assert!(inputs.auth_key == key);
        let mic =
            compute_ike_auth_shared_key_mic(profile(), &inputs.material, inputs.signed(), key)
                .expect("synthetic handoff AUTH");
        assert!(mic == octets(&case["wire_hex"])[4..]);
    }
}

#[test]
fn refreshed_digests_cannot_hide_mic_or_key_mutations() {
    let reference = reference();
    for case in reference["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .filter(|c| c["case_class"] == "positive")
    {
        let mut inputs = Inputs::new(&case["inputs"]);
        let body = octets(&case["wire_hex"]);
        for index in 0..32 {
            for bit in 0..8 {
                let mut changed = body.clone();
                changed[4 + index] ^= 1 << bit;
                assert_eq!(
                    inputs.verify(&changed),
                    Err("ike_auth_verify_authentication_failed")
                );
                inputs.auth_key[index] ^= 1 << bit;
                assert_eq!(
                    inputs.verify(&body),
                    Err("ike_auth_verify_authentication_failed")
                );
                inputs.auth_key[index] ^= 1 << bit;
            }
        }
        for size in 0..body.len() {
            assert!(inputs.verify(&body[..size]).is_err());
        }
        for field in 0..3 {
            let length = match field {
                0 => inputs.message.len(),
                1 => inputs.identity.len(),
                _ => inputs.nonce.len(),
            };
            for index in 0..length {
                let value = match field {
                    0 => &mut inputs.message,
                    1 => &mut inputs.identity,
                    _ => &mut inputs.nonce,
                };
                value[index] ^= 1;
                assert_eq!(
                    inputs.verify(&body),
                    Err("ike_auth_verify_authentication_failed")
                );
                let value = match field {
                    0 => &mut inputs.message,
                    1 => &mut inputs.identity,
                    _ => &mut inputs.nonce,
                };
                value[index] ^= 1;
            }
        }
    }
}

#[path = "support/key_lifecycle.rs"]
mod lifecycle;
