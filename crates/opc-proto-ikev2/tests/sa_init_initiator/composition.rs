// Shared by an integration test and a standalone consumer without testkit.
// Every expected cryptographic result comes from the independent Python vector.

use bytes::{Bytes, BytesMut};
use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{
    admit_ike_sa_init_response, build_ike_auth_cleartext_payload_chain, build_ike_sa_init_request,
    compute_ike_auth_shared_key_mic, derive_ike_sa_init_key_material, encode_header,
    install_ikev2_software_crypto_module, open_protected_payloads,
    seal_ikev2_sa_init_protected_payload, Header, HeaderFlags, Ikev2CryptoRequirements,
    Ikev2DhGroup, Ikev2EphemeralDhKey, Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2ProtectedPayloadDirection, Ikev2SaInitCryptoProfile,
    Ikev2SaInitKeyMaterial, Ikev2SaInitProtectedPayloadProvider, Ikev2SaInitResponse,
    Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, Message, PayloadType, ProtectedPayloadKind,
    ProtectedPayloadSealContext, EXCHANGE_TYPE_IKE_AUTH,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

const VECTOR: &str = include_str!("../vectors/ikev2_initiator_reference.json");

fn fixture(name: &str) -> Vec<u8> {
    // The pinned generator writes flat string fields containing lowercase hex.
    let prefix = format!("\"{name}\": \"");
    let line = VECTOR
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .unwrap();
    let hex = line
        .strip_prefix(&prefix)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn offer() -> Ikev2SaPayloadBuild {
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: 1,
            spi: vec![],
            transforms: vec![
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
                    transform_id: 5,
                    attributes: vec![],
                },
                Ikev2SaTransformBuild {
                    transform_type: 4,
                    transform_id: 19,
                    attributes: vec![],
                },
            ],
        }],
    }
}

fn body(kind: u8, bytes: Vec<u8>) -> Ikev2IkeAuthPayloadBuild {
    Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::from_u8(kind),
        body: bytes,
    }
}

fn auth_body(mic: &[u8]) -> Vec<u8> {
    let mut result = vec![2, 0, 0, 0];
    result.extend_from_slice(mic);
    result
}

fn protected_exchange(
    name: &str,
    responder: bool,
    message_id: u32,
    counter: u64,
    entries: &[Ikev2IkeAuthPayloadBuild],
    profile: Ikev2SaInitCryptoProfile,
    keys: &Ikev2SaInitKeyMaterial,
) {
    let direction = if responder {
        Ikev2ProtectedPayloadDirection::ResponderToInitiator
    } else {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder
    };
    let (first, cleartext) = build_ike_auth_cleartext_payload_chain(entries).unwrap();
    assert_eq!(&cleartext[..], fixture(&format!("{name}_cleartext")));
    let payload_length = u16::try_from(4 + 8 + cleartext.len() + 1 + 16).unwrap();
    let mut header = Header::new(
        u64::from_be_bytes(fixture("spi_i").try_into().unwrap()),
        u64::from_be_bytes(fixture("spi_r").try_into().unwrap()),
        PayloadType::Encrypted,
        EXCHANGE_TYPE_IKE_AUTH,
        HeaderFlags::from_bits(!responder, responder, false),
        message_id,
    );
    header.length = 28 + u32::from(payload_length);
    let mut prefix = BytesMut::new();
    encode_header(&header, &mut prefix, EncodeContext::default()).unwrap();
    prefix.extend_from_slice(&[first.as_u8(), 0]);
    prefix.extend_from_slice(&payload_length.to_be_bytes());
    let sealed = seal_ikev2_sa_init_protected_payload(
        profile,
        keys,
        direction,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &prefix,
        },
        &cleartext,
        0,
        counter.to_be_bytes(),
    )
    .unwrap();
    let mut wire = prefix.to_vec();
    wire.extend_from_slice(&sealed);
    let expected = fixture(name);
    assert_eq!(wire, expected, "independent {name} seal");
    // Open the reference implementation's packet, not merely our sealed bytes.
    let (_, message) = Message::decode(&expected, DecodeContext::default()).unwrap();
    let provider = Ikev2SaInitProtectedPayloadProvider::new(profile, keys, direction);
    let opened =
        open_protected_payloads(&message, &expected, DecodeContext::default(), &provider).unwrap();
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].first_inner_payload, first);
    assert_eq!(opened[0].cleartext, Bytes::copy_from_slice(&cleartext));
    // Direction keys are not interchangeable.
    let opposite = if responder {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder
    } else {
        Ikev2ProtectedPayloadDirection::ResponderToInitiator
    };
    let wrong = Ikev2SaInitProtectedPayloadProvider::new(profile, keys, opposite);
    assert!(
        open_protected_payloads(&message, &expected, DecodeContext::default(), &wrong).is_err()
    );
}

pub fn run() {
    let mut requirements = Ikev2CryptoRequirements::all_software_supported();
    requirements.require_dh_checkpoint(Ikev2DhGroup::Ecp256);
    let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
    install_ikev2_software_crypto_module(policy, requirements).unwrap();
    let mut checkpoint = vec![1, 0, 19];
    checkpoint.extend_from_slice(&fixture("scalar_i"));
    let key = Ikev2EphemeralDhKey::import_private_checkpoint(
        Ikev2DhGroup::Ecp256,
        &checkpoint,
        &fixture("ke_i"),
    )
    .unwrap();
    let ni = fixture("ni");
    let request = build_ike_sa_init_request(
        u64::from_be_bytes(fixture("spi_i").try_into().unwrap()),
        &offer(),
        &key,
        &ni,
        &[],
    )
    .unwrap();
    let mut request_wire = BytesMut::new();
    request
        .message()
        .encode(&mut request_wire, EncodeContext::default())
        .unwrap();
    assert_eq!(&request_wire[..], fixture("sa_init_request"));
    let response_wire = fixture("sa_init_response");
    let (_, response) = Message::decode(&response_wire, DecodeContext::default()).unwrap();
    let Ikev2SaInitResponse::Accepted(accepted) =
        admit_ike_sa_init_response(&request, &response, DecodeContext::default()).unwrap()
    else {
        panic!("reference response must be admitted")
    };
    let profile = accepted.profile();
    assert_eq!(accepted.key_exchange(), fixture("ke_r"));
    assert_eq!(accepted.nonce(), fixture("nr"));
    let shared = key.agree(accepted.key_exchange()).unwrap();
    assert_eq!(&shared[..], fixture("dh_shared"));
    let keys = derive_ike_sa_init_key_material(
        profile,
        request.message().header.initiator_spi.to_be_bytes(),
        accepted.responder_spi().to_be_bytes(),
        &ni,
        accepted.nonce(),
        &shared,
        None,
    )
    .unwrap();
    for (name, bytes) in [
        ("skeyseed", keys.skeyseed()),
        ("sk_d", keys.sk_d()),
        ("sk_ai", keys.sk_ai()),
        ("sk_ar", keys.sk_ar()),
        ("sk_ei", keys.sk_ei()),
        ("sk_er", keys.sk_er()),
        ("sk_pi", keys.sk_pi()),
        ("sk_pr", keys.sk_pr()),
    ] {
        assert_eq!(bytes, fixture(name), "independent {name}");
    }
    let id_i = fixture("id_i_body");
    let id_r = fixture("id_r_body");
    let signed_i = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Initiator,
        ike_sa_init_message: &request_wire,
        peer_nonce: accepted.nonce(),
        identity_payload_body: &id_i,
    };
    let signed_r = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: &response_wire,
        peer_nonce: &ni,
        identity_payload_body: &id_r,
    };
    let psk_i = compute_ike_auth_shared_key_mic(profile, &keys, signed_i, &fixture("psk")).unwrap();
    let psk_r = compute_ike_auth_shared_key_mic(profile, &keys, signed_r, &fixture("psk")).unwrap();
    assert_eq!(psk_i, fixture("psk_auth_i"));
    assert_eq!(psk_r, fixture("psk_auth_r"));
    protected_exchange(
        "psk_request",
        false,
        1,
        1,
        &[body(35, id_i.clone()), body(39, auth_body(&psk_i))],
        profile,
        &keys,
    );
    protected_exchange(
        "psk_response",
        true,
        1,
        1,
        &[body(36, id_r.clone()), body(39, auth_body(&psk_r))],
        profile,
        &keys,
    );

    // Independent alternative fixture: EAP identity exchange and EAP success,
    // followed by AUTH with a synthetic key-generating EAP method's MSK.
    protected_exchange(
        "eap_start_request",
        false,
        1,
        1,
        &[body(35, id_i.clone())],
        profile,
        &keys,
    );
    protected_exchange(
        "eap_identity_request",
        true,
        1,
        1,
        &[body(48, vec![1, 1, 0, 5, 1])],
        profile,
        &keys,
    );
    protected_exchange(
        "eap_identity_response",
        false,
        2,
        2,
        &[body(48, b"\x02\x01\x00\x09\x01test".to_vec())],
        profile,
        &keys,
    );
    protected_exchange(
        "eap_success",
        true,
        2,
        2,
        &[body(48, vec![3, 1, 0, 4])],
        profile,
        &keys,
    );
    let eap_i =
        compute_ike_auth_shared_key_mic(profile, &keys, signed_i, &fixture("eap_msk")).unwrap();
    let eap_r =
        compute_ike_auth_shared_key_mic(profile, &keys, signed_r, &fixture("eap_msk")).unwrap();
    assert_eq!(eap_i, fixture("eap_auth_i"));
    assert_eq!(eap_r, fixture("eap_auth_r"));
    assert_ne!(eap_i, psk_i);
    protected_exchange(
        "eap_auth_request",
        false,
        3,
        3,
        &[body(39, auth_body(&eap_i))],
        profile,
        &keys,
    );
    protected_exchange(
        "eap_auth_response",
        true,
        3,
        3,
        &[body(39, auth_body(&eap_r))],
        profile,
        &keys,
    );
    let diagnostics =
        format!("{request:?} {accepted:?} {key:?} {keys:?} {signed_i:?} {signed_r:?}");
    for name in [
        "ke_i",
        "ke_r",
        "ni",
        "nr",
        "dh_shared",
        "skeyseed",
        "sk_d",
        "sk_ei",
        "sk_er",
        "sk_pi",
        "sk_pr",
    ] {
        let bytes = fixture(name);
        assert!(!diagnostics.contains(&format!("{bytes:?}")));
        assert!(
            !diagnostics.contains(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
        );
    }
}
