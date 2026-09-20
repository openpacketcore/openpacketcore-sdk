//! Synthetic independently sealed IKE peer for native roster relocation tests.

use aes_gcm::{
    aead::{Aead, Key, KeyInit, Nonce, Payload},
    Aes128Gcm,
};
use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{
    derive_ike_sa_init_key_material, install_ikev2_software_crypto_module,
    nwu::mobike::{Migration, NatState, Path, ProbeOutcome, Responder},
    nwu::{
        Address, AddressFamilies, ConfigurationReply, ConfigurationRequest, Limits, NasEndpoint,
    },
    Ikev2CryptoRequirements, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2InitiatorMessageIdWindow,
    Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection, Ikev2ResponderMessageIdWindow,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SaInitProtectedPayloadProvider,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

const SPIS: [u64; 2] = [0x0102030405060708, 0x1112131415161718];
fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .unwrap()
}

pub fn keys() -> Ikev2SaInitKeyMaterial {
    static ADMISSION: OnceLock<()> = OnceLock::new();
    ADMISSION.get_or_init(|| {
        let requirements = Ikev2CryptoRequirements::all_software_supported();
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        let _ = install_ikev2_software_crypto_module(policy, requirements).unwrap();
    });
    derive_ike_sa_init_key_material(
        profile(),
        SPIS[0].to_be_bytes(),
        SPIS[1].to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        None,
    )
    .unwrap()
}

pub fn responder(keys: &Ikev2SaInitKeyMaterial, udp: bool) -> Responder<'_> {
    let address = Address::new("203.0.113.1".parse().unwrap());
    let configuration = ConfigurationReply::new(
        ConfigurationRequest {
            families: AddressFamilies::Ipv4,
            mobike_supported: true,
        },
        Some(address),
        None,
        NasEndpoint::new(Some(address), None, 20000).unwrap(),
    )
    .unwrap();
    Responder::new(
        SPIS,
        configuration,
        Ikev2SaInitProtectedPayloadProvider::new(
            profile(),
            keys,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ),
        NatState::new(true, udp).unwrap(),
        Limits::default(),
    )
    .unwrap()
}

// These RFC 7296 headers and RFC 5282 authenticated bytes do not use SDK packet
// builders or sealers. The only variable plaintext is the synthetic COOKIE2.
fn packet(keys: &Ikev2SaInitKeyMaterial, id: u32, response: bool, body: &[u8]) -> Vec<u8> {
    static IV: AtomicU64 = AtomicU64::new(1);
    let iv = IV.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    let mut plaintext = vec![0, 0];
    plaintext.extend(((body.len() + 4) as u16).to_be_bytes());
    plaintext.extend(body);
    plaintext.push(0);
    let protected_len = 8 + plaintext.len() + 16;
    let mut aad = SPIS[0].to_be_bytes().to_vec();
    aad.extend(SPIS[1].to_be_bytes());
    aad.extend([46, 0x20, 37, if response { 0x28 } else { 0x08 }]);
    aad.extend(id.to_be_bytes());
    aad.extend(((32 + protected_len) as u32).to_be_bytes());
    aad.extend([41, 0]);
    aad.extend(((4 + protected_len) as u16).to_be_bytes());
    let (key, salt) = keys.sk_ei().split_at(16);
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(&iv);
    let cipher = Aes128Gcm::new(<&Key<Aes128Gcm>>::try_from(key).unwrap());
    let ciphertext = cipher
        .encrypt(
            <&Nonce<Aes128Gcm>>::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    let mut result = vec![0; 4];
    result.extend(aad);
    result.extend(iv);
    result.extend(ciphertext);
    result
}

pub fn migration(
    keys: &Ikev2SaInitKeyMaterial,
    responder: &mut Responder<'_>,
    path: Path,
) -> Migration {
    let mut receive = Ikev2ResponderMessageIdWindow::with_highest_processed(2);
    let mut send = Ikev2InitiatorMessageIdWindow::with_next_message_id(20);
    let mut corrupted = packet(keys, 3, false, &[0, 0, 0x40, 0x10]);
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(responder
        .receive_request(&corrupted, path, &mut receive, |_| true)
        .is_err());
    responder
        .receive_request(
            &packet(keys, 3, false, &[0, 0, 0x40, 0x10]),
            path,
            &mut receive,
            |_| true,
        )
        .unwrap();
    let probe = responder.begin_return_routability(&mut send).unwrap();
    let reply = packet(keys, probe.message_id(), true, &probe.payloads()[0].body);
    let ProbeOutcome::Verified(migration) = responder
        .receive_probe_response(&reply, path, &mut send)
        .unwrap()
    else {
        panic!("COOKIE2 proof required")
    };
    migration
}
