#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::protocol_key::{
    Ikev2ProtocolKeyAssociation, Ikev2ProtocolKeyError, Ikev2ProtocolKeyPurpose,
};
use opc_proto_ikev2::{
    derive_ike_sa_init_key_material, install_ikev2_software_crypto_module, Ikev2CryptoRequirements,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
};
use std::{num::NonZeroU64, sync::OnceLock};
use zeroize::Zeroizing;

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .unwrap()
}

fn material() -> &'static Ikev2SaInitKeyMaterial {
    static MATERIAL: OnceLock<Ikev2SaInitKeyMaterial> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let mut requirements = Ikev2CryptoRequirements::new();
        requirements.require_ike_sa_profile(profile()).unwrap();
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        install_ikev2_software_crypto_module(policy, requirements).unwrap();
        // Fixed synthetic SA keys are fuzz inputs, never deployed custody.
        derive_ike_sa_init_key_material(
            profile(),
            [1; 8],
            [2; 8],
            &[3; 32],
            &[4; 32],
            &[5; 32],
            None,
        )
        .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 || data.len() > 4096 {
        return;
    }
    let material = material();
    let id = NonZeroU64::new(1).unwrap();
    let association = Ikev2ProtocolKeyAssociation::new(id);
    let operation = association.begin_ike_auth(id, id, profile()).unwrap();
    let length = usize::from(data[1]);
    let purpose = if data[0] & 1 == 0 {
        Ikev2ProtocolKeyPurpose::N3iwfMsk
    } else {
        Ikev2ProtocolKeyPurpose::Unsupported
    };
    let key = operation.import(purpose, Zeroizing::new(vec![data[2]; length]));
    if purpose == Ikev2ProtocolKeyPurpose::Unsupported || length != 32 {
        assert!(key.is_err());
        assert_eq!(
            operation
                .import(
                    Ikev2ProtocolKeyPurpose::N3iwfMsk,
                    Zeroizing::new(vec![0; 32])
                )
                .unwrap_err(),
            Ikev2ProtocolKeyError::Retired
        );
        return;
    }
    let key = key.unwrap();
    let message = &data[5..];
    let nonce = &data[..data.len().min(usize::from(data[3]))];
    let identity = [1, 0, 0, 0, 192, 0, 2, 1];
    let initiator = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Initiator,
        ike_sa_init_message: message,
        peer_nonce: nonce,
        identity_payload_body: &identity,
    };
    let responder = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ..initiator
    };
    let foreign = Ikev2ProtocolKeyAssociation::new(id);
    let foreign_op = foreign.begin_ike_auth(id, id, profile()).unwrap();
    assert_eq!(
        key.consume_ike_auth(&foreign_op, material, initiator, responder, 4096)
            .unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    let action = data[4] % 4;
    match action {
        0 => {}
        1 => operation.cancel(),
        2 => association.release(),
        3 => association
            .replace_generation(id, NonZeroU64::new(2).unwrap())
            .unwrap(),
        _ => unreachable!(),
    }
    let cap = 4096;
    let result = key.consume_ike_auth(&operation, material, initiator, responder, cap);
    let within_contract = action == 0
        && !message.is_empty()
        && (16..=256).contains(&nonce.len())
        && 2 * (message.len() + nonce.len() + identity.len()) <= cap;
    assert_eq!(result.is_ok(), within_contract);
    assert!(key
        .consume_ike_auth(&operation, material, initiator, responder, cap)
        .is_err());
    assert_eq!(format!("{key:?}"), "Ikev2ProtocolKeyHandle(<redacted>)");
});
