use opc_proto_ikev2::protocol_key::{
    Ikev2ProtocolKeyAssociation, Ikev2ProtocolKeyError, Ikev2ProtocolKeyPurpose,
};
use opc_proto_ikev2::{
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile,
};
use zeroize::Zeroizing;

#[test]
fn imports_fail_closed_without_an_admitted_crypto_module() {
    let id = std::num::NonZeroU64::new(1).unwrap();
    let association = Ikev2ProtocolKeyAssociation::new(id);
    assert_eq!(
        format!("{association:?}"),
        "Ikev2ProtocolKeyAssociation(<redacted>)"
    );
    let profile = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .unwrap();
    let operation = association.begin_ike_auth(id, id, profile).unwrap();
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0x5a; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::CryptoUnavailable
    );
    assert_eq!(
        operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0x5a; 32])
            )
            .unwrap_err(),
        Ikev2ProtocolKeyError::Retired
    );
}
