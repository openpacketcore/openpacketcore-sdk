//! Process-isolated proof that RFC 7427 offers follow installed admission.

use opc_crypto_provider::{IkeSignatureAlgorithm, ProviderPolicy};
use opc_proto_ikev2::{
    install_ikev2_software_crypto_module, negotiate_ikev2_signature_hash_algorithms,
    Ikev2CryptoRequirements, Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalOffer,
    Ikev2SignatureHashLocalRole, Ikev2SignatureHashNegotiationError,
};
use opc_protocol::DecodeContext;

mod support;

#[test]
fn restricted_admission_controls_local_offer_and_directional_candidates() {
    let mut requirements = Ikev2CryptoRequirements::new();
    requirements
        .require_signature_verification(IkeSignatureAlgorithm::EcdsaP256Sha2_256)
        .require_signature_generation(IkeSignatureAlgorithm::EcdsaP384Sha2_384);
    let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
    let _report = install_ikev2_software_crypto_module(policy, requirements)
        .expect("restricted software module admission");

    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&[Ikev2SignatureHashAlgorithm::Sha2_256])
            .expect("admitted verification hash")
            .algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_256]
    );
    assert_eq!(
        Ikev2SignatureHashLocalOffer::new(&[Ikev2SignatureHashAlgorithm::Sha2_384]),
        Err(Ikev2SignatureHashNegotiationError::UnsupportedLocalAlgorithm)
    );

    let (request, response) = support::signature_hash_exchange(
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_384]),
    );
    let negotiation = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("directional candidate uses separately admitted operations");
    assert_eq!(
        negotiation.signing_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_384]
    );
    assert_eq!(
        negotiation.verification_algorithms(),
        &[Ikev2SignatureHashAlgorithm::Sha2_256]
    );

    let (request, response) = support::signature_hash_exchange(
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
        Some(&[Ikev2SignatureHashAlgorithm::Sha2_256]),
    );
    assert_eq!(
        negotiate_ikev2_signature_hash_algorithms(
            Ikev2SignatureHashLocalRole::Initiator,
            &request,
            &response,
            DecodeContext::default(),
        ),
        Err(Ikev2SignatureHashNegotiationError::UnsupportedOnly)
    );
}
