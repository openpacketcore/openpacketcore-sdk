use std::sync::OnceLock;

use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{
    install_ikev2_software_crypto_module, negotiate_ikev2_signature_hash_algorithms,
    Ikev2CryptoRequirements, Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalRole,
    Ikev2SignatureHashSigningAuthority, Ikev2SignatureHashSigningAuthorization,
    Ikev2SignatureHashVerificationAuthority, Ikev2SignatureHashVerificationAuthorization,
    EXCHANGE_TYPE_IKE_SA_INIT,
};
use opc_protocol::DecodeContext;

pub(crate) fn ensure_ike_crypto() {
    static INSTALL: OnceLock<Result<(), &'static str>> = OnceLock::new();
    let result = INSTALL.get_or_init(|| {
        let requirements = Ikev2CryptoRequirements::all_software_supported();
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        install_ikev2_software_crypto_module(policy, requirements)
            .map(|_| ())
            .map_err(|_| "explicit IKEv2 software module admission failed")
    });
    if let Err(message) = result {
        panic!("{message}");
    }
}

const TEST_INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const TEST_RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
pub(crate) const TEST_INITIATOR_NONCE: &[u8] = &[0x66; 32];
pub(crate) const TEST_RESPONDER_NONCE: &[u8] = &[0x77; 32];
const PAYLOAD_SECURITY_ASSOCIATION: u8 = 33;
const PAYLOAD_KEY_EXCHANGE: u8 = 34;
const PAYLOAD_NONCE: u8 = 40;
const PAYLOAD_NOTIFY: u8 = 41;

#[allow(
    dead_code,
    reason = "each integration test compiles its own support module"
)]
pub(crate) fn signature_hash_exchange(
    request_offer: Option<&[Ikev2SignatureHashAlgorithm]>,
    response_offer: Option<&[Ikev2SignatureHashAlgorithm]>,
) -> (Vec<u8>, Vec<u8>) {
    (
        build_sa_init_message(true, request_offer),
        build_sa_init_message(false, response_offer),
    )
}

#[allow(
    dead_code,
    reason = "each integration test compiles its own support module"
)]
pub(crate) fn responder_signature_hash_authorities(
    algorithms: &[Ikev2SignatureHashAlgorithm],
) -> (
    Vec<u8>,
    Vec<u8>,
    Ikev2SignatureHashSigningAuthority,
    Ikev2SignatureHashVerificationAuthority,
) {
    ensure_ike_crypto();
    let (request, response) = signature_hash_exchange(Some(algorithms), Some(algorithms));
    let responder = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder test signature-hash negotiation")
    .into_authorities()
    .into_parts();
    let initiator = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("initiator test signature-hash negotiation")
    .into_authorities()
    .into_parts();
    (request, response, responder.0, initiator.1)
}

#[allow(
    dead_code,
    reason = "each integration test compiles its own support module"
)]
pub(crate) struct ResponderSignatureHashContext {
    pub(crate) sa_init_request: Vec<u8>,
    pub(crate) sa_init_response: Vec<u8>,
    pub(crate) signing: Ikev2SignatureHashSigningAuthority,
    pub(crate) verification: Ikev2SignatureHashVerificationAuthority,
}

#[allow(
    dead_code,
    reason = "each integration test compiles its own support module"
)]
impl ResponderSignatureHashContext {
    pub(crate) fn signing_authorization(&self) -> Ikev2SignatureHashSigningAuthorization<'_> {
        self.signing
            .for_exchange(&self.sa_init_request, &self.sa_init_response)
            .expect("test signing authority matches exchange")
    }

    pub(crate) fn verification_authorization(
        &self,
    ) -> Ikev2SignatureHashVerificationAuthorization<'_> {
        self.verification
            .for_exchange(&self.sa_init_request, &self.sa_init_response)
            .expect("test verification authority matches exchange")
    }
}

#[allow(
    dead_code,
    reason = "each integration test compiles its own support module"
)]
pub(crate) fn responder_signature_hash_context(
    algorithm: Ikev2SignatureHashAlgorithm,
) -> ResponderSignatureHashContext {
    let (sa_init_request, sa_init_response, signing, verification) =
        responder_signature_hash_authorities(&[algorithm]);
    ResponderSignatureHashContext {
        sa_init_request,
        sa_init_response,
        signing,
        verification,
    }
}

fn build_sa_init_message(request: bool, offer: Option<&[Ikev2SignatureHashAlgorithm]>) -> Vec<u8> {
    let sa_body = [
        0, 0, 0, 16, // Last proposal, reserved, proposal length.
        1, 1, 0, 1, // Proposal number, IKE protocol, no SPI, one transform.
        0, 0, 0, 8, // Last transform, reserved, transform length.
        1, 0, 0, 12, // ENCR transform, reserved, AES-CBC.
    ];
    let mut ke_body = vec![0, 19, 0, 0];
    ke_body.extend_from_slice(&[0x55; 32]);
    let nonce_body = if request {
        TEST_INITIATOR_NONCE
    } else {
        TEST_RESPONDER_NONCE
    };

    let mut raw_payloads = Vec::new();
    append_payload(&mut raw_payloads, PAYLOAD_KEY_EXCHANGE, &sa_body);
    append_payload(&mut raw_payloads, PAYLOAD_NONCE, &ke_body);
    append_payload(
        &mut raw_payloads,
        if offer.is_some() { PAYLOAD_NOTIFY } else { 0 },
        nonce_body,
    );
    if let Some(algorithms) = offer {
        let mut notify_body = vec![0, 0, 0x40, 0x2f];
        for algorithm in algorithms {
            notify_body.extend_from_slice(&algorithm.as_u16().to_be_bytes());
        }
        append_payload(&mut raw_payloads, 0, &notify_body);
    }

    let total_len = 28usize
        .checked_add(raw_payloads.len())
        .expect("bounded test message length");
    let total_len = u32::try_from(total_len).expect("test message fits u32");
    let mut out = Vec::with_capacity(total_len as usize);
    out.extend_from_slice(&TEST_INITIATOR_SPI.to_be_bytes());
    out.extend_from_slice(&(if request { 0 } else { TEST_RESPONDER_SPI }).to_be_bytes());
    out.push(PAYLOAD_SECURITY_ASSOCIATION);
    out.push(0x20);
    out.push(EXCHANGE_TYPE_IKE_SA_INIT);
    out.push(if request { 0x08 } else { 0x20 });
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&raw_payloads);
    out
}

fn append_payload(out: &mut Vec<u8>, next_payload: u8, body: &[u8]) {
    let len = u16::try_from(4usize.checked_add(body.len()).expect("test payload length"))
        .expect("test payload fits u16");
    out.push(next_payload);
    out.push(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
}
