//! Test-only IKEv2 fixture builders.
//!
//! These helpers are deterministic packet fixtures for tests. They are not
//! production IKE negotiation, transform selection, cookie policy, crypto, or
//! Child SA installation APIs.

use std::{error::Error, fmt};

use bytes::{Bytes, BytesMut};
use opc_protocol::{Encode, EncodeContext};

use crate::{
    header::{Header, HeaderFlags, EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT, HEADER_LEN},
    message::OwnedMessage,
    nat_traversal::{IKE_NAT_TRAVERSAL_UDP_PORT, IKE_UDP_PORT, NAT_TRAVERSAL_KEEPALIVE},
    payload::{PayloadType, GENERIC_PAYLOAD_HEADER_LEN},
    sa_init::{
        encode_ke_payload_build, encode_nonce_payload_build, encode_sa_payload_build,
        Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild, Ikev2SaInitBuildError,
        Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild,
        Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue,
    },
    sa_init_crypto::Ikev2DhGroup,
};

const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];

/// UDP transport framing used by an IKEv2 fixture datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2FixtureTransport {
    /// UDP/500 IKE datagram without NAT-T marker.
    Udp500,
    /// UDP/4500 IKE datagram with RFC 3948 non-ESP marker.
    Udp4500NatTraversal,
}

impl Ikev2FixtureTransport {
    /// Return the UDP destination port represented by this fixture transport.
    pub const fn udp_destination_port(self) -> u16 {
        match self {
            Self::Udp500 => IKE_UDP_PORT,
            Self::Udp4500NatTraversal => IKE_NAT_TRAVERSAL_UDP_PORT,
        }
    }

    /// Stable machine-readable transport name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp500 => "udp_500",
            Self::Udp4500NatTraversal => "udp_4500_nat_t",
        }
    }
}

/// One generic payload body in an IKEv2 fixture chain.
///
/// `Debug` reports the body length and not the body bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2FixturePayload<'a> {
    /// Payload type selected by the previous chain link or fixed header.
    pub payload_type: PayloadType,
    /// Optional explicit Next Payload value for protected-payload shells.
    pub next_payload: Option<PayloadType>,
    /// Deterministic fixture body bytes.
    pub body: &'a [u8],
}

impl<'a> Ikev2FixturePayload<'a> {
    /// Build a fixture payload whose Next Payload is inferred from chain order.
    pub const fn new(payload_type: PayloadType, body: &'a [u8]) -> Self {
        Self {
            payload_type,
            next_payload: None,
            body,
        }
    }

    /// Build a fixture payload with an explicit Next Payload value.
    ///
    /// This is useful for protected SK/SKF shells where Next Payload names the
    /// first inner payload after decryption rather than the next cleartext
    /// outer payload.
    pub const fn with_next_payload(
        payload_type: PayloadType,
        next_payload: PayloadType,
        body: &'a [u8],
    ) -> Self {
        Self {
            payload_type,
            next_payload: Some(next_payload),
            body,
        }
    }
}

impl fmt::Debug for Ikev2FixturePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2FixturePayload")
            .field("payload_type", &self.payload_type)
            .field("next_payload", &self.next_payload)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// IKEv2 fixture message construction plan.
///
/// `Debug` reports the payload count and not payload body bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2FixtureMessagePlan<'a> {
    /// Initiator SPI to place in the IKE fixed header.
    pub initiator_spi: u64,
    /// Responder SPI to place in the IKE fixed header.
    pub responder_spi: u64,
    /// IKEv2 exchange type value.
    pub exchange_type: u8,
    /// IKEv2 header flags.
    pub flags: HeaderFlags,
    /// IKEv2 Message ID.
    pub message_id: u32,
    /// Payload chain to encode.
    pub payloads: &'a [Ikev2FixturePayload<'a>],
}

impl fmt::Debug for Ikev2FixtureMessagePlan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2FixtureMessagePlan")
            .field("initiator_spi_present", &(self.initiator_spi != 0))
            .field("responder_spi_present", &(self.responder_spi != 0))
            .field("exchange_type", &self.exchange_type)
            .field("flags", &self.flags)
            .field("message_id", &self.message_id)
            .field("payload_count", &self.payloads.len())
            .finish()
    }
}

/// Failure building an IKEv2 test fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2FixtureBuildError {
    /// A generic payload exceeded the u16 payload length field.
    PayloadTooLong {
        /// Payload length including the four-octet generic payload header.
        len: usize,
    },
    /// The complete IKE message exceeded the u32 header length field.
    MessageTooLong {
        /// Complete IKE message length.
        len: usize,
    },
    /// SDK encoding rejected the fixture message.
    EncodeFailed,
    /// A typed SA/KE/Nonce fixture body failed typed-builder validation.
    ///
    /// The inner code is a stable, redaction-safe machine code; no payload
    /// bytes are carried.
    TypedPayload(Ikev2SaInitBuildError),
}

impl Ikev2FixtureBuildError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayloadTooLong { .. } => "ikev2_fixture_payload_too_long",
            Self::MessageTooLong { .. } => "ikev2_fixture_message_too_long",
            Self::EncodeFailed => "ikev2_fixture_encode_failed",
            Self::TypedPayload(_) => "ikev2_fixture_typed_payload_invalid",
        }
    }
}

impl fmt::Display for Ikev2FixtureBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLong { len } => {
                write!(f, "ikev2_fixture_payload_too_long: len={len}")
            }
            Self::MessageTooLong { len } => {
                write!(f, "ikev2_fixture_message_too_long: len={len}")
            }
            Self::EncodeFailed => f.write_str("ikev2_fixture_encode_failed"),
            Self::TypedPayload(error) => {
                write!(f, "ikev2_fixture_typed_payload_invalid: {error}")
            }
        }
    }
}

impl Error for Ikev2FixtureBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TypedPayload(error) => Some(error),
            _ => None,
        }
    }
}

/// Build a raw generic payload chain from fixture payload bodies.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] when a payload body exceeds the generic
/// payload length field.
pub fn build_fixture_payload_chain(
    payloads: &[Ikev2FixturePayload<'_>],
) -> Result<(PayloadType, Bytes), Ikev2FixtureBuildError> {
    let Some(first) = payloads.first() else {
        return Ok((PayloadType::NoNext, Bytes::new()));
    };

    let mut raw = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let inferred_next = payloads
            .get(index.saturating_add(1))
            .map_or(PayloadType::NoNext, |next| next.payload_type);
        let next_payload = payload.next_payload.unwrap_or(inferred_next);
        append_generic_payload(&mut raw, next_payload, payload.body)?;
    }
    Ok((first.payload_type, Bytes::from(raw)))
}

/// Build an owned IKEv2 fixture message from a fixture plan.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] when the payload chain or complete
/// message length exceeds IKEv2 fields.
pub fn build_fixture_message(
    plan: Ikev2FixtureMessagePlan<'_>,
) -> Result<OwnedMessage, Ikev2FixtureBuildError> {
    let (first_payload, raw_payloads) = build_fixture_payload_chain(plan.payloads)?;
    let total_len = HEADER_LEN
        .checked_add(raw_payloads.len())
        .ok_or(Ikev2FixtureBuildError::MessageTooLong { len: usize::MAX })?;
    let total_len_u32 = u32::try_from(total_len)
        .map_err(|_| Ikev2FixtureBuildError::MessageTooLong { len: total_len })?;

    let mut header = Header::new(
        plan.initiator_spi,
        plan.responder_spi,
        first_payload,
        plan.exchange_type,
        plan.flags,
        plan.message_id,
    );
    header.length = total_len_u32;

    Ok(OwnedMessage {
        header,
        raw_payloads,
    })
}

/// Build an encoded IKEv2 fixture datagram for UDP/500 or UDP/4500 NAT-T.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] when fixture message construction or SDK
/// encoding fails.
pub fn build_fixture_datagram(
    transport: Ikev2FixtureTransport,
    plan: Ikev2FixtureMessagePlan<'_>,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let message = build_fixture_message(plan)?;
    encode_fixture_datagram(transport, &message)
}

/// Build a deterministic IKE_SA_INIT request fixture datagram.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn ike_sa_init_request_datagram(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let payloads = default_sa_init_payloads();
    build_fixture_datagram(
        transport,
        Ikev2FixtureMessagePlan {
            initiator_spi,
            responder_spi: 0,
            exchange_type: EXCHANGE_TYPE_IKE_SA_INIT,
            flags: HeaderFlags::from_bits(true, false, false),
            message_id: 0,
            payloads: &payloads,
        },
    )
}

/// Build an exact retransmission of the deterministic IKE_SA_INIT request.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn ike_sa_init_retransmission_datagram(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    ike_sa_init_request_datagram(transport, initiator_spi)
}

/// DH group used by the default typed SA_INIT request fixture (NIST P-256).
const TYPED_FIXTURE_DH_GROUP: Ikev2DhGroup = Ikev2DhGroup::Ecp256;
/// Nonce length for the default typed fixture, above the RFC 7296 16-octet min.
const TYPED_FIXTURE_NONCE_LEN: usize = 32;

// IKEv2 transform type and ID selectors for the default typed proposal
// (RFC 7296 §3.3.2 and the IANA IKEv2 Transform registries). ENCR reuses the
// AES-CBC transform and 256-bit key-length attribute of the crate's own passing
// SA_INIT decode test; PRF/INTEG/DH round the proposal out to a decodable set.
const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_PRF: u8 = 2;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const TRANSFORM_TYPE_DH: u8 = 4;
const TRANSFORM_ID_ENCR_AES_CBC: u16 = 12;
const TRANSFORM_ID_PRF_HMAC_SHA2_256: u16 = 5;
const TRANSFORM_ID_AUTH_HMAC_SHA2_256_128: u16 = 12;
const TRANSFORM_ATTR_KEY_LENGTH: u16 = 14;
const AES_256_KEY_LENGTH_BITS: u16 = 256;

/// Typed IKE_SA_INIT request fixture profile.
///
/// Unlike [`ike_sa_init_request_datagram`], whose SA/KE/Nonce bodies are opaque
/// placeholders, this profile carries the crate's typed SA/KE/Nonce builders so
/// the resulting fixture datagram decodes through
/// [`decode_ike_sa_init_request_payloads`]. It is a deterministic test fixture,
/// not a negotiation policy or transform-selection API.
///
/// The public fields are the override surface: replace them for custom
/// proposals, a different KE group and public data, or custom nonce bytes.
/// Invalid overrides surface as [`Ikev2FixtureBuildError::TypedPayload`] at
/// build time and never panic.
///
/// `Debug` reports typed metadata and lengths only, never KE or nonce bytes.
///
/// [`decode_ike_sa_init_request_payloads`]: crate::decode_ike_sa_init_request_payloads
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2TypedSaInitProfile {
    /// SA payload proposals.
    pub security_association: Ikev2SaPayloadBuild,
    /// KE payload DH group and public data.
    pub key_exchange: Ikev2KeyExchangePayloadBuild,
    /// Nonce payload bytes.
    pub nonce: Ikev2NoncePayloadBuild,
}

impl Ikev2TypedSaInitProfile {
    /// Build the deterministic default typed SA_INIT request profile.
    ///
    /// Mirrors the crate's own passing SA_INIT decode test: an AES-CBC
    /// encryption transform with a 256-bit key-length attribute (plus PRF,
    /// INTEG, and DH transforms), DH group ECP-256, group-sized deterministic KE
    /// public data, and a deterministic nonce above the RFC 7296 minimum. No RNG
    /// is used.
    #[must_use]
    pub fn default_profile() -> Self {
        Self {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: 1,
                    spi: Vec::new(),
                    transforms: vec![
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_ENCR,
                            transform_id: TRANSFORM_ID_ENCR_AES_CBC,
                            attributes: vec![Ikev2TransformAttributeBuild {
                                attribute_type: TRANSFORM_ATTR_KEY_LENGTH,
                                value: Ikev2TransformAttributeBuildValue::Tv(
                                    AES_256_KEY_LENGTH_BITS,
                                ),
                            }],
                        },
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_PRF,
                            transform_id: TRANSFORM_ID_PRF_HMAC_SHA2_256,
                            attributes: Vec::new(),
                        },
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_INTEG,
                            transform_id: TRANSFORM_ID_AUTH_HMAC_SHA2_256_128,
                            attributes: Vec::new(),
                        },
                        Ikev2SaTransformBuild {
                            transform_type: TRANSFORM_TYPE_DH,
                            transform_id: TYPED_FIXTURE_DH_GROUP.transform_id(),
                            attributes: Vec::new(),
                        },
                    ],
                }],
            },
            key_exchange: Ikev2KeyExchangePayloadBuild {
                dh_group: TYPED_FIXTURE_DH_GROUP.transform_id(),
                key_exchange_data: deterministic_fixture_bytes(
                    TYPED_FIXTURE_DH_GROUP.public_value_len(),
                    0x40,
                ),
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: deterministic_fixture_bytes(TYPED_FIXTURE_NONCE_LEN, 0x80),
            },
        }
    }
}

impl Default for Ikev2TypedSaInitProfile {
    fn default() -> Self {
        Self::default_profile()
    }
}

/// Build a deterministic IKE_SA_INIT request fixture datagram whose SA, KE, and
/// Nonce bodies are typed payloads that decode through
/// [`decode_ike_sa_init_request_payloads`].
///
/// `transport` selects UDP/500 cleartext or UDP/4500 NAT-T framing; both reuse
/// the same cleartext SA -> KE -> Nonce request chain, so no separate NAT-T
/// builder is needed.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError::TypedPayload`] when a profile body fails
/// typed-builder validation (for example a nonce below the RFC 7296 minimum or
/// empty KE data), or the other [`Ikev2FixtureBuildError`] variants when fixture
/// encoding exceeds IKEv2 length fields.
///
/// [`decode_ike_sa_init_request_payloads`]: crate::decode_ike_sa_init_request_payloads
pub fn ike_sa_init_request_datagram_typed(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
    profile: &Ikev2TypedSaInitProfile,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let sa_body = encode_sa_payload_build(&profile.security_association)
        .map_err(Ikev2FixtureBuildError::TypedPayload)?;
    let ke_body = encode_ke_payload_build(&profile.key_exchange)
        .map_err(Ikev2FixtureBuildError::TypedPayload)?;
    let nonce_body =
        encode_nonce_payload_build(&profile.nonce).map_err(Ikev2FixtureBuildError::TypedPayload)?;

    let payloads = [
        Ikev2FixturePayload::new(PayloadType::SecurityAssociation, &sa_body),
        Ikev2FixturePayload::new(PayloadType::KeyExchange, &ke_body),
        Ikev2FixturePayload::new(PayloadType::Nonce, &nonce_body),
    ];
    build_fixture_datagram(
        transport,
        Ikev2FixtureMessagePlan {
            initiator_spi,
            responder_spi: 0,
            exchange_type: EXCHANGE_TYPE_IKE_SA_INIT,
            flags: HeaderFlags::from_bits(true, false, false),
            message_id: 0,
            payloads: &payloads,
        },
    )
}

/// Build the deterministic IKE_SA_INIT request fixture datagram using the
/// default typed profile.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn ike_sa_init_request_datagram_typed_default(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    ike_sa_init_request_datagram_typed(
        transport,
        initiator_spi,
        &Ikev2TypedSaInitProfile::default_profile(),
    )
}

/// Build a deterministic IKE_SA_INIT response fixture datagram.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn ike_sa_init_response_datagram(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
    responder_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let payloads = default_sa_init_payloads();
    build_fixture_datagram(
        transport,
        Ikev2FixtureMessagePlan {
            initiator_spi,
            responder_spi,
            exchange_type: EXCHANGE_TYPE_IKE_SA_INIT,
            flags: HeaderFlags::from_bits(true, true, false),
            message_id: 0,
            payloads: &payloads,
        },
    )
}

/// Build a deterministic protected IKE_AUTH request fixture datagram.
///
/// The protected body is fixture ciphertext, not a valid encrypted IKE_AUTH
/// result. It exists only to exercise protected-payload boundaries.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn protected_ike_auth_request_datagram(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
    responder_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let payloads = [Ikev2FixturePayload::with_next_payload(
        PayloadType::Encrypted,
        PayloadType::ExtensibleAuthentication,
        b"fixture-protected-ike-auth",
    )];
    build_fixture_datagram(
        transport,
        Ikev2FixtureMessagePlan {
            initiator_spi,
            responder_spi,
            exchange_type: EXCHANGE_TYPE_IKE_AUTH,
            flags: HeaderFlags::from_bits(true, false, false),
            message_id: 1,
            payloads: &payloads,
        },
    )
}

/// Build a malformed IKE_SA_INIT request with a truncated generic payload.
///
/// The returned datagram is intentionally malformed and is useful for decoder
/// boundary tests.
///
/// # Errors
///
/// Returns [`Ikev2FixtureBuildError`] if fixture encoding fails.
pub fn malformed_truncated_payload_datagram(
    transport: Ikev2FixtureTransport,
    initiator_spi: u64,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let mut header = Header::new(
        initiator_spi,
        0,
        PayloadType::SecurityAssociation,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    header.length =
        u32::try_from(HEADER_LEN + 2).map_err(|_| Ikev2FixtureBuildError::MessageTooLong {
            len: HEADER_LEN + 2,
        })?;
    let message = OwnedMessage {
        header,
        raw_payloads: Bytes::from_static(&[0x00, 0x00]),
    };
    encode_fixture_datagram(transport, &message)
}

/// Build an RFC 3948 NAT-T keepalive datagram fixture.
pub fn nat_t_keepalive_datagram() -> Bytes {
    Bytes::from_static(&[NAT_TRAVERSAL_KEEPALIVE])
}

/// Build a UDP/4500 non-ESP marker-only malformed IKE fixture.
pub fn nat_t_non_esp_marker_only_datagram() -> Bytes {
    Bytes::from_static(&NON_ESP_MARKER)
}

fn default_sa_init_payloads() -> [Ikev2FixturePayload<'static>; 3] {
    [
        Ikev2FixturePayload::new(PayloadType::SecurityAssociation, b"fixture-sa"),
        Ikev2FixturePayload::new(PayloadType::KeyExchange, b"fixture-ke"),
        Ikev2FixturePayload::new(PayloadType::Nonce, b"fixture-nonce"),
    ]
}

/// Deterministic fixture bytes: `seed` plus a wrapping octet index. No RNG, so
/// fixture KE/nonce material is reproducible byte-for-byte across runs.
fn deterministic_fixture_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn append_generic_payload(
    dst: &mut Vec<u8>,
    next_payload: PayloadType,
    body: &[u8],
) -> Result<(), Ikev2FixtureBuildError> {
    let len = body
        .len()
        .checked_add(GENERIC_PAYLOAD_HEADER_LEN)
        .ok_or(Ikev2FixtureBuildError::PayloadTooLong { len: usize::MAX })?;
    let len_u16 = u16::try_from(len).map_err(|_| Ikev2FixtureBuildError::PayloadTooLong { len })?;

    dst.reserve(len);
    dst.push(next_payload.as_u8());
    dst.push(0);
    dst.extend_from_slice(&len_u16.to_be_bytes());
    dst.extend_from_slice(body);
    Ok(())
}

fn encode_fixture_datagram(
    transport: Ikev2FixtureTransport,
    message: &OwnedMessage,
) -> Result<Bytes, Ikev2FixtureBuildError> {
    let mut encoded = BytesMut::new();
    if transport == Ikev2FixtureTransport::Udp4500NatTraversal {
        encoded.extend_from_slice(&NON_ESP_MARKER);
    }
    message
        .encode(&mut encoded, EncodeContext::default())
        .map_err(|_| Ikev2FixtureBuildError::EncodeFailed)?;
    Ok(encoded.freeze())
}
