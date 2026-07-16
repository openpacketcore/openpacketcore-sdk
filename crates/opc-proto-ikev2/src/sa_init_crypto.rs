//! IKE_SA_INIT key-agreement and key-material derivation helpers.
//!
//! This module owns only transport-neutral IKE_SA_INIT cryptographic material:
//! supported transform identifiers, ephemeral DH/ECDH, SKEYSEED, PRF+, and the
//! seven IKE SA keys produced from the negotiated transforms. It deliberately
//! does not own IKE SA state, authentication, EAP, Child SA installation,
//! responder SPI allocation, retransmission, or ePDG/N3IWF policy.
//!
//! @spec IETF RFC7296 2.14, 3.3.2, 3.3.5; IETF RFC8784 2
//! @req REQ-IETF-RFC7296-SA-INIT-CRYPTO-MATERIAL-001

use std::{error::Error, fmt};

use crypto_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    Odd, Random, U2048,
};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret,
    elliptic_curve::{common::Generate, point::PointCompression, sec1::ToSec1Point},
    PublicKey as P256PublicKey,
};
use p384::{ecdh::EphemeralSecret as P384EphemeralSecret, PublicKey as P384PublicKey};
use p521::{ecdh::EphemeralSecret as P521EphemeralSecret, PublicKey as P521PublicKey};
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

use crate::{
    ike_auth::Ikev2ChildSaNegotiation,
    sa_init::{
        Ikev2SaProposal, Ikev2SaTransform, Ikev2SaTransformBuild,
        Ikev2TransformAttributeBuildValue, Ikev2TransformAttributeValue,
    },
};

const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_PRF: u8 = 2;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const TRANSFORM_TYPE_DH: u8 = 4;
const TRANSFORM_ATTRIBUTE_KEY_LENGTH: u16 = 14;
const PROTOCOL_ID_IKE: u8 = 1;

const ENCR_AES_CBC: u16 = 12;
const ENCR_AES_GCM_16: u16 = 20;
const PRF_HMAC_SHA2_256: u16 = 5;
const PRF_HMAC_SHA2_384: u16 = 6;
const INTEG_HMAC_SHA2_256_128: u16 = 12;
const INTEG_HMAC_SHA2_384_192: u16 = 13;
const INTEG_HMAC_SHA2_512_256: u16 = 14;
const DH_MODP_2048: u16 = 14;
const DH_ECP_256: u16 = 19;
const DH_ECP_384: u16 = 20;
const DH_ECP_521: u16 = 21;
const IKEV2_NONCE_MIN_LEN: usize = 16;
const IKEV2_NONCE_MAX_LEN: usize = 256;
const IKE_SPI_LEN: usize = 8;
const AES_GCM_SALT_LEN: usize = 4;
const AES_128_KEY_BITS: u16 = 128;
const AES_192_KEY_BITS: u16 = 192;
const AES_256_KEY_BITS: u16 = 256;
const AES_GCM_128_KEY_BITS: u16 = 128;
const AES_GCM_192_KEY_BITS: u16 = 192;
const AES_GCM_256_KEY_BITS: u16 = 256;
const MODP_2048_PUBLIC_VALUE_LEN: usize = 256;
const ECP_256_PUBLIC_VALUE_LEN: usize = 64;
const ECP_384_PUBLIC_VALUE_LEN: usize = 96;
const ECP_521_PUBLIC_VALUE_LEN: usize = 132;
const MODP_GENERATOR_TWO: u64 = 2;
const MODP_PRIVATE_REJECTION_LIMIT: usize = 64;

const MODP_2048_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

/// IKEv2 Diffie-Hellman groups supported by the SDK SA_INIT material helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2DhGroup {
    /// 2048-bit MODP group, IKEv2 Transform ID 14.
    Modp2048,
    /// NIST P-256 ECP group, IKEv2 Transform ID 19.
    Ecp256,
    /// NIST P-384 ECP group, IKEv2 Transform ID 20.
    Ecp384,
    /// NIST P-521 ECP group, IKEv2 Transform ID 21.
    Ecp521,
}

impl Ikev2DhGroup {
    /// Convert an IKEv2 DH Transform ID to a supported group.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::UnsupportedDhGroup`] for unsupported
    /// Transform IDs.
    pub const fn from_transform_id(transform_id: u16) -> Result<Self, Ikev2SaInitCryptoError> {
        match transform_id {
            DH_MODP_2048 => Ok(Self::Modp2048),
            DH_ECP_256 => Ok(Self::Ecp256),
            DH_ECP_384 => Ok(Self::Ecp384),
            DH_ECP_521 => Ok(Self::Ecp521),
            _ => Err(Ikev2SaInitCryptoError::UnsupportedDhGroup { transform_id }),
        }
    }

    /// IKEv2 DH Transform ID.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::Modp2048 => DH_MODP_2048,
            Self::Ecp256 => DH_ECP_256,
            Self::Ecp384 => DH_ECP_384,
            Self::Ecp521 => DH_ECP_521,
        }
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Modp2048 => "MODP-2048",
            Self::Ecp256 => "ECP-256",
            Self::Ecp384 => "ECP-384",
            Self::Ecp521 => "ECP-521",
        }
    }

    /// Wire public value length in octets for this group.
    pub const fn public_value_len(self) -> usize {
        match self {
            Self::Modp2048 => MODP_2048_PUBLIC_VALUE_LEN,
            Self::Ecp256 => ECP_256_PUBLIC_VALUE_LEN,
            Self::Ecp384 => ECP_384_PUBLIC_VALUE_LEN,
            Self::Ecp521 => ECP_521_PUBLIC_VALUE_LEN,
        }
    }
}

impl TryFrom<u16> for Ikev2DhGroup {
    type Error = Ikev2SaInitCryptoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_transform_id(value)
    }
}

/// IKEv2 PRF algorithms supported by the SDK SA_INIT material helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2PrfAlgorithm {
    /// PRF_HMAC_SHA2_256, IKEv2 Transform ID 5.
    HmacSha2_256,
    /// PRF_HMAC_SHA2_384, IKEv2 Transform ID 6.
    HmacSha2_384,
}

impl Ikev2PrfAlgorithm {
    /// Convert an IKEv2 PRF Transform ID to a supported PRF.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::UnsupportedPrf`] for unsupported
    /// Transform IDs.
    pub const fn from_transform_id(transform_id: u16) -> Result<Self, Ikev2SaInitCryptoError> {
        match transform_id {
            PRF_HMAC_SHA2_256 => Ok(Self::HmacSha2_256),
            PRF_HMAC_SHA2_384 => Ok(Self::HmacSha2_384),
            _ => Err(Ikev2SaInitCryptoError::UnsupportedPrf { transform_id }),
        }
    }

    /// IKEv2 PRF Transform ID.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::HmacSha2_256 => PRF_HMAC_SHA2_256,
            Self::HmacSha2_384 => PRF_HMAC_SHA2_384,
        }
    }

    /// PRF output length and preferred key length in octets.
    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha2_256 => 32,
            Self::HmacSha2_384 => 48,
        }
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::HmacSha2_256 => "HMAC-SHA2-256",
            Self::HmacSha2_384 => "HMAC-SHA2-384",
        }
    }
}

impl TryFrom<u16> for Ikev2PrfAlgorithm {
    type Error = Ikev2SaInitCryptoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_transform_id(value)
    }
}

/// IKEv2 encryption algorithms supported by the SDK SA_INIT material helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2EncryptionAlgorithm {
    /// ENCR_AES_CBC with a 128-bit AES key.
    AesCbc128,
    /// ENCR_AES_CBC with a 192-bit AES key.
    AesCbc192,
    /// ENCR_AES_CBC with a 256-bit AES key.
    AesCbc256,
    /// ENCR_AES_GCM_16 with a 128-bit AES key and 4-octet salt.
    AesGcm16_128,
    /// ENCR_AES_GCM_16 with a 192-bit AES key and 4-octet salt.
    AesGcm16_192,
    /// ENCR_AES_GCM_16 with a 256-bit AES key and 4-octet salt.
    AesGcm16_256,
}

impl Ikev2EncryptionAlgorithm {
    /// Convert IKEv2 encryption Transform ID and Key Length attribute to an algorithm.
    ///
    /// # Errors
    ///
    /// Returns an unsupported encryption error for unsupported Transform IDs
    /// or unsupported/missing AES-GCM key lengths.
    pub const fn from_transform_id(
        transform_id: u16,
        key_bits: Option<u16>,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        match (transform_id, key_bits) {
            (ENCR_AES_CBC, Some(AES_128_KEY_BITS)) => Ok(Self::AesCbc128),
            (ENCR_AES_CBC, Some(AES_192_KEY_BITS)) => Ok(Self::AesCbc192),
            (ENCR_AES_CBC, Some(AES_256_KEY_BITS)) => Ok(Self::AesCbc256),
            (ENCR_AES_CBC, other) => Err(Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
                transform_id,
                key_bits: other,
            }),
            (ENCR_AES_GCM_16, Some(AES_GCM_128_KEY_BITS)) => Ok(Self::AesGcm16_128),
            (ENCR_AES_GCM_16, Some(AES_GCM_192_KEY_BITS)) => Ok(Self::AesGcm16_192),
            (ENCR_AES_GCM_16, Some(AES_GCM_256_KEY_BITS)) => Ok(Self::AesGcm16_256),
            (ENCR_AES_GCM_16, other) => {
                Err(Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
                    transform_id,
                    key_bits: other,
                })
            }
            _ => Err(Ikev2SaInitCryptoError::UnsupportedEncryptionTransform { transform_id }),
        }
    }

    pub(crate) fn from_sa_transform(
        transform: &Ikev2SaTransform<'_>,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        Self::from_transform_id(
            transform.transform_id,
            transform_key_length_bits(transform)?,
        )
    }

    pub(crate) fn from_sa_transform_build(
        transform: &Ikev2SaTransformBuild,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        Self::from_transform_id(
            transform.transform_id,
            transform_build_key_length_bits(transform)?,
        )
    }

    /// IKEv2 encryption Transform ID.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::AesCbc128 | Self::AesCbc192 | Self::AesCbc256 => ENCR_AES_CBC,
            Self::AesGcm16_128 | Self::AesGcm16_192 | Self::AesGcm16_256 => ENCR_AES_GCM_16,
        }
    }

    /// Key Length transform attribute value in bits.
    pub const fn key_bits(self) -> u16 {
        match self {
            Self::AesCbc128 | Self::AesGcm16_128 => AES_128_KEY_BITS,
            Self::AesCbc192 | Self::AesGcm16_192 => AES_192_KEY_BITS,
            Self::AesCbc256 | Self::AesGcm16_256 => AES_256_KEY_BITS,
        }
    }

    /// True for combined-mode AEAD algorithms that do not use a separate
    /// integrity transform.
    pub const fn is_aead(self) -> bool {
        match self {
            Self::AesGcm16_128 | Self::AesGcm16_192 | Self::AesGcm16_256 => true,
            Self::AesCbc128 | Self::AesCbc192 | Self::AesCbc256 => false,
        }
    }

    /// Directional key-material length in octets.
    ///
    /// AES-GCM includes the 4-octet RFC 4106 salt. AES-CBC is the raw cipher
    /// key length only.
    pub const fn key_material_len(self) -> usize {
        let key_len = self.key_bits() as usize / 8;
        if self.is_aead() {
            key_len + AES_GCM_SALT_LEN
        } else {
            key_len
        }
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AesCbc128 => "AES-CBC-128",
            Self::AesCbc192 => "AES-CBC-192",
            Self::AesCbc256 => "AES-CBC-256",
            Self::AesGcm16_128 => "AES-GCM-16-128",
            Self::AesGcm16_192 => "AES-GCM-16-192",
            Self::AesGcm16_256 => "AES-GCM-16-256",
        }
    }
}

/// IKEv2 ESP integrity algorithms for encrypt-then-MAC Child SAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2IntegrityAlgorithm {
    /// AUTH_HMAC_SHA2_256_128, IKEv2 Transform ID 12.
    HmacSha2_256_128,
    /// AUTH_HMAC_SHA2_384_192, IKEv2 Transform ID 13.
    HmacSha2_384_192,
    /// AUTH_HMAC_SHA2_512_256, IKEv2 Transform ID 14.
    HmacSha2_512_256,
}

impl Ikev2IntegrityAlgorithm {
    /// Convert an IKEv2 integrity Transform ID to a supported algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::UnsupportedIntegrityTransform`] for
    /// unsupported Transform IDs.
    pub const fn from_transform_id(transform_id: u16) -> Result<Self, Ikev2SaInitCryptoError> {
        match transform_id {
            INTEG_HMAC_SHA2_256_128 => Ok(Self::HmacSha2_256_128),
            INTEG_HMAC_SHA2_384_192 => Ok(Self::HmacSha2_384_192),
            INTEG_HMAC_SHA2_512_256 => Ok(Self::HmacSha2_512_256),
            _ => Err(Ikev2SaInitCryptoError::UnsupportedIntegrityTransform { transform_id }),
        }
    }

    /// IKEv2 integrity Transform ID.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::HmacSha2_256_128 => INTEG_HMAC_SHA2_256_128,
            Self::HmacSha2_384_192 => INTEG_HMAC_SHA2_384_192,
            Self::HmacSha2_512_256 => INTEG_HMAC_SHA2_512_256,
        }
    }

    /// ESP integrity key length in octets.
    pub const fn key_len(self) -> usize {
        match self {
            Self::HmacSha2_256_128 => 32,
            Self::HmacSha2_384_192 => 48,
            Self::HmacSha2_512_256 => 64,
        }
    }

    /// XFRM authentication truncation length in bits.
    pub const fn icv_len_bits(self) -> u32 {
        match self {
            Self::HmacSha2_256_128 => 128,
            Self::HmacSha2_384_192 => 192,
            Self::HmacSha2_512_256 => 256,
        }
    }

    /// Exact Linux kernel XFRM algorithm name safe to copy into auth requests.
    pub const fn xfrm_name(self) -> &'static str {
        match self {
            Self::HmacSha2_256_128 => "hmac(sha256)",
            Self::HmacSha2_384_192 => "hmac(sha384)",
            Self::HmacSha2_512_256 => "hmac(sha512)",
        }
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::HmacSha2_256_128 => "HMAC-SHA2-256-128",
            Self::HmacSha2_384_192 => "HMAC-SHA2-384-192",
            Self::HmacSha2_512_256 => "HMAC-SHA2-512-256",
        }
    }
}

/// Cipher/integrity profile used to size Child SA KEYMAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2ChildSaCryptoProfile {
    prf: Ikev2PrfAlgorithm,
    encryption: Ikev2EncryptionAlgorithm,
    integrity: Option<Ikev2IntegrityAlgorithm>,
}

impl Ikev2ChildSaCryptoProfile {
    /// Build a combined-mode AEAD Child SA crypto profile.
    #[must_use]
    pub const fn new_aead(prf: Ikev2PrfAlgorithm, encryption: Ikev2EncryptionAlgorithm) -> Self {
        Self {
            prf,
            encryption,
            integrity: None,
        }
    }

    /// Build an encrypt-then-MAC Child SA crypto profile.
    #[must_use]
    pub const fn new_encrypt_then_mac(
        prf: Ikev2PrfAlgorithm,
        encryption: Ikev2EncryptionAlgorithm,
        integrity: Ikev2IntegrityAlgorithm,
    ) -> Self {
        Self {
            prf,
            encryption,
            integrity: Some(integrity),
        }
    }

    /// Build a Child SA profile from a negotiated proposal and IKE-SA PRF.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when the selected transforms omit an
    /// encryption transform, duplicate relevant transforms, or request an
    /// unsupported or inconsistent encryption/integrity shape.
    pub fn from_child_sa_negotiation(
        prf: Ikev2PrfAlgorithm,
        negotiation: &Ikev2ChildSaNegotiation,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        let mut encryption = None;
        let mut integrity = None;

        for transform in &negotiation.transforms {
            match transform.transform_type {
                TRANSFORM_TYPE_ENCR => {
                    if encryption.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    encryption = Some(Ikev2EncryptionAlgorithm::from_transform_id(
                        transform.transform_id,
                        transform_build_key_length_bits(transform)?,
                    )?);
                }
                TRANSFORM_TYPE_INTEG => {
                    if integrity.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    integrity = Some(Ikev2IntegrityAlgorithm::from_transform_id(
                        transform.transform_id,
                    )?);
                }
                _ => {}
            }
        }

        let profile = Self {
            prf,
            encryption: encryption.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?,
            integrity,
        };
        profile.validate_consistency()?;
        Ok(profile)
    }

    /// IKE-SA PRF used to derive `SK_d`.
    pub const fn prf(self) -> Ikev2PrfAlgorithm {
        self.prf
    }

    /// Child SA encryption transform.
    pub const fn encryption(self) -> Ikev2EncryptionAlgorithm {
        self.encryption
    }

    /// Child SA integrity transform; `None` means combined-mode AEAD.
    pub const fn integrity(self) -> Option<Ikev2IntegrityAlgorithm> {
        self.integrity
    }

    /// Per-direction encryption key-material length.
    pub const fn directional_encryption_len(self) -> usize {
        self.encryption.key_material_len()
    }

    /// Per-direction integrity key length.
    pub const fn directional_integrity_len(self) -> usize {
        match self.integrity {
            Some(integrity) => integrity.key_len(),
            None => 0,
        }
    }

    /// Total Child SA KEYMAT length required by RFC 7296 section 2.17.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when the profile is inconsistent,
    /// overflows `usize`, or exceeds the RFC 7296 PRF+ 255-block limit.
    pub fn keymat_len(self) -> Result<usize, Ikev2SaInitCryptoError> {
        self.validate_consistency()?;
        let directional = self
            .directional_encryption_len()
            .checked_add(self.directional_integrity_len())
            .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
                requested_len: usize::MAX,
                prf_output_len: self.prf.output_len(),
            })?;
        let total =
            directional
                .checked_mul(2)
                .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
                    requested_len: usize::MAX,
                    prf_output_len: self.prf.output_len(),
                })?;
        validate_prf_plus_limit(total, self.prf.output_len())?;
        Ok(total)
    }

    fn validate_consistency(self) -> Result<(), Ikev2SaInitCryptoError> {
        match (self.encryption.is_aead(), self.integrity) {
            (true, None) | (false, Some(_)) => Ok(()),
            _ => Err(Ikev2SaInitCryptoError::InconsistentTransformSet),
        }
    }
}

/// Directional Child SA KEYMAT split according to RFC 7296 section 2.17.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaKeyMaterial {
    profile: Ikev2ChildSaCryptoProfile,
    initiator_to_responder_encryption: Zeroizing<Vec<u8>>,
    initiator_to_responder_integrity: Zeroizing<Vec<u8>>,
    responder_to_initiator_encryption: Zeroizing<Vec<u8>>,
    responder_to_initiator_integrity: Zeroizing<Vec<u8>>,
}

impl Ikev2ChildSaKeyMaterial {
    /// Child SA crypto profile used to split this KEYMAT.
    pub const fn profile(&self) -> Ikev2ChildSaCryptoProfile {
        self.profile
    }

    /// Initiator-to-responder encryption key material.
    pub fn initiator_to_responder_encryption(&self) -> &[u8] {
        &self.initiator_to_responder_encryption
    }

    /// Initiator-to-responder integrity key material.
    pub fn initiator_to_responder_integrity(&self) -> &[u8] {
        &self.initiator_to_responder_integrity
    }

    /// Responder-to-initiator encryption key material.
    pub fn responder_to_initiator_encryption(&self) -> &[u8] {
        &self.responder_to_initiator_encryption
    }

    /// Responder-to-initiator integrity key material.
    pub fn responder_to_initiator_integrity(&self) -> &[u8] {
        &self.responder_to_initiator_integrity
    }
}

impl fmt::Debug for Ikev2ChildSaKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaKeyMaterial")
            .field("profile", &self.profile)
            .field(
                "initiator_to_responder_encryption_len",
                &self.initiator_to_responder_encryption.len(),
            )
            .field(
                "initiator_to_responder_integrity_len",
                &self.initiator_to_responder_integrity.len(),
            )
            .field(
                "responder_to_initiator_encryption_len",
                &self.responder_to_initiator_encryption.len(),
            )
            .field(
                "responder_to_initiator_integrity_len",
                &self.responder_to_initiator_integrity.len(),
            )
            .field("material", &"<redacted>")
            .finish()
    }
}

/// Complete supported transform profile for IKE_SA_INIT key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2SaInitCryptoProfile {
    prf: Ikev2PrfAlgorithm,
    dh_group: Ikev2DhGroup,
    encryption: Ikev2EncryptionAlgorithm,
    integrity_key_len: usize,
}

impl Ikev2SaInitCryptoProfile {
    /// Build a supported IKE_SA_INIT crypto profile from algorithms.
    ///
    /// AES-GCM profiles use zero integrity key length. Encrypt-then-MAC
    /// profiles must carry the negotiated integrity key length.
    pub const fn new(
        prf: Ikev2PrfAlgorithm,
        dh_group: Ikev2DhGroup,
        encryption: Ikev2EncryptionAlgorithm,
    ) -> Self {
        Self {
            prf,
            dh_group,
            encryption,
            integrity_key_len: 0,
        }
    }

    /// Negotiated PRF algorithm.
    pub const fn prf(self) -> Ikev2PrfAlgorithm {
        self.prf
    }

    /// Negotiated DH group.
    pub const fn dh_group(self) -> Ikev2DhGroup {
        self.dh_group
    }

    /// Negotiated encryption algorithm.
    pub const fn encryption(self) -> Ikev2EncryptionAlgorithm {
        self.encryption
    }

    /// Integrity key length in octets.
    pub const fn integrity_key_len(self) -> usize {
        self.integrity_key_len
    }

    /// Build a profile from explicit IKEv2 Transform IDs.
    ///
    /// `encryption_key_bits` is the Key Length transform attribute for AES
    /// transforms. AES-GCM profiles require `integrity_key_len == 0`; AES-CBC
    /// profiles require a non-zero integrity key length.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when any transform is unsupported or
    /// the resulting transform set is inconsistent.
    pub const fn from_transform_ids(
        prf_transform_id: u16,
        dh_transform_id: u16,
        encryption_transform_id: u16,
        encryption_key_bits: Option<u16>,
        integrity_key_len: usize,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        let prf = match Ikev2PrfAlgorithm::from_transform_id(prf_transform_id) {
            Ok(prf) => prf,
            Err(error) => return Err(error),
        };
        let dh_group = match Ikev2DhGroup::from_transform_id(dh_transform_id) {
            Ok(group) => group,
            Err(error) => return Err(error),
        };
        let encryption = match Ikev2EncryptionAlgorithm::from_transform_id(
            encryption_transform_id,
            encryption_key_bits,
        ) {
            Ok(encryption) => encryption,
            Err(error) => return Err(error),
        };
        let profile = Self {
            prf,
            dh_group,
            encryption,
            integrity_key_len,
        };
        match (profile.encryption.is_aead(), profile.integrity_key_len) {
            (true, 0) | (false, 1..) => Ok(profile),
            _ => Err(Ikev2SaInitCryptoError::InconsistentTransformSet),
        }
    }

    /// Build a profile from a selected set of decoded SA Transform substructures.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when the selected transforms omit a
    /// required transform, contain duplicate relevant transforms, use an
    /// unsupported algorithm, or request separate integrity with AEAD.
    pub fn from_transforms(
        transforms: &[Ikev2SaTransform<'_>],
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        let mut prf = None;
        let mut dh_group = None;
        let mut encryption = None;
        let mut integrity_key_len = None;

        for transform in transforms {
            match transform.transform_type {
                TRANSFORM_TYPE_ENCR => {
                    if encryption.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    encryption = Some(Ikev2EncryptionAlgorithm::from_transform_id(
                        transform.transform_id,
                        transform_key_length_bits(transform)?,
                    )?);
                }
                TRANSFORM_TYPE_PRF => {
                    if prf.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    prf = Some(Ikev2PrfAlgorithm::from_transform_id(
                        transform.transform_id,
                    )?);
                }
                TRANSFORM_TYPE_INTEG => {
                    if integrity_key_len.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    integrity_key_len = Some(
                        Ikev2IntegrityAlgorithm::from_transform_id(transform.transform_id)?
                            .key_len(),
                    );
                }
                TRANSFORM_TYPE_DH => {
                    if dh_group.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    dh_group = Some(Ikev2DhGroup::from_transform_id(transform.transform_id)?);
                }
                _ => {}
            }
        }

        let profile = Self {
            prf: prf.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?,
            dh_group: dh_group.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?,
            encryption: encryption.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?,
            integrity_key_len: integrity_key_len.unwrap_or(0),
        };
        profile.validate_consistency()?;
        Ok(profile)
    }

    /// Build a profile from a selected decoded SA Proposal substructure.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when the proposal transform set is
    /// unsupported, incomplete, or inconsistent.
    pub fn from_proposal(proposal: &Ikev2SaProposal<'_>) -> Result<Self, Ikev2SaInitCryptoError> {
        if proposal.protocol_id != PROTOCOL_ID_IKE
            || proposal.spi_size != 0
            || !proposal.spi.is_empty()
        {
            return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
        }
        Self::from_transforms(&proposal.transforms)
    }

    /// Total key-material length required by RFC 7296 PRF+.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::KeyMaterialLimitOverflow`] if the
    /// profile lengths overflow `usize` or the RFC 7296 PRF+ counter limit.
    pub fn key_material_len(self) -> Result<usize, Ikev2SaInitCryptoError> {
        self.validate_consistency()?;
        let prf_len = self.prf.output_len();
        let total = prf_len
            .checked_add(self.integrity_key_len)
            .and_then(|value| value.checked_add(self.integrity_key_len))
            .and_then(|value| value.checked_add(self.encryption.key_material_len()))
            .and_then(|value| value.checked_add(self.encryption.key_material_len()))
            .and_then(|value| value.checked_add(prf_len))
            .and_then(|value| value.checked_add(prf_len))
            .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
                requested_len: usize::MAX,
                prf_output_len: prf_len,
            })?;
        validate_prf_plus_limit(total, prf_len)?;
        Ok(total)
    }

    fn validate_consistency(self) -> Result<(), Ikev2SaInitCryptoError> {
        match (self.encryption.is_aead(), self.integrity_key_len) {
            (true, 0) | (false, 1..) => Ok(()),
            _ => Err(Ikev2SaInitCryptoError::InconsistentTransformSet),
        }
    }
}

/// Ephemeral DH/ECDH key pair for one IKE_SA_INIT exchange.
pub struct Ikev2EphemeralDhKey {
    group: Ikev2DhGroup,
    public_value: Vec<u8>,
    secret: Ikev2EphemeralDhSecret,
}

enum Ikev2EphemeralDhSecret {
    Modp2048(Zeroizing<Vec<u8>>),
    Ecp256(P256EphemeralSecret),
    Ecp384(P384EphemeralSecret),
    Ecp521(P521EphemeralSecret),
}

impl Ikev2EphemeralDhKey {
    /// Generate an ephemeral key pair for the supplied group.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::KeyGenerationFailed`] when the system
    /// random source fails or when generated MODP private material cannot be
    /// sampled in range.
    pub fn generate(group: Ikev2DhGroup) -> Result<Self, Ikev2SaInitCryptoError> {
        match group {
            Ikev2DhGroup::Modp2048 => generate_modp2048_key(),
            Ikev2DhGroup::Ecp256 => {
                let secret = P256EphemeralSecret::try_generate()
                    .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
                let public_value = ecp_public_value_bytes(&secret.public_key(), group)?;
                Ok(Self {
                    group,
                    public_value,
                    secret: Ikev2EphemeralDhSecret::Ecp256(secret),
                })
            }
            Ikev2DhGroup::Ecp384 => {
                let secret = P384EphemeralSecret::try_generate()
                    .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
                let public_value = ecp_public_value_bytes(&secret.public_key(), group)?;
                Ok(Self {
                    group,
                    public_value,
                    secret: Ikev2EphemeralDhSecret::Ecp384(secret),
                })
            }
            Ikev2DhGroup::Ecp521 => {
                let secret = P521EphemeralSecret::try_generate()
                    .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
                let public_value = ecp_public_value_bytes(&secret.public_key(), group)?;
                Ok(Self {
                    group,
                    public_value,
                    secret: Ikev2EphemeralDhSecret::Ecp521(secret),
                })
            }
        }
    }

    /// DH group for this key pair.
    pub const fn group(&self) -> Ikev2DhGroup {
        self.group
    }

    /// Public value bytes suitable for the IKEv2 Key Exchange payload.
    pub fn public_value(&self) -> &[u8] {
        &self.public_value
    }

    /// Perform DH/ECDH agreement with the peer's IKEv2 Key Exchange public value.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::InvalidPeerPublicKey`] when the peer
    /// public value has an invalid length or does not validate for the group,
    /// and [`Ikev2SaInitCryptoError::KeyAgreementFailed`] when agreement fails.
    pub fn agree(
        &self,
        peer_public_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
        validate_peer_public_len(self.group, peer_public_value)?;
        match &self.secret {
            Ikev2EphemeralDhSecret::Modp2048(private) => agree_modp2048(private, peer_public_value),
            Ikev2EphemeralDhSecret::Ecp256(secret) => agree_ecp256(secret, peer_public_value),
            Ikev2EphemeralDhSecret::Ecp384(secret) => agree_ecp384(secret, peer_public_value),
            Ikev2EphemeralDhSecret::Ecp521(secret) => agree_ecp521(secret, peer_public_value),
        }
    }
}

impl fmt::Debug for Ikev2EphemeralDhKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2EphemeralDhKey")
            .field("group", &self.group)
            .field("public_value_len", &self.public_value.len())
            .finish_non_exhaustive()
    }
}

/// Derived IKE_SA_INIT SKEYSEED and IKE SA keys.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaInitKeyMaterial {
    ppk_applied: bool,
    skeyseed: Zeroizing<Vec<u8>>,
    sk_d: Zeroizing<Vec<u8>>,
    sk_ai: Zeroizing<Vec<u8>>,
    sk_ar: Zeroizing<Vec<u8>>,
    sk_ei: Zeroizing<Vec<u8>>,
    sk_er: Zeroizing<Vec<u8>>,
    sk_pi: Zeroizing<Vec<u8>>,
    sk_pr: Zeroizing<Vec<u8>>,
}

impl Ikev2SaInitKeyMaterial {
    /// Rebuild established IKE SA key material from persisted `SK_*` bytes.
    ///
    /// This constructor is for restoring an already-established IKE SA after
    /// the IKE_SA_INIT DH secret and nonces have been discarded. `SKEYSEED` is
    /// intentionally not an input because post-establishment message
    /// protection, AUTH verification, and Child SA KEYMAT derivation use the
    /// `SK_*` values directly. The restored value therefore reports an empty
    /// [`Self::skeyseed`].
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] if the profile is inconsistent or any
    /// supplied `SK_*` slice does not match the negotiated profile lengths.
    #[allow(clippy::too_many_arguments)]
    pub fn from_established_keys(
        profile: Ikev2SaInitCryptoProfile,
        ppk_applied: bool,
        sk_d: &[u8],
        sk_ai: &[u8],
        sk_ar: &[u8],
        sk_ei: &[u8],
        sk_er: &[u8],
        sk_pi: &[u8],
        sk_pr: &[u8],
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        profile.validate_consistency()?;

        let prf_len = profile.prf.output_len();
        let integrity_key_len = profile.integrity_key_len;
        let encryption_key_len = profile.encryption.key_material_len();

        validate_exact_key_len("SK_d", sk_d, prf_len)?;
        validate_exact_key_len("SK_ai", sk_ai, integrity_key_len)?;
        validate_exact_key_len("SK_ar", sk_ar, integrity_key_len)?;
        validate_exact_key_len("SK_ei", sk_ei, encryption_key_len)?;
        validate_exact_key_len("SK_er", sk_er, encryption_key_len)?;
        validate_exact_key_len("SK_pi", sk_pi, prf_len)?;
        validate_exact_key_len("SK_pr", sk_pr, prf_len)?;

        Ok(Self {
            ppk_applied,
            skeyseed: Zeroizing::new(Vec::new()),
            sk_d: Zeroizing::new(sk_d.to_vec()),
            sk_ai: Zeroizing::new(sk_ai.to_vec()),
            sk_ar: Zeroizing::new(sk_ar.to_vec()),
            sk_ei: Zeroizing::new(sk_ei.to_vec()),
            sk_er: Zeroizing::new(sk_er.to_vec()),
            sk_pi: Zeroizing::new(sk_pi.to_vec()),
            sk_pr: Zeroizing::new(sk_pr.to_vec()),
        })
    }

    /// Whether RFC 8784 PPK post-processing was applied to SK_d/SK_pi/SK_pr.
    pub const fn ppk_applied(&self) -> bool {
        self.ppk_applied
    }

    /// SKEYSEED from RFC 7296 section 2.14.
    pub fn skeyseed(&self) -> &[u8] {
        &self.skeyseed
    }

    /// SK_d key material.
    pub fn sk_d(&self) -> &[u8] {
        &self.sk_d
    }

    /// SK_ai key material.
    pub fn sk_ai(&self) -> &[u8] {
        &self.sk_ai
    }

    /// SK_ar key material.
    pub fn sk_ar(&self) -> &[u8] {
        &self.sk_ar
    }

    /// SK_ei key material, including AEAD salt for AES-GCM profiles.
    pub fn sk_ei(&self) -> &[u8] {
        &self.sk_ei
    }

    /// SK_er key material, including AEAD salt for AES-GCM profiles.
    pub fn sk_er(&self) -> &[u8] {
        &self.sk_er
    }

    /// SK_pi key material.
    pub fn sk_pi(&self) -> &[u8] {
        &self.sk_pi
    }

    /// SK_pr key material.
    pub fn sk_pr(&self) -> &[u8] {
        &self.sk_pr
    }
}

impl fmt::Debug for Ikev2SaInitKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaInitKeyMaterial")
            .field("ppk_applied", &self.ppk_applied)
            .field("skeyseed_len", &self.skeyseed.len())
            .field("sk_d_len", &self.sk_d.len())
            .field("sk_ai_len", &self.sk_ai.len())
            .field("sk_ar_len", &self.sk_ar.len())
            .field("sk_ei_len", &self.sk_ei.len())
            .field("sk_er_len", &self.sk_er.len())
            .field("sk_pi_len", &self.sk_pi.len())
            .field("sk_pr_len", &self.sk_pr.len())
            .finish()
    }
}

/// Stable machine-readable SA_INIT crypto error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2SaInitCryptoErrorCode {
    /// Unsupported DH group Transform ID.
    UnsupportedDhGroup,
    /// Unsupported PRF Transform ID.
    UnsupportedPrf,
    /// Unsupported encryption Transform ID.
    UnsupportedEncryptionTransform,
    /// Unsupported or missing encryption key length.
    UnsupportedEncryptionKeyLength,
    /// Unsupported integrity Transform ID.
    UnsupportedIntegrityTransform,
    /// Peer public value was invalid for the negotiated DH group.
    InvalidPeerPublicKey,
    /// Ephemeral key generation failed.
    KeyGenerationFailed,
    /// Key agreement failed.
    KeyAgreementFailed,
    /// Nonce length was outside the RFC 7296 range.
    InvalidNonceLength,
    /// Key input length was invalid.
    InvalidKeyLength,
    /// PRF+ requested more material than RFC 7296 permits or `usize` can hold.
    KeyMaterialLimitOverflow,
    /// Transform set omitted a required transform.
    IncompleteTransformSet,
    /// Transform set contained incompatible or duplicate transforms.
    InconsistentTransformSet,
}

impl Ikev2SaInitCryptoErrorCode {
    /// Stable machine-readable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedDhGroup => "ike_sa_init_crypto_unsupported_dh_group",
            Self::UnsupportedPrf => "ike_sa_init_crypto_unsupported_prf",
            Self::UnsupportedEncryptionTransform => {
                "ike_sa_init_crypto_unsupported_encryption_transform"
            }
            Self::UnsupportedEncryptionKeyLength => {
                "ike_sa_init_crypto_unsupported_encryption_key_length"
            }
            Self::UnsupportedIntegrityTransform => {
                "ike_sa_init_crypto_unsupported_integrity_transform"
            }
            Self::InvalidPeerPublicKey => "ike_sa_init_crypto_invalid_peer_public_key",
            Self::KeyGenerationFailed => "ike_sa_init_crypto_key_generation_failed",
            Self::KeyAgreementFailed => "ike_sa_init_crypto_key_agreement_failed",
            Self::InvalidNonceLength => "ike_sa_init_crypto_invalid_nonce_length",
            Self::InvalidKeyLength => "ike_sa_init_crypto_invalid_key_length",
            Self::KeyMaterialLimitOverflow => "ike_sa_init_crypto_key_material_limit_overflow",
            Self::IncompleteTransformSet => "ike_sa_init_crypto_incomplete_transform_set",
            Self::InconsistentTransformSet => "ike_sa_init_crypto_inconsistent_transform_set",
        }
    }
}

/// Error returned by IKE_SA_INIT crypto material helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SaInitCryptoError {
    /// Unsupported DH group Transform ID.
    UnsupportedDhGroup {
        /// Unsupported Transform ID.
        transform_id: u16,
    },
    /// Unsupported PRF Transform ID.
    UnsupportedPrf {
        /// Unsupported Transform ID.
        transform_id: u16,
    },
    /// Unsupported encryption Transform ID.
    UnsupportedEncryptionTransform {
        /// Unsupported Transform ID.
        transform_id: u16,
    },
    /// Unsupported or missing encryption Key Length transform attribute.
    UnsupportedEncryptionKeyLength {
        /// Encryption Transform ID.
        transform_id: u16,
        /// Key Length attribute value, in bits.
        key_bits: Option<u16>,
    },
    /// Unsupported integrity Transform ID.
    UnsupportedIntegrityTransform {
        /// Unsupported Transform ID.
        transform_id: u16,
    },
    /// Peer public value was invalid for the negotiated DH group.
    InvalidPeerPublicKey {
        /// Negotiated DH group.
        group: Ikev2DhGroup,
        /// Supplied peer public value length.
        actual_len: usize,
    },
    /// Ephemeral key generation failed.
    KeyGenerationFailed {
        /// Requested DH group.
        group: Ikev2DhGroup,
    },
    /// Key agreement failed.
    KeyAgreementFailed {
        /// Negotiated DH group.
        group: Ikev2DhGroup,
    },
    /// Nonce length was outside the RFC 7296 range.
    InvalidNonceLength {
        /// Redaction-safe role label.
        role: &'static str,
        /// Supplied nonce length.
        len: usize,
    },
    /// Secret keying input length was invalid.
    InvalidKeyLength {
        /// Redaction-safe key label.
        name: &'static str,
        /// Supplied key length.
        len: usize,
    },
    /// Requested key-material length exceeded the RFC 7296 PRF+ limit.
    KeyMaterialLimitOverflow {
        /// Requested key-material length.
        requested_len: usize,
        /// PRF output length.
        prf_output_len: usize,
    },
    /// Transform set omitted a required transform.
    IncompleteTransformSet,
    /// Transform set contained incompatible or duplicate transforms.
    InconsistentTransformSet,
}

impl Ikev2SaInitCryptoError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> Ikev2SaInitCryptoErrorCode {
        match self {
            Self::UnsupportedDhGroup { .. } => Ikev2SaInitCryptoErrorCode::UnsupportedDhGroup,
            Self::UnsupportedPrf { .. } => Ikev2SaInitCryptoErrorCode::UnsupportedPrf,
            Self::UnsupportedEncryptionTransform { .. } => {
                Ikev2SaInitCryptoErrorCode::UnsupportedEncryptionTransform
            }
            Self::UnsupportedEncryptionKeyLength { .. } => {
                Ikev2SaInitCryptoErrorCode::UnsupportedEncryptionKeyLength
            }
            Self::UnsupportedIntegrityTransform { .. } => {
                Ikev2SaInitCryptoErrorCode::UnsupportedIntegrityTransform
            }
            Self::InvalidPeerPublicKey { .. } => Ikev2SaInitCryptoErrorCode::InvalidPeerPublicKey,
            Self::KeyGenerationFailed { .. } => Ikev2SaInitCryptoErrorCode::KeyGenerationFailed,
            Self::KeyAgreementFailed { .. } => Ikev2SaInitCryptoErrorCode::KeyAgreementFailed,
            Self::InvalidNonceLength { .. } => Ikev2SaInitCryptoErrorCode::InvalidNonceLength,
            Self::InvalidKeyLength { .. } => Ikev2SaInitCryptoErrorCode::InvalidKeyLength,
            Self::KeyMaterialLimitOverflow { .. } => {
                Ikev2SaInitCryptoErrorCode::KeyMaterialLimitOverflow
            }
            Self::IncompleteTransformSet => Ikev2SaInitCryptoErrorCode::IncompleteTransformSet,
            Self::InconsistentTransformSet => Ikev2SaInitCryptoErrorCode::InconsistentTransformSet,
        }
    }

    /// Stable machine-readable error code string.
    pub const fn as_str(&self) -> &'static str {
        self.code().as_str()
    }
}

impl fmt::Display for Ikev2SaInitCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDhGroup { transform_id } => {
                write!(f, "unsupported IKEv2 DH group transform ID {transform_id}")
            }
            Self::UnsupportedPrf { transform_id } => {
                write!(f, "unsupported IKEv2 PRF transform ID {transform_id}")
            }
            Self::UnsupportedEncryptionTransform { transform_id } => {
                write!(
                    f,
                    "unsupported IKEv2 encryption transform ID {transform_id}"
                )
            }
            Self::UnsupportedEncryptionKeyLength {
                transform_id,
                key_bits,
            } => {
                write!(
                    f,
                    "unsupported IKEv2 encryption key length for transform ID {transform_id}: {key_bits:?}"
                )
            }
            Self::UnsupportedIntegrityTransform { transform_id } => {
                write!(f, "unsupported IKEv2 integrity transform ID {transform_id}")
            }
            Self::InvalidPeerPublicKey { group, actual_len } => {
                write!(
                    f,
                    "invalid peer public key for {} with length {actual_len}",
                    group.name()
                )
            }
            Self::KeyGenerationFailed { group } => {
                write!(f, "IKEv2 {} ephemeral key generation failed", group.name())
            }
            Self::KeyAgreementFailed { group } => {
                write!(f, "IKEv2 {} key agreement failed", group.name())
            }
            Self::InvalidNonceLength { role, len } => {
                write!(f, "invalid {role} nonce length {len}")
            }
            Self::InvalidKeyLength { name, len } => {
                write!(f, "invalid {name} length {len}")
            }
            Self::KeyMaterialLimitOverflow {
                requested_len,
                prf_output_len,
            } => {
                write!(
                    f,
                    "IKEv2 key material length {requested_len} exceeds PRF+ limit for output length {prf_output_len}"
                )
            }
            Self::IncompleteTransformSet => f.write_str("incomplete IKEv2 transform set"),
            Self::InconsistentTransformSet => f.write_str("inconsistent IKEv2 transform set"),
        }
    }
}

impl Error for Ikev2SaInitCryptoError {}

/// Derive SKEYSEED and IKE SA keys for an initial IKE_SA_INIT exchange.
///
/// `ppk` is an optional RFC 8784 Post-quantum Preshared Key. When supplied,
/// only SK_d, SK_pi, and SK_pr are re-derived with `prf+ (PPK, SK_*')`; the
/// encryption and integrity keys remain the standard RFC 7296 outputs.
///
/// # Errors
///
/// Returns [`Ikev2SaInitCryptoError`] when nonce lengths are invalid, required
/// secret inputs are empty, or PRF+ length limits would be exceeded.
pub fn derive_ike_sa_init_key_material(
    profile: Ikev2SaInitCryptoProfile,
    initiator_spi: [u8; IKE_SPI_LEN],
    responder_spi: [u8; IKE_SPI_LEN],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    dh_shared_secret: &[u8],
    ppk: Option<&[u8]>,
) -> Result<Ikev2SaInitKeyMaterial, Ikev2SaInitCryptoError> {
    validate_nonce("initiator", initiator_nonce)?;
    validate_nonce("responder", responder_nonce)?;
    validate_secret_input("DH shared secret", dh_shared_secret)?;
    if let Some(ppk) = ppk {
        validate_secret_input("PPK", ppk)?;
    }

    let mut nonce_seed = Vec::with_capacity(initiator_nonce.len() + responder_nonce.len());
    nonce_seed.extend_from_slice(initiator_nonce);
    nonce_seed.extend_from_slice(responder_nonce);
    let skeyseed = prf(profile.prf, &nonce_seed, dh_shared_secret)?;

    let mut key_seed = Vec::with_capacity(nonce_seed.len() + IKE_SPI_LEN + IKE_SPI_LEN);
    key_seed.extend_from_slice(&nonce_seed);
    key_seed.extend_from_slice(&initiator_spi);
    key_seed.extend_from_slice(&responder_spi);

    let key_material_len = profile.key_material_len()?;
    let key_stream = prf_plus(profile.prf, &skeyseed, &key_seed, key_material_len)?;
    split_key_stream(profile, skeyseed, key_stream, ppk)
}

/// Derive Child SA KEYMAT from `SK_d` and Child SA nonces.
///
/// Computes `prf+(SK_d, [g^ir(new) |] Ni | Nr)` and splits the output as
/// `E_i2r | A_i2r | E_r2i | A_r2i` per RFC 7296 section 2.17. Pass
/// `new_dh_shared_secret` for CREATE_CHILD_SA rekey with PFS; use `None` for
/// the initial Child SA or a rekey without PFS.
///
/// # Errors
///
/// Returns [`Ikev2SaInitCryptoError`] when profile/key lengths are
/// inconsistent, nonce lengths are outside RFC 7296 limits, the optional new DH
/// shared secret is empty, or PRF+ cannot produce the requested amount.
pub fn derive_child_sa_key_material(
    profile: Ikev2ChildSaCryptoProfile,
    sk_d: &[u8],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    new_dh_shared_secret: Option<&[u8]>,
) -> Result<Ikev2ChildSaKeyMaterial, Ikev2SaInitCryptoError> {
    validate_exact_key_len("SK_d", sk_d, profile.prf.output_len())?;
    validate_nonce("initiator", initiator_nonce)?;
    validate_nonce("responder", responder_nonce)?;
    if let Some(secret) = new_dh_shared_secret {
        validate_secret_input("new DH shared secret", secret)?;
    }

    let seed_len = initiator_nonce
        .len()
        .checked_add(responder_nonce.len())
        .and_then(|len| len.checked_add(new_dh_shared_secret.map_or(0, <[u8]>::len)))
        .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len: usize::MAX,
            prf_output_len: profile.prf.output_len(),
        })?;
    let mut seed = Zeroizing::new(Vec::with_capacity(seed_len));
    if let Some(secret) = new_dh_shared_secret {
        seed.extend_from_slice(secret);
    }
    seed.extend_from_slice(initiator_nonce);
    seed.extend_from_slice(responder_nonce);

    let key_stream = prf_plus(profile.prf, sk_d, &seed, profile.keymat_len()?)?;
    split_child_key_stream(profile, key_stream)
}

fn split_key_stream(
    profile: Ikev2SaInitCryptoProfile,
    skeyseed: Zeroizing<Vec<u8>>,
    key_stream: Zeroizing<Vec<u8>>,
    ppk: Option<&[u8]>,
) -> Result<Ikev2SaInitKeyMaterial, Ikev2SaInitCryptoError> {
    let prf_len = profile.prf.output_len();
    let integrity_key_len = profile.integrity_key_len;
    let encryption_key_len = profile.encryption.key_material_len();
    let mut offset = 0;
    let mut take =
        |len: usize| take_key_stream(&key_stream, &mut offset, len, profile.prf.output_len());

    let mut sk_d = take(prf_len)?;
    let sk_ai = take(integrity_key_len)?;
    let sk_ar = take(integrity_key_len)?;
    let sk_ei = take(encryption_key_len)?;
    let sk_er = take(encryption_key_len)?;
    let mut sk_pi = take(prf_len)?;
    let mut sk_pr = take(prf_len)?;

    let ppk_applied = if let Some(ppk) = ppk {
        sk_d = prf_plus(profile.prf, ppk, &sk_d, prf_len)?;
        sk_pi = prf_plus(profile.prf, ppk, &sk_pi, prf_len)?;
        sk_pr = prf_plus(profile.prf, ppk, &sk_pr, prf_len)?;
        true
    } else {
        false
    };

    Ok(Ikev2SaInitKeyMaterial {
        ppk_applied,
        skeyseed,
        sk_d,
        sk_ai,
        sk_ar,
        sk_ei,
        sk_er,
        sk_pi,
        sk_pr,
    })
}

fn split_child_key_stream(
    profile: Ikev2ChildSaCryptoProfile,
    key_stream: Zeroizing<Vec<u8>>,
) -> Result<Ikev2ChildSaKeyMaterial, Ikev2SaInitCryptoError> {
    let encryption_key_len = profile.directional_encryption_len();
    let integrity_key_len = profile.directional_integrity_len();
    let mut offset = 0;

    let initiator_to_responder_encryption = take_key_stream(
        &key_stream,
        &mut offset,
        encryption_key_len,
        profile.prf.output_len(),
    )?;
    let initiator_to_responder_integrity = take_key_stream(
        &key_stream,
        &mut offset,
        integrity_key_len,
        profile.prf.output_len(),
    )?;
    let responder_to_initiator_encryption = take_key_stream(
        &key_stream,
        &mut offset,
        encryption_key_len,
        profile.prf.output_len(),
    )?;
    let responder_to_initiator_integrity = take_key_stream(
        &key_stream,
        &mut offset,
        integrity_key_len,
        profile.prf.output_len(),
    )?;

    Ok(Ikev2ChildSaKeyMaterial {
        profile,
        initiator_to_responder_encryption,
        initiator_to_responder_integrity,
        responder_to_initiator_encryption,
        responder_to_initiator_integrity,
    })
}

fn take_key_stream(
    key_stream: &[u8],
    offset: &mut usize,
    len: usize,
    prf_output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let next = offset
        .checked_add(len)
        .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len: usize::MAX,
            prf_output_len,
        })?;
    let Some(bytes) = key_stream.get(*offset..next) else {
        return Err(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len: next,
            prf_output_len,
        });
    };
    *offset = next;
    Ok(Zeroizing::new(bytes.to_vec()))
}

fn validate_nonce(role: &'static str, nonce: &[u8]) -> Result<(), Ikev2SaInitCryptoError> {
    if !(IKEV2_NONCE_MIN_LEN..=IKEV2_NONCE_MAX_LEN).contains(&nonce.len()) {
        return Err(Ikev2SaInitCryptoError::InvalidNonceLength {
            role,
            len: nonce.len(),
        });
    }
    Ok(())
}

fn validate_exact_key_len(
    name: &'static str,
    key: &[u8],
    expected_len: usize,
) -> Result<(), Ikev2SaInitCryptoError> {
    if key.len() != expected_len {
        return Err(Ikev2SaInitCryptoError::InvalidKeyLength {
            name,
            len: key.len(),
        });
    }
    Ok(())
}

fn validate_secret_input(name: &'static str, secret: &[u8]) -> Result<(), Ikev2SaInitCryptoError> {
    if secret.is_empty() {
        return Err(Ikev2SaInitCryptoError::InvalidKeyLength { name, len: 0 });
    }
    Ok(())
}

fn prf(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    match algorithm {
        Ikev2PrfAlgorithm::HmacSha2_256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| {
                Ikev2SaInitCryptoError::InvalidKeyLength {
                    name: "PRF key",
                    len: key.len(),
                }
            })?;
            mac.update(data);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }
        Ikev2PrfAlgorithm::HmacSha2_384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key).map_err(|_| {
                Ikev2SaInitCryptoError::InvalidKeyLength {
                    name: "PRF key",
                    len: key.len(),
                }
            })?;
            mac.update(data);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }
    }
}

fn prf_plus(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    seed: &[u8],
    requested_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let prf_output_len = algorithm.output_len();
    validate_prf_plus_limit(requested_len, prf_output_len)?;
    let mut out = Zeroizing::new(Vec::with_capacity(requested_len));
    let mut previous = Zeroizing::new(Vec::new());
    let mut counter = 1u8;

    while out.len() < requested_len {
        let mut input = Vec::with_capacity(previous.len() + seed.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(seed);
        input.push(counter);
        previous = prf(algorithm, key, &input)?;
        let needed = requested_len - out.len();
        out.extend_from_slice(&previous[..previous.len().min(needed)]);
        counter = counter.wrapping_add(1);
    }

    Ok(out)
}

fn validate_prf_plus_limit(
    requested_len: usize,
    prf_output_len: usize,
) -> Result<(), Ikev2SaInitCryptoError> {
    let max = prf_output_len.checked_mul(255).ok_or(
        Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len,
            prf_output_len,
        },
    )?;
    if requested_len > max {
        return Err(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len,
            prf_output_len,
        });
    }
    Ok(())
}

fn transform_key_length_bits(
    transform: &Ikev2SaTransform<'_>,
) -> Result<Option<u16>, Ikev2SaInitCryptoError> {
    let mut key_bits = None;
    for attribute in &transform.attributes {
        if attribute.attribute_type != TRANSFORM_ATTRIBUTE_KEY_LENGTH {
            continue;
        }
        if key_bits.is_some() {
            return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
        }
        match attribute.value {
            Ikev2TransformAttributeValue::Tv(value) => key_bits = Some(value),
            Ikev2TransformAttributeValue::Tlv(_) => {
                return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
            }
        }
    }
    Ok(key_bits)
}

fn transform_build_key_length_bits(
    transform: &Ikev2SaTransformBuild,
) -> Result<Option<u16>, Ikev2SaInitCryptoError> {
    let mut key_bits = None;
    for attribute in &transform.attributes {
        if attribute.attribute_type != TRANSFORM_ATTRIBUTE_KEY_LENGTH {
            continue;
        }
        if key_bits.is_some() {
            return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
        }
        match &attribute.value {
            Ikev2TransformAttributeBuildValue::Tv(value) => key_bits = Some(*value),
            Ikev2TransformAttributeBuildValue::Tlv(_) => {
                return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
            }
        }
    }
    Ok(key_bits)
}

fn generate_modp2048_key() -> Result<Ikev2EphemeralDhKey, Ikev2SaInitCryptoError> {
    let group = Ikev2DhGroup::Modp2048;
    let prime = modp2048_prime();
    let max_private = prime.wrapping_sub(&U2048::from_u64(2));

    for _ in 0..MODP_PRIVATE_REJECTION_LIMIT {
        let candidate = U2048::try_random()
            .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
        if candidate < U2048::from_u64(2) || candidate > max_private {
            continue;
        }
        let private_bytes = Zeroizing::new(candidate.to_be_bytes().as_ref().to_vec());
        let public_value = modp2048_pow(&U2048::from_u64(MODP_GENERATOR_TWO), &candidate)?
            .to_be_bytes()
            .as_ref()
            .to_vec();
        return Ok(Ikev2EphemeralDhKey {
            group,
            public_value,
            secret: Ikev2EphemeralDhSecret::Modp2048(private_bytes),
        });
    }

    Err(Ikev2SaInitCryptoError::KeyGenerationFailed { group })
}

fn agree_modp2048(
    private: &[u8],
    peer_public_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let group = Ikev2DhGroup::Modp2048;
    let peer = U2048::from_be_slice(peer_public_value);
    let prime = modp2048_prime();
    let min_public = U2048::from_u64(2);
    let max_public = prime.wrapping_sub(&U2048::from_u64(2));
    if peer < min_public || peer > max_public {
        return Err(Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group,
            actual_len: peer_public_value.len(),
        });
    }
    let private = U2048::from_be_slice(private);
    let shared = modp2048_pow(&peer, &private)?;
    if shared <= U2048::ONE {
        return Err(Ikev2SaInitCryptoError::KeyAgreementFailed { group });
    }
    Ok(Zeroizing::new(shared.to_be_bytes().as_ref().to_vec()))
}

fn modp2048_pow(base: &U2048, exponent: &U2048) -> Result<U2048, Ikev2SaInitCryptoError> {
    let odd_prime = Odd::new(modp2048_prime()).into_option().ok_or(
        Ikev2SaInitCryptoError::KeyAgreementFailed {
            group: Ikev2DhGroup::Modp2048,
        },
    )?;
    let params = FixedMontyParams::new_vartime(odd_prime);
    Ok(FixedMontyForm::new(base, &params).pow(exponent).retrieve())
}

fn modp2048_prime() -> U2048 {
    U2048::from_be_hex(MODP_2048_PRIME_HEX)
}

fn validate_peer_public_len(
    group: Ikev2DhGroup,
    peer_public_value: &[u8],
) -> Result<(), Ikev2SaInitCryptoError> {
    if peer_public_value.len() != group.public_value_len() {
        return Err(Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group,
            actual_len: peer_public_value.len(),
        });
    }
    Ok(())
}

fn ecp_public_value_bytes<C>(
    public_key: &p256::elliptic_curve::PublicKey<C>,
    group: Ikev2DhGroup,
) -> Result<Vec<u8>, Ikev2SaInitCryptoError>
where
    C: p256::elliptic_curve::CurveArithmetic + PointCompression,
    p256::elliptic_curve::AffinePoint<C>:
        p256::elliptic_curve::sec1::FromSec1Point<C> + p256::elliptic_curve::sec1::ToSec1Point<C>,
    p256::elliptic_curve::FieldBytesSize<C>: p256::elliptic_curve::sec1::ModulusSize,
{
    let encoded = public_key.to_sec1_point(false);
    let bytes = encoded.as_bytes();
    match bytes.split_first() {
        Some((0x04, xy)) if xy.len() == group.public_value_len() => Ok(xy.to_vec()),
        _ => Err(Ikev2SaInitCryptoError::KeyGenerationFailed { group }),
    }
}

fn sec1_uncompressed_from_ike(
    group: Ikev2DhGroup,
    peer_public_value: &[u8],
) -> Result<Vec<u8>, Ikev2SaInitCryptoError> {
    validate_peer_public_len(group, peer_public_value)?;
    let mut sec1 = Vec::with_capacity(peer_public_value.len() + 1);
    sec1.push(0x04);
    sec1.extend_from_slice(peer_public_value);
    Ok(sec1)
}

fn agree_ecp256(
    secret: &P256EphemeralSecret,
    peer_public_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let group = Ikev2DhGroup::Ecp256;
    let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
    let peer = P256PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group,
            actual_len: peer_public_value.len(),
        }
    })?;
    Ok(Zeroizing::new(
        secret.diffie_hellman(&peer).raw_secret_bytes().to_vec(),
    ))
}

fn agree_ecp384(
    secret: &P384EphemeralSecret,
    peer_public_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let group = Ikev2DhGroup::Ecp384;
    let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
    let peer = P384PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group,
            actual_len: peer_public_value.len(),
        }
    })?;
    Ok(Zeroizing::new(
        secret.diffie_hellman(&peer).raw_secret_bytes().to_vec(),
    ))
}

fn agree_ecp521(
    secret: &P521EphemeralSecret,
    peer_public_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    let group = Ikev2DhGroup::Ecp521;
    let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
    let peer = P521PublicKey::from_sec1_bytes(&sec1).map_err(|_| {
        Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group,
            actual_len: peer_public_value.len(),
        }
    })?;
    Ok(Zeroizing::new(
        secret.diffie_hellman(&peer).raw_secret_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ike_auth::Ikev2TrafficSelectorBuild,
        sa_init::{Ikev2TransformAttribute, Ikev2TransformAttributeBuild},
    };

    fn must_ok<T, E: fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    fn must_err<T: fmt::Debug, E>(result: Result<T, E>) -> E {
        match result {
            Ok(value) => panic!("unexpected success: {value:?}"),
            Err(error) => error,
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len() % 2, 0);
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn base_profile(encryption: Ikev2EncryptionAlgorithm) -> Ikev2SaInitCryptoProfile {
        Ikev2SaInitCryptoProfile::new(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2DhGroup::Ecp256,
            encryption,
        )
    }

    fn selected_transform_set() -> Vec<Ikev2SaTransform<'static>> {
        vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttribute {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeValue::Tv(128),
                }],
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_PRF,
                transform_id: PRF_HMAC_SHA2_256,
                attributes: Vec::new(),
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_DH,
                transform_id: DH_ECP_256,
                attributes: Vec::new(),
            },
        ]
    }

    fn child_sa_negotiation(transforms: Vec<Ikev2SaTransformBuild>) -> Ikev2ChildSaNegotiation {
        let selector = Ikev2TrafficSelectorBuild {
            ts_type: 7,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: vec![192, 0, 2, 1],
            end_address: vec![192, 0, 2, 1],
        };
        Ikev2ChildSaNegotiation {
            proposal_number: 1,
            protocol_id: 3,
            initiator_spi: vec![0x11, 0x22, 0x33, 0x44],
            transforms,
            initiator_traffic_selector: selector.clone(),
            responder_traffic_selector: selector,
        }
    }

    #[test]
    fn transform_id_conversions_are_stable() {
        assert_eq!(
            must_ok(Ikev2DhGroup::from_transform_id(14)),
            Ikev2DhGroup::Modp2048
        );
        assert_eq!(
            must_ok(Ikev2DhGroup::from_transform_id(19)),
            Ikev2DhGroup::Ecp256
        );
        assert_eq!(
            must_ok(Ikev2DhGroup::from_transform_id(20)),
            Ikev2DhGroup::Ecp384
        );
        assert_eq!(
            must_ok(Ikev2DhGroup::from_transform_id(21)),
            Ikev2DhGroup::Ecp521
        );
        assert_eq!(
            must_ok(Ikev2PrfAlgorithm::from_transform_id(5)),
            Ikev2PrfAlgorithm::HmacSha2_256
        );
        assert_eq!(
            must_ok(Ikev2PrfAlgorithm::from_transform_id(6)),
            Ikev2PrfAlgorithm::HmacSha2_384
        );
        assert_eq!(
            must_ok(Ikev2EncryptionAlgorithm::from_transform_id(20, Some(128))),
            Ikev2EncryptionAlgorithm::AesGcm16_128
        );
        assert_eq!(
            must_ok(Ikev2EncryptionAlgorithm::from_transform_id(20, Some(192))),
            Ikev2EncryptionAlgorithm::AesGcm16_192
        );
        assert_eq!(
            must_ok(Ikev2EncryptionAlgorithm::from_transform_id(20, Some(256))),
            Ikev2EncryptionAlgorithm::AesGcm16_256
        );
        assert_eq!(
            must_ok(Ikev2EncryptionAlgorithm::from_transform_id(12, Some(256))),
            Ikev2EncryptionAlgorithm::AesCbc256
        );
        assert_eq!(
            must_ok(Ikev2IntegrityAlgorithm::from_transform_id(12)),
            Ikev2IntegrityAlgorithm::HmacSha2_256_128
        );
    }

    #[test]
    fn integrity_xfrm_names_use_linux_kernel_templates() {
        assert_eq!(
            Ikev2IntegrityAlgorithm::HmacSha2_256_128.xfrm_name(),
            "hmac(sha256)"
        );
        assert_eq!(
            Ikev2IntegrityAlgorithm::HmacSha2_384_192.xfrm_name(),
            "hmac(sha384)"
        );
        assert_eq!(
            Ikev2IntegrityAlgorithm::HmacSha2_512_256.xfrm_name(),
            "hmac(sha512)"
        );
    }

    #[test]
    fn unsupported_transform_ids_fail_closed_with_stable_codes() {
        assert_eq!(
            must_err(Ikev2DhGroup::from_transform_id(31)).as_str(),
            "ike_sa_init_crypto_unsupported_dh_group"
        );
        assert_eq!(
            must_err(Ikev2PrfAlgorithm::from_transform_id(9)).as_str(),
            "ike_sa_init_crypto_unsupported_prf"
        );
        assert_eq!(
            must_err(Ikev2EncryptionAlgorithm::from_transform_id(99, Some(128))).as_str(),
            "ike_sa_init_crypto_unsupported_encryption_transform"
        );
        assert_eq!(
            must_err(Ikev2EncryptionAlgorithm::from_transform_id(20, Some(224))).as_str(),
            "ike_sa_init_crypto_unsupported_encryption_key_length"
        );
        assert_eq!(
            must_err(Ikev2EncryptionAlgorithm::from_transform_id(20, None)).as_str(),
            "ike_sa_init_crypto_unsupported_encryption_key_length"
        );
        assert_eq!(
            must_err(Ikev2IntegrityAlgorithm::from_transform_id(99)).as_str(),
            "ike_sa_init_crypto_unsupported_integrity_transform"
        );
    }

    #[test]
    fn profile_builds_from_selected_transform_set() {
        let transforms = vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttribute {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeValue::Tv(256),
                }],
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_PRF,
                transform_id: PRF_HMAC_SHA2_384,
                attributes: Vec::new(),
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_DH,
                transform_id: DH_ECP_384,
                attributes: Vec::new(),
            },
        ];

        let profile = must_ok(Ikev2SaInitCryptoProfile::from_transforms(&transforms));
        assert_eq!(profile.prf(), Ikev2PrfAlgorithm::HmacSha2_384);
        assert_eq!(profile.dh_group(), Ikev2DhGroup::Ecp384);
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::AesGcm16_256);
        assert_eq!(profile.integrity_key_len(), 0);
    }

    #[test]
    fn profile_builds_from_selected_ike_proposal_shape() {
        let proposal = Ikev2SaProposal {
            proposal_number: 1,
            protocol_id: PROTOCOL_ID_IKE,
            spi_size: 0,
            spi: &[],
            transforms: selected_transform_set(),
        };

        let profile = must_ok(Ikev2SaInitCryptoProfile::from_proposal(&proposal));
        assert_eq!(profile.prf(), Ikev2PrfAlgorithm::HmacSha2_256);
        assert_eq!(profile.dh_group(), Ikev2DhGroup::Ecp256);
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::AesGcm16_128);
    }

    #[test]
    fn profile_rejects_incomplete_and_inconsistent_transform_sets() {
        let missing_dh = vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttribute {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeValue::Tv(128),
                }],
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_PRF,
                transform_id: PRF_HMAC_SHA2_256,
                attributes: Vec::new(),
            },
        ];
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(&missing_dh)).as_str(),
            "ike_sa_init_crypto_incomplete_transform_set"
        );

        let duplicate_prf = vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttribute {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeValue::Tv(128),
                }],
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_PRF,
                transform_id: PRF_HMAC_SHA2_256,
                attributes: Vec::new(),
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_PRF,
                transform_id: PRF_HMAC_SHA2_384,
                attributes: Vec::new(),
            },
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_DH,
                transform_id: DH_ECP_256,
                attributes: Vec::new(),
            },
        ];
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(&duplicate_prf)).as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        let explicit_integrity = vec![
            selected_transform_set()[0].clone(),
            selected_transform_set()[1].clone(),
            selected_transform_set()[2].clone(),
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_INTEG,
                transform_id: 12,
                attributes: Vec::new(),
            },
        ];
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(
                &explicit_integrity
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        let duplicate_key_length = vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![
                    Ikev2TransformAttribute {
                        attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                        value: Ikev2TransformAttributeValue::Tv(128),
                    },
                    Ikev2TransformAttribute {
                        attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                        value: Ikev2TransformAttributeValue::Tv(256),
                    },
                ],
            },
            selected_transform_set()[1].clone(),
            selected_transform_set()[2].clone(),
        ];
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(
                &duplicate_key_length
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        let tlv_key_length = vec![
            Ikev2SaTransform {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttribute {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeValue::Tlv(&[0, 128]),
                }],
            },
            selected_transform_set()[1].clone(),
            selected_transform_set()[2].clone(),
        ];
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(&tlv_key_length)).as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transform_ids(
                PRF_HMAC_SHA2_256,
                DH_ECP_256,
                ENCR_AES_GCM_16,
                Some(128),
                16,
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );
    }

    #[test]
    fn profile_rejects_non_ike_sa_init_proposal_shapes() {
        let esp_proposal = Ikev2SaProposal {
            proposal_number: 1,
            protocol_id: 3,
            spi_size: 0,
            spi: &[],
            transforms: selected_transform_set(),
        };
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_proposal(&esp_proposal)).as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        let proposal_with_spi_size = Ikev2SaProposal {
            proposal_number: 1,
            protocol_id: PROTOCOL_ID_IKE,
            spi_size: 8,
            spi: &[],
            transforms: selected_transform_set(),
        };
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_proposal(
                &proposal_with_spi_size
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );

        let spi = [0xaau8; 8];
        let proposal_with_spi = Ikev2SaProposal {
            proposal_number: 1,
            protocol_id: PROTOCOL_ID_IKE,
            spi_size: 0,
            spi: &spi,
            transforms: selected_transform_set(),
        };
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_proposal(&proposal_with_spi)).as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );
    }

    #[test]
    fn dh_round_trip_succeeds_for_all_supported_groups() {
        for group in [
            Ikev2DhGroup::Modp2048,
            Ikev2DhGroup::Ecp256,
            Ikev2DhGroup::Ecp384,
            Ikev2DhGroup::Ecp521,
        ] {
            let left = must_ok(Ikev2EphemeralDhKey::generate(group));
            let right = must_ok(Ikev2EphemeralDhKey::generate(group));
            assert_eq!(left.public_value().len(), group.public_value_len());
            assert_eq!(right.public_value().len(), group.public_value_len());

            let left_shared = must_ok(left.agree(right.public_value()));
            let right_shared = must_ok(right.agree(left.public_value()));
            assert_eq!(&*left_shared, &*right_shared);
            assert!(!left_shared.is_empty());
        }
    }

    #[test]
    fn malformed_peer_public_values_fail_closed() {
        for group in [
            Ikev2DhGroup::Modp2048,
            Ikev2DhGroup::Ecp256,
            Ikev2DhGroup::Ecp384,
            Ikev2DhGroup::Ecp521,
        ] {
            let key = must_ok(Ikev2EphemeralDhKey::generate(group));
            let short = vec![0u8; group.public_value_len() - 1];
            assert_eq!(
                must_err(key.agree(&short)).as_str(),
                "ike_sa_init_crypto_invalid_peer_public_key"
            );
            let zeros = vec![0u8; group.public_value_len()];
            assert_eq!(
                must_err(key.agree(&zeros)).as_str(),
                "ike_sa_init_crypto_invalid_peer_public_key"
            );
        }
    }

    #[test]
    fn skeyseed_matches_existing_epdg_vector() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let ni = hex_to_bytes("5b0f9f3a20b5a4e7190d1778d88f8f1f");
        let nr = hex_to_bytes("2cf8de5f0df8188a4b68dcb068fc2a67");
        let shared = hex_to_bytes(concat!(
            "9f8bbf6c18db2946d5a4f1e7c039ce2b7c3344733b7bc7f7",
            "b9426f14f0e657e636b988f9a4602732c3ce8fae2a5afdbfb0",
            "8d98bc577f71589d6e8a39f8ea2b42"
        ));
        let expected =
            hex_to_bytes("4ee8eaac55159b21c5bfaa70b9686c9e45d0eeeed2a1ae94cdda0c9ccbaf87cb");

        let material = must_ok(derive_ike_sa_init_key_material(
            profile,
            0x0102030405060708u64.to_be_bytes(),
            0x1112131415161718u64.to_be_bytes(),
            &ni,
            &nr,
            &shared,
            None,
        ));

        assert_eq!(material.skeyseed(), expected.as_slice());
    }

    #[test]
    fn split_key_stream_rejects_short_stream_without_panicking() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let required_len = must_ok(profile.key_material_len());
        let short_stream = Zeroizing::new(vec![0x44; required_len - 1]);
        let skeyseed = Zeroizing::new(vec![0x33; profile.prf.output_len()]);

        let err = must_err(split_key_stream(profile, skeyseed, short_stream, None));

        assert_eq!(
            err.as_str(),
            "ike_sa_init_crypto_key_material_limit_overflow"
        );
    }

    #[test]
    fn aes_gcm_key_lengths_include_salt() {
        assert_eq!(
            Ikev2EncryptionAlgorithm::AesGcm16_128.key_material_len(),
            20
        );
        assert_eq!(
            Ikev2EncryptionAlgorithm::AesGcm16_192.key_material_len(),
            28
        );
        assert_eq!(
            Ikev2EncryptionAlgorithm::AesGcm16_256.key_material_len(),
            36
        );

        let ni = [0x11u8; 16];
        let nr = [0x22u8; 16];
        let shared = [0x33u8; 32];
        let material_128 = must_ok(derive_ike_sa_init_key_material(
            base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128),
            [0x44; 8],
            [0x55; 8],
            &ni,
            &nr,
            &shared,
            None,
        ));
        assert_eq!(material_128.sk_ei().len(), 20);
        assert_eq!(material_128.sk_er().len(), 20);
        assert_eq!(material_128.sk_ai().len(), 0);
        assert_eq!(material_128.sk_ar().len(), 0);

        let material_256 = must_ok(derive_ike_sa_init_key_material(
            base_profile(Ikev2EncryptionAlgorithm::AesGcm16_256),
            [0x44; 8],
            [0x55; 8],
            &ni,
            &nr,
            &shared,
            None,
        ));
        assert_eq!(material_256.sk_ei().len(), 36);
        assert_eq!(material_256.sk_er().len(), 36);
    }

    #[test]
    fn child_sa_keymat_aes_gcm_reference_vector_is_split_directionally() {
        let profile = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        );
        let material = must_ok(derive_child_sa_key_material(
            profile,
            &[0x0f; 32],
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));

        assert_eq!(material.profile(), profile);
        assert_eq!(profile.directional_encryption_len(), 36);
        assert_eq!(profile.directional_integrity_len(), 0);
        assert_eq!(
            material.initiator_to_responder_encryption(),
            hex_to_bytes(
                "7ae50b9713ddfd346dbb3cfbe8b8d45a34c79925bedb4f4ae6a5ad6bc76d8ab578ea306c"
            )
        );
        assert_eq!(material.initiator_to_responder_integrity(), &[]);
        assert_eq!(
            material.responder_to_initiator_encryption(),
            hex_to_bytes(
                "e36f6fde3c1f71951c1fe8c6d7477a4a2adfe9b746fd3c6fd6be52da8c2afd17eeff3e2a"
            )
        );
        assert_eq!(material.responder_to_initiator_integrity(), &[]);

        let rendered = format!("{material:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("7ae50b9713ddfd34"));
        assert!(!rendered.contains("e36f6fde3c1f7195"));
    }

    #[test]
    fn child_sa_keymat_pfs_seed_prepends_new_dh_secret() {
        let profile = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        );
        let no_pfs = must_ok(derive_child_sa_key_material(
            profile,
            &[0x0f; 32],
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));
        let with_pfs = must_ok(derive_child_sa_key_material(
            profile,
            &[0x0f; 32],
            &[0xa1; 16],
            &[0xb2; 16],
            Some(&[0xc3; 32]),
        ));

        assert_ne!(
            no_pfs.initiator_to_responder_encryption(),
            with_pfs.initiator_to_responder_encryption()
        );
        assert_eq!(
            with_pfs.initiator_to_responder_encryption(),
            hex_to_bytes(
                "4fa879ae7695e8b30398b8a9c20682e1783fd1fa74fd1e9cccb2328416ae39d0445275aa"
            )
        );
        assert_eq!(
            with_pfs.responder_to_initiator_encryption(),
            hex_to_bytes(
                "d985e7bfa178e8a896b425c196d2a6c05c9d7ced9b3b988aad31df0d7f496fd142abbaef"
            )
        );
    }

    #[test]
    fn child_sa_keymat_encrypt_then_mac_splits_encryption_then_integrity() {
        let profile = Ikev2ChildSaCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
        );
        let material = must_ok(derive_child_sa_key_material(
            profile,
            &[0x0f; 32],
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));

        assert_eq!(must_ok(profile.keymat_len()), 128);
        assert_eq!(profile.directional_encryption_len(), 32);
        assert_eq!(profile.directional_integrity_len(), 32);
        assert_eq!(
            material.initiator_to_responder_encryption(),
            hex_to_bytes("7ae50b9713ddfd346dbb3cfbe8b8d45a34c79925bedb4f4ae6a5ad6bc76d8ab5")
        );
        assert_eq!(
            material.initiator_to_responder_integrity(),
            hex_to_bytes("78ea306ce36f6fde3c1f71951c1fe8c6d7477a4a2adfe9b746fd3c6fd6be52da")
        );
        assert_eq!(
            material.responder_to_initiator_encryption(),
            hex_to_bytes("8c2afd17eeff3e2a77f1c49d07cb5a9456546102f02fe52ee641dd4e3bc207ce")
        );
        assert_eq!(
            material.responder_to_initiator_integrity(),
            hex_to_bytes("537f5464dcf7a673975dae2711e072fbc781ec3e2edb96e163d216aae050d513")
        );
    }

    #[test]
    fn child_sa_profile_builds_from_negotiated_transforms() {
        let aes_gcm = child_sa_negotiation(vec![Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_ENCR,
            transform_id: ENCR_AES_GCM_16,
            attributes: vec![Ikev2TransformAttributeBuild {
                attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                value: Ikev2TransformAttributeBuildValue::Tv(256),
            }],
        }]);
        let profile = must_ok(Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &aes_gcm,
        ));
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::AesGcm16_256);
        assert_eq!(profile.integrity(), None);

        let aes_cbc = child_sa_negotiation(vec![
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_CBC,
                attributes: vec![Ikev2TransformAttributeBuild {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeBuildValue::Tv(256),
                }],
            },
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_INTEG,
                transform_id: INTEG_HMAC_SHA2_256_128,
                attributes: Vec::new(),
            },
        ]);
        let profile = must_ok(Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &aes_cbc,
        ));
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::AesCbc256);
        assert_eq!(
            profile.integrity(),
            Some(Ikev2IntegrityAlgorithm::HmacSha2_256_128)
        );

        let gcm_with_integrity = child_sa_negotiation(vec![
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_AES_GCM_16,
                attributes: vec![Ikev2TransformAttributeBuild {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeBuildValue::Tv(256),
                }],
            },
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_INTEG,
                transform_id: INTEG_HMAC_SHA2_256_128,
                attributes: Vec::new(),
            },
        ]);
        assert_eq!(
            must_err(Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
                Ikev2PrfAlgorithm::HmacSha2_256,
                &gcm_with_integrity,
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );
    }

    #[test]
    fn child_sa_keymat_rejects_invalid_inputs_fail_closed() {
        let profile = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_128,
        );
        assert_eq!(
            must_err(derive_child_sa_key_material(
                profile,
                &[0x0f; 31],
                &[0xa1; 16],
                &[0xb2; 16],
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );
        assert_eq!(
            must_err(derive_child_sa_key_material(
                profile,
                &[0x0f; 32],
                &[0xa1; 15],
                &[0xb2; 16],
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_nonce_length"
        );
        assert_eq!(
            must_err(derive_child_sa_key_material(
                profile,
                &[0x0f; 32],
                &[0xa1; 16],
                &[0xb2; 16],
                Some(&[]),
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );

        let inconsistent = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesCbc256,
        );
        assert_eq!(
            must_err(derive_child_sa_key_material(
                inconsistent,
                &[0x0f; 32],
                &[0xa1; 16],
                &[0xb2; 16],
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );
    }

    #[test]
    fn ppk_rederives_only_sk_d_sk_pi_sk_pr() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let ni = [0x11u8; 16];
        let nr = [0x22u8; 16];
        let shared = [0x33u8; 32];
        let ppk = b"high-entropy-post-quantum-preshared-key";

        let standard = must_ok(derive_ike_sa_init_key_material(
            profile, [0x44; 8], [0x55; 8], &ni, &nr, &shared, None,
        ));
        let with_ppk = must_ok(derive_ike_sa_init_key_material(
            profile,
            [0x44; 8],
            [0x55; 8],
            &ni,
            &nr,
            &shared,
            Some(ppk),
        ));

        assert!(with_ppk.ppk_applied());
        assert_eq!(
            with_ppk.sk_d(),
            &*must_ok(prf_plus(
                profile.prf(),
                ppk,
                standard.sk_d(),
                profile.prf().output_len(),
            ))
        );
        assert_eq!(
            with_ppk.sk_pi(),
            &*must_ok(prf_plus(
                profile.prf(),
                ppk,
                standard.sk_pi(),
                profile.prf().output_len(),
            ))
        );
        assert_eq!(
            with_ppk.sk_pr(),
            &*must_ok(prf_plus(
                profile.prf(),
                ppk,
                standard.sk_pr(),
                profile.prf().output_len(),
            ))
        );
        assert_ne!(standard.sk_d(), with_ppk.sk_d());
        assert_ne!(standard.sk_pi(), with_ppk.sk_pi());
        assert_ne!(standard.sk_pr(), with_ppk.sk_pr());
        assert_eq!(standard.sk_ai(), with_ppk.sk_ai());
        assert_eq!(standard.sk_ar(), with_ppk.sk_ar());
        assert_eq!(standard.sk_ei(), with_ppk.sk_ei());
        assert_eq!(standard.sk_er(), with_ppk.sk_er());
        assert_eq!(standard.skeyseed(), with_ppk.skeyseed());
    }

    #[test]
    fn established_key_material_rehydrates_derived_keys_without_skeyseed() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let ni = [0x11u8; 16];
        let nr = [0x22u8; 16];
        let shared = [0x33u8; 32];
        let material = must_ok(derive_ike_sa_init_key_material(
            profile,
            [0x44; 8],
            [0x55; 8],
            &ni,
            &nr,
            &shared,
            Some(b"sealed-restore-ppk"),
        ));

        let restored = must_ok(Ikev2SaInitKeyMaterial::from_established_keys(
            profile,
            material.ppk_applied(),
            material.sk_d(),
            material.sk_ai(),
            material.sk_ar(),
            material.sk_ei(),
            material.sk_er(),
            material.sk_pi(),
            material.sk_pr(),
        ));

        assert!(restored.ppk_applied());
        assert!(restored.skeyseed().is_empty());
        assert_eq!(restored.sk_d(), material.sk_d());
        assert_eq!(restored.sk_ai(), material.sk_ai());
        assert_eq!(restored.sk_ar(), material.sk_ar());
        assert_eq!(restored.sk_ei(), material.sk_ei());
        assert_eq!(restored.sk_er(), material.sk_er());
        assert_eq!(restored.sk_pi(), material.sk_pi());
        assert_eq!(restored.sk_pr(), material.sk_pr());

        let child_profile = Ikev2ChildSaCryptoProfile::new_aead(
            profile.prf(),
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        );
        let child_from_live = must_ok(derive_child_sa_key_material(
            child_profile,
            material.sk_d(),
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));
        let child_from_restored = must_ok(derive_child_sa_key_material(
            child_profile,
            restored.sk_d(),
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));
        assert_eq!(child_from_restored, child_from_live);
    }

    #[test]
    fn established_key_material_rejects_profile_length_mismatch() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let good_sk_d = [0x10; 32];
        let bad_sk_d = [0x10; 31];
        let good_sk_e = [0x20; 20];
        let bad_sk_e = [0x20; 19];
        let good_sk_p = [0x30; 32];

        assert_eq!(
            must_err(Ikev2SaInitKeyMaterial::from_established_keys(
                profile,
                false,
                &bad_sk_d,
                &[],
                &[],
                &good_sk_e,
                &good_sk_e,
                &good_sk_p,
                &good_sk_p,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );

        assert_eq!(
            must_err(Ikev2SaInitKeyMaterial::from_established_keys(
                profile,
                false,
                &good_sk_d,
                &[],
                &[],
                &bad_sk_e,
                &good_sk_e,
                &good_sk_p,
                &good_sk_p,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );

        let cbc_profile = Ikev2SaInitCryptoProfile::new(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2DhGroup::Ecp256,
            Ikev2EncryptionAlgorithm::AesCbc256,
        );
        assert_eq!(
            must_err(Ikev2SaInitKeyMaterial::from_established_keys(
                cbc_profile,
                false,
                &good_sk_d,
                &[],
                &[],
                &[0x20; 32],
                &[0x20; 32],
                &good_sk_p,
                &good_sk_p,
            ))
            .as_str(),
            "ike_sa_init_crypto_inconsistent_transform_set"
        );
    }

    #[test]
    fn sha384_profile_derives_expected_material_lengths() {
        let profile = must_ok(Ikev2SaInitCryptoProfile::from_transform_ids(
            PRF_HMAC_SHA2_384,
            DH_ECP_384,
            ENCR_AES_GCM_16,
            Some(256),
            0,
        ));
        let ni = [0x11u8; IKEV2_NONCE_MAX_LEN];
        let nr = [0x22u8; IKEV2_NONCE_MAX_LEN];
        let shared = [0x33u8; 48];

        let material = must_ok(derive_ike_sa_init_key_material(
            profile, [0x44; 8], [0x55; 8], &ni, &nr, &shared, None,
        ));

        assert_eq!(material.skeyseed().len(), 48);
        assert_eq!(material.sk_d().len(), 48);
        assert_eq!(material.sk_pi().len(), 48);
        assert_eq!(material.sk_pr().len(), 48);
        assert_eq!(material.sk_ei().len(), 36);
        assert_eq!(material.sk_er().len(), 36);
    }

    #[test]
    fn invalid_nonce_and_key_lengths_fail_closed() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let nonce = [0x11u8; 16];
        let overlong_nonce = [0x11u8; IKEV2_NONCE_MAX_LEN + 1];
        let shared = [0x33u8; 32];

        assert_eq!(
            must_err(derive_ike_sa_init_key_material(
                profile, [0; 8], [1; 8], &[0u8; 15], &nonce, &shared, None,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_nonce_length"
        );
        assert_eq!(
            must_err(derive_ike_sa_init_key_material(
                profile,
                [0; 8],
                [1; 8],
                &overlong_nonce,
                &nonce,
                &shared,
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_nonce_length"
        );
        assert_eq!(
            must_err(derive_ike_sa_init_key_material(
                profile,
                [0; 8],
                [1; 8],
                &nonce,
                &nonce,
                &[],
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );
        assert_eq!(
            must_err(derive_ike_sa_init_key_material(
                profile,
                [0; 8],
                [1; 8],
                &nonce,
                &nonce,
                &shared,
                Some(&[]),
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );
    }

    #[test]
    fn redacted_debug_and_display_do_not_leak_material() {
        let profile = base_profile(Ikev2EncryptionAlgorithm::AesGcm16_128);
        let ni = hex_to_bytes("5b0f9f3a20b5a4e7190d1778d88f8f1f");
        let nr = hex_to_bytes("2cf8de5f0df8188a4b68dcb068fc2a67");
        let shared = hex_to_bytes(
            "9f8bbf6c18db2946d5a4f1e7c039ce2b7c3344733b7bc7f7b9426f14f0e657e636b988f9a4602732c3ce8fae2a5afdbfb08d98bc577f71589d6e8a39f8ea2b42",
        );
        let key = must_ok(Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256));
        let material = must_ok(derive_ike_sa_init_key_material(
            profile,
            [0x44; 8],
            [0x55; 8],
            &ni,
            &nr,
            &shared,
            Some(b"redaction-test-ppk"),
        ));

        let rendered = format!(
            "{:?} {:?} {}",
            key,
            material,
            Ikev2SaInitCryptoError::InvalidPeerPublicKey {
                group: Ikev2DhGroup::Ecp256,
                actual_len: 64,
            }
        );
        let forbidden = [
            "5b0f9f3a20b5a4e7190d1778d88f8f1f",
            "2cf8de5f0df8188a4b68dcb068fc2a67",
            "9f8bbf6c18db2946d5a4f1e7c039ce2b",
            "redaction-test-ppk",
            "4ee8eaac55159b21c5bfaa70b9686c9e",
            "private",
            "shared_secret",
        ];
        for needle in forbidden {
            assert!(
                !rendered.contains(needle),
                "rendered output leaked {needle}: {rendered}"
            );
        }
        assert!(rendered.contains("public_value_len"));
        assert!(rendered.contains("skeyseed_len"));
    }
}
