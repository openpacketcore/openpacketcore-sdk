//! IKE_SA_INIT key-agreement and key-material derivation helpers.
//!
//! This module owns only transport-neutral IKE_SA_INIT cryptographic material:
//! supported transform identifiers, ephemeral DH/ECDH, SKEYSEED, PRF+, and the
//! seven IKE SA keys produced from the negotiated transforms. It deliberately
//! does not own IKE SA state, authentication, EAP, Child SA installation,
//! responder SPI allocation, retransmission, or ePDG/N3IWF policy.
//!
//! @spec IETF RFC7296 2.14, 2.17, 2.18, 3.3.2, 3.3.5; IETF RFC4868 2.6-2.7;
//! IETF RFC8784 2
//! @req REQ-IETF-RFC7296-SA-INIT-CRYPTO-MATERIAL-001

use std::{error::Error, fmt};

use crypto_bigint::{
    modular::{FixedMontyForm, FixedMontyParams},
    Odd, Random, U2048,
};
use opc_crypto_provider::{CryptoOperationErrorCode, IkeDhKeyPair};
use p256::{
    ecdh::EphemeralSecret as P256EphemeralSecret,
    elliptic_curve::{common::Generate, point::PointCompression, sec1::ToSec1Point},
    PublicKey as P256PublicKey,
};
use p384::{ecdh::EphemeralSecret as P384EphemeralSecret, PublicKey as P384PublicKey};
use p521::{ecdh::EphemeralSecret as P521EphemeralSecret, PublicKey as P521PublicKey};
use zeroize::Zeroizing;

use crate::{
    crypto_module::{
        execute_dh_agree, execute_dh_generate, execute_prf, execute_prf_plus,
        Ikev2CryptoModuleError,
    },
    hmac_sha2::{hmac_sha2_256, hmac_sha2_384, hmac_sha2_512},
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

const ENCR_NULL: u16 = 11;
const ENCR_AES_CBC: u16 = 12;
const ENCR_AES_GCM_16: u16 = 20;
const PRF_HMAC_SHA2_256: u16 = 5;
const PRF_HMAC_SHA2_384: u16 = 6;
const PRF_HMAC_SHA2_512: u16 = 7;
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
const MODP_2048_SHARED_SECRET_LEN: usize = 256;
const ECP_256_SHARED_SECRET_LEN: usize = 32;
const ECP_384_SHARED_SECRET_LEN: usize = 48;
const ECP_521_SHARED_SECRET_LEN: usize = 66;
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

    /// Fixed-width shared-secret length in octets for this group.
    ///
    /// MODP agreement is padded to the modulus width. ECP agreement uses the
    /// fixed-width x-coordinate representation defined for the group.
    pub const fn shared_secret_len(self) -> usize {
        match self {
            Self::Modp2048 => MODP_2048_SHARED_SECRET_LEN,
            Self::Ecp256 => ECP_256_SHARED_SECRET_LEN,
            Self::Ecp384 => ECP_384_SHARED_SECRET_LEN,
            Self::Ecp521 => ECP_521_SHARED_SECRET_LEN,
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
    /// PRF_HMAC_SHA2_512, IKEv2 Transform ID 7.
    HmacSha2_512,
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
            PRF_HMAC_SHA2_512 => Ok(Self::HmacSha2_512),
            _ => Err(Ikev2SaInitCryptoError::UnsupportedPrf { transform_id }),
        }
    }

    /// IKEv2 PRF Transform ID.
    pub const fn transform_id(self) -> u16 {
        match self {
            Self::HmacSha2_256 => PRF_HMAC_SHA2_256,
            Self::HmacSha2_384 => PRF_HMAC_SHA2_384,
            Self::HmacSha2_512 => PRF_HMAC_SHA2_512,
        }
    }

    /// PRF output length and preferred key length in octets.
    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha2_256 => 32,
            Self::HmacSha2_384 => 48,
            Self::HmacSha2_512 => 64,
        }
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::HmacSha2_256 => "HMAC-SHA2-256",
            Self::HmacSha2_384 => "HMAC-SHA2-384",
            Self::HmacSha2_512 => "HMAC-SHA2-512",
        }
    }
}

impl TryFrom<u16> for Ikev2PrfAlgorithm {
    type Error = Ikev2SaInitCryptoError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::from_transform_id(value)
    }
}

/// IKEv2 encryption algorithms supported by the SDK IKE/Child-SA helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2EncryptionAlgorithm {
    /// ENCR_NULL, Transform ID 11, for authenticated-only ESP Child SAs.
    ///
    /// This transform has no key, salt, or Key Length attribute. It is not an
    /// executable IKE-SA protected-payload algorithm.
    Null,
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
    /// Returns an unsupported encryption error for unsupported Transform IDs,
    /// prohibited ENCR_NULL Key Length attributes, or unsupported/missing AES
    /// key lengths.
    pub const fn from_transform_id(
        transform_id: u16,
        key_bits: Option<u16>,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        match (transform_id, key_bits) {
            (ENCR_NULL, None) => Ok(Self::Null),
            (ENCR_NULL, other) => Err(Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
                transform_id,
                key_bits: other,
            }),
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
            Self::Null => ENCR_NULL,
            Self::AesCbc128 | Self::AesCbc192 | Self::AesCbc256 => ENCR_AES_CBC,
            Self::AesGcm16_128 | Self::AesGcm16_192 | Self::AesGcm16_256 => ENCR_AES_GCM_16,
        }
    }

    /// Raw encryption-key length in bits.
    ///
    /// ENCR_NULL returns zero. Use [`Self::key_length_attribute_bits`] when
    /// building a transform because ENCR_NULL prohibits the Key Length
    /// attribute rather than encoding an attribute with value zero.
    pub const fn key_bits(self) -> u16 {
        match self {
            Self::Null => 0,
            Self::AesCbc128 | Self::AesGcm16_128 => AES_128_KEY_BITS,
            Self::AesCbc192 | Self::AesGcm16_192 => AES_192_KEY_BITS,
            Self::AesCbc256 | Self::AesGcm16_256 => AES_256_KEY_BITS,
        }
    }

    /// Key Length transform attribute value, when the transform permits one.
    pub const fn key_length_attribute_bits(self) -> Option<u16> {
        match self {
            Self::Null => None,
            _ => Some(self.key_bits()),
        }
    }

    /// Raw per-direction encryption-key length in octets, excluding any salt.
    pub const fn encryption_key_len(self) -> usize {
        self.key_bits() as usize / 8
    }

    /// Per-direction salt length in octets.
    pub const fn salt_len(self) -> usize {
        if self.is_aead() {
            AES_GCM_SALT_LEN
        } else {
            0
        }
    }

    /// True when this is the authenticated-only ESP ENCR_NULL transform.
    pub const fn is_null(self) -> bool {
        matches!(self, Self::Null)
    }

    /// True for combined-mode AEAD algorithms that do not use a separate
    /// integrity transform.
    pub const fn is_aead(self) -> bool {
        match self {
            Self::AesGcm16_128 | Self::AesGcm16_192 | Self::AesGcm16_256 => true,
            Self::Null | Self::AesCbc128 | Self::AesCbc192 | Self::AesCbc256 => false,
        }
    }

    /// Directional key-material length in octets.
    ///
    /// AES-GCM includes the 4-octet RFC 4106 salt. AES-CBC is the raw cipher
    /// key length only, and ENCR_NULL is zero.
    pub const fn key_material_len(self) -> usize {
        self.encryption_key_len() + self.salt_len()
    }

    /// Human-readable algorithm name safe for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::AesCbc128 => "AES-CBC-128",
            Self::AesCbc192 => "AES-CBC-192",
            Self::AesCbc256 => "AES-CBC-256",
            Self::AesGcm16_128 => "AES-GCM-16-128",
            Self::AesGcm16_192 => "AES-GCM-16-192",
            Self::AesGcm16_256 => "AES-GCM-16-256",
        }
    }
}

/// IKEv2 integrity algorithms for encrypt-then-MAC IKE and Child SAs.
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

    /// Preferred integrity key length in octets.
    pub const fn key_len(self) -> usize {
        match self {
            Self::HmacSha2_256_128 => 32,
            Self::HmacSha2_384_192 => 48,
            Self::HmacSha2_512_256 => 64,
        }
    }

    /// Truncated integrity checksum length in octets.
    pub const fn icv_len(self) -> usize {
        match self {
            Self::HmacSha2_256_128 => 16,
            Self::HmacSha2_384_192 => 24,
            Self::HmacSha2_512_256 => 32,
        }
    }

    /// XFRM authentication truncation length in bits.
    pub const fn icv_len_bits(self) -> u32 {
        (self.icv_len() * 8) as u32
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

    /// Build an authenticated-only ESP Child SA using ENCR_NULL.
    ///
    /// This profile derives only the selected directional integrity keys. It
    /// does not fabricate encryption key or salt bytes.
    #[must_use]
    pub const fn new_authenticated_only(
        prf: Ikev2PrfAlgorithm,
        integrity: Ikev2IntegrityAlgorithm,
    ) -> Self {
        Self {
            prf,
            encryption: Ikev2EncryptionAlgorithm::Null,
            integrity: Some(integrity),
        }
    }

    /// Restore a Child-SA profile from its exact negotiated Transform IDs.
    ///
    /// `encryption_key_bits` is the received Key Length attribute. It must be
    /// `None` for ENCR_NULL. `integrity_transform_id` is required for
    /// ENCR_NULL and AES-CBC and prohibited for AEAD transforms.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when a transform is unsupported or
    /// the restored transform relationship is inconsistent.
    pub const fn from_transform_ids(
        prf_transform_id: u16,
        encryption_transform_id: u16,
        encryption_key_bits: Option<u16>,
        integrity_transform_id: Option<u16>,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        let prf = match Ikev2PrfAlgorithm::from_transform_id(prf_transform_id) {
            Ok(prf) => prf,
            Err(error) => return Err(error),
        };
        let encryption = match Ikev2EncryptionAlgorithm::from_transform_id(
            encryption_transform_id,
            encryption_key_bits,
        ) {
            Ok(encryption) => encryption,
            Err(error) => return Err(error),
        };
        let integrity = match integrity_transform_id {
            Some(transform_id) => match Ikev2IntegrityAlgorithm::from_transform_id(transform_id) {
                Ok(integrity) => Some(integrity),
                Err(error) => return Err(error),
            },
            None => None,
        };
        let profile = Self {
            prf,
            encryption,
            integrity,
        };
        match profile.validate_executable() {
            Ok(()) => Ok(profile),
            Err(error) => Err(error),
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
        profile.validate_executable()?;
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
        self.validate_executable()?;
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

    /// Validate the Child-SA transform relationship before deriving KEYMAT.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::InconsistentTransformSet`] for
    /// ENCR_NULL/AES-CBC without integrity or AEAD with separate integrity.
    pub const fn validate_executable(self) -> Result<(), Ikev2SaInitCryptoError> {
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
    integrity: Option<Ikev2IntegrityAlgorithm>,
}

impl Ikev2SaInitCryptoProfile {
    /// Build a supported combined-mode AEAD IKE-SA crypto profile.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::MissingIntegrityTransform`] when
    /// `encryption` is not an AEAD algorithm.
    pub const fn new_aead(
        prf: Ikev2PrfAlgorithm,
        dh_group: Ikev2DhGroup,
        encryption: Ikev2EncryptionAlgorithm,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        if !encryption.is_aead() {
            return Err(Ikev2SaInitCryptoError::MissingIntegrityTransform);
        }
        Ok(Self {
            prf,
            dh_group,
            encryption,
            integrity: None,
        })
    }

    /// Build a supported encrypt-then-MAC IKE-SA crypto profile.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError::UnexpectedIntegrityTransform`] when
    /// `encryption` is an AEAD algorithm.
    pub const fn new_encrypt_then_mac(
        prf: Ikev2PrfAlgorithm,
        dh_group: Ikev2DhGroup,
        encryption: Ikev2EncryptionAlgorithm,
        integrity: Ikev2IntegrityAlgorithm,
    ) -> Result<Self, Ikev2SaInitCryptoError> {
        if encryption.is_aead() {
            return Err(Ikev2SaInitCryptoError::UnexpectedIntegrityTransform);
        }
        if encryption.is_null() {
            return Err(Ikev2SaInitCryptoError::UnsupportedEncryptionTransform {
                transform_id: ENCR_NULL,
            });
        }
        Ok(Self {
            prf,
            dh_group,
            encryption,
            integrity: Some(integrity),
        })
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

    /// Negotiated integrity algorithm, or `None` for combined-mode AEAD.
    pub const fn integrity(self) -> Option<Ikev2IntegrityAlgorithm> {
        self.integrity
    }

    /// Integrity key length in octets.
    pub const fn integrity_key_len(self) -> usize {
        match self.integrity {
            Some(integrity) => integrity.key_len(),
            None => 0,
        }
    }

    /// Integrity checksum length in octets, or zero for combined-mode AEAD.
    pub const fn integrity_icv_len(self) -> usize {
        match self.integrity {
            Some(integrity) => integrity.icv_len(),
            None => 0,
        }
    }

    /// Validate that every layer needed to protect IKE messages can execute
    /// this profile.
    ///
    /// Profiles can only be obtained through validating constructors, so this
    /// is primarily a configuration-validation boundary for consumers that
    /// want an explicit startup capability check.
    ///
    /// # Errors
    ///
    /// Returns a typed crypto error if the profile is not executable.
    pub const fn validate_executable(self) -> Result<(), Ikev2SaInitCryptoError> {
        if self.encryption.is_null() {
            return Err(Ikev2SaInitCryptoError::UnsupportedEncryptionTransform {
                transform_id: ENCR_NULL,
            });
        }
        match (self.encryption.is_aead(), self.integrity) {
            (true, None) | (false, Some(_)) => Ok(()),
            (true, Some(_)) => Err(Ikev2SaInitCryptoError::UnexpectedIntegrityTransform),
            (false, None) => Err(Ikev2SaInitCryptoError::MissingIntegrityTransform),
        }
    }

    /// Build a profile from explicit IKEv2 Transform IDs.
    ///
    /// `encryption_key_bits` is the Key Length transform attribute for AES
    /// transforms. `integrity_transform_id` must be `None` for AES-GCM and the
    /// negotiated typed integrity Transform ID for AES-CBC.
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
        integrity_transform_id: Option<u16>,
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
        match integrity_transform_id {
            Some(transform_id) => {
                let integrity = match Ikev2IntegrityAlgorithm::from_transform_id(transform_id) {
                    Ok(integrity) => integrity,
                    Err(error) => return Err(error),
                };
                Self::new_encrypt_then_mac(prf, dh_group, encryption, integrity)
            }
            None => Self::new_aead(prf, dh_group, encryption),
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
        let mut integrity = None;

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
                    if integrity.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    integrity = Some(Ikev2IntegrityAlgorithm::from_transform_id(
                        transform.transform_id,
                    )?);
                }
                TRANSFORM_TYPE_DH => {
                    if dh_group.is_some() {
                        return Err(Ikev2SaInitCryptoError::InconsistentTransformSet);
                    }
                    dh_group = Some(Ikev2DhGroup::from_transform_id(transform.transform_id)?);
                }
                _ => return Err(Ikev2SaInitCryptoError::InconsistentTransformSet),
            }
        }

        let prf = prf.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?;
        let dh_group = dh_group.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?;
        let encryption = encryption.ok_or(Ikev2SaInitCryptoError::IncompleteTransformSet)?;
        match integrity {
            Some(integrity) => Self::new_encrypt_then_mac(prf, dh_group, encryption, integrity),
            None => Self::new_aead(prf, dh_group, encryption),
        }
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
        self.validate_executable()?;
        let prf_len = self.prf.output_len();
        let integrity_key_len = self.integrity_key_len();
        let total = prf_len
            .checked_add(integrity_key_len)
            .and_then(|value| value.checked_add(integrity_key_len))
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
}

/// Ephemeral DH/ECDH key pair for one IKE_SA_INIT exchange.
pub struct Ikev2EphemeralDhKey {
    group: Ikev2DhGroup,
    public_value: Vec<u8>,
    inner: Box<dyn IkeDhKeyPair>,
}

impl Ikev2EphemeralDhKey {
    /// Generate an ephemeral key pair through the admitted process module.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when the module admission is absent
    /// or withdrawn, the group was not preflighted, or generation fails.
    pub fn generate(group: Ikev2DhGroup) -> Result<Self, Ikev2SaInitCryptoError> {
        let (inner, public_value) =
            execute_dh_generate(group).map_err(|error| map_dh_module_error(group, 0, error))?;
        Ok(Self {
            group,
            public_value,
            inner,
        })
    }

    /// DH group for this key pair.
    pub const fn group(&self) -> Ikev2DhGroup {
        self.group
    }

    /// Public value bytes suitable for the IKEv2 Key Exchange payload.
    pub fn public_value(&self) -> &[u8] {
        &self.public_value
    }

    /// Perform agreement after rechecking the original module admission.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] when admission or readiness was
    /// withdrawn after generation, the peer value is invalid, or agreement
    /// fails.
    pub fn agree(
        &self,
        peer_public_value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
        execute_dh_agree(
            self.group,
            self.inner.as_ref(),
            &self.public_value,
            peer_public_value,
        )
        .map_err(|error| map_dh_module_error(self.group, peer_public_value.len(), error))
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

fn map_dh_module_error(
    group: Ikev2DhGroup,
    peer_public_len: usize,
    error: Ikev2CryptoModuleError,
) -> Ikev2SaInitCryptoError {
    match error.operation_code() {
        Some(CryptoOperationErrorCode::InvalidPeerPublicKey) => {
            Ikev2SaInitCryptoError::InvalidPeerPublicKey {
                group,
                actual_len: peer_public_len,
            }
        }
        Some(CryptoOperationErrorCode::KeyGenerationFailed) => {
            Ikev2SaInitCryptoError::KeyGenerationFailed { group }
        }
        Some(CryptoOperationErrorCode::KeyAgreementFailed) => {
            Ikev2SaInitCryptoError::KeyAgreementFailed { group }
        }
        _ => Ikev2SaInitCryptoError::CryptoModuleFailure { error },
    }
}

pub(crate) struct SoftwareEphemeralDhKey {
    group: Ikev2DhGroup,
    public_value: Vec<u8>,
    secret: SoftwareEphemeralDhSecret,
}

enum SoftwareEphemeralDhSecret {
    Modp2048(Zeroizing<Vec<u8>>),
    Ecp256(P256EphemeralSecret),
    Ecp384(P384EphemeralSecret),
    Ecp521(P521EphemeralSecret),
}

impl SoftwareEphemeralDhKey {
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
                    secret: SoftwareEphemeralDhSecret::Ecp256(secret),
                })
            }
            Ikev2DhGroup::Ecp384 => {
                let secret = P384EphemeralSecret::try_generate()
                    .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
                let public_value = ecp_public_value_bytes(&secret.public_key(), group)?;
                Ok(Self {
                    group,
                    public_value,
                    secret: SoftwareEphemeralDhSecret::Ecp384(secret),
                })
            }
            Ikev2DhGroup::Ecp521 => {
                let secret = P521EphemeralSecret::try_generate()
                    .map_err(|_| Ikev2SaInitCryptoError::KeyGenerationFailed { group })?;
                let public_value = ecp_public_value_bytes(&secret.public_key(), group)?;
                Ok(Self {
                    group,
                    public_value,
                    secret: SoftwareEphemeralDhSecret::Ecp521(secret),
                })
            }
        }
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
            SoftwareEphemeralDhSecret::Modp2048(private) => {
                agree_modp2048(private, peer_public_value)
            }
            SoftwareEphemeralDhSecret::Ecp256(secret) => agree_ecp256(secret, peer_public_value),
            SoftwareEphemeralDhSecret::Ecp384(secret) => agree_ecp384(secret, peer_public_value),
            SoftwareEphemeralDhSecret::Ecp521(secret) => agree_ecp521(secret, peer_public_value),
        }
    }
}

impl fmt::Debug for SoftwareEphemeralDhKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareEphemeralDhKey")
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
        profile.validate_executable()?;

        let prf_len = profile.prf.output_len();
        let integrity_key_len = profile.integrity_key_len();
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
    /// Encrypt-then-MAC encryption omitted its required integrity transform.
    MissingIntegrityTransform,
    /// AEAD encryption supplied a prohibited separate integrity transform.
    UnexpectedIntegrityTransform,
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
    /// The admitted process crypto module was absent, withdrawn, or failed.
    CryptoModuleFailure,
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
            Self::MissingIntegrityTransform => "ike_sa_init_crypto_missing_integrity_transform",
            Self::UnexpectedIntegrityTransform => {
                "ike_sa_init_crypto_unexpected_integrity_transform"
            }
            Self::InvalidPeerPublicKey => "ike_sa_init_crypto_invalid_peer_public_key",
            Self::KeyGenerationFailed => "ike_sa_init_crypto_key_generation_failed",
            Self::KeyAgreementFailed => "ike_sa_init_crypto_key_agreement_failed",
            Self::InvalidNonceLength => "ike_sa_init_crypto_invalid_nonce_length",
            Self::InvalidKeyLength => "ike_sa_init_crypto_invalid_key_length",
            Self::KeyMaterialLimitOverflow => "ike_sa_init_crypto_key_material_limit_overflow",
            Self::IncompleteTransformSet => "ike_sa_init_crypto_incomplete_transform_set",
            Self::InconsistentTransformSet => "ike_sa_init_crypto_inconsistent_transform_set",
            Self::CryptoModuleFailure => "ike_sa_init_crypto_module_failure",
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
    /// Encrypt-then-MAC encryption omitted its required integrity transform.
    MissingIntegrityTransform,
    /// AEAD encryption supplied a prohibited separate integrity transform.
    UnexpectedIntegrityTransform,
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
    /// The admitted process crypto module was absent, withdrawn, or failed.
    CryptoModuleFailure {
        /// Stable, redaction-safe module boundary error.
        error: Ikev2CryptoModuleError,
    },
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
            Self::MissingIntegrityTransform => {
                Ikev2SaInitCryptoErrorCode::MissingIntegrityTransform
            }
            Self::UnexpectedIntegrityTransform => {
                Ikev2SaInitCryptoErrorCode::UnexpectedIntegrityTransform
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
            Self::CryptoModuleFailure { .. } => Ikev2SaInitCryptoErrorCode::CryptoModuleFailure,
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
            Self::MissingIntegrityTransform => {
                f.write_str("IKEv2 encryption requires a separate integrity transform")
            }
            Self::UnexpectedIntegrityTransform => {
                f.write_str("IKEv2 AEAD encryption prohibits a separate integrity transform")
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
            Self::CryptoModuleFailure { error } => {
                write!(f, "IKEv2 crypto module operation failed: {error}")
            }
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

/// Derive key material for an IKE SA created by an IKE-SA rekey exchange.
///
/// RFC 7296 section 2.18 deliberately uses two possibly different PRFs. The
/// old IKE SA's negotiated PRF derives the new `SKEYSEED` from `SK_d (old)`,
/// while the new IKE SA's negotiated PRF expands that `SKEYSEED` into the new
/// seven-key stream. `new_dh_shared_secret` is mandatory for an IKE-SA rekey
/// and must already use the selected group's fixed-width representation: 256
/// octets for MODP-2048 or 32, 48, and 66 octets for ECP-256, ECP-384, and
/// ECP-521 respectively. MODP leading-zero padding and the ECP fixed-width
/// x-coordinate representation must be retained.
///
/// RFC 8784 PPK post-processing is not repeated during rekey. Quantum
/// resistance, when present, is inherited through the old SA's already-mixed
/// `SK_d` input.
///
/// # Errors
///
/// Returns [`Ikev2SaInitCryptoError`] when the new profile is not executable,
/// `old_sk_d` does not match the old PRF's preferred key length, a nonce or
/// the mandatory new DH secret has the wrong fixed width, or PRF+ limits are
/// exceeded. Shared-secret failures reuse the redaction-safe
/// [`Ikev2SaInitCryptoError::InvalidKeyLength`] contract.
#[allow(clippy::too_many_arguments)]
pub fn derive_ike_sa_rekey_key_material(
    old_prf: Ikev2PrfAlgorithm,
    old_sk_d: &[u8],
    new_profile: Ikev2SaInitCryptoProfile,
    new_initiator_spi: [u8; IKE_SPI_LEN],
    new_responder_spi: [u8; IKE_SPI_LEN],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    new_dh_shared_secret: &[u8],
) -> Result<Ikev2SaInitKeyMaterial, Ikev2SaInitCryptoError> {
    new_profile.validate_executable()?;
    validate_exact_key_len("old SK_d", old_sk_d, old_prf.output_len())?;
    validate_nonce("initiator", initiator_nonce)?;
    validate_nonce("responder", responder_nonce)?;
    validate_dh_shared_secret_len(new_profile.dh_group(), new_dh_shared_secret)?;

    let rekey_seed_len = new_dh_shared_secret
        .len()
        .checked_add(initiator_nonce.len())
        .and_then(|len| len.checked_add(responder_nonce.len()))
        .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len: usize::MAX,
            prf_output_len: old_prf.output_len(),
        })?;
    let mut rekey_seed = Zeroizing::new(Vec::with_capacity(rekey_seed_len));
    rekey_seed.extend_from_slice(new_dh_shared_secret);
    rekey_seed.extend_from_slice(initiator_nonce);
    rekey_seed.extend_from_slice(responder_nonce);
    let skeyseed = prf(old_prf, old_sk_d, &rekey_seed)?;

    let key_seed_len = initiator_nonce
        .len()
        .checked_add(responder_nonce.len())
        .and_then(|len| len.checked_add(IKE_SPI_LEN * 2))
        .ok_or(Ikev2SaInitCryptoError::KeyMaterialLimitOverflow {
            requested_len: usize::MAX,
            prf_output_len: new_profile.prf.output_len(),
        })?;
    let mut key_seed = Vec::with_capacity(key_seed_len);
    key_seed.extend_from_slice(initiator_nonce);
    key_seed.extend_from_slice(responder_nonce);
    key_seed.extend_from_slice(&new_initiator_spi);
    key_seed.extend_from_slice(&new_responder_spi);

    let key_stream = prf_plus(
        new_profile.prf,
        &skeyseed,
        &key_seed,
        new_profile.key_material_len()?,
    )?;
    split_key_stream(new_profile, skeyseed, key_stream, None)
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
    let integrity_key_len = profile.integrity_key_len();
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

fn validate_dh_shared_secret_len(
    group: Ikev2DhGroup,
    secret: &[u8],
) -> Result<(), Ikev2SaInitCryptoError> {
    let expected_len = group.shared_secret_len();
    if secret.len() != expected_len {
        return Err(Ikev2SaInitCryptoError::InvalidKeyLength {
            // Keep the pre-existing empty-input diagnostic stable while using
            // the same established public variant for every invalid width.
            name: "new DH shared secret",
            len: secret.len(),
        });
    }
    Ok(())
}

pub(crate) fn prf(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    execute_prf(algorithm, key, data)
        .map_err(|error| Ikev2SaInitCryptoError::CryptoModuleFailure { error })
}

pub(crate) fn software_prf(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    if key.is_empty() {
        return Err(Ikev2SaInitCryptoError::InvalidKeyLength {
            name: "PRF key",
            len: 0,
        });
    }
    match algorithm {
        Ikev2PrfAlgorithm::HmacSha2_256 => Ok(hmac_sha2_256(key, &[data])),
        Ikev2PrfAlgorithm::HmacSha2_384 => Ok(hmac_sha2_384(key, &[data])),
        Ikev2PrfAlgorithm::HmacSha2_512 => Ok(hmac_sha2_512(key, &[data])),
    }
}

pub(crate) fn prf_plus(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Ikev2SaInitCryptoError> {
    execute_prf_plus(algorithm, key, seed, output_len)
        .map_err(|error| Ikev2SaInitCryptoError::CryptoModuleFailure { error })
}

pub(crate) fn software_prf_plus(
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
        let mut input = Zeroizing::new(Vec::with_capacity(previous.len() + seed.len() + 1));
        input.extend_from_slice(&previous);
        input.extend_from_slice(seed);
        input.push(counter);
        previous = software_prf(algorithm, key, &input)?;
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

fn generate_modp2048_key() -> Result<SoftwareEphemeralDhKey, Ikev2SaInitCryptoError> {
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
        return Ok(SoftwareEphemeralDhKey {
            group,
            public_value,
            secret: SoftwareEphemeralDhSecret::Modp2048(private_bytes),
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

pub(crate) fn validate_dh_public_value(
    group: Ikev2DhGroup,
    peer_public_value: &[u8],
) -> Result<(), Ikev2SaInitCryptoError> {
    validate_peer_public_len(group, peer_public_value)?;
    let invalid = || Ikev2SaInitCryptoError::InvalidPeerPublicKey {
        group,
        actual_len: peer_public_value.len(),
    };
    match group {
        Ikev2DhGroup::Modp2048 => {
            let peer = U2048::from_be_slice(peer_public_value);
            let prime = modp2048_prime();
            let min_public = U2048::from_u64(2);
            let max_public = prime.wrapping_sub(&U2048::from_u64(2));
            if peer < min_public || peer > max_public {
                return Err(invalid());
            }
        }
        Ikev2DhGroup::Ecp256 => {
            let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
            P256PublicKey::from_sec1_bytes(&sec1).map_err(|_| invalid())?;
        }
        Ikev2DhGroup::Ecp384 => {
            let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
            P384PublicKey::from_sec1_bytes(&sec1).map_err(|_| invalid())?;
        }
        Ikev2DhGroup::Ecp521 => {
            let sec1 = sec1_uncompressed_from_ike(group, peer_public_value)?;
            P521PublicKey::from_sec1_bytes(&sec1).map_err(|_| invalid())?;
        }
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
        crate::test_support::ensure_ike_crypto();
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
        must_ok(Ikev2SaInitCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2DhGroup::Ecp256,
            encryption,
        ))
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

    fn observed_cbc_sha512_transform_set(
        integrity_before_prf: bool,
    ) -> Vec<Ikev2SaTransform<'static>> {
        let encryption = Ikev2SaTransform {
            transform_type: TRANSFORM_TYPE_ENCR,
            transform_id: ENCR_AES_CBC,
            attributes: vec![Ikev2TransformAttribute {
                attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                value: Ikev2TransformAttributeValue::Tv(AES_256_KEY_BITS),
            }],
        };
        let integrity = Ikev2SaTransform {
            transform_type: TRANSFORM_TYPE_INTEG,
            transform_id: INTEG_HMAC_SHA2_512_256,
            attributes: Vec::new(),
        };
        let prf = Ikev2SaTransform {
            transform_type: TRANSFORM_TYPE_PRF,
            transform_id: PRF_HMAC_SHA2_512,
            attributes: Vec::new(),
        };
        let dh = Ikev2SaTransform {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: DH_MODP_2048,
            attributes: Vec::new(),
        };

        if integrity_before_prf {
            vec![encryption, integrity, prf, dh]
        } else {
            vec![encryption, prf, integrity, dh]
        }
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
            must_ok(Ikev2PrfAlgorithm::from_transform_id(7)),
            Ikev2PrfAlgorithm::HmacSha2_512
        );
        assert_eq!(Ikev2PrfAlgorithm::HmacSha2_512.transform_id(), 7);
        assert_eq!(Ikev2PrfAlgorithm::HmacSha2_512.output_len(), 64);
        assert_eq!(Ikev2PrfAlgorithm::HmacSha2_512.name(), "HMAC-SHA2-512");
        assert_eq!(
            must_ok(Ikev2EncryptionAlgorithm::from_transform_id(11, None)),
            Ikev2EncryptionAlgorithm::Null
        );
        assert_eq!(Ikev2EncryptionAlgorithm::Null.transform_id(), 11);
        assert_eq!(Ikev2EncryptionAlgorithm::Null.key_bits(), 0);
        assert_eq!(
            Ikev2EncryptionAlgorithm::Null.key_length_attribute_bits(),
            None
        );
        assert_eq!(Ikev2EncryptionAlgorithm::Null.encryption_key_len(), 0);
        assert_eq!(Ikev2EncryptionAlgorithm::Null.salt_len(), 0);
        assert_eq!(Ikev2EncryptionAlgorithm::Null.key_material_len(), 0);
        assert_eq!(Ikev2EncryptionAlgorithm::Null.name(), "NULL");
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
        assert_eq!(Ikev2IntegrityAlgorithm::HmacSha2_256_128.icv_len(), 16);
        assert_eq!(Ikev2IntegrityAlgorithm::HmacSha2_384_192.icv_len(), 24);
        assert_eq!(Ikev2IntegrityAlgorithm::HmacSha2_512_256.icv_len(), 32);
    }

    #[test]
    fn exact_observed_profile_is_typed_and_transform_order_independent() {
        let by_ids = must_ok(Ikev2SaInitCryptoProfile::from_transform_ids(
            PRF_HMAC_SHA2_512,
            DH_MODP_2048,
            ENCR_AES_CBC,
            Some(AES_256_KEY_BITS),
            Some(INTEG_HMAC_SHA2_512_256),
        ));
        let integ_then_prf = must_ok(Ikev2SaInitCryptoProfile::from_transforms(
            &observed_cbc_sha512_transform_set(true),
        ));
        let prf_then_integ = must_ok(Ikev2SaInitCryptoProfile::from_transforms(
            &observed_cbc_sha512_transform_set(false),
        ));

        assert_eq!(by_ids, integ_then_prf);
        assert_eq!(integ_then_prf, prf_then_integ);
        assert_eq!(by_ids.prf(), Ikev2PrfAlgorithm::HmacSha2_512);
        assert_eq!(by_ids.dh_group(), Ikev2DhGroup::Modp2048);
        assert_eq!(by_ids.encryption(), Ikev2EncryptionAlgorithm::AesCbc256);
        assert_eq!(
            by_ids.integrity(),
            Some(Ikev2IntegrityAlgorithm::HmacSha2_512_256)
        );
        assert_eq!(by_ids.integrity_key_len(), 64);
        assert_eq!(by_ids.integrity_icv_len(), 32);
        assert_eq!(must_ok(by_ids.key_material_len()), 384);
        assert_eq!(by_ids.validate_executable(), Ok(()));
    }

    #[test]
    fn direct_profile_constructors_reject_mismatched_integrity_shape() {
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::new_aead(
                Ikev2PrfAlgorithm::HmacSha2_512,
                Ikev2DhGroup::Modp2048,
                Ikev2EncryptionAlgorithm::AesCbc256,
            )),
            Ikev2SaInitCryptoError::MissingIntegrityTransform
        );
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
                Ikev2PrfAlgorithm::HmacSha2_512,
                Ikev2DhGroup::Modp2048,
                Ikev2EncryptionAlgorithm::AesGcm16_256,
                Ikev2IntegrityAlgorithm::HmacSha2_512_256,
            )),
            Ikev2SaInitCryptoError::UnexpectedIntegrityTransform
        );
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transform_ids(
                PRF_HMAC_SHA2_512,
                DH_MODP_2048,
                ENCR_AES_CBC,
                Some(AES_256_KEY_BITS),
                None,
            ))
            .as_str(),
            "ike_sa_init_crypto_missing_integrity_transform"
        );
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
                Ikev2PrfAlgorithm::HmacSha2_256,
                Ikev2DhGroup::Modp2048,
                Ikev2EncryptionAlgorithm::Null,
                Ikev2IntegrityAlgorithm::HmacSha2_256_128,
            )),
            Ikev2SaInitCryptoError::UnsupportedEncryptionTransform {
                transform_id: ENCR_NULL,
            }
        );
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transform_ids(
                PRF_HMAC_SHA2_256,
                DH_MODP_2048,
                ENCR_NULL,
                None,
                Some(INTEG_HMAC_SHA2_256_128),
            )),
            Ikev2SaInitCryptoError::UnsupportedEncryptionTransform {
                transform_id: ENCR_NULL,
            }
        );
    }

    #[test]
    fn profile_rejects_each_duplicate_and_unknown_transform_type() {
        let transforms = observed_cbc_sha512_transform_set(true);
        for index in 0..transforms.len() {
            let mut duplicated = transforms.clone();
            duplicated.insert(index, transforms[index].clone());
            assert_eq!(
                must_err(Ikev2SaInitCryptoProfile::from_transforms(&duplicated)),
                Ikev2SaInitCryptoError::InconsistentTransformSet,
                "duplicate transform at index {index} must fail closed"
            );
        }

        let mut unknown_type = transforms;
        unknown_type.push(Ikev2SaTransform {
            transform_type: 5,
            transform_id: 1,
            attributes: Vec::new(),
        });
        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::from_transforms(&unknown_type)),
            Ikev2SaInitCryptoError::InconsistentTransformSet
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
            must_err(Ikev2EncryptionAlgorithm::from_transform_id(11, Some(0))).as_str(),
            "ike_sa_init_crypto_unsupported_encryption_key_length"
        );
        assert_eq!(
            must_err(Ikev2EncryptionAlgorithm::from_transform_id(11, Some(128))).as_str(),
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
            "ike_sa_init_crypto_unexpected_integrity_transform"
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
                Some(INTEG_HMAC_SHA2_256_128),
            ))
            .as_str(),
            "ike_sa_init_crypto_unexpected_integrity_transform"
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
        crate::test_support::ensure_ike_crypto();
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
    fn hmac_sha512_matches_rfc4231_test_case_1() {
        crate::test_support::ensure_ike_crypto();
        let actual = must_ok(prf(
            Ikev2PrfAlgorithm::HmacSha2_512,
            &[0x0b; 20],
            b"Hi There",
        ));
        let expected = hex_to_bytes(concat!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0",
            "2379f4e2ce4ec2787ad0b30545e17cde",
            "daa833b7d6b8a702038b274eaea3f4e4",
            "be9d914eeb61f1702e696c203a126854"
        ));

        assert_eq!(&*actual, expected.as_slice());
    }

    #[test]
    fn hmac_sha512_matches_rfc4868_auth512_test_case_1() {
        crate::test_support::ensure_ike_crypto();
        let actual = must_ok(prf(
            Ikev2PrfAlgorithm::HmacSha2_512,
            &[0x0b; 64],
            b"Hi There",
        ));
        let expected = hex_to_bytes(concat!(
            "637edc6e01dce7e6742a99451aae82df",
            "23da3e92439e590e43e761b33e910fb8",
            "ac2878ebd5803f6f0b61dbce5e251ff8",
            "789a4722c1be65aea45fd464e89f8f5b"
        ));
        let expected_icv = hex_to_bytes(concat!(
            "637edc6e01dce7e6742a99451aae82df",
            "23da3e92439e590e43e761b33e910fb8"
        ));

        assert_eq!(&*actual, expected.as_slice());
        assert_eq!(&actual[..32], expected_icv.as_slice());
    }

    #[test]
    fn sha512_cbc_ike_sa_kdf_matches_independent_vector() {
        // Generated independently with OpenSSL 3 HMAC-SHA-512 and the RFC
        // 7296 section 2.13/2.14 PRF+ equations. This is synthetic test-only
        // material and contains no captured peer secrets.
        let profile = must_ok(Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha2_512,
            Ikev2DhGroup::Modp2048,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2IntegrityAlgorithm::HmacSha2_512_256,
        ));
        let initiator_nonce: Vec<u8> = (0x00..0x20).collect();
        let responder_nonce: Vec<u8> = (0xa0..0xc0).collect();
        let shared_secret: Vec<u8> = (0x00..=0xff).collect();

        let material = must_ok(derive_ike_sa_init_key_material(
            profile,
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            &initiator_nonce,
            &responder_nonce,
            &shared_secret,
            None,
        ));

        assert_eq!(
            material.skeyseed(),
            hex_to_bytes(concat!(
                "be6bee7f3a87542831303538d74f1d0f",
                "3a0a43476538969db0ec73b87ca2e732",
                "9246e4c25cfc6d20dff6081d6305e18d",
                "2b0bf073ecef0b8b97354a865faf0374"
            ))
        );
        assert_eq!(
            material.sk_d(),
            hex_to_bytes(concat!(
                "3a6780f9b7988b52b3640daa79e5b312",
                "54c8626ef3a8d5a99ea2a9eaa2d16b8b",
                "729b3469ef799357a90ce554942c209b",
                "f192c8f39295b727a9eb1681a097f89e"
            ))
        );
        assert_eq!(
            material.sk_ai(),
            hex_to_bytes(concat!(
                "77f1ee6d2350595a0de2a98b516ad4d7",
                "271c6ead856cdd0b41cff6cbe70378c6",
                "4dd8d0f6ddc99175e5d24b280ff06533",
                "aa5b1e2883480a55bdf00c91c5965eed"
            ))
        );
        assert_eq!(
            material.sk_ar(),
            hex_to_bytes(concat!(
                "19973371058ed48a8aca918ea0ca6558",
                "db708cf43dedc71346087d26571312c2",
                "3804aa1862746430c0831684b6f2d060",
                "9835a49860704d9de9603633e3f30652"
            ))
        );
        assert_eq!(
            material.sk_ei(),
            hex_to_bytes("e8d7681465f7bb4b2a38526b8d6d9e85b07f4d02038a30cc629af84f1beea3d1")
        );
        assert_eq!(
            material.sk_er(),
            hex_to_bytes("05bbff5bbdb0e310ca533a87326779a8438d70b699d27514ef0bffe69d286405")
        );
        assert_eq!(
            material.sk_pi(),
            hex_to_bytes(concat!(
                "5f5ca92e01d475e94bcf891d030ad537",
                "5af225315d7a0538416dd5e6fa9b3c92",
                "a91ac1f1745ad930d43985490e04ce20",
                "31503ba369809d3ce5fd812fe762c54e"
            ))
        );
        assert_eq!(
            material.sk_pr(),
            hex_to_bytes(concat!(
                "ab498746f6e2f55fd41801101a531174",
                "d6f0e5bc7a0b50bb5b205cec3717176c",
                "bd2cdf6ffe4de67d396d83877e958c21",
                "4fe84e6766788041bc906d90bbeea9eb"
            ))
        );
        assert_eq!(material.sk_ai().len(), 64);
        assert_eq!(material.sk_ar().len(), 64);
        assert_eq!(material.sk_ei().len(), 32);
        assert_eq!(material.sk_er().len(), 32);

        let restored = must_ok(Ikev2SaInitKeyMaterial::from_established_keys(
            profile,
            false,
            material.sk_d(),
            material.sk_ai(),
            material.sk_ar(),
            material.sk_ei(),
            material.sk_er(),
            material.sk_pi(),
            material.sk_pr(),
        ));
        assert_eq!(restored.sk_d(), material.sk_d());
        assert_eq!(restored.sk_ai(), material.sk_ai());
        assert_eq!(restored.sk_ei(), material.sk_ei());
    }

    #[test]
    fn ike_sa_rekey_uses_old_prf_then_new_sha512_prf() {
        // Generated independently with OpenSSL 3. The old SA uses
        // PRF-HMAC-SHA2-256; the new suite uses PRF-HMAC-SHA2-512.
        let new_profile = must_ok(Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha2_512,
            Ikev2DhGroup::Modp2048,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2IntegrityAlgorithm::HmacSha2_512_256,
        ));
        let old_sk_d: Vec<u8> = (0x40..0x60).collect();
        let initiator_nonce: Vec<u8> = (0x00..0x20).collect();
        let responder_nonce: Vec<u8> = (0xa0..0xc0).collect();
        let shared_secret: Vec<u8> = (0x00..=0xff).collect();

        let material = must_ok(derive_ike_sa_rekey_key_material(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &old_sk_d,
            new_profile,
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            &initiator_nonce,
            &responder_nonce,
            &shared_secret,
        ));

        assert_eq!(
            material.skeyseed(),
            hex_to_bytes("35fbc890deb524b1e80cccbe7020a7918e06a4853de448cfc1f0eb37218318c4")
        );
        assert_eq!(
            material.sk_d(),
            hex_to_bytes(concat!(
                "02e1ca700ce78e36823ffcaea5aea667",
                "294b805f57069130d53ad916ee45b9c4",
                "000b50655509083aa69e68e4d16f663d",
                "4bb538e1ad5ee604522e433791922ad3"
            ))
        );
        assert_eq!(
            material.sk_ei(),
            hex_to_bytes("2f60d126ebd040ec6c975f71a0bc7dd8ba4b3827af157ed83c320c4edf2b2fc3")
        );
        assert_eq!(material.skeyseed().len(), 32, "old PRF owns SKEYSEED");
        assert_eq!(material.sk_d().len(), 64, "new PRF owns SK_d");
        assert_eq!(material.sk_ai().len(), 64);
        assert_eq!(material.sk_ei().len(), 32);
        assert!(!material.ppk_applied());

        let mut rekey_seed = Zeroizing::new(Vec::new());
        rekey_seed.extend_from_slice(&shared_secret);
        rekey_seed.extend_from_slice(&initiator_nonce);
        rekey_seed.extend_from_slice(&responder_nonce);
        let wrong_new_prf_skeyseed =
            must_ok(prf(Ikev2PrfAlgorithm::HmacSha2_512, &old_sk_d, &rekey_seed));
        assert_ne!(material.skeyseed(), &*wrong_new_prf_skeyseed);
    }

    #[test]
    fn ike_sa_rekey_rejects_wrong_old_sk_d_and_missing_new_dh() {
        let new_profile = must_ok(Ikev2SaInitCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_512,
            Ikev2DhGroup::Ecp256,
            Ikev2EncryptionAlgorithm::AesGcm16_128,
        ));
        let nonce = [0x11; 32];

        assert_eq!(
            must_err(derive_ike_sa_rekey_key_material(
                Ikev2PrfAlgorithm::HmacSha2_256,
                &[0x22; 31],
                new_profile,
                [0x33; 8],
                [0x44; 8],
                &nonce,
                &nonce,
                &[0x55; 32],
            ))
            .as_str(),
            "ike_sa_init_crypto_invalid_key_length"
        );
        assert_eq!(
            must_err(derive_ike_sa_rekey_key_material(
                Ikev2PrfAlgorithm::HmacSha2_256,
                &[0x22; 32],
                new_profile,
                [0x33; 8],
                [0x44; 8],
                &nonce,
                &nonce,
                &[],
            )),
            Ikev2SaInitCryptoError::InvalidKeyLength {
                name: "new DH shared secret",
                len: 0,
            }
        );
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
        crate::test_support::ensure_ike_crypto();
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
        crate::test_support::ensure_ike_crypto();
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
        crate::test_support::ensure_ike_crypto();
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
    fn child_sa_encr_null_derives_only_independent_integrity_vectors() {
        crate::test_support::ensure_ike_crypto();
        // Generated independently with OpenSSL 3 HMAC-SHA256 and the RFC 7296
        // section 2.17 PRF+ equations. T1 is i2r A and T2 is r2i A because
        // ENCR_NULL contributes zero E octets in each direction.
        let profile = Ikev2ChildSaCryptoProfile::new_authenticated_only(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
        );
        let material = must_ok(derive_child_sa_key_material(
            profile,
            &[0x0f; 32],
            &[0xa1; 16],
            &[0xb2; 16],
            None,
        ));

        assert_eq!(profile.validate_executable(), Ok(()));
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::Null);
        assert_eq!(profile.directional_encryption_len(), 0);
        assert_eq!(profile.directional_integrity_len(), 32);
        assert_eq!(must_ok(profile.keymat_len()), 64);
        assert_eq!(material.profile(), profile);
        assert!(material.initiator_to_responder_encryption().is_empty());
        assert!(material.responder_to_initiator_encryption().is_empty());
        assert_eq!(
            material.initiator_to_responder_integrity(),
            hex_to_bytes("7ae50b9713ddfd346dbb3cfbe8b8d45a34c79925bedb4f4ae6a5ad6bc76d8ab5")
        );
        assert_eq!(
            material.responder_to_initiator_integrity(),
            hex_to_bytes("78ea306ce36f6fde3c1f71951c1fe8c6d7477a4a2adfe9b746fd3c6fd6be52da")
        );
        let debug = format!("{material:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7ae50b9713ddfd34"));
    }

    #[test]
    fn child_sa_encr_null_restores_from_exact_transform_ids() {
        let profile = must_ok(Ikev2ChildSaCryptoProfile::from_transform_ids(
            PRF_HMAC_SHA2_256,
            ENCR_NULL,
            None,
            Some(INTEG_HMAC_SHA2_256_128),
        ));

        assert_eq!(profile.prf().transform_id(), PRF_HMAC_SHA2_256);
        assert_eq!(profile.encryption().transform_id(), ENCR_NULL);
        assert_eq!(profile.encryption().key_length_attribute_bits(), None);
        assert_eq!(
            profile.integrity().map(|value| value.transform_id()),
            Some(INTEG_HMAC_SHA2_256_128)
        );
        assert_eq!(profile.directional_encryption_len(), 0);
        assert_eq!(must_ok(profile.keymat_len()), 64);

        assert_eq!(
            must_err(Ikev2ChildSaCryptoProfile::from_transform_ids(
                PRF_HMAC_SHA2_256,
                ENCR_NULL,
                None,
                None,
            )),
            Ikev2SaInitCryptoError::InconsistentTransformSet
        );
        assert_eq!(
            must_err(Ikev2ChildSaCryptoProfile::from_transform_ids(
                PRF_HMAC_SHA2_256,
                ENCR_NULL,
                Some(128),
                Some(INTEG_HMAC_SHA2_256_128),
            )),
            Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
                transform_id: ENCR_NULL,
                key_bits: Some(128),
            }
        );
    }

    #[test]
    fn child_sa_sha512_keymat_matches_independent_vector() {
        crate::test_support::ensure_ike_crypto();
        // Generated independently with OpenSSL 3 and RFC 7296 section 2.17.
        let profile = Ikev2ChildSaCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha2_512,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2IntegrityAlgorithm::HmacSha2_512_256,
        );
        let sk_d: Vec<u8> = (0x40..0x80).collect();
        let initiator_nonce: Vec<u8> = (0x00..0x20).collect();
        let responder_nonce: Vec<u8> = (0xa0..0xc0).collect();
        let material = must_ok(derive_child_sa_key_material(
            profile,
            &sk_d,
            &initiator_nonce,
            &responder_nonce,
            None,
        ));

        assert_eq!(
            material.initiator_to_responder_encryption(),
            hex_to_bytes("09c697426fc5c806353447f86db77edade7ef3776f9ab86f08a41ed2150fa52e")
        );
        assert_eq!(
            material.initiator_to_responder_integrity(),
            hex_to_bytes(concat!(
                "cb113b3457ecb795d45797b870418abe",
                "7e789b9cfb32bfa92b8ece727484dd5b",
                "6616ceda28cb525dc2362ac5269a8a47",
                "51f44f295b55034a5295ea3115c33314"
            ))
        );
        assert_eq!(
            material.responder_to_initiator_encryption(),
            hex_to_bytes("8c3fba5a203fef4253d490042638c6a6e5f136de4b4f51e8d48df7a1a5705ad0")
        );
        assert_eq!(
            material.responder_to_initiator_integrity(),
            hex_to_bytes(concat!(
                "d12dc46f13f2a3bab87b9f41ddab02ff",
                "47b9bf9566f3874b98032c93ba958629",
                "3cabd37aa27114323fd42054244fb24bb",
                "51949488c5abed1ad2fb08dbf7c0480"
            ))
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

        let encr_null = child_sa_negotiation(vec![
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_NULL,
                attributes: Vec::new(),
            },
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_INTEG,
                transform_id: INTEG_HMAC_SHA2_256_128,
                attributes: Vec::new(),
            },
        ]);
        let profile = must_ok(Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &encr_null,
        ));
        assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::Null);
        assert_eq!(
            profile.integrity(),
            Some(Ikev2IntegrityAlgorithm::HmacSha2_256_128)
        );
        assert_eq!(profile.validate_executable(), Ok(()));

        let null_without_integrity = child_sa_negotiation(vec![Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_ENCR,
            transform_id: ENCR_NULL,
            attributes: Vec::new(),
        }]);
        assert_eq!(
            must_err(Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
                Ikev2PrfAlgorithm::HmacSha2_256,
                &null_without_integrity,
            )),
            Ikev2SaInitCryptoError::InconsistentTransformSet
        );

        let null_with_key_length = child_sa_negotiation(vec![
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_ENCR,
                transform_id: ENCR_NULL,
                attributes: vec![Ikev2TransformAttributeBuild {
                    attribute_type: TRANSFORM_ATTRIBUTE_KEY_LENGTH,
                    value: Ikev2TransformAttributeBuildValue::Tv(128),
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
                &null_with_key_length,
            )),
            Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
                transform_id: ENCR_NULL,
                key_bits: Some(128),
            }
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

        let null_without_auth = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::Null,
        );
        assert_eq!(
            must_err(derive_child_sa_key_material(
                null_without_auth,
                &[0x0f; 32],
                &[0xa1; 16],
                &[0xb2; 16],
                None,
            )),
            Ikev2SaInitCryptoError::InconsistentTransformSet
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

        assert_eq!(
            must_err(Ikev2SaInitCryptoProfile::new_aead(
                Ikev2PrfAlgorithm::HmacSha2_256,
                Ikev2DhGroup::Ecp256,
                Ikev2EncryptionAlgorithm::AesCbc256,
            ))
            .as_str(),
            "ike_sa_init_crypto_missing_integrity_transform"
        );
    }

    #[test]
    fn sha384_profile_derives_expected_material_lengths() {
        let profile = must_ok(Ikev2SaInitCryptoProfile::from_transform_ids(
            PRF_HMAC_SHA2_384,
            DH_ECP_384,
            ENCR_AES_GCM_16,
            Some(256),
            None,
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
