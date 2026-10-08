//! RustCrypto-backed 128-NIA2 and 128-NEA2.

use std::fmt;

use ::aes::{
    cipher::{Block, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher},
    Aes128,
};
use bytes::Bytes;
use cmac::{block_api::CmacCipher, Cmac, Mac};
use opc_key::{KeyHandle, KeyPurpose};
use zeroize::Zeroizing;

use super::{
    NasCipheringAlgorithm, NasConnectionId, NasCount, NasIntegrityAlgorithm, NasSecurityAlgorithms,
    NasSecurityDirection, NasSecurityError,
};

/// A 128-bit NAS algorithm key, redacted in Debug and zeroized on drop.
///
/// Key derivation and lifetime selection belong to the caller. This is an
/// already-derived KNASint or KNASenc, not KAMF or an SDK storage-encryption key.
#[derive(Clone)]
pub struct NasAesKey(Zeroizing<[u8; 16]>);

impl NasAesKey {
    /// Take ownership of an already-derived, zeroizing 128-bit key.
    pub fn new(key: Zeroizing<[u8; 16]>) -> Self {
        Self(key)
    }
}

impl fmt::Debug for NasAesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NasAesKey(<redacted>)")
    }
}

/// Validated COUNT, BEARER, DIRECTION and LENGTH inputs to Annex D algorithms.
///
/// COUNT is the full 32-bit algorithm input, allowing the TS 33.401 Annex C
/// vectors to be used unchanged. The NAS provider zero-extends [`NasCount`]'s
/// 24-bit value. LENGTH is in bits, counted most-significant bit first; input
/// slices must contain exactly `ceil(LENGTH/8)` octets. Unused low bits in the
/// final octet are ignored (and zeroed in cipher output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasAlgorithmInput {
    count: u32,
    bearer: u8,
    direction: NasSecurityDirection,
    bit_length: usize,
}

impl NasAlgorithmInput {
    /// Validate a five-bit bearer and an at-most-32-bit bit length.
    pub fn new(
        count: u32,
        bearer: u8,
        direction: NasSecurityDirection,
        bit_length: usize,
    ) -> Result<Self, NasSecurityError> {
        if bearer > 31 {
            return Err(NasSecurityError::InvalidBearer);
        }
        if u32::try_from(bit_length).is_err() {
            return Err(NasSecurityError::InvalidLength);
        }
        Ok(Self {
            count,
            bearer,
            direction,
            bit_length,
        })
    }

    /// Full algorithm COUNT.
    pub const fn count(self) -> u32 {
        self.count
    }
    /// Five-bit BEARER.
    pub const fn bearer(self) -> u8 {
        self.bearer
    }
    /// Uplink (0) or downlink (1) DIRECTION.
    pub const fn direction(self) -> NasSecurityDirection {
        self.direction
    }
    /// LENGTH in bits.
    pub const fn bit_length(self) -> usize {
        self.bit_length
    }

    fn prefix(self) -> [u8; 8] {
        let mut prefix = [0; 8];
        prefix[..4].copy_from_slice(&self.count.to_be_bytes());
        let direction = u8::from(self.direction == NasSecurityDirection::Downlink);
        prefix[4] = (self.bearer << 3) | (direction << 2);
        prefix
    }

    fn check_message(self, input: &[u8]) -> Result<(), NasSecurityError> {
        if input.len() != self.bit_length.div_ceil(8) {
            return Err(NasSecurityError::InvalidLength);
        }
        Ok(())
    }
}

/// Compute 128-NIA2 (AES-CMAC), returning the most significant 32 tag bits.
///
/// Implements TS 33.501 §D.3.1.3 / TS 33.401 §B.2.3. The message is the
/// *complete* integrity input. For a protected NAS envelope it includes the
/// sequence-number octet followed by the transmitted (possibly ciphered) NAS
/// payload; [`super::NasSecurityContext`] supplies that framing.
pub fn nia2_mac(
    key: &NasAesKey,
    input: NasAlgorithmInput,
    message: &[u8],
) -> Result<[u8; 4], NasSecurityError> {
    input.check_message(message)?;
    let prefix = input.prefix();
    let mut mac = Cmac::<Aes128>::new((&*key.0).into());
    let tail_bits = input.bit_length % 8;
    if tail_bits == 0 {
        mac.update(&prefix);
        mac.update(message);
    } else {
        // RustCrypto CMAC accepts octets. For a partial final octet, form the
        // bit-padded final block from NIST SP 800-38B §6.2, then XOR K1 ^ K2.
        // Feeding this complete block to CMAC cancels its K1 finalization and
        // applies the required K2 instead. All CBC chaining and AES operations
        // remain in RustCrypto. No prefix or padding bit is counted as MESSAGE.
        let complete_bytes = (8 + input.bit_length / 8) / 16 * 16;
        let mut last = Zeroizing::new([0u8; 16]);
        let used = if complete_bytes == 0 {
            last[..8].copy_from_slice(&prefix);
            last[8..8 + message.len()].copy_from_slice(message);
            8 + message.len()
        } else {
            mac.update(&prefix);
            mac.update(&message[..complete_bytes - 8]);
            let tail = &message[complete_bytes - 8..];
            last[..tail.len()].copy_from_slice(tail);
            tail.len()
        };
        last[used - 1] = (last[used - 1] & (0xff << (8 - tail_bits))) | (0x80 >> tail_bits);
        let cipher = Aes128::new((&*key.0).into());
        let mut l = Zeroizing::new(Block::<Aes128>::default());
        cipher.encrypt_block(&mut l);
        let k1 = Zeroizing::new(<Aes128 as CmacCipher>::dbl(*l));
        let k2 = Zeroizing::new(<Aes128 as CmacCipher>::dbl(*k1));
        for i in 0..16 {
            last[i] ^= k1[i] ^ k2[i];
        }
        mac.update(&*last);
    }
    let tag = mac.finalize().into_bytes();
    Ok([tag[0], tag[1], tag[2], tag[3]])
}

/// Apply 128-NEA2 (AES-CTR) to exactly LENGTH bits, symmetrically.
///
/// Implements TS 33.501 §D.2.1.3 / TS 33.401 §B.1.3. The high 64 counter bits
/// contain COUNT, BEARER, DIRECTION and 26 zeros. The low 64 bits start at zero
/// and increment in big-endian order. This primitive does not authenticate its
/// input; use [`super::NasSecurityContext::verify_and_decipher`] for envelopes.
/// Never reuse a key/COUNT/BEARER/DIRECTION tuple to encrypt different messages.
pub fn nea2_cipher(
    key: &NasAesKey,
    input: NasAlgorithmInput,
    message: &[u8],
) -> Result<Bytes, NasSecurityError> {
    input.check_message(message)?;
    let mut counter = [0; 16];
    counter[..8].copy_from_slice(&input.prefix());
    let mut cipher = ctr::Ctr64BE::<Aes128>::new((&*key.0).into(), (&counter).into());
    let mut output = message.to_vec();
    cipher
        .try_apply_keystream(&mut output)
        .map_err(|_| NasSecurityError::InvalidLength)?;
    let tail_bits = input.bit_length % 8;
    if tail_bits != 0 {
        if let Some(last) = output.last_mut() {
            *last &= 0xff << (8 - tail_bits);
        }
    }
    Ok(output.into())
}

/// Which already-derived NAS key a resolver must return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasKeyUsage {
    /// KNASint for integrity.
    Integrity(NasIntegrityAlgorithm),
    /// KNASenc for ciphering.
    Ciphering(NasCipheringAlgorithm),
}

/// Resolve an opaque SDK session handle to an already-derived 128-bit NAS key.
///
/// The resolver owns key selection, tenant/handle authorization and derivation.
/// Usage includes the selected algorithm identity for TS 33.501 Annex A.8;
/// return only the key derived for that algorithm type and identity.
/// SDK handles carry opaque storage keys; this provider never extracts or
/// truncates their material. Return [`NasSecurityError::KeyUnavailable`] for an
/// unknown or unauthorized handle. Closures with this signature implement the
/// trait. Returned material is zeroized after each operation.
pub trait NasAesKeyResolver {
    /// Look up the authorized KNASint or KNASenc for this handle and usage.
    fn resolve_key(
        &self,
        handle: &KeyHandle,
        usage: NasKeyUsage,
    ) -> Result<NasAesKey, NasSecurityError>;
}

impl<F> NasAesKeyResolver for F
where
    F: Fn(&KeyHandle, NasKeyUsage) -> Result<NasAesKey, NasSecurityError>,
{
    fn resolve_key(
        &self,
        handle: &KeyHandle,
        usage: NasKeyUsage,
    ) -> Result<NasAesKey, NasSecurityError> {
        self(handle, usage)
    }
}

/// RustCrypto provider implementing NIA2 with NEA2 or NEA0 pass-through.
///
/// The security context supplies its connection identifier and COUNT for each
/// call, so one provider may serve both accesses. The resolver is told the
/// algorithm type and identity (TS 33.501 Annex A.8); it owns authorization and
/// key derivation. NEA0 requires no cipher key lookup. NIA0, NIA1/NEA1 (SNOW 3G)
/// and NIA3/NEA3 (ZUC) are refused; explicit NIA0 uses the null provider.
pub struct AesNasSecurityAlgorithms<R> {
    resolver: R,
}

impl<R: NasAesKeyResolver> AesNasSecurityAlgorithms<R> {
    /// Construct a provider with a caller-owned NAS key resolver.
    pub const fn new(resolver: R) -> Self {
        Self { resolver }
    }

    fn input(
        count: NasCount,
        connection_id: NasConnectionId,
        direction: NasSecurityDirection,
        len: usize,
    ) -> Result<NasAlgorithmInput, NasSecurityError> {
        let bit_length = len.checked_mul(8).ok_or(NasSecurityError::InvalidLength)?;
        NasAlgorithmInput::new(
            count.as_u32(),
            connection_id.as_bearer(),
            direction,
            bit_length,
        )
    }
    fn key(&self, handle: &KeyHandle, usage: NasKeyUsage) -> Result<NasAesKey, NasSecurityError> {
        if handle.purpose() != KeyPurpose::Session {
            return Err(NasSecurityError::KeyPurposeMismatch);
        }
        self.resolver.resolve_key(handle, usage)
    }
}

impl<R> fmt::Debug for AesNasSecurityAlgorithms<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesNasSecurityAlgorithms")
            .field("resolver", &"<redacted>")
            .finish()
    }
}

impl<R: NasAesKeyResolver> NasSecurityAlgorithms for AesNasSecurityAlgorithms<R> {
    fn compute_mac(
        &self,
        algorithm: NasIntegrityAlgorithm,
        key: &KeyHandle,
        count: NasCount,
        connection_id: NasConnectionId,
        direction: NasSecurityDirection,
        message: &[u8],
    ) -> Result<[u8; 4], NasSecurityError> {
        if algorithm != NasIntegrityAlgorithm::Nia2 {
            return Err(NasSecurityError::UnsupportedAlgorithm);
        }
        let input = Self::input(count, connection_id, direction, message.len())?;
        nia2_mac(
            &self.key(key, NasKeyUsage::Integrity(algorithm))?,
            input,
            message,
        )
    }
    fn apply_cipher(
        &self,
        algorithm: NasCipheringAlgorithm,
        key: &KeyHandle,
        count: NasCount,
        connection_id: NasConnectionId,
        direction: NasSecurityDirection,
        input: &[u8],
    ) -> Result<Bytes, NasSecurityError> {
        if algorithm == NasCipheringAlgorithm::Nea0 {
            return Ok(Bytes::copy_from_slice(input));
        }
        if algorithm != NasCipheringAlgorithm::Nea2 {
            return Err(NasSecurityError::UnsupportedAlgorithm);
        }
        let params = Self::input(count, connection_id, direction, input.len())?;
        nea2_cipher(
            &self.key(key, NasKeyUsage::Ciphering(algorithm))?,
            params,
            input,
        )
    }
}
