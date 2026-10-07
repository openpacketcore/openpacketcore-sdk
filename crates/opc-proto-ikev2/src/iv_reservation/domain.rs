use std::fmt;

use bytes::Bytes;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::Ikev2AesGcmIvReservationError;
use crate::{
    seal_ikev2_sa_init_protected_payload, Ikev2EncryptionAlgorithm, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, ProtectedPayloadSealContext,
};

/// Ordinary-IV key epoch: nonzero SPI pair, original-role direction, algorithm,
/// and exact selected encryption key plus RFC 5282 four-octet salt.
///
/// Rebuild this descriptor from the same atomic durable SA record as the IV
/// high-water. Key copies are zeroized on drop and excluded from diagnostics.
/// A new SPI or descriptor alone never makes reused key material fresh.
/// Obtain a fresh allocator's [`super::Ikev2AesGcmIvAllocator::domain`] or a
/// persisted [`super::Ikev2AesGcmIvRecord::domain`]; independent assembly is private.
///
/// ```compile_fail
/// use opc_proto_ikev2::{Ikev2AesGcmEpochInputs, Ikev2AesGcmIvDomain};
/// fn assemble(i: Ikev2AesGcmEpochInputs<'_>) {
///     let _ = Ikev2AesGcmIvDomain::new(i.initiator_spi, i.responder_spi,
///         i.sending_direction, i.profile, i.keys);
/// }
/// ```
#[derive(Clone)]
pub struct Ikev2AesGcmIvDomain {
    initiator_spi: u64,
    responder_spi: u64,
    direction: Ikev2ProtectedPayloadDirection,
    encryption: Ikev2EncryptionAlgorithm,
    key_and_salt: Zeroizing<Vec<u8>>,
}

impl Ikev2AesGcmIvDomain {
    /// Bind an ordinary-IV descriptor to the actual established GCM key material.
    ///
    /// # Errors
    /// Returns `InvalidDomain` for zero SPIs, non-GCM profiles, wrong key lengths,
    /// or identical directional key/salt pairs (which would collide at IV zero).
    pub(crate) fn new(
        initiator_spi: u64,
        responder_spi: u64,
        direction: Ikev2ProtectedPayloadDirection,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
    ) -> Result<Self, Ikev2AesGcmIvReservationError> {
        if initiator_spi == 0
            || responder_spi == 0
            || !matches!(
                profile.encryption(),
                Ikev2EncryptionAlgorithm::AesGcm16_128
                    | Ikev2EncryptionAlgorithm::AesGcm16_192
                    | Ikev2EncryptionAlgorithm::AesGcm16_256
            )
            || keys.sk_ei().len() != profile.encryption().key_material_len()
            || keys.sk_er().len() != profile.encryption().key_material_len()
            || bool::from(keys.sk_ei().ct_eq(keys.sk_er()))
        {
            return Err(Ikev2AesGcmIvReservationError::InvalidDomain);
        }
        let selected = match direction {
            Ikev2ProtectedPayloadDirection::InitiatorToResponder => keys.sk_ei(),
            Ikev2ProtectedPayloadDirection::ResponderToInitiator => keys.sk_er(),
        };
        Ok(Self {
            initiator_spi,
            responder_spi,
            direction,
            encryption: profile.encryption(),
            key_and_salt: Zeroizing::new(selected.to_vec()),
        })
    }

    /// Original initiator's established SPI.
    pub const fn initiator_spi(&self) -> u64 {
        self.initiator_spi
    }
    /// Original responder's established SPI.
    pub const fn responder_spi(&self) -> u64 {
        self.responder_spi
    }
    /// Sending direction relative to the original roles of this SA.
    pub const fn direction(&self) -> Ikev2ProtectedPayloadDirection {
        self.direction
    }
    /// GCM key size bound by the descriptor.
    pub const fn encryption(&self) -> Ikev2EncryptionAlgorithm {
        self.encryption
    }

    pub(crate) fn key_and_salt(&self) -> &[u8] {
        &self.key_and_salt
    }
}

impl PartialEq for Ikev2AesGcmIvDomain {
    fn eq(&self, other: &Self) -> bool {
        self.initiator_spi == other.initiator_spi
            && self.responder_spi == other.responder_spi
            && self.direction == other.direction
            && self.encryption == other.encryption
            && bool::from(
                self.key_and_salt
                    .as_slice()
                    .ct_eq(other.key_and_salt.as_slice()),
            )
    }
}
impl Eq for Ikev2AesGcmIvDomain {}

impl fmt::Debug for Ikev2AesGcmIvDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AesGcmIvDomain")
            .finish_non_exhaustive()
    }
}

/// Non-cloneable, domain-bound ordinary IV consumed by exactly one seal attempt.
///
/// Dropping it burns the position. The token borrows its allocator, so another
/// allocation cannot race its use. It is no authentication, durable exchange,
/// Message-ID, or transmission authority.
#[must_use = "dropping an allocation burns its reserved IV"]
pub struct Ikev2AesGcmIvAllocation<'a> {
    domain: &'a Ikev2AesGcmIvDomain,
    value: u64,
}

impl<'a> Ikev2AesGcmIvAllocation<'a> {
    pub(super) const fn new(domain: &'a Ikev2AesGcmIvDomain, value: u64) -> Self {
        Self { domain, value }
    }

    /// Consume the IV and seal using the existing admitted crypto module.
    ///
    /// # Errors
    /// Rejects a different key/salt/profile, SPI pair or IKE initiator flag before
    /// encryption. Other crypto/context failures retain the existing typed error.
    /// Every failure burns this IV; retrying needs a new allocation. The caller
    /// still must commit any required exchange state before sending these bytes.
    pub fn seal(
        self,
        profile: Ikev2SaInitCryptoProfile,
        keys: &Ikev2SaInitKeyMaterial,
        context: ProtectedPayloadSealContext<'_>,
        cleartext_payloads: &[u8],
        padding_len: u8,
    ) -> Result<Bytes, Ikev2AesGcmIvReservationError> {
        let expected = self.domain;
        let actual = Ikev2AesGcmIvDomain::new(
            expected.initiator_spi,
            expected.responder_spi,
            expected.direction,
            profile,
            keys,
        )
        .map_err(|_| Ikev2AesGcmIvReservationError::DomainMismatch)?;
        let prefix = context.message_prefix;
        let initiator = expected.direction == Ikev2ProtectedPayloadDirection::InitiatorToResponder;
        if &actual != expected
            || prefix.get(..8) != Some(expected.initiator_spi.to_be_bytes().as_slice())
            || prefix.get(8..16) != Some(expected.responder_spi.to_be_bytes().as_slice())
            || prefix.get(19).map(|flags| flags & 0x08 != 0) != Some(initiator)
        {
            return Err(Ikev2AesGcmIvReservationError::DomainMismatch);
        }
        seal_ikev2_sa_init_protected_payload(
            profile,
            keys,
            expected.direction,
            context,
            cleartext_payloads,
            padding_len,
            self.value.to_be_bytes(),
        )
        .map_err(Ikev2AesGcmIvReservationError::Crypto)
    }
}

impl fmt::Debug for Ikev2AesGcmIvAllocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AesGcmIvAllocation")
            .finish_non_exhaustive()
    }
}
