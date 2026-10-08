use std::{fmt, sync::Arc};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::Ikev2WindowError;
use crate::{
    Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm,
    Ikev2ProtectedPayloadDirection, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
};

/// Established CBC epoch inputs from one trusted atomic SA record.
///
/// The caller supplies the actual established keys, original roles and SPIs.
/// A new SPI or descriptor does not make previously used keys fresh.
#[derive(Clone, Copy, Debug)]
pub struct Ikev2CbcEpochInputs<'a> {
    /// Original initiator's nonzero SPI.
    pub initiator_spi: u64,
    /// Original responder's nonzero SPI.
    pub responder_spi: u64,
    /// Local sending direction relative to this SA's original roles.
    pub sending_direction: Ikev2ProtectedPayloadDirection,
    /// Established CBC encryption, integrity and PRF algorithms.
    pub profile: Ikev2SaInitCryptoProfile,
    /// Complete established key material, including SK_d and both traffic directions.
    pub keys: &'a Ikev2SaInitKeyMaterial,
}

/// Immutable CBC key-epoch descriptor, with no IV counter or allocation state.
///
/// Persist its metadata atomically with the established SA and all of its keys.
/// It retains zeroizing key copies in memory; diagnostics reveal no keys. Neither
/// constructing this value nor comparing a readback acknowledges persistence or
/// grants permission to send. Canonical CBC sending requires a checked window
/// and current profile qualification.
///
/// There is no marker retrofit or IV high-water interface:
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CbcEpochRecord;
/// fn retrofit(record: &mut Ikev2CbcEpochRecord) {
///     record.set_canonical_format(Some(1));
/// }
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::recovery::Ikev2CbcEpochRecord;
/// fn floor(record: &Ikev2CbcEpochRecord) { let _ = record.exclusive_end(); }
/// ```
#[derive(Clone)]
pub struct Ikev2CbcEpochRecord {
    binding: Arc<Binding>,
}

#[derive(Clone)]
struct Binding {
    initiator_spi: u64,
    responder_spi: u64,
    direction: Ikev2ProtectedPayloadDirection,
    encryption: Ikev2EncryptionAlgorithm,
    integrity: Ikev2IntegrityAlgorithm,
    prf: Ikev2PrfAlgorithm,
    canonical_format: Option<u8>,
    sk_d: Zeroizing<Vec<u8>>,
    sk_ei: Zeroizing<Vec<u8>>,
    sk_er: Zeroizing<Vec<u8>>,
    sk_ai: Zeroizing<Vec<u8>>,
    sk_ar: Zeroizing<Vec<u8>>,
    ledger_key: [u8; 32],
    canonical_binding: Option<[u8; 32]>,
}

impl Ikev2CbcEpochRecord {
    /// Create the CBC-V1 descriptor for a genuinely fresh established key epoch.
    ///
    /// The consumer must establish freshness and durably store marker `1` with
    /// the complete immutable epoch and keys in one atomic commit. This function
    /// cannot establish their history or acknowledge that write. Never use it to
    /// add a marker to an existing epoch; restore that epoch's original marker
    /// with [`Self::from_persisted`]. No derived IV key or reply bytes are persisted.
    ///
    /// # Errors
    /// Returns `DomainMismatch` for invalid SPIs, profile, key widths, or either
    /// identical pair of directional encryption or integrity keys.
    pub fn fresh(inputs: Ikev2CbcEpochInputs<'_>) -> Result<Self, Ikev2WindowError> {
        Self::from_persisted(inputs, Some(1))
    }

    /// Restore the exact immutable descriptor from a trusted latest atomic record.
    ///
    /// Missing and unknown markers are preserved and grant no canonical authority.
    /// All fields, including SK_d and receive-side keys, belong to the binding.
    /// Freshness, atomic persistence and writer fencing remain caller obligations.
    ///
    /// # Errors
    /// Returns `DomainMismatch` for invalid SPIs, profile, key widths, or either
    /// identical pair of directional encryption or integrity keys.
    pub fn from_persisted(
        inputs: Ikev2CbcEpochInputs<'_>,
        canonical_format: Option<u8>,
    ) -> Result<Self, Ikev2WindowError> {
        let Ikev2CbcEpochInputs {
            initiator_spi,
            responder_spi,
            sending_direction,
            profile,
            keys,
        } = inputs;
        let encryption = profile.encryption();
        let integrity = profile
            .integrity()
            .ok_or(Ikev2WindowError::DomainMismatch)?;
        let prf = profile.prf();
        if initiator_spi == 0
            || responder_spi == 0
            || !matches!(
                encryption,
                Ikev2EncryptionAlgorithm::AesCbc128
                    | Ikev2EncryptionAlgorithm::AesCbc192
                    | Ikev2EncryptionAlgorithm::AesCbc256
            )
            || keys.sk_d().len() != prf.output_len()
            || keys.sk_ei().len() != encryption.encryption_key_len()
            || keys.sk_er().len() != encryption.encryption_key_len()
            || keys.sk_ai().len() != integrity.key_len()
            || keys.sk_ar().len() != integrity.key_len()
            || bool::from(keys.sk_ei().ct_eq(keys.sk_er()) | keys.sk_ai().ct_eq(keys.sk_ar()))
        {
            return Err(Ikev2WindowError::DomainMismatch);
        }

        let (sending_e, sending_a) = match sending_direction {
            Ikev2ProtectedPayloadDirection::InitiatorToResponder => (keys.sk_ei(), keys.sk_ai()),
            Ikev2ProtectedPayloadDirection::ResponderToInitiator => (keys.sk_er(), keys.sk_ar()),
        };
        let mut ledger = Sha256::new();
        ledger.update(b"opc-ikev2-canonical-cbc-ledger-key-v1\0");
        ledger.update(encryption.transform_id().to_be_bytes());
        ledger.update(encryption.key_bits().to_be_bytes());
        ledger.update(integrity.transform_id().to_be_bytes());
        hash_key(&mut ledger, sending_e);
        hash_key(&mut ledger, sending_a);

        let canonical_binding = (canonical_format == Some(1)).then(|| {
            let mut hash = Sha256::new();
            hash.update(b"opc-ikev2-canonical-cbc-binding-v1\0");
            hash.update(initiator_spi.to_be_bytes());
            hash.update(responder_spi.to_be_bytes());
            hash.update([match sending_direction {
                Ikev2ProtectedPayloadDirection::InitiatorToResponder => 0,
                Ikev2ProtectedPayloadDirection::ResponderToInitiator => 1,
            }]);
            hash.update(encryption.transform_id().to_be_bytes());
            hash.update(encryption.key_bits().to_be_bytes());
            hash.update(integrity.transform_id().to_be_bytes());
            hash.update(prf.transform_id().to_be_bytes());
            hash.update([1]);
            for key in [
                keys.sk_ei(),
                keys.sk_er(),
                keys.sk_ai(),
                keys.sk_ar(),
                keys.sk_d(),
            ] {
                hash_key(&mut hash, key);
            }
            hash.finalize().into()
        });
        Ok(Self {
            binding: Arc::new(Binding {
                initiator_spi,
                responder_spi,
                direction: sending_direction,
                encryption,
                integrity,
                prf,
                canonical_format,
                sk_d: Zeroizing::new(keys.sk_d().to_vec()),
                sk_ei: Zeroizing::new(keys.sk_ei().to_vec()),
                sk_er: Zeroizing::new(keys.sk_er().to_vec()),
                sk_ai: Zeroizing::new(keys.sk_ai().to_vec()),
                sk_ar: Zeroizing::new(keys.sk_ar().to_vec()),
                ledger_key: ledger.finalize().into(),
                canonical_binding,
            }),
        })
    }

    /// Original initiator's established SPI.
    pub fn initiator_spi(&self) -> u64 {
        self.binding.initiator_spi
    }
    /// Original responder's established SPI.
    pub fn responder_spi(&self) -> u64 {
        self.binding.responder_spi
    }
    /// Local direction relative to the original IKE roles.
    pub fn direction(&self) -> Ikev2ProtectedPayloadDirection {
        self.binding.direction
    }
    /// Bound CBC encryption algorithm and key size.
    pub fn encryption(&self) -> Ikev2EncryptionAlgorithm {
        self.binding.encryption
    }
    /// Bound integrity algorithm.
    pub fn integrity(&self) -> Ikev2IntegrityAlgorithm {
        self.binding.integrity
    }
    /// Bound SA PRF algorithm used with SK_d.
    pub fn prf(&self) -> Ikev2PrfAlgorithm {
        self.binding.prf
    }
    /// Exact immutable stored format marker; absence never implies CBC-V1.
    pub fn canonical_format(&self) -> Option<u8> {
        self.binding.canonical_format
    }

    pub(crate) fn ledger_key(&self) -> [u8; 32] {
        self.binding.ledger_key
    }

    pub(crate) fn binding_fingerprint(&self) -> Option<[u8; 32]> {
        self.binding.canonical_binding
    }

    // SK_d stays in the immutable epoch; the live recipe owns its derived,
    // zeroizing IV key. The recipe receives only the local traffic key pair.
    pub(crate) fn canonical_keys(&self) -> (&[u8], &[u8], &[u8]) {
        let (e, a) = match self.direction() {
            Ikev2ProtectedPayloadDirection::InitiatorToResponder => {
                (&self.binding.sk_ei, &self.binding.sk_ai)
            }
            Ikev2ProtectedPayloadDirection::ResponderToInitiator => {
                (&self.binding.sk_er, &self.binding.sk_ar)
            }
        };
        (&self.binding.sk_d, e, a)
    }
}

fn hash_key(hash: &mut Sha256, key: &[u8]) {
    // Constructor validation bounds each supported key to at most 64 octets.
    hash.update((key.len() as u16).to_be_bytes());
    hash.update(key);
}

impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        // The full raw-key binding is authoritative. Fingerprints are only
        // indexes, compared under the same constant-time policy as the keys.
        let keys = self.sk_d.as_slice().ct_eq(other.sk_d.as_slice())
            & self.sk_ei.as_slice().ct_eq(other.sk_ei.as_slice())
            & self.sk_er.as_slice().ct_eq(other.sk_er.as_slice())
            & self.sk_ai.as_slice().ct_eq(other.sk_ai.as_slice())
            & self.sk_ar.as_slice().ct_eq(other.sk_ar.as_slice());
        let fingerprints = self.ledger_key.ct_eq(&other.ledger_key)
            & match (&self.canonical_binding, &other.canonical_binding) {
                (Some(a), Some(b)) => a.ct_eq(b),
                (None, None) => 1.into(),
                _ => 0.into(),
            };
        self.initiator_spi == other.initiator_spi
            && self.responder_spi == other.responder_spi
            && self.direction == other.direction
            && self.encryption == other.encryption
            && self.integrity == other.integrity
            && self.prf == other.prf
            && self.canonical_format == other.canonical_format
            && bool::from(keys & fingerprints)
    }
}
impl Eq for Binding {}

impl PartialEq for Ikev2CbcEpochRecord {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding
    }
}
impl Eq for Ikev2CbcEpochRecord {}

impl fmt::Debug for Ikev2CbcEpochRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CbcEpochRecord")
            .finish_non_exhaustive()
    }
}

// Both views retain the same complete immutable epoch. Changing the selected
// direction never substitutes a partial binding containing only a traffic key.
#[derive(Clone, PartialEq, Eq)]
pub struct CbcDirection {
    epoch: Ikev2CbcEpochRecord,
    direction: Ikev2ProtectedPayloadDirection,
}

impl CbcDirection {
    pub(crate) fn epoch(&self) -> &Ikev2CbcEpochRecord {
        &self.epoch
    }

    pub(super) fn new(
        epoch: &Ikev2CbcEpochRecord,
        direction: Ikev2ProtectedPayloadDirection,
    ) -> Self {
        Self {
            epoch: epoch.clone(),
            direction,
        }
    }
}

impl super::profile::DirectionBinding for CbcDirection {
    fn initiator_spi(&self) -> u64 {
        self.epoch.initiator_spi()
    }
    fn responder_spi(&self) -> u64 {
        self.epoch.responder_spi()
    }
    fn direction(&self) -> Ikev2ProtectedPayloadDirection {
        self.direction
    }
    fn encryption(&self) -> Ikev2EncryptionAlgorithm {
        self.epoch.encryption()
    }
}

#[cfg(test)]
mod tests;
