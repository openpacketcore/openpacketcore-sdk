//! Security-critical capability enumeration and fail-closed capability sets.

use std::fmt;

/// One security-critical operation family a cryptographic module may advertise.
///
/// The stable identity of a capability is its [`Self::as_str`] code; internal
/// bit positions are not part of the public contract. The enum is
/// `#[non_exhaustive]` so later slices can add capabilities additively: a
/// capability a consumer does not know about is simply never present in its
/// required set, and a capability a module does not report is never available
/// (see [`CapabilitySet`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CryptoCapability {
    /// TLS handshake and record protection.
    Tls,
    /// IKEv2 pseudo-random function (PRF) computation.
    IkePrf,
    /// IKEv2 protocol hashing, including RFC 7296 NAT detection SHA-1.
    IkeHash,
    /// IKEv2 integrity protection.
    IkeIntegrity,
    /// IKEv2 payload encryption and decryption.
    IkeEncryption,
    /// IKEv2 authentication signature generation and verification.
    IkeSignature,
    /// IKEv2 Diffie-Hellman key agreement.
    IkeDiffieHellman,
    /// Entropy from a source the module declares approved for key generation.
    ApprovedEntropy,
    /// Zeroization of key material when it is released.
    Zeroization,
    /// Sealed, non-exportable key storage: keys never leave the module.
    SealedKeyStorage,
}

impl CryptoCapability {
    /// Every capability this crate models, in stable declaration order.
    ///
    /// This is a slice (not a fixed-size array) so adding a capability later
    /// is additive rather than a breaking change.
    pub const ALL: &'static [CryptoCapability] = &[
        CryptoCapability::Tls,
        CryptoCapability::IkePrf,
        CryptoCapability::IkeHash,
        CryptoCapability::IkeIntegrity,
        CryptoCapability::IkeEncryption,
        CryptoCapability::IkeSignature,
        CryptoCapability::IkeDiffieHellman,
        CryptoCapability::ApprovedEntropy,
        CryptoCapability::Zeroization,
        CryptoCapability::SealedKeyStorage,
    ];

    /// Stable machine-readable capability code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::IkePrf => "ike_prf",
            Self::IkeHash => "ike_hash",
            Self::IkeIntegrity => "ike_integrity",
            Self::IkeEncryption => "ike_encryption",
            Self::IkeSignature => "ike_signature",
            Self::IkeDiffieHellman => "ike_dh",
            Self::ApprovedEntropy => "approved_entropy",
            Self::Zeroization => "zeroization",
            Self::SealedKeyStorage => "sealed_key_storage",
        }
    }

    const fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

impl fmt::Display for CryptoCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl serde::Serialize for CryptoCapability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// A set of advertised capabilities with fail-closed semantics.
///
/// The default value is the **empty** set: a capability that was never
/// explicitly reported reads as unavailable. There is no "all capabilities"
/// constructor — every available capability must be named by whoever
/// advertises it, so nothing can become available implicitly.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapabilitySet {
    bits: u16,
}

impl CapabilitySet {
    /// The empty set: nothing is available. Identical to `Default`.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Build a set from an explicit list of capabilities.
    pub const fn from_slice(capabilities: &[CryptoCapability]) -> Self {
        let mut bits = 0_u16;
        let mut index = 0;
        while index < capabilities.len() {
            bits |= capabilities[index].bit();
            index += 1;
        }
        Self { bits }
    }

    /// Returns `true` only when `capability` was explicitly reported.
    ///
    /// Anything not reported — including capabilities this build of the
    /// consumer does not know about — reads as unavailable.
    #[must_use]
    pub const fn contains(self, capability: CryptoCapability) -> bool {
        self.bits & capability.bit() != 0
    }

    /// Returns `true` only when every capability in `required` is present.
    #[must_use]
    pub const fn contains_all(self, required: CapabilitySet) -> bool {
        required.bits & !self.bits == 0
    }

    /// A copy of this set with `capability` added.
    pub const fn with(self, capability: CryptoCapability) -> Self {
        Self {
            bits: self.bits | capability.bit(),
        }
    }

    /// A copy of this set with `capability` removed.
    pub const fn without(self, capability: CryptoCapability) -> Self {
        Self {
            bits: self.bits & !capability.bit(),
        }
    }

    /// Capabilities present in either set.
    pub const fn union(self, other: CapabilitySet) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Capabilities present in both sets.
    pub const fn intersection(self, other: CapabilitySet) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Capabilities present in this set but not in `other`.
    pub const fn difference(self, other: CapabilitySet) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    /// Returns `true` when no capability is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Number of capabilities present.
    #[must_use]
    pub const fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Iterate over the present capabilities in stable declaration order.
    pub fn iter(self) -> impl Iterator<Item = CryptoCapability> {
        CryptoCapability::ALL
            .iter()
            .copied()
            .filter(move |capability| self.contains(*capability))
    }
}

impl FromIterator<CryptoCapability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = CryptoCapability>>(iter: I) -> Self {
        iter.into_iter()
            .fold(Self::empty(), |set, capability| set.with(capability))
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_set()
            .entries(self.iter().map(CryptoCapability::as_str))
            .finish()
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[")?;
        let mut first = true;
        for capability in self.iter() {
            if !first {
                formatter.write_str(",")?;
            }
            formatter.write_str(capability.as_str())?;
            first = false;
        }
        formatter.write_str("]")
    }
}

impl serde::Serialize for CapabilitySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.iter().map(CryptoCapability::as_str))
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilitySet, CryptoCapability};

    #[test]
    fn every_listed_capability_has_a_unique_bit_and_a_unique_stable_code() {
        let mut seen_bits = CapabilitySet::empty();
        let mut codes: Vec<&'static str> = Vec::new();
        for capability in CryptoCapability::ALL.iter().copied() {
            assert!(
                !seen_bits.contains(capability),
                "duplicate bit for {capability}"
            );
            seen_bits = seen_bits.with(capability);
            assert!(
                !codes.contains(&capability.as_str()),
                "duplicate code for {capability}"
            );
            codes.push(capability.as_str());
        }
        assert_eq!(
            CapabilitySet::from_slice(CryptoCapability::ALL).len(),
            CryptoCapability::ALL.len()
        );
    }

    #[test]
    fn default_and_empty_sets_report_every_capability_as_unavailable() {
        for set in [CapabilitySet::default(), CapabilitySet::empty()] {
            assert!(set.is_empty());
            assert_eq!(set.len(), 0);
            for capability in CryptoCapability::ALL.iter().copied() {
                assert!(
                    !set.contains(capability),
                    "{capability} must be unavailable in an empty set"
                );
            }
        }
    }

    #[test]
    fn set_algebra_only_ever_yields_explicitly_named_capabilities() {
        let advertised =
            CapabilitySet::from_slice(&[CryptoCapability::Tls, CryptoCapability::IkePrf]);
        assert!(advertised.contains(CryptoCapability::Tls));
        assert!(!advertised.contains(CryptoCapability::SealedKeyStorage));

        let narrowed = advertised.without(CryptoCapability::Tls);
        assert!(!narrowed.contains(CryptoCapability::Tls));
        assert!(narrowed.contains(CryptoCapability::IkePrf));

        let required = CapabilitySet::from_slice(&[
            CryptoCapability::Tls,
            CryptoCapability::IkePrf,
            CryptoCapability::IkeDiffieHellman,
        ]);
        assert!(!advertised.contains_all(required));
        let missing = required.difference(advertised);
        assert_eq!(
            missing,
            CapabilitySet::empty().with(CryptoCapability::IkeDiffieHellman)
        );
        assert!(advertised.union(missing).contains_all(required));
        assert_eq!(
            required.intersection(advertised),
            advertised,
            "intersection must not invent capabilities"
        );
    }

    #[test]
    fn rendering_and_serialization_use_stable_codes_in_declaration_order() {
        let set = CapabilitySet::from_slice(&[
            CryptoCapability::SealedKeyStorage,
            CryptoCapability::Tls,
            CryptoCapability::IkeDiffieHellman,
        ]);
        assert_eq!(set.to_string(), "[tls,ike_dh,sealed_key_storage]");
        assert_eq!(
            format!("{set:?}"),
            "{\"tls\", \"ike_dh\", \"sealed_key_storage\"}"
        );
        let json = match serde_json::to_string(&set) {
            Ok(json) => json,
            Err(error) => panic!("capability set must serialize: {error}"),
        };
        assert_eq!(json, "[\"tls\",\"ike_dh\",\"sealed_key_storage\"]");
    }

    #[test]
    fn collecting_from_an_iterator_matches_from_slice() {
        let collected: CapabilitySet = [CryptoCapability::Zeroization, CryptoCapability::IkePrf]
            .into_iter()
            .collect();
        assert_eq!(
            collected,
            CapabilitySet::from_slice(&[CryptoCapability::IkePrf, CryptoCapability::Zeroization])
        );
    }
}
