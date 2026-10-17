//! Checked wire values shared by the IKEv2 and GTPv2-C N1-mode codecs.
//!
//! These are value codecs, not authorization or session-lifecycle state. Wire
//! bytes require explicit access; formatting never exposes their contents.
//! Unlike the textual [`crate::Snssai`], [`SnssaiValue`] preserves every
//! TS 24.501 mapped-HPLMN field.

use std::fmt;

/// A malformed N1-mode wire value, without any input bytes or identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum N1ModeValueError {
    /// The PDU session identity code is reserved.
    #[error("reserved PDU session identity")]
    PduSessionId,
    /// The S-NSSAI value length is reserved or incomplete.
    #[error("invalid S-NSSAI value length")]
    SnssaiLength,
    /// A PLMN digit or the two-digit MNC filler is malformed.
    #[error("invalid PLMN identity coding")]
    PlmnIdentity,
}

/// TS 24.007 §11.2.3.1b PDU session identity code.
///
/// Zero represents an unassigned identity; assigned identities are 1 through
/// 15. An unassigned code is not an N1-disabled indication. Procedure-specific
/// requirements to supply an assigned identity remain with the caller.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PduSessionId(u8);

impl PduSessionId {
    /// The standardized unassigned identity code.
    pub const UNASSIGNED: Self = Self(0);

    /// Decode an assigned or unassigned identity code.
    ///
    /// # Errors
    ///
    /// Returns [`N1ModeValueError::PduSessionId`] for a reserved code.
    pub const fn new(value: u8) -> Result<Self, N1ModeValueError> {
        if value <= 15 {
            Ok(Self(value))
        } else {
            Err(N1ModeValueError::PduSessionId)
        }
    }

    /// Explicitly expose the wire code.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Whether the code denotes an assigned identity.
    #[must_use]
    pub const fn is_assigned(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for PduSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionId(<redacted>)")
    }
}

impl fmt::Display for PduSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Complete S-NSSAI value from TS 24.501 §9.11.2.8, without its IEI or length.
///
/// The five valid lengths are 1, 2, 4, 5 and 8 octets. SST and SD code points
/// are preserved, including a no-SD value accompanying mapped-HPLMN fields;
/// this type does not decide whether a slice is subscribed or supported.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnssaiValue {
    bytes: [u8; 8],
    len: u8,
}

impl SnssaiValue {
    /// Copy a complete value into bounded storage.
    ///
    /// # Errors
    ///
    /// Returns [`N1ModeValueError::SnssaiLength`] for any other length.
    pub fn from_bytes(value: &[u8]) -> Result<Self, N1ModeValueError> {
        let len = match value.len() {
            1 => 1,
            2 => 2,
            4 => 4,
            5 => 5,
            8 => 8,
            _ => return Err(N1ModeValueError::SnssaiLength),
        };
        let mut bytes = [0; 8];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self { bytes, len })
    }

    /// Explicitly borrow the exact wire value, without an IEI or length.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Explicitly expose the slice/service type.
    #[must_use]
    pub const fn sst(self) -> u8 {
        self.bytes[0]
    }

    /// Explicitly expose the encoded SD field, when present.
    ///
    /// The standardized no-SD code remains `Some` when encoded on the wire.
    #[must_use]
    pub const fn sd(self) -> Option<[u8; 3]> {
        if self.len >= 4 {
            Some([self.bytes[1], self.bytes[2], self.bytes[3]])
        } else {
            None
        }
    }

    /// Explicitly expose the mapped HPLMN SST, when present.
    #[must_use]
    pub const fn mapped_hplmn_sst(self) -> Option<u8> {
        match self.len {
            2 => Some(self.bytes[1]),
            5 | 8 => Some(self.bytes[4]),
            _ => None,
        }
    }

    /// Explicitly expose the mapped HPLMN SD, when present.
    #[must_use]
    pub const fn mapped_hplmn_sd(self) -> Option<[u8; 3]> {
        if self.len == 8 {
            Some([self.bytes[5], self.bytes[6], self.bytes[7]])
        } else {
            None
        }
    }
}

impl fmt::Debug for SnssaiValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnssaiValue(<redacted>)")
    }
}

impl fmt::Display for SnssaiValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Three-octet PLMN value from TS 24.008 §10.5.5.36.
///
/// Preserves two- and three-digit MNC coding, including leading zeroes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlmnIdentity([u8; 3]);

impl PlmnIdentity {
    /// Validate the decimal TBCD digits and optional third-MNC-digit filler.
    ///
    /// # Errors
    ///
    /// Returns [`N1ModeValueError::PlmnIdentity`] for any invalid digit.
    pub const fn from_bytes(value: [u8; 3]) -> Result<Self, N1ModeValueError> {
        let mnc_third = value[1] >> 4;
        if value[0] & 0x0f > 9
            || value[0] >> 4 > 9
            || value[1] & 0x0f > 9
            || value[2] & 0x0f > 9
            || value[2] >> 4 > 9
            || (mnc_third > 9 && mnc_third != 0x0f)
        {
            Err(N1ModeValueError::PlmnIdentity)
        } else {
            Ok(Self(value))
        }
    }

    /// Explicitly borrow the exact three wire octets.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 3] {
        &self.0
    }
}

impl fmt::Debug for PlmnIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlmnIdentity(<redacted>)")
    }
}

impl fmt::Display for PlmnIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}
