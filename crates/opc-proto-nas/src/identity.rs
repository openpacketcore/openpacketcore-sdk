//! 5GS mobile identity decoding (TS 24.501 §9.11.3.4).
//!
//! Operates on the *content* of a 5GS mobile identity IE (the value bytes,
//! after any IEI/length framing has been removed by the message layer).
//! Every variant retains the original content bytes, so re-encoding is
//! byte-exact by construction; structured fields are parsed views.
//!
//! @spec 3GPP TS24501 R18 9.11.3.4
//! @req REQ-3GPP-TS24501-R18-9.11.3.4-001
//! @conformance v0

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{DecodeError, DecodeErrorCode, EncodeError, SpecRef};

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS24501", "9.11.3.4")
}

/// Type-of-identity values (bits 3–1 of the first content octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    /// No identity (0).
    NoIdentity = 0,
    /// SUCI (1).
    Suci = 1,
    /// 5G-GUTI (2).
    Guti5g = 2,
    /// IMEI (3).
    Imei = 3,
    /// 5G-S-TMSI (4).
    Tmsi5gs = 4,
    /// IMEISV (5).
    Imeisv = 5,
    /// MAC address (6).
    MacAddress = 6,
    /// EUI-64 (7).
    Eui64 = 7,
}

impl IdentityType {
    fn from_bits(bits: u8) -> Self {
        // All eight 3-bit values are assigned in TS 24.501 §9.11.3.4.
        match bits & 0x07 {
            0 => Self::NoIdentity,
            1 => Self::Suci,
            2 => Self::Guti5g,
            3 => Self::Imei,
            4 => Self::Tmsi5gs,
            5 => Self::Imeisv,
            6 => Self::MacAddress,
            _ => Self::Eui64,
        }
    }
}

/// Parsed view of a 5G-GUTI (11-octet identity content).
///
/// Layout per §9.11.3.4: type octet, MCC/MNC (3 octets BCD), AMF Region ID,
/// AMF Set ID (10 bits) + AMF Pointer (6 bits), 5G-TMSI (4 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GutiView {
    /// MCC/MNC as the raw 3-octet BCD encoding (TS 24.501 keeps the
    /// TS 23.003 digit packing; this crate does not unpack digits in v0).
    pub plmn: [u8; 3],
    /// AMF Region ID (8 bits).
    pub amf_region_id: u8,
    /// AMF Set ID (10 bits).
    pub amf_set_id: u16,
    /// AMF Pointer (6 bits).
    pub amf_pointer: u8,
    /// 5G-TMSI.
    pub tmsi: u32,
}

/// Parsed view of a SUCI identity content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuciView {
    /// SUPI format 0: IMSI-based SUCI.
    Imsi {
        /// MCC/MNC raw 3-octet BCD encoding.
        plmn: [u8; 3],
        /// Routing indicator, raw 2-octet BCD (digits not unpacked in v0).
        routing_indicator: [u8; 2],
        /// Protection scheme id (low nibble of octet 7). 0 = null scheme.
        protection_scheme_id: u8,
        /// Home network public key identifier.
        home_network_pki: u8,
        /// Scheme output (MSIN BCD for the null scheme; ECIES output
        /// otherwise). Never de-concealed by this crate.
        scheme_output: Bytes,
    },
    /// SUPI format 1: network-specific identifier (NAI), kept as raw bytes.
    Nai {
        /// The NAI bytes as received (typically UTF-8, not validated in v0).
        nai: Bytes,
    },
    /// Any other SUPI format value, preserved raw.
    Other {
        /// SUPI format value (bits 7–5 of the first content octet).
        supi_format: u8,
    },
}

/// A decoded 5GS mobile identity.
///
/// The original content bytes are always retained in `raw`, and
/// [`MobileIdentity::encode`] writes them back verbatim, so decode → encode
/// is byte-exact regardless of how much structure v0 parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileIdentity {
    /// Type of identity from bits 3–1 of the first content octet.
    pub identity_type: IdentityType,
    /// Structured view, where v0 parses one (5G-GUTI and SUCI only).
    pub view: IdentityView,
    /// The full identity content as received.
    pub raw: Bytes,
}

/// Structured views by identity type. Types without a v0 structured parse
/// (IMEI/IMEISV/5G-S-TMSI/MAC/EUI-64/no-identity) are length-checked only
/// and exposed through [`MobileIdentity::raw`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityView {
    /// 5G-GUTI fields.
    Guti(GutiView),
    /// SUCI fields.
    Suci(SuciView),
    /// No structured view in v0; consult `MobileIdentity::raw`.
    Raw,
}

/// Minimum content lengths per identity type, used for structural
/// validation before any field access.
fn min_len(identity_type: IdentityType) -> usize {
    match identity_type {
        IdentityType::NoIdentity => 1,
        // type octet + PLMN(3) + routing(2) + scheme(1) + HN-PKI(1)
        IdentityType::Suci => 8,
        // type octet + PLMN(3) + region(1) + set/pointer(2) + TMSI(4)
        IdentityType::Guti5g => 11,
        // type octet with first digit; at least one more BCD octet
        IdentityType::Imei | IdentityType::Imeisv => 2,
        // type octet + set/pointer(2) + TMSI(4)
        IdentityType::Tmsi5gs => 7,
        // type octet + 48-bit MAC
        IdentityType::MacAddress => 7,
        // type octet + 64-bit EUI
        IdentityType::Eui64 => 9,
    }
}

impl MobileIdentity {
    /// Decode a 5GS mobile identity from IE content bytes.
    ///
    /// `content` must be the IE value only (no IEI octet, no length octets).
    /// Exact-length types (5G-GUTI, 5G-S-TMSI, MAC, EUI-64) reject surplus
    /// bytes; digit-based types accept variable length.
    ///
    /// @spec 3GPP TS24501 R18 9.11.3.4
    /// @req REQ-3GPP-TS24501-R18-9.11.3.4-002
    /// @conformance v0
    pub fn decode(content: &[u8]) -> Result<Self, DecodeError> {
        if content.is_empty() {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref()));
        }

        let identity_type = IdentityType::from_bits(content[0]);
        if content.len() < min_len(identity_type) {
            return Err(DecodeError::new(DecodeErrorCode::Truncated, 0).with_spec_ref(spec_ref()));
        }

        let exact_len = match identity_type {
            IdentityType::Guti5g => Some(11),
            IdentityType::Tmsi5gs => Some(7),
            IdentityType::MacAddress => Some(7),
            IdentityType::Eui64 => Some(9),
            _ => None,
        };
        if let Some(expected) = exact_len {
            if content.len() != expected {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "unexpected mobile identity content length",
                    },
                    0,
                )
                .with_spec_ref(spec_ref()));
            }
        }

        let view = match identity_type {
            IdentityType::Guti5g => IdentityView::Guti(GutiView {
                plmn: [content[1], content[2], content[3]],
                amf_region_id: content[4],
                // AMF Set ID spans octet 6 and the top two bits of octet 7.
                amf_set_id: (u16::from(content[5]) << 2) | (u16::from(content[6]) >> 6),
                amf_pointer: content[6] & 0x3F,
                tmsi: u32::from_be_bytes([content[7], content[8], content[9], content[10]]),
            }),
            IdentityType::Suci => {
                let supi_format = (content[0] >> 4) & 0x07;
                match supi_format {
                    0 => IdentityView::Suci(SuciView::Imsi {
                        plmn: [content[1], content[2], content[3]],
                        routing_indicator: [content[4], content[5]],
                        protection_scheme_id: content[6] & 0x0F,
                        home_network_pki: content[7],
                        scheme_output: Bytes::copy_from_slice(&content[8..]),
                    }),
                    1 => IdentityView::Suci(SuciView::Nai {
                        nai: Bytes::copy_from_slice(&content[1..]),
                    }),
                    other => IdentityView::Suci(SuciView::Other { supi_format: other }),
                }
            }
            _ => IdentityView::Raw,
        };

        Ok(Self {
            identity_type,
            view,
            raw: Bytes::copy_from_slice(content),
        })
    }

    /// Write the identity content back verbatim (byte-exact with the
    /// decoded input by construction).
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        dst.put_slice(&self.raw);
        Ok(())
    }

    /// Content length in octets.
    pub fn wire_len(&self) -> usize {
        self.raw.len()
    }

    /// For IMEI/IMEISV identities: whether the digit count is odd
    /// (bit 4 of the first content octet). `None` for other types.
    pub fn odd_digit_indicator(&self) -> Option<bool> {
        match self.identity_type {
            IdentityType::Imei | IdentityType::Imeisv | IdentityType::Suci => {
                Some((self.raw[0] & 0x08) != 0)
            }
            _ => None,
        }
    }
}
