//! IKEv2 encrypted fragmentation (`SKF`) structural helpers.
//!
//! These helpers cover RFC 7383 payload structure and reassembly of already
//! decrypted fragment cleartext. They deliberately do not perform encryption,
//! authentication, retransmission policy, or memory-queue ownership.
//!
//! @spec IETF RFC7383
//! @req REQ-IETF-RFC7383-SKF-STRUCTURE-001

use std::{error::Error, fmt};

use bytes::Bytes;

use crate::payload::{PayloadType, RawPayload};

/// Notify message type used to advertise IKEv2 fragmentation support.
pub const IKEV2_FRAGMENTATION_SUPPORTED_NOTIFY_TYPE: u16 = 16_430;

/// Fixed SKF body prefix length: Fragment Number and Total Fragments.
pub const IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN: usize = 4;

/// Borrowed typed view of an encrypted fragment payload body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EncryptedFragmentPayload<'a> {
    /// Generic-header Next Payload value.
    ///
    /// For fragment 1 this names the first inner protected payload. For
    /// fragments greater than 1 this must be [`PayloadType::NoNext`].
    pub next_payload: PayloadType,
    /// Fragment number, starting at 1.
    pub fragment_number: u16,
    /// Total number of fragments in the fragmented protected payload.
    pub total_fragments: u16,
    /// Encrypted/authenticated fragment data after the SKF fixed fields.
    pub encrypted_fragment: &'a [u8],
}

impl<'a> Ikev2EncryptedFragmentPayload<'a> {
    /// Decode an SKF raw payload into a typed encrypted-fragment view.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2FragmentationError`] when the raw payload is not SKF or
    /// the RFC 7383 fragment-number fields are malformed.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2FragmentationError> {
        if raw.payload_type != PayloadType::EncryptedFragment {
            return Err(Ikev2FragmentationError::NotEncryptedFragmentPayload);
        }
        if raw.body.len() < IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN {
            return Err(Ikev2FragmentationError::FragmentTooShort {
                len: raw.body.len(),
            });
        }

        let fragment_number = u16::from_be_bytes([raw.body[0], raw.body[1]]);
        let total_fragments = u16::from_be_bytes([raw.body[2], raw.body[3]]);
        validate_fragment_header(fragment_number, total_fragments)?;
        validate_fragment_next_payload(raw.next_payload, fragment_number)?;

        Ok(Self {
            next_payload: raw.next_payload,
            fragment_number,
            total_fragments,
            encrypted_fragment: &raw.body[IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN..],
        })
    }
}

/// Builder input for an encrypted fragment payload body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EncryptedFragmentPayloadBuild<'a> {
    /// Generic-header Next Payload value.
    pub next_payload: PayloadType,
    /// Fragment number, starting at 1.
    pub fragment_number: u16,
    /// Total number of fragments in the fragmented protected payload.
    pub total_fragments: u16,
    /// Encrypted/authenticated fragment data.
    pub encrypted_fragment: &'a [u8],
}

/// One already-decrypted IKEv2 fragment cleartext segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2DecryptedFragment<'a> {
    /// Generic-header Next Payload value from the SKF payload.
    pub next_payload: PayloadType,
    /// Fragment number, starting at 1.
    pub fragment_number: u16,
    /// Total number of fragments in the fragmented protected payload.
    pub total_fragments: u16,
    /// Decrypted cleartext fragment data.
    pub cleartext: &'a [u8],
}

/// Reassembled protected-payload cleartext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ReassembledFragmentedPayloads {
    /// First inner payload type carried by fragment 1.
    pub first_payload: PayloadType,
    /// Concatenated decrypted cleartext from fragments 1..N.
    pub cleartext: Bytes,
}

/// Error returned while decoding, building, or reassembling IKEv2 fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2FragmentationError {
    /// The raw payload type is not SKF.
    NotEncryptedFragmentPayload,
    /// The SKF body is shorter than the fixed fragment fields.
    FragmentTooShort {
        /// Observed body length.
        len: usize,
    },
    /// Fragment number is zero.
    FragmentNumberZero,
    /// Total fragments is zero.
    TotalFragmentsZero,
    /// Fragment number is greater than Total Fragments.
    FragmentNumberExceedsTotal {
        /// Fragment number.
        fragment_number: u16,
        /// Total fragments.
        total_fragments: u16,
    },
    /// A non-first fragment carried a nonzero Next Payload value.
    NonFirstFragmentNextPayloadNonZero {
        /// Fragment number.
        fragment_number: u16,
        /// Next Payload value.
        next_payload: PayloadType,
    },
    /// The encoded body length would overflow.
    PayloadLengthOverflow,
    /// No fragments were supplied for reassembly.
    EmptyFragmentSet,
    /// Fragment total fields disagree within one reassembly set.
    InconsistentTotalFragments {
        /// Expected total fragments.
        expected: u16,
        /// Observed total fragments.
        observed: u16,
    },
    /// Two fragments used the same fragment number.
    DuplicateFragmentNumber {
        /// Duplicate fragment number.
        fragment_number: u16,
    },
    /// A fragment in the declared 1..N range is missing.
    MissingFragment {
        /// Missing fragment number.
        fragment_number: u16,
    },
    /// Fragment 1 did not identify the first inner payload.
    FirstFragmentMissingNextPayload,
    /// The concatenated cleartext would exceed the caller's limit.
    ReassembledPayloadTooLarge {
        /// Caller-supplied maximum length.
        max_len: usize,
    },
}

impl Ikev2FragmentationError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotEncryptedFragmentPayload => "ikev2_fragment_not_encrypted_fragment_payload",
            Self::FragmentTooShort { .. } => "ikev2_fragment_too_short",
            Self::FragmentNumberZero => "ikev2_fragment_number_zero",
            Self::TotalFragmentsZero => "ikev2_fragment_total_zero",
            Self::FragmentNumberExceedsTotal { .. } => "ikev2_fragment_number_exceeds_total",
            Self::NonFirstFragmentNextPayloadNonZero { .. } => {
                "ikev2_fragment_non_first_next_payload_non_zero"
            }
            Self::PayloadLengthOverflow => "ikev2_fragment_payload_length_overflow",
            Self::EmptyFragmentSet => "ikev2_fragment_empty_set",
            Self::InconsistentTotalFragments { .. } => "ikev2_fragment_inconsistent_total",
            Self::DuplicateFragmentNumber { .. } => "ikev2_fragment_duplicate_number",
            Self::MissingFragment { .. } => "ikev2_fragment_missing_fragment",
            Self::FirstFragmentMissingNextPayload => "ikev2_fragment_first_missing_next_payload",
            Self::ReassembledPayloadTooLarge { .. } => "ikev2_fragment_reassembled_too_large",
        }
    }
}

impl fmt::Display for Ikev2FragmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2FragmentationError {}

/// Build the body bytes for an SKF payload.
///
/// The caller still owns the generic IKEv2 payload header and encrypted
/// fragment bytes.
///
/// # Errors
///
/// Returns [`Ikev2FragmentationError`] when fragment numbering is invalid, a
/// non-first fragment uses a nonzero Next Payload value, or the output length
/// overflows.
pub fn build_ikev2_encrypted_fragment_payload_body(
    input: &Ikev2EncryptedFragmentPayloadBuild<'_>,
) -> Result<Bytes, Ikev2FragmentationError> {
    validate_fragment_header(input.fragment_number, input.total_fragments)?;
    validate_fragment_next_payload(input.next_payload, input.fragment_number)?;
    let capacity = IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN
        .checked_add(input.encrypted_fragment.len())
        .ok_or(Ikev2FragmentationError::PayloadLengthOverflow)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&input.fragment_number.to_be_bytes());
    out.extend_from_slice(&input.total_fragments.to_be_bytes());
    out.extend_from_slice(input.encrypted_fragment);
    Ok(Bytes::from(out))
}

/// Reassemble already-decrypted SKF fragments.
///
/// Fragments may be supplied in any order. The helper validates nonzero
/// numbering, consistent totals, duplicate numbers, missing fragments, RFC 7383
/// Next Payload rules, and a caller-owned maximum reassembled size before it
/// concatenates cleartext in fragment-number order.
///
/// # Errors
///
/// Returns [`Ikev2FragmentationError`] when the fragment set is incomplete,
/// inconsistent, duplicated, malformed, or would exceed `max_reassembled_len`.
pub fn reassemble_decrypted_ikev2_fragments(
    fragments: &[Ikev2DecryptedFragment<'_>],
    max_reassembled_len: usize,
) -> Result<Ikev2ReassembledFragmentedPayloads, Ikev2FragmentationError> {
    let first_supplied = match fragments.first() {
        Some(fragment) => fragment,
        None => return Err(Ikev2FragmentationError::EmptyFragmentSet),
    };
    let total_fragments = first_supplied.total_fragments;
    if total_fragments == 0 {
        return Err(Ikev2FragmentationError::TotalFragmentsZero);
    }

    let slot_count = usize::from(total_fragments)
        .checked_add(1)
        .ok_or(Ikev2FragmentationError::PayloadLengthOverflow)?;
    let mut slots: Vec<Option<&Ikev2DecryptedFragment<'_>>> = vec![None; slot_count];
    let mut total_len = 0usize;

    for fragment in fragments {
        validate_fragment_header(fragment.fragment_number, fragment.total_fragments)?;
        validate_fragment_next_payload(fragment.next_payload, fragment.fragment_number)?;
        if fragment.total_fragments != total_fragments {
            return Err(Ikev2FragmentationError::InconsistentTotalFragments {
                expected: total_fragments,
                observed: fragment.total_fragments,
            });
        }

        let index = usize::from(fragment.fragment_number);
        if slots[index].is_some() {
            return Err(Ikev2FragmentationError::DuplicateFragmentNumber {
                fragment_number: fragment.fragment_number,
            });
        }
        total_len = total_len
            .checked_add(fragment.cleartext.len())
            .ok_or(Ikev2FragmentationError::PayloadLengthOverflow)?;
        if total_len > max_reassembled_len {
            return Err(Ikev2FragmentationError::ReassembledPayloadTooLarge {
                max_len: max_reassembled_len,
            });
        }
        slots[index] = Some(fragment);
    }

    for fragment_number in 1..=total_fragments {
        if slots[usize::from(fragment_number)].is_none() {
            return Err(Ikev2FragmentationError::MissingFragment { fragment_number });
        }
    }

    let first_fragment = match slots[1] {
        Some(fragment) => fragment,
        None => {
            return Err(Ikev2FragmentationError::MissingFragment { fragment_number: 1 });
        }
    };
    if first_fragment.next_payload == PayloadType::NoNext {
        return Err(Ikev2FragmentationError::FirstFragmentMissingNextPayload);
    }

    let mut cleartext = Vec::with_capacity(total_len);
    for fragment_number in 1..=total_fragments {
        if let Some(fragment) = slots[usize::from(fragment_number)] {
            cleartext.extend_from_slice(fragment.cleartext);
        }
    }

    Ok(Ikev2ReassembledFragmentedPayloads {
        first_payload: first_fragment.next_payload,
        cleartext: Bytes::from(cleartext),
    })
}

fn validate_fragment_header(
    fragment_number: u16,
    total_fragments: u16,
) -> Result<(), Ikev2FragmentationError> {
    if fragment_number == 0 {
        return Err(Ikev2FragmentationError::FragmentNumberZero);
    }
    if total_fragments == 0 {
        return Err(Ikev2FragmentationError::TotalFragmentsZero);
    }
    if fragment_number > total_fragments {
        return Err(Ikev2FragmentationError::FragmentNumberExceedsTotal {
            fragment_number,
            total_fragments,
        });
    }
    Ok(())
}

fn validate_fragment_next_payload(
    next_payload: PayloadType,
    fragment_number: u16,
) -> Result<(), Ikev2FragmentationError> {
    if fragment_number > 1 && next_payload != PayloadType::NoNext {
        return Err(
            Ikev2FragmentationError::NonFirstFragmentNextPayloadNonZero {
                fragment_number,
                next_payload,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skf_raw<'a>(next_payload: PayloadType, body: &'a [u8]) -> RawPayload<'a> {
        RawPayload {
            payload_type: PayloadType::EncryptedFragment,
            next_payload,
            critical: false,
            reserved: 0,
            length: u16::try_from(4 + body.len()).unwrap_or(u16::MAX),
            body,
            offset: 0,
        }
    }

    #[test]
    fn decodes_encrypted_fragment_payload() {
        let body = [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let decoded =
            Ikev2EncryptedFragmentPayload::decode(skf_raw(PayloadType::SecurityAssociation, &body));
        assert!(matches!(
            decoded,
            Ok(Ikev2EncryptedFragmentPayload {
                next_payload: PayloadType::SecurityAssociation,
                fragment_number: 1,
                total_fragments: 3,
                encrypted_fragment: [0xaa, 0xbb, 0xcc],
            })
        ));
    }

    #[test]
    fn rejects_malformed_encrypted_fragment_headers() {
        assert!(matches!(
            Ikev2EncryptedFragmentPayload::decode(skf_raw(PayloadType::NoNext, &[0, 1, 0])),
            Err(Ikev2FragmentationError::FragmentTooShort { len: 3 })
        ));
        assert!(matches!(
            Ikev2EncryptedFragmentPayload::decode(skf_raw(PayloadType::NoNext, &[0, 0, 0, 1])),
            Err(Ikev2FragmentationError::FragmentNumberZero)
        ));
        assert!(matches!(
            Ikev2EncryptedFragmentPayload::decode(skf_raw(PayloadType::NoNext, &[0, 2, 0, 1])),
            Err(Ikev2FragmentationError::FragmentNumberExceedsTotal {
                fragment_number: 2,
                total_fragments: 1
            })
        ));
        assert!(matches!(
            Ikev2EncryptedFragmentPayload::decode(skf_raw(
                PayloadType::SecurityAssociation,
                &[0, 2, 0, 2]
            )),
            Err(
                Ikev2FragmentationError::NonFirstFragmentNextPayloadNonZero {
                    fragment_number: 2,
                    next_payload: PayloadType::SecurityAssociation
                }
            )
        ));
    }

    #[test]
    fn builds_encrypted_fragment_body() {
        let built =
            build_ikev2_encrypted_fragment_payload_body(&Ikev2EncryptedFragmentPayloadBuild {
                next_payload: PayloadType::NoNext,
                fragment_number: 2,
                total_fragments: 2,
                encrypted_fragment: &[0xde, 0xad],
            });
        assert_eq!(
            built,
            Ok(Bytes::from_static(&[0x00, 0x02, 0x00, 0x02, 0xde, 0xad]))
        );
    }

    #[test]
    fn reassembles_out_of_order_decrypted_fragments() {
        let fragments = [
            Ikev2DecryptedFragment {
                next_payload: PayloadType::NoNext,
                fragment_number: 2,
                total_fragments: 3,
                cleartext: b"lo",
            },
            Ikev2DecryptedFragment {
                next_payload: PayloadType::SecurityAssociation,
                fragment_number: 1,
                total_fragments: 3,
                cleartext: b"hel",
            },
            Ikev2DecryptedFragment {
                next_payload: PayloadType::NoNext,
                fragment_number: 3,
                total_fragments: 3,
                cleartext: b"!",
            },
        ];
        let reassembled = reassemble_decrypted_ikev2_fragments(&fragments, 8);
        assert_eq!(
            reassembled,
            Ok(Ikev2ReassembledFragmentedPayloads {
                first_payload: PayloadType::SecurityAssociation,
                cleartext: Bytes::from_static(b"hello!"),
            })
        );
    }

    #[test]
    fn reassembly_rejects_duplicate_missing_and_oversized_sets() {
        let duplicate = [
            Ikev2DecryptedFragment {
                next_payload: PayloadType::SecurityAssociation,
                fragment_number: 1,
                total_fragments: 2,
                cleartext: b"a",
            },
            Ikev2DecryptedFragment {
                next_payload: PayloadType::SecurityAssociation,
                fragment_number: 1,
                total_fragments: 2,
                cleartext: b"b",
            },
        ];
        assert!(matches!(
            reassemble_decrypted_ikev2_fragments(&duplicate, 8),
            Err(Ikev2FragmentationError::DuplicateFragmentNumber { fragment_number: 1 })
        ));

        let missing = [Ikev2DecryptedFragment {
            next_payload: PayloadType::SecurityAssociation,
            fragment_number: 1,
            total_fragments: 2,
            cleartext: b"a",
        }];
        assert!(matches!(
            reassemble_decrypted_ikev2_fragments(&missing, 8),
            Err(Ikev2FragmentationError::MissingFragment { fragment_number: 2 })
        ));

        let oversized = [
            Ikev2DecryptedFragment {
                next_payload: PayloadType::SecurityAssociation,
                fragment_number: 1,
                total_fragments: 2,
                cleartext: b"abcd",
            },
            Ikev2DecryptedFragment {
                next_payload: PayloadType::NoNext,
                fragment_number: 2,
                total_fragments: 2,
                cleartext: b"efgh",
            },
        ];
        assert!(matches!(
            reassemble_decrypted_ikev2_fragments(&oversized, 7),
            Err(Ikev2FragmentationError::ReassembledPayloadTooLarge { max_len: 7 })
        ));
    }
}
