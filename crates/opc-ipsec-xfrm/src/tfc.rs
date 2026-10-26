//! ESP dummy plaintext construction (RFC 4303 sections 2.4 through 2.7).

use crate::XfrmError;

/// Build dummy ESP plaintext with caller-provided traffic flow confidentiality
/// data, ascending alignment padding, Pad Length, and Next Header 59.
///
/// `alignment` must be a multiple of four between 4 and 256 inclusive, selected
/// for the SA's encryption transform. Explicit IVs must be accounted for by the
/// sender. The result excludes SPI, sequence number, IV, encryption and ICV.
/// The caller owns SA sequencing, cryptography, peer-capability checks and
/// scheduling; this helper never injects packets into a kernel-owned SA.
///
/// # Errors
/// Returns [`XfrmError::InvalidConfig`] for an invalid alignment or an
/// unrepresentable/unallocatable payload length.
pub fn esp_dummy_payload(tfc_data: &[u8], alignment: usize) -> Result<Vec<u8>, XfrmError> {
    let _ = (tfc_data, alignment);
    Err(XfrmError::UnsupportedFeature {
        feature: "esp_dummy_payload",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tfc_dummy_payload_has_rfc4303_trailer_and_separate_alignment_padding() {
        assert_eq!(esp_dummy_payload(&[], 4).unwrap(), [1, 2, 2, 59]);
        assert_eq!(esp_dummy_payload(&[9, 8], 4).unwrap(), [9, 8, 0, 59]);
        for alignment in [4, 16, 256] {
            for length in [0, 1, 2, 3, 14, 15, 254, 255, 256, 4097] {
                let data = vec![0xa5; length];
                let result = esp_dummy_payload(&data, alignment).unwrap();
                let pad_len = usize::from(result[result.len() - 2]);
                assert_eq!(result.len() % alignment, 0);
                assert_eq!(result.last(), Some(&59));
                assert_eq!(&result[..length], data);
                assert_eq!(result.len(), length + pad_len + 2);
                assert_eq!(
                    &result[length..length + pad_len],
                    (1..=pad_len as u8).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn tfc_dummy_payload_rejects_invalid_alignment() {
        for alignment in [0, 1, 2, 3, 5, 255, 257, usize::MAX] {
            assert!(matches!(
                esp_dummy_payload(&[0; 8], alignment),
                Err(XfrmError::InvalidConfig {
                    field: "alignment",
                    ..
                })
            ));
        }
    }
}
