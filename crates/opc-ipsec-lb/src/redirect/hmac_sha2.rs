//! Private zeroizing HMAC-SHA-256 composition for redirect integrity mode.
//!
//! This mirrors the established IKEv2 SDK helper: the normalized key,
//! ipad/opad, inner digest, and final output are all owned by zeroizing values,
//! while `sha2-zeroize` wipes the digest state itself on drop.

use sha2_zeroize::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_OUTPUT_BYTES: usize = 32;

pub(super) fn hmac_sha2_256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; SHA256_OUTPUT_BYTES]> {
    let mut normalized_key = Zeroizing::new([0_u8; SHA256_BLOCK_BYTES]);
    if key.len() > SHA256_BLOCK_BYTES {
        let mut digest = Sha256::new();
        digest.update(key);
        let mut hashed_key = digest.finalize();
        normalized_key[..SHA256_OUTPUT_BYTES].copy_from_slice(hashed_key.as_slice());
        hashed_key.as_mut_slice().zeroize();
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36_u8; SHA256_BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; SHA256_BLOCK_BYTES]);
    for ((inner, outer), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(normalized_key.iter())
    {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let mut inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_digest.as_slice());
    inner_digest.as_mut_slice().zeroize();
    let mut digest = outer.finalize();
    let mut output = Zeroizing::new([0_u8; SHA256_OUTPUT_BYTES]);
    output.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize();
    output
}

#[cfg(test)]
mod tests {
    use super::hmac_sha2_256;

    #[test]
    fn rfc4231_test_case_one_matches_hmac_sha256() {
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(
            hmac_sha2_256(&[0x0b; 20], &[b"Hi There"]).as_slice(),
            expected
        );
    }

    #[test]
    fn rfc4231_test_case_six_hashes_a_long_key_before_hmac_sha256() {
        let expected = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];
        assert_eq!(
            hmac_sha2_256(
                &[0xaa; 131],
                &[
                    b"Test Using Larger Than Block-Size ",
                    b"Key - Hash Key First"
                ],
            )
            .as_slice(),
            expected
        );
    }
}
