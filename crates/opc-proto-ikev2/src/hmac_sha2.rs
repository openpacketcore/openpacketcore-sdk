//! Zeroizing HMAC-SHA2 composition for IKE key derivation and integrity.
//!
//! RustCrypto supplies the SHA-2 primitive and its zeroizing digest state. This
//! narrow composition additionally owns and wipes the HMAC normalized key,
//! ipad/opad blocks, inner digest, and final digest on every path.

use sha2_zeroize::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

macro_rules! hmac_sha2 {
    ($function:ident, $digest:ty, $block_len:expr) => {
        pub(crate) fn $function(key: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
            let mut normalized_key = Zeroizing::new([0_u8; $block_len]);
            if key.len() > $block_len {
                let mut digest = <$digest>::new();
                digest.update(key);
                let hashed_key = Zeroizing::new(digest.finalize());
                normalized_key[..hashed_key.len()].copy_from_slice(&hashed_key);
            } else {
                normalized_key[..key.len()].copy_from_slice(key);
            }

            let mut inner_pad = Zeroizing::new([0x36_u8; $block_len]);
            let mut outer_pad = Zeroizing::new([0x5c_u8; $block_len]);
            for ((inner, outer), key_byte) in inner_pad
                .iter_mut()
                .zip(outer_pad.iter_mut())
                .zip(normalized_key.iter())
            {
                *inner ^= key_byte;
                *outer ^= key_byte;
            }

            let mut inner = <$digest>::new();
            inner.update(inner_pad.as_slice());
            for part in parts {
                inner.update(part);
            }
            let inner_digest = Zeroizing::new(inner.finalize());

            let mut outer = <$digest>::new();
            outer.update(outer_pad.as_slice());
            outer.update(inner_digest.as_slice());
            let output = Zeroizing::new(outer.finalize());
            Zeroizing::new(output.to_vec())
        }
    };
}

hmac_sha2!(hmac_sha2_256, Sha256, 64);
hmac_sha2!(hmac_sha2_384, Sha384, 128);
hmac_sha2!(hmac_sha2_512, Sha512, 128);

#[cfg(test)]
mod tests {
    use super::{hmac_sha2_256, hmac_sha2_384, hmac_sha2_512};

    #[test]
    fn rfc4868_prf_one_vectors_match_all_sha2_sizes() {
        let key = [0x0b; 20];
        let sha256 = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let sha384 = [
            0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46,
            0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c,
            0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1,
            0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
        ];
        let sha512 = [
            0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d,
            0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05,
            0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b,
            0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
            0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
        ];

        assert_eq!(hmac_sha2_256(&key, &[b"Hi There"]).as_slice(), sha256);
        assert_eq!(hmac_sha2_384(&key, &[b"Hi There"]).as_slice(), sha384);
        assert_eq!(hmac_sha2_512(&key, &[b"Hi There"]).as_slice(), sha512);
    }

    #[test]
    fn rfc4868_prf_five_hashes_a_key_larger_than_sha512_block() {
        let key = [0xaa; 131];
        let expected = [
            0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd, 0x7b,
            0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b, 0x01, 0x37,
            0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f,
            0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52, 0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec,
            0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98,
        ];
        assert_eq!(
            hmac_sha2_512(
                &key,
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )
            .as_slice(),
            expected
        );
    }
}
