//! Zeroizing HMAC-SHA1 composition for IKEv2 compatibility profiles.
//!
//! The SHA-1 primitive is enabled with its `zeroize` feature so digest state
//! is wiped on drop. This composition additionally wipes the normalized key,
//! pads, inner digest, and returned intermediate digest on every path.

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

const SHA1_BLOCK_LEN: usize = 64;

pub(crate) fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut normalized_key = Zeroizing::new([0_u8; SHA1_BLOCK_LEN]);
    if key.len() > SHA1_BLOCK_LEN {
        let mut digest = Sha1::new();
        digest.update(key);
        let hashed_key = Zeroizing::new(digest.finalize());
        normalized_key[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36_u8; SHA1_BLOCK_LEN]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; SHA1_BLOCK_LEN]);
    for ((inner, outer), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(normalized_key.iter())
    {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }

    let mut inner = Sha1::new();
    inner.update(inner_pad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let inner_digest = Zeroizing::new(inner.finalize());

    let mut outer = Sha1::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_digest.as_slice());
    let output = Zeroizing::new(outer.finalize());
    Zeroizing::new(output.to_vec())
}

#[cfg(test)]
mod tests {
    use super::hmac_sha1;

    #[test]
    fn rfc2202_test_case_one_matches() {
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(hmac_sha1(&[0x0b; 20], &[b"Hi There"]).as_slice(), expected);
    }
}
