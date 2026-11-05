//! AES-XCBC-MAC (RFC 3566) and AES-XCBC-PRF-128 (RFC 4434).
//!
//! The PRF is the full 128-bit XCBC-MAC output (not the 96-bit truncated MAC)
//! over the RFC 4434 key-length normalisation. Test vectors in this module are
//! the RFC 3566 section 4.6 / RFC 4434 section 2.1 published values.

use aes::{
    cipher::{BlockCipherEncrypt, KeyInit},
    Aes128, Block,
};

fn encrypt(cipher: &Aes128, block: &mut Block) {
    cipher.encrypt_block(block);
}

fn xcbc_mac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let key_block = Block::from(*key);
    let cipher = Aes128::new(&key_block);
    let derive = |constant: u8| {
        let mut block = Block::from([constant; 16]);
        encrypt(&cipher, &mut block);
        let mut out = [0_u8; 16];
        out.copy_from_slice(block.as_slice());
        out
    };
    let k1 = derive(0x01);
    let k2 = derive(0x02);
    let k3 = derive(0x03);

    let cipher_k1 = Aes128::new(&Block::from(k1));

    let mut state = [0_u8; 16];
    let blocks = message.len().div_ceil(16).max(1);
    for index in 0..blocks {
        let offset = index * 16;
        let remaining = message.len().saturating_sub(offset);
        let take = remaining.min(16);
        let mut block = [0_u8; 16];
        block[..take].copy_from_slice(&message[offset..offset + take]);
        let ending = index == blocks - 1;
        if ending && take == 16 {
            for (byte, mask) in block.iter_mut().zip(k2) {
                *byte ^= mask;
            }
        } else if ending {
            block[take] = 0x80;
            for (byte, mask) in block.iter_mut().zip(k3) {
                *byte ^= mask;
            }
        }
        for (byte, mask) in block.iter_mut().zip(state) {
            *byte ^= mask;
        }
        let mut block = Block::from(block);
        encrypt(&cipher_k1, &mut block);
        state.copy_from_slice(block.as_slice());
    }
    state
}

/// AES-XCBC-PRF-128 (RFC 4434): full 128-bit XCBC-MAC PRF output.
///
/// A 16-octet key is used as-is, a shorter key is zero-padded on the right,
/// and a longer key is first reduced to 16 octets by XCBC-MAC with a 128-bit
/// zero key over the long key, exactly as RFC 4434 section 2 specifies.
pub(crate) fn aes_xcbc_prf_128(key: &[u8], data: &[u8]) -> [u8; 16] {
    let normalized = match key.len() {
        16 => {
            let mut exact = [0_u8; 16];
            exact.copy_from_slice(key);
            exact
        }
        len if len < 16 => {
            let mut padded = [0_u8; 16];
            padded[..len].copy_from_slice(key);
            padded
        }
        _ => {
            let zero = [0_u8; 16];
            xcbc_mac(&zero, key)
        }
    };
    xcbc_mac(&normalized, data)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex")
            })
            .collect()
    }

    const KEY: &str = "000102030405060708090a0b0c0d0e0f";

    fn key() -> [u8; 16] {
        let mut out = [0_u8; 16];
        out.copy_from_slice(&hex(KEY));
        out
    }

    #[test]
    fn rfc3566_full_mac_vectors_match() {
        for (message, expected) in [
            ("", "75f0251d528ac01c4573dfd584d79f29"),
            ("000102", "5b376580ae2f19afe7219ceef172756f"),
            (
                "000102030405060708090a0b0c0d0e0f",
                "d2a246fa349b68a79998a4394ff7a263",
            ),
            (
                "000102030405060708090a0b0c0d0e0f10111213",
                "47f51b4564966215b8985c63055ed308",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "f54f0ec8d2b9f3d36807734bd5283fd4",
            ),
        ] {
            assert_eq!(xcbc_mac(&key(), &hex(message)), hex(expected).as_slice());
        }
    }

    #[test]
    fn rfc4434_prf_vectors_cover_key_normalization() {
        let message = hex("000102030405060708090a0b0c0d0e0f10111213");
        for (key_hex, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "47f51b4564966215b8985c63055ed308",
            ),
            ("00010203040506070809", "0fa087af7d866e7653434e602fdde835"),
            (
                "000102030405060708090a0b0c0d0e0fedcb",
                "8cd3c93ae598a9803006ffb67c40e9e4",
            ),
        ] {
            assert_eq!(
                aes_xcbc_prf_128(&hex(key_hex), &message),
                hex(expected).as_slice()
            );
        }
    }
}
