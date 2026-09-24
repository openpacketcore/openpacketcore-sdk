//! Binary extents are admission data, not key or AAD authority.
use super::*;

fn framed(key: &[u8], aad: &[u8], algorithm: AeadAlgorithm) -> Vec<u8> {
    let nonce = [0x37; 12];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&algorithm.id().to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(key.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(nonce.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(aad.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(aad);
    bytes.extend_from_slice(&[0x93; AEAD_TAG_LEN]);
    bytes
}

#[test]
fn metadata_lengths_match_original_validated_decoding() {
    for algorithm in [AeadAlgorithm::Aes256GcmSiv, AeadAlgorithm::RemoteSeal] {
        for key_len in [1, 512] {
            let key = "k".repeat(key_len);
            for aad_len in [
                0,
                1,
                CONFIG_CAPACITY_V1_AAD_BYTES,
                CONFIG_CAPACITY_V1_AAD_BYTES + 1,
            ] {
                // These bytes intentionally are not JSON. This API reports
                // framing only and must not silently claim AAD validation.
                let aad = vec![0xFF; aad_len];
                let bytes = framed(key.as_bytes(), &aad, algorithm);
                assert_eq!(
                    CryptoEnvelopeRef::encoded_metadata_lengths(&bytes).unwrap(),
                    (key_len, aad_len),
                );
                let owned = CryptoEnvelopeV1::decode(&bytes).unwrap();
                assert_eq!(owned.key_id.as_str().len(), key_len);
                assert_eq!(owned.aad.len(), aad_len);
            }
        }
    }
}

#[test]
fn metadata_lengths_reject_truncated_and_impossible_extents() {
    let bytes = framed(b"synthetic-key", b"opaque-aad", AeadAlgorithm::Aes256GcmSiv);
    // The original contains exactly one minimum-size tag; every proper
    // prefix is invalid, including prefixes ending at a declared field edge.
    for length in 0..bytes.len() {
        assert!(CryptoEnvelopeRef::encoded_metadata_lengths(&bytes[..length]).is_err());
    }
    for offset in [0, 4, 6] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(CryptoEnvelopeRef::encoded_metadata_lengths(&changed).is_err());
    }
    for (start, width) in [(8, 2), (10, 2), (12, 4)] {
        let mut changed = bytes.clone();
        changed[start..start + width].fill(0xFF);
        assert!(CryptoEnvelopeRef::encoded_metadata_lengths(&changed).is_err());
    }
    let invalid_utf8 = framed(&[0xFF], b"aad", AeadAlgorithm::Aes256GcmSiv);
    assert!(CryptoEnvelopeRef::encoded_metadata_lengths(&invalid_utf8).is_err());
}

#[test]
fn metadata_lengths_do_not_grant_key_or_aad_authority() {
    for key in [
        "".to_owned(),
        "invalid key".to_owned(),
        "k".repeat(513),
        "k".repeat(usize::from(u16::MAX)),
    ] {
        let bytes = framed(
            key.as_bytes(),
            b"not-an-authenticated-aad",
            AeadAlgorithm::Aes256GcmSiv,
        );
        assert_eq!(
            CryptoEnvelopeRef::encoded_metadata_lengths(&bytes).unwrap(),
            (key.len(), b"not-an-authenticated-aad".len()),
        );
        assert!(CryptoEnvelopeRef::decode(&bytes).is_err());
        assert!(CryptoEnvelopeV1::decode(&bytes).is_err());
    }
}
