use super::*;

fn original_owned_decode(bytes: &[u8]) -> Result<CryptoEnvelopeV1, CryptoError> {
    if bytes.len() < HEADER_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }

    if bytes[..4] != ENVELOPE_MAGIC {
        return Err(CryptoError::InvalidEnvelope);
    }

    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::InvalidEnvelope);
    }

    let algorithm = AeadAlgorithm::from_id(u16::from_be_bytes([bytes[6], bytes[7]]))
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let key_id_len = usize::from(u16::from_be_bytes([bytes[8], bytes[9]]));
    let nonce_len = usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    let aad_len = usize::try_from(u32::from_be_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15],
    ]))
    .map_err(|_| CryptoError::InvalidEnvelope)?;

    let payload_offset = HEADER_LEN
        .checked_add(key_id_len)
        .and_then(|value| value.checked_add(nonce_len))
        .and_then(|value| value.checked_add(aad_len))
        .ok_or(CryptoError::InvalidEnvelope)?;
    if payload_offset > bytes.len() {
        return Err(CryptoError::InvalidEnvelope);
    }

    let key_id_end = HEADER_LEN + key_id_len;
    let nonce_end = key_id_end + nonce_len;
    let aad_end = nonce_end + aad_len;
    let ciphertext_and_tag = bytes[aad_end..].to_vec();
    if ciphertext_and_tag.len() < AEAD_TAG_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }

    let key_id = std::str::from_utf8(&bytes[HEADER_LEN..key_id_end])
        .map_err(|_| CryptoError::InvalidEnvelope)?;

    Ok(CryptoEnvelopeV1 {
        algorithm,
        key_id: KeyId::new(key_id.to_owned()).map_err(|_| CryptoError::InvalidEnvelope)?,
        nonce: bytes[key_id_end..nonce_end].to_vec(),
        aad: bytes[nonce_end..aad_end].to_vec(),
        ciphertext_and_tag,
    })
}

fn original_matches(view: &CryptoEnvelopeRef<'_>, bytes: &[u8]) -> bool {
    CryptoEnvelopeV1 {
        algorithm: view.algorithm,
        key_id: view.key_id.clone(),
        nonce: view.nonce.to_vec(),
        aad: view.aad.to_vec(),
        ciphertext_and_tag: view.ciphertext_and_tag.to_vec(),
    }
    .encode()
    .is_ok_and(|encoded| encoded == bytes)
}

fn compare_decoders(bytes: &[u8]) {
    let expected = original_owned_decode(bytes);
    let borrowed = CryptoEnvelopeRef::decode(bytes);
    let owned = CryptoEnvelopeV1::decode(bytes);
    assert_eq!(borrowed.is_ok(), expected.is_ok());
    assert_eq!(owned.is_ok(), expected.is_ok());
    if let Ok(expected) = expected {
        let view = borrowed.unwrap();
        assert_eq!(owned.unwrap(), expected);
        assert_eq!(view.algorithm, expected.algorithm);
        assert_eq!(view.key_id, expected.key_id);
        assert_eq!(view.nonce, expected.nonce);
        assert_eq!(view.aad, expected.aad);
        assert_eq!(view.ciphertext_and_tag, expected.ciphertext_and_tag);
        assert_eq!(view.matches_encoding(bytes), original_matches(&view, bytes));
    }
}

#[test]
fn borrowed_envelope_matches_original_decoder_on_boundaries_and_mutations() {
    for algorithm in [AeadAlgorithm::Aes256GcmSiv, AeadAlgorithm::RemoteSeal] {
        for ciphertext_len in [AEAD_TAG_LEN, AEAD_TAG_LEN + 1, 1024] {
            let encoded = CryptoEnvelopeV1 {
                algorithm,
                key_id: KeyId::new("opaque-key-id").unwrap(),
                nonce: vec![0x53; algorithm.nonce_len()],
                aad: b"opaque-aad-bytes".to_vec(),
                ciphertext_and_tag: vec![0xA5; ciphertext_len],
            }
            .encode()
            .unwrap();
            compare_decoders(&encoded);
            let view = CryptoEnvelopeRef::decode(&encoded).unwrap();
            assert!(view.matches_encoding(&encoded));
            let offset = HEADER_LEN + view.key_id.as_str().len();
            assert_eq!(view.nonce.as_ptr(), encoded[offset..].as_ptr());
            assert_eq!(
                view.aad.as_ptr(),
                encoded[offset + view.nonce.len()..].as_ptr()
            );
            assert_eq!(
                view.ciphertext_and_tag.as_ptr(),
                encoded[encoded.len() - ciphertext_len..].as_ptr()
            );
            for length in 0..encoded.len() {
                compare_decoders(&encoded[..length]);
                assert!(!view.matches_encoding(&encoded[..length]));
            }
            for index in 0..encoded.len() {
                for mask in [1, 0x80, 0xFF] {
                    let mut changed = encoded.clone();
                    changed[index] ^= mask;
                    compare_decoders(&changed);
                    assert!(!view.matches_encoding(&changed));
                }
            }
            let mut trailing = encoded.clone();
            trailing.push(0);
            compare_decoders(&trailing);
            assert!(!view.matches_encoding(&trailing));
        }
    }
}

#[test]
fn borrowed_envelope_canonical_comparison_observes_every_view_field() {
    let encoded = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: KeyId::new("opaque-key-id").unwrap(),
        nonce: vec![0x53; 12],
        aad: b"opaque-aad-bytes".to_vec(),
        ciphertext_and_tag: vec![0xA5; 32],
    }
    .encode()
    .unwrap();
    for field in 0..7 {
        let mut view = CryptoEnvelopeRef::decode(&encoded).unwrap();
        let wide_nonce = vec![0; usize::from(u16::MAX) + 1];
        match field {
            0 => view.algorithm = AeadAlgorithm::RemoteSeal,
            1 => view.key_id = KeyId::new("different-key-id").unwrap(),
            2 => view.nonce = b"different-no",
            3 => view.aad = b"different-aad",
            4 => view.ciphertext_and_tag = b"different-ciphertext-and-tag",
            5 => view.ciphertext_and_tag = &[],
            _ => view.nonce = &wide_nonce,
        }
        assert!(!view.matches_encoding(&encoded));
        assert_eq!(
            view.matches_encoding(&encoded),
            original_matches(&view, &encoded)
        );
    }
}
