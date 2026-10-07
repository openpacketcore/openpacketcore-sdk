use bytes::BytesMut;
use opc_protocol::EncodeContext;
use zeroize::Zeroizing;

use super::Ikev2CanonicalError as Error;
use crate::{
    crypto_module::{execute_aead_open, execute_aead_seal},
    encode_header, Header, HeaderFlags, Ikev2AesGcmIvDomain, Ikev2EncryptionAlgorithm,
    Ikev2ProtectedPayloadDirection as Direction, PayloadType, IKEV2_AES_GCM_NORMAL_IV_END,
};

#[derive(Clone, Copy)]
pub(super) struct Inputs<'a> {
    pub(super) initiator_spi: u64,
    pub(super) responder_spi: u64,
    pub(super) direction: Direction,
    pub(super) algorithm: Ikev2EncryptionAlgorithm,
    pub(super) key_and_salt: &'a [u8],
}

impl<'a> Inputs<'a> {
    pub(super) fn from_domain(domain: &'a Ikev2AesGcmIvDomain) -> Self {
        Self {
            initiator_spi: domain.initiator_spi(),
            responder_spi: domain.responder_spi(),
            direction: domain.direction(),
            algorithm: domain.encryption(),
            key_and_salt: domain.key_and_salt(),
        }
    }
}

pub(super) fn seal(inputs: Inputs<'_>, message_id: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
    let iv = IKEV2_AES_GCM_NORMAL_IV_END
        .checked_add(u64::from(message_id))
        .ok_or(Error::InvalidRequest)?
        .to_be_bytes();
    let mut header = Header::new(
        inputs.initiator_spi,
        inputs.responder_spi,
        PayloadType::Encrypted,
        37,
        HeaderFlags::from_bits(
            inputs.direction == Direction::InitiatorToResponder,
            true,
            false,
        ),
        message_id,
    );
    header.length = 57;
    let mut aad = BytesMut::with_capacity(32);
    encode_header(&header, &mut aad, EncodeContext::default()).map_err(|_| Error::InvalidOutput)?;
    aad.extend_from_slice(&[0, 0, 0, 29]);
    let (key, salt) = split_key(inputs)?;
    let body =
        execute_aead_seal(inputs.algorithm, key, salt, &iv, &aad, &[0]).map_err(|error| {
            if error.code() == crate::Ikev2CryptoModuleErrorCode::InvalidOutput {
                Error::InvalidOutput
            } else {
                Error::Unavailable
            }
        })?;
    let mut packet = Zeroizing::new(aad.to_vec());
    packet.extend_from_slice(&body);
    verify(inputs, message_id, &packet)?;
    Ok(packet)
}

fn split_key(inputs: Inputs<'_>) -> Result<(&[u8], &[u8]), Error> {
    if !matches!(
        inputs.algorithm,
        Ikev2EncryptionAlgorithm::AesGcm16_128
            | Ikev2EncryptionAlgorithm::AesGcm16_192
            | Ikev2EncryptionAlgorithm::AesGcm16_256
    ) || inputs.key_and_salt.len() != inputs.algorithm.key_material_len()
    {
        return Err(Error::BindingMismatch);
    }
    Ok(inputs.key_and_salt.split_at(inputs.key_and_salt.len() - 4))
}

pub(super) fn verify(inputs: Inputs<'_>, message_id: u32, packet: &[u8]) -> Result<(), Error> {
    // Independent field writes, not a copy of the generated header/output buffer.
    let mut prefix = [0_u8; 40];
    prefix[0..8].copy_from_slice(&inputs.initiator_spi.to_be_bytes());
    prefix[8..16].copy_from_slice(&inputs.responder_spi.to_be_bytes());
    prefix[16..20].copy_from_slice(&[
        46,
        0x20,
        37,
        match inputs.direction {
            Direction::InitiatorToResponder => 0x28,
            Direction::ResponderToInitiator => 0x20,
        },
    ]);
    prefix[20..24].copy_from_slice(&message_id.to_be_bytes());
    prefix[24..32].copy_from_slice(&[0, 0, 0, 57, 0, 0, 0, 29]);
    prefix[32..36].fill(0xff);
    prefix[36..40].copy_from_slice(&message_id.to_be_bytes());
    if packet.len() != 57 || packet[..40] != prefix {
        return Err(Error::InvalidOutput);
    }
    let (key, salt) = split_key(inputs)?;
    let plaintext = execute_aead_open(inputs.algorithm, key, salt, &prefix[..32], &packet[32..])
        .map_err(|_| Error::InvalidOutput)?;
    if plaintext.as_slice() != [0] {
        return Err(Error::InvalidOutput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_prefix_check_rejects_even_valid_tags_for_corrupted_generation_inputs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        crate::test_support::ensure_ike_crypto();
        for algorithm in [
            Ikev2EncryptionAlgorithm::AesGcm16_128,
            Ikev2EncryptionAlgorithm::AesGcm16_192,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        ] {
            let key_and_salt = vec![0x42; algorithm.key_material_len()];
            for direction in [
                Direction::InitiatorToResponder,
                Direction::ResponderToInitiator,
            ] {
                let inputs = Inputs {
                    initiator_spi: 1,
                    responder_spi: 2,
                    direction,
                    algorithm,
                    key_and_salt: &key_and_salt,
                };
                let packet = seal(inputs, 0x1234_5678)?;
                // The unverified body and whole packet are guarded even on an
                // error/unwind. No unsafe observation of freed memory is needed.
                fn zeroizing_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
                zeroizing_on_drop(&packet);
                for bit in 0..320 {
                    let mut corrupt = packet.to_vec();
                    corrupt[bit / 8] ^= 1 << (bit % 8);
                    let (key, salt) = split_key(inputs)?;
                    let body = execute_aead_seal(
                        algorithm,
                        key,
                        salt,
                        &corrupt[32..40],
                        &corrupt[..32],
                        &[0],
                    )?;
                    zeroizing_on_drop(&body);
                    corrupt[32..].copy_from_slice(&body);
                    assert_eq!(
                        *execute_aead_open(algorithm, key, salt, &corrupt[..32], &corrupt[32..])?,
                        [0]
                    );
                    assert_eq!(
                        verify(inputs, 0x1234_5678, &corrupt),
                        Err(Error::InvalidOutput)
                    );
                }
                for length in [0, 31, 39, 56, 58] {
                    let mut corrupt = packet.to_vec();
                    corrupt.resize(length, 0);
                    assert_eq!(
                        verify(inputs, 0x1234_5678, &corrupt),
                        Err(Error::InvalidOutput)
                    );
                }
            }
        }
        Ok(())
    }
}
