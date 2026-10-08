//! Private CBC byte recipe and qualification.

use std::sync::OnceLock;

use bytes::BytesMut;
use opc_protocol::EncodeContext;
use zeroize::Zeroizing;

use super::{Ikev2CanonicalError as Error, Ikev2CanonicalPolicy as Policy};
use crate::{
    crypto_module::{
        canonical_module_declares_validation, check_cbc_admission, check_prf_admission,
        execute_cbc_decrypt, execute_cbc_encrypt, execute_integrity_checksum,
        execute_integrity_verification, execute_prf_plus,
    },
    encode_header, Header, HeaderFlags, Ikev2CryptoModuleError, Ikev2CryptoModuleErrorCode,
    Ikev2EncryptionAlgorithm as Encryption, Ikev2IntegrityAlgorithm as Integrity,
    Ikev2PrfAlgorithm as Prf, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile, PayloadType,
};

#[cfg(test)]
mod tests;

const KEY_LABEL: &[u8; 34] = b"opc-ikev2-canonical-cbc-iv-key-v1\0";
const IV_LABEL: &[u8; 12] = b"opc-cbc-iv-1";

// The CBC integration has passed its required crypto code review.
pub(crate) fn integration_review_gate() -> Result<(), Error> {
    Ok(())
}

const VECTORS: &str = include_str!("cbc_v1.txt");
static QUALIFIED: [OnceLock<Result<(), Error>>; 48] = [const { OnceLock::new() }; 48];

#[derive(Clone, Copy)]
enum CbcEncryption {
    Aes128,
    Aes192,
    Aes256,
}

impl CbcEncryption {
    const fn algorithm(self) -> Encryption {
        match self {
            Self::Aes128 => Encryption::AesCbc128,
            Self::Aes192 => Encryption::AesCbc192,
            Self::Aes256 => Encryption::AesCbc256,
        }
    }

    const fn bits(self) -> u16 {
        match self {
            Self::Aes128 => 128,
            Self::Aes192 => 192,
            Self::Aes256 => 256,
        }
    }
}

// A checked CBC profile cannot carry AEAD key/salt or reservation evidence.
#[derive(Clone, Copy)]
struct Profile {
    encryption: CbcEncryption,
    integrity: Integrity,
    prf: Prf,
    index: usize,
}

impl Profile {
    fn new(profile: Ikev2SaInitCryptoProfile) -> Result<Self, Error> {
        Self::from_algorithms(
            profile.encryption(),
            profile.integrity().ok_or(Error::BindingMismatch)?,
            profile.prf(),
        )
    }

    fn from_algorithms(
        encryption: Encryption,
        integrity: Integrity,
        prf: Prf,
    ) -> Result<Self, Error> {
        let (encryption, cipher_index) = match encryption {
            Encryption::AesCbc128 => (CbcEncryption::Aes128, 0),
            Encryption::AesCbc192 => (CbcEncryption::Aes192, 1),
            Encryption::AesCbc256 => (CbcEncryption::Aes256, 2),
            _ => return Err(Error::BindingMismatch),
        };
        let integrity_index = match integrity {
            Integrity::HmacSha1_96 => 0,
            Integrity::HmacSha2_256_128 => 1,
            Integrity::HmacSha2_384_192 => 2,
            Integrity::HmacSha2_512_256 => 3,
        };
        let prf_index = match prf {
            Prf::HmacSha1 => 0,
            Prf::HmacSha2_256 => 1,
            Prf::HmacSha2_384 => 2,
            Prf::HmacSha2_512 => 3,
        };
        Ok(Self {
            encryption,
            integrity,
            prf,
            index: (cipher_index * 4 + integrity_index) * 4 + prf_index,
        })
    }

    fn admitted(self) -> Result<(), Error> {
        check_cbc_admission(self.encryption.algorithm(), self.integrity)
            .map_err(|_| Error::Unavailable)?;
        check_prf_admission(self.prf).map_err(|_| Error::Unavailable)
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct Inputs<'a> {
    pub(crate) initiator_spi: u64,
    pub(crate) responder_spi: u64,
    pub(crate) direction: Direction,
    pub(crate) profile: Ikev2SaInitCryptoProfile,
    pub(crate) sk_d: &'a [u8],
    pub(crate) sk_e: &'a [u8],
    pub(crate) sk_a: &'a [u8],
}

struct KeyInputs<'a> {
    initiator_spi: u64,
    responder_spi: u64,
    direction: Direction,
    sk_d: &'a [u8],
    sk_e: &'a [u8],
    sk_a: &'a [u8],
}

struct Traffic {
    initiator_spi: u64,
    responder_spi: u64,
    direction: Direction,
    sk_e: Zeroizing<Vec<u8>>,
    sk_a: Zeroizing<Vec<u8>>,
}

// Associated recipe type of the sealed CBC profile; no raw-key public API.
pub struct Recipe {
    inputs: Traffic,
    profile: Profile,
    iv_key: Zeroizing<Vec<u8>>,
}

impl Recipe {
    #[cfg(test)]
    pub(crate) fn new(inputs: Inputs<'_>) -> Result<Self, Error> {
        Self::new_bound(
            Profile::new(inputs.profile)?,
            KeyInputs {
                initiator_spi: inputs.initiator_spi,
                responder_spi: inputs.responder_spi,
                direction: inputs.direction,
                sk_d: inputs.sk_d,
                sk_e: inputs.sk_e,
                sk_a: inputs.sk_a,
            },
        )
    }

    pub(crate) fn from_epoch(epoch: &crate::recovery::Ikev2CbcEpochRecord) -> Result<Self, Error> {
        integration_review_gate()?;
        let (sk_d, sk_e, sk_a) = epoch.canonical_keys();
        Self::new_bound(
            Profile::from_algorithms(epoch.encryption(), epoch.integrity(), epoch.prf())?,
            KeyInputs {
                initiator_spi: epoch.initiator_spi(),
                responder_spi: epoch.responder_spi(),
                direction: epoch.direction(),
                sk_d,
                sk_e,
                sk_a,
            },
        )
    }

    fn new_bound(profile: Profile, inputs: KeyInputs<'_>) -> Result<Self, Error> {
        let key_len = usize::from(profile.encryption.bits() / 8);
        if inputs.initiator_spi == 0
            || inputs.responder_spi == 0
            || inputs.sk_d.len() != profile.prf.output_len()
            || inputs.sk_e.len() != key_len
            || inputs.sk_a.len() != profile.integrity.key_len()
        {
            return Err(Error::BindingMismatch);
        }
        profile.admitted()?;
        let mut seed = [0_u8; 60];
        seed[..34].copy_from_slice(KEY_LABEL);
        seed[34..42].copy_from_slice(&inputs.initiator_spi.to_be_bytes());
        seed[42..50].copy_from_slice(&inputs.responder_spi.to_be_bytes());
        seed[50] = u8::from(inputs.direction == Direction::ResponderToInitiator);
        seed[51..53].copy_from_slice(&12_u16.to_be_bytes());
        seed[53..55].copy_from_slice(&profile.encryption.bits().to_be_bytes());
        seed[55..57].copy_from_slice(&profile.integrity.transform_id().to_be_bytes());
        seed[57..59].copy_from_slice(&profile.prf.transform_id().to_be_bytes());
        seed[59] = 1;
        let iv_key =
            execute_prf_plus(profile.prf, inputs.sk_d, &seed, key_len).map_err(map_crypto_error)?;
        Ok(Self {
            inputs: Traffic {
                initiator_spi: inputs.initiator_spi,
                responder_spi: inputs.responder_spi,
                direction: inputs.direction,
                sk_e: Zeroizing::new(inputs.sk_e.to_vec()),
                sk_a: Zeroizing::new(inputs.sk_a.to_vec()),
            },
            profile,
            iv_key,
        })
    }

    pub(crate) fn seal(&self, message_id: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut block = [0_u8; 16];
        block[..12].copy_from_slice(IV_LABEL);
        block[12..].copy_from_slice(&message_id.to_be_bytes());
        let algorithm = self.profile.encryption.algorithm();
        let iv = execute_cbc_encrypt(algorithm, &self.iv_key, &[0; 16], &block)
            .map_err(map_crypto_error)?;
        let mut plaintext = Zeroizing::new([0_u8; 16]);
        plaintext[15] = 15;
        let ciphertext = execute_cbc_encrypt(algorithm, &self.inputs.sk_e, &iv, &plaintext[..])
            .map_err(map_crypto_error)?;
        let tag_len = self.profile.integrity.icv_len();
        let mut header = Header::new(
            self.inputs.initiator_spi,
            self.inputs.responder_spi,
            PayloadType::Encrypted,
            37,
            HeaderFlags::from_bits(
                self.inputs.direction == Direction::InitiatorToResponder,
                true,
                false,
            ),
            message_id,
        );
        header.length = u32::try_from(64 + tag_len).map_err(|_| Error::InvalidOutput)?;
        let mut prefix = BytesMut::with_capacity(32);
        encode_header(&header, &mut prefix, EncodeContext::default())
            .map_err(|_| Error::InvalidOutput)?;
        prefix.extend_from_slice(&[0, 0]);
        prefix.extend_from_slice(
            &u16::try_from(36 + tag_len)
                .map_err(|_| Error::InvalidOutput)?
                .to_be_bytes(),
        );
        let mut packet = Zeroizing::new(Vec::with_capacity(64 + tag_len));
        packet.extend_from_slice(&prefix);
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&ciphertext);
        let icv =
            execute_integrity_checksum(self.profile.integrity, &self.inputs.sk_a, &packet, &[])
                .map_err(map_crypto_error)?;
        packet.extend_from_slice(&icv);
        self.verify(message_id, &packet)?;
        Ok(packet)
    }

    pub(crate) fn verify(&self, message_id: u32, packet: &[u8]) -> Result<(), Error> {
        // Independent literal layouts, not a copy of the sealer's header buffer.
        let (length, suffix) = match self.profile.integrity {
            Integrity::HmacSha1_96 => (76, [0, 0, 0, 76, 0, 0, 0, 48]),
            Integrity::HmacSha2_256_128 => (80, [0, 0, 0, 80, 0, 0, 0, 52]),
            Integrity::HmacSha2_384_192 => (88, [0, 0, 0, 88, 0, 0, 0, 60]),
            Integrity::HmacSha2_512_256 => (96, [0, 0, 0, 96, 0, 0, 0, 68]),
        };
        if packet.len() != length {
            return Err(Error::InvalidOutput);
        }
        let mut prefix = [0_u8; 32];
        prefix[..8].copy_from_slice(&self.inputs.initiator_spi.to_be_bytes());
        prefix[8..16].copy_from_slice(&self.inputs.responder_spi.to_be_bytes());
        prefix[16..20].copy_from_slice(&[
            46,
            0x20,
            37,
            match self.inputs.direction {
                Direction::InitiatorToResponder => 0x28,
                Direction::ResponderToInitiator => 0x20,
            },
        ]);
        prefix[20..24].copy_from_slice(&message_id.to_be_bytes());
        prefix[24..].copy_from_slice(&suffix);
        if packet[..32] != prefix {
            return Err(Error::InvalidOutput);
        }
        let algorithm = self.profile.encryption.algorithm();
        let input = execute_cbc_decrypt(algorithm, &self.iv_key, &[0; 16], &packet[32..48])
            .map_err(|_| Error::InvalidOutput)?;
        let mut expected_input = [0_u8; 16];
        expected_input[..12].copy_from_slice(b"opc-cbc-iv-1");
        expected_input[12..].copy_from_slice(&message_id.to_be_bytes());
        if input.as_slice() != expected_input {
            return Err(Error::InvalidOutput);
        }
        execute_integrity_verification(
            self.profile.integrity,
            &self.inputs.sk_a,
            &packet[..64],
            &packet[64..],
        )
        .map_err(|_| Error::InvalidOutput)?;
        let plaintext = execute_cbc_decrypt(
            algorithm,
            &self.inputs.sk_e,
            &packet[32..48],
            &packet[48..64],
        )
        .map_err(|_| Error::InvalidOutput)?;
        if plaintext.as_slice() != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15] {
            return Err(Error::InvalidOutput);
        }
        Ok(())
    }
}

pub(super) fn preflight(profile: Ikev2SaInitCryptoProfile, policy: Policy) -> Result<(), Error> {
    preflight_checked(
        Profile::new(profile).map_err(|_| Error::Unavailable)?,
        policy,
    )
}

pub(crate) fn preflight_epoch(
    epoch: &crate::recovery::Ikev2CbcEpochRecord,
    policy: Policy,
) -> Result<(), Error> {
    preflight_checked(
        Profile::from_algorithms(epoch.encryption(), epoch.integrity(), epoch.prf())?,
        policy,
    )
}

fn preflight_checked(checked: Profile, policy: Policy) -> Result<(), Error> {
    checked.admitted()?;
    let declared = canonical_module_declares_validation(checked.encryption.algorithm())
        .map_err(|_| Error::Unavailable)?;
    if declared && !policy.allow_declared_validated {
        return Err(Error::ValidationOptInRequired);
    }
    *QUALIFIED[checked.index]
        .get_or_init(|| qualify(checked).map_err(|_| Error::QualificationFailed))
}

fn qualify(checked: Profile) -> Result<(), Error> {
    let mut count = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 11 {
            return Err(Error::QualificationFailed);
        }
        if fields[0]
            .parse::<u16>()
            .map_err(|_| Error::QualificationFailed)?
            != checked.encryption.bits()
            || fields[1]
                .parse::<u16>()
                .map_err(|_| Error::QualificationFailed)?
                != checked.integrity.transform_id()
            || fields[2]
                .parse::<u16>()
                .map_err(|_| Error::QualificationFailed)?
                != checked.prf.transform_id()
        {
            continue;
        }
        let direction = match fields[3] {
            "I" => Direction::InitiatorToResponder,
            "R" => Direction::ResponderToInitiator,
            _ => return Err(Error::QualificationFailed),
        };
        let id = u32::from_str_radix(fields[4], 16).map_err(|_| Error::QualificationFailed)?;
        let sk_d = hex(fields[5])?;
        let sk_e = hex(fields[6])?;
        let sk_a = hex(fields[7])?;
        let recipe = Recipe::new_bound(
            checked,
            KeyInputs {
                initiator_spi: 0x0102_0304_0506_0708,
                responder_spi: 0x1112_1314_1516_1718,
                direction,
                sk_d: &sk_d,
                sk_e: &sk_e,
                sk_a: &sk_a,
            },
        )?;
        let packet = recipe.seal(id)?;
        if recipe.iv_key != hex(fields[8])?
            || packet[32..48] != hex(fields[9])?[..]
            || packet != hex(fields[10])?
        {
            return Err(Error::QualificationFailed);
        }
        count += 1;
    }
    if count == 8 {
        Ok(())
    } else {
        Err(Error::QualificationFailed)
    }
}

fn hex(value: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err(Error::QualificationFailed);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for index in (0..value.len()).step_by(2) {
        bytes.push(
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| Error::QualificationFailed)?,
        );
    }
    Ok(bytes)
}

fn map_crypto_error(error: Ikev2CryptoModuleError) -> Error {
    if error.code() == Ikev2CryptoModuleErrorCode::InvalidOutput {
        Error::InvalidOutput
    } else {
        Error::Unavailable
    }
}
