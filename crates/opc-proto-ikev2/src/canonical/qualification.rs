use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::{wire, Ikev2CanonicalError as Error, Ikev2CanonicalPolicy as Policy};
use crate::{
    crypto_module::canonical_module_declares_validation, Ikev2EncryptionAlgorithm as Algorithm,
    Ikev2ProtectedPayloadDirection as Direction,
};

static QUALIFIED: [OnceLock<Result<(), Error>>; 3] = [const { OnceLock::new() }; 3];
const VECTORS: &str = include_str!("v1.txt");

pub(super) fn preflight(algorithm: Algorithm, policy: Policy) -> Result<(), Error> {
    let index = match algorithm {
        Algorithm::AesGcm16_128 => 0,
        Algorithm::AesGcm16_192 => 1,
        Algorithm::AesGcm16_256 => 2,
        _ => return Err(Error::Unavailable),
    };
    let declared =
        canonical_module_declares_validation(algorithm).map_err(|_| Error::Unavailable)?;
    if declared && !policy.allow_declared_validated {
        return Err(Error::ValidationOptInRequired);
    }
    *QUALIFIED[index].get_or_init(|| qualify(algorithm).map_err(|_| Error::QualificationFailed))
}

fn qualify(algorithm: Algorithm) -> Result<(), Error> {
    let key_bits = (algorithm.key_material_len() - 4) * 8;
    let mut count = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 5 {
            return Err(Error::QualificationFailed);
        }
        if fields[0]
            .parse::<usize>()
            .map_err(|_| Error::QualificationFailed)?
            != key_bits
        {
            continue;
        }
        let direction = match fields[1] {
            "I" => Direction::InitiatorToResponder,
            "R" => Direction::ResponderToInitiator,
            _ => return Err(Error::QualificationFailed),
        };
        let message_id =
            u32::from_str_radix(fields[2], 16).map_err(|_| Error::QualificationFailed)?;
        let key_and_salt = hex(fields[3])?;
        let expected = hex(fields[4])?;
        let packet = wire::seal(
            wire::Inputs {
                initiator_spi: 0x0102_0304_0506_0708,
                responder_spi: 0x1112_1314_1516_1718,
                direction,
                algorithm,
                key_and_salt: &key_and_salt,
            },
            message_id,
        )?;
        if packet != expected {
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

// Only immutable checked-in public test keys/packets are parsed here. Never a
// runtime SA input, consumer-selectable known answer or replacement fixture.
fn hex(value: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
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
