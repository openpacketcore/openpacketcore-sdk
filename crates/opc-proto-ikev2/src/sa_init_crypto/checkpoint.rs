//! Bounded group/version encoding for opt-in initiator private checkpoints.
//! No envelope, key-provider call, module identity or diagnostic byte rendering.

use super::*;
use opc_crypto_provider::{CryptoOperationError as Error, CryptoOperationErrorCode as Code};

fn invalid() -> Error {
    Error::new(Code::InvalidCheckpoint)
}

// crypto_bigint's EncodedUint exposes mutable bytes but has no Zeroize impl.
// Cover both integer and curve encodings without leaving an unwiped temporary.
struct SecretEncoding<T>(T);
impl<T: AsMut<[u8]>> Zeroize for SecretEncoding<T> {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl SoftwareEphemeralDhKey {
    pub(crate) fn export_checkpoint(&self) -> Zeroizing<Vec<u8>> {
        let mut output = Zeroizing::new(Vec::with_capacity(3 + self.group.shared_secret_len()));
        output.push(1);
        output.extend_from_slice(&self.group.transform_id().to_be_bytes());
        macro_rules! append {
            ($value:expr) => {{
                let bytes = Zeroizing::new(SecretEncoding($value));
                output.extend_from_slice(bytes.0.as_ref());
            }};
        }
        match &self.secret {
            SoftwareEphemeralDhSecret::Modp768(value) => append!(value.to_be_bytes()),
            SoftwareEphemeralDhSecret::Modp1024(value) => append!(value.to_be_bytes()),
            SoftwareEphemeralDhSecret::Modp2048(value) => append!(value.to_be_bytes()),
            SoftwareEphemeralDhSecret::Ecp256(value) => append!(value.to_bytes()),
            SoftwareEphemeralDhSecret::Ecp384(value) => append!(value.to_bytes()),
            SoftwareEphemeralDhSecret::Ecp521(value) => append!(value.to_bytes()),
        }
        output
    }

    pub(crate) fn from_checkpoint(
        group: Ikev2DhGroup,
        checkpoint: &[u8],
        expected_public_value: &[u8],
    ) -> Result<Self, Error> {
        if checkpoint.len() != 3 + group.shared_secret_len()
            || checkpoint[0] != 1
            || u16::from_be_bytes([checkpoint[1], checkpoint[2]]) != group.transform_id()
        {
            return Err(invalid());
        }
        let scalar = &checkpoint[3..];
        macro_rules! modp {
            ($uint:ty, $prime:ident, $pow:ident, $variant:ident) => {{
                let private = Zeroizing::new(<$uint>::from_be_slice(scalar));
                if *private < <$uint>::from_u64(2)
                    || *private > $prime().wrapping_sub(&<$uint>::from_u64(2))
                {
                    return Err(invalid());
                }
                let public = $pow(&<$uint>::from_u64(MODP_GENERATOR_TWO), &private)
                    .map_err(|_| invalid())?;
                Self {
                    group,
                    public_value: public.to_be_bytes().as_ref().to_vec(),
                    secret: SoftwareEphemeralDhSecret::$variant(private),
                }
            }};
        }
        macro_rules! ecp {
            ($key:ty, $variant:ident) => {{
                // The exact-width check above disallows SecretKey's shorter,
                // zero-padded representations. Its parser also rejects zero and
                // values outside the group's scalar range.
                let secret = <$key>::from_slice(scalar).map_err(|_| invalid())?;
                let public_value =
                    ecp_public_value_bytes(&secret.public_key(), group).map_err(|_| invalid())?;
                Self {
                    group,
                    public_value,
                    secret: SoftwareEphemeralDhSecret::$variant(secret),
                }
            }};
        }
        let restored = match group {
            Ikev2DhGroup::Modp768 => modp!(U768, modp768_prime, modp768_pow, Modp768),
            Ikev2DhGroup::Modp1024 => modp!(U1024, modp1024_prime, modp1024_pow, Modp1024),
            Ikev2DhGroup::Modp2048 => modp!(U2048, modp2048_prime, modp2048_pow, Modp2048),
            Ikev2DhGroup::Ecp256 => ecp!(P256SecretKey, Ecp256),
            Ikev2DhGroup::Ecp384 => ecp!(P384SecretKey, Ecp384),
            Ikev2DhGroup::Ecp521 => ecp!(P521SecretKey, Ecp521),
        };
        validate_dh_public_value(group, restored.public_value()).map_err(|_| invalid())?;
        if restored.public_value() != expected_public_value {
            return Err(Error::new(Code::CheckpointPublicValueMismatch));
        }
        Ok(restored)
    }
}
