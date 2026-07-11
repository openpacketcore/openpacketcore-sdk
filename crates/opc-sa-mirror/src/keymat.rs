//! In-memory SA keymat custody types.
//!
//! Key material on the mirror path lives only in [`zeroize::Zeroizing`]
//! buffers, is never serializable, and is redacted from every `Debug`
//! rendering. See RFC 015 §4 for the custody invariant these types enforce.

use std::fmt;
use std::num::NonZeroU64;

use opc_ipsec_lb::SaId;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::SaMirrorError;

/// CNF-owned discriminant for the opaque keymat encoding.
///
/// The SDK never interprets mirrored key bytes; the producing CNF tags them
/// with a format it defines so a standby can reject an encoding it cannot
/// install. Zero is reserved as "unspecified" and rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeymatFormat(NonZeroU64);

impl KeymatFormat {
    /// Build a non-zero keymat format discriminant.
    pub fn new(value: u64) -> Result<Self, SaMirrorError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(SaMirrorError::invalid(
                "format",
                "keymat format must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric format discriminant.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonic per-SA key generation, bumped by the producer at every rekey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyEpoch(NonZeroU64);

impl KeyEpoch {
    /// Build a non-zero key epoch.
    pub fn new(value: u64) -> Result<Self, SaMirrorError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(SaMirrorError::invalid(
                "epoch",
                "key epoch must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric epoch.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Opaque live SA key material held in zeroizing memory.
///
/// The byte encoding is CNF-defined and tagged with a [`KeymatFormat`]; the
/// SDK transports and keeps custody of the bytes without ever interpreting
/// them. The type deliberately implements neither `serde::Serialize` nor
/// `serde::Deserialize`, so it cannot be handed to a persistence or generic
/// logging layer:
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<opc_sa_mirror::MirroredSaKeymat>();
/// ```
///
/// ```compile_fail
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<opc_sa_mirror::MirroredSaKeymat>();
/// ```
pub struct MirroredSaKeymat {
    format: KeymatFormat,
    secret: Zeroizing<Vec<u8>>,
}

impl MirroredSaKeymat {
    /// Take custody of freshly derived key material.
    ///
    /// The honest source is the keymat the CNF's IKE layer just derived at SA
    /// install or rekey time, captured before the only remaining copy is
    /// inside the kernel — never a kernel read-back (RFC 015 §5.1). Callers
    /// should build the buffer directly in [`Zeroizing`] form so no
    /// unzeroized copy outlives the transfer.
    pub fn new(format: KeymatFormat, secret: Zeroizing<Vec<u8>>) -> Result<Self, SaMirrorError> {
        if secret.is_empty() {
            return Err(SaMirrorError::invalid(
                "keymat",
                "mirrored keymat must not be empty",
            ));
        }
        Ok(Self { format, secret })
    }

    /// Return the CNF-owned format discriminant.
    #[must_use]
    pub const fn format(&self) -> KeymatFormat {
        self.format
    }

    /// Expose the secret key bytes for dataplane installation.
    ///
    /// The deliberately loud name keeps every access greppable in audits.
    /// Callers must not copy the bytes into non-zeroizing storage.
    #[must_use]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Constant-time equality of the secret bytes (idempotency checks only).
    #[must_use]
    pub(crate) fn secret_ct_eq(&self, other: &Self) -> bool {
        self.secret.len() == other.secret.len()
            && bool::from(self.secret.ct_eq(&other.secret))
            && self.format == other.format
    }
}

impl Zeroize for MirroredSaKeymat {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

// The only secret field is a `Zeroizing` buffer, which wipes itself on drop.
impl zeroize::ZeroizeOnDrop for MirroredSaKeymat {}

impl fmt::Debug for MirroredSaKeymat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MirroredSaKeymat")
            .field("format", &self.format)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Request to place a new key generation for one SA into standby custody.
#[derive(Debug)]
pub struct SaMirrorInstall {
    /// SA whose keymat is mirrored.
    pub sa: SaId,
    /// Key generation carried by this install.
    pub epoch: KeyEpoch,
    /// Opaque zeroizing key material.
    pub keymat: MirroredSaKeymat,
    /// Initial lower-bound "next to send" outbound IV/counter value.
    ///
    /// ESP sequence numbers start at 1 (RFC 4303), so ESP installs must carry
    /// a non-zero value; IKE explicit-IV counters may start at zero.
    pub send_iv_next: u64,
    /// Initial inbound anti-replay high watermark.
    pub replay_highest_accepted: u64,
}

impl SaMirrorInstall {
    /// Validate the install shape before transport or custody.
    pub fn validate(&self) -> Result<(), SaMirrorError> {
        validate_sa(self.sa)?;
        if matches!(self.sa, SaId::Esp { .. }) && self.send_iv_next == 0 {
            return Err(SaMirrorError::invalid(
                "send_iv_next",
                "ESP next sequence must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Monotonic counter checkpoint for an already-mirrored SA.
///
/// Checkpoints are stale lower bounds by design; the standby merges them with
/// a per-field monotonic maximum so replayed or reordered frames can never
/// lower the base from which the takeover forward-jump is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SaCounterCheckpoint {
    /// SA being checkpointed.
    pub sa: SaId,
    /// Key generation the counters belong to.
    pub epoch: KeyEpoch,
    /// Lower-bound "next to send" outbound IV/counter value.
    pub send_iv_next: u64,
    /// Inbound anti-replay high watermark.
    pub replay_highest_accepted: u64,
}

impl SaCounterCheckpoint {
    /// Validate the checkpoint shape before transport or custody.
    pub fn validate(&self) -> Result<(), SaMirrorError> {
        validate_sa(self.sa)?;
        if matches!(self.sa, SaId::Esp { .. }) && self.send_iv_next == 0 {
            return Err(SaMirrorError::invalid(
                "send_iv_next",
                "ESP next sequence must be non-zero",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_sa(sa: SaId) -> Result<(), SaMirrorError> {
    match sa {
        SaId::Esp { spi: 0 } => Err(SaMirrorError::invalid("sa.spi", "ESP SPI must be non-zero")),
        SaId::Ike { responder_spi: 0 } => Err(SaMirrorError::invalid(
            "sa.responder_spi",
            "IKE responder SPI must be non-zero",
        )),
        SaId::Esp { .. } | SaId::Ike { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keymat(bytes: &[u8]) -> MirroredSaKeymat {
        MirroredSaKeymat::new(
            KeymatFormat::new(1).unwrap(),
            Zeroizing::new(bytes.to_vec()),
        )
        .unwrap()
    }

    #[test]
    fn keymat_debug_redacts_secret_bytes() {
        let secret = keymat(b"super-secret-sa-keymat");
        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret"));
        // The byte values must not leak either.
        assert!(!debug.contains("115"));
    }

    #[test]
    fn keymat_is_zeroize_on_drop_and_explicit_zeroize_wipes() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MirroredSaKeymat>();

        let mut secret = keymat(&[0xAA; 16]);
        secret.zeroize();
        assert!(secret.expose_secret_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn keymat_rejects_empty_secret_and_zero_format() {
        assert!(matches!(
            MirroredSaKeymat::new(KeymatFormat::new(1).unwrap(), Zeroizing::new(Vec::new())),
            Err(SaMirrorError::Invalid {
                field: "keymat",
                ..
            })
        ));
        assert!(matches!(
            KeymatFormat::new(0),
            Err(SaMirrorError::Invalid {
                field: "format",
                ..
            })
        ));
        assert!(matches!(
            KeyEpoch::new(0),
            Err(SaMirrorError::Invalid { field: "epoch", .. })
        ));
    }

    #[test]
    fn keymat_ct_eq_requires_identical_format_and_bytes() {
        assert!(keymat(&[1, 2, 3]).secret_ct_eq(&keymat(&[1, 2, 3])));
        assert!(!keymat(&[1, 2, 3]).secret_ct_eq(&keymat(&[1, 2, 4])));
        assert!(!keymat(&[1, 2, 3]).secret_ct_eq(&keymat(&[1, 2, 3, 4])));
        let other_format =
            MirroredSaKeymat::new(KeymatFormat::new(2).unwrap(), Zeroizing::new(vec![1, 2, 3]))
                .unwrap();
        assert!(!keymat(&[1, 2, 3]).secret_ct_eq(&other_format));
    }

    #[test]
    fn install_and_checkpoint_validation_fails_closed() {
        let valid = SaMirrorInstall {
            sa: SaId::Esp { spi: 7 },
            epoch: KeyEpoch::new(1).unwrap(),
            keymat: keymat(&[1; 32]),
            send_iv_next: 1,
            replay_highest_accepted: 0,
        };
        valid.validate().unwrap();

        let zero_spi = SaMirrorInstall {
            sa: SaId::Esp { spi: 0 },
            ..SaMirrorInstall {
                sa: valid.sa,
                epoch: valid.epoch,
                keymat: keymat(&[1; 32]),
                send_iv_next: 1,
                replay_highest_accepted: 0,
            }
        };
        assert!(zero_spi.validate().is_err());

        let esp_zero_seq = SaMirrorInstall {
            sa: SaId::Esp { spi: 7 },
            epoch: valid.epoch,
            keymat: keymat(&[1; 32]),
            send_iv_next: 0,
            replay_highest_accepted: 0,
        };
        assert!(matches!(
            esp_zero_seq.validate(),
            Err(SaMirrorError::Invalid {
                field: "send_iv_next",
                ..
            })
        ));

        // IKE explicit-IV counters may start at zero.
        SaMirrorInstall {
            sa: SaId::Ike { responder_spi: 9 },
            epoch: valid.epoch,
            keymat: keymat(&[1; 32]),
            send_iv_next: 0,
            replay_highest_accepted: 0,
        }
        .validate()
        .unwrap();

        assert!(SaCounterCheckpoint {
            sa: SaId::Esp { spi: 7 },
            epoch: valid.epoch,
            send_iv_next: 0,
            replay_highest_accepted: 0,
        }
        .validate()
        .is_err());
        assert!(SaCounterCheckpoint {
            sa: SaId::Ike { responder_spi: 0 },
            epoch: valid.epoch,
            send_iv_next: 5,
            replay_highest_accepted: 0,
        }
        .validate()
        .is_err());
    }
}
