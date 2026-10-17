//! Typed N1-mode Notify values, independent of session and authorization policy.
//!
//! Decode these only after the caller has opened and authenticated the enclosing
//! exchange as required by its procedure. Successful decoding establishes wire
//! validity, not negotiation, slice authorization, or a session mapping.
//!
//! @spec 3GPP TS24302 V18.7.0 8.2.9.15, 8.2.9.16, 8.2.9.17
//! @conformance boundary-only

pub use opc_types::n1_mode::{PduSessionId, PlmnIdentity, SnssaiValue};

pub use crate::notify::{
    IKEV2_NOTIFY_N1_MODE_CAPABILITY, IKEV2_NOTIFY_N1_MODE_INFORMATION,
    IKEV2_NOTIFY_N1_MODE_S_NSSAI_PLMN_ID,
};
use crate::{
    notify::{Ikev2NotifyPayload, IKEV2_NOTIFY_PROTOCOL_ID_NONE},
    sa_init::{encode_notify_payload_build, Ikev2NotifyPayloadBuild},
};

/// Local work bound for the collection decoder, including unrelated Notifies.
pub const N1_MODE_MAX_NOTIFIES: usize = 64;

/// A checked value from one of the three N1-mode Notify types.
///
/// Formatting identifies the variant but redacts its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2N1ModeNotify {
    /// N1_MODE_CAPABILITY and its PDU session identity.
    Capability(PduSessionId),
    /// N1_MODE_INFORMATION and its complete S-NSSAI value.
    Information(SnssaiValue),
    /// N1_MODE_S_NSSAI_PLMN_ID and the associated PLMN.
    SnssaiPlmnId(PlmnIdentity),
}

impl Ikev2N1ModeNotify {
    /// Build the generic Notify representation with protocol ID zero and no SPI.
    #[must_use]
    pub fn to_notify_build(self) -> Ikev2NotifyPayloadBuild {
        let (notify_message_type, notification_data) = match self {
            Self::Capability(value) => (IKEV2_NOTIFY_N1_MODE_CAPABILITY, vec![1, value.value()]),
            Self::Information(value) => {
                let mut data = Vec::with_capacity(1 + value.as_bytes().len());
                // The checked value has at most eight octets.
                data.push(value.as_bytes().len() as u8);
                data.extend_from_slice(value.as_bytes());
                (IKEV2_NOTIFY_N1_MODE_INFORMATION, data)
            }
            Self::SnssaiPlmnId(value) => {
                let mut data = Vec::with_capacity(4);
                data.push(3);
                data.extend_from_slice(value.as_bytes());
                (IKEV2_NOTIFY_N1_MODE_S_NSSAI_PLMN_ID, data)
            }
        };
        Ikev2NotifyPayloadBuild {
            protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            spi: Vec::new(),
            notify_message_type,
            notification_data,
        }
    }
}

/// A value-free N1-mode Notify codec or collection failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Ikev2N1ModeNotifyError {
    /// A recognized Notify carries an SPI or a nonzero SPI size.
    #[error("N1-mode Notify SPI must be empty")]
    SpiNotEmpty,
    /// The inner length is missing or does not exactly cover the value.
    #[error("N1-mode Notify inner length mismatch")]
    LengthMismatch,
    /// The PDU session identity has an invalid shape or reserved code.
    #[error("invalid N1-mode PDU session identity")]
    InvalidPduSessionId,
    /// The S-NSSAI does not have a complete supported value shape.
    #[error("invalid N1-mode S-NSSAI")]
    InvalidSnssai,
    /// The PLMN does not have three correctly coded octets.
    #[error("invalid N1-mode PLMN identity")]
    InvalidPlmnIdentity,
    /// The collection contains the same recognized type more than once.
    #[error("duplicate N1-mode Notify type")]
    DuplicateNotify,
    /// The input collection exceeds the local work bound.
    #[error("N1-mode Notify collection limit exceeded")]
    TooManyNotifies,
    /// The generic Notify body builder rejected the checked value.
    #[error("N1-mode Notify encoding failed")]
    Encoding,
}

/// Interpret one generic Notify without conflating absence and malformed data.
///
/// An unrelated type returns `Ok(None)` without interpreting its fields. A
/// recognized type requires an empty SPI and an exact one-octet inner length.
/// Protocol ID is ignored on receipt when SPI size is zero (RFC 7296 §3.10).
/// The encoder emits the canonical zero protocol ID.
///
/// # Errors
///
/// Returns a value-free error for a malformed recognized Notify.
pub fn decode_ikev2_n1_mode_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2N1ModeNotify>, Ikev2N1ModeNotifyError> {
    if !matches!(
        notify.notify_message_type,
        IKEV2_NOTIFY_N1_MODE_CAPABILITY
            | IKEV2_NOTIFY_N1_MODE_INFORMATION
            | IKEV2_NOTIFY_N1_MODE_S_NSSAI_PLMN_ID
    ) {
        return Ok(None);
    }
    if notify.spi_size != 0 || !notify.spi.is_empty() {
        return Err(Ikev2N1ModeNotifyError::SpiNotEmpty);
    }
    let (&length, value) = notify
        .notification_data
        .split_first()
        .ok_or(Ikev2N1ModeNotifyError::LengthMismatch)?;
    if usize::from(length) != value.len() {
        return Err(Ikev2N1ModeNotifyError::LengthMismatch);
    }
    let typed = match notify.notify_message_type {
        IKEV2_NOTIFY_N1_MODE_CAPABILITY => {
            let &[identity] = value else {
                return Err(Ikev2N1ModeNotifyError::InvalidPduSessionId);
            };
            Ikev2N1ModeNotify::Capability(
                PduSessionId::new(identity)
                    .map_err(|_| Ikev2N1ModeNotifyError::InvalidPduSessionId)?,
            )
        }
        IKEV2_NOTIFY_N1_MODE_INFORMATION => Ikev2N1ModeNotify::Information(
            SnssaiValue::from_bytes(value).map_err(|_| Ikev2N1ModeNotifyError::InvalidSnssai)?,
        ),
        _ => {
            let bytes = value
                .try_into()
                .map_err(|_| Ikev2N1ModeNotifyError::InvalidPlmnIdentity)?;
            Ikev2N1ModeNotify::SnssaiPlmnId(
                PlmnIdentity::from_bytes(bytes)
                    .map_err(|_| Ikev2N1ModeNotifyError::InvalidPlmnIdentity)?,
            )
        }
    };
    Ok(Some(typed))
}

/// Encode a checked N1-mode Notify body, excluding the generic payload header.
///
/// # Errors
///
/// Returns [`Ikev2N1ModeNotifyError::Encoding`] if the generic body builder fails.
pub fn build_ikev2_n1_mode_notify(
    value: Ikev2N1ModeNotify,
) -> Result<Vec<u8>, Ikev2N1ModeNotifyError> {
    encode_notify_payload_build(&value.to_notify_build())
        .map_err(|_| Ikev2N1ModeNotifyError::Encoding)
}

/// Optional N1-mode values from one caller-selected Notify collection.
///
/// The local SDK rule rejects repeated recognized types, even when identical;
/// it does not select a first or last value. This is an ambiguity policy, not a
/// duplicate rule imposed by TS 24.302. A malformed recognized Notify anywhere
/// fails the whole collection; no partial result is returned. Unrelated
/// Notifies remain in the caller's input and count toward the work bound.
/// Cross-field and exchange-specific requirements remain caller policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ikev2N1ModeNotifications {
    capability: Option<PduSessionId>,
    information: Option<SnssaiValue>,
    plmn_id: Option<PlmnIdentity>,
}

impl Ikev2N1ModeNotifications {
    /// Decode a bounded collection without allocating or retaining wire bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed recognized values, duplicate types and oversized input.
    pub fn decode(notifies: &[Ikev2NotifyPayload<'_>]) -> Result<Self, Ikev2N1ModeNotifyError> {
        if notifies.len() > N1_MODE_MAX_NOTIFIES {
            return Err(Ikev2N1ModeNotifyError::TooManyNotifies);
        }
        let mut values = Self::default();
        for notify in notifies {
            let duplicate = match decode_ikev2_n1_mode_notify(*notify)? {
                Some(Ikev2N1ModeNotify::Capability(value)) => {
                    values.capability.replace(value).is_some()
                }
                Some(Ikev2N1ModeNotify::Information(value)) => {
                    values.information.replace(value).is_some()
                }
                Some(Ikev2N1ModeNotify::SnssaiPlmnId(value)) => {
                    values.plmn_id.replace(value).is_some()
                }
                None => false,
            };
            if duplicate {
                return Err(Ikev2N1ModeNotifyError::DuplicateNotify);
            }
        }
        Ok(values)
    }

    /// The capability's identity, if its Notify was present.
    #[must_use]
    pub const fn capability(self) -> Option<PduSessionId> {
        self.capability
    }

    /// The complete slice value, if its Notify was present.
    #[must_use]
    pub const fn information(self) -> Option<SnssaiValue> {
        self.information
    }

    /// The slice's PLMN, if its Notify was present.
    #[must_use]
    pub const fn plmn_id(self) -> Option<PlmnIdentity> {
        self.plmn_id
    }
}
