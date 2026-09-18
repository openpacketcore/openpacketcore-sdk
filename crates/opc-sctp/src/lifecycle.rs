//! Bounded Linux notification metadata. RFC 6525 section 6 defines the event
//! semantics; the native layouts are Linux UAPI, not SCTP wire encoding.
use std::fmt;

#[cfg(any(target_os = "linux", test))]
use crate::{read_i32_ne, read_u16_ne, read_u32_ne, SctpEvent};

/// Maximum explicit stream identifiers retained in one reset notification.
///
/// Larger notifications are rejected, never truncated. An empty list means
/// all streams and does not consume this bound. This is an SDK resource bound,
/// not a protocol limit on negotiated streams.
pub const MAX_RESET_STREAM_IDS: usize = 64;

/// Typed association state from a Linux association-change notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpAssociationState {
    /// The association is established.
    Established,
    /// The association was lost.
    Lost,
    /// The peer restarted the association.
    Restarted,
    /// Shutdown completed.
    ShutdownComplete,
    /// Establishment failed.
    CannotStart,
    /// A state outside the qualified Linux values.
    Unknown,
}

impl SctpAssociationState {
    /// Classify a Linux `sac_state` without granting generation authority.
    #[must_use]
    pub const fn from_kernel(value: u16) -> Self {
        match value {
            0 => Self::Established,
            1 => Self::Lost,
            2 => Self::Restarted,
            3 => Self::ShutdownComplete,
            4 => Self::CannotStart,
            _ => Self::Unknown,
        }
    }
}

/// Outcome reported by a stream/association reconfiguration notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpReconfigurationStatus {
    /// The requested change completed.
    Completed,
    /// The peer denied the request.
    Denied,
    /// The request failed.
    Failed,
}

/// Exact bounded reset-stream list with redacted diagnostics.
///
/// Order and repeated identifiers are preserved. Empty means all streams.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SctpResetStreams {
    values: [u16; MAX_RESET_STREAM_IDS],
    len: u8,
}

impl fmt::Debug for SctpResetStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SctpResetStreams { .. }")
    }
}

impl SctpResetStreams {
    /// Copy at most [`MAX_RESET_STREAM_IDS`] identifiers without allocation.
    /// Returns `None` when the list exceeds the resource bound.
    #[must_use]
    pub fn new(streams: &[u16]) -> Option<Self> {
        if streams.len() > MAX_RESET_STREAM_IDS {
            return None;
        }
        let mut result = Self {
            values: [0; MAX_RESET_STREAM_IDS],
            len: u8::try_from(streams.len()).ok()?,
        };
        result.values[..streams.len()].copy_from_slice(streams);
        Some(result)
    }

    /// Borrow the exact explicit list; empty identifies all streams.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.values[..usize::from(self.len)]
    }

    /// Whether this reset applies to the supplied stream.
    #[must_use]
    pub fn includes(&self, stream: u16) -> bool {
        self.len == 0 || self.as_slice().contains(&stream)
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn is_lifecycle_event(kind: u16) -> bool {
    matches!(kind, 0x8006 | 0x800a | 0x800b | 0x800c)
}

#[cfg(any(target_os = "linux", test))]
fn status(flags: u16) -> Option<SctpReconfigurationStatus> {
    match flags {
        0 => Some(SctpReconfigurationStatus::Completed),
        4 => Some(SctpReconfigurationStatus::Denied),
        8 => Some(SctpReconfigurationStatus::Failed),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn parse(payload: &[u8]) -> Option<SctpEvent> {
    let kind = read_u16_ne(payload, 0)?;
    let flags = read_u16_ne(payload, 2)?;
    let declared = usize::try_from(read_u32_ne(payload, 4)?).ok()?;
    if declared != payload.len() {
        return None;
    }
    match kind {
        0x800a => {
            if !(12..=12 + 2 * MAX_RESET_STREAM_IDS).contains(&declared)
                || (declared - 12) % 2 != 0
                || flags & 3 == 0
            {
                return None;
            }
            let status = status(flags & !3)?;
            let count = (declared - 12) / 2;
            let mut streams = SctpResetStreams {
                values: [0; MAX_RESET_STREAM_IDS],
                len: u8::try_from(count).ok()?,
            };
            for index in 0..count {
                streams.values[index] = read_u16_ne(payload, 12 + 2 * index)?;
            }
            Some(SctpEvent::StreamReset {
                assoc_id: read_i32_ne(payload, 8)?,
                incoming: flags & 1 != 0,
                outgoing: flags & 2 != 0,
                status,
                streams,
            })
        }
        0x800b if declared == 20 => Some(SctpEvent::AssociationReset {
            assoc_id: read_i32_ne(payload, 8)?,
            status: status(flags)?,
            local_tsn: read_u32_ne(payload, 12)?,
            remote_tsn: read_u32_ne(payload, 16)?,
        }),
        0x800c if declared == 16 => Some(SctpEvent::StreamChange {
            assoc_id: read_i32_ne(payload, 8)?,
            status: status(flags)?,
            inbound_streams: read_u16_ne(payload, 12)?,
            outbound_streams: read_u16_ne(payload, 14)?,
        }),
        0x8006 if declared == 24 && flags == 0 && read_u32_ne(payload, 8)? == 0 => {
            Some(SctpEvent::PartialDeliveryAborted {
                assoc_id: read_i32_ne(payload, 12)?,
                stream_id: read_u32_ne(payload, 16)?,
                sequence: read_u32_ne(payload, 20)?,
            })
        }
        _ => None,
    }
}
