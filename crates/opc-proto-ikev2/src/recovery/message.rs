use bytes::Bytes;

use super::Ikev2WindowError as Error;

pub(super) const MAX_FRAGMENTS: usize = 256;
pub(super) const MAX_CLEARTEXT: usize = 65_536;
pub(super) const MAX_WIRE: usize = MAX_CLEARTEXT + MAX_FRAGMENTS * 128;

/// Exact protected packets for one ordinary exchange message, in fragment order.
///
/// These are persistence inputs, not authentication or transmission authority.
/// Restore authenticates every packet and checks the complete message. Never
/// concatenate the packets into one UDP datagram or persist only the first one.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ProtectedMessage {
    packets: Vec<Bytes>,
}

impl Ikev2ProtectedMessage {
    /// Rebuild a bounded packet collection from one trusted atomic record.
    /// # Errors
    /// Rejects empty packets/collections, too many fragments, or excessive size.
    pub fn from_persisted(packets: Vec<Bytes>) -> Result<Self, Error> {
        if packets.is_empty()
            || packets.len() > MAX_FRAGMENTS
            || packets.iter().any(Bytes::is_empty)
            || packets
                .iter()
                .try_fold(0usize, |sum, packet| sum.checked_add(packet.len()))
                .is_none_or(|size| size > MAX_WIRE)
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self { packets })
    }

    pub(super) fn single(packet: Bytes) -> Self {
        Self {
            packets: vec![packet],
        }
    }

    /// Each element is a separate complete IKE packet, without transport framing.
    pub fn packets(&self) -> &[Bytes] {
        &self.packets
    }

    /// A single-packet message, for consumers that deliberately require that shape.
    /// # Errors
    /// A fragmented collection cannot be mistaken for its first packet.
    pub fn single_packet(&self) -> Result<&[u8], Error> {
        match self.packets.as_slice() {
            [packet] => Ok(packet),
            _ => Err(Error::UnsupportedShape),
        }
    }
}
