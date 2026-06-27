//! Transport-neutral Diameter peer helper skeletons.
//!
//! This module names base peer procedures and command-code mappings without
//! owning TCP/SCTP connections, realm routing, watchdog thresholds, failover,
//! or deployment readiness policy.

use crate::base::{
    self, COMMAND_CAPABILITIES_EXCHANGE, COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER,
};
use crate::dictionary::{CommandKind, Dictionary, DictionarySet};
use crate::{CommandCode, CommandFlags, Header};

static PEER_DICTIONARY_REFS: [&Dictionary; 1] = [base::dictionary()];

/// Dictionary set used by the peer-helper skeleton.
pub static PEER_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&PEER_DICTIONARY_REFS);

/// Diameter base peer procedures named by RFC 6733.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerProcedure {
    /// Capabilities exchange procedure.
    CapabilitiesExchange,
    /// Device watchdog procedure.
    DeviceWatchdog,
    /// Disconnect peer procedure.
    DisconnectPeer,
}

impl PeerProcedure {
    /// Return the Diameter command code for this peer procedure.
    pub const fn command_code(self) -> CommandCode {
        match self {
            Self::CapabilitiesExchange => COMMAND_CAPABILITIES_EXCHANGE,
            Self::DeviceWatchdog => COMMAND_DEVICE_WATCHDOG,
            Self::DisconnectPeer => COMMAND_DISCONNECT_PEER,
        }
    }

    /// Return the request command dictionary name for this procedure.
    pub const fn request_name(self) -> &'static str {
        match self {
            Self::CapabilitiesExchange => "Capabilities-Exchange-Request",
            Self::DeviceWatchdog => "Device-Watchdog-Request",
            Self::DisconnectPeer => "Disconnect-Peer-Request",
        }
    }

    /// Return the answer command dictionary name for this procedure.
    pub const fn answer_name(self) -> &'static str {
        match self {
            Self::CapabilitiesExchange => "Capabilities-Exchange-Answer",
            Self::DeviceWatchdog => "Device-Watchdog-Answer",
            Self::DisconnectPeer => "Disconnect-Peer-Answer",
        }
    }
}

/// Return the peer procedure for a base command code, if one is known.
pub const fn procedure_for_command(command_code: CommandCode) -> Option<PeerProcedure> {
    if command_code.get() == COMMAND_CAPABILITIES_EXCHANGE.get() {
        Some(PeerProcedure::CapabilitiesExchange)
    } else if command_code.get() == COMMAND_DEVICE_WATCHDOG.get() {
        Some(PeerProcedure::DeviceWatchdog)
    } else if command_code.get() == COMMAND_DISCONNECT_PEER.get() {
        Some(PeerProcedure::DisconnectPeer)
    } else {
        None
    }
}

/// Return the peer procedure and request/answer role for a decoded header.
pub fn classify_header(header: &Header) -> Option<(PeerProcedure, CommandKind)> {
    procedure_for_command(header.command_code)
        .map(|procedure| (procedure, header.flags.command_kind()))
}

/// Build command flags for a peer request.
pub const fn peer_request_flags(procedure: PeerProcedure) -> CommandFlags {
    match procedure {
        PeerProcedure::CapabilitiesExchange
        | PeerProcedure::DeviceWatchdog
        | PeerProcedure::DisconnectPeer => CommandFlags::request(false),
    }
}

/// Build command flags for a peer answer.
pub const fn peer_answer_flags(procedure: PeerProcedure, error: bool) -> CommandFlags {
    match procedure {
        PeerProcedure::CapabilitiesExchange
        | PeerProcedure::DeviceWatchdog
        | PeerProcedure::DisconnectPeer => CommandFlags::answer(false, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApplicationId, Header};

    #[test]
    fn classifies_device_watchdog_answer() {
        let header = Header::new(
            peer_answer_flags(PeerProcedure::DeviceWatchdog, false),
            COMMAND_DEVICE_WATCHDOG,
            ApplicationId::new(0),
            1,
            2,
        );
        assert_eq!(
            classify_header(&header),
            Some((PeerProcedure::DeviceWatchdog, CommandKind::Answer))
        );
    }
}
