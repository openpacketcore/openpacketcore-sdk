//! S2b-oriented GTPv2-C scaffold constants.
//!
//! The constants in this module identify the message types planned for the
//! S2b subset. They do not by themselves provide typed procedure validation.
//!
//! @spec 3GPP TS29274 R18 S2b procedure use
//! @req REQ-3GPP-TS29274-R18-S2B-SCAFFOLD-001

/// Create Session Request message type.
pub const CREATE_SESSION_REQUEST: u8 = 32;

/// Create Session Response message type.
pub const CREATE_SESSION_RESPONSE: u8 = 33;

/// Modify Bearer Request message type.
pub const MODIFY_BEARER_REQUEST: u8 = 34;

/// Modify Bearer Response message type.
pub const MODIFY_BEARER_RESPONSE: u8 = 35;

/// Delete Session Request message type.
pub const DELETE_SESSION_REQUEST: u8 = 36;

/// Delete Session Response message type.
pub const DELETE_SESSION_RESPONSE: u8 = 37;

/// S2b procedure markers planned for typed support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// Create Session request/response exchange.
    CreateSession,
    /// Modify Bearer request/response exchange.
    ModifyBearer,
    /// Delete Session request/response exchange.
    DeleteSession,
}

impl Procedure {
    /// Return the GTPv2-C request message type for this procedure.
    pub const fn request_type(self) -> u8 {
        match self {
            Self::CreateSession => CREATE_SESSION_REQUEST,
            Self::ModifyBearer => MODIFY_BEARER_REQUEST,
            Self::DeleteSession => DELETE_SESSION_REQUEST,
        }
    }

    /// Return the GTPv2-C response message type for this procedure.
    pub const fn response_type(self) -> u8 {
        match self {
            Self::CreateSession => CREATE_SESSION_RESPONSE,
            Self::ModifyBearer => MODIFY_BEARER_RESPONSE,
            Self::DeleteSession => DELETE_SESSION_RESPONSE,
        }
    }
}

/// Return `true` when `message_type` belongs to the scaffolded S2b procedure
/// set for this crate.
pub const fn is_scaffolded_s2b_message_type(message_type: u8) -> bool {
    matches!(
        message_type,
        CREATE_SESSION_REQUEST
            | CREATE_SESSION_RESPONSE
            | MODIFY_BEARER_REQUEST
            | MODIFY_BEARER_RESPONSE
            | DELETE_SESSION_REQUEST
            | DELETE_SESSION_RESPONSE
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procedure_maps_request_and_response_types() {
        assert_eq!(
            Procedure::CreateSession.request_type(),
            CREATE_SESSION_REQUEST
        );
        assert_eq!(
            Procedure::CreateSession.response_type(),
            CREATE_SESSION_RESPONSE
        );
        assert!(is_scaffolded_s2b_message_type(DELETE_SESSION_RESPONSE));
        assert!(!is_scaffolded_s2b_message_type(1));
    }
}
