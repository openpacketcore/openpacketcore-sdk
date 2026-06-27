#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! GTPv2-C protocol crate for OpenPacketCore S2b work.
//!
//! This crate provides a bounded GTPv2-C codec surface for S2b work. It keeps
//! the raw-preserving common-header and TLIV IE layer for forwarding paths, and
//! adds an experimental typed subset for Echo plus Create/Modify/Delete/Update
//! Session-oriented S2b message views. Unsupported IEs remain raw-preserved.
//!
//! @spec 3GPP TS29274 R18
//! @req REQ-3GPP-TS29274-R18-SCAFFOLD-001
//! @conformance s2b-subset — see CONFORMANCE.md

pub mod header;
pub mod ie;
pub mod message;
pub mod s2b;

pub use header::{decode_header, encode_header, Header, GTPV2C_VERSION};
pub use ie::{
    decode_typed_ie_sequence, validate_ie_region, AccessPointName, AggregateMaximumBitRate,
    ApnRestriction, BearerContext, Cause, CauseValue, EpsBearerId, FullyQualifiedTeid, OwnedRawIe,
    PdnAddressAllocation, PdnType, PdnTypeValue, PlmnId, RatType, RatTypeValue, RawIe,
    RawIeIterator, Recovery, SelectionMode, SelectionModeValue, ServingNetwork, TbcdDigits,
    TypedIe, TypedIeValue, IE_HEADER_LEN, IE_TYPE_AMBR, IE_TYPE_APN, IE_TYPE_APN_RESTRICTION,
    IE_TYPE_BEARER_CONTEXT, IE_TYPE_CAUSE, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI, IE_TYPE_MEI,
    IE_TYPE_MSISDN, IE_TYPE_PAA, IE_TYPE_PCO, IE_TYPE_PDN_TYPE, IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY,
    IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK,
};
pub use message::{Message, OwnedMessage};
pub use s2b::{
    is_s2b_message_type, is_scaffolded_s2b_message_type, MessageDirection, Procedure, S2bMessage,
    S2bProcedureMessage, CREATE_SESSION_REQUEST, CREATE_SESSION_RESPONSE, DELETE_SESSION_REQUEST,
    DELETE_SESSION_RESPONSE, ECHO_REQUEST, ECHO_RESPONSE, MODIFY_BEARER_REQUEST,
    MODIFY_BEARER_RESPONSE, UPDATE_BEARER_REQUEST, UPDATE_BEARER_RESPONSE,
};
