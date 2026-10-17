//! Directional N1-mode containers in ordinary Additional PCO (APCO).
//!
//! The request codec interprets only MS-to-network container `0x001a`; the
//! response codec interprets only network-to-MS container `0x001b`. Unknown and
//! opposite-direction identifiers are skipped without interpreting their value,
//! after checking their framing. Append operations preserve all existing bytes.
//!
//! These codecs handle the ordinary PCO format carried by APCO type 163,
//! instance 0 at S2b Create Session message top level. Large APCO, standalone
//! ePCO, and NAS messages are outside this contract. Decoding establishes wire
//! validity only: negotiation, slice authorization and session mapping remain
//! caller responsibilities.
//!
//! @spec 3GPP TS24008 V20.0.0 10.5.6.3
//! @spec 3GPP TS29274 V18.8.0 7.2.1, 7.2.2, 8.12, 8.94
//! @conformance boundary-only

pub use opc_types::n1_mode::{PduSessionId, PlmnIdentity, SnssaiValue};

pub use crate::IndicationFlag;
use crate::{
    AdditionalProtocolConfigurationOptions, MessageDirection, MessageType, Procedure,
    S2bProcedureMessage, TypedIe, TypedIeValue,
};

/// MS-to-network PDU session identity container identifier.
pub const APCO_CONTAINER_PDU_SESSION_ID: u16 = 0x001a;
/// Network-to-MS S-NSSAI and associated PLMN container identifier.
pub const APCO_CONTAINER_SNSSAI: u16 = 0x001b;
/// Local work bound, counting all protocol and container units.
pub const N1_MODE_APCO_MAX_CONTAINERS: usize = 64;
/// Ordinary PCO contents limit, excluding its NAS IEI and length octets.
///
/// TS 24.008 §10.5.6.3 limits the complete PCO IE to 253 octets. APCO carries
/// those contents beginning at octet 3, hence at most 251 octets here.
pub const N1_MODE_APCO_MAX_CONTENTS_LEN: usize = 251;

/// A value-free ordinary APCO framing or N1-mode value error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum N1ModeApcoError {
    /// The S2b procedure, direction or header type does not match the codec.
    #[error("N1-mode APCO requires the matching S2b Create Session message")]
    WrongS2bMessage,
    /// The PCO contents are empty or the extension bit is not set.
    #[error("invalid ordinary APCO header")]
    InvalidHeader,
    /// A protocol/container identifier, length or value is truncated.
    #[error("truncated APCO unit")]
    TruncatedContainer,
    /// The direction's N1 container occurs more than once.
    #[error("duplicate N1-mode APCO container")]
    DuplicateContainer,
    /// The PDU session identity length or code is invalid.
    #[error("invalid APCO PDU session identity")]
    InvalidPduSessionId,
    /// The S-NSSAI value is incomplete or has a reserved length.
    #[error("invalid APCO S-NSSAI")]
    InvalidSnssai,
    /// The PLMN's digit coding is invalid.
    #[error("invalid APCO PLMN identity")]
    InvalidPlmnIdentity,
    /// All units together exceed the local work bound.
    #[error("APCO unit count limit exceeded")]
    TooManyContainers,
    /// The ordinary PCO contents bound is exceeded.
    #[error("ordinary APCO contents length limit exceeded")]
    ContentsTooLong,
}

/// Checked PDU session identity sent from MS to network in APCO.
///
/// Formatting redacts the identity. A zero identity remains the standardized
/// unassigned value; this type does not infer N1-mode enablement from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N1ModeApcoRequest {
    pdu_session_id: PduSessionId,
}

impl N1ModeApcoRequest {
    /// Construct from a checked wire identity.
    #[must_use]
    pub const fn new(pdu_session_id: PduSessionId) -> Self {
        Self { pdu_session_id }
    }

    /// Explicitly expose the identity.
    #[must_use]
    pub const fn pdu_session_id(self) -> PduSessionId {
        self.pdu_session_id
    }

    /// Encode canonical ordinary APCO containing only the N1 request unit.
    #[must_use]
    pub fn encode_apco(self) -> AdditionalProtocolConfigurationOptions {
        encode_container(
            APCO_CONTAINER_PDU_SESSION_ID,
            &[self.pdu_session_id.value()],
        )
    }

    /// Build an APCO type 163, instance 0 IE for message top-level placement.
    #[must_use]
    pub fn to_s2b_ie(self) -> TypedIe<'static> {
        s2b_ie(self.encode_apco())
    }

    /// Read N1 data from an S2b Create Session Request's top-level APCO instance 0.
    ///
    /// The first matching IE still present in `view` supplies the value. To
    /// preserve the first occurrence on the wire, decode with `S2bMessage::decode`
    /// and `ValidationLevel::ProcedureAware` (which forces `DuplicateIePolicy::First`),
    /// or select `First` explicitly at another validation level. `Reject` at
    /// another level rejects duplicates before projection. The default context
    /// and `Strict` with the default `Last` policy have already discarded earlier
    /// occurrences; this helper cannot recover them.
    ///
    /// PCO, grouped APCO and other instances are ignored. Call this after ordinary
    /// S2b message validation; it does not validate unrelated mandatory IEs or
    /// establish authorization.
    ///
    /// # Errors
    ///
    /// Rejects an inconsistent procedure/direction/header or malformed N1 APCO.
    pub fn from_s2b(view: &S2bProcedureMessage<'_>) -> Result<Option<Self>, N1ModeApcoError> {
        match s2b_apco(view, Direction::MsToNetwork)? {
            Some(apco) => Self::decode(apco),
            None => Ok(None),
        }
    }

    /// Decode a complete MS-to-network ordinary APCO contents region.
    ///
    /// Returns `Ok(None)` if the direction's N1 container is absent. An
    /// identical duplicate is rejected just like a conflicting duplicate;
    /// this is a local SDK ambiguity rule. Unknown containers are retained in
    /// the caller's APCO value, not returned as N1 data.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing, bounds, duplicate N1 containers or invalid IDs.
    pub fn decode(
        apco: &AdditionalProtocolConfigurationOptions,
    ) -> Result<Option<Self>, N1ModeApcoError> {
        let scan = scan(apco, Direction::MsToNetwork, APCO_CONTAINER_PDU_SESSION_ID)?;
        scan.value
            .map(|value| {
                let &[identity] = value else {
                    return Err(N1ModeApcoError::InvalidPduSessionId);
                };
                PduSessionId::new(identity)
                    .map(Self::new)
                    .map_err(|_| N1ModeApcoError::InvalidPduSessionId)
            })
            .transpose()
    }

    /// Append to existing MS-to-network APCO without changing any input byte.
    ///
    /// # Errors
    ///
    /// Rejects malformed existing framing, an existing N1 request container,
    /// or a result that would exceed either ordinary APCO bound.
    pub fn append_to(
        self,
        apco: &AdditionalProtocolConfigurationOptions,
    ) -> Result<AdditionalProtocolConfigurationOptions, N1ModeApcoError> {
        append(
            apco,
            Direction::MsToNetwork,
            APCO_CONTAINER_PDU_SESSION_ID,
            self.encode_apco(),
        )
    }
}

/// Checked network-to-MS S-NSSAI value together with its associated PLMN.
///
/// Both fields are required by TS 24.008 §10.5.6.3 and both are redacted when
/// formatted. The S-NSSAI has no nested NAS IEI or length octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N1ModeApcoResponse {
    snssai: SnssaiValue,
    plmn_id: PlmnIdentity,
}

impl N1ModeApcoResponse {
    /// Construct from a complete slice value and its PLMN identity.
    #[must_use]
    pub const fn new(snssai: SnssaiValue, plmn_id: PlmnIdentity) -> Self {
        Self { snssai, plmn_id }
    }

    /// Explicitly expose the complete slice value.
    #[must_use]
    pub const fn snssai(self) -> SnssaiValue {
        self.snssai
    }

    /// Explicitly expose the slice's PLMN.
    #[must_use]
    pub const fn plmn_id(self) -> PlmnIdentity {
        self.plmn_id
    }

    /// Encode canonical ordinary APCO containing only the N1 response unit.
    #[must_use]
    pub fn encode_apco(self) -> AdditionalProtocolConfigurationOptions {
        let mut value = Vec::with_capacity(self.snssai.as_bytes().len() + 3);
        value.extend_from_slice(self.snssai.as_bytes());
        value.extend_from_slice(self.plmn_id.as_bytes());
        encode_container(APCO_CONTAINER_SNSSAI, &value)
    }

    /// Build an APCO type 163, instance 0 IE for message top-level placement.
    #[must_use]
    pub fn to_s2b_ie(self) -> TypedIe<'static> {
        s2b_ie(self.encode_apco())
    }

    /// Read N1 data from an S2b Create Session Response's top-level APCO instance 0.
    ///
    /// The first matching IE still present in `view` supplies the value. To
    /// preserve the first occurrence on the wire, decode with `S2bMessage::decode`
    /// and `ValidationLevel::ProcedureAware` (which forces `DuplicateIePolicy::First`),
    /// or select `First` explicitly at another validation level. `Reject` at
    /// another level rejects duplicates before projection. The default context
    /// and `Strict` with the default `Last` policy have already discarded earlier
    /// occurrences; this helper cannot recover them.
    ///
    /// PCO, grouped APCO and other instances are ignored. Call this after ordinary
    /// S2b message validation. A value or error neither changes Cause nor establishes
    /// session acceptance or rejection; that decision remains with the caller.
    ///
    /// # Errors
    ///
    /// Rejects an inconsistent procedure/direction/header or malformed N1 APCO.
    pub fn from_s2b(view: &S2bProcedureMessage<'_>) -> Result<Option<Self>, N1ModeApcoError> {
        match s2b_apco(view, Direction::NetworkToMs)? {
            Some(apco) => Self::decode(apco),
            None => Ok(None),
        }
    }

    /// Decode a complete network-to-MS ordinary APCO contents region.
    ///
    /// Returns `Ok(None)` if the direction's N1 container is absent. Repeated
    /// N1 response containers, including identical copies, fail under the
    /// local SDK ambiguity rule. No partial value is returned on error.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing, bounds, duplicates, slice shapes or PLMN digits.
    pub fn decode(
        apco: &AdditionalProtocolConfigurationOptions,
    ) -> Result<Option<Self>, N1ModeApcoError> {
        let scan = scan(apco, Direction::NetworkToMs, APCO_CONTAINER_SNSSAI)?;
        scan.value
            .map(|value| {
                let slice_len = value
                    .len()
                    .checked_sub(3)
                    .ok_or(N1ModeApcoError::InvalidSnssai)?;
                let (slice, plmn) = value.split_at(slice_len);
                let snssai =
                    SnssaiValue::from_bytes(slice).map_err(|_| N1ModeApcoError::InvalidSnssai)?;
                let bytes = plmn
                    .try_into()
                    .map_err(|_| N1ModeApcoError::InvalidPlmnIdentity)?;
                let plmn_id = PlmnIdentity::from_bytes(bytes)
                    .map_err(|_| N1ModeApcoError::InvalidPlmnIdentity)?;
                Ok(Self::new(snssai, plmn_id))
            })
            .transpose()
    }

    /// Append to existing network-to-MS APCO while preserving all input bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed existing framing, an existing N1 response container,
    /// or a result that would exceed either ordinary APCO bound.
    pub fn append_to(
        self,
        apco: &AdditionalProtocolConfigurationOptions,
    ) -> Result<AdditionalProtocolConfigurationOptions, N1ModeApcoError> {
        append(
            apco,
            Direction::NetworkToMs,
            APCO_CONTAINER_SNSSAI,
            self.encode_apco(),
        )
    }
}

#[derive(Clone, Copy)]
enum Direction {
    MsToNetwork,
    NetworkToMs,
}

impl Direction {
    fn has_two_octet_length(self, identifier: u16) -> bool {
        // TS 24.008 V20.0.0 §10.5.6.3: length fields are direction-specific.
        matches!(identifier, 0x0041 | 0x0051 | 0x0056 | 0x0061)
            || (matches!(self, Self::NetworkToMs)
                && matches!(identifier, 0x0023 | 0x0024 | 0x0030 | 0x0031 | 0x0032))
    }
}

struct Scan<'a> {
    value: Option<&'a [u8]>,
    count: usize,
}

fn scan(
    apco: &AdditionalProtocolConfigurationOptions,
    direction: Direction,
    wanted: u16,
) -> Result<Scan<'_>, N1ModeApcoError> {
    if apco.value.len() > N1_MODE_APCO_MAX_CONTENTS_LEN {
        return Err(N1ModeApcoError::ContentsTooLong);
    }
    let (&header, mut remaining) = apco
        .value
        .split_first()
        .ok_or(N1ModeApcoError::InvalidHeader)?;
    // Configuration protocol codes fall back to PPP; spare bits are ignored.
    if header & 0x80 == 0 {
        return Err(N1ModeApcoError::InvalidHeader);
    }
    let mut result = Scan {
        value: None,
        count: 0,
    };
    while !remaining.is_empty() {
        if result.count == N1_MODE_APCO_MAX_CONTAINERS {
            return Err(N1ModeApcoError::TooManyContainers);
        }
        if remaining.len() < 3 {
            return Err(N1ModeApcoError::TruncatedContainer);
        }
        let identifier = u16::from_be_bytes([remaining[0], remaining[1]]);
        let (header_len, value_len) = if direction.has_two_octet_length(identifier) {
            let low = *remaining
                .get(3)
                .ok_or(N1ModeApcoError::TruncatedContainer)?;
            (4, usize::from(u16::from_be_bytes([remaining[2], low])))
        } else {
            (3, usize::from(remaining[2]))
        };
        let end = header_len + value_len;
        let value = remaining
            .get(header_len..end)
            .ok_or(N1ModeApcoError::TruncatedContainer)?;
        if identifier == wanted && result.value.replace(value).is_some() {
            return Err(N1ModeApcoError::DuplicateContainer);
        }
        result.count += 1;
        remaining = &remaining[end..];
    }
    Ok(result)
}

fn encode_container(identifier: u16, value: &[u8]) -> AdditionalProtocolConfigurationOptions {
    // Private callers supply only checked N1 values, at most eleven octets.
    let mut contents = Vec::with_capacity(4 + value.len());
    contents.push(0x80);
    contents.extend_from_slice(&identifier.to_be_bytes());
    contents.push(value.len() as u8);
    contents.extend_from_slice(value);
    AdditionalProtocolConfigurationOptions { value: contents }
}

fn s2b_ie(apco: AdditionalProtocolConfigurationOptions) -> TypedIe<'static> {
    TypedIe {
        instance: 0,
        value: TypedIeValue::AdditionalProtocolConfigurationOptions(apco),
    }
}

fn s2b_apco<'a>(
    view: &'a S2bProcedureMessage<'_>,
    direction: Direction,
) -> Result<Option<&'a AdditionalProtocolConfigurationOptions>, N1ModeApcoError> {
    let (message_type, message_direction) = match direction {
        Direction::MsToNetwork => (MessageType::CreateSessionRequest, MessageDirection::Request),
        Direction::NetworkToMs => (
            MessageType::CreateSessionResponse,
            MessageDirection::Response,
        ),
    };
    if view.procedure != Procedure::CreateSession
        || view.direction != message_direction
        || view.message_type() != message_type
    {
        return Err(N1ModeApcoError::WrongS2bMessage);
    }
    Ok(view.ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::AdditionalProtocolConfigurationOptions(apco) if ie.instance == 0 => {
            Some(apco)
        }
        _ => None,
    }))
}

fn append(
    apco: &AdditionalProtocolConfigurationOptions,
    direction: Direction,
    identifier: u16,
    encoded: AdditionalProtocolConfigurationOptions,
) -> Result<AdditionalProtocolConfigurationOptions, N1ModeApcoError> {
    let scan = scan(apco, direction, identifier)?;
    if scan.value.is_some() {
        return Err(N1ModeApcoError::DuplicateContainer);
    }
    if scan.count == N1_MODE_APCO_MAX_CONTAINERS {
        return Err(N1ModeApcoError::TooManyContainers);
    }
    let unit = &encoded.value[1..];
    if apco.value.len() + unit.len() > N1_MODE_APCO_MAX_CONTENTS_LEN {
        return Err(N1ModeApcoError::ContentsTooLong);
    }
    let mut value = Vec::with_capacity(apco.value.len() + unit.len());
    value.extend_from_slice(&apco.value);
    value.extend_from_slice(unit);
    Ok(AdditionalProtocolConfigurationOptions { value })
}
