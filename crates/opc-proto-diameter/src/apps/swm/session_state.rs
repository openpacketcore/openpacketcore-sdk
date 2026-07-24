//! RFC 6733 authorization-session state retained from SWm answers.
//!
//! This module keeps opaque `Class` values and authorization-session routing
//! directives behind redaction-safe typed boundaries. It deliberately does
//! not own a session map, select peers, schedule retries, or decide when a
//! session must be terminated.

use bytes::BytesMut;
use opc_protocol::{DecodeError, DecodeErrorCode, EncodeContext, EncodeError, SpecRef};
use std::{error::Error, fmt};

use super::{
    builder_helpers, lifecycle, Redacted, SwmAdditionalAvp, SwmDiameterEapAnswer, SwmReAuthRequest,
    SwmSessionTerminationRequest,
};
use crate::avp::dictionary::Sensitive;
use crate::base;
use crate::dictionary::AvpKey;
use crate::{AvpFlags, AvpHeader, RawAvp};

/// Maximum number of retained `Class` AVPs in one authorization session.
///
/// This matches the typed SWm additional-AVP boundary and independently caps
/// repeated opaque values before they enter consumer-owned session storage.
pub const MAX_SWM_CLASS_AVPS: usize = 128;

/// Maximum aggregate number of opaque `Class` value octets retained per
/// authorization session.
///
/// RFC 6733 recommends that clients be prepared to store at least 4096 octets
/// of Class data. The SDK uses that interoperability target as its explicit
/// bounded typed projection.
pub const MAX_SWM_CLASS_VALUE_BYTES: usize = 4096;

/// Stable reason for a typed SWm authorization-session state failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwmSessionStateErrorCode {
    /// More than [`MAX_SWM_CLASS_AVPS`] values were supplied.
    TooManyClassAvps,
    /// Aggregate opaque Class data exceeded [`MAX_SWM_CLASS_VALUE_BYTES`].
    ClassValueBytesExceeded,
    /// A Class AVP did not use the canonical RFC 6733 base header.
    InvalidClassAvp,
    /// Replacing Class values would exceed a request's additional-AVP bound.
    AdditionalAvpCapacityExceeded,
    /// A routing directive was applied to a different Diameter session.
    SessionMismatch,
    /// Session-Server-Failover accompanied a binding that prohibits every
    /// defined Destination-Host use.
    ContradictoryRoutingDirectives,
    /// The retained failover directive does not permit a hostless retry.
    DestinationHostRemovalProhibited,
}

/// Redaction-safe typed SWm authorization-session state failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmSessionStateError {
    code: SwmSessionStateErrorCode,
}

impl SwmSessionStateError {
    const fn new(code: SwmSessionStateErrorCode) -> Self {
        Self { code }
    }

    /// Return the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> SwmSessionStateErrorCode {
        self.code
    }

    /// Return a value-free label suitable for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.code {
            SwmSessionStateErrorCode::TooManyClassAvps => "swm_class_avp_count_exceeded",
            SwmSessionStateErrorCode::ClassValueBytesExceeded => "swm_class_value_bytes_exceeded",
            SwmSessionStateErrorCode::InvalidClassAvp => "swm_class_avp_invalid",
            SwmSessionStateErrorCode::AdditionalAvpCapacityExceeded => {
                "swm_session_state_additional_avp_capacity_exceeded"
            }
            SwmSessionStateErrorCode::SessionMismatch => "swm_session_routing_session_mismatch",
            SwmSessionStateErrorCode::ContradictoryRoutingDirectives => {
                "swm_session_routing_directives_contradict"
            }
            SwmSessionStateErrorCode::DestinationHostRemovalProhibited => {
                "swm_session_routing_host_removal_prohibited"
            }
        }
    }
}

impl fmt::Display for SwmSessionStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmSessionStateError {}

/// Ordered, bounded, opaque RFC 6733 `Class` AVPs.
///
/// Values and raw headers are private and never appear in `Debug` or
/// `Display`. Use [`Self::try_from_values`] at a trusted origination boundary,
/// or obtain a replacement through a correlated authorization answer. The
/// clone/move helpers replace any existing IETF Class AVPs in a typed request
/// while preserving every other additional AVP.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SwmClassAvps {
    avps: Vec<SwmAdditionalAvp>,
    aggregate_value_bytes: usize,
}

impl SwmClassAvps {
    /// Construct an ordered Class set from trusted opaque values.
    ///
    /// Empty values are valid and retain their occurrence and order. The
    /// resulting AVPs use the mandatory, non-vendor RFC 6733 Class header.
    pub fn try_from_values(values: Vec<Vec<u8>>) -> Result<Self, SwmSessionStateError> {
        let mut class_avps = Self::default();
        for value in values {
            class_avps.push_originated(value)?;
        }
        Ok(class_avps)
    }

    /// Return the number of retained Class occurrences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.avps.len()
    }

    /// Return whether this collection contains no Class occurrence.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.avps.is_empty()
    }

    /// Return the aggregate opaque value length without exposing values.
    #[must_use]
    pub const fn aggregate_value_bytes(&self) -> usize {
        self.aggregate_value_bytes
    }

    /// Clone this Class set into a typed STR, replacing its prior Class AVPs.
    pub fn clone_into_session_termination_request(
        &self,
        request: &mut SwmSessionTerminationRequest,
    ) -> Result<(), SwmSessionStateError> {
        replace_class_avps(&mut request.additional_avps, self.avps.clone())
    }

    /// Move this Class set into a typed STR, replacing its prior Class AVPs.
    pub fn move_into_session_termination_request(
        self,
        request: &mut SwmSessionTerminationRequest,
    ) -> Result<(), SwmSessionStateError> {
        replace_class_avps(&mut request.additional_avps, self.avps)
    }

    /// Clone this Class set into a typed RAR, replacing its prior Class AVPs.
    pub fn clone_into_re_auth_request(
        &self,
        request: &mut SwmReAuthRequest,
    ) -> Result<(), SwmSessionStateError> {
        replace_class_avps(&mut request.additional_avps, self.avps.clone())
    }

    /// Move this Class set into a typed RAR, replacing its prior Class AVPs.
    pub fn move_into_re_auth_request(
        self,
        request: &mut SwmReAuthRequest,
    ) -> Result<(), SwmSessionStateError> {
        replace_class_avps(&mut request.additional_avps, self.avps)
    }

    fn push_originated(&mut self, value: Vec<u8>) -> Result<(), SwmSessionStateError> {
        self.check_next_value(value.len())?;
        let avp = SwmAdditionalAvp::new(
            AvpHeader::ietf(base::AVP_CLASS, true),
            value,
            EncodeContext::default(),
        )
        .map_err(|_| SwmSessionStateError::new(SwmSessionStateErrorCode::InvalidClassAvp))?;
        self.aggregate_value_bytes = self
            .aggregate_value_bytes
            .checked_add(avp.value_len())
            .ok_or_else(|| {
                SwmSessionStateError::new(SwmSessionStateErrorCode::ClassValueBytesExceeded)
            })?;
        self.avps.push(avp);
        Ok(())
    }

    pub(super) fn push_received(
        &mut self,
        avp: &RawAvp<'_>,
        offset: usize,
    ) -> Result<(), DecodeError> {
        lifecycle::validate_base_definition(avp, offset)?;
        self.check_next_value(avp.value.len())
            .map_err(|error| class_decode_error(error, offset))?;
        self.aggregate_value_bytes = self
            .aggregate_value_bytes
            .checked_add(avp.value.len())
            .ok_or_else(|| {
                DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                    .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.20"))
            })?;
        self.avps.push(SwmAdditionalAvp::from_raw_exact(avp));
        Ok(())
    }

    fn check_next_value(&self, value_len: usize) -> Result<(), SwmSessionStateError> {
        if self.avps.len() >= MAX_SWM_CLASS_AVPS {
            return Err(SwmSessionStateError::new(
                SwmSessionStateErrorCode::TooManyClassAvps,
            ));
        }
        let next_bytes = self
            .aggregate_value_bytes
            .checked_add(value_len)
            .ok_or_else(|| {
                SwmSessionStateError::new(SwmSessionStateErrorCode::ClassValueBytesExceeded)
            })?;
        if next_bytes > MAX_SWM_CLASS_VALUE_BYTES {
            return Err(SwmSessionStateError::new(
                SwmSessionStateErrorCode::ClassValueBytesExceeded,
            ));
        }
        Ok(())
    }

    pub(super) fn append_to(
        &self,
        dst: &mut BytesMut,
        ctx: EncodeContext,
    ) -> Result<(), EncodeError> {
        for avp in &self.avps {
            avp.append_to(dst, ctx)?;
        }
        Ok(())
    }

    fn from_additional_avps(
        additional_avps: &[SwmAdditionalAvp],
    ) -> Result<Self, SwmSessionStateError> {
        let mut class_avps = Self::default();
        for avp in additional_avps
            .iter()
            .filter(|avp| avp.header().key() == AvpKey::ietf(base::AVP_CLASS))
        {
            if avp.header().flags != AvpFlags::new(false, true, false)
                || avp.header().vendor_id.is_some()
            {
                return Err(SwmSessionStateError::new(
                    SwmSessionStateErrorCode::InvalidClassAvp,
                ));
            }
            class_avps.check_next_value(avp.value_len())?;
            class_avps.aggregate_value_bytes = class_avps
                .aggregate_value_bytes
                .checked_add(avp.value_len())
                .ok_or_else(|| {
                    SwmSessionStateError::new(SwmSessionStateErrorCode::ClassValueBytesExceeded)
                })?;
            class_avps.avps.push(avp.clone());
        }
        Ok(class_avps)
    }
}

impl fmt::Debug for SwmClassAvps {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmClassAvps")
            .field("count", &self.avps.len())
            .field("aggregate_value_bytes", &self.aggregate_value_bytes)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for SwmClassAvps {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "swm_class_avps(count={},values=<redacted>)",
            self.avps.len()
        )
    }
}

/// Explicit RFC 6733 Class state update from an authorization answer.
///
/// `Unchanged` represents an answer with no Class occurrence and therefore
/// never erases previously retained state. `Replace` is produced when one or
/// more Class AVPs were present, including zero-length values.
#[derive(Clone, PartialEq, Eq)]
pub enum SwmClassAvpUpdate {
    /// The answer supplied no Class AVP; retain the prior set unchanged.
    Unchanged,
    /// Replace the prior set with this ordered nonempty Class collection.
    Replace(SwmClassAvps),
}

impl SwmClassAvpUpdate {
    /// Return whether this answer leaves retained Class state unchanged.
    #[must_use]
    pub const fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// Borrow the replacement when the answer supplied Class AVPs.
    #[must_use]
    pub const fn replacement(&self) -> Option<&SwmClassAvps> {
        match self {
            Self::Unchanged => None,
            Self::Replace(class_avps) => Some(class_avps),
        }
    }

    /// Apply this update to consumer-owned optional session state by moving it.
    pub fn apply_to(self, retained: &mut Option<SwmClassAvps>) {
        if let Self::Replace(class_avps) = self {
            *retained = Some(class_avps);
        }
    }

    /// Apply this update to consumer-owned optional session state by cloning it.
    pub fn clone_into(&self, retained: &mut Option<SwmClassAvps>) {
        if let Self::Replace(class_avps) = self {
            *retained = Some(class_avps.clone());
        }
    }

    pub(super) fn from_class_avps(class_avps: &SwmClassAvps) -> Self {
        if class_avps.is_empty() {
            Self::Unchanged
        } else {
            Self::Replace(class_avps.clone())
        }
    }

    pub(super) fn from_additional_avps(
        additional_avps: &[SwmAdditionalAvp],
    ) -> Result<Self, SwmSessionStateError> {
        let class_avps = SwmClassAvps::from_additional_avps(additional_avps)?;
        Ok(Self::from_class_avps(&class_avps))
    }
}

impl fmt::Debug for SwmClassAvpUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => formatter.write_str("SwmClassAvpUpdate::Unchanged"),
            Self::Replace(class_avps) => formatter
                .debug_tuple("SwmClassAvpUpdate::Replace")
                .field(class_avps)
                .finish(),
        }
    }
}

impl fmt::Display for SwmClassAvpUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => formatter.write_str("swm_class_avp_update(unchanged)"),
            Self::Replace(class_avps) => write!(
                formatter,
                "swm_class_avp_update(replace_count={},values=<redacted>)",
                class_avps.len()
            ),
        }
    }
}

/// Whether a later request must carry or omit `Destination-Host`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmDestinationHostRequirement {
    /// The final authorizing server identity must be included.
    Required,
    /// `Destination-Host` must be omitted so normal realm routing applies.
    Prohibited,
}

impl fmt::Debug for SwmDestinationHostRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-routing-requirement>")
    }
}

impl fmt::Display for SwmDestinationHostRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-routing-requirement>")
    }
}

/// RFC 6733 Session-Binding bitmask with forward-compatible unknown-bit
/// retention.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmSessionBinding {
    bits: u32,
}

impl SwmSessionBinding {
    const RE_AUTH_BIT: u32 = 1;
    const STR_BIT: u32 = 2;
    const ACCOUNTING_BIT: u32 = 4;
    const KNOWN_BITS: u32 = Self::RE_AUTH_BIT | Self::STR_BIT | Self::ACCOUNTING_BIT;

    /// Construct a canonical binding from the three RFC 6733 requirements.
    #[must_use]
    pub const fn new(
        re_auth: SwmDestinationHostRequirement,
        session_termination: SwmDestinationHostRequirement,
        accounting: SwmDestinationHostRequirement,
    ) -> Self {
        let mut bits = 0;
        if matches!(re_auth, SwmDestinationHostRequirement::Prohibited) {
            bits |= Self::RE_AUTH_BIT;
        }
        if matches!(
            session_termination,
            SwmDestinationHostRequirement::Prohibited
        ) {
            bits |= Self::STR_BIT;
        }
        if matches!(accounting, SwmDestinationHostRequirement::Prohibited) {
            bits |= Self::ACCOUNTING_BIT;
        }
        Self { bits }
    }

    /// Return the later re-authorization `Destination-Host` requirement.
    #[must_use]
    pub const fn re_auth_destination_host(self) -> SwmDestinationHostRequirement {
        requirement_from_bit(self.bits, Self::RE_AUTH_BIT)
    }

    /// Return the later STR `Destination-Host` requirement.
    #[must_use]
    pub const fn session_termination_destination_host(self) -> SwmDestinationHostRequirement {
        requirement_from_bit(self.bits, Self::STR_BIT)
    }

    /// Return the later accounting `Destination-Host` requirement.
    #[must_use]
    pub const fn accounting_destination_host(self) -> SwmDestinationHostRequirement {
        requirement_from_bit(self.bits, Self::ACCOUNTING_BIT)
    }

    /// Return whether unrecognized future binding bits were retained.
    #[must_use]
    pub const fn has_unknown_bits(self) -> bool {
        self.bits & !Self::KNOWN_BITS != 0
    }

    const fn prohibits_all_defined_destination_hosts(self) -> bool {
        self.bits & Self::KNOWN_BITS == Self::KNOWN_BITS
    }

    pub(super) const fn from_wire(bits: u32) -> Self {
        Self { bits }
    }

    pub(super) const fn wire_bits(self) -> u32 {
        self.bits
    }
}

impl fmt::Debug for SwmSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmSessionBinding(<redacted>)")
    }
}

impl fmt::Display for SwmSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("swm_session_binding(<redacted>)")
    }
}

const fn requirement_from_bit(bits: u32, bit: u32) -> SwmDestinationHostRequirement {
    if bits & bit == 0 {
        SwmDestinationHostRequirement::Required
    } else {
        SwmDestinationHostRequirement::Prohibited
    }
}

/// Known semantic projection of Session-Server-Failover.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwmSessionServerFailoverPolicy {
    /// Terminate service and do not retry.
    RefuseService,
    /// Retry once without `Destination-Host`.
    TryAgain,
    /// Treat re-auth delivery failure as success; STR still terminates.
    AllowService,
    /// Retry once without `Destination-Host`, then apply Allow-Service.
    TryAgainAllowService,
}

impl fmt::Debug for SwmSessionServerFailoverPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-failover-policy>")
    }
}

impl fmt::Display for SwmSessionServerFailoverPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-failover-policy>")
    }
}

/// RFC 6733 Session-Server-Failover value.
///
/// The typed value can represent only the four values assigned by RFC 6733
/// section 8.18. Unassigned wire values fail closed during decode.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmSessionServerFailover {
    policy: SwmSessionServerFailoverPolicy,
}

impl SwmSessionServerFailover {
    /// RFC default and explicit REFUSE_SERVICE value.
    pub const REFUSE_SERVICE: Self = Self {
        policy: SwmSessionServerFailoverPolicy::RefuseService,
    };
    /// TRY_AGAIN value.
    pub const TRY_AGAIN: Self = Self {
        policy: SwmSessionServerFailoverPolicy::TryAgain,
    };
    /// ALLOW_SERVICE value.
    pub const ALLOW_SERVICE: Self = Self {
        policy: SwmSessionServerFailoverPolicy::AllowService,
    };
    /// TRY_AGAIN_ALLOW_SERVICE value.
    pub const TRY_AGAIN_ALLOW_SERVICE: Self = Self {
        policy: SwmSessionServerFailoverPolicy::TryAgainAllowService,
    };

    /// Return the RFC 6733 failover policy.
    #[must_use]
    pub const fn policy(self) -> SwmSessionServerFailoverPolicy {
        self.policy
    }

    pub(super) const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::REFUSE_SERVICE),
            1 => Some(Self::TRY_AGAIN),
            2 => Some(Self::ALLOW_SERVICE),
            3 => Some(Self::TRY_AGAIN_ALLOW_SERVICE),
            _ => None,
        }
    }

    pub(super) const fn wire_value(self) -> u32 {
        match self.policy {
            SwmSessionServerFailoverPolicy::RefuseService => 0,
            SwmSessionServerFailoverPolicy::TryAgain => 1,
            SwmSessionServerFailoverPolicy::AllowService => 2,
            SwmSessionServerFailoverPolicy::TryAgainAllowService => 3,
        }
    }
}

impl Default for SwmSessionServerFailover {
    fn default() -> Self {
        Self::REFUSE_SERVICE
    }
}

impl fmt::Debug for SwmSessionServerFailover {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmSessionServerFailover(<redacted>)")
    }
}

impl fmt::Display for SwmSessionServerFailover {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("swm_session_server_failover(<redacted>)")
    }
}

/// Correlation-gated routing facts for one authorized Diameter session.
///
/// The final Origin identity comes from the ordinary DEA after authenticated
/// connection, transaction, Origin-policy, application, Session-Id, P-bit, and
/// Proxy-Info correlation. It is intentionally distinct from the transport or
/// DRA identity. This value owns only protocol facts; session association,
/// peer selection, retry timing, and service teardown remain consumer-owned.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizationSessionRouting {
    session_id: Sensitive<String>,
    authorizing_origin_host: Redacted<String>,
    authorizing_origin_realm: Redacted<String>,
    session_binding: Option<SwmSessionBinding>,
    server_failover: Option<SwmSessionServerFailover>,
}

impl SwmAuthorizationSessionRouting {
    /// Borrow the final authorizing Origin-Host.
    #[must_use]
    pub const fn authorizing_origin_host(&self) -> &Redacted<String> {
        &self.authorizing_origin_host
    }

    /// Borrow the final authorizing Origin-Realm.
    #[must_use]
    pub const fn authorizing_origin_realm(&self) -> &Redacted<String> {
        &self.authorizing_origin_realm
    }

    /// Return the explicit Session-Binding, preserving absence.
    #[must_use]
    pub const fn session_binding(&self) -> Option<SwmSessionBinding> {
        self.session_binding
    }

    /// Return the explicit Session-Server-Failover, preserving absence.
    #[must_use]
    pub const fn explicit_server_failover(&self) -> Option<SwmSessionServerFailover> {
        self.server_failover
    }

    /// Return the effective failover directive.
    ///
    /// Absence is the RFC 6733 default `REFUSE_SERVICE`. Unassigned wire values
    /// fail closed during DEA decode and cannot enter this typed state.
    #[must_use]
    pub const fn effective_server_failover_policy(&self) -> SwmSessionServerFailoverPolicy {
        match self.server_failover {
            Some(value) => value.policy(),
            None => SwmSessionServerFailoverPolicy::RefuseService,
        }
    }

    /// Return the re-authorization `Destination-Host` requirement.
    #[must_use]
    pub const fn re_auth_destination_host_requirement(&self) -> SwmDestinationHostRequirement {
        match self.session_binding {
            Some(binding) => binding.re_auth_destination_host(),
            None => SwmDestinationHostRequirement::Required,
        }
    }

    /// Return the STR `Destination-Host` requirement.
    #[must_use]
    pub const fn session_termination_destination_host_requirement(
        &self,
    ) -> SwmDestinationHostRequirement {
        match self.session_binding {
            Some(binding) => binding.session_termination_destination_host(),
            None => SwmDestinationHostRequirement::Required,
        }
    }

    /// Return the accounting `Destination-Host` requirement.
    #[must_use]
    pub const fn accounting_destination_host_requirement(&self) -> SwmDestinationHostRequirement {
        match self.session_binding {
            Some(binding) => binding.accounting_destination_host(),
            None => SwmDestinationHostRequirement::Required,
        }
    }

    /// Apply final-server routing to a later STR for this exact session.
    ///
    /// Destination-Realm is always replaced with the final authorizing
    /// Origin-Realm. Destination-Host is the final authorizing Origin-Host
    /// when required and is removed when the STR binding bit prohibits it.
    pub fn apply_to_session_termination_request(
        &self,
        request: &mut SwmSessionTerminationRequest,
    ) -> Result<(), SwmSessionStateError> {
        self.ensure_session(request.session_id.as_ref())?;
        request.destination_realm = self.authorizing_origin_realm.clone();
        request.destination_host = match self.session_termination_destination_host_requirement() {
            SwmDestinationHostRequirement::Required => Some(self.authorizing_origin_host.clone()),
            SwmDestinationHostRequirement::Prohibited => None,
        };
        Ok(())
    }

    /// Prepare a later STR retry after a delivery failure.
    ///
    /// Only `TRY_AGAIN` and `TRY_AGAIN_ALLOW_SERVICE` authorize a subsequent
    /// hostless request. Absence, `REFUSE_SERVICE`, and `ALLOW_SERVICE` return a
    /// stable error without mutating the request.
    pub fn remove_destination_host_after_session_termination_delivery_failure(
        &self,
        request: &mut SwmSessionTerminationRequest,
    ) -> Result<(), SwmSessionStateError> {
        self.ensure_session(request.session_id.as_ref())?;
        if !matches!(
            self.effective_server_failover_policy(),
            SwmSessionServerFailoverPolicy::TryAgain
                | SwmSessionServerFailoverPolicy::TryAgainAllowService
        ) {
            return Err(SwmSessionStateError::new(
                SwmSessionStateErrorCode::DestinationHostRemovalProhibited,
            ));
        }
        request.destination_host = None;
        Ok(())
    }

    fn ensure_session(&self, session_id: &str) -> Result<(), SwmSessionStateError> {
        if self.session_id.as_ref() == session_id {
            Ok(())
        } else {
            Err(SwmSessionStateError::new(
                SwmSessionStateErrorCode::SessionMismatch,
            ))
        }
    }

    pub(super) fn from_correlated_answer(answer: &SwmDiameterEapAnswer) -> Self {
        Self {
            session_id: Sensitive::new(answer.session_id.as_ref().clone()),
            authorizing_origin_host: answer.origin_host.clone(),
            authorizing_origin_realm: answer.origin_realm.clone(),
            session_binding: answer.extensions.session_binding,
            server_failover: answer.extensions.session_server_failover,
        }
    }
}

impl fmt::Debug for SwmAuthorizationSessionRouting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizationSessionRouting")
            .field("session_id", &"<redacted>")
            .field("authorizing_origin_host", &"<redacted>")
            .field("authorizing_origin_realm", &"<redacted>")
            .field("session_binding_present", &self.session_binding.is_some())
            .field("server_failover_present", &self.server_failover.is_some())
            .finish()
    }
}

impl fmt::Display for SwmAuthorizationSessionRouting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("swm_authorization_session_routing(<redacted>)")
    }
}

pub(super) fn parse_session_binding(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmSessionBinding, DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    let bits = builder_helpers::parse_u32_value(avp.value, value_offset, "8.17")?;
    Ok(SwmSessionBinding::from_wire(bits))
}

pub(super) fn parse_session_server_failover(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmSessionServerFailover, DecodeError> {
    lifecycle::validate_base_definition(avp, offset)?;
    let value = builder_helpers::parse_u32_value(avp.value, value_offset, "8.18")?;
    SwmSessionServerFailover::from_wire(value).ok_or_else(|| {
        DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Session-Server-Failover contains an unassigned value",
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.18"))
    })
}

pub(super) fn validate_session_routing_directives(
    session_binding: Option<SwmSessionBinding>,
    session_server_failover: Option<SwmSessionServerFailover>,
) -> Result<(), SwmSessionStateError> {
    if matches!(
        (session_binding, session_server_failover),
        (Some(binding), Some(_)) if binding.prohibits_all_defined_destination_hosts()
    ) {
        return Err(SwmSessionStateError::new(
            SwmSessionStateErrorCode::ContradictoryRoutingDirectives,
        ));
    }
    Ok(())
}

pub(super) fn validate_session_routing_directives_for_decode(
    session_binding: Option<SwmSessionBinding>,
    session_server_failover: Option<SwmSessionServerFailover>,
    offset: usize,
) -> Result<(), DecodeError> {
    validate_session_routing_directives(session_binding, session_server_failover).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Session-Server-Failover contradicts Session-Binding",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.18"))
    })
}

pub(super) fn validate_class_additional_avps_for_decode(
    additional_avps: &[SwmAdditionalAvp],
    offset: usize,
) -> Result<(), DecodeError> {
    SwmClassAvps::from_additional_avps(additional_avps)
        .map(|_| ())
        .map_err(|error| class_decode_error(error, offset))
}

pub(super) fn validate_class_additional_avps_for_encode(
    additional_avps: &[SwmAdditionalAvp],
) -> Result<(), EncodeError> {
    SwmClassAvps::from_additional_avps(additional_avps)
        .map(|_| ())
        .map_err(|_| {
            super::encode_structural_error(
                "SWm authorization Class AVPs exceed the typed session-state boundary",
                "8.20",
            )
        })
}

fn replace_class_avps(
    additional_avps: &mut Vec<SwmAdditionalAvp>,
    replacements: Vec<SwmAdditionalAvp>,
) -> Result<(), SwmSessionStateError> {
    let retained_count = additional_avps
        .iter()
        .filter(|avp| avp.header().key() != AvpKey::ietf(base::AVP_CLASS))
        .count();
    let next_count = retained_count
        .checked_add(replacements.len())
        .ok_or_else(|| {
            SwmSessionStateError::new(SwmSessionStateErrorCode::AdditionalAvpCapacityExceeded)
        })?;
    if next_count > MAX_SWM_CLASS_AVPS {
        return Err(SwmSessionStateError::new(
            SwmSessionStateErrorCode::AdditionalAvpCapacityExceeded,
        ));
    }
    additional_avps.retain(|avp| avp.header().key() != AvpKey::ietf(base::AVP_CLASS));
    additional_avps.extend(replacements);
    Ok(())
}

fn class_decode_error(error: SwmSessionStateError, offset: usize) -> DecodeError {
    let code = match error.code() {
        SwmSessionStateErrorCode::TooManyClassAvps => DecodeErrorCode::IeCountExceeded,
        SwmSessionStateErrorCode::ClassValueBytesExceeded => DecodeErrorCode::Structural {
            reason: "SWm Class value aggregate exceeds the typed session-state boundary",
        },
        SwmSessionStateErrorCode::InvalidClassAvp
        | SwmSessionStateErrorCode::AdditionalAvpCapacityExceeded
        | SwmSessionStateErrorCode::SessionMismatch
        | SwmSessionStateErrorCode::ContradictoryRoutingDirectives
        | SwmSessionStateErrorCode::DestinationHostRemovalProhibited => {
            DecodeErrorCode::Structural {
                reason: "SWm Class AVP is invalid",
            }
        }
    };
    DecodeError::new(code, offset).with_spec_ref(SpecRef::new("ietf", "RFC6733", "8.20"))
}
