//! Typed SWm subscriber/equipment trace directives.
//!
//! TS 29.273 narrows the generic TS 29.272 `Trace-Data` group to the PDN-GW
//! fields that an ePDG can forward on S2b. This module models that finite
//! profile rather than exposing the trace bitmaps as opaque byte strings.

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};
use std::{collections::HashSet, error::Error, fmt, net::IpAddr, str::FromStr};

use super::{builder_helpers, lifecycle, DiameterEapRetention, SwmAdditionalAvp, VENDOR_ID_3GPP};
use crate::dictionary::{AvpFlagRules, AvpKey, FlagRequirement};
use crate::{AvpCode, AvpHeader, RawAvp};

/// Trace-Info grouped AVP code (3GPP TS 29.273 section 8.2.3.13).
pub const AVP_TRACE_INFO: AvpCode = AvpCode::new(1505);
/// Trace-Data grouped AVP code (3GPP TS 29.272 section 7.3.63).
pub const AVP_TRACE_DATA: AvpCode = AvpCode::new(1458);
/// Trace-Reference AVP code (3GPP TS 29.272 section 7.3.64).
pub const AVP_TRACE_REFERENCE: AvpCode = AvpCode::new(1459);
/// Trace-Depth AVP code (3GPP TS 29.272 section 7.3.67).
pub const AVP_TRACE_DEPTH: AvpCode = AvpCode::new(1462);
/// Trace-NE-Type-List AVP code (3GPP TS 29.272 section 7.3.68).
pub const AVP_TRACE_NE_TYPE_LIST: AvpCode = AvpCode::new(1463);
/// Trace-Interface-List AVP code (3GPP TS 29.272 section 7.3.69).
pub const AVP_TRACE_INTERFACE_LIST: AvpCode = AvpCode::new(1464);
/// Trace-Event-List AVP code (3GPP TS 29.272 section 7.3.70).
pub const AVP_TRACE_EVENT_LIST: AvpCode = AvpCode::new(1465);
/// Trace-Collection-Entity AVP code (3GPP TS 29.272 section 7.3.98).
pub const AVP_TRACE_COLLECTION_ENTITY: AvpCode = AvpCode::new(1452);
/// Trace-Reporting-Consumer-Uri AVP code (3GPP TS 29.272 section 7.3.252).
pub const AVP_TRACE_REPORTING_CONSUMER_URI: AvpCode = AvpCode::new(1727);

const TRACE_REFERENCE_LEN: usize = 6;
// TS 32.422 V18.5 §5.1 overview assigns one octet to each table row,
// including the reserved rows. PGW/SGW share octet 9, and the table extends
// through the SMSF row at octet 17.
const TRACE_EVENT_LIST_LEN: usize = 17;
const TRACE_NE_TYPE_LIST_LEN: usize = 3;
// TS 32.422 V18.5/V18.7 §5.5 assigns one octet to each overview row; PDN GW
// is row/octet 11 and the complete table extends through octet 23.
const TRACE_INTERFACE_LIST_LEN: usize = 23;
const PGW_EVENT_INDEX: usize = 8;
const PGW_INTERFACE_INDEX: usize = 10;
// TS 32.422 V18.5/V18.7 §5.4: PDN GW is bit 1 of octet 2 in the
// three-octet NE-type list.
const PGW_NE_TYPE_LIST: [u8; TRACE_NE_TYPE_LIST_LEN] = [0x00, 0x01, 0x00];
const MAX_TRACE_REPORTING_CONSUMER_URI_LEN: usize = 2_048;

const TRACE_INFO_FLAGS: AvpFlagRules = AvpFlagRules::new(
    FlagRequirement::MustBeSet,
    FlagRequirement::MustBeUnset,
    FlagRequirement::MustBeUnset,
);
const TRACE_DATA_CHILD_FLAGS: AvpFlagRules = AvpFlagRules::new(
    FlagRequirement::MustBeSet,
    FlagRequirement::MustBeSet,
    FlagRequirement::MustBeUnset,
);
const TRACE_REPORTING_URI_FLAGS: AvpFlagRules = AvpFlagRules::new(
    FlagRequirement::MustBeSet,
    FlagRequirement::MustBeUnset,
    FlagRequirement::MustBeUnset,
);

/// Fail-closed error returned by trace value constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwmTraceValueError {
    /// The trace reference is not the six-octet TS 29.272 PLMN/Trace-ID form.
    InvalidTraceReference,
    /// The reporting URI is not a bounded TS 32.158 HTTP(S) MnS URI.
    InvalidReportingConsumerUri,
    /// A receive-derived trace value was presented for a new origination.
    InvalidReplayProvenance,
}

impl SwmTraceValueError {
    /// Return a stable, value-free error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTraceReference => "swm_trace_invalid_reference",
            Self::InvalidReportingConsumerUri => "swm_trace_invalid_reporting_consumer_uri",
            Self::InvalidReplayProvenance => "swm_trace_invalid_replay_provenance",
        }
    }
}

impl fmt::Display for SwmTraceValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmTraceValueError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SwmTraceValueOrigin {
    Originated,
    Received,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SwmTraceEncodePurpose {
    Origination,
    ParsedReplay,
}

/// Globally unique TS 32.422 trace reference.
///
/// The first three octets carry the TS 24.008 PLMN encoding and the remaining
/// three octets carry the Trace ID. The value is operationally sensitive and
/// is redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmTraceReference {
    octets: [u8; TRACE_REFERENCE_LEN],
    origin: SwmTraceValueOrigin,
}

impl SwmTraceReference {
    /// Validate a six-octet PLMN/Trace-ID value.
    pub fn new(octets: [u8; TRACE_REFERENCE_LEN]) -> Result<Self, SwmTraceValueError> {
        if !valid_plmn_octets(&octets[..3]) {
            return Err(SwmTraceValueError::InvalidTraceReference);
        }
        Ok(Self {
            octets,
            origin: SwmTraceValueOrigin::Originated,
        })
    }

    /// Return the exact six-octet value for a standards protocol projection.
    ///
    /// The returned value contains trace identity material and must not be
    /// logged or used as a metric label.
    #[must_use]
    pub const fn octets(&self) -> [u8; TRACE_REFERENCE_LEN] {
        self.octets
    }

    fn from_received(octets: [u8; TRACE_REFERENCE_LEN]) -> Result<Self, SwmTraceValueError> {
        if !valid_plmn_octets(&octets[..3]) {
            return Err(SwmTraceValueError::InvalidTraceReference);
        }
        Ok(Self {
            octets,
            origin: SwmTraceValueOrigin::Received,
        })
    }

    fn validate_origin(&self, expected: SwmTraceValueOrigin) -> Result<(), SwmTraceValueError> {
        if self.origin == expected {
            Ok(())
        } else {
            Err(SwmTraceValueError::InvalidReplayProvenance)
        }
    }
}

impl fmt::Debug for SwmTraceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmTraceReference(<redacted>)")
    }
}

/// TS 32.422 session Trace Depth.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwmTraceDepth {
    /// Minimum trace depth (0).
    Minimum,
    /// Medium trace depth (1).
    Medium,
    /// Maximum trace depth (2).
    Maximum,
    /// Minimum trace depth without vendor-specific extensions (3).
    MinimumWithoutVendorSpecificExtension,
    /// Medium trace depth without vendor-specific extensions (4).
    MediumWithoutVendorSpecificExtension,
    /// Maximum trace depth without vendor-specific extensions (5).
    MaximumWithoutVendorSpecificExtension,
}

impl SwmTraceDepth {
    const fn value(self) -> u32 {
        match self {
            Self::Minimum => 0,
            Self::Medium => 1,
            Self::Maximum => 2,
            Self::MinimumWithoutVendorSpecificExtension => 3,
            Self::MediumWithoutVendorSpecificExtension => 4,
            Self::MaximumWithoutVendorSpecificExtension => 5,
        }
    }

    fn from_value(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Minimum),
            1 => Some(Self::Medium),
            2 => Some(Self::Maximum),
            3 => Some(Self::MinimumWithoutVendorSpecificExtension),
            4 => Some(Self::MediumWithoutVendorSpecificExtension),
            5 => Some(Self::MaximumWithoutVendorSpecificExtension),
            _ => None,
        }
    }
}

impl fmt::Debug for SwmTraceDepth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmTraceDepth(<redacted>)")
    }
}

/// PGW triggering events from the Release-18 TS 32.422 seventeen-octet bitmap.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SwmPgwTraceEvents(u8);

impl SwmPgwTraceEvents {
    const CONNECTION_CREATION: u8 = 0x10;
    const CONNECTION_TERMINATION: u8 = 0x20;
    const BEARER_LIFECYCLE: u8 = 0x40;
    const ASSIGNED: u8 =
        Self::CONNECTION_CREATION | Self::CONNECTION_TERMINATION | Self::BEARER_LIFECYCLE;

    /// Construct the PGW event selection.
    #[must_use]
    pub const fn new(
        pdn_connection_creation: bool,
        pdn_connection_termination: bool,
        bearer_lifecycle: bool,
    ) -> Self {
        let mut bits = 0;
        if pdn_connection_creation {
            bits |= Self::CONNECTION_CREATION;
        }
        if pdn_connection_termination {
            bits |= Self::CONNECTION_TERMINATION;
        }
        if bearer_lifecycle {
            bits |= Self::BEARER_LIFECYCLE;
        }
        Self(bits)
    }

    /// Return whether PDN connection creation is traced.
    #[must_use]
    pub const fn traces_pdn_connection_creation(self) -> bool {
        self.0 & Self::CONNECTION_CREATION != 0
    }

    /// Return whether PDN connection termination is traced.
    #[must_use]
    pub const fn traces_pdn_connection_termination(self) -> bool {
        self.0 & Self::CONNECTION_TERMINATION != 0
    }

    /// Return whether bearer activation/modification/deletion is traced.
    #[must_use]
    pub const fn traces_bearer_lifecycle(self) -> bool {
        self.0 & Self::BEARER_LIFECYCLE != 0
    }

    fn wire(self) -> [u8; TRACE_EVENT_LIST_LEN] {
        let mut wire = [0_u8; TRACE_EVENT_LIST_LEN];
        wire[PGW_EVENT_INDEX] = self.0;
        wire
    }

    fn parse(value: &[u8]) -> Option<Self> {
        if value.len() != TRACE_EVENT_LIST_LEN {
            return None;
        }
        if value
            .iter()
            .enumerate()
            .any(|(index, byte)| index != PGW_EVENT_INDEX && *byte != 0)
            || value[PGW_EVENT_INDEX] & !Self::ASSIGNED != 0
        {
            return None;
        }
        Some(Self(value[PGW_EVENT_INDEX]))
    }
}

impl fmt::Debug for SwmPgwTraceEvents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmPgwTraceEvents(<redacted>)")
    }
}

/// PGW interfaces from the Release-18 TS 32.422 twenty-three-octet bitmap.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SwmPgwTraceInterfaces(u8);

impl SwmPgwTraceInterfaces {
    const S2A: u8 = 0x01;
    const S2B: u8 = 0x02;
    const S2C: u8 = 0x04;
    const S5: u8 = 0x08;
    const S6B: u8 = 0x10;
    const GX: u8 = 0x20;
    const S8B: u8 = 0x40;
    const SGI: u8 = 0x80;

    /// Construct the PGW interface selection in TS 32.422 bit order.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        s2a: bool,
        s2b: bool,
        s2c: bool,
        s5: bool,
        s6b: bool,
        gx: bool,
        s8b: bool,
        sgi: bool,
    ) -> Self {
        let mut bits = 0;
        if s2a {
            bits |= Self::S2A;
        }
        if s2b {
            bits |= Self::S2B;
        }
        if s2c {
            bits |= Self::S2C;
        }
        if s5 {
            bits |= Self::S5;
        }
        if s6b {
            bits |= Self::S6B;
        }
        if gx {
            bits |= Self::GX;
        }
        if s8b {
            bits |= Self::S8B;
        }
        if sgi {
            bits |= Self::SGI;
        }
        Self(bits)
    }

    /// Return whether S2a reporting is selected.
    #[must_use]
    pub const fn includes_s2a(self) -> bool {
        self.0 & Self::S2A != 0
    }

    /// Return whether S2b reporting is selected.
    #[must_use]
    pub const fn includes_s2b(self) -> bool {
        self.0 & Self::S2B != 0
    }

    /// Return whether S2c reporting is selected.
    #[must_use]
    pub const fn includes_s2c(self) -> bool {
        self.0 & Self::S2C != 0
    }

    /// Return whether S5 reporting is selected.
    #[must_use]
    pub const fn includes_s5(self) -> bool {
        self.0 & Self::S5 != 0
    }

    /// Return whether S6b reporting is selected.
    #[must_use]
    pub const fn includes_s6b(self) -> bool {
        self.0 & Self::S6B != 0
    }

    /// Return whether Gx reporting is selected.
    #[must_use]
    pub const fn includes_gx(self) -> bool {
        self.0 & Self::GX != 0
    }

    /// Return whether S8b reporting is selected.
    #[must_use]
    pub const fn includes_s8b(self) -> bool {
        self.0 & Self::S8B != 0
    }

    /// Return whether SGi reporting is selected.
    #[must_use]
    pub const fn includes_sgi(self) -> bool {
        self.0 & Self::SGI != 0
    }

    fn wire(self) -> [u8; TRACE_INTERFACE_LIST_LEN] {
        let mut wire = [0_u8; TRACE_INTERFACE_LIST_LEN];
        wire[PGW_INTERFACE_INDEX] = self.0;
        wire
    }

    fn parse(value: &[u8]) -> Option<Self> {
        if value.len() != TRACE_INTERFACE_LIST_LEN
            || value
                .iter()
                .enumerate()
                .any(|(index, byte)| index != PGW_INTERFACE_INDEX && *byte != 0)
        {
            return None;
        }
        Some(Self(value[PGW_INTERFACE_INDEX]))
    }
}

impl fmt::Debug for SwmPgwTraceInterfaces {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmPgwTraceInterfaces(<redacted>)")
    }
}

/// Validated HTTP(S) Trace Reporting MnS consumer URI.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmTraceReportingConsumerUri {
    value: String,
    origin: SwmTraceValueOrigin,
}

impl SwmTraceReportingConsumerUri {
    /// Validate one TS 32.158 HTTP(S) management-service URI.
    ///
    /// The SDK implements a strict syntax profile of TS 32.158 section 4.4.3:
    /// `http[s]://authority/{root?}/{MnSName}/{MnSVersion}/{MnSResourcePath}`.
    /// Optional nonempty root segments are accepted, followed by the required
    /// single-segment MnS name and version and at least one resource segment.
    /// The SDK validates that there are at least three path segments; their
    /// deployment-specific names and semantic ownership remain caller policy.
    ///
    /// The endpoint is bounded to 2048 ASCII octets as an SDK resource limit,
    /// not a 3GPP wire limit. Credentials, fragments, queries, empty or dot
    /// path segments, malformed percent escapes, and schemes other than
    /// case-insensitive `http` or `https` are rejected. Originated values emit
    /// a lowercase scheme; immutable parsed replay preserves the received URI
    /// value while canonicalizing its AVP header flags.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SwmTraceValueError> {
        let value = value.as_ref();
        if !valid_trace_reporting_uri(value) {
            return Err(SwmTraceValueError::InvalidReportingConsumerUri);
        }
        let (scheme, remainder) = value
            .split_once("://")
            .ok_or(SwmTraceValueError::InvalidReportingConsumerUri)?;
        let canonical_scheme = if scheme.eq_ignore_ascii_case("http") {
            "http"
        } else {
            "https"
        };
        let mut normalized = String::with_capacity(value.len());
        normalized.push_str(canonical_scheme);
        normalized.push_str("://");
        normalized.push_str(remainder);
        Ok(Self {
            value: normalized,
            origin: SwmTraceValueOrigin::Originated,
        })
    }

    /// Return the validated endpoint.
    ///
    /// This value is operationally sensitive and must not be logged or used as
    /// a metric label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    fn from_received(value: &str) -> Result<Self, SwmTraceValueError> {
        if !valid_trace_reporting_uri(value) {
            return Err(SwmTraceValueError::InvalidReportingConsumerUri);
        }
        Ok(Self {
            value: value.to_owned(),
            origin: SwmTraceValueOrigin::Received,
        })
    }

    fn validate_origin(&self, expected: SwmTraceValueOrigin) -> Result<(), SwmTraceValueError> {
        if self.origin == expected {
            Ok(())
        } else {
            Err(SwmTraceValueError::InvalidReplayProvenance)
        }
    }
}

impl fmt::Debug for SwmTraceReportingConsumerUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmTraceReportingConsumerUri(<redacted>)")
    }
}

/// SWm's PDN-GW subset of the TS 29.272 Trace-Data group.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmTraceData {
    trace_reference: SwmTraceReference,
    depth: SwmTraceDepth,
    events: SwmPgwTraceEvents,
    explicit_pdn_gateway_target: bool,
    interfaces: Option<SwmPgwTraceInterfaces>,
    collection_entity: IpAddr,
    reporting_consumer_uri: Option<SwmTraceReportingConsumerUri>,
    additional_avps: Vec<SwmAdditionalAvp>,
    origin: SwmTraceValueOrigin,
}

impl SwmTraceData {
    /// Construct the required SWm trace activation fields.
    ///
    /// An omitted Trace-NE-Type-List means PDN-GW activation under TS 29.273.
    /// Use [`Self::with_explicit_pdn_gateway_target`] when the canonical
    /// Release-18 PDN-GW bitmap must be sent explicitly.
    pub fn new(
        trace_reference: SwmTraceReference,
        depth: SwmTraceDepth,
        events: SwmPgwTraceEvents,
        collection_entity: IpAddr,
    ) -> Result<Self, SwmTraceValueError> {
        trace_reference.validate_origin(SwmTraceValueOrigin::Originated)?;
        Ok(Self {
            trace_reference,
            depth,
            events,
            explicit_pdn_gateway_target: false,
            interfaces: None,
            collection_entity,
            reporting_consumer_uri: None,
            additional_avps: Vec::new(),
            origin: SwmTraceValueOrigin::Originated,
        })
    }

    /// Emit the canonical TS 32.422 Release-18 PDN-GW NE bitmap explicitly.
    #[must_use]
    pub fn with_explicit_pdn_gateway_target(mut self) -> Self {
        self.explicit_pdn_gateway_target = true;
        self
    }

    /// Attach the optional PGW interface selection.
    #[must_use]
    pub fn with_interfaces(mut self, interfaces: SwmPgwTraceInterfaces) -> Self {
        self.interfaces = Some(interfaces);
        self
    }

    /// Attach the preferred streaming-reporting endpoint.
    pub fn with_reporting_consumer_uri(
        mut self,
        uri: SwmTraceReportingConsumerUri,
    ) -> Result<Self, SwmTraceValueError> {
        uri.validate_origin(SwmTraceValueOrigin::Originated)?;
        self.reporting_consumer_uri = Some(uri);
        Ok(self)
    }

    /// Return the trace reference.
    #[must_use]
    pub const fn trace_reference(&self) -> &SwmTraceReference {
        &self.trace_reference
    }

    /// Return the trace depth.
    #[must_use]
    pub const fn depth(&self) -> SwmTraceDepth {
        self.depth
    }

    /// Return the PGW triggering-event selection.
    #[must_use]
    pub const fn events(&self) -> SwmPgwTraceEvents {
        self.events
    }

    /// Return whether the PDN-GW NE bitmap was explicitly present.
    #[must_use]
    pub const fn has_explicit_pdn_gateway_target(&self) -> bool {
        self.explicit_pdn_gateway_target
    }

    /// Return the optional PGW interface selection.
    ///
    /// Omission requests reporting for all PGW interfaces defined by the
    /// supported TS 32.422 release; it does not mean that no interfaces were
    /// selected.
    #[must_use]
    pub const fn interfaces(&self) -> Option<SwmPgwTraceInterfaces> {
        self.interfaces
    }

    /// Return the file-reporting collection address.
    ///
    /// This value is operationally sensitive and must not be logged or used as
    /// a metric label.
    #[must_use]
    pub const fn collection_entity(&self) -> IpAddr {
        self.collection_entity
    }

    /// Return the preferred streaming endpoint, when present.
    ///
    /// When the receiver supports streaming reporting, this URI takes
    /// precedence over the collection entity under TS 29.273. Whether that
    /// reporting mode and endpoint are trusted remains product policy.
    #[must_use]
    pub const fn reporting_consumer_uri(&self) -> Option<&SwmTraceReportingConsumerUri> {
        self.reporting_consumer_uri.as_ref()
    }

    /// Return the number of parser-retained optional extension AVPs.
    #[must_use]
    pub fn additional_avp_count(&self) -> usize {
        self.additional_avps.len()
    }

    fn validate_for_encode(
        &self,
        purpose: SwmTraceEncodePurpose,
    ) -> Result<(), SwmTraceValueError> {
        let expected = match purpose {
            SwmTraceEncodePurpose::Origination => SwmTraceValueOrigin::Originated,
            SwmTraceEncodePurpose::ParsedReplay => SwmTraceValueOrigin::Received,
        };
        if self.origin != expected
            || (purpose == SwmTraceEncodePurpose::Origination && !self.additional_avps.is_empty())
        {
            return Err(SwmTraceValueError::InvalidReplayProvenance);
        }
        self.trace_reference.validate_origin(expected)?;
        if let Some(uri) = self.reporting_consumer_uri.as_ref() {
            uri.validate_origin(expected)?;
        }
        Ok(())
    }
}

impl fmt::Debug for SwmTraceData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmTraceData")
            .field("trace_reference", &"<redacted>")
            .field("depth", &"<redacted>")
            .field("events", &"<redacted>")
            .field(
                "explicit_pdn_gateway_target",
                &self.explicit_pdn_gateway_target,
            )
            .field("interfaces_present", &self.interfaces.is_some())
            .field("collection_entity", &"<redacted>")
            .field(
                "reporting_consumer_uri_present",
                &self.reporting_consumer_uri.is_some(),
            )
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

/// Typed command-268 SWm DEA Trace-Info activation data.
///
/// TS 29.273 permits only a `Trace-Data` child in the initial Diameter-EAP
/// Answer. The direct `Trace-Reference` deactivation form belongs to the
/// separate command-265 Authorization Answer and is intentionally not modeled
/// by this command-specific type.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmTraceInfo {
    data: SwmTraceData,
    additional_avps: Vec<SwmAdditionalAvp>,
    origin: SwmTraceValueOrigin,
}

impl SwmTraceInfo {
    /// Construct trace activation data for a command-268 DEA.
    pub fn activation(data: SwmTraceData) -> Result<Self, SwmTraceValueError> {
        data.validate_for_encode(SwmTraceEncodePurpose::Origination)?;
        Ok(Self {
            data,
            additional_avps: Vec::new(),
            origin: SwmTraceValueOrigin::Originated,
        })
    }

    /// Borrow the correlated typed activation data.
    ///
    /// This accessor reports the received protocol value. It does not decide
    /// whether a product is authorized or configured to execute a trace.
    #[must_use]
    pub const fn data(&self) -> &SwmTraceData {
        &self.data
    }

    /// Return the number of parser-retained optional extension AVPs.
    #[must_use]
    pub fn additional_avp_count(&self) -> usize {
        self.additional_avps.len()
    }

    pub(super) fn retained_avp_count(&self) -> Option<usize> {
        let nested_count = self.data.additional_avps.len();
        self.additional_avps.len().checked_add(nested_count)
    }

    pub(super) fn validate_for_encode(
        &self,
        purpose: SwmTraceEncodePurpose,
    ) -> Result<(), SwmTraceValueError> {
        let expected = match purpose {
            SwmTraceEncodePurpose::Origination => SwmTraceValueOrigin::Originated,
            SwmTraceEncodePurpose::ParsedReplay => SwmTraceValueOrigin::Received,
        };
        if self.origin != expected
            || (purpose == SwmTraceEncodePurpose::Origination && !self.additional_avps.is_empty())
        {
            return Err(SwmTraceValueError::InvalidReplayProvenance);
        }
        self.data.validate_for_encode(purpose)
    }
}

impl fmt::Debug for SwmTraceInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmTraceInfo")
            .field("trace_data", &"<redacted>")
            .field("additional_avp_count", &self.additional_avps.len())
            .finish()
    }
}

pub(super) const fn is_trace_avp_code(code: AvpCode) -> bool {
    matches!(
        code,
        AVP_TRACE_INFO
            | AVP_TRACE_DATA
            | AVP_TRACE_REFERENCE
            | AVP_TRACE_DEPTH
            | AVP_TRACE_NE_TYPE_LIST
            | AVP_TRACE_INTERFACE_LIST
            | AVP_TRACE_EVENT_LIST
            | AVP_TRACE_COLLECTION_ENTITY
            | AVP_TRACE_REPORTING_CONSUMER_URI
    )
}

pub(super) fn parse_trace_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmTraceInfo, DecodeError> {
    validate_flags(
        &avp.header,
        TRACE_INFO_FLAGS,
        outer_offset,
        "8.2.3.13",
        "Trace-Info must set V and clear P",
    )?;

    let mut trace_data = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, 1, |offset, child| {
        reject_zero_vendor(&child, offset)?;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "8.2.3.13")?;
        if child.header.key() == AvpKey::vendor(AVP_TRACE_DATA, VENDOR_ID_3GPP) {
            let data = parse_trace_data(&child, ctx, offset, child_value_offset, 2, retention)?;
            builder_helpers::set_once(&mut trace_data, data, offset, "8.2.3.13")
        } else if is_trace_avp_code(child.header.code) {
            Err(trace_decode_error_at(
                "Trace-Info child uses the wrong vendor identity or nesting",
                offset,
                "8.2.3.13",
            ))
        } else {
            retain_unknown_child(
                &mut additional_avps,
                &child,
                ctx,
                offset,
                "8.2.3.13",
                retention,
                &mut additional_keys,
            )
        }
    })?;

    Ok(SwmTraceInfo {
        data: require_trace_field(
            trace_data,
            "command-268 SWm Trace-Info requires exactly one Trace-Data child",
            outer_offset,
            "8.2.3.13",
        )?,
        additional_avps,
        origin: SwmTraceValueOrigin::Received,
    })
}

fn parse_trace_data(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmTraceData, DecodeError> {
    validate_flags(
        &avp.header,
        TRACE_DATA_CHILD_FLAGS,
        outer_offset,
        "7.3.63",
        "Trace-Data must set V and clear P",
    )?;

    let mut trace_reference = None;
    let mut trace_depth = None;
    let mut explicit_pdn_gateway_target = None;
    let mut interfaces = None;
    let mut events = None;
    let mut collection_entity = None;
    let mut reporting_consumer_uri = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, depth, |offset, child| {
        reject_zero_vendor(&child, offset)?;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "7.3.63")?;
        let key = child.header.key();
        if key == AvpKey::vendor(AVP_TRACE_REFERENCE, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.64",
                "Trace-Reference must set V and clear P",
            )?;
            let value = parse_trace_reference(child.value, child_value_offset)?;
            builder_helpers::set_once(&mut trace_reference, value, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_DEPTH, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.67",
                "Trace-Depth must set V and clear P",
            )?;
            let raw = builder_helpers::parse_u32_value(child.value, child_value_offset, "7.3.67")?;
            let value = SwmTraceDepth::from_value(raw).ok_or_else(|| {
                trace_decode_error_at(
                    "Trace-Depth contains an unassigned value",
                    child_value_offset,
                    "7.3.67",
                )
            })?;
            builder_helpers::set_once(&mut trace_depth, value, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_NE_TYPE_LIST, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.68",
                "Trace-NE-Type-List must set V and clear P",
            )?;
            if child.value != PGW_NE_TYPE_LIST {
                return Err(trace_decode_error_at(
                    "SWm Trace-NE-Type-List must contain only the Release-18 PDN-GW bit",
                    child_value_offset,
                    "7.3.68",
                ));
            }
            builder_helpers::set_once(&mut explicit_pdn_gateway_target, true, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_INTERFACE_LIST, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.69",
                "Trace-Interface-List must set V and clear P",
            )?;
            let value = SwmPgwTraceInterfaces::parse(child.value).ok_or_else(|| {
                trace_decode_error_at(
                    "SWm Trace-Interface-List must contain only the Release-18 PGW bitmap",
                    child_value_offset,
                    "7.3.69",
                )
            })?;
            builder_helpers::set_once(&mut interfaces, value, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_EVENT_LIST, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.70",
                "Trace-Event-List must set V and clear P",
            )?;
            let value = SwmPgwTraceEvents::parse(child.value).ok_or_else(|| {
                trace_decode_error_at(
                    "SWm Trace-Event-List must contain only the Release-18 PGW bitmap",
                    child_value_offset,
                    "7.3.70",
                )
            })?;
            builder_helpers::set_once(&mut events, value, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_COLLECTION_ENTITY, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_DATA_CHILD_FLAGS,
                offset,
                "7.3.98",
                "Trace-Collection-Entity must set V and clear P",
            )?;
            let value =
                builder_helpers::parse_address_value(child.value, child_value_offset, "7.3.98")?;
            builder_helpers::set_once(&mut collection_entity, value, offset, "7.3.63")
        } else if key == AvpKey::vendor(AVP_TRACE_REPORTING_CONSUMER_URI, VENDOR_ID_3GPP) {
            validate_flags(
                &child.header,
                TRACE_REPORTING_URI_FLAGS,
                offset,
                "7.3.252",
                "Trace-Reporting-Consumer-Uri must set V and clear P",
            )?;
            let value = parse_reporting_consumer_uri(child.value, child_value_offset)?;
            builder_helpers::set_once(&mut reporting_consumer_uri, value, offset, "7.3.63")
        } else if is_trace_avp_code(child.header.code) {
            Err(trace_decode_error_at(
                "Trace-Data child uses the wrong vendor identity or nesting",
                offset,
                "7.3.63",
            ))
        } else {
            retain_unknown_child(
                &mut additional_avps,
                &child,
                ctx,
                offset,
                "7.3.63",
                retention,
                &mut additional_keys,
            )
        }
    })?;

    Ok(SwmTraceData {
        trace_reference: require_trace_field(
            trace_reference,
            "SWm Trace-Data requires Trace-Reference",
            outer_offset,
            "7.3.63",
        )?,
        depth: require_trace_field(
            trace_depth,
            "SWm Trace-Data requires Trace-Depth",
            outer_offset,
            "7.3.63",
        )?,
        events: require_trace_field(
            events,
            "SWm Trace-Data requires the PGW Trace-Event-List",
            outer_offset,
            "7.3.63",
        )?,
        explicit_pdn_gateway_target: explicit_pdn_gateway_target.is_some(),
        interfaces,
        collection_entity: require_trace_field(
            collection_entity,
            "SWm Trace-Data requires Trace-Collection-Entity",
            outer_offset,
            "7.3.63",
        )?,
        reporting_consumer_uri,
        additional_avps,
        origin: SwmTraceValueOrigin::Received,
    })
}

pub(super) fn append_trace_info(
    dst: &mut BytesMut,
    trace_info: &SwmTraceInfo,
    purpose: SwmTraceEncodePurpose,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    trace_info
        .validate_for_encode(purpose)
        .map_err(trace_encode_error)?;
    let mut children = BytesMut::new();
    append_trace_data(&mut children, &trace_info.data, ctx)?;
    for additional in &trace_info.additional_avps {
        additional.append_to(&mut children, ctx)?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_TRACE_INFO, VENDOR_ID_3GPP, false),
        &children,
        ctx,
    )
}

fn append_trace_data(
    dst: &mut BytesMut,
    data: &SwmTraceData,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut children = BytesMut::new();
    builder_helpers::append_vendor_octet_string_avp(
        &mut children,
        AVP_TRACE_REFERENCE,
        VENDOR_ID_3GPP,
        &data.trace_reference.octets(),
        true,
        ctx,
    )?;
    builder_helpers::append_vendor_u32_avp(
        &mut children,
        AVP_TRACE_DEPTH,
        VENDOR_ID_3GPP,
        data.depth.value(),
        true,
        ctx,
    )?;
    if data.explicit_pdn_gateway_target {
        builder_helpers::append_vendor_octet_string_avp(
            &mut children,
            AVP_TRACE_NE_TYPE_LIST,
            VENDOR_ID_3GPP,
            &PGW_NE_TYPE_LIST,
            true,
            ctx,
        )?;
    }
    if let Some(interfaces) = data.interfaces {
        builder_helpers::append_vendor_octet_string_avp(
            &mut children,
            AVP_TRACE_INTERFACE_LIST,
            VENDOR_ID_3GPP,
            &interfaces.wire(),
            true,
            ctx,
        )?;
    }
    builder_helpers::append_vendor_octet_string_avp(
        &mut children,
        AVP_TRACE_EVENT_LIST,
        VENDOR_ID_3GPP,
        &data.events.wire(),
        true,
        ctx,
    )?;
    let mut address = BytesMut::new();
    builder_helpers::encode_address_value(&mut address, data.collection_entity);
    builder_helpers::append_vendor_octet_string_avp(
        &mut children,
        AVP_TRACE_COLLECTION_ENTITY,
        VENDOR_ID_3GPP,
        &address,
        true,
        ctx,
    )?;
    if let Some(uri) = data.reporting_consumer_uri.as_ref() {
        builder_helpers::append_vendor_octet_string_avp(
            &mut children,
            AVP_TRACE_REPORTING_CONSUMER_URI,
            VENDOR_ID_3GPP,
            uri.as_str().as_bytes(),
            false,
            ctx,
        )?;
    }
    for additional in &data.additional_avps {
        additional.append_to(&mut children, ctx)?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_TRACE_DATA, VENDOR_ID_3GPP, true),
        &children,
        ctx,
    )
}

fn parse_trace_reference(value: &[u8], offset: usize) -> Result<SwmTraceReference, DecodeError> {
    let octets: [u8; TRACE_REFERENCE_LEN] = value.try_into().map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "Trace-Reference must be exactly six octets",
            },
            offset,
        )
        .with_spec_ref(trace_spec("7.3.64"))
    })?;
    SwmTraceReference::from_received(octets).map_err(|_| {
        trace_decode_error_at(
            "Trace-Reference contains an invalid PLMN encoding",
            offset,
            "7.3.64",
        )
    })
}

fn parse_reporting_consumer_uri(
    value: &[u8],
    offset: usize,
) -> Result<SwmTraceReportingConsumerUri, DecodeError> {
    if value.is_empty() || value.len() > MAX_TRACE_REPORTING_CONSUMER_URI_LEN || !value.is_ascii() {
        return Err(trace_decode_error_at(
            "Trace-Reporting-Consumer-Uri must be a valid bounded HTTP(S) URI",
            offset,
            "7.3.252",
        ));
    }
    let value = std::str::from_utf8(value).map_err(|_| {
        trace_decode_error_at(
            "Trace-Reporting-Consumer-Uri must be a valid bounded HTTP(S) URI",
            offset,
            "7.3.252",
        )
    })?;
    SwmTraceReportingConsumerUri::from_received(value).map_err(|_| {
        trace_decode_error_at(
            "Trace-Reporting-Consumer-Uri must be a valid bounded HTTP(S) URI",
            offset,
            "7.3.252",
        )
    })
}

fn retain_unknown_child(
    retained: &mut Vec<SwmAdditionalAvp>,
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    section: &'static str,
    retention: &mut DiameterEapRetention,
    additional_keys: &mut HashSet<AvpKey>,
) -> Result<(), DecodeError> {
    if ctx.unknown_ie_policy == UnknownIePolicy::Reject || avp.header.flags.is_mandatory() {
        return Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
            .with_spec_ref(trace_spec(section)));
    }
    if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
        && !additional_keys.insert(avp.header.key())
    {
        return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
            .with_spec_ref(trace_spec(section)));
    }
    if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
        retention.account(avp, offset, section, ctx)?;
        retained.push(SwmAdditionalAvp::from_raw_exact(avp));
    }
    Ok(())
}

fn reject_zero_vendor(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if avp.header.vendor_id.is_some_and(|vendor| vendor.get() == 0) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "nested trace AVP Vendor-Id field must not contain zero",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
    }
    Ok(())
}

fn validate_flags(
    header: &AvpHeader,
    rules: AvpFlagRules,
    offset: usize,
    section: &'static str,
    reason: &'static str,
) -> Result<(), DecodeError> {
    // TS 29.273 table 7.2.3.1/1 note 2 and table 7.2.3.1/2 note 2
    // require a receiver that understands an AVP to ignore an M-bit mismatch.
    // The dictionary and encode path retain the canonical per-AVP M value.
    let receive_rules =
        AvpFlagRules::new(rules.vendor(), FlagRequirement::MayBeSet, rules.protected());
    lifecycle::validate_flags(header, receive_rules, offset, section).map_err(|_| {
        let flag_offset = match builder_helpers::offset_add(offset, 4, section) {
            Ok(value) => value,
            Err(_) => offset,
        };
        trace_decode_error_at(reason, flag_offset, section)
    })
}

fn require_trace_field<T>(
    value: Option<T>,
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> Result<T, DecodeError> {
    value.ok_or_else(|| trace_decode_error_at(reason, offset, section))
}

fn valid_plmn_octets(value: &[u8]) -> bool {
    let [first, second, third] = value else {
        return false;
    };
    let decimal = |nibble: u8| nibble <= 9;
    decimal(first & 0x0f)
        && decimal(first >> 4)
        && decimal(second & 0x0f)
        && (decimal(second >> 4) || second >> 4 == 0x0f)
        && decimal(third & 0x0f)
        && decimal(third >> 4)
}

fn valid_trace_reporting_uri(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TRACE_REPORTING_CONSUMER_URI_LEN || !value.is_ascii() {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let Some(path_start) = remainder.find('/') else {
        return false;
    };
    let authority = &remainder[..path_start];
    let path = &remainder[path_start..];
    !authority.is_empty()
        && !authority.contains('@')
        && valid_http_authority(authority)
        && valid_mns_path(path)
}

fn valid_http_authority(authority: &str) -> bool {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        let host = &rest[..close];
        let suffix = &rest[close + 1..];
        return std::net::Ipv6Addr::from_str(host).is_ok()
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_http_port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() || port.is_some_and(|port| !valid_http_port(port)) {
        return false;
    }
    if let Ok(address) = std::net::Ipv4Addr::from_str(host) {
        return address.to_string() == host;
    }
    if looks_like_legacy_ipv4_literal(host) {
        return false;
    }
    valid_dns_name(host)
}

fn looks_like_legacy_ipv4_literal(host: &str) -> bool {
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return true;
    }
    host.split('.').all(|component| {
        component
            .strip_prefix("0x")
            .or_else(|| component.strip_prefix("0X"))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || (!component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn valid_http_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|value| value != 0)
}

fn valid_dns_name(host: &str) -> bool {
    let host = match host.strip_suffix('.') {
        Some(value) => value,
        None => host,
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_mns_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return false;
    }
    let mut segments = path[1..].split('/');
    let mut count = 0_usize;
    if !segments.all(|segment| {
        count += 1;
        valid_mns_path_segment(segment)
    }) {
        return false;
    }
    count >= 3
}

fn valid_mns_path_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let bytes = segment.as_bytes();
    let mut index = 0;
    let mut decoded_len = 0_usize;
    let mut decoded_all_dots = true;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            let decoded = (high << 4) | low;
            if decoded.is_ascii_control() || matches!(decoded, b'/' | b'\\' | b'?' | b'#' | b'%') {
                return false;
            }
            decoded_len += 1;
            decoded_all_dots &= decoded == b'.';
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            ))
        {
            return false;
        }
        decoded_len += 1;
        decoded_all_dots &= byte == b'.';
        index += 1;
    }
    !(decoded_all_dots && matches!(decoded_len, 1 | 2))
}

fn hex_value(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

pub(super) fn trace_encode_error(error: SwmTraceValueError) -> EncodeError {
    let reason = match error {
        SwmTraceValueError::InvalidTraceReference => {
            "SWm Trace-Reference is not a valid six-octet PLMN/Trace-ID value"
        }
        SwmTraceValueError::InvalidReportingConsumerUri => {
            "SWm Trace-Reporting-Consumer-Uri is outside the supported TS 32.158 profile"
        }
        SwmTraceValueError::InvalidReplayProvenance => {
            "receive-derived SWm trace state may only be emitted by immutable parsed replay"
        }
    };
    EncodeError::new(EncodeErrorCode::Structural { reason }).with_spec_ref(trace_spec("8.2.3.13"))
}

fn trace_decode_error_at(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(trace_spec(section))
}

fn trace_spec(section: &'static str) -> SpecRef {
    SpecRef::new("3gpp", "TS29273/TS29272/TS32422", section)
}
