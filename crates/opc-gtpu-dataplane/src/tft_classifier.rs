//! Backend-neutral, fail-closed uplink TFT classifier model.
//!
//! This boundary consumes the canonical [`opc_proto_tft`] model. It classifies
//! the *inner* IP packet after shared-SA/IPsec processing and before the
//! existing marked GTP-U bearer lookup. It deliberately has no XFRM, SA, or
//! downlink TEID semantics.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, TftOperation, TrafficFlowTemplate,
};

use crate::{GtpBearerMark, GtpuError};

/// One bearer participating in a shared-PAA TFT classifier.
#[derive(Clone, PartialEq, Eq)]
pub struct TftUplinkBearer {
    mark: Option<GtpBearerMark>,
    tft: Option<TrafficFlowTemplate>,
}

impl TftUplinkBearer {
    /// Construct the single unfiltered/default bearer. Its mark is always zero.
    #[must_use]
    pub const fn default_bearer() -> Self {
        Self {
            mark: None,
            tft: None,
        }
    }

    /// Construct a dedicated bearer with one complete canonical TFT snapshot.
    #[must_use]
    pub fn dedicated(mark: GtpBearerMark, tft: TrafficFlowTemplate) -> Self {
        Self {
            mark: Some(mark),
            tft: Some(tft),
        }
    }

    /// Mark selected when this bearer's TFT matches.
    #[must_use]
    pub const fn mark(&self) -> Option<GtpBearerMark> {
        self.mark
    }

    /// Complete canonical TFT snapshot, if this is a filtered bearer.
    #[must_use]
    pub const fn tft(&self) -> Option<&TrafficFlowTemplate> {
        self.tft.as_ref()
    }
}

impl fmt::Debug for TftUplinkBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftUplinkBearer")
            .field(
                "kind",
                &if self.tft.is_some() {
                    "filtered"
                } else {
                    "default"
                },
            )
            .field("mark", &self.mark.map(|_| "<redacted>"))
            .finish()
    }
}

/// Exact desired classifier for a single shared-PAA attachment.
#[derive(Clone, PartialEq, Eq)]
pub struct TftUplinkClassifier {
    link_ifindex: u32,
    paa: IpAddr,
    bearers: Vec<TftUplinkBearer>,
}

impl TftUplinkClassifier {
    /// Validate one complete classifier snapshot.
    ///
    /// A packet is considered uplink only when its inner source equals `paa`.
    /// At most one unfiltered bearer may exist; it is the ETSI fallback. If it
    /// is absent and no TFT matches, the packet is discarded.
    pub fn new(
        link_ifindex: u32,
        paa: IpAddr,
        bearers: Vec<TftUplinkBearer>,
    ) -> Result<Self, GtpuError> {
        if link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "tft_uplink_classifier.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        if paa.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "tft_uplink_classifier.paa",
                "PAA must not be unspecified",
            ));
        }
        if bearers.is_empty() {
            return Err(GtpuError::invalid_config(
                "tft_uplink_classifier.bearers",
                "at least one bearer is required",
            ));
        }

        let mut default = None;
        let mut dedicated = Vec::with_capacity(bearers.len());
        let mut marks = Vec::with_capacity(bearers.len());
        let mut precedences = [false; 256];
        for bearer in bearers {
            match (bearer.mark, bearer.tft) {
                (None, None) => {
                    if default.replace(TftUplinkBearer::default_bearer()).is_some() {
                        return Err(GtpuError::invalid_config(
                            "tft_uplink_classifier.bearers",
                            "multiple unfiltered bearers conflict",
                        ));
                    }
                }
                (Some(mark), Some(tft)) => {
                    if marks.contains(&mark) {
                        return Err(GtpuError::invalid_config(
                            "tft_uplink_classifier.bearers",
                            "duplicate bearer ownership",
                        ));
                    }
                    marks.push(mark);
                    validate_tft(&tft, &mut precedences)?;
                    dedicated.push(TftUplinkBearer::dedicated(mark, canonicalize_tft(&tft)?));
                }
                _ => {
                    return Err(GtpuError::invalid_config(
                        "tft_uplink_classifier.bearers",
                        "default and filtered bearer ownership must be explicit",
                    ));
                }
            }
        }
        dedicated.sort_by_key(|bearer| bearer.mark());
        let mut canonical_bearers =
            Vec::with_capacity(dedicated.len() + usize::from(default.is_some()));
        if let Some(default) = default {
            canonical_bearers.push(default);
        }
        canonical_bearers.extend(dedicated);
        Ok(Self {
            link_ifindex,
            paa,
            bearers: canonical_bearers,
        })
    }

    /// Attachment interface index.
    #[must_use]
    pub const fn link_ifindex(&self) -> u32 {
        self.link_ifindex
    }

    /// Shared subscriber PAA. This value is redacted in diagnostics.
    #[must_use]
    pub const fn paa(&self) -> IpAddr {
        self.paa
    }

    /// Ordered configured bearer snapshots.
    #[must_use]
    pub fn bearers(&self) -> &[TftUplinkBearer] {
        &self.bearers
    }

    /// Classify an exact inner IPv4 or IPv6 packet.
    ///
    /// Truncated, fragmented, extension-header, or otherwise unsupported
    /// packets never fall through to a default bearer: they are dropped.
    #[must_use]
    pub fn classify(&self, packet: &[u8]) -> TftUplinkClassification {
        let parsed = match ParsedPacket::parse(packet) {
            Ok(parsed) => parsed,
            Err(reason) => return TftUplinkClassification::Drop(reason),
        };
        if parsed.local != self.paa {
            return TftUplinkClassification::Drop(TftUplinkDropReason::PaaMismatch);
        }

        let mut selected: Option<(u8, Option<GtpBearerMark>)> = None;
        for bearer in &self.bearers {
            let Some(tft) = bearer.tft() else {
                continue;
            };
            let Some(filters) = tft.packet_filters().filters() else {
                return TftUplinkClassification::Drop(TftUplinkDropReason::InvalidState);
            };
            for filter in filters {
                if filter_matches(filter, &parsed) {
                    let candidate = (filter.evaluation_precedence(), bearer.mark());
                    if selected.is_none_or(|current| candidate.0 < current.0) {
                        selected = Some(candidate);
                    }
                }
            }
        }
        if let Some((_, mark)) = selected {
            return TftUplinkClassification::Selected(mark);
        }
        if self.bearers.iter().any(|bearer| bearer.tft().is_none()) {
            TftUplinkClassification::Selected(None)
        } else {
            TftUplinkClassification::Drop(TftUplinkDropReason::NoMatch)
        }
    }
}

impl fmt::Debug for TftUplinkClassifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TftUplinkClassifier")
            .field("attachment", &"<redacted>")
            .field("bearer_count", &self.bearers.len())
            .finish()
    }
}

/// Value-independent reason an unmarked packet was not classified.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftUplinkDropReason {
    /// The input was malformed, truncated, fragmented, or unsafe to parse.
    MalformedOrUnsupportedPacket,
    /// The packet's source does not equal the owned shared PAA.
    PaaMismatch,
    /// No filter matched and there is no unfiltered/default bearer.
    NoMatch,
    /// Readback or in-memory state contradicted the validated desired object.
    InvalidState,
}

/// Result of selecting a bearer for one inner uplink packet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TftUplinkClassification {
    /// Mark to feed to the existing bearer lookup; `None` is the default mark zero.
    Selected(Option<GtpBearerMark>),
    /// Packet must be silently discarded.
    Drop(TftUplinkDropReason),
}

impl fmt::Debug for TftUplinkClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(mark) => f
                .debug_tuple("TftUplinkClassification::Selected")
                .field(&mark.map(|_| "<redacted>"))
                .finish(),
            Self::Drop(reason) => f
                .debug_tuple("TftUplinkClassification::Drop")
                .field(reason)
                .finish(),
        }
    }
}

/// Exact classifier readback result.
#[derive(Clone, PartialEq, Eq)]
pub enum TftUplinkClassifierReadback {
    /// No classifier owns this attachment/PAA.
    Absent,
    /// One complete owned classifier is present.
    Present(TftUplinkClassifier),
    /// State was partial, stale, or cannot be proven complete.
    Indeterminate,
}

impl fmt::Debug for TftUplinkClassifierReadback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("TftUplinkClassifierReadback::Absent"),
            Self::Present(value) => f
                .debug_tuple("TftUplinkClassifierReadback::Present")
                .field(value)
                .finish(),
            Self::Indeterminate => f.write_str("TftUplinkClassifierReadback::Indeterminate"),
        }
    }
}

/// Exact reconciliation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftUplinkClassifierReconcileOutcome {
    /// The previously absent classifier was installed.
    Installed,
    /// The exact desired classifier was already installed.
    AlreadyPresent,
    /// A different complete self-owned classifier was atomically replaced.
    ///
    /// No transient absent classifier or classifier with wrong bearer ownership
    /// was published.
    Replaced,
    /// A complete classifier owned by another authority owns this attachment/PAA.
    Conflict,
    /// State was partial, mixed, stale, or otherwise cannot be proven complete.
    /// No mutation was authorized.
    Indeterminate,
}

/// Exact removal result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftUplinkClassifierRemovalOutcome {
    /// Exact owned state was removed.
    Removed,
    /// No classifier was present.
    AlreadyAbsent,
    /// Another classifier owns the attachment/PAA.
    Conflict,
    /// State was incomplete or stale, or post-publication cleanup could not
    /// be confirmed. An exact retry is required and may finish cleanup that
    /// already began.
    Indeterminate,
}

fn validate_tft(tft: &TrafficFlowTemplate, precedences: &mut [bool; 256]) -> Result<(), GtpuError> {
    if !matches!(tft.operation(), TftOperation::CreateNew) || !tft.parameters().is_empty() {
        return Err(GtpuError::invalid_config(
            "tft_uplink_classifier.tft",
            "only complete create-new TFT snapshots are supported",
        ));
    }
    let filters = tft.packet_filters().filters().ok_or_else(|| {
        GtpuError::invalid_config(
            "tft_uplink_classifier.tft",
            "full packet filters are required",
        )
    })?;
    for filter in filters {
        if !matches!(
            filter.direction(),
            PacketFilterDirection::UplinkOnly | PacketFilterDirection::Bidirectional
        ) {
            return Err(GtpuError::invalid_config(
                "tft_uplink_classifier.direction",
                "only uplink or bidirectional filters are supported",
            ));
        }
        let precedence = usize::from(filter.evaluation_precedence());
        if precedences[precedence] {
            return Err(GtpuError::invalid_config(
                "tft_uplink_classifier.precedence",
                "duplicate classification ownership",
            ));
        }
        precedences[precedence] = true;
        for component in filter.components() {
            if !matches!(
                component,
                PacketFilterComponent::Ipv4RemoteAddress { .. }
                    | PacketFilterComponent::Ipv4LocalAddress { .. }
                    | PacketFilterComponent::Ipv6RemoteAddress { .. }
                    | PacketFilterComponent::Ipv6RemoteAddressPrefix(_)
                    | PacketFilterComponent::Ipv6LocalAddressPrefix(_)
                    | PacketFilterComponent::ProtocolIdentifierNextHeader(_)
                    | PacketFilterComponent::SingleLocalPort(_)
                    | PacketFilterComponent::LocalPortRange(_)
                    | PacketFilterComponent::SingleRemotePort(_)
                    | PacketFilterComponent::RemotePortRange(_)
                    | PacketFilterComponent::SecurityParameterIndex(_)
                    | PacketFilterComponent::TypeOfServiceTrafficClass { .. }
                    | PacketFilterComponent::FlowLabel(_)
            ) {
                return Err(GtpuError::invalid_config(
                    "tft_uplink_classifier.component",
                    "packet-filter component is unsupported",
                ));
            }
        }
    }
    Ok(())
}

/// Rebuild a complete TFT in the classifier's semantic canonical form.
///
/// Packet filters are ordered by global evaluation precedence and their
/// components by the standardized component-type code. The latter is a stable
/// category order that retains both a single-port component and an equal-end
/// range as distinct public model values.
fn canonicalize_tft(tft: &TrafficFlowTemplate) -> Result<TrafficFlowTemplate, GtpuError> {
    let filters = tft.packet_filters().filters().ok_or_else(|| {
        GtpuError::invalid_config(
            "tft_uplink_classifier.tft",
            "full packet filters are required",
        )
    })?;
    let mut canonical_filters = Vec::with_capacity(filters.len());
    for filter in filters {
        let mut components = filter.components().to_vec();
        components.sort_by_key(|component| component.kind().type_code());
        let canonical_filter = PacketFilter::new(
            filter.identifier(),
            filter.direction(),
            filter.evaluation_precedence(),
            components,
        )
        .map_err(|_| {
            GtpuError::invalid_config(
                "tft_uplink_classifier.tft",
                "canonical TFT reconstruction failed",
            )
        })?;
        canonical_filters.push(canonical_filter);
    }
    canonical_filters.sort_by_key(PacketFilter::evaluation_precedence);
    TrafficFlowTemplate::create_new(canonical_filters, Vec::new()).map_err(|_| {
        GtpuError::invalid_config(
            "tft_uplink_classifier.tft",
            "canonical TFT reconstruction failed",
        )
    })
}

#[derive(Clone, Copy)]
struct ParsedPacket {
    local: IpAddr,
    remote: IpAddr,
    protocol: u8,
    traffic_class: u8,
    flow_label: Option<u32>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    spi: Option<u32>,
}

impl ParsedPacket {
    fn parse(packet: &[u8]) -> Result<Self, TftUplinkDropReason> {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => Self::parse_ipv4(packet),
            Some(6) => Self::parse_ipv6(packet),
            _ => Err(TftUplinkDropReason::MalformedOrUnsupportedPacket),
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Result<Self, TftUplinkDropReason> {
        if packet.len() < 20 {
            return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket);
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if header_len < 20
            || header_len > packet.len()
            || total_len != packet.len()
            || total_len < header_len
            || fragment & 0xbfff != 0
        {
            return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket);
        }
        Self::with_transport(
            IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            packet[9],
            packet[1],
            None,
            &packet[header_len..],
        )
    }

    fn parse_ipv6(packet: &[u8]) -> Result<Self, TftUplinkDropReason> {
        if packet.len() < 40
            || usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len()
        {
            return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket);
        }
        let next_header = packet[6];
        if matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
            return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket);
        }
        let traffic_class = ((packet[0] & 0x0f) << 4) | (packet[1] >> 4);
        let flow_label = (u32::from(packet[1] & 0x0f) << 16)
            | (u32::from(packet[2]) << 8)
            | u32::from(packet[3]);
        let mut source = [0_u8; 16];
        let mut destination = [0_u8; 16];
        source.copy_from_slice(&packet[8..24]);
        destination.copy_from_slice(&packet[24..40]);
        Self::with_transport(
            IpAddr::V6(Ipv6Addr::from(source)),
            IpAddr::V6(Ipv6Addr::from(destination)),
            next_header,
            traffic_class,
            Some(flow_label),
            &packet[40..],
        )
    }

    fn with_transport(
        local: IpAddr,
        remote: IpAddr,
        protocol: u8,
        traffic_class: u8,
        flow_label: Option<u32>,
        payload: &[u8],
    ) -> Result<Self, TftUplinkDropReason> {
        let (local_port, remote_port) = match protocol {
            6 if payload.len() >= 20
                && usize::from(payload[12] >> 4) * 4 <= payload.len()
                && payload[12] >> 4 >= 5 =>
            {
                (
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                )
            }
            17 if payload.len() >= 8
                && usize::from(u16::from_be_bytes([payload[4], payload[5]])) == payload.len() =>
            {
                (
                    Some(u16::from_be_bytes([payload[0], payload[1]])),
                    Some(u16::from_be_bytes([payload[2], payload[3]])),
                )
            }
            6 | 17 => return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket),
            _ => (None, None),
        };
        let spi = if protocol == 50 {
            if payload.len() < 8 {
                return Err(TftUplinkDropReason::MalformedOrUnsupportedPacket);
            }
            Some(u32::from_be_bytes([
                payload[0], payload[1], payload[2], payload[3],
            ]))
        } else {
            None
        };
        Ok(Self {
            local,
            remote,
            protocol,
            traffic_class,
            flow_label,
            local_port,
            remote_port,
            spi,
        })
    }
}

fn filter_matches(filter: &PacketFilter, packet: &ParsedPacket) -> bool {
    filter.components().iter().all(|component| match component {
        PacketFilterComponent::Ipv4LocalAddress { address, mask } => match packet.local {
            IpAddr::V4(value) => masked_ipv4(value, *address, *mask),
            IpAddr::V6(_) => false,
        },
        PacketFilterComponent::Ipv4RemoteAddress { address, mask } => match packet.remote {
            IpAddr::V4(value) => masked_ipv4(value, *address, *mask),
            IpAddr::V6(_) => false,
        },
        PacketFilterComponent::Ipv6RemoteAddress { address, mask } => match packet.remote {
            IpAddr::V6(value) => masked_ipv6(value, *address, *mask),
            IpAddr::V4(_) => false,
        },
        PacketFilterComponent::Ipv6LocalAddressPrefix(prefix) => match packet.local {
            IpAddr::V6(value) => prefix_matches(value, prefix.address(), prefix.prefix_length()),
            IpAddr::V4(_) => false,
        },
        PacketFilterComponent::Ipv6RemoteAddressPrefix(prefix) => match packet.remote {
            IpAddr::V6(value) => prefix_matches(value, prefix.address(), prefix.prefix_length()),
            IpAddr::V4(_) => false,
        },
        PacketFilterComponent::ProtocolIdentifierNextHeader(value) => packet.protocol == *value,
        PacketFilterComponent::SingleLocalPort(value) => packet.local_port == Some(*value),
        PacketFilterComponent::LocalPortRange(range) => packet
            .local_port
            .is_some_and(|port| port >= range.low() && port <= range.high()),
        PacketFilterComponent::SingleRemotePort(value) => packet.remote_port == Some(*value),
        PacketFilterComponent::RemotePortRange(range) => packet
            .remote_port
            .is_some_and(|port| port >= range.low() && port <= range.high()),
        PacketFilterComponent::SecurityParameterIndex(value) => packet.spi == Some(*value),
        PacketFilterComponent::TypeOfServiceTrafficClass { value, mask } => {
            packet.traffic_class & mask == value & mask
        }
        PacketFilterComponent::FlowLabel(value) => packet.flow_label == Some(value.value()),
        _ => false,
    })
}

fn masked_ipv4(value: Ipv4Addr, address: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(value) & u32::from(mask) == u32::from(address) & u32::from(mask)
}

fn masked_ipv6(value: Ipv6Addr, address: Ipv6Addr, mask: Ipv6Addr) -> bool {
    value
        .octets()
        .iter()
        .zip(address.octets())
        .zip(mask.octets())
        .all(|((actual, expected), mask)| actual & mask == expected & mask)
}

fn prefix_matches(value: Ipv6Addr, address: Ipv6Addr, prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    let remaining = prefix % 8;
    value.octets()[..full_bytes] == address.octets()[..full_bytes]
        && (remaining == 0
            || value.octets()[full_bytes] & (!0_u8 << (8 - remaining))
                == address.octets()[full_bytes] & (!0_u8 << (8 - remaining)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_proto_tft::{PacketFilterComponent, PacketFilterIdentifier, TrafficFlowTemplate};

    fn filter(precedence: u8, components: Vec<PacketFilterComponent>) -> PacketFilter {
        PacketFilter::new(
            PacketFilterIdentifier::new(precedence % 16).unwrap(),
            PacketFilterDirection::UplinkOnly,
            precedence,
            components,
        )
        .unwrap()
    }

    fn ipv4_udp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    fn ipv6_udp(
        source: [u8; 16],
        destination: [u8; 16],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x6a;
        packet[1] = 0xb1;
        packet[2] = 0x23;
        packet[3] = 0x45;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    fn dedicated(
        mark: u32,
        precedence: u8,
        components: Vec<PacketFilterComponent>,
    ) -> TftUplinkBearer {
        TftUplinkBearer::dedicated(
            GtpBearerMark::new(mark).unwrap(),
            TrafficFlowTemplate::create_new(vec![filter(precedence, components)], vec![]).unwrap(),
        )
    }

    #[test]
    fn selects_lowest_precedence_then_default_and_discards_without_default() {
        let classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![
                TftUplinkBearer::default_bearer(),
                dedicated(
                    11,
                    50,
                    vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
                ),
                dedicated(12, 10, vec![PacketFilterComponent::SingleRemotePort(443)]),
            ],
        )
        .unwrap();
        let packet = ipv4_udp([10, 0, 0, 1], [192, 0, 2, 1], 40000, 443);
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Selected(GtpBearerMark::new(12))
        );
        let packet = ipv4_udp([10, 0, 0, 1], [192, 0, 2, 1], 40000, 80);
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Selected(GtpBearerMark::new(11))
        );

        let no_default = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![dedicated(
                11,
                50,
                vec![PacketFilterComponent::SingleRemotePort(443)],
            )],
        )
        .unwrap();
        assert_eq!(
            no_default.classify(&packet),
            TftUplinkClassification::Drop(TftUplinkDropReason::NoMatch)
        );
    }

    #[test]
    fn rejects_conflicting_ownership_and_unsupported_tft_direction() {
        let one = dedicated(
            11,
            1,
            vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
        );
        let two = dedicated(
            12,
            1,
            vec![PacketFilterComponent::ProtocolIdentifierNextHeader(6)],
        );
        assert!(TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![one, two]
        )
        .is_err());
        let filter = PacketFilter::new(
            PacketFilterIdentifier::new(1).unwrap(),
            PacketFilterDirection::DownlinkOnly,
            1,
            vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
        )
        .unwrap();
        let invalid = TftUplinkBearer::dedicated(
            GtpBearerMark::new(9).unwrap(),
            TrafficFlowTemplate::create_new(vec![filter], vec![]).unwrap(),
        );
        assert!(
            TftUplinkClassifier::new(7, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), vec![invalid])
                .is_err()
        );
        let replacement = TftUplinkBearer::dedicated(
            GtpBearerMark::new(10).unwrap(),
            TrafficFlowTemplate::replace_packet_filters(
                vec![PacketFilter::new(
                    PacketFilterIdentifier::new(2).unwrap(),
                    PacketFilterDirection::UplinkOnly,
                    2,
                    vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
                )
                .unwrap()],
                vec![],
            )
            .unwrap(),
        );
        assert!(TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![replacement]
        )
        .is_err());
    }

    #[test]
    fn accepts_and_canonicalizes_sixteen_filters_across_two_dedicated_tfts() {
        let packet_component = || PacketFilterComponent::ProtocolIdentifierNextHeader(17);
        let higher_precedences = (8_u8..16)
            .rev()
            .map(|precedence| filter(precedence, vec![packet_component()]))
            .collect();
        let lower_precedences = (0_u8..8)
            .rev()
            .map(|precedence| filter(precedence, vec![packet_component()]))
            .collect();
        let classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(20).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(higher_precedences, Vec::new())
                        .expect("synthetic complete TFT"),
                ),
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(10).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(lower_precedences, Vec::new())
                        .expect("synthetic complete TFT"),
                ),
            ],
        )
        .expect("two valid dedicated TFTs fit one classifier snapshot");

        assert_eq!(classifier.bearers()[0].mark(), GtpBearerMark::new(10));
        assert_eq!(classifier.bearers()[1].mark(), GtpBearerMark::new(20));
        let canonical_precedences = |bearer: &TftUplinkBearer| {
            bearer
                .tft()
                .and_then(|tft| tft.packet_filters().filters())
                .expect("canonical dedicated TFT")
                .iter()
                .map(PacketFilter::evaluation_precedence)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            canonical_precedences(&classifier.bearers()[0]),
            (0_u8..8).collect::<Vec<_>>()
        );
        assert_eq!(
            canonical_precedences(&classifier.bearers()[1]),
            (8_u8..16).collect::<Vec<_>>()
        );
    }

    #[test]
    fn canonicalizes_bearer_filter_and_component_permutations_exactly() {
        let paa = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let first = PacketFilter::new(
            PacketFilterIdentifier::new(15).expect("synthetic identifier"),
            PacketFilterDirection::Bidirectional,
            30,
            vec![
                PacketFilterComponent::SingleRemotePort(443),
                PacketFilterComponent::ProtocolIdentifierNextHeader(17),
            ],
        )
        .expect("synthetic filter");
        let second = PacketFilter::new(
            PacketFilterIdentifier::new(0).expect("synthetic identifier"),
            PacketFilterDirection::UplinkOnly,
            10,
            vec![PacketFilterComponent::SingleLocalPort(40_000)],
        )
        .expect("synthetic filter");
        let reordered_first = PacketFilter::new(
            PacketFilterIdentifier::new(15).expect("synthetic identifier"),
            PacketFilterDirection::Bidirectional,
            30,
            vec![
                PacketFilterComponent::ProtocolIdentifierNextHeader(17),
                PacketFilterComponent::SingleRemotePort(443),
            ],
        )
        .expect("synthetic filter");
        let left = TftUplinkClassifier::new(
            7,
            paa,
            vec![
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(20).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(vec![first], vec![]).expect("synthetic TFT"),
                ),
                TftUplinkBearer::default_bearer(),
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(10).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(vec![second], vec![]).expect("synthetic TFT"),
                ),
            ],
        )
        .expect("canonical classifier");
        let right = TftUplinkClassifier::new(
            7,
            paa,
            vec![
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(10).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(
                        vec![PacketFilter::new(
                            PacketFilterIdentifier::new(0).expect("synthetic identifier"),
                            PacketFilterDirection::UplinkOnly,
                            10,
                            vec![PacketFilterComponent::SingleLocalPort(40_000)],
                        )
                        .expect("synthetic filter")],
                        vec![],
                    )
                    .expect("synthetic TFT"),
                ),
                TftUplinkBearer::dedicated(
                    GtpBearerMark::new(20).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(vec![reordered_first], vec![])
                        .expect("synthetic TFT"),
                ),
                TftUplinkBearer::default_bearer(),
            ],
        )
        .expect("canonical classifier");
        assert_eq!(left, right);
        assert_eq!(left.bearers()[0].mark(), None);
        assert_eq!(left.bearers()[1].mark(), GtpBearerMark::new(10));
        assert_eq!(left.bearers()[2].mark(), GtpBearerMark::new(20));
        let filter = left.bearers()[2]
            .tft()
            .and_then(|tft| tft.packet_filters().filters())
            .and_then(|filters| filters.first())
            .expect("canonical filter");
        assert_eq!(filter.identifier().value(), 15);
        assert_eq!(filter.direction(), PacketFilterDirection::Bidirectional);
        assert!(matches!(
            filter.components(),
            [
                PacketFilterComponent::ProtocolIdentifierNextHeader(17),
                PacketFilterComponent::SingleRemotePort(443)
            ]
        ));
        assert!(!format!("{left:?}").contains("10.0.0.1"));
    }

    #[test]
    fn exact_tft_identifier_direction_and_port_form_remain_distinct() {
        let paa = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let classifier = |identifier, direction, component| {
            TftUplinkClassifier::new(
                7,
                paa,
                vec![TftUplinkBearer::dedicated(
                    GtpBearerMark::new(10).expect("synthetic mark"),
                    TrafficFlowTemplate::create_new(
                        vec![PacketFilter::new(identifier, direction, 1, vec![component])
                            .expect("synthetic filter")],
                        vec![],
                    )
                    .expect("synthetic TFT"),
                )],
            )
            .expect("classifier")
        };
        let single = classifier(
            PacketFilterIdentifier::new(0).expect("synthetic identifier"),
            PacketFilterDirection::UplinkOnly,
            PacketFilterComponent::SingleRemotePort(443),
        );
        let range = classifier(
            PacketFilterIdentifier::new(0).expect("synthetic identifier"),
            PacketFilterDirection::UplinkOnly,
            PacketFilterComponent::RemotePortRange(
                opc_proto_tft::PortRange::new(443, 443).expect("synthetic range"),
            ),
        );
        let different_identifier = classifier(
            PacketFilterIdentifier::new(15).expect("synthetic identifier"),
            PacketFilterDirection::UplinkOnly,
            PacketFilterComponent::SingleRemotePort(443),
        );
        let bidirectional = classifier(
            PacketFilterIdentifier::new(0).expect("synthetic identifier"),
            PacketFilterDirection::Bidirectional,
            PacketFilterComponent::SingleRemotePort(443),
        );
        assert_ne!(single, range);
        assert_ne!(single, different_identifier);
        assert_ne!(single, bidirectional);
    }

    #[test]
    fn malformed_or_wrong_paa_never_falls_through_to_default() {
        let classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![TftUplinkBearer::default_bearer()],
        )
        .unwrap();
        assert_eq!(
            classifier.classify(&[0x45]),
            TftUplinkClassification::Drop(TftUplinkDropReason::MalformedOrUnsupportedPacket)
        );
        let packet = ipv4_udp([10, 0, 0, 2], [192, 0, 2, 1], 1, 2);
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Drop(TftUplinkDropReason::PaaMismatch)
        );
        let mut reserved_fragment = ipv4_udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        reserved_fragment[6] = 0x80;
        assert_eq!(
            classifier.classify(&reserved_fragment),
            TftUplinkClassification::Drop(TftUplinkDropReason::MalformedOrUnsupportedPacket)
        );
        let mut dont_fragment = ipv4_udp([10, 0, 0, 1], [192, 0, 2, 1], 1, 2);
        dont_fragment[6] = 0x40;
        assert_eq!(
            classifier.classify(&dont_fragment),
            TftUplinkClassification::Selected(None)
        );
    }

    #[test]
    fn ipv6_extension_headers_never_fall_through_or_match_as_protocols() {
        let source = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        for next_header in [135, 139, 140] {
            let classifier = TftUplinkClassifier::new(
                7,
                IpAddr::V6(Ipv6Addr::from(source)),
                vec![
                    TftUplinkBearer::default_bearer(),
                    dedicated(
                        11,
                        next_header,
                        vec![PacketFilterComponent::ProtocolIdentifierNextHeader(
                            next_header,
                        )],
                    ),
                ],
            )
            .unwrap();
            let mut packet = vec![0_u8; 40];
            packet[0] = 0x60;
            packet[6] = next_header;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source);
            packet[24..40].copy_from_slice(&destination);
            assert_eq!(
                classifier.classify(&packet),
                TftUplinkClassification::Drop(TftUplinkDropReason::MalformedOrUnsupportedPacket)
            );
        }
    }

    #[test]
    fn tos_matching_masks_ignored_bits_on_both_operands() {
        let classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![dedicated(
                11,
                1,
                vec![PacketFilterComponent::TypeOfServiceTrafficClass {
                    value: 0x21,
                    mask: 0xf0,
                }],
            )],
        )
        .expect("raw ToS value and mask are representable");
        let mut packet = ipv4_udp([10, 0, 0, 1], [192, 0, 2, 1], 40_000, 443);
        packet[1] = 0x20;
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Selected(GtpBearerMark::new(11))
        );
        packet[1] = 0x30;
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Drop(TftUplinkDropReason::NoMatch)
        );
    }

    #[test]
    fn matches_representable_ipv6_components_and_esp_spi() {
        let source = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V6(Ipv6Addr::from(source)),
            vec![dedicated(
                12,
                1,
                vec![
                    PacketFilterComponent::Ipv6LocalAddressPrefix(
                        opc_proto_tft::Ipv6AddressPrefix::new(Ipv6Addr::from(source), 64).unwrap(),
                    ),
                    PacketFilterComponent::Ipv6RemoteAddressPrefix(
                        opc_proto_tft::Ipv6AddressPrefix::new(Ipv6Addr::from(destination), 64)
                            .unwrap(),
                    ),
                    PacketFilterComponent::ProtocolIdentifierNextHeader(17),
                    PacketFilterComponent::LocalPortRange(
                        opc_proto_tft::PortRange::new(40_000, 40_100).unwrap(),
                    ),
                    PacketFilterComponent::RemotePortRange(
                        opc_proto_tft::PortRange::new(443, 443).unwrap(),
                    ),
                    PacketFilterComponent::TypeOfServiceTrafficClass {
                        value: 0xab,
                        mask: 0xff,
                    },
                ],
            )],
        )
        .unwrap();
        assert_eq!(
            classifier.classify(&ipv6_udp(source, destination, 40_001, 443)),
            TftUplinkClassification::Selected(GtpBearerMark::new(12))
        );

        let flow_classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V6(Ipv6Addr::from(source)),
            vec![dedicated(
                14,
                3,
                vec![PacketFilterComponent::FlowLabel(
                    opc_proto_tft::Ipv6FlowLabel::new(0x12345).unwrap(),
                )],
            )],
        )
        .unwrap();
        assert_eq!(
            flow_classifier.classify(&ipv6_udp(source, destination, 40_001, 443)),
            TftUplinkClassification::Selected(GtpBearerMark::new(14))
        );

        let esp = {
            let mut packet = vec![0_u8; 28];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
            packet[9] = 50;
            packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
            packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
            packet[20..24].copy_from_slice(&0x1020_3040_u32.to_be_bytes());
            packet
        };
        let esp_classifier = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![dedicated(
                13,
                2,
                vec![
                    PacketFilterComponent::ProtocolIdentifierNextHeader(50),
                    PacketFilterComponent::SecurityParameterIndex(0x1020_3040),
                ],
            )],
        )
        .unwrap();
        assert_eq!(
            esp_classifier.classify(&esp),
            TftUplinkClassification::Selected(GtpBearerMark::new(13))
        );
    }

    #[test]
    fn diagnostics_do_not_expose_packet_or_mark_values() {
        let result = TftUplinkClassification::Selected(GtpBearerMark::new(0xfeed_beef));
        assert!(!format!("{result:?}").contains("feed"));
    }
}
