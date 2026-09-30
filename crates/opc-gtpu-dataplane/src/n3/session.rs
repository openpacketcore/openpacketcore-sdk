//! Experimental RFC 021 N3IWF PDU session intent and lifecycle contract.
//!
//! [`N3iwfSessionIntent`] is the complete desired forwarding state of one PDU
//! session relayed between NWu user-plane Child SAs and one N3 tunnel pair:
//! the QoS flows received over N2, the logical Child SAs with their NWu inner
//! addresses and explicitly associated QFIs, exactly one default Child SA, and
//! the caller's declared disposition for a downlink QFI outside the session.
//! There is no PAA: the N3IWF never learns the PDU address it would need.
//!
//! Construction validates the exact rules of RFC 021 section 5.2 and
//! canonicalizes order, so equal content always compares equal. The pure
//! [`N3iwfSessionIntent::uplink_admission`] and
//! [`N3iwfSessionIntent::downlink_selection`] functions encode the receiver
//! dispositions of RFC 021 section 6 and are the reference model for any
//! datapath.
//!
//! These values are desired state only. They authenticate no peer, prove no
//! address ownership, allocate no TEID or mark, install no XFRM state and grant
//! no mutation authority. Lifecycle operations live on
//! [`crate::GtpuDataplaneBackend`] and default to
//! [`crate::GtpuError::UnsupportedFeature`]. Every value-bearing type redacts
//! its complete `Debug` output; errors carry only static reasons.

use std::{
    fmt,
    iter::FusedIterator,
    net::IpAddr,
    num::{NonZeroU32, NonZeroU64},
};

use opc_types::DscpCodepoint;
use thiserror::Error;

use super::{LocalN3DownlinkTnl, N3Qfi, ReceivedN3UplinkTnl};
use crate::{
    GtpBearerMark, GtpDevice, GtpuCapability, GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy,
    PdpContextIndeterminateReason, PdpContextRepairReason, PdpDeviceIncarnation,
    PdpLiveWriterProof, PdpRestartRecoveryProof,
};

/// Maximum user-plane Child SAs in one session intent.
///
/// This is SDK policy (RFC 021 section 5.4), not a 3GPP limit. It stays within
/// the 32-pair installed Child SA roster bound and fixes the composite record
/// size. Raising it requires a new record format version.
pub const N3IWF_SESSION_MAX_CHILD_SAS: usize = 8;

/// Stable, value-free refusal of an N3IWF session model value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum N3iwfSessionModelError {
    /// The N3 link ifindex is zero.
    #[error("N3IWF session requires a nonzero N3 link ifindex")]
    InvalidLinkIfindex,
    /// The received UPF TNL and the local N3IWF TNL use different families.
    #[error("N3IWF N3 tunnel endpoints use different address families")]
    MixedN3Family,
    /// The uplink source-port policy is not a canonical encodable value.
    #[error("N3IWF uplink source-port policy is not canonical")]
    InvalidSourcePortPolicy,
    /// An NWu inner address is unspecified, multicast, broadcast or loopback.
    #[error("N3IWF inner address must be a concrete unicast address")]
    InvalidInnerAddress,
    /// A Child SA's UE inner and UP addresses use different families.
    #[error("N3IWF Child SA inner addresses use different families")]
    MixedChildSaFamily,
    /// Two addresses that must differ are equal.
    #[error("N3IWF session address aliases another endpoint")]
    AliasedAddress,
    /// A QFI appears twice where each QFI must be unique.
    #[error("duplicate N3IWF QFI")]
    DuplicateQfi,
    /// The session has no QoS flow.
    #[error("N3IWF session requires at least one QoS flow")]
    NoQosFlows,
    /// The session has no Child SA.
    #[error("N3IWF session requires at least one Child SA")]
    NoChildSas,
    /// The session exceeds the SDK Child SA bound.
    #[error("N3IWF session Child SA limit exceeded")]
    TooManyChildSas,
    /// Two Child SAs use the same mark.
    #[error("duplicate N3IWF Child SA mark")]
    DuplicateChildSaMark,
    /// The named default Child SA is not one of the session's Child SAs.
    #[error("N3IWF default Child SA is not in the session")]
    UnknownDefaultChildSa,
    /// A Child SA associates a QFI that is not a session QoS flow.
    #[error("N3IWF Child SA associates a QFI outside the session")]
    AssociatedQfiNotInSession,
    /// One QFI is associated with more than one Child SA.
    #[error("N3IWF QFI associated with more than one Child SA")]
    QfiAssociatedTwice,
    /// Two Child SAs of one family use different UE inner addresses.
    #[error("N3IWF session uses more than one UE inner address per family")]
    InconsistentUeInnerAddress,
    /// A flow update would change the session's N3 tunnel.
    #[error("N3IWF flow update cannot change the N3 tunnel")]
    N3TunnelChanged,
}

/// Allocation-free set of QFIs 0–63.
///
/// Adding a QFI that is already present is an error, so a set built from a
/// list proves that the list had no duplicates.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct N3iwfQfiSet(u64);

impl N3iwfQfiSet {
    /// Create an empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Build a set from QFIs, refusing any duplicate.
    ///
    /// # Errors
    /// Returns [`N3iwfSessionModelError::DuplicateQfi`] for a repeated QFI.
    pub fn try_from_qfis(
        qfis: impl IntoIterator<Item = N3Qfi>,
    ) -> Result<Self, N3iwfSessionModelError> {
        let mut set = Self::empty();
        for qfi in qfis {
            set = set.try_with(qfi)?;
        }
        Ok(set)
    }

    /// Return this set with `qfi` added.
    ///
    /// # Errors
    /// Returns [`N3iwfSessionModelError::DuplicateQfi`] if `qfi` is present.
    pub const fn try_with(self, qfi: N3Qfi) -> Result<Self, N3iwfSessionModelError> {
        let bit = 1u64 << qfi.get();
        if self.0 & bit == 0 {
            Ok(Self(self.0 | bit))
        } else {
            Err(N3iwfSessionModelError::DuplicateQfi)
        }
    }

    /// Test membership.
    #[must_use]
    pub const fn contains(self, qfi: N3Qfi) -> bool {
        self.0 & (1u64 << qfi.get()) != 0
    }

    /// Number of QFIs in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Iterate in ascending QFI order without allocating.
    #[must_use]
    pub const fn iter(self) -> N3iwfQfiSetIter {
        N3iwfQfiSetIter { remaining: self.0 }
    }

    const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    const fn is_disjoint(self, other: Self) -> bool {
        self.0 & other.0 == 0
    }

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl IntoIterator for N3iwfQfiSet {
    type Item = N3Qfi;
    type IntoIter = N3iwfQfiSetIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for N3iwfQfiSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfQfiSet(<redacted>)")
    }
}

/// Ascending iterator over an [`N3iwfQfiSet`].
#[derive(Clone)]
pub struct N3iwfQfiSetIter {
    remaining: u64,
}

impl Iterator for N3iwfQfiSetIter {
    type Item = N3Qfi;

    fn next(&mut self) -> Option<N3Qfi> {
        if self.remaining == 0 {
            return None;
        }
        let index = u8::try_from(self.remaining.trailing_zeros()).ok()?;
        self.remaining &= self.remaining - 1;
        N3Qfi::new(index).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining.count_ones() as usize;
        (len, Some(len))
    }
}

impl ExactSizeIterator for N3iwfQfiSetIter {}

impl FusedIterator for N3iwfQfiSetIter {}

impl fmt::Debug for N3iwfQfiSetIter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfQfiSetIter(<redacted>)")
    }
}

/// One QoS flow of the PDU session as received over N2.
///
/// The optional DSCP is the uplink N3 packet marking for this flow (TS 23.501
/// section 6.2.9). Its value is caller policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct N3iwfQosFlow {
    qfi: N3Qfi,
    n3_uplink_dscp: Option<DscpCodepoint>,
}

impl N3iwfQosFlow {
    /// Record one session QoS flow.
    #[must_use]
    pub const fn new(qfi: N3Qfi, n3_uplink_dscp: Option<DscpCodepoint>) -> Self {
        Self {
            qfi,
            n3_uplink_dscp,
        }
    }

    /// The flow's QFI.
    #[must_use]
    pub const fn qfi(&self) -> N3Qfi {
        self.qfi
    }

    /// Optional uplink N3 outer DSCP for this flow.
    #[must_use]
    pub const fn n3_uplink_dscp(&self) -> Option<DscpCodepoint> {
        self.n3_uplink_dscp
    }
}

impl fmt::Debug for N3iwfQosFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfQosFlow(<redacted>)")
    }
}

fn check_inner_address(address: IpAddr) -> Result<(), N3iwfSessionModelError> {
    if address.is_unspecified()
        || address.is_multicast()
        || address.is_loopback()
        || matches!(address, IpAddr::V4(value) if value.is_broadcast())
    {
        Err(N3iwfSessionModelError::InvalidInnerAddress)
    } else {
        Ok(())
    }
}

/// One logical user-plane Child SA of an N3IWF PDU session.
///
/// The mark is the complete 32-bit XFRM mark the inbound SA sets and the
/// outbound policy selects; it stays stable across a rekey. The UE inner
/// address is the `INTERNAL_IP4_ADDRESS` or `INTERNAL_IP6_ADDRESS` of the IKE
/// SA and the UP address is the SA's `UP_IP4_ADDRESS` or `UP_IP6_ADDRESS`
/// (TS 24.502 section 8.3.2). The associated QFIs are the `5G_QOS_INFO` QFI
/// list, which may be empty (TS 24.502 section 9.3.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct N3iwfChildSa {
    mark: GtpBearerMark,
    ue_inner_address: IpAddr,
    up_address: IpAddr,
    associated_qfis: N3iwfQfiSet,
}

impl N3iwfChildSa {
    /// Record one Child SA.
    ///
    /// # Errors
    /// Refuses an unusable address, mixed families or equal UE inner and UP
    /// addresses.
    pub fn new(
        mark: GtpBearerMark,
        ue_inner_address: IpAddr,
        up_address: IpAddr,
        associated_qfis: N3iwfQfiSet,
    ) -> Result<Self, N3iwfSessionModelError> {
        check_inner_address(ue_inner_address)?;
        check_inner_address(up_address)?;
        if ue_inner_address.is_ipv4() != up_address.is_ipv4() {
            return Err(N3iwfSessionModelError::MixedChildSaFamily);
        }
        if ue_inner_address == up_address {
            return Err(N3iwfSessionModelError::AliasedAddress);
        }
        Ok(Self {
            mark,
            ue_inner_address,
            up_address,
            associated_qfis,
        })
    }

    /// Complete XFRM mark of this Child SA; do not log it.
    #[must_use]
    pub const fn mark(&self) -> GtpBearerMark {
        self.mark
    }

    /// UE inner address; sensitive, never log it.
    #[must_use]
    pub const fn ue_inner_address(&self) -> IpAddr {
        self.ue_inner_address
    }

    /// N3IWF UP address of this Child SA; do not log it.
    #[must_use]
    pub const fn up_address(&self) -> IpAddr {
        self.up_address
    }

    /// QFIs explicitly associated with this Child SA.
    #[must_use]
    pub const fn associated_qfis(&self) -> N3iwfQfiSet {
        self.associated_qfis
    }
}

impl fmt::Debug for N3iwfChildSa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfChildSa(<redacted>)")
    }
}

/// The N3 side of one N3IWF PDU session.
///
/// The received UPF TNL and the locally supplied N3IWF TNL keep their distinct
/// types and must use one address family. Source-port policies follow the
/// existing ordinary GTP-U contract.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct N3iwfN3Tunnel {
    link_ifindex: NonZeroU32,
    received_uplink: ReceivedN3UplinkTnl,
    local_downlink: LocalN3DownlinkTnl,
    downlink_source_port_policy: GtpuSourcePortPolicy,
    uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
}

impl N3iwfN3Tunnel {
    /// Record the N3 tunnel pair of a session.
    ///
    /// # Errors
    /// Refuses ifindex zero, mixed TNL families and a non-canonical uplink
    /// source-port policy.
    pub fn new(
        link_ifindex: u32,
        received_uplink: ReceivedN3UplinkTnl,
        local_downlink: LocalN3DownlinkTnl,
        downlink_source_port_policy: GtpuSourcePortPolicy,
        uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
    ) -> Result<Self, N3iwfSessionModelError> {
        let link_ifindex =
            NonZeroU32::new(link_ifindex).ok_or(N3iwfSessionModelError::InvalidLinkIfindex)?;
        if received_uplink.destination().is_ipv4() != local_downlink.local_address().is_ipv4() {
            return Err(N3iwfSessionModelError::MixedN3Family);
        }
        if uplink_source_port_policy.map_value().is_none() {
            return Err(N3iwfSessionModelError::InvalidSourcePortPolicy);
        }
        Ok(Self {
            link_ifindex,
            received_uplink,
            local_downlink,
            downlink_source_port_policy,
            uplink_source_port_policy,
        })
    }

    /// N3 attachment ifindex.
    #[must_use]
    pub const fn link_ifindex(&self) -> u32 {
        self.link_ifindex.get()
    }

    /// Received UPF destination.
    #[must_use]
    pub const fn received_uplink(&self) -> ReceivedN3UplinkTnl {
        self.received_uplink
    }

    /// Locally supplied N3IWF receive endpoint.
    #[must_use]
    pub const fn local_downlink(&self) -> LocalN3DownlinkTnl {
        self.local_downlink
    }

    /// Inbound G-PDU source-port authorization.
    #[must_use]
    pub const fn downlink_source_port_policy(&self) -> GtpuSourcePortPolicy {
        self.downlink_source_port_policy
    }

    /// Uplink source-port selection.
    #[must_use]
    pub const fn uplink_source_port_policy(&self) -> GtpuUplinkSourcePortPolicy {
        self.uplink_source_port_policy
    }
}

impl fmt::Debug for N3iwfN3Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfN3Tunnel(<redacted>)")
    }
}

/// Caller-declared downlink disposition for a QFI outside the session.
///
/// This is caller policy (RFC 021 section 6, row D3). There is no implicit
/// default: every session names one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum N3iwfDownlinkUnknownQfi {
    /// Drop the G-PDU.
    Drop,
    /// Send it on the default Child SA with its received QFI and RQI.
    DefaultChildSa,
}

/// Value-free uplink admission result (RFC 021 section 6, rows U1 to U4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum N3iwfUplinkAdmission {
    /// The QFI arrived on the Child SA the UE is required to use.
    Admitted,
    /// The QFI is a session flow that belongs to another Child SA.
    WrongChildSa,
    /// The QFI is not a session QoS flow.
    UnknownQfi,
    /// The mark names no Child SA of this session.
    UnknownChildSa,
}

/// Downlink Child SA selection (RFC 021 section 6, rows D1 to D3).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum N3iwfDownlinkSelection<'a> {
    /// The QFI is explicitly associated with this Child SA.
    Associated(&'a N3iwfChildSa),
    /// The QFI is a session flow without explicit association.
    SessionFlowDefault(&'a N3iwfChildSa),
    /// The QFI is outside the session and the session declared the default.
    UnknownQfiDefault(&'a N3iwfChildSa),
    /// The QFI is outside the session and the session declared a drop.
    Drop,
}

impl<'a> N3iwfDownlinkSelection<'a> {
    /// The selected Child SA, or `None` for a drop.
    #[must_use]
    pub const fn child_sa(&self) -> Option<&'a N3iwfChildSa> {
        match *self {
            Self::Associated(child_sa)
            | Self::SessionFlowDefault(child_sa)
            | Self::UnknownQfiDefault(child_sa) => Some(child_sa),
            Self::Drop => None,
        }
    }
}

impl fmt::Debug for N3iwfDownlinkSelection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Associated(_) => "Associated(<redacted>)",
            Self::SessionFlowDefault(_) => "SessionFlowDefault(<redacted>)",
            Self::UnknownQfiDefault(_) => "UnknownQfiDefault(<redacted>)",
            Self::Drop => "Drop",
        })
    }
}

/// Complete, canonical desired state of one N3IWF PDU session.
///
/// QoS flows are ordered by QFI and Child SAs by mark, so equal content always
/// compares equal regardless of input order. This value is neither an install
/// request with authority nor a readback receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct N3iwfSessionIntent {
    n3: N3iwfN3Tunnel,
    qos_flows: Vec<N3iwfQosFlow>,
    session_qfis: N3iwfQfiSet,
    child_sas: Vec<N3iwfChildSa>,
    default_child_sa: N3iwfChildSa,
    downlink_unknown_qfi: N3iwfDownlinkUnknownQfi,
}

impl N3iwfSessionIntent {
    /// Validate and canonicalize a session.
    ///
    /// Rules are checked in this order, and the first failure is returned:
    /// flows present, QFIs unique, Child SA count, marks unique, default
    /// present, associations inside the session and disjoint, one UE inner
    /// address per family, and no aliasing of the N3 endpoints.
    ///
    /// # Errors
    /// Returns the value-free [`N3iwfSessionModelError`] for the first rule
    /// the session breaks.
    pub fn new(
        n3: N3iwfN3Tunnel,
        mut qos_flows: Vec<N3iwfQosFlow>,
        mut child_sas: Vec<N3iwfChildSa>,
        default_child_sa: GtpBearerMark,
        downlink_unknown_qfi: N3iwfDownlinkUnknownQfi,
    ) -> Result<Self, N3iwfSessionModelError> {
        if qos_flows.is_empty() {
            return Err(N3iwfSessionModelError::NoQosFlows);
        }
        let session_qfis = N3iwfQfiSet::try_from_qfis(qos_flows.iter().map(N3iwfQosFlow::qfi))?;
        if child_sas.is_empty() {
            return Err(N3iwfSessionModelError::NoChildSas);
        }
        if child_sas.len() > N3IWF_SESSION_MAX_CHILD_SAS {
            return Err(N3iwfSessionModelError::TooManyChildSas);
        }
        child_sas.sort_unstable_by_key(|child_sa| child_sa.mark);
        if child_sas
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.mark == right.mark))
        {
            return Err(N3iwfSessionModelError::DuplicateChildSaMark);
        }
        let default = *child_sas
            .iter()
            .find(|child_sa| child_sa.mark == default_child_sa)
            .ok_or(N3iwfSessionModelError::UnknownDefaultChildSa)?;
        let mut associated = N3iwfQfiSet::empty();
        for child_sa in &child_sas {
            if !child_sa.associated_qfis.is_subset_of(session_qfis) {
                return Err(N3iwfSessionModelError::AssociatedQfiNotInSession);
            }
            if !child_sa.associated_qfis.is_disjoint(associated) {
                return Err(N3iwfSessionModelError::QfiAssociatedTwice);
            }
            associated = associated.union(child_sa.associated_qfis);
        }
        for family_is_ipv4 in [true, false] {
            let mut addresses = child_sas
                .iter()
                .map(|child_sa| child_sa.ue_inner_address)
                .filter(|address| address.is_ipv4() == family_is_ipv4);
            if let Some(first) = addresses.next() {
                if addresses.any(|address| address != first) {
                    return Err(N3iwfSessionModelError::InconsistentUeInnerAddress);
                }
            }
        }
        let n3_local = n3.local_downlink.local_address();
        let n3_remote = n3.received_uplink.destination();
        if child_sas.iter().any(|child_sa| {
            child_sa.ue_inner_address == n3_local
                || child_sa.ue_inner_address == n3_remote
                || child_sa.up_address == n3_remote
        }) {
            return Err(N3iwfSessionModelError::AliasedAddress);
        }
        qos_flows.sort_unstable_by_key(|flow| flow.qfi.get());
        Ok(Self {
            n3,
            qos_flows,
            session_qfis,
            child_sas,
            default_child_sa: default,
            downlink_unknown_qfi,
        })
    }

    /// The N3 tunnel pair.
    #[must_use]
    pub const fn n3(&self) -> &N3iwfN3Tunnel {
        &self.n3
    }

    /// QoS flows in ascending QFI order.
    #[must_use]
    pub fn qos_flows(&self) -> &[N3iwfQosFlow] {
        &self.qos_flows
    }

    /// The QoS flow with this QFI, if it is a session flow.
    #[must_use]
    pub fn qos_flow(&self, qfi: N3Qfi) -> Option<&N3iwfQosFlow> {
        self.qos_flows.iter().find(|flow| flow.qfi == qfi)
    }

    /// The set of session QFIs.
    #[must_use]
    pub const fn session_qfis(&self) -> N3iwfQfiSet {
        self.session_qfis
    }

    /// Child SAs in ascending mark order.
    #[must_use]
    pub fn child_sas(&self) -> &[N3iwfChildSa] {
        &self.child_sas
    }

    /// The Child SA with this mark, if the session has one.
    #[must_use]
    pub fn child_sa(&self, mark: GtpBearerMark) -> Option<&N3iwfChildSa> {
        self.child_sas.iter().find(|child_sa| child_sa.mark == mark)
    }

    /// The session's one default Child SA (TS 23.502 section 4.12.5 step 4a).
    #[must_use]
    pub const fn default_child_sa(&self) -> &N3iwfChildSa {
        &self.default_child_sa
    }

    /// The caller-declared disposition for an unknown downlink QFI.
    #[must_use]
    pub const fn downlink_unknown_qfi(&self) -> N3iwfDownlinkUnknownQfi {
        self.downlink_unknown_qfi
    }

    /// The Child SA the UE is required to use for this uplink QFI: the Child
    /// SA explicitly associated with it, otherwise the default Child SA (TS
    /// 24.502 section 8.3.1). `None` means the QFI is not a session flow.
    #[must_use]
    pub fn uplink_child_sa(&self, qfi: N3Qfi) -> Option<&N3iwfChildSa> {
        if !self.session_qfis.contains(qfi) {
            return None;
        }
        Some(
            self.child_sas
                .iter()
                .find(|child_sa| child_sa.associated_qfis.contains(qfi))
                .unwrap_or(&self.default_child_sa),
        )
    }

    /// Admission of an uplink GRE packet that arrived on the Child SA with
    /// `child_sa_mark` and carries `qfi` (RFC 021 section 6, rows U1 to U4).
    #[must_use]
    pub fn uplink_admission(
        &self,
        child_sa_mark: GtpBearerMark,
        qfi: N3Qfi,
    ) -> N3iwfUplinkAdmission {
        if self.child_sa(child_sa_mark).is_none() {
            return N3iwfUplinkAdmission::UnknownChildSa;
        }
        match self.uplink_child_sa(qfi) {
            None => N3iwfUplinkAdmission::UnknownQfi,
            Some(required) if required.mark == child_sa_mark => N3iwfUplinkAdmission::Admitted,
            Some(_) => N3iwfUplinkAdmission::WrongChildSa,
        }
    }

    /// The Child SA for a downlink G-PDU carrying `qfi` (RFC 021 section 6,
    /// rows D1 to D3).
    #[must_use]
    pub fn downlink_selection(&self, qfi: N3Qfi) -> N3iwfDownlinkSelection<'_> {
        if !self.session_qfis.contains(qfi) {
            return match self.downlink_unknown_qfi {
                N3iwfDownlinkUnknownQfi::Drop => N3iwfDownlinkSelection::Drop,
                N3iwfDownlinkUnknownQfi::DefaultChildSa => {
                    N3iwfDownlinkSelection::UnknownQfiDefault(&self.default_child_sa)
                }
            };
        }
        self.child_sas
            .iter()
            .find(|child_sa| child_sa.associated_qfis.contains(qfi))
            .map_or(
                N3iwfDownlinkSelection::SessionFlowDefault(&self.default_child_sa),
                N3iwfDownlinkSelection::Associated,
            )
    }

    /// Names of the fields in which `other` differs, in canonical order.
    fn mismatches(&self, other: &Self) -> Vec<N3iwfSessionMismatchField> {
        let mut fields = Vec::new();
        let (left, right) = (&self.n3, &other.n3);
        if left.link_ifindex != right.link_ifindex {
            fields.push(N3iwfSessionMismatchField::LinkIfindex);
        }
        if left.received_uplink != right.received_uplink {
            fields.push(N3iwfSessionMismatchField::ReceivedUplink);
        }
        if left.local_downlink != right.local_downlink {
            fields.push(N3iwfSessionMismatchField::LocalDownlink);
        }
        if left.downlink_source_port_policy != right.downlink_source_port_policy {
            fields.push(N3iwfSessionMismatchField::DownlinkSourcePortPolicy);
        }
        if left.uplink_source_port_policy != right.uplink_source_port_policy {
            fields.push(N3iwfSessionMismatchField::UplinkSourcePortPolicy);
        }
        if self.qos_flows != other.qos_flows {
            fields.push(N3iwfSessionMismatchField::QosFlows);
        }
        if self.child_sas != other.child_sas {
            fields.push(N3iwfSessionMismatchField::ChildSas);
        }
        if self.default_child_sa.mark != other.default_child_sa.mark {
            fields.push(N3iwfSessionMismatchField::DefaultChildSa);
        }
        if self.downlink_unknown_qfi != other.downlink_unknown_qfi {
            fields.push(N3iwfSessionMismatchField::DownlinkUnknownQfi);
        }
        fields
    }
}

impl fmt::Debug for N3iwfSessionIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionIntent(<redacted>)")
    }
}

/// Backend-issued generation of an installed session record.
///
/// A generation starts at one, grows by exactly one per successful flow swap
/// and never wraps. It is an observation token that fences stale writers, not
/// authority: presenting a wrong one yields a conflict.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct N3iwfSessionGeneration(NonZeroU64);

impl N3iwfSessionGeneration {
    /// The generation of a newly installed record.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Wrap a backend-issued generation.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    /// Raw value for backend encoding; do not log it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The following generation, or `None` on exhaustion.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Debug for N3iwfSessionGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionGeneration(<redacted>)")
    }
}

/// A session exactly as a backend reports it installed, with its generation.
#[derive(Clone, PartialEq, Eq)]
pub struct N3iwfInstalledSession {
    intent: N3iwfSessionIntent,
    generation: N3iwfSessionGeneration,
}

impl N3iwfInstalledSession {
    /// Pair an intent with the generation of its installed record.
    #[must_use]
    pub const fn new(intent: N3iwfSessionIntent, generation: N3iwfSessionGeneration) -> Self {
        Self { intent, generation }
    }

    /// The installed intent.
    #[must_use]
    pub const fn intent(&self) -> &N3iwfSessionIntent {
        &self.intent
    }

    /// The installed record's generation.
    #[must_use]
    pub const fn generation(&self) -> N3iwfSessionGeneration {
        self.generation
    }

    /// Recover the intent.
    #[must_use]
    pub fn into_intent(self) -> N3iwfSessionIntent {
        self.intent
    }
}

impl fmt::Debug for N3iwfInstalledSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfInstalledSession(<redacted>)")
    }
}

/// Key of an [`N3iwfSessionSelector`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N3iwfSessionSelectorKey {
    /// The locally supplied N3IWF TNL; its address supplies the outer family.
    LocalDownlink(LocalN3DownlinkTnl),
    /// A user-plane Child SA mark.
    ChildSaMark(GtpBearerMark),
}

/// Readback selector for one N3IWF session on one N3 link.
///
/// A lookup reports whatever session occupies the selector. The caller
/// compares the returned session with its own durable descriptor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct N3iwfSessionSelector {
    link_ifindex: NonZeroU32,
    key: N3iwfSessionSelectorKey,
}

impl N3iwfSessionSelector {
    /// Select by the locally supplied downlink TNL (the record key).
    ///
    /// # Errors
    /// Returns [`N3iwfSessionModelError::InvalidLinkIfindex`] for ifindex zero.
    pub fn local_downlink(
        link_ifindex: u32,
        local_downlink: LocalN3DownlinkTnl,
    ) -> Result<Self, N3iwfSessionModelError> {
        Ok(Self {
            link_ifindex: NonZeroU32::new(link_ifindex)
                .ok_or(N3iwfSessionModelError::InvalidLinkIfindex)?,
            key: N3iwfSessionSelectorKey::LocalDownlink(local_downlink),
        })
    }

    /// Select by one Child SA mark (the uplink index).
    ///
    /// # Errors
    /// Returns [`N3iwfSessionModelError::InvalidLinkIfindex`] for ifindex zero.
    pub fn child_sa(
        link_ifindex: u32,
        mark: GtpBearerMark,
    ) -> Result<Self, N3iwfSessionModelError> {
        Ok(Self {
            link_ifindex: NonZeroU32::new(link_ifindex)
                .ok_or(N3iwfSessionModelError::InvalidLinkIfindex)?,
            key: N3iwfSessionSelectorKey::ChildSaMark(mark),
        })
    }

    /// The local downlink selector projected by an intent.
    #[must_use]
    pub const fn from_intent(intent: &N3iwfSessionIntent) -> Self {
        Self {
            link_ifindex: intent.n3.link_ifindex,
            key: N3iwfSessionSelectorKey::LocalDownlink(intent.n3.local_downlink),
        }
    }

    /// N3 link ifindex.
    #[must_use]
    pub const fn link_ifindex(&self) -> u32 {
        self.link_ifindex.get()
    }

    /// Lookup key.
    #[must_use]
    pub const fn key(&self) -> N3iwfSessionSelectorKey {
        self.key
    }
}

impl fmt::Debug for N3iwfSessionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionSelector(<redacted>)")
    }
}

/// Result of an exact session readback.
///
/// Partial, transitional or inconsistent state is reported as an error by the
/// backend, never as `Absent`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N3iwfSessionReadback {
    /// No session occupies the selector.
    Absent,
    /// One complete Active session occupies the selector.
    Present(N3iwfInstalledSession),
}

/// Selectors occupied by state that conflicts with a request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum N3iwfSessionOccupancy {
    /// Another session occupies the local TEID.
    LocalTeid,
    /// Another session owns at least one requested Child SA mark.
    ChildSaMark,
    /// Both of the above.
    Both,
    /// Non-N3IWF state on the attachment holds the local TEID.
    OtherRole,
}

/// Session field that differs, without its value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum N3iwfSessionMismatchField {
    /// N3 link ifindex.
    LinkIfindex,
    /// Received UPF TNL.
    ReceivedUplink,
    /// Locally supplied N3IWF TNL.
    LocalDownlink,
    /// Inbound source-port policy.
    DownlinkSourcePortPolicy,
    /// Uplink source-port policy.
    UplinkSourcePortPolicy,
    /// QoS flows or their N3 DSCP.
    QosFlows,
    /// Child SAs, their addresses or associations.
    ChildSas,
    /// The default Child SA.
    DefaultChildSa,
    /// The unknown downlink QFI disposition.
    DownlinkUnknownQfi,
    /// The installed record generation.
    Generation,
}

/// Value-free evidence for a session conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N3iwfSessionConflict {
    occupancy: N3iwfSessionOccupancy,
    mismatches: Vec<N3iwfSessionMismatchField>,
}

impl N3iwfSessionConflict {
    /// Compare the occupying session with the requested one.
    ///
    /// Returns `None` when they are identical, so a conflict always names at
    /// least one field.
    #[must_use]
    pub fn between(
        occupancy: N3iwfSessionOccupancy,
        existing: &N3iwfSessionIntent,
        desired: &N3iwfSessionIntent,
    ) -> Option<Self> {
        Self::from_mismatch_fields(occupancy, existing.mismatches(desired))
    }

    /// Compare an installed session with the expected one, generation
    /// included.
    #[must_use]
    pub fn between_installed(
        occupancy: N3iwfSessionOccupancy,
        existing: &N3iwfInstalledSession,
        expected: &N3iwfInstalledSession,
    ) -> Option<Self> {
        let mut fields = existing.intent.mismatches(&expected.intent);
        if existing.generation != expected.generation {
            fields.push(N3iwfSessionMismatchField::Generation);
        }
        Self::from_mismatch_fields(occupancy, fields)
    }

    /// Build evidence from field names; sorted and deduplicated. An empty
    /// list returns `None`.
    #[must_use]
    pub fn from_mismatch_fields(
        occupancy: N3iwfSessionOccupancy,
        mismatches: impl IntoIterator<Item = N3iwfSessionMismatchField>,
    ) -> Option<Self> {
        let mut mismatches: Vec<_> = mismatches.into_iter().collect();
        mismatches.sort_unstable();
        mismatches.dedup();
        (!mismatches.is_empty()).then_some(Self {
            occupancy,
            mismatches,
        })
    }

    /// Evidence that non-N3IWF state holds the local TEID.
    #[must_use]
    pub const fn other_role() -> Self {
        Self {
            occupancy: N3iwfSessionOccupancy::OtherRole,
            mismatches: Vec::new(),
        }
    }

    /// Occupied selectors.
    #[must_use]
    pub const fn occupancy(&self) -> N3iwfSessionOccupancy {
        self.occupancy
    }

    /// Differing field names in canonical order.
    #[must_use]
    pub fn mismatches(&self) -> &[N3iwfSessionMismatchField] {
        &self.mismatches
    }
}

/// Classified result of a session install.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N3iwfSessionInstallOutcome {
    /// Newly installed and exactly read back.
    Installed(N3iwfSessionGeneration),
    /// The exact session was already installed.
    ExactAlreadyPresent(N3iwfSessionGeneration),
    /// Existing state conflicts; nothing changed.
    Conflict(N3iwfSessionConflict),
    /// The final state could not be proven.
    Indeterminate(PdpContextIndeterminateReason),
}

/// An atomic flow-table swap from an exact installed session to a desired
/// intent with the same N3 tunnel.
#[derive(Clone, PartialEq, Eq)]
pub struct N3iwfSessionFlowUpdate {
    expected: N3iwfInstalledSession,
    desired: N3iwfSessionIntent,
}

impl N3iwfSessionFlowUpdate {
    /// Pair the expected current session with the desired one.
    ///
    /// # Errors
    /// Returns [`N3iwfSessionModelError::N3TunnelChanged`] when the desired
    /// session names a different N3 tunnel. UPF tunnel relocation is a separate
    /// operation.
    pub fn new(
        expected: N3iwfInstalledSession,
        desired: N3iwfSessionIntent,
    ) -> Result<Self, N3iwfSessionModelError> {
        if expected.intent.n3 != desired.n3 {
            return Err(N3iwfSessionModelError::N3TunnelChanged);
        }
        Ok(Self { expected, desired })
    }

    /// The exact session and generation the swap replaces.
    #[must_use]
    pub const fn expected(&self) -> &N3iwfInstalledSession {
        &self.expected
    }

    /// The desired session.
    #[must_use]
    pub const fn desired(&self) -> &N3iwfSessionIntent {
        &self.desired
    }

    /// Split into the expected and desired sessions.
    #[must_use]
    pub fn into_parts(self) -> (N3iwfInstalledSession, N3iwfSessionIntent) {
        (self.expected, self.desired)
    }
}

impl fmt::Debug for N3iwfSessionFlowUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionFlowUpdate(<redacted>)")
    }
}

/// Classified result of a flow-table swap.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N3iwfSessionReconcileOutcome {
    /// Swapped and exactly read back at this generation.
    Reconciled(N3iwfSessionGeneration),
    /// The desired session is already installed at this generation.
    ExactAlreadyPresent(N3iwfSessionGeneration),
    /// No session occupies the expected local TEID; nothing changed.
    Absent,
    /// Existing state differs from the expectation; nothing changed.
    Conflict(N3iwfSessionConflict),
    /// The final state could not be proven.
    Indeterminate(PdpContextIndeterminateReason),
}

/// Classified result of an exact session removal.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N3iwfSessionRemovalOutcome {
    /// The exact session was removed and its absence proven.
    Removed,
    /// No session occupied the expected local TEID.
    AlreadyAbsent,
    /// A different session or generation is installed; nothing changed.
    Conflict(N3iwfSessionConflict),
    /// The final state could not be proven.
    Indeterminate(PdpContextIndeterminateReason),
    /// A structural precondition failed before any mutation.
    RepairRequired(PdpContextRepairReason),
}

/// Exact removal of a durable session after its previous writer stopped.
///
/// The request binds the expected device identity, its non-reusable
/// incarnation and the complete expected session. Backends refuse a device
/// whose ifindex differs from the session's N3 link before any mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct N3iwfSessionRecoveryRequest {
    device: GtpDevice,
    incarnation: PdpDeviceIncarnation,
    expected: N3iwfInstalledSession,
    writer_proof: PdpRestartRecoveryProof,
}

impl N3iwfSessionRecoveryRequest {
    /// Build a restart-recovery request.
    #[must_use]
    pub const fn new(
        device: GtpDevice,
        incarnation: PdpDeviceIncarnation,
        expected: N3iwfInstalledSession,
        writer_proof: PdpRestartRecoveryProof,
    ) -> Self {
        Self {
            device,
            incarnation,
            expected,
            writer_proof,
        }
    }

    /// Expected device identity.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Non-reusable device incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> PdpDeviceIncarnation {
        self.incarnation
    }

    /// Complete expected session.
    #[must_use]
    pub const fn expected(&self) -> &N3iwfInstalledSession {
        &self.expected
    }

    /// Prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> PdpRestartRecoveryProof {
        self.writer_proof
    }
}

impl fmt::Debug for N3iwfSessionRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionRecoveryRequest(<redacted>)")
    }
}

/// Exact removal of a session under the current live writer's affine proof.
///
/// The proof comes from
/// [`crate::GtpuDataplaneBackend::acquire_pdp_live_writer_proof`] and cannot
/// be cloned, so neither can this request.
///
/// ```compile_fail
/// # use opc_gtpu_dataplane::n3::N3iwfSessionLiveWriterRemovalRequest;
/// fn cannot_clone(
///     request: N3iwfSessionLiveWriterRemovalRequest,
/// ) -> N3iwfSessionLiveWriterRemovalRequest {
///     request.clone()
/// }
/// ```
pub struct N3iwfSessionLiveWriterRemovalRequest {
    device: GtpDevice,
    incarnation: PdpDeviceIncarnation,
    expected: N3iwfInstalledSession,
    writer_proof: PdpLiveWriterProof,
}

impl N3iwfSessionLiveWriterRemovalRequest {
    /// Build a live-writer removal request.
    #[must_use]
    pub const fn new(
        device: GtpDevice,
        incarnation: PdpDeviceIncarnation,
        expected: N3iwfInstalledSession,
        writer_proof: PdpLiveWriterProof,
    ) -> Self {
        Self {
            device,
            incarnation,
            expected,
            writer_proof,
        }
    }

    /// Expected device identity.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Non-reusable device incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> PdpDeviceIncarnation {
        self.incarnation
    }

    /// Complete expected session.
    #[must_use]
    pub const fn expected(&self) -> &N3iwfInstalledSession {
        &self.expected
    }

    /// Live-writer ownership attestation.
    #[must_use = "inspect the affine live-writer proof reference"]
    pub const fn writer_proof(&self) -> &PdpLiveWriterProof {
        &self.writer_proof
    }
}

impl fmt::Debug for N3iwfSessionLiveWriterRemovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("N3iwfSessionLiveWriterRemovalRequest(<redacted>)")
    }
}

/// Support for each N3IWF session lifecycle operation.
///
/// This reports state lifecycle only. It is not a forwarding claim: see
/// [`crate::GtpuDataplaneBackend::n3_forwarding_capability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct N3iwfSessionLifecycleCapabilities {
    /// Exact readback.
    pub readback: GtpuCapability,
    /// Classified install.
    pub classified_install: GtpuCapability,
    /// Atomic flow-table swap.
    pub flow_reconcile: GtpuCapability,
    /// Exact removal.
    pub exact_removal: GtpuCapability,
    /// Exact removal after the prior writer stopped.
    pub restart_recovery: GtpuCapability,
    /// Exact removal under the live-writer proof.
    pub live_writer_removal: GtpuCapability,
}

impl N3iwfSessionLifecycleCapabilities {
    /// Capabilities of an implementation that has not opted in.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            readback: GtpuCapability::Missing,
            classified_install: GtpuCapability::Missing,
            flow_reconcile: GtpuCapability::Missing,
            exact_removal: GtpuCapability::Missing,
            restart_recovery: GtpuCapability::Missing,
            live_writer_removal: GtpuCapability::Missing,
        }
    }
}
