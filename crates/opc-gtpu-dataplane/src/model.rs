//! Safe model types for Linux GTP-U dataplane backend operations.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;

pub use opc_gtpu_ebpf_common::{
    GtpuDownlinkFragmentContract, GtpuOuterFragmentPolicy, GtpuReassemblyBounds,
    GtpuSourcePortPolicy, GtpuSourcePortRange, GtpuUplinkMtuPolicy, GtpuUplinkSourcePortPolicy,
};
use opc_types::DscpCodepoint;

/// Default GTP-U UDP port.
pub const GTPU_PORT: u16 = 2152;
/// Default PDP context hash size used by libgtpnl examples.
pub const DEFAULT_PDP_HASHSIZE: u32 = 131_072;

/// GTP Tunnel Endpoint Identifier.
///
/// TEIDs are treated as sensitive routing/session handles. `Debug` and
/// `Display` never emit the raw value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Teid(NonZeroU32);

impl Teid {
    /// Create a TEID. Returns `None` for zero, which is not valid for GTPv1 PDP
    /// contexts.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw TEID value for kernel encoding.
    ///
    /// Callers must not expose this value through logs or diagnostics.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Debug for Teid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Teid").field(&"<redacted>").finish()
    }
}

impl fmt::Display for Teid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-teid>")
    }
}

/// Non-zero Linux packet mark selecting one bearer that shares a UE PAA.
///
/// The eBPF backend owns the complete 32-bit mark: the default inbound Child
/// SA must clear it with `(value=0, mask=u32::MAX)`, while a dedicated inbound
/// Child SA must set `(value=mark, mask=u32::MAX)` and the corresponding
/// outbound XFRM policy must select the same exact value/full mask. Partial
/// masks are incompatible and fail closed. Marks are treated as routing
/// handles and are redacted from diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GtpBearerMark(NonZeroU32);

impl GtpBearerMark {
    /// Create a bearer mark. Zero is reserved for the unmarked/default path.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the complete Linux packet-mark value.
    ///
    /// Callers must not expose routing handles through logs or diagnostics.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Debug for GtpBearerMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GtpBearerMark").field(&"<redacted>").finish()
    }
}

impl fmt::Display for GtpBearerMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-bearer-mark>")
    }
}

/// Linux GTP netdevice role.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpRole {
    /// Gateway side (`GTP_ROLE_GGSN`), appropriate for GGSN/P-GW/ePDG gateway behavior.
    #[default]
    Ggsn,
    /// Serving side (`GTP_ROLE_SGSN`).
    Sgsn,
}

/// Supported GTP user-plane version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpVersion {
    /// GTP-U version 1.
    #[default]
    V1,
}

/// Address family used to remove a PDP context.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpAddressFamily {
    /// IPv4 MS/UE address family.
    Ipv4,
    /// IPv6 MS/UE address family.
    Ipv6,
}

impl GtpAddressFamily {
    /// Derive a GTP address family from an IP address.
    #[must_use]
    pub const fn from_ip(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Linux `gtp` netdevice identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GtpDevice {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub ifindex: u32,
}

/// Explicit caller attestation required before removing a drained legacy v2
/// eBPF pin graph.
///
/// Constructing this value asserts that the application writer is stopped,
/// every session/PDP context has been drained, and no traffic is expected to
/// traverse the target attachment. The backend independently proves that all
/// forwarding maps are empty; this attestation never bypasses kernel-state or
/// identity validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuV2DrainProof {
    _private: (),
}

impl GtpuV2DrainProof {
    /// Attest that session state and traffic have both been drained.
    ///
    /// This is an explicit maintenance acknowledgement, not an observation
    /// made by the SDK. The teardown operation still refuses populated,
    /// malformed, foreign, or identity-indeterminate state.
    #[must_use]
    pub const fn sessions_and_traffic_drained() -> Self {
        Self { _private: () }
    }
}

/// Request to remove one positively identified drained legacy v2 eBPF pin
/// graph before provisioning the current source-port-v4 schema.
#[derive(Clone, PartialEq, Eq)]
pub struct DrainedV2TeardownRequest {
    device: GtpDevice,
    drain_proof: GtpuV2DrainProof,
}

impl DrainedV2TeardownRequest {
    /// Build a request for an exact interface name/index identity.
    #[must_use]
    pub const fn new(device: GtpDevice, drain_proof: GtpuV2DrainProof) -> Self {
        Self {
            device,
            drain_proof,
        }
    }

    /// Return the expected interface identity.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Return the explicit drain attestation.
    #[must_use]
    pub const fn drain_proof(&self) -> GtpuV2DrainProof {
        self.drain_proof
    }
}

impl fmt::Debug for DrainedV2TeardownRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DrainedV2TeardownRequest")
            .field("device", &"<redacted-interface-identity>")
            .field("drain_proof", &self.drain_proof)
            .finish()
    }
}

/// Stable reason a drained-v2 teardown was refused without intentionally
/// changing the legacy program/map graph.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrainedV2TeardownRefusal {
    /// The interface name no longer resolves to the expected ifindex.
    InterfaceIdentityChanged,
    /// This backend instance already manages the attachment through the normal
    /// device lifecycle.
    ManagedAttachment,
    /// The retained state is absent, not schema v2, or not a complete
    /// committed legacy-v2 graph.
    NotLegacyV2,
    /// At least one forwarding/session map still contains state.
    PopulatedState,
    /// A named pin or tc hook is foreign, replaced, or no longer has the exact
    /// SDK-owned legacy identity.
    IdentityMismatch,
    /// Complete, stable kernel state or mutation authority could not be
    /// established.
    IndeterminateState,
}

/// Stable progress classification for an incomplete teardown.
///
/// Every value is safe to persist as operator evidence. A caller must retry
/// the exact same request and must not provision the current schema until it observes
/// [`DrainedV2TeardownOutcome::Removed`] or
/// [`DrainedV2TeardownOutcome::AlreadyAbsent`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrainedV2TeardownProgress {
    /// A durable SDK-owned teardown proof exists, but both exact legacy hooks
    /// may still be present.
    ProofCommitted,
    /// Exactly one legacy tc hook is confirmed absent.
    OneHookDetached,
    /// Both legacy tc hooks are confirmed absent and all legacy pins remain
    /// identity-bound by the teardown proof.
    HooksDetached,
    /// Forwarding/session state appeared in a surviving legacy map after the
    /// durable teardown proof was committed. No further cleanup is allowed
    /// until the writer is stopped, state is drained again, and the exact
    /// request is retried.
    PopulatedStateObserved,
    /// Pin removal started; the durable proof preserves the exact remaining
    /// identities for an idempotent retry.
    PinCleanupStarted,
    /// A mutation may have completed, but authoritative readback could not
    /// classify the final state.
    Indeterminate,
}

/// Classified result of an explicit drained legacy-v2 teardown.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DrainedV2TeardownOutcome {
    /// The exact legacy hooks, pins, and teardown proof were removed.
    Removed,
    /// The configured legacy namespace is absent and a complete hook dump
    /// found no legacy SDK program name at any priority or handle on the exact
    /// interface.
    AlreadyAbsent,
    /// The request was refused before intentional graph mutation.
    Refused(DrainedV2TeardownRefusal),
    /// Cleanup is incomplete and the exact request must be retried.
    Partial(DrainedV2TeardownProgress),
}

/// Request to create a Linux `gtp` netdevice.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CreateGtpDeviceRequest {
    /// Interface name.
    pub name: String,
    /// Linux GTP role.
    pub role: GtpRole,
    /// UDP address bound before passing the GTP-U socket to the kernel.
    pub bind_address: IpAddr,
    /// UDP port bound before passing the GTP-U socket to the kernel.
    pub bind_port: u16,
    /// Optional PDP hash size. The default request uses
    /// [`DEFAULT_PDP_HASHSIZE`], mirroring libgtpnl examples.
    pub pdp_hashsize: Option<u32>,
    /// Optional explicit uplink PMTU/outer-fragmentation policy for the
    /// device's S2b-U link.
    ///
    /// `None` preserves the pre-policy behavior: only the IPv4 total-length
    /// `u16` limit is enforced on uplink encapsulation. `Some` requires the
    /// backend to enforce the effective link MTU fail closed — an over-MTU
    /// encapsulation is either emitted with outer fragmentation when the
    /// policy permits it, or rejected with typed Packet-Too-Big guidance and
    /// never leaked unencapsulated. Backends whose
    /// [`GtpuProbe::uplink_pmtu_enforcement`] is not
    /// [`GtpuCapability::Available`] reject `Some` rather than silently
    /// ignoring it.
    pub uplink_mtu_policy: Option<GtpuUplinkMtuPolicy>,
}

impl CreateGtpDeviceRequest {
    /// Build a GGSN-role GTP device request bound to `0.0.0.0:2152`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            role: GtpRole::Ggsn,
            bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_port: GTPU_PORT,
            pdp_hashsize: Some(DEFAULT_PDP_HASHSIZE),
            uplink_mtu_policy: None,
        }
    }
}

impl fmt::Debug for CreateGtpDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateGtpDeviceRequest")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("bind_address", &"<redacted>")
            .field("bind_port", &self.bind_port)
            .field("pdp_hashsize", &self.pdp_hashsize)
            .field("uplink_mtu_policy", &self.uplink_mtu_policy)
            .finish()
    }
}

/// Exact backend-neutral identity of one authorized downlink GTP-U endpoint.
///
/// The current eBPF adapter constructs this value from the PDP peer address,
/// the device's concrete local bind address, the managed ingress ifindex, and
/// the request's explicit source-port policy. The same semantic model covers
/// IPv4 and IPv6; an adapter that cannot execute a family rejects it before
/// publishing dataplane state.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GtpuDownlinkEndpoint {
    peer_address: IpAddr,
    local_address: IpAddr,
    ingress_ifindex: u32,
    source_port_policy: GtpuSourcePortPolicy,
}

impl GtpuDownlinkEndpoint {
    /// Construct a canonical endpoint identity.
    ///
    /// Mixed address families, unspecified addresses, and ifindex zero return
    /// `None` rather than creating an identity an adapter cannot bind safely.
    #[must_use]
    pub fn new(
        peer_address: IpAddr,
        local_address: IpAddr,
        ingress_ifindex: u32,
        source_port_policy: GtpuSourcePortPolicy,
    ) -> Option<Self> {
        if peer_address.is_unspecified()
            || local_address.is_unspecified()
            || ingress_ifindex == 0
            || GtpAddressFamily::from_ip(peer_address) != GtpAddressFamily::from_ip(local_address)
        {
            return None;
        }
        Some(Self {
            peer_address,
            local_address,
            ingress_ifindex,
            source_port_policy,
        })
    }

    /// Return the authorized outer peer address.
    #[must_use]
    pub const fn peer_address(&self) -> IpAddr {
        self.peer_address
    }

    /// Return the authorized local outer destination.
    #[must_use]
    pub const fn local_address(&self) -> IpAddr {
        self.local_address
    }

    /// Return the exact ingress attachment ifindex.
    #[must_use]
    pub const fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    /// Return the explicit UDP source-port policy.
    #[must_use]
    pub const fn source_port_policy(&self) -> GtpuSourcePortPolicy {
        self.source_port_policy
    }
}

impl fmt::Debug for GtpuDownlinkEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuDownlinkEndpoint")
            .field("peer_address", &"<redacted>")
            .field("local_address", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .field("source_port_policy", &"<redacted>")
            .finish()
    }
}

/// GTP-U PDP context programmed into the Linux `gtp` kernel module.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GtpPdpContext {
    /// Incoming/local S2b-U/N3 TEID.
    pub local_teid: Teid,
    /// Outgoing peer PGW/UPF TEID.
    pub peer_teid: Teid,
    /// MS/UE packet-data-network address.
    pub ms_address: IpAddr,
    /// Peer PGW/UPF GTP-U address.
    pub peer_address: IpAddr,
    /// GTP netdevice ifindex.
    pub link_ifindex: u32,
    /// Explicit UDP source-port authorization for inbound GTP-U G-PDUs.
    ///
    /// Use [`GtpuSourcePortPolicy::Any`] for peers that select dynamic source
    /// ports as described by TS 29.281 section 4.4.2. The eBPF adapter never
    /// infers this policy from missing state: every published downlink PDR is
    /// paired with this exact bounded policy.
    pub downlink_source_port_policy: GtpuSourcePortPolicy,
    /// GTP version.
    pub gtp_version: GtpVersion,
    /// Optional non-zero packet mark selecting this bearer.
    ///
    /// The Linux eBPF backend keys marked uplink state by this value together
    /// with `ms_address`, and stamps it on downlink packets before XFRM policy
    /// lookup. Backends whose [`GtpuProbe::per_bearer_marking`] is not
    /// [`GtpuCapability::Available`] reject `Some`. `None` preserves legacy
    /// map and wire bytes; successful eBPF downlink decapsulation explicitly
    /// clears the complete packet mark to the default-bearer value zero.
    pub bearer_mark: Option<GtpBearerMark>,
    /// Explicit uplink UDP source-port selection policy.
    ///
    /// TS 29.281 section 4.4.2 fixes the destination service port at 2152 and
    /// leaves the source port dynamic.
    /// [`GtpuUplinkSourcePortPolicy::LegacyServicePort`] is the explicit
    /// pre-feature fixed-2152 behavior;
    /// [`GtpuUplinkSourcePortPolicy::Selected`] persists one stable
    /// per-context port in the eBPF uplink source-port maps. Backends whose
    /// [`GtpuProbe::uplink_source_port_selection`] is not
    /// [`GtpuCapability::Available`] reject a non-legacy policy rather than
    /// silently falling back to 2152. This uplink selection is independent
    /// of `downlink_source_port_policy`: a peer is never assumed to return
    /// traffic from the selected port.
    pub uplink_source_port_policy: GtpuUplinkSourcePortPolicy,
    /// Optional fixed DSCP stamped on the outer uplink IP header.
    ///
    /// The Linux eBPF backend supports this per PDP context. Backends whose
    /// [`GtpuProbe::egress_dscp_marking`] is not [`GtpuCapability::Available`]
    /// reject `Some` rather than silently ignoring it. `None` preserves the
    /// backend's pre-DSCP packet and kernel-message behavior.
    pub egress_dscp: Option<DscpCodepoint>,
}

impl fmt::Debug for GtpPdpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpPdpContext")
            .field("local_teid", &self.local_teid)
            .field("peer_teid", &self.peer_teid)
            .field("ms_address", &"<redacted>")
            .field("peer_address", &"<redacted>")
            .field("link_ifindex", &self.link_ifindex)
            .field("downlink_source_port_policy", &"<redacted>")
            .field("gtp_version", &self.gtp_version)
            .field("bearer_mark", &self.bearer_mark)
            .field("egress_dscp", &self.egress_dscp)
            .field("uplink_source_port_policy", &"<redacted>")
            .finish()
    }
}

/// Uplink selector identity for one PDP context.
///
/// The identity is the UE/MS packet-data address plus the optional complete
/// bearer mark. It is deliberately separate from the downlink local TEID:
/// reconciliation must inspect both kernel selector axes before classifying a
/// collision as idempotent or conflicting.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PdpContextUplinkIdentity {
    ms_address: IpAddr,
    bearer_mark: Option<GtpBearerMark>,
}

impl PdpContextUplinkIdentity {
    /// Construct a canonical uplink identity.
    ///
    /// Unspecified UE/MS addresses do not identify installable PDP state and
    /// return `None`.
    #[must_use]
    pub const fn new(ms_address: IpAddr, bearer_mark: Option<GtpBearerMark>) -> Option<Self> {
        if ms_address.is_unspecified() {
            return None;
        }
        Some(Self {
            ms_address,
            bearer_mark,
        })
    }

    /// Build the uplink identity projected by a complete PDP context.
    #[must_use]
    pub const fn from_context(context: &GtpPdpContext) -> Option<Self> {
        Self::new(context.ms_address, context.bearer_mark)
    }

    /// Return the UE/MS packet-data address.
    #[must_use]
    pub const fn ms_address(&self) -> IpAddr {
        self.ms_address
    }

    /// Return the optional complete bearer mark.
    #[must_use]
    pub const fn bearer_mark(&self) -> Option<GtpBearerMark> {
        self.bearer_mark
    }
}

impl fmt::Debug for PdpContextUplinkIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpContextUplinkIdentity")
            .field("ms_address", &"<redacted>")
            .field("bearer_mark", &"<redacted>")
            .finish()
    }
}

/// Lookup by the downlink selector of one PDP context.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PdpContextLocalTeidSelector {
    link_ifindex: NonZeroU32,
    gtp_version: GtpVersion,
    address_family: GtpAddressFamily,
    local_teid: Teid,
}

impl PdpContextLocalTeidSelector {
    /// Construct a local-TEID selector.
    ///
    /// The address family is explicit so a backend cannot report an IPv6 PDP
    /// context absent after performing only an IPv4 kernel lookup.
    #[must_use]
    pub const fn new(
        link_ifindex: u32,
        gtp_version: GtpVersion,
        address_family: GtpAddressFamily,
        local_teid: Teid,
    ) -> Option<Self> {
        match NonZeroU32::new(link_ifindex) {
            Some(link_ifindex) => Some(Self {
                link_ifindex,
                gtp_version,
                address_family,
                local_teid,
            }),
            None => None,
        }
    }

    /// Build the selector projected by a complete PDP context.
    #[must_use]
    pub fn from_context(context: &GtpPdpContext) -> Option<Self> {
        Self::new(
            context.link_ifindex,
            context.gtp_version,
            GtpAddressFamily::from_ip(context.ms_address),
            context.local_teid,
        )
    }

    /// Return the Linux GTP link ifindex.
    #[must_use]
    pub const fn link_ifindex(&self) -> u32 {
        self.link_ifindex.get()
    }

    /// Return the GTP version.
    #[must_use]
    pub const fn gtp_version(&self) -> GtpVersion {
        self.gtp_version
    }

    /// Return the expected UE/MS address family.
    #[must_use]
    pub const fn address_family(&self) -> GtpAddressFamily {
        self.address_family
    }

    /// Return the local/downlink TEID.
    #[must_use]
    pub const fn local_teid(&self) -> Teid {
        self.local_teid
    }
}

impl fmt::Debug for PdpContextLocalTeidSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpContextLocalTeidSelector")
            .field("link_ifindex", &"<redacted>")
            .field("gtp_version", &self.gtp_version)
            .field("address_family", &self.address_family)
            .field("local_teid", &self.local_teid)
            .finish()
    }
}

/// Lookup by the uplink selector of one PDP context.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PdpContextUplinkSelector {
    link_ifindex: NonZeroU32,
    gtp_version: GtpVersion,
    identity: PdpContextUplinkIdentity,
}

impl PdpContextUplinkSelector {
    /// Construct an uplink selector.
    #[must_use]
    pub const fn new(
        link_ifindex: u32,
        gtp_version: GtpVersion,
        identity: PdpContextUplinkIdentity,
    ) -> Option<Self> {
        match NonZeroU32::new(link_ifindex) {
            Some(link_ifindex) => Some(Self {
                link_ifindex,
                gtp_version,
                identity,
            }),
            None => None,
        }
    }

    /// Build the selector projected by a complete PDP context.
    #[must_use]
    pub fn from_context(context: &GtpPdpContext) -> Option<Self> {
        PdpContextUplinkIdentity::from_context(context)
            .and_then(|identity| Self::new(context.link_ifindex, context.gtp_version, identity))
    }

    /// Return the Linux GTP link ifindex.
    #[must_use]
    pub const fn link_ifindex(&self) -> u32 {
        self.link_ifindex.get()
    }

    /// Return the GTP version.
    #[must_use]
    pub const fn gtp_version(&self) -> GtpVersion {
        self.gtp_version
    }

    /// Return the typed uplink identity.
    #[must_use]
    pub const fn identity(&self) -> &PdpContextUplinkIdentity {
        &self.identity
    }
}

impl fmt::Debug for PdpContextUplinkSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpContextUplinkSelector")
            .field("link_ifindex", &"<redacted>")
            .field("gtp_version", &self.gtp_version)
            .field("identity", &self.identity)
            .finish()
    }
}

/// Backend-neutral selector for PDP-context readback.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum PdpContextSelector {
    /// Lookup by the incoming/downlink local TEID.
    LocalTeid(PdpContextLocalTeidSelector),
    /// Lookup by UE/MS address plus optional bearer mark.
    Uplink(PdpContextUplinkSelector),
}

impl fmt::Debug for PdpContextSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalTeid(selector) => f.debug_tuple("LocalTeid").field(selector).finish(),
            Self::Uplink(selector) => f.debug_tuple("Uplink").field(selector).finish(),
        }
    }
}

/// Result of a backend-neutral PDP-context lookup.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpContextReadback {
    /// No context occupies the requested selector.
    Absent,
    /// One complete, validated context occupies the selector.
    Present(GtpPdpContext),
}

/// PDP-context field whose value differs from a desired context.
///
/// Values are never included. This enum is non-exhaustive so future context
/// fields can be reported without exposing routing/session identifiers or
/// forcing downstream exhaustive matches.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum PdpContextMismatchField {
    /// Incoming/downlink local TEID.
    LocalTeid,
    /// Outgoing/uplink peer TEID.
    PeerTeid,
    /// UE/MS packet-data address.
    MsAddress,
    /// GTP-U peer address.
    PeerAddress,
    /// Linux GTP link ifindex.
    LinkIfindex,
    /// GTP version.
    GtpVersion,
    /// Optional complete bearer mark.
    BearerMark,
    /// Optional fixed outer DSCP.
    EgressDscp,
    /// Inbound GTP-U source-port policy.
    DownlinkSourcePortPolicy,
    /// Uplink GTP-U source-port selection policy.
    UplinkSourcePortPolicy,
}

/// Selector axes occupied by valid state that conflicts with a request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdpContextSelectorOccupancy {
    /// Only the requested local-TEID selector is occupied.
    LocalTeid,
    /// Only the requested uplink selector is occupied.
    Uplink,
    /// Both requested selector axes are occupied.
    Both,
}

/// Redaction-safe evidence for a PDP-context conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdpContextConflict {
    occupied: PdpContextSelectorOccupancy,
    mismatches: Vec<PdpContextMismatchField>,
}

impl PdpContextConflict {
    pub(crate) fn new(
        occupied: PdpContextSelectorOccupancy,
        mut mismatches: Vec<PdpContextMismatchField>,
    ) -> Self {
        mismatches.sort_unstable();
        mismatches.dedup();
        Self {
            occupied,
            mismatches,
        }
    }

    /// Construct conflict evidence by comparing one occupied context with the
    /// desired context.
    ///
    /// Returns `None` when the contexts are identical, preventing an adapter
    /// from manufacturing a conflict without at least one typed mismatch.
    /// Neither context value is retained in the returned diagnostic.
    #[must_use]
    pub fn between(
        occupied: PdpContextSelectorOccupancy,
        existing: &GtpPdpContext,
        desired: &GtpPdpContext,
    ) -> Option<Self> {
        Self::from_mismatch_fields(occupied, pdp_context_mismatches(existing, desired))
    }

    /// Construct conflict evidence from a nonempty set of mismatch field
    /// names.
    ///
    /// Values cannot be supplied through this boundary. Fields are sorted and
    /// deduplicated; an empty iterator returns `None`.
    #[must_use]
    pub fn from_mismatch_fields(
        occupied: PdpContextSelectorOccupancy,
        mismatches: impl IntoIterator<Item = PdpContextMismatchField>,
    ) -> Option<Self> {
        let mut mismatches = mismatches.into_iter().collect::<Vec<_>>();
        mismatches.sort_unstable();
        mismatches.dedup();
        (!mismatches.is_empty()).then_some(Self {
            occupied,
            mismatches,
        })
    }

    /// Return which requested selector axes are occupied.
    #[must_use]
    pub const fn occupied(&self) -> PdpContextSelectorOccupancy {
        self.occupied
    }

    /// Return only the names of differing fields, in deterministic order.
    #[must_use]
    pub fn mismatches(&self) -> &[PdpContextMismatchField] {
        &self.mismatches
    }
}

/// Stable reason why PDP reconciliation could not prove a final state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdpContextIndeterminateReason {
    /// State was partial, malformed, transitional, or internally inconsistent.
    IncompleteState,
    /// State changed during the bounded observation window.
    StateChanged,
    /// Program, map, lease, or other mutation authority could not be proven.
    AuthorityUnavailable,
    /// A mutation was attempted but its final state could not be confirmed.
    MutationUnconfirmed,
}

/// Classified result of strict PDP-context installation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpContextInstallOutcome {
    /// The requested context was newly installed and exactly read back.
    Installed,
    /// Both selector axes already identified the exact complete context.
    ExactAlreadyPresent,
    /// Valid existing state differs from the request.
    Conflict(PdpContextConflict),
    /// Equality or the final mutation state could not be proven.
    Indeterminate(PdpContextIndeterminateReason),
}

/// Classified result of exact PDP-context removal.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdpContextRemovalOutcome {
    /// The exact expected context was removed and both selectors are absent.
    Removed,
    /// Both expected selector axes were already absent.
    AlreadyAbsent,
    /// Valid existing state differs from the expected context and was untouched.
    Conflict(PdpContextConflict),
    /// Exact ownership or the final mutation state could not be proven.
    Indeterminate(PdpContextIndeterminateReason),
}

/// Capabilities of the explicit PDP-context reconciliation contract.
///
/// These capabilities are separate from packet-processing features in
/// [`GtpuProbe`]. A backend may support readback but intentionally lack exact
/// removal, as the mainline Linux GTP API does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdpContextReconciliationCapabilities {
    /// Typed readback by local TEID and uplink identity.
    pub readback: GtpuCapability,
    /// Dual-selector classified installation.
    pub classified_install: GtpuCapability,
    /// Authority-safe exact removal.
    pub exact_removal: GtpuCapability,
}

impl PdpContextReconciliationCapabilities {
    /// Capabilities for an implementation that has not opted into the
    /// additive reconciliation API.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            readback: GtpuCapability::Missing,
            classified_install: GtpuCapability::Missing,
            exact_removal: GtpuCapability::Missing,
        }
    }
}

pub(crate) fn pdp_context_mismatches(
    existing: &GtpPdpContext,
    desired: &GtpPdpContext,
) -> Vec<PdpContextMismatchField> {
    let mut fields = Vec::with_capacity(10);
    if existing.local_teid != desired.local_teid {
        fields.push(PdpContextMismatchField::LocalTeid);
    }
    if existing.peer_teid != desired.peer_teid {
        fields.push(PdpContextMismatchField::PeerTeid);
    }
    if existing.ms_address != desired.ms_address {
        fields.push(PdpContextMismatchField::MsAddress);
    }
    if existing.peer_address != desired.peer_address {
        fields.push(PdpContextMismatchField::PeerAddress);
    }
    if existing.link_ifindex != desired.link_ifindex {
        fields.push(PdpContextMismatchField::LinkIfindex);
    }
    if existing.gtp_version != desired.gtp_version {
        fields.push(PdpContextMismatchField::GtpVersion);
    }
    if existing.bearer_mark != desired.bearer_mark {
        fields.push(PdpContextMismatchField::BearerMark);
    }
    if existing.egress_dscp != desired.egress_dscp {
        fields.push(PdpContextMismatchField::EgressDscp);
    }
    if existing.downlink_source_port_policy != desired.downlink_source_port_policy {
        fields.push(PdpContextMismatchField::DownlinkSourcePortPolicy);
    }
    if existing.uplink_source_port_policy != desired.uplink_source_port_policy {
        fields.push(PdpContextMismatchField::UplinkSourcePortPolicy);
    }
    fields
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DualSelectorState {
    BothAbsent,
    Exact,
    Conflict(PdpContextConflict),
    Indeterminate,
}

pub(crate) fn classify_dual_selector_state(
    local: &PdpContextReadback,
    uplink: &PdpContextReadback,
    desired: &GtpPdpContext,
) -> DualSelectorState {
    match (local, uplink) {
        (PdpContextReadback::Absent, PdpContextReadback::Absent) => DualSelectorState::BothAbsent,
        (PdpContextReadback::Present(local), PdpContextReadback::Present(uplink))
            if local == desired && uplink == desired =>
        {
            DualSelectorState::Exact
        }
        (PdpContextReadback::Present(existing), PdpContextReadback::Absent)
            if existing == desired =>
        {
            DualSelectorState::Indeterminate
        }
        (PdpContextReadback::Absent, PdpContextReadback::Present(existing))
            if existing == desired =>
        {
            DualSelectorState::Indeterminate
        }
        (PdpContextReadback::Present(existing), PdpContextReadback::Absent) => {
            DualSelectorState::Conflict(PdpContextConflict::new(
                PdpContextSelectorOccupancy::LocalTeid,
                pdp_context_mismatches(existing, desired),
            ))
        }
        (PdpContextReadback::Absent, PdpContextReadback::Present(existing)) => {
            DualSelectorState::Conflict(PdpContextConflict::new(
                PdpContextSelectorOccupancy::Uplink,
                pdp_context_mismatches(existing, desired),
            ))
        }
        (PdpContextReadback::Present(local), PdpContextReadback::Present(uplink)) => {
            let mut mismatches = pdp_context_mismatches(local, desired);
            mismatches.extend(pdp_context_mismatches(uplink, desired));
            DualSelectorState::Conflict(PdpContextConflict::new(
                PdpContextSelectorOccupancy::Both,
                mismatches,
            ))
        }
    }
}

/// Request to remove a GTP-U PDP context.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RemovePdpContextRequest {
    /// Incoming/local S2b-U/N3 TEID.
    pub local_teid: Teid,
    /// GTP netdevice ifindex.
    pub link_ifindex: u32,
    /// GTP version.
    pub gtp_version: GtpVersion,
    /// MS/UE address family used by the kernel lookup.
    pub address_family: GtpAddressFamily,
}

impl RemovePdpContextRequest {
    /// Build a remove request from an installed PDP context.
    #[must_use]
    pub fn from_context(context: &GtpPdpContext) -> Self {
        Self {
            local_teid: context.local_teid,
            link_ifindex: context.link_ifindex,
            gtp_version: context.gtp_version,
            address_family: GtpAddressFamily::from_ip(context.ms_address),
        }
    }
}

impl fmt::Debug for RemovePdpContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemovePdpContextRequest")
            .field("local_teid", &self.local_teid)
            .field("link_ifindex", &self.link_ifindex)
            .field("gtp_version", &self.gtp_version)
            .field("address_family", &self.address_family)
            .finish()
    }
}

/// Kind of GTP-U backend implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuBackendKind {
    /// Backend is not implemented for the current platform.
    #[default]
    Unsupported,
    /// Backend talks to the Linux kernel GTP netlink interfaces.
    LinuxKernel,
    /// Backend drives tc clsact eBPF GTP-U datapath programs.
    LinuxEbpf,
    /// In-memory mock/dry-run backend for tests and offline development.
    Mock,
}

/// Capability state reported by a GTP-U backend probe.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuCapability {
    /// Capability state has not been determined.
    #[default]
    Unknown,
    /// The capability is available for production mutations.
    Available,
    /// The backend cannot provide the capability.
    Missing,
    /// The capability exists but current process privileges are insufficient.
    PermissionDenied,
}

/// Capability and health probe for a GTP-U backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GtpuProbe {
    /// Kind of backend that produced the probe.
    pub kind: GtpuBackendKind,
    /// The platform supports Linux GTP-U operations.
    pub platform_supported: bool,
    /// The backend believes it can reach route and generic netlink.
    pub kernel_reachable: bool,
    /// The Linux `gtp` generic-netlink family is present.
    pub gtp_module_present: bool,
    /// The process has `CAP_NET_ADMIN` in its effective set.
    pub net_admin_capable: bool,
    /// The process can load eBPF programs (`CAP_BPF` or `CAP_SYS_ADMIN`).
    /// Only probed by the eBPF backend; the netlink backend leaves it false.
    pub bpf_capable: bool,
    /// Kernel BTF (`/sys/kernel/btf/vmlinux`) is available for CO-RE loads.
    /// Only probed by the eBPF backend; the netlink backend leaves it false.
    pub btf_present: bool,
    /// Mutating operations appear ready: kernel reachable, module present,
    /// NET_ADMIN available, and the UDP GTP-U socket can be bound.
    pub mutation_ready: bool,
    /// Ability to stamp a fixed per-PDP DSCP on uplink outer IP headers.
    pub egress_dscp_marking: GtpuCapability,
    /// Ability to select uplink TEIDs and downlink XFRM policies by a
    /// per-bearer Linux packet mark while multiple bearers share one UE PAA.
    pub per_bearer_marking: GtpuCapability,
    /// Ability to bind every downlink PDR to an exact outer peer/local pair,
    /// ingress attachment, address family, and explicit source-port policy.
    pub downlink_endpoint_binding: GtpuCapability,
    /// Ability to stamp a stable per-PDP-context UDP source port on uplink
    /// outer headers while the destination remains the fixed service port.
    pub uplink_source_port_selection: GtpuCapability,
    /// Ability to enforce a typed uplink PMTU/outer-fragmentation policy:
    /// the effective link MTU is honored fail closed and over-MTU
    /// encapsulations are either outer-fragmented (when permitted) or
    /// rejected with typed Packet-Too-Big guidance, never silently emitted
    /// or leaked unencapsulated.
    pub uplink_pmtu_enforcement: GtpuCapability,
    /// The backend's demonstrated contract for fragmented outer downlink
    /// packets: either a bounded kernel-reassembly handoff whose reassembled
    /// datagrams re-enter the SDK GTP-U consumer exactly once, or an
    /// explicit unsupported statement. A backend must never leave this
    /// implicit.
    pub downlink_outer_fragment_handling: GtpuDownlinkFragmentContract,
    /// Optional human-readable detail; static so the probe stays `Copy`.
    pub details: Option<&'static str>,
}

impl GtpuProbe {
    /// Probe result for the in-memory mock backend.
    pub const fn mock() -> Self {
        Self {
            kind: GtpuBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            gtp_module_present: false,
            net_admin_capable: false,
            bpf_capable: false,
            btf_present: false,
            mutation_ready: false,
            egress_dscp_marking: GtpuCapability::Missing,
            per_bearer_marking: GtpuCapability::Missing,
            downlink_endpoint_binding: GtpuCapability::Missing,
            uplink_source_port_selection: GtpuCapability::Missing,
            uplink_pmtu_enforcement: GtpuCapability::Missing,
            downlink_outer_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
            details: Some("dry-run/mock backend"),
        }
    }

    /// Probe result for an unsupported platform.
    pub const fn unsupported() -> Self {
        Self {
            kind: GtpuBackendKind::Unsupported,
            platform_supported: false,
            kernel_reachable: false,
            gtp_module_present: false,
            net_admin_capable: false,
            bpf_capable: false,
            btf_present: false,
            mutation_ready: false,
            egress_dscp_marking: GtpuCapability::Missing,
            per_bearer_marking: GtpuCapability::Missing,
            downlink_endpoint_binding: GtpuCapability::Missing,
            uplink_source_port_selection: GtpuCapability::Missing,
            uplink_pmtu_enforcement: GtpuCapability::Missing,
            downlink_outer_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
            details: Some("GTP-U dataplane operations are not supported on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn reconciliation_context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: Teid::new(0x1234_5678).unwrap(),
            peer_teid: Teid::new(0x8765_4321).unwrap(),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Exact(21_152),
            gtp_version: GtpVersion::V1,
            bearer_mark: Some(GtpBearerMark::new(0x3456_789a).unwrap()),
            egress_dscp: Some(DscpCodepoint::new(46).unwrap()),
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::selected(40_000).unwrap(),
        }
    }

    #[test]
    fn teid_rejects_zero_and_redacts_debug_display() {
        assert_eq!(Teid::new(0), None);
        let teid = Teid::new(0x1234_5678).unwrap();
        assert_eq!(teid.get(), 0x1234_5678);
        assert!(!format!("{teid:?}").contains("12345678"));
        assert!(!teid.to_string().contains("12345678"));
    }

    #[test]
    fn bearer_mark_rejects_zero_and_redacts_debug_display() {
        assert_eq!(GtpBearerMark::new(0), None);
        let mark = GtpBearerMark::new(0x1234_5678).unwrap();
        assert_eq!(mark.get(), 0x1234_5678);
        assert_eq!(
            GtpBearerMark::new(u32::MAX).map(GtpBearerMark::get),
            Some(u32::MAX)
        );
        assert!(!format!("{mark:?}").contains("12345678"));
        assert!(!mark.to_string().contains("12345678"));
    }

    #[test]
    fn default_device_request_uses_gateway_defaults() {
        let req = CreateGtpDeviceRequest::new("gtp0");
        assert_eq!(req.name, "gtp0");
        assert_eq!(req.role, GtpRole::Ggsn);
        assert_eq!(req.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.bind_port, GTPU_PORT);
        assert_eq!(req.pdp_hashsize, Some(DEFAULT_PDP_HASHSIZE));
    }

    #[test]
    fn pdp_context_debug_redacts_teids_and_addresses() {
        let ctx = GtpPdpContext {
            local_teid: Teid::new(0x1234_5678).unwrap(),
            peer_teid: Teid::new(0x8765_4321).unwrap(),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Exact(21_152),
            gtp_version: GtpVersion::V1,
            bearer_mark: Some(GtpBearerMark::new(0x3456_789a).unwrap()),
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::selected(40_000).unwrap(),
        };
        let debug = format!("{ctx:?}");
        assert!(!debug.contains("12345678"));
        assert!(!debug.contains("87654321"));
        assert!(!debug.contains("10.23.0.2"));
        assert!(!debug.contains("::1"));
        assert!(!debug.contains("3456789a"));
        assert!(!debug.contains("21152"));
        assert!(!debug.contains("40000"));
    }

    #[test]
    fn reconciliation_selectors_are_typed_and_redaction_safe() {
        let context = reconciliation_context();
        let local = PdpContextLocalTeidSelector::from_context(&context).unwrap();
        assert_eq!(local.link_ifindex(), context.link_ifindex);
        assert_eq!(local.gtp_version(), context.gtp_version);
        assert_eq!(local.address_family(), GtpAddressFamily::Ipv4);
        assert_eq!(local.local_teid(), context.local_teid);

        let uplink = PdpContextUplinkSelector::from_context(&context).unwrap();
        assert_eq!(uplink.link_ifindex(), context.link_ifindex);
        assert_eq!(uplink.gtp_version(), context.gtp_version);
        assert_eq!(uplink.identity().ms_address(), context.ms_address);
        assert_eq!(uplink.identity().bearer_mark(), context.bearer_mark);

        let debug = format!(
            "{:?} {:?}",
            PdpContextSelector::LocalTeid(local),
            PdpContextSelector::Uplink(uplink)
        );
        for sensitive in ["12345678", "10.23.0.2", "3456789a", "21152"] {
            assert!(!debug.contains(sensitive));
        }

        assert!(PdpContextLocalTeidSelector::new(
            0,
            GtpVersion::V1,
            GtpAddressFamily::Ipv4,
            context.local_teid,
        )
        .is_none());
        let identity = PdpContextUplinkIdentity::from_context(&context).unwrap();
        assert!(PdpContextUplinkSelector::new(0, GtpVersion::V1, identity).is_none());
        let mut invalid = context;
        invalid.link_ifindex = 0;
        assert!(PdpContextLocalTeidSelector::from_context(&invalid).is_none());
        assert!(PdpContextUplinkSelector::from_context(&invalid).is_none());
    }

    #[test]
    fn mismatch_evidence_contains_only_deterministic_field_names() {
        let desired = reconciliation_context();
        let mut existing = desired.clone();
        existing.local_teid = Teid::new(1).unwrap();
        existing.peer_teid = Teid::new(2).unwrap();
        existing.ms_address = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3));
        existing.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        existing.link_ifindex = 8;
        existing.bearer_mark = None;
        existing.egress_dscp = None;
        existing.downlink_source_port_policy = GtpuSourcePortPolicy::Any;
        existing.uplink_source_port_policy = GtpuUplinkSourcePortPolicy::LegacyServicePort;

        let conflict = PdpContextConflict::new(
            PdpContextSelectorOccupancy::Both,
            pdp_context_mismatches(&existing, &desired),
        );
        assert_eq!(conflict.occupied(), PdpContextSelectorOccupancy::Both);
        assert_eq!(
            conflict.mismatches(),
            &[
                PdpContextMismatchField::LocalTeid,
                PdpContextMismatchField::PeerTeid,
                PdpContextMismatchField::MsAddress,
                PdpContextMismatchField::PeerAddress,
                PdpContextMismatchField::LinkIfindex,
                PdpContextMismatchField::BearerMark,
                PdpContextMismatchField::EgressDscp,
                PdpContextMismatchField::DownlinkSourcePortPolicy,
                PdpContextMismatchField::UplinkSourcePortPolicy,
            ]
        );
        let debug = format!("{conflict:?}");
        for sensitive in [
            "12345678",
            "87654321",
            "10.23.0.2",
            "192.0.2.10",
            "3456789a",
            "21152",
            "40000",
        ] {
            assert!(!debug.contains(sensitive));
        }

        assert!(
            PdpContextConflict::between(PdpContextSelectorOccupancy::Both, &desired, &desired,)
                .is_none()
        );
        assert!(
            PdpContextConflict::from_mismatch_fields(PdpContextSelectorOccupancy::Both, [],)
                .is_none()
        );
    }

    #[test]
    fn dual_selector_classification_requires_both_axes_for_exactness() {
        let desired = reconciliation_context();
        let absent = PdpContextReadback::Absent;
        let exact = PdpContextReadback::Present(desired.clone());

        assert_eq!(
            classify_dual_selector_state(&absent, &absent, &desired),
            DualSelectorState::BothAbsent
        );
        assert_eq!(
            classify_dual_selector_state(&exact, &exact, &desired),
            DualSelectorState::Exact
        );
        assert_eq!(
            classify_dual_selector_state(&exact, &absent, &desired),
            DualSelectorState::Indeterminate
        );

        let mut conflict = desired.clone();
        conflict.peer_teid = Teid::new(3).unwrap();
        let classified =
            classify_dual_selector_state(&PdpContextReadback::Present(conflict), &absent, &desired);
        assert!(matches!(
            classified,
            DualSelectorState::Conflict(conflict)
                if conflict.occupied() == PdpContextSelectorOccupancy::LocalTeid
                    && conflict.mismatches() == [PdpContextMismatchField::PeerTeid]
        ));
    }

    #[test]
    fn downlink_endpoint_supports_both_families_and_redacts_identity() {
        let ipv4 = GtpuDownlinkEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            7,
            GtpuSourcePortPolicy::Exact(21_152),
        )
        .unwrap();
        assert_eq!(ipv4.ingress_ifindex(), 7);
        assert_eq!(
            ipv4.source_port_policy(),
            GtpuSourcePortPolicy::Exact(21_152)
        );

        let ipv6 = GtpuDownlinkEndpoint::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            7,
            GtpuSourcePortPolicy::Any,
        );
        assert!(ipv6.is_none(), "unspecified local addresses fail closed");
        assert!(GtpuDownlinkEndpoint::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9,
            GtpuSourcePortPolicy::Any,
        )
        .is_some());
        assert!(GtpuDownlinkEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .is_none());

        let debug = format!("{ipv4:?}");
        for secret in ["192.0.2.10", "192.0.2.1", "21152"] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn remove_request_derives_family_from_context() {
        let ctx = GtpPdpContext {
            local_teid: Teid::new(1).unwrap(),
            peer_teid: Teid::new(2).unwrap(),
            ms_address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 9,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        let remove = RemovePdpContextRequest::from_context(&ctx);
        assert_eq!(remove.local_teid, ctx.local_teid);
        assert_eq!(remove.link_ifindex, 9);
        assert_eq!(remove.address_family, GtpAddressFamily::Ipv6);
    }
}
