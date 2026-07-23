//! Safe model types for Linux GTP-U dataplane backend operations.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use opc_gtpu_ebpf_common::GtpuEndpointAddress;
pub use opc_gtpu_ebpf_common::{
    GtpuDownlinkFragmentContract, GtpuOuterFragmentPolicy, GtpuReassemblyBounds,
    GtpuSessionDeviceId, GtpuSessionGroupId, GtpuSessionPaa, GtpuSourcePortPolicy,
    GtpuSourcePortRange, GtpuUplinkMtuPolicy, GtpuUplinkSourcePortPolicy,
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

/// Explicit caller attestation that the prior writer of a persistent eBPF
/// GTP-U graph has stopped.
///
/// This proof is intentionally separate from [`CurrentEbpfGraphDrainProof`]:
/// stopping the old process authorizes ownership recovery, but it does not by
/// itself authorize deleting retained forwarding/session entries. The backend
/// still acquires its own host-global namespace lease and proves the exact
/// current-schema graph and live-program state before mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphWriterProof {
    _private: (),
}

impl CurrentEbpfGraphWriterProof {
    /// Attest that the process which previously owned the graph is stopped.
    #[must_use]
    pub const fn previous_writer_stopped() -> Self {
        Self { _private: () }
    }
}

/// Explicit caller attestation that every session represented by an orphaned
/// current-schema eBPF graph and all traffic using it have been drained.
///
/// Supplying this value authorizes recovery when otherwise-valid forwarding
/// maps remain populated. It never bypasses schema, pin, program, hook, lease,
/// or interface-identity validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphDrainProof {
    _private: (),
}

impl CurrentEbpfGraphDrainProof {
    /// Attest that sessions and traffic represented by the orphan graph are
    /// drained and its retained forwarding entries may be removed.
    #[must_use]
    pub const fn sessions_and_traffic_drained() -> Self {
        Self { _private: () }
    }
}

/// Request to recover one orphaned current-schema eBPF pin graph.
///
/// `pin_namespace` selects the stable directory below the configured bpffs
/// root. An optional `replacement_device` is validated independently in the
/// caller's current network namespace; its mutable ifindex is deliberately not
/// part of the persistent graph lease identity. Finalizers may omit it after
/// both the old and replacement namespaces have gone.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentEbpfGraphRecoveryRequest {
    pin_namespace: String,
    replacement_device: Option<GtpDevice>,
    writer_proof: CurrentEbpfGraphWriterProof,
    drain_proof: Option<CurrentEbpfGraphDrainProof>,
}

impl CurrentEbpfGraphRecoveryRequest {
    /// Build a recovery request which requires every forwarding map to be
    /// empty.
    #[must_use]
    pub fn new(
        pin_namespace: impl Into<String>,
        writer_proof: CurrentEbpfGraphWriterProof,
    ) -> Self {
        Self {
            pin_namespace: pin_namespace.into(),
            replacement_device: None,
            writer_proof,
            drain_proof: None,
        }
    }

    /// Require the named replacement interface to retain this exact ifindex
    /// and require both of its SDK tc slots to be empty before recovery.
    #[must_use]
    pub fn with_replacement_device(mut self, replacement_device: GtpDevice) -> Self {
        self.replacement_device = Some(replacement_device);
        self
    }

    /// Authorize removal of a validated graph whose forwarding maps remain
    /// populated after the product has drained all represented sessions.
    #[must_use]
    pub const fn with_drain_proof(mut self, drain_proof: CurrentEbpfGraphDrainProof) -> Self {
        self.drain_proof = Some(drain_proof);
        self
    }

    /// Return the stable pin namespace below the backend's configured root.
    #[must_use]
    pub fn pin_namespace(&self) -> &str {
        &self.pin_namespace
    }

    /// Return the independently validated replacement interface identity.
    #[must_use]
    pub const fn replacement_device(&self) -> Option<&GtpDevice> {
        self.replacement_device.as_ref()
    }

    /// Return the prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> CurrentEbpfGraphWriterProof {
        self.writer_proof
    }

    /// Return the optional populated-graph drain attestation.
    #[must_use]
    pub const fn drain_proof(&self) -> Option<CurrentEbpfGraphDrainProof> {
        self.drain_proof
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentEbpfGraphRecoveryRequest")
            .field("pin_namespace", &"<redacted-pin-namespace>")
            .field(
                "replacement_device",
                &self
                    .replacement_device
                    .as_ref()
                    .map(|_| "<redacted-interface-identity>"),
            )
            .field("writer_proof", &self.writer_proof)
            .field("drain_proof", &self.drain_proof)
            .finish()
    }
}

/// Stable reason current-schema orphan recovery was refused before graph
/// deletion was committed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryRefusal {
    /// The replacement interface name no longer resolves to its requested
    /// ifindex.
    ReplacementInterfaceIdentityChanged,
    /// This backend instance already manages the replacement attachment or
    /// the requested persistent pin namespace.
    ManagedAttachment,
    /// Another process holds the host-global lease for this pin namespace.
    ActiveOwner,
    /// The graph is not the exact current schema supported by this SDK build.
    NotCurrentSchema,
    /// At least one forwarding/session map is populated and no drain proof was
    /// supplied.
    PopulatedState,
    /// A pin, loaded program, or replacement tc hook is foreign or replaced.
    IdentityMismatch,
    /// Complete stable kernel state could not be established.
    IndeterminateState,
}

/// Stable progress classification for cleanup committed by current-schema
/// orphan recovery.
///
/// A caller must retry the exact request until it observes
/// [`CurrentEbpfGraphRecoveryOutcome::Removed`] or
/// [`CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryProgress {
    /// Exact graph identity was durably recorded, but no recorded map pin has
    /// yet been removed.
    ProofCommitted,
    /// At least one recorded map pin has been removed and cleanup is pending.
    PinCleanupStarted,
    /// A committed recovery could not classify its exact final state.
    Indeterminate,
}

/// Classified result of current-schema orphan graph recovery.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryOutcome {
    /// The exact orphan graph and its durable cleanup proof were removed.
    Removed,
    /// No canonical graph exists and replacement hook slots are
    /// authoritatively empty.
    AlreadyAbsent,
    /// Recovery was refused before graph deletion was committed.
    Refused(CurrentEbpfGraphRecoveryRefusal),
    /// Cleanup was committed but is incomplete; retry the exact request.
    Partial(CurrentEbpfGraphRecoveryProgress),
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
    /// `Some` requires the backend either to execute the selected policy or
    /// reject it during configuration. The tc eBPF backend accepts only
    /// `SignalPacketTooBig`: every over-MTU encapsulation is a counted drop,
    /// typed Packet-Too-Big guidance remains available to host callers, and
    /// neither an oversized encapsulation nor the inner packet is emitted.
    /// Host implementations may execute `RequireOuterFragmentation` before
    /// transmission. `None` requests no change: a fresh
    /// device gets the pre-policy behavior (only the IPv4 total-length
    /// `u16` limit) and a device with a persisted policy keeps it — use the
    /// backend's explicit policy-update method to change or clear a
    /// persisted policy. Backends whose
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

/// Redaction-safe reason a grouped-session model value is invalid.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuSessionModelError {
    /// A local endpoint or PDP address is unspecified.
    UnspecifiedAddress,
    /// Both endpoint-set addresses use the same family.
    DuplicateEndpointFamily,
    /// The legacy single bind address conflicts with the explicit endpoint set.
    ConflictingLegacyBindAddress,
    /// Local and peer outer addresses use different families.
    OuterFamilyMismatch,
    /// A local outer endpoint aliases the inner PAA identity.
    InnerOuterAlias,
    /// A PDP context lacks a usable link or canonical PAA.
    InvalidContext,
    /// A group has no family entries.
    EmptyGroup,
    /// A group has more than one entry per supported inner family.
    TooManyEntries,
    /// Two entries project the same inner family.
    DuplicateInnerFamily,
    /// Entries refer to different GTP links.
    MixedLinks,
    /// Entries use different GTP versions.
    MixedVersions,
    /// A group and managed attachment carry different stable device IDs.
    DeviceIdentityMismatch,
    /// The live interface does not match every entry's exact attachment.
    AttachmentMismatch,
    /// An entry's local outer address is not in the managed endpoint set.
    LocalEndpointNotManaged,
    /// Selector-reuse evidence names the wrong device, group, or graph.
    ReuseProofMismatch,
}

impl fmt::Display for GtpuSessionModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnspecifiedAddress => "grouped GTP-U address is unspecified",
            Self::DuplicateEndpointFamily => "grouped GTP-U endpoint family is duplicated",
            Self::ConflictingLegacyBindAddress => {
                "legacy GTP-U bind address conflicts with explicit endpoint set"
            }
            Self::OuterFamilyMismatch => "grouped GTP-U outer address families differ",
            Self::InnerOuterAlias => "grouped GTP-U inner and local outer identities alias",
            Self::InvalidContext => "grouped GTP-U PDP context is invalid",
            Self::EmptyGroup => "grouped GTP-U session has no entries",
            Self::TooManyEntries => "grouped GTP-U session has too many entries",
            Self::DuplicateInnerFamily => "grouped GTP-U inner family is duplicated",
            Self::MixedLinks => "grouped GTP-U entries use different links",
            Self::MixedVersions => "grouped GTP-U entries use different versions",
            Self::DeviceIdentityMismatch => "grouped GTP-U device identity differs",
            Self::AttachmentMismatch => "grouped GTP-U attachment differs",
            Self::LocalEndpointNotManaged => "grouped GTP-U local endpoint is not managed",
            Self::ReuseProofMismatch => "grouped GTP-U selector reuse proof differs",
        })
    }
}

impl std::error::Error for GtpuSessionModelError {}

/// One or two exact local outer addresses managed as a single attachment.
///
/// The set is family-canonical and contains at most one IPv4 and one IPv6
/// address. It is attachment authority, not a wildcard: every grouped
/// reconcile, readback, and adoption must revalidate entry membership against
/// the currently proven set.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuLocalEndpointSet {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

impl GtpuLocalEndpointSet {
    /// Construct an exact one- or two-family endpoint set.
    ///
    /// # Errors
    ///
    /// Unspecified addresses and a duplicate family are rejected.
    pub fn new(primary: IpAddr, secondary: Option<IpAddr>) -> Result<Self, GtpuSessionModelError> {
        if primary.is_unspecified() || secondary.is_some_and(|address| address.is_unspecified()) {
            return Err(GtpuSessionModelError::UnspecifiedAddress);
        }
        let mut endpoints = Self {
            ipv4: None,
            ipv6: None,
        };
        for address in [Some(primary), secondary].into_iter().flatten() {
            match address {
                IpAddr::V4(address) if endpoints.ipv4.replace(address).is_some() => {
                    return Err(GtpuSessionModelError::DuplicateEndpointFamily);
                }
                IpAddr::V6(address) if endpoints.ipv6.replace(address).is_some() => {
                    return Err(GtpuSessionModelError::DuplicateEndpointFamily);
                }
                IpAddr::V4(_) | IpAddr::V6(_) => {}
            }
        }
        Ok(endpoints)
    }

    /// Return the exact IPv4 endpoint, if managed.
    #[must_use]
    pub const fn ipv4(self) -> Option<Ipv4Addr> {
        self.ipv4
    }

    /// Return the exact IPv6 endpoint, if managed.
    #[must_use]
    pub const fn ipv6(self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    /// Return whether the exact address belongs to the set.
    #[must_use]
    pub const fn contains(self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => match self.ipv4 {
                Some(expected) => expected.to_bits() == address.to_bits(),
                None => false,
            },
            IpAddr::V6(address) => match self.ipv6 {
                Some(expected) => expected.to_bits() == address.to_bits(),
                None => false,
            },
        }
    }
}

impl fmt::Debug for GtpuLocalEndpointSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuLocalEndpointSet")
            .field("ipv4", &self.ipv4.map(|_| "<redacted>"))
            .field("ipv6", &self.ipv6.map(|_| "<redacted>"))
            .finish()
    }
}

/// Additive device request with exact dual-family endpoint authority.
///
/// `device_id` identifies the stable pin namespace and is deliberately
/// independent of the mutable Linux ifindex. A replacement interface must be
/// proven and rebound independently before this identity authorizes it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CreateGtpDeviceEndpointSetRequest {
    device: CreateGtpDeviceRequest,
    device_id: GtpuSessionDeviceId,
    local_endpoints: GtpuLocalEndpointSet,
}

impl CreateGtpDeviceEndpointSetRequest {
    /// Wrap a legacy-compatible device request with explicit endpoint
    /// authority.
    ///
    /// The legacy `bind_address` must remain unspecified. A concrete value
    /// would create two competing local-address authorities and is rejected.
    pub fn new(
        device: CreateGtpDeviceRequest,
        device_id: GtpuSessionDeviceId,
        local_endpoints: GtpuLocalEndpointSet,
    ) -> Result<Self, GtpuSessionModelError> {
        if !device.bind_address.is_unspecified() {
            return Err(GtpuSessionModelError::ConflictingLegacyBindAddress);
        }
        Ok(Self {
            device,
            device_id,
            local_endpoints,
        })
    }

    /// Underlying device policy/name request.
    #[must_use]
    pub const fn device(&self) -> &CreateGtpDeviceRequest {
        &self.device
    }

    /// Stable managed device/pin-namespace identity.
    #[must_use]
    pub const fn device_id(&self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Exact managed local endpoints.
    #[must_use]
    pub const fn local_endpoints(&self) -> GtpuLocalEndpointSet {
        self.local_endpoints
    }

    /// Consume the request without discarding stable attachment authority.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CreateGtpDeviceRequest,
        GtpuSessionDeviceId,
        GtpuLocalEndpointSet,
    ) {
        (self.device, self.device_id, self.local_endpoints)
    }
}

impl fmt::Debug for CreateGtpDeviceEndpointSetRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateGtpDeviceEndpointSetRequest")
            .field("device", &self.device)
            .field("device_id", &self.device_id)
            .field("local_endpoints", &self.local_endpoints)
            .finish()
    }
}

/// Exact point-in-time attachment selected for grouped capability inspection.
///
/// The stable device ID selects one managed pin namespace while `device`
/// identifies the currently expected name/ifindex binding and
/// `local_endpoints` supplies the exact endpoint authority that must be
/// observed. A successful capability query is scoped to this complete value;
/// it is never a backend-global assertion.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionAttachmentSelector {
    device_id: GtpuSessionDeviceId,
    device: GtpDevice,
    local_endpoints: GtpuLocalEndpointSet,
}

impl GtpuSessionAttachmentSelector {
    /// Construct an exact stable-identity/live-attachment selector.
    ///
    /// # Errors
    ///
    /// An empty interface name or ifindex zero cannot identify a live
    /// attachment and is rejected.
    pub fn new(
        device_id: GtpuSessionDeviceId,
        device: GtpDevice,
        local_endpoints: GtpuLocalEndpointSet,
    ) -> Result<Self, GtpuSessionModelError> {
        if device.name.is_empty() || device.ifindex == 0 {
            return Err(GtpuSessionModelError::AttachmentMismatch);
        }
        Ok(Self {
            device_id,
            device,
            local_endpoints,
        })
    }

    /// Stable managed device/pin-namespace identity.
    #[must_use]
    pub const fn device_id(&self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Exact expected live interface identity.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Exact currently managed local endpoints.
    #[must_use]
    pub const fn local_endpoints(&self) -> GtpuLocalEndpointSet {
        self.local_endpoints
    }
}

impl fmt::Debug for GtpuSessionAttachmentSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionAttachmentSelector")
            .field("device_id", &self.device_id)
            .field("device", &"<redacted-interface-identity>")
            .field("local_endpoints", &self.local_endpoints)
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

fn endpoint_address(address: IpAddr) -> GtpuEndpointAddress {
    match address {
        IpAddr::V4(address) => GtpuEndpointAddress::Ipv4(address.octets()),
        IpAddr::V6(address) => GtpuEndpointAddress::Ipv6(address.octets()),
    }
}

/// One canonical inner-family entry in a grouped session.
///
/// Construction projects `context.ms_address` to the canonical IPv4 `/32` or
/// TS 29.274 IPv6 `/64` forwarding address. The owned context therefore never
/// retains an IPv6 interface identifier that the fixed ABI cannot persist or
/// reconstruct. Outer addresses remain exact `/32` or `/128`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GtpuSessionEntry {
    context: GtpPdpContext,
    inner_paa: GtpuSessionPaa,
    local_outer_address: IpAddr,
}

impl GtpuSessionEntry {
    /// Construct one group entry with an exact local outer address.
    ///
    /// # Errors
    ///
    /// Unspecified addresses, ifindex zero, an unusable PAA prefix, and mixed
    /// local/peer outer families fail closed.
    pub fn new(
        mut context: GtpPdpContext,
        local_outer_address: IpAddr,
    ) -> Result<Self, GtpuSessionModelError> {
        if context.ms_address.is_unspecified()
            || context.peer_address.is_unspecified()
            || local_outer_address.is_unspecified()
            || context.link_ifindex == 0
        {
            return Err(GtpuSessionModelError::InvalidContext);
        }
        if GtpAddressFamily::from_ip(context.peer_address)
            != GtpAddressFamily::from_ip(local_outer_address)
        {
            return Err(GtpuSessionModelError::OuterFamilyMismatch);
        }
        let inner_paa = GtpuSessionPaa::from_full_paa(endpoint_address(context.ms_address))
            .ok_or(GtpuSessionModelError::InvalidContext)?;
        if inner_paa.contains(endpoint_address(local_outer_address)) {
            return Err(GtpuSessionModelError::InnerOuterAlias);
        }
        context.ms_address = match inner_paa.canonical_address() {
            GtpuEndpointAddress::Ipv4(address) => IpAddr::V4(Ipv4Addr::from(address)),
            GtpuEndpointAddress::Ipv6(address) => IpAddr::V6(Ipv6Addr::from(address)),
        };
        Ok(Self {
            context,
            inner_paa,
            local_outer_address,
        })
    }

    /// Complete existing PDP-context policy.
    #[must_use]
    pub const fn context(&self) -> &GtpPdpContext {
        &self.context
    }

    /// Canonical IPv4 `/32` or IPv6 `/64` forwarding identity.
    #[must_use]
    pub const fn inner_paa(&self) -> GtpuSessionPaa {
        self.inner_paa
    }

    /// Exact managed local outer source/destination address.
    #[must_use]
    pub const fn local_outer_address(&self) -> IpAddr {
        self.local_outer_address
    }

    /// Inner family slot.
    #[must_use]
    pub const fn inner_family(&self) -> GtpAddressFamily {
        GtpAddressFamily::from_ip(self.context.ms_address)
    }

    /// Outer transport family.
    #[must_use]
    pub const fn outer_family(&self) -> GtpAddressFamily {
        GtpAddressFamily::from_ip(self.context.peer_address)
    }
}

impl fmt::Debug for GtpuSessionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionEntry")
            .field("inner_family", &self.inner_family())
            .field("outer_family", &self.outer_family())
            .field("attachment_and_routing_identity", &"<redacted>")
            .finish()
    }
}

/// One caller-identified logical session containing one or both inner families.
///
/// Entry order is canonicalized to IPv4 then IPv6. Each entry may use an
/// independent outer family. The same outer-family/local-TEID pair may serve
/// both slots in this one group because downlink authorization first parses
/// and exact-checks the inner family and PAA; it may not alias another group.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionGroup {
    id: GtpuSessionGroupId,
    device_id: GtpuSessionDeviceId,
    entries: Vec<GtpuSessionEntry>,
}

impl GtpuSessionGroup {
    /// Construct a one- or two-family group.
    ///
    /// Group IDs are caller-owned cryptographically unique values and must be
    /// permanently retired after removal for the stable pin-namespace
    /// lifetime. They must not be derived from subscriber/TEID selectors.
    pub fn new(
        id: GtpuSessionGroupId,
        device_id: GtpuSessionDeviceId,
        mut entries: Vec<GtpuSessionEntry>,
    ) -> Result<Self, GtpuSessionModelError> {
        if entries.is_empty() {
            return Err(GtpuSessionModelError::EmptyGroup);
        }
        if entries.len() > 2 {
            return Err(GtpuSessionModelError::TooManyEntries);
        }
        entries.sort_by_key(|entry| match entry.inner_family() {
            GtpAddressFamily::Ipv4 => 0_u8,
            GtpAddressFamily::Ipv6 => 1,
        });
        if entries.len() == 2 && entries[0].inner_family() == entries[1].inner_family() {
            return Err(GtpuSessionModelError::DuplicateInnerFamily);
        }
        let link_ifindex = entries[0].context.link_ifindex;
        if entries
            .iter()
            .any(|entry| entry.context.link_ifindex != link_ifindex)
        {
            return Err(GtpuSessionModelError::MixedLinks);
        }
        let version = entries[0].context.gtp_version;
        if entries
            .iter()
            .any(|entry| entry.context.gtp_version != version)
        {
            return Err(GtpuSessionModelError::MixedVersions);
        }
        Ok(Self {
            id,
            device_id,
            entries,
        })
    }

    /// Stable caller-owned group identity.
    #[must_use]
    pub const fn id(&self) -> GtpuSessionGroupId {
        self.id
    }

    /// Stable managed device/pin-namespace identity.
    #[must_use]
    pub const fn device_id(&self) -> GtpuSessionDeviceId {
        self.device_id
    }

    /// Canonically ordered family entries.
    #[must_use]
    pub fn entries(&self) -> &[GtpuSessionEntry] {
        &self.entries
    }

    /// Revalidate this graph against exact live attachment authority.
    ///
    /// Backends call this on every reconcile, readback, and adoption; success
    /// during construction is never cached as durable proof.
    pub fn validate_attachment(
        &self,
        expected_device_id: GtpuSessionDeviceId,
        device: &GtpDevice,
        local_endpoints: GtpuLocalEndpointSet,
    ) -> Result<(), GtpuSessionModelError> {
        if self.device_id != expected_device_id {
            return Err(GtpuSessionModelError::DeviceIdentityMismatch);
        }
        if device.ifindex == 0
            || self
                .entries
                .iter()
                .any(|entry| entry.context.link_ifindex != device.ifindex)
        {
            return Err(GtpuSessionModelError::AttachmentMismatch);
        }
        if self
            .entries
            .iter()
            .any(|entry| !local_endpoints.contains(entry.local_outer_address))
        {
            return Err(GtpuSessionModelError::LocalEndpointNotManaged);
        }
        Ok(())
    }
}

impl fmt::Debug for GtpuSessionGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionGroup")
            .field("id", &self.id)
            .field("device_id", &self.device_id)
            .field("entries", &self.entries)
            .finish()
    }
}

/// Exact typed selector for grouped-session readback.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuSessionGroupSelector {
    id: GtpuSessionGroupId,
    device_id: GtpuSessionDeviceId,
}

impl GtpuSessionGroupSelector {
    /// Construct a selector that cannot silently cross a managed device.
    #[must_use]
    pub const fn new(id: GtpuSessionGroupId, device_id: GtpuSessionDeviceId) -> Self {
        Self { id, device_id }
    }

    /// Group identity.
    #[must_use]
    pub const fn id(self) -> GtpuSessionGroupId {
        self.id
    }

    /// Expected managed device identity.
    #[must_use]
    pub const fn device_id(self) -> GtpuSessionDeviceId {
        self.device_id
    }
}

impl fmt::Debug for GtpuSessionGroupSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionGroupSelector")
            .field("id", &self.id)
            .field("device_id", &self.device_id)
            .finish()
    }
}

/// Caller evidence that makes one retired selector graph safe to reuse.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuSessionSelectorReuseEvidence {
    /// Every source of packets that could retain the retired index values was
    /// stopped and completely drained before reuse.
    TrafficDrained,
    /// A complete RCU grace period was observed after exact source-group
    /// removal.
    RcuGracePeriodElapsed,
}

/// Explicit attestation for selector/TEID reuse from one exact retired group.
///
/// This value carries the complete old semantic graph so a backend can compare
/// only overlapping selectors and reject invented or cross-device evidence.
/// It does not authorize direct transfer from a still-live source authority:
/// exact source removal must already be proven.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionSelectorReuseProof {
    retired_group: GtpuSessionGroup,
    evidence: GtpuSessionSelectorReuseEvidence,
}

impl GtpuSessionSelectorReuseProof {
    /// Attest that traffic for the exact retired group was fully drained.
    #[must_use]
    pub const fn after_traffic_drain(retired_group: GtpuSessionGroup) -> Self {
        Self {
            retired_group,
            evidence: GtpuSessionSelectorReuseEvidence::TrafficDrained,
        }
    }

    /// Attest that an RCU grace period completed after exact group removal.
    #[must_use]
    pub const fn after_rcu_grace_period(retired_group: GtpuSessionGroup) -> Self {
        Self {
            retired_group,
            evidence: GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed,
        }
    }

    /// Exact graph whose selectors have been retired.
    #[must_use]
    pub const fn retired_group(&self) -> &GtpuSessionGroup {
        &self.retired_group
    }

    /// Kind of external completion evidence supplied by the caller.
    #[must_use]
    pub const fn evidence(&self) -> GtpuSessionSelectorReuseEvidence {
        self.evidence
    }
}

impl fmt::Debug for GtpuSessionSelectorReuseProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionSelectorReuseProof")
            .field(
                "retired_group",
                &GtpuSessionGroupSelector::new(self.retired_group.id, self.retired_group.device_id),
            )
            .field("semantic_graph", &"<redacted>")
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Provenance of selectors newly introduced by one reconciliation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuSessionSelectorProvenance {
    /// The caller's durable registry proves every selector not already owned
    /// by this same active group has never been published in the stable pin
    /// namespace.
    Fresh,
    /// Reuse after exact removal and explicit drain/grace evidence.
    Reused(GtpuSessionSelectorReuseProof),
}

/// Complete request for grouped-session convergence.
///
/// Selector provenance is mandatory because the bounded dataplane journal
/// does not retain permanent selector tombstones. A backend rejects reused or
/// historically indeterminate selectors as
/// [`GtpuSessionGroupIndeterminateReason::GraceUnproven`] unless the request
/// carries exact source-bound completion evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionGroupReconcileRequest {
    desired: GtpuSessionGroup,
    selector_provenance: GtpuSessionSelectorProvenance,
}

impl GtpuSessionGroupReconcileRequest {
    /// Construct a request with an explicit selector-history claim.
    ///
    /// # Errors
    ///
    /// Reuse proof for the same group or another device is rejected before a
    /// backend can inspect or mutate dataplane state.
    pub fn new(
        desired: GtpuSessionGroup,
        selector_provenance: GtpuSessionSelectorProvenance,
    ) -> Result<Self, GtpuSessionModelError> {
        if let GtpuSessionSelectorProvenance::Reused(proof) = &selector_provenance {
            if proof.retired_group.device_id != desired.device_id
                || proof.retired_group.id == desired.id
            {
                return Err(GtpuSessionModelError::ReuseProofMismatch);
            }
        }
        Ok(Self {
            desired,
            selector_provenance,
        })
    }

    /// Desired canonical semantic graph.
    #[must_use]
    pub const fn desired(&self) -> &GtpuSessionGroup {
        &self.desired
    }

    /// Explicit freshness or reuse evidence for introduced selectors.
    #[must_use]
    pub const fn selector_provenance(&self) -> &GtpuSessionSelectorProvenance {
        &self.selector_provenance
    }

    /// Consume the request without discarding mandatory selector provenance.
    #[must_use]
    pub fn into_parts(self) -> (GtpuSessionGroup, GtpuSessionSelectorProvenance) {
        (self.desired, self.selector_provenance)
    }
}

impl fmt::Debug for GtpuSessionGroupReconcileRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuSessionGroupReconcileRequest")
            .field(
                "desired",
                &GtpuSessionGroupSelector::new(self.desired.id, self.desired.device_id),
            )
            .field("semantic_graph", &"<redacted>")
            .field("selector_provenance", &self.selector_provenance)
            .finish()
    }
}

/// Stable reason grouped reconciliation could not prove a final state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuSessionGroupIndeterminateReason {
    /// A map/index/journal graph is partial, malformed, or transitional.
    IncompleteState,
    /// State changed during the bounded observation window.
    StateChanged,
    /// Exact map, program, hook, lease, or pin authority was not proven.
    AuthorityUnavailable,
    /// Mutation final state could not be confirmed after possible ACK loss.
    MutationUnconfirmed,
    /// The durable base/desired journal does not exactly match live state.
    JournalMismatch,
    /// Local endpoint-set membership could not be proven.
    EndpointAuthorityMismatch,
    /// Stable pin identity and live replacement attachment were not both proven.
    AttachmentIdentityMismatch,
    /// The monotonic generation has no successor.
    GenerationExhausted,
    /// Selector/TEID reuse lacks a required RCU grace or traffic-drain proof.
    GraceUnproven,
}

/// Redaction-safe grouped-session conflict classification.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuSessionGroupConflict {
    /// The group ID is already bound to another managed device.
    DeviceAlias,
    /// The group ID identifies a different valid semantic graph.
    GroupMismatch,
    /// A desired selector belongs to another group; cross-group transfer is forbidden.
    SelectorOwnedByAnotherGroup,
}

/// Strict grouped-session readback.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuSessionGroupReadback {
    /// No authority or selector component remains for this never-used ID.
    Absent,
    /// One exact Active authority and complete index graph was proven.
    Active(GtpuSessionGroup),
    /// Exact completeness/equality could not be proven.
    Indeterminate(GtpuSessionGroupIndeterminateReason),
}

/// Classified result of grouped-session convergence.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuSessionGroupReconcileOutcome {
    /// The desired complete graph became the one Active generation.
    Activated,
    /// Exact Active state was already present; this is the only idempotent retry.
    ExactAlreadyActive,
    /// Valid state conflicts and was left untouched.
    Conflict(GtpuSessionGroupConflict),
    /// Final state or exact authority could not be proven.
    Indeterminate(GtpuSessionGroupIndeterminateReason),
}

/// Classified result of exact grouped-session removal.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuSessionGroupRemovalOutcome {
    /// The exact graph was fenced, selectors removed, and authority deleted last.
    Removed,
    /// No component existed for an ID proven never to have been reused.
    AlreadyAbsent,
    /// Valid state differs from the exact expected graph and was untouched.
    Conflict(GtpuSessionGroupConflict),
    /// Exact ownership or final cleanup could not be proven.
    Indeterminate(GtpuSessionGroupIndeterminateReason),
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

/// Uplink checksum/offload contract for software outer IPv6 UDP checksums.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuUplinkChecksumOffloadContract {
    /// The runtime has not independently qualified checksum handling.
    #[default]
    Unknown,
    /// Only fully materialized, non-GSO inner packets are admitted.
    ///
    /// Before room adjustment, tc rejects `gso_size != 0`. It then performs a
    /// reversible non-pseudo `bpf_l4_csum_replace` probe on one safe even
    /// 16-bit word: the first update must visibly change the word, the reverse
    /// update must restore the exact snapshot, and every helper/reload failure
    /// drops. Linux leaves the target unchanged for `CHECKSUM_PARTIAL`, so that
    /// state is rejected without parsing an inner transport header. Only after
    /// this proof may software compute outer IPv6 UDP checksum over materialized
    /// bytes. This contract does not claim GSO or checksum-offload support.
    MaterializedOnly,
    /// This backend cannot execute a correct outer IPv6 UDP checksum contract.
    Unsupported,
}

/// Additive address-family and atomic-group capability report.
///
/// This report is separate from [`GtpuProbe`] so existing public probe literals
/// remain source compatible. `grouped_atomic_reconciliation` is Available only
/// after exact v6 schema/map IDs and normal HASH map types, exact program hooks,
/// canonical endpoint configuration, and the exclusive namespace lease have
/// all been proven. Ordinary Linux generic-netlink GTP remains Missing: its
/// multi-command updates have no external atomic activation gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuIpFamilyCapabilities {
    /// Grouped inner IPv4 `/32` forwarding.
    pub inner_ipv4: GtpuCapability,
    /// Grouped inner IPv6 TS 29.274 `/64` forwarding.
    pub inner_ipv6: GtpuCapability,
    /// Exact outer IPv4 GTP-U transport.
    pub outer_ipv4: GtpuCapability,
    /// Exact outer IPv6 GTP-U transport.
    pub outer_ipv6: GtpuCapability,
    /// One-generation activation for one- or two-family session groups.
    pub grouped_atomic_reconciliation: GtpuCapability,
    /// Managed one- or two-family local endpoint sets.
    pub local_endpoint_sets: GtpuCapability,
    /// Mandatory outer IPv6 UDP checksum generation/verification.
    pub ipv6_udp_checksum: GtpuCapability,
    /// Exact offload/materialization invariant used for uplink checksums.
    pub uplink_checksum_offload: GtpuUplinkChecksumOffloadContract,
}

impl GtpuIpFamilyCapabilities {
    /// Explicit unsupported defaults for backends that have not implemented
    /// and independently qualified the additive grouped contract.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            inner_ipv4: GtpuCapability::Missing,
            inner_ipv6: GtpuCapability::Missing,
            outer_ipv4: GtpuCapability::Missing,
            outer_ipv6: GtpuCapability::Missing,
            grouped_atomic_reconciliation: GtpuCapability::Missing,
            local_endpoint_sets: GtpuCapability::Missing,
            ipv6_udp_checksum: GtpuCapability::Missing,
            uplink_checksum_offload: GtpuUplinkChecksumOffloadContract::Unsupported,
        }
    }
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
    /// Ability to enforce a typed uplink PMTU policy. The effective link MTU
    /// is honored fail closed: over-MTU encapsulations are rejected with a
    /// counted drop and are never emitted or leaked unencapsulated. The eBPF
    /// backend emits no ICMP itself; typed Packet-Too-Big guidance is
    /// available to host callers. The host-only
    /// `RequireOuterFragmentation` policy is rejected because tc redirect
    /// cannot execute the required fragmentation.
    pub uplink_pmtu_enforcement: GtpuCapability,
    /// The backend's demonstrated contract for fragmented outer downlink
    /// packets: a bounded kernel-reassembly handoff whose reassembled
    /// datagrams re-enter the SDK GTP-U consumer exactly once, or an
    /// explicit unsupported statement. The handoff contract is
    /// handoff-capable only: it is complete only while the operator runs an
    /// SDK consumer bound on the concrete local S2b-U address (never
    /// `0.0.0.0`); without one, reassembled sets are answered with ICMP
    /// port unreachable and dropped. A backend must never leave this
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

    #[test]
    fn current_graph_recovery_request_is_typed_and_redacts_deployment_identity() {
        let request = CurrentEbpfGraphRecoveryRequest::new(
            "tenant-sensitive-pin",
            CurrentEbpfGraphWriterProof::previous_writer_stopped(),
        )
        .with_replacement_device(GtpDevice {
            name: "tenant-sensitive-interface".to_string(),
            ifindex: 41,
        })
        .with_drain_proof(CurrentEbpfGraphDrainProof::sessions_and_traffic_drained());

        assert_eq!(request.pin_namespace(), "tenant-sensitive-pin");
        assert_eq!(
            request.replacement_device().map(|device| device.ifindex),
            Some(41)
        );
        assert_eq!(
            request.writer_proof(),
            CurrentEbpfGraphWriterProof::previous_writer_stopped()
        );
        assert!(request.drain_proof().is_some());
        let debug = format!("{request:?}");
        assert!(!debug.contains("tenant-sensitive-pin"));
        assert!(!debug.contains("tenant-sensitive-interface"));
        assert!(!debug.contains("41"));
    }

    #[test]
    fn grouped_endpoint_set_is_exact_canonical_and_redacted() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1));
        let endpoints = GtpuLocalEndpointSet::new(ipv6, Some(ipv4)).unwrap();
        assert!(endpoints.contains(ipv4));
        assert!(endpoints.contains(ipv6));
        assert!(!endpoints.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert_eq!(
            GtpuLocalEndpointSet::new(ipv4, Some(IpAddr::V4(Ipv4Addr::LOCALHOST))),
            Err(GtpuSessionModelError::DuplicateEndpointFamily)
        );
        assert_eq!(
            GtpuLocalEndpointSet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), None),
            Err(GtpuSessionModelError::UnspecifiedAddress)
        );

        let device_id = GtpuSessionDeviceId::new([2; 16]).unwrap();
        let request = CreateGtpDeviceEndpointSetRequest::new(
            CreateGtpDeviceRequest::new("gtp0"),
            device_id,
            endpoints,
        )
        .unwrap();
        assert_eq!(request.device_id(), device_id);
        assert_eq!(request.local_endpoints(), endpoints);
        let (round_trip_device, round_trip_device_id, round_trip_endpoints) =
            request.clone().into_parts();
        assert_eq!(&round_trip_device, request.device());
        assert_eq!(round_trip_device_id, device_id);
        assert_eq!(round_trip_endpoints, endpoints);
        let mut conflicting = CreateGtpDeviceRequest::new("gtp0");
        conflicting.bind_address = ipv4;
        assert_eq!(
            CreateGtpDeviceEndpointSetRequest::new(conflicting, device_id, endpoints),
            Err(GtpuSessionModelError::ConflictingLegacyBindAddress)
        );
        let attachment = GtpuSessionAttachmentSelector::new(
            device_id,
            GtpDevice {
                name: "tenant-sensitive-interface".to_string(),
                ifindex: 41,
            },
            endpoints,
        )
        .unwrap();
        assert_eq!(attachment.device_id(), device_id);
        assert_eq!(attachment.device().ifindex, 41);
        assert_eq!(attachment.local_endpoints(), endpoints);
        assert_eq!(
            GtpuSessionAttachmentSelector::new(
                device_id,
                GtpDevice {
                    name: "gtp0".to_string(),
                    ifindex: 0,
                },
                endpoints,
            ),
            Err(GtpuSessionModelError::AttachmentMismatch)
        );
        let debug = format!(
            "{request:?} {endpoints:?} {attachment:?} \
             {round_trip_device:?} {round_trip_device_id:?} {round_trip_endpoints:?}"
        );
        for secret in [
            "192.0.2.1",
            "2001:db8",
            "[2, 2",
            "tenant-sensitive-interface",
            "41",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn grouped_session_normalizes_ipv6_paa_and_revalidates_attachment() {
        let ipv4_local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let ipv6_local = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1));
        let ipv4_entry = GtpuSessionEntry::new(reconciliation_context(), ipv4_local).unwrap();
        let mut ipv6_context = reconciliation_context();
        ipv6_context.local_teid = Teid::new(0x1234_5679).unwrap();
        ipv6_context.peer_teid = Teid::new(0x8765_4322).unwrap();
        ipv6_context.ms_address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0xbeef));
        ipv6_context.peer_address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 10));
        let mut same_prefix_context = ipv6_context.clone();
        same_prefix_context.ms_address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 7));
        let ipv6_entry = GtpuSessionEntry::new(ipv6_context, ipv6_local).unwrap();
        let same_prefix_entry = GtpuSessionEntry::new(same_prefix_context, ipv6_local).unwrap();
        assert_eq!(
            ipv6_entry.context().ms_address,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0))
        );
        assert_eq!(
            ipv6_entry, same_prefix_entry,
            "equality must contain only state reconstructible from the /64 ABI"
        );
        assert!(ipv6_entry.inner_paa().contains(GtpuEndpointAddress::Ipv6(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 7).octets()
        )));
        assert!(!ipv6_entry.inner_paa().contains(GtpuEndpointAddress::Ipv6(
            Ipv6Addr::new(0x2001, 0xdb8, 1, 1, 0, 0, 0, 7).octets()
        )));

        let group_id = GtpuSessionGroupId::new([1; 16]).unwrap();
        let device_id = GtpuSessionDeviceId::new([2; 16]).unwrap();
        let group = GtpuSessionGroup::new(
            group_id,
            device_id,
            vec![ipv6_entry.clone(), ipv4_entry.clone()],
        )
        .unwrap();
        assert_eq!(group.entries()[0].inner_family(), GtpAddressFamily::Ipv4);
        assert_eq!(group.entries()[1].inner_family(), GtpAddressFamily::Ipv6);
        assert_eq!(
            GtpuSessionGroup::new(
                group_id,
                device_id,
                vec![ipv4_entry.clone(), ipv4_entry.clone()]
            ),
            Err(GtpuSessionModelError::DuplicateInnerFamily)
        );

        let device = GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 7,
        };
        let endpoints = GtpuLocalEndpointSet::new(ipv4_local, Some(ipv6_local)).unwrap();
        assert_eq!(
            group.validate_attachment(device_id, &device, endpoints),
            Ok(())
        );
        assert_eq!(
            group.validate_attachment(
                GtpuSessionDeviceId::new([3; 16]).unwrap(),
                &device,
                endpoints
            ),
            Err(GtpuSessionModelError::DeviceIdentityMismatch)
        );
        let wrong_endpoints =
            GtpuLocalEndpointSet::new(ipv4_local, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))).unwrap();
        assert_eq!(
            group.validate_attachment(device_id, &device, wrong_endpoints),
            Err(GtpuSessionModelError::LocalEndpointNotManaged)
        );
        let replacement = GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 8,
        };
        assert_eq!(
            group.validate_attachment(device_id, &replacement, endpoints),
            Err(GtpuSessionModelError::AttachmentMismatch)
        );

        let debug = format!("{group:?}");
        for secret in ["10.23.0.2", "2001:db8", "12345678", "[1, 1", "[2, 2"] {
            assert!(!debug.contains(secret));
        }

        let desired = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([3; 16]).unwrap(),
            device_id,
            group.entries().to_vec(),
        )
        .unwrap();
        let reuse_proof = GtpuSessionSelectorReuseProof::after_rcu_grace_period(group.clone());
        let reconcile = GtpuSessionGroupReconcileRequest::new(
            desired.clone(),
            GtpuSessionSelectorProvenance::Reused(reuse_proof),
        )
        .unwrap();
        assert_eq!(reconcile.desired(), &desired);
        assert!(matches!(
            reconcile.selector_provenance(),
            GtpuSessionSelectorProvenance::Reused(proof)
                if proof.retired_group() == &group
                    && proof.evidence()
                        == GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed
        ));
        let (round_trip_desired, round_trip_provenance) = reconcile.clone().into_parts();
        assert_eq!(round_trip_desired, desired);
        assert_eq!(
            round_trip_provenance,
            reconcile.selector_provenance().clone()
        );
        let parts_debug = format!("{round_trip_desired:?} {round_trip_provenance:?}");
        for secret in ["10.23.0.2", "2001:db8", "gtp0", "ifindex", "[1, 1"] {
            assert!(!parts_debug.contains(secret));
        }
        let same_group_proof = GtpuSessionSelectorReuseProof::after_traffic_drain(desired.clone());
        assert_eq!(
            GtpuSessionGroupReconcileRequest::new(
                desired.clone(),
                GtpuSessionSelectorProvenance::Reused(same_group_proof),
            ),
            Err(GtpuSessionModelError::ReuseProofMismatch)
        );
        let other_device_source = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([4; 16]).unwrap(),
            GtpuSessionDeviceId::new([9; 16]).unwrap(),
            group.entries().to_vec(),
        )
        .unwrap();
        assert_eq!(
            GtpuSessionGroupReconcileRequest::new(
                desired,
                GtpuSessionSelectorProvenance::Reused(
                    GtpuSessionSelectorReuseProof::after_traffic_drain(other_device_source,),
                ),
            ),
            Err(GtpuSessionModelError::ReuseProofMismatch)
        );
        let debug = format!("{reconcile:?}");
        for secret in ["10.23.0.2", "2001:db8", "gtp0", "ifindex", "[1, 1"] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn grouped_entry_rejects_outer_mismatch_and_inner_outer_alias() {
        let mut mismatch = reconciliation_context();
        mismatch.peer_address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 10));
        assert_eq!(
            GtpuSessionEntry::new(mismatch, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Err(GtpuSessionModelError::OuterFamilyMismatch)
        );

        let mut alias = reconciliation_context();
        alias.peer_address = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3));
        assert_eq!(
            GtpuSessionEntry::new(alias, IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2))),
            Err(GtpuSessionModelError::InnerOuterAlias)
        );
    }

    #[test]
    fn unqualified_grouped_capabilities_are_explicitly_unsupported() {
        let capabilities = GtpuIpFamilyCapabilities::unsupported();
        assert_eq!(
            capabilities.grouped_atomic_reconciliation,
            GtpuCapability::Missing
        );
        assert_eq!(capabilities.inner_ipv6, GtpuCapability::Missing);
        assert_eq!(capabilities.outer_ipv6, GtpuCapability::Missing);
        assert_eq!(
            capabilities.uplink_checksum_offload,
            GtpuUplinkChecksumOffloadContract::Unsupported
        );
    }
}
