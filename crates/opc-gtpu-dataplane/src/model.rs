//! Safe model types for Linux GTP-U dataplane backend operations.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use opc_gtpu_ebpf_common::GtpuEndpointAddress;
pub use opc_gtpu_ebpf_common::{
    GtpuDownlinkFragmentContract, GtpuOuterFragmentPolicy, GtpuReassemblyBounds,
    GtpuSessionDeviceId, GtpuSessionGroupId, GtpuSessionPaa, GtpuSourcePortPolicy,
    GtpuSourcePortRange, GtpuUplinkMtuPolicy, GtpuUplinkSourcePortPolicy,
};
use opc_types::DscpCodepoint;
use sha2::{Digest, Sha256};

/// Default GTP-U UDP port.
pub const GTPU_PORT: u16 = 2152;
/// Default PDP context hash size used by libgtpnl examples.
pub const DEFAULT_PDP_HASHSIZE: u32 = 131_072;

/// Fixed external-fence contract for current-schema eBPF graph retirement.
///
/// This is deliberately distinct from the frozen shipped-25 historical
/// recovery contract.  Both contracts consume the same kind of live node
/// authority, but a current graph must never be mistaken for a historical
/// compatibility target.
pub const CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID: &str =
    "opc.gtpu.current-ebpf-graph-recovery-authority.r1";
/// Wire-compatible version of [`CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID`].
pub const CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION: u16 = 1;

/// Stable codec identity of the fsynced current-terminal WAL.
///
/// The WAL is retained outside the deleted graph and is the only durable
/// current-graph terminal evidence.  A legacy outcome alone is never a
/// terminal receipt.
pub const CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_WAL_CODEC_ID: &str =
    "opc.gtpu.current-ebpf-recovery-terminal-wal.r1";

/// Stable codec identity of the redaction-safe current terminal receipt
/// commitment used by an external broker's retired-to-new authority CAS.
pub const CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_RECEIPT_CODEC_ID: &str =
    "opc.gtpu.current-ebpf-recovery-terminal-receipt.r1";

/// Stable codec identity of an authenticated current terminal transfer.
pub const CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_TRANSFER_CODEC_ID: &str =
    "opc.gtpu.current-ebpf-recovery-terminal-transfer.r1";

/// Closed provenance of the graph evidence retained by an authenticated
/// current-terminal WAL.
///
/// The `HistoricalR5Handoff` variant is deliberately separate from the
/// current graph commitment: its 25-map commitment is never interpreted as a
/// current 34-map inventory. The terminal WAL retains the sealed R5 record
/// codec/KAT binding and revalidates that source receipt under the same
/// target locks before it can issue this projection.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryTerminalSource {
    /// The terminal retired only an exact current-schema graph.
    CurrentGraph,
    /// The current terminal was created in a namespace whose authenticated
    /// shipped-25 R5 handoff remains retained in the target authority leaf.
    HistoricalR5Handoff {
        /// The sealed exact shipped-25 graph commitment. This is opaque and
        /// comparable; it contains no map IDs or paths.
        exact_historical_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
    },
}

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

/// Which build of the eBPF datapath program a live tc hook is running.
///
/// A hook is judged by the program tag the kernel computed for it, compared
/// against tags derived offline from the objects this build carries. The
/// judgement is about the instruction stream, not about map shape: two builds
/// can agree on every map and still be different generations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfDatapathGeneration {
    /// The generation this build itself would attach.
    Current,
    /// A named generation older than this build's.
    Historical(EbpfHistoricalDatapathGeneration),
    /// A hook carrying an SDK program name whose tag matches no generation
    /// this build can name. Its behaviour is unknown, so it is never treated
    /// as compatible.
    ///
    /// This is broader than "foreign". Only the generations listed in
    /// [`EbpfHistoricalDatapathGeneration`] are named, so a superseded
    /// generation this build embeds for other purposes but does not yet carry
    /// as a tag candidate — the frozen bearer-v2 datapath among them — also
    /// reports here. The refusal is identical either way, so what that costs is
    /// operator evidence rather than safety.
    Unrecognized,
}

/// A superseded datapath generation this build can still recognise on a hook.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EbpfHistoricalDatapathGeneration {
    /// The frozen endpoint-unbound generation from before per-bearer marks.
    ///
    /// Its retained counter map is narrower than the current program indexes,
    /// so it cannot be replaced in place even though this build can identify
    /// its hook tags exactly.
    PreBearerMark,
    /// The generation immediately preceding the uplink redirect-outcome
    /// counter, whose counter map carries one slot fewer than this build
    /// indexes.
    PreUplinkRedirectCounter,
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

/// Cloneable, non-authorizing plan for current-schema graph retirement.
///
/// A retry recreates an affine live authority and combines it with this value
/// through [`CurrentEbpfGraphRecoveryIntent::into_request_with_authority`].
/// Keeping the intent separate prevents a cached request from standing in for
/// a live node-fence check.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentEbpfGraphRecoveryIntent {
    pin_namespace: String,
    replacement_device: Option<GtpDevice>,
    writer_proof: CurrentEbpfGraphWriterProof,
    drain_proof: Option<CurrentEbpfGraphDrainProof>,
}

impl CurrentEbpfGraphRecoveryIntent {
    /// Build a current-schema recovery plan which requires empty forwarding
    /// maps unless a drain proof is explicitly supplied.
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

    /// Require the replacement interface to retain this exact identity.
    #[must_use]
    pub fn with_replacement_device(mut self, replacement_device: GtpDevice) -> Self {
        self.replacement_device = Some(replacement_device);
        self
    }

    /// Permit a graph with forwarding state only after explicit draining.
    #[must_use]
    pub const fn with_drain_proof(mut self, drain_proof: CurrentEbpfGraphDrainProof) -> Self {
        self.drain_proof = Some(drain_proof);
        self
    }

    /// Bind this retryable plan to one newly acquired live external authority.
    #[must_use]
    pub fn into_request_with_authority(
        self,
        authority: CurrentEbpfGraphRecoveryAuthority,
    ) -> CurrentEbpfGraphRecoveryAuthorizedRequest {
        CurrentEbpfGraphRecoveryAuthorizedRequest {
            intent: self,
            authority,
        }
    }

    #[must_use]
    pub fn pin_namespace(&self) -> &str {
        &self.pin_namespace
    }

    #[must_use]
    pub const fn replacement_device(&self) -> Option<&GtpDevice> {
        self.replacement_device.as_ref()
    }

    #[must_use]
    pub const fn writer_proof(&self) -> CurrentEbpfGraphWriterProof {
        self.writer_proof
    }

    #[must_use]
    pub const fn drain_proof(&self) -> Option<CurrentEbpfGraphDrainProof> {
        self.drain_proof
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentEbpfGraphRecoveryIntent")
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

impl From<CurrentEbpfGraphRecoveryRequest> for CurrentEbpfGraphRecoveryIntent {
    fn from(request: CurrentEbpfGraphRecoveryRequest) -> Self {
        Self {
            pin_namespace: request.pin_namespace,
            replacement_device: request.replacement_device,
            writer_proof: request.writer_proof,
            drain_proof: request.drain_proof,
        }
    }
}

/// Bounded construction failures for current-schema external authority.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryAuthorityError {
    /// A fixed-width commitment was all zeroes.
    ZeroCommitment,
    /// The fixed-width operation identifier was all zeroes.
    ZeroOperationId,
}

impl fmt::Display for CurrentEbpfGraphRecoveryAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCommitment => f.write_str("current recovery commitment is invalid"),
            Self::ZeroOperationId => f.write_str("current recovery operation is invalid"),
        }
    }
}

impl std::error::Error for CurrentEbpfGraphRecoveryAuthorityError {}

/// Opaque nonzero external scope, predecessor-basis, or target commitment for
/// current-schema graph retirement.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryCommitment([u8; 32]);

impl CurrentEbpfGraphRecoveryCommitment {
    /// Construct a fixed-width nonzero commitment without exposing its source.
    pub fn new(value: [u8; 32]) -> Result<Self, CurrentEbpfGraphRecoveryAuthorityError> {
        if value == [0; 32] {
            Err(CurrentEbpfGraphRecoveryAuthorityError::ZeroCommitment)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentEbpfGraphRecoveryCommitment(<opaque>)")
    }
}

/// Opaque nonzero operation identifier for one current-schema recovery
/// attempt.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryOperationId([u8; 16]);

impl CurrentEbpfGraphRecoveryOperationId {
    /// Construct a fixed-width nonzero operation identifier.
    pub fn new(value: [u8; 16]) -> Result<Self, CurrentEbpfGraphRecoveryAuthorityError> {
        if value == [0; 16] {
            Err(CurrentEbpfGraphRecoveryAuthorityError::ZeroOperationId)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub(crate) const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentEbpfGraphRecoveryOperationId(<opaque>)")
    }
}

/// Opaque host, bpffs-root, and graph-leaf commitments for current recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryHostCommitments {
    host: CurrentEbpfGraphRecoveryCommitment,
    root: CurrentEbpfGraphRecoveryCommitment,
    leaf: CurrentEbpfGraphRecoveryCommitment,
}

impl CurrentEbpfGraphRecoveryHostCommitments {
    /// Bind this authority to one committed host, bpffs root, and graph leaf.
    #[must_use]
    pub const fn new(
        host: CurrentEbpfGraphRecoveryCommitment,
        root: CurrentEbpfGraphRecoveryCommitment,
        leaf: CurrentEbpfGraphRecoveryCommitment,
    ) -> Self {
        Self { host, root, leaf }
    }

    #[must_use]
    pub const fn host(self) -> CurrentEbpfGraphRecoveryCommitment {
        self.host
    }

    #[must_use]
    pub const fn root(self) -> CurrentEbpfGraphRecoveryCommitment {
        self.root
    }

    #[must_use]
    pub const fn leaf(self) -> CurrentEbpfGraphRecoveryCommitment {
        self.leaf
    }
}

/// Stable result of one mandatory live current-schema authority check.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryAuthorityCurrentness {
    /// The external node authority is no longer held by this attempt.
    Changed,
    /// The live authority now names a different exact binding.
    Mismatch,
    /// The external authority could not be read conclusively.
    Unavailable,
}

/// Object-safe asynchronous source of current external authority.
///
/// The SDK awaits this check after its current root and graph locks and before
/// and after every irreversible proof, pin, and directory effect. A
/// successful check must also prove that the caller holds a host-global,
/// target-scoped maintenance exclusion covering every SDK creator of the
/// target graph and its target authority leaves for the whole authority
/// lifetime. It must perform a fresh live authority read for every invocation;
/// cached currentness, construction-time attestation, or a lock that permits a
/// concurrent creator is not sufficient.
pub trait CurrentEbpfGraphRecoveryCurrentnessGuard: Send + Sync {
    /// Prove that the exact authority remains current at this instant.
    fn verify_current(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), CurrentEbpfGraphRecoveryAuthorityCurrentness>>
                + Send
                + 'static,
        >,
    >;
}

/// Copyable receipt/proof projection of an affine current recovery authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryAuthorityBinding {
    contract_version: u16,
    scope_commitment: CurrentEbpfGraphRecoveryCommitment,
    predecessor_basis_commitment: CurrentEbpfGraphRecoveryCommitment,
    fence_epoch: NonZeroU64,
    operation_id: CurrentEbpfGraphRecoveryOperationId,
    host_commitments: CurrentEbpfGraphRecoveryHostCommitments,
}

impl CurrentEbpfGraphRecoveryAuthorityBinding {
    /// Recreate a receipt-safe expected binding from the fixed-width
    /// commitments retained by an external terminal broker.
    ///
    /// This constructor does not authorize mutation. It can only be consumed
    /// by [`CurrentEbpfGraphRecoveryTerminalTransfer`], whose runtime path
    /// compares every component with an SDK-authenticated retained WAL while
    /// a newly live affine authority is held. It therefore lets a
    /// cross-language broker carry an old terminal binding without exposing
    /// paths, map IDs, or private SDK record bytes.
    #[must_use]
    pub const fn new(
        scope_commitment: CurrentEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: CurrentEbpfGraphRecoveryCommitment,
        fence_epoch: NonZeroU64,
        operation_id: CurrentEbpfGraphRecoveryOperationId,
        host_commitments: CurrentEbpfGraphRecoveryHostCommitments,
    ) -> Self {
        Self {
            contract_version: CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
            scope_commitment,
            predecessor_basis_commitment,
            fence_epoch,
            operation_id,
            host_commitments,
        }
    }

    #[must_use]
    pub const fn contract_version(self) -> u16 {
        self.contract_version
    }

    #[must_use]
    pub const fn scope_commitment(self) -> CurrentEbpfGraphRecoveryCommitment {
        self.scope_commitment
    }

    #[must_use]
    pub const fn predecessor_basis_commitment(self) -> CurrentEbpfGraphRecoveryCommitment {
        self.predecessor_basis_commitment
    }

    #[must_use]
    pub const fn fence_epoch(self) -> NonZeroU64 {
        self.fence_epoch
    }

    #[must_use]
    pub const fn operation_id(self) -> CurrentEbpfGraphRecoveryOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn host_commitments(self) -> CurrentEbpfGraphRecoveryHostCommitments {
        self.host_commitments
    }
}

/// Affine live external authority for one current-schema recovery attempt.
///
/// This type is intentionally not `Clone`. A bounded retry retains the
/// cloneable intent and acquires a fresh authority/guard before each call.
pub struct CurrentEbpfGraphRecoveryAuthority {
    binding: CurrentEbpfGraphRecoveryAuthorityBinding,
    guard: Box<dyn CurrentEbpfGraphRecoveryCurrentnessGuard>,
}

impl CurrentEbpfGraphRecoveryAuthority {
    /// Construct one current-schema authority binding and its live guard.
    #[must_use]
    pub fn new(
        scope_commitment: CurrentEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: CurrentEbpfGraphRecoveryCommitment,
        fence_epoch: NonZeroU64,
        operation_id: CurrentEbpfGraphRecoveryOperationId,
        host_commitments: CurrentEbpfGraphRecoveryHostCommitments,
        guard: Box<dyn CurrentEbpfGraphRecoveryCurrentnessGuard>,
    ) -> Self {
        Self {
            binding: CurrentEbpfGraphRecoveryAuthorityBinding {
                contract_version: CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
                scope_commitment,
                predecessor_basis_commitment,
                fence_epoch,
                operation_id,
                host_commitments,
            },
            guard,
        }
    }

    /// Return the immutable binding persisted in the current proof record.
    #[must_use]
    pub const fn binding(&self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.binding
    }

    pub(crate) fn verify_current(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), CurrentEbpfGraphRecoveryAuthorityCurrentness>>
                + Send
                + 'static,
        >,
    > {
        self.guard.verify_current()
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentEbpfGraphRecoveryAuthority")
            .field("binding", &self.binding)
            .field("guard", &"<affine-live-guard>")
            .finish()
    }
}

/// Authority-bearing current-schema recovery request.
///
/// This value is non-cloneable because it owns the live guard. Create it from
/// a [`CurrentEbpfGraphRecoveryIntent`] for each retry.
pub struct CurrentEbpfGraphRecoveryAuthorizedRequest {
    intent: CurrentEbpfGraphRecoveryIntent,
    authority: CurrentEbpfGraphRecoveryAuthority,
}

impl CurrentEbpfGraphRecoveryAuthorizedRequest {
    /// Return the retryable non-authorizing request plan.
    #[must_use]
    pub const fn intent(&self) -> &CurrentEbpfGraphRecoveryIntent {
        &self.intent
    }

    /// Return the receipt-safe external authority binding.
    #[must_use]
    pub const fn authority_binding(&self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.authority.binding()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CurrentEbpfGraphRecoveryIntent,
        CurrentEbpfGraphRecoveryAuthority,
    ) {
        (self.intent, self.authority)
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryAuthorizedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentEbpfGraphRecoveryAuthorizedRequest")
            .field("intent", &self.intent)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Fixed-width redaction-safe commitment of an authenticated current terminal
/// receipt.
///
/// The bytes are deliberately public: they are derived only from fixed SDK
/// contract labels, opaque commitments, the fence epoch, operation ID, and
/// the SDK-computed graph commitment. They contain no path, map ID, endpoint,
/// object ID, key, or payload and are intended for an external durable CAS.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryTerminalReceiptCommitment([u8; 32]);

impl CurrentEbpfGraphRecoveryTerminalReceiptCommitment {
    /// Recreate a nonzero retained terminal receipt commitment supplied by an
    /// external broker. This value is an expected checksum only; it cannot
    /// create or authorize a terminal state.
    pub fn new(value: [u8; 32]) -> Result<Self, CurrentEbpfGraphRecoveryAuthorityError> {
        if value == [0; 32] {
            Err(CurrentEbpfGraphRecoveryAuthorityError::ZeroCommitment)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the fixed-width, redaction-safe canonical receipt commitment.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn for_terminal(
        authority: CurrentEbpfGraphRecoveryAuthorityBinding,
        graph: CurrentEbpfGraphRecoveryCommitment,
        source: CurrentEbpfGraphRecoveryTerminalSource,
    ) -> Self {
        let host = authority.host_commitments();
        let mut digest = Sha256::new();
        digest.update(b"opc.gtpu.current-ebpf-terminal-receipt\\0r1");
        digest.update(CURRENT_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID.as_bytes());
        digest.update(CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_WAL_CODEC_ID.as_bytes());
        digest.update(CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_RECEIPT_CODEC_ID.as_bytes());
        digest.update(authority.contract_version().to_be_bytes());
        digest.update(authority.scope_commitment().bytes());
        digest.update(authority.predecessor_basis_commitment().bytes());
        digest.update(authority.fence_epoch().get().to_be_bytes());
        digest.update(authority.operation_id().bytes());
        digest.update(host.host().bytes());
        digest.update(host.root().bytes());
        digest.update(host.leaf().bytes());
        digest.update(graph.bytes());
        match source {
            CurrentEbpfGraphRecoveryTerminalSource::CurrentGraph => {
                digest.update([0]);
            }
            CurrentEbpfGraphRecoveryTerminalSource::HistoricalR5Handoff {
                exact_historical_graph_commitment,
            } => {
                digest.update([1]);
                digest.update(HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID.as_bytes());
                digest.update(HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID.as_bytes());
                digest.update(exact_historical_graph_commitment.bytes());
            }
        }
        Self(digest.finalize().into())
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryTerminalReceiptCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentEbpfGraphRecoveryTerminalReceiptCommitment(<redaction-safe>)")
    }
}

/// Authenticated immediate predecessor of a current-terminal transfer.
///
/// This is a bounded projection of a durable terminal WAL. It lets a worker
/// prove exactly which retired authority it consumed without reconstructing
/// SDK-private map identities or accepting a loose `Removed` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryTerminalAdoption {
    prior_authority: CurrentEbpfGraphRecoveryAuthorityBinding,
    prior_terminal_receipt_commitment: CurrentEbpfGraphRecoveryTerminalReceiptCommitment,
}

impl CurrentEbpfGraphRecoveryTerminalAdoption {
    pub(crate) const fn new(
        prior_authority: CurrentEbpfGraphRecoveryAuthorityBinding,
        prior_terminal_receipt_commitment: CurrentEbpfGraphRecoveryTerminalReceiptCommitment,
    ) -> Self {
        Self {
            prior_authority,
            prior_terminal_receipt_commitment,
        }
    }

    /// Return the exact prior terminal authority binding retained by the WAL.
    #[must_use]
    pub const fn prior_authority(self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.prior_authority
    }

    /// Return the prior canonical terminal receipt commitment.
    #[must_use]
    pub const fn prior_terminal_receipt_commitment(
        self,
    ) -> CurrentEbpfGraphRecoveryTerminalReceiptCommitment {
        self.prior_terminal_receipt_commitment
    }
}

/// Broker-retained exact predecessor required to transfer a durable current
/// terminal WAL to a new affine authority.
///
/// Constructing this value has no kernel effect. The transfer operation
/// requires the retained WAL to authenticate this exact binding and receipt
/// commitment, prove the graph remains absent, and then bind the new live
/// authority. A stale, forged, missing, or ambiguous predecessor is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryTerminalTransfer {
    prior_authority: CurrentEbpfGraphRecoveryAuthorityBinding,
    prior_terminal_receipt_commitment: CurrentEbpfGraphRecoveryTerminalReceiptCommitment,
}

impl CurrentEbpfGraphRecoveryTerminalTransfer {
    /// Build a transfer expectation from the exact authority and receipt
    /// commitment retained by the external terminal broker.
    #[must_use]
    pub const fn new(
        prior_authority: CurrentEbpfGraphRecoveryAuthorityBinding,
        prior_terminal_receipt_commitment: CurrentEbpfGraphRecoveryTerminalReceiptCommitment,
    ) -> Self {
        Self {
            prior_authority,
            prior_terminal_receipt_commitment,
        }
    }

    /// Project an authenticated terminal receipt into the only transferable
    /// predecessor form. Pristine read-only absence has no durable WAL and
    /// therefore deliberately returns `None`.
    #[must_use]
    pub const fn from_authenticated_receipt(
        receipt: CurrentEbpfGraphRecoveryReceipt,
    ) -> Option<Self> {
        match (
            receipt.terminal_kind,
            receipt.terminal_absence_proof,
            receipt.outcome,
            receipt.exact_graph_commitment,
            receipt.terminal_receipt_commitment,
        ) {
            (
                Some(CurrentEbpfGraphRecoveryTerminalKind::AuthenticatedTerminal),
                CurrentEbpfGraphTerminalAbsenceProof::Proven,
                CurrentEbpfGraphRecoveryOutcome::Removed
                | CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent,
                Some(_),
                Some(commitment),
            ) => Some(Self::new(receipt.authority, commitment)),
            _ => None,
        }
    }

    #[must_use]
    pub const fn prior_authority(self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.prior_authority
    }

    #[must_use]
    pub const fn prior_terminal_receipt_commitment(
        self,
    ) -> CurrentEbpfGraphRecoveryTerminalReceiptCommitment {
        self.prior_terminal_receipt_commitment
    }
}

/// Affine request to authenticate and transfer a retained current-terminal
/// WAL to a newly live authority.
///
/// Retrying retains the cloneable intent and transfer expectation but always
/// recreates the new authority/guard. The operation never deletes the WAL.
pub struct CurrentEbpfGraphRecoveryTerminalTransferRequest {
    intent: CurrentEbpfGraphRecoveryIntent,
    transfer: CurrentEbpfGraphRecoveryTerminalTransfer,
    authority: CurrentEbpfGraphRecoveryAuthority,
}

impl CurrentEbpfGraphRecoveryIntent {
    /// Bind a retained terminal expectation to one newly acquired live
    /// authority for a broker-authorized transfer.
    #[must_use]
    pub fn into_terminal_transfer_request(
        self,
        transfer: CurrentEbpfGraphRecoveryTerminalTransfer,
        authority: CurrentEbpfGraphRecoveryAuthority,
    ) -> CurrentEbpfGraphRecoveryTerminalTransferRequest {
        CurrentEbpfGraphRecoveryTerminalTransferRequest {
            intent: self,
            transfer,
            authority,
        }
    }
}

impl CurrentEbpfGraphRecoveryTerminalTransferRequest {
    #[must_use]
    pub const fn intent(&self) -> &CurrentEbpfGraphRecoveryIntent {
        &self.intent
    }

    #[must_use]
    pub const fn transfer(&self) -> CurrentEbpfGraphRecoveryTerminalTransfer {
        self.transfer
    }

    #[must_use]
    pub const fn authority_binding(&self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.authority.binding()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CurrentEbpfGraphRecoveryIntent,
        CurrentEbpfGraphRecoveryTerminalTransfer,
        CurrentEbpfGraphRecoveryAuthority,
    ) {
        (self.intent, self.transfer, self.authority)
    }
}

impl fmt::Debug for CurrentEbpfGraphRecoveryTerminalTransferRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CurrentEbpfGraphRecoveryTerminalTransferRequest")
            .field("intent", &self.intent)
            .field("transfer", &self.transfer)
            .field("authority", &self.authority)
            .finish()
    }
}

/// Stable reason current-schema orphan recovery was refused before graph
/// deletion was committed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryRefusal {
    /// No affine live external node authority was supplied. The legacy
    /// unbound recovery entrypoint refuses before observing or mutating the
    /// graph.
    AuthorityRequired,
    /// The persisted current recovery proof binds a different exact external
    /// authority tuple.
    AuthorityMismatch,
    /// The live external authority changed or could not be established at an
    /// irreversible effect boundary.
    AuthorityChanged,
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
    /// A retained terminal WAL did not authenticate the exact brokered prior
    /// Maintenance binding, receipt commitment, source union, or target.
    /// This includes an attempted transfer from a pristine receipt.
    TerminalTransferMismatch,
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

/// Stable terminal classification for authority-bound current recovery.
///
/// Callers must consume this typed classification rather than inferring a
/// terminal proof from `Removed` or `AlreadyAbsent` on the legacy outcome
/// API. `PristineAbsence` is read-only; `AuthenticatedTerminal` is backed by
/// the fsynced current-terminal WAL outside the deleted graph.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphRecoveryTerminalKind {
    /// A live-guarded, two-snapshot read-only observation proved the target
    /// was never created. No SDK authority leaf, proof, or marker was made.
    PristineAbsence,
    /// The exact current graph was retired under an authenticated durable
    /// terminal WAL which remains in the target authority leaf for retry and
    /// broker-acknowledged handoff.
    AuthenticatedTerminal,
}

/// Whether the current terminal receipt proves the requested target absent.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurrentEbpfGraphTerminalAbsenceProof {
    /// The guarded terminal observation conclusively proved target absence.
    Proven,
    /// The result is refused or partial; terminal absence is not claimed.
    NotProven,
}

/// Redaction-safe terminal/current progress receipt for one affine authority
/// attempt.
///
/// This receipt is intentionally the product verification surface for
/// current-first maintenance. It binds the external authority and either a
/// nonpersistent pristine observation or an exact graph commitment recovered
/// from the fsynced terminal WAL. It never renders paths, map IDs, or tenant
/// identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrentEbpfGraphRecoveryReceipt {
    authority: CurrentEbpfGraphRecoveryAuthorityBinding,
    outcome: CurrentEbpfGraphRecoveryOutcome,
    terminal_kind: Option<CurrentEbpfGraphRecoveryTerminalKind>,
    terminal_absence_proof: CurrentEbpfGraphTerminalAbsenceProof,
    exact_graph_commitment: Option<CurrentEbpfGraphRecoveryCommitment>,
    terminal_source: Option<CurrentEbpfGraphRecoveryTerminalSource>,
    terminal_adoption: Option<CurrentEbpfGraphRecoveryTerminalAdoption>,
    terminal_receipt_commitment: Option<CurrentEbpfGraphRecoveryTerminalReceiptCommitment>,
}

impl CurrentEbpfGraphRecoveryReceipt {
    pub(crate) const fn nonterminal(
        authority: CurrentEbpfGraphRecoveryAuthorityBinding,
        outcome: CurrentEbpfGraphRecoveryOutcome,
    ) -> Self {
        Self {
            authority,
            outcome,
            terminal_kind: None,
            terminal_absence_proof: CurrentEbpfGraphTerminalAbsenceProof::NotProven,
            exact_graph_commitment: None,
            terminal_source: None,
            terminal_adoption: None,
            terminal_receipt_commitment: None,
        }
    }

    pub(crate) fn pristine_absence(authority: CurrentEbpfGraphRecoveryAuthorityBinding) -> Self {
        Self {
            authority,
            outcome: CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent,
            terminal_kind: Some(CurrentEbpfGraphRecoveryTerminalKind::PristineAbsence),
            terminal_absence_proof: CurrentEbpfGraphTerminalAbsenceProof::Proven,
            exact_graph_commitment: None,
            terminal_source: None,
            terminal_adoption: None,
            terminal_receipt_commitment: None,
        }
    }

    pub(crate) fn authenticated_terminal(
        authority: CurrentEbpfGraphRecoveryAuthorityBinding,
        outcome: CurrentEbpfGraphRecoveryOutcome,
        exact_graph_commitment: CurrentEbpfGraphRecoveryCommitment,
        terminal_source: CurrentEbpfGraphRecoveryTerminalSource,
        terminal_adoption: Option<CurrentEbpfGraphRecoveryTerminalAdoption>,
    ) -> Self {
        debug_assert!(matches!(
            outcome,
            CurrentEbpfGraphRecoveryOutcome::Removed
                | CurrentEbpfGraphRecoveryOutcome::AlreadyAbsent
        ));
        Self {
            authority,
            outcome,
            terminal_kind: Some(CurrentEbpfGraphRecoveryTerminalKind::AuthenticatedTerminal),
            terminal_absence_proof: CurrentEbpfGraphTerminalAbsenceProof::Proven,
            exact_graph_commitment: Some(exact_graph_commitment),
            terminal_source: Some(terminal_source),
            terminal_adoption,
            terminal_receipt_commitment: Some(
                CurrentEbpfGraphRecoveryTerminalReceiptCommitment::for_terminal(
                    authority,
                    exact_graph_commitment,
                    terminal_source,
                ),
            ),
        }
    }

    /// Return the immutable external authority binding for this attempt.
    #[must_use]
    pub const fn authority(self) -> CurrentEbpfGraphRecoveryAuthorityBinding {
        self.authority
    }

    /// Return the classified current recovery result.
    #[must_use]
    pub const fn outcome(self) -> CurrentEbpfGraphRecoveryOutcome {
        self.outcome
    }

    /// Return the non-inferable terminal kind, if terminal absence is proven.
    #[must_use]
    pub const fn terminal_kind(self) -> Option<CurrentEbpfGraphRecoveryTerminalKind> {
        self.terminal_kind
    }

    /// Return whether this receipt proves terminal target absence.
    #[must_use]
    pub const fn terminal_absence_proof(self) -> CurrentEbpfGraphTerminalAbsenceProof {
        self.terminal_absence_proof
    }

    /// Return the opaque exact graph/map commitment only for an authenticated
    /// WAL-backed terminal. It is never manufactured for pristine absence.
    #[must_use]
    pub const fn exact_graph_commitment(self) -> Option<CurrentEbpfGraphRecoveryCommitment> {
        self.exact_graph_commitment
    }

    /// Return the sealed source domain for an authenticated terminal WAL.
    /// `None` distinguishes nonterminal progress and read-only pristine
    /// absence from a durable source-bound terminal.
    #[must_use]
    pub const fn terminal_source(self) -> Option<CurrentEbpfGraphRecoveryTerminalSource> {
        self.terminal_source
    }

    /// Return the immediate predecessor when this receipt transferred a
    /// previously authenticated terminal WAL to a new authority.
    #[must_use]
    pub const fn terminal_adoption(self) -> Option<CurrentEbpfGraphRecoveryTerminalAdoption> {
        self.terminal_adoption
    }

    /// Return the stable redaction-safe commitment of an authenticated
    /// terminal receipt. `None` distinguishes both nonterminal progress and
    /// read-only pristine absence from a broker-transferable WAL terminal.
    #[must_use]
    pub const fn terminal_receipt_commitment(
        self,
    ) -> Option<CurrentEbpfGraphRecoveryTerminalReceiptCommitment> {
        self.terminal_receipt_commitment
    }

    /// Return the terminal receipt codec identity used to derive
    /// [`Self::terminal_receipt_commitment`].
    #[must_use]
    pub const fn terminal_receipt_codec_identity(self) -> &'static str {
        CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_RECEIPT_CODEC_ID
    }

    /// Return the durable current-terminal WAL codec identity.
    #[must_use]
    pub const fn terminal_wal_codec_identity(self) -> &'static str {
        CURRENT_EBPF_GRAPH_RECOVERY_TERMINAL_WAL_CODEC_ID
    }
}

/// A frozen eBPF datapath generation that this SDK can recover only through a
/// dedicated maintenance operation.
///
/// Historical graphs are never adopted by ordinary startup or cleanup-only
/// recovery. Their authority layout and map/program ABI are a separate
/// compatibility boundary, so callers must name the exact generation they
/// intend to retire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphGeneration {
    /// The 25-map graph shipped before selector stamps and traffic-observation
    /// maps were added.
    PreSessionSelectorStampTrafficObservationV1,
}

impl HistoricalEbpfGraphGeneration {
    /// Stable public identity of this frozen shipped graph generation.
    #[must_use]
    pub const fn identity(self) -> &'static str {
        match self {
            Self::PreSessionSelectorStampTrafficObservationV1 => {
                "pre-session-selector-stamp-traffic-observation-v1"
            }
        }
    }
}

/// Explicit caller attestation that the writer of a historical eBPF graph has
/// stopped.
///
/// This caller attestation is not removal authority by itself. Historical
/// recovery independently takes both kernel-backed authority locks and proves
/// the exact generation, legacy and current authority domains,
/// map/program/hook identity, graph directory identity, and replacement
/// identity before any effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphWriterProof {
    _private: (),
}

impl HistoricalEbpfGraphWriterProof {
    /// Attest that the process which previously owned the historical graph is
    /// stopped.
    #[must_use]
    pub const fn previous_writer_stopped() -> Self {
        Self { _private: () }
    }
}

/// Explicit caller attestation that all forwarding/session state represented
/// by a historical eBPF graph has been drained.
///
/// This caller attestation is not evidence that the kernel graph is empty.
/// Supplying it never bypasses the live map, hook, program, identity, and
/// authority checks; any populated or ambiguous graph remains fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphDrainProof {
    _private: (),
}

/// Fixed public identity of the historical eBPF graph-recovery authority
/// contract.  The value identifies an SDK contract, not a tenant, node, pin
/// path, endpoint, or recovery payload.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID: &str =
    "opc.gtpu.historical-ebpf-graph-recovery-authority.r5";

/// Fixed version of [`HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID`].
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION: u16 = 5;

/// Stable public R5 recovery-contract identity for cross-language parity.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID: &str =
    "opc.gtpu.historical-ebpf-graph-recovery.r5";

/// Stable public R5 durable-record codec identity for cross-language parity.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID: &str =
    "opc.gtpu.historical-recovery-record.r5";

/// Stable public identity of the pure shipped-25 compatibility KAT.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID: &str = "opc.gtpu.historical-ebpf-recovery-kat.r5";

/// Stable identity of the immutable object bundled with shipped generation
/// 25. This is an artifact label, not a claim about a loaded kernel object.
pub const HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID: &str = "opc.gtpu.shipped-25-artifact.v1";

/// Stable identity of the exact 25-map ABI bundled with shipped generation
/// 25. This is an artifact label, not a live-kernel assertion.
pub const HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID: &str = "opc.gtpu.shipped-25-map-abi.v1";

/// Exact fixed control-root entry used by the shipped-25 authority layout.
/// It contains no tenant or node data; callers use it when committing their
/// externally fenced maintenance scope rather than mirroring a private SDK
/// literal.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID: &str = "GTPU_RECONCILER_LOCKS";

/// Fixed identity of the live external evidence which proves that the former
/// attachment/netns is destroyed, or that this target was never created.
///
/// The evidence itself remains opaque.  Its value is bound to every R5
/// authority, persisted before historical effects, and must be re-proved by
/// the live guard at every effect boundary.  It is deliberately not a global
/// host scan: it names only the former target committed by the caller.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_FORMER_LINK_EVIDENCE_ID: &str =
    "opc.gtpu.historical-ebpf-former-link-evidence.v1";

/// Fixed identity of the external provenance attestation required before a
/// detached shipped-25 graph can be retired.  Exact map shape alone is not
/// provenance; this commitment binds the caller's product/SDK artifact proof
/// to the authority target and the sealed shipped generation.
pub const HISTORICAL_EBPF_GRAPH_RECOVERY_ARTIFACT_PROVENANCE_ID: &str =
    "opc.gtpu.historical-ebpf-artifact-provenance.v1";

/// Opaque fixed-width commitment used by historical graph recovery authority.
///
/// The SDK deliberately does not provide a formatter or raw-byte accessor for
/// this value.  A caller keeps any sensitive source material outside this
/// contract and commits to it before constructing authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryCommitment([u8; 32]);

impl HistoricalEbpfGraphRecoveryCommitment {
    /// Construct a nonzero opaque commitment.
    pub fn new(value: [u8; 32]) -> Result<Self, HistoricalEbpfGraphRecoveryAuthorityError> {
        if value == [0; 32] {
            Err(HistoricalEbpfGraphRecoveryAuthorityError::ZeroCommitment)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub(crate) const fn bytes(self) -> [u8; 32] {
        self.0
    }

    /// Internal construction from a SHA-256-derived fixed artifact value.
    /// Callers of the public API must use [`Self::new`].
    pub(crate) const fn from_fixed_digest(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryCommitment(<opaque>)")
    }
}

/// SDK-issued, target-scoped evidence that the exact inspected shipped-25
/// graph was detached.
///
/// This is intentionally not an arbitrary external attestation.  For a
/// present graph, the SDK obtains it only from an
/// [`HistoricalEbpfGraphRecoveryGraphInspection`] after it has locked the
/// graph and proved that no program or tc hook references its exact map-ID
/// inventory. Recovery recomputes the same value while its effect locks are
/// held. The external guard still proves exclusive live authority; it does
/// not make a kernel/netns detachment claim it cannot inspect.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::{
///     HistoricalEbpfGraphRecoveryCommitment,
///     HistoricalEbpfGraphRecoveryFormerLinkEvidence,
/// };
///
/// let arbitrary = HistoricalEbpfGraphRecoveryCommitment::new([1; 32]).unwrap();
/// // Only `ExactDetached(...).former_link_evidence()` can issue this proof.
/// let _ = HistoricalEbpfGraphRecoveryFormerLinkEvidence::new(arbitrary);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryFormerLinkEvidence(HistoricalEbpfGraphRecoveryCommitment);

impl HistoricalEbpfGraphRecoveryFormerLinkEvidence {
    fn for_exact_graph(exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"opc.gtpu.historical-ebpf-former-link-evidence\\0r1");
        digest.update(HISTORICAL_EBPF_GRAPH_RECOVERY_FORMER_LINK_EVIDENCE_ID.as_bytes());
        digest.update(HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID.as_bytes());
        digest.update(HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID.as_bytes());
        digest.update(exact_graph_commitment.bytes());
        Self(HistoricalEbpfGraphRecoveryCommitment::from_fixed_digest(
            digest.finalize().into(),
        ))
    }

    /// Project the only detached former-link proof accepted for an exact
    /// SDK-issued inspection challenge.
    #[must_use]
    pub fn from_inspection(inspection: HistoricalEbpfGraphRecoveryGraphInspection) -> Self {
        Self::for_exact_graph(inspection.exact_graph_commitment())
    }

    /// Rebuild an already checksum-authenticated record projection. This is
    /// crate-private so callers cannot turn an arbitrary commitment into
    /// former-link evidence.
    pub(crate) const fn from_persisted(commitment: HistoricalEbpfGraphRecoveryCommitment) -> Self {
        Self(commitment)
    }

    #[must_use]
    pub const fn commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.0
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryFormerLinkEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryFormerLinkEvidence(<opaque>)")
    }
}

/// Opaque external provenance for a detached shipped-25 graph.
///
/// It commits to product/SDK artifact provenance in the caller's authority
/// system. The SDK persists and compares it with the scope, host/root/leaf,
/// sealed generation, and exact graph commitment; a lookalike graph with the
/// same map ABI but a different provenance is refused before mutation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryArtifactProvenance {
    artifact_commitment: HistoricalEbpfGraphRecoveryCommitment,
    observed_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
}

impl HistoricalEbpfGraphRecoveryArtifactProvenance {
    /// Bind nonzero opaque artifact provenance and the exact graph commitment
    /// observed by the external product authority. The SDK independently
    /// recomputes the latter from the locked shipped-25 graph before any
    /// effect; it is therefore not a caller assertion that a same-shape
    /// lookalike is acceptable.
    #[must_use]
    pub(crate) const fn new(
        artifact_commitment: HistoricalEbpfGraphRecoveryCommitment,
        observed_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
    ) -> Self {
        Self {
            artifact_commitment,
            observed_graph_commitment,
        }
    }

    #[must_use]
    pub const fn artifact_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.artifact_commitment
    }

    /// Return the external authority's exact observed-graph commitment. This
    /// is opaque but comparable; callers do not need raw pins or map IDs.
    #[must_use]
    pub const fn observed_graph_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.observed_graph_commitment
    }

    /// Bind product artifact provenance to an expected SDK inspection
    /// challenge that an external broker retained durably. This constructor
    /// intentionally accepts no local inspection object: recovery must
    /// re-inspect under its effect locks and the guard must freshly prove the
    /// broker still binds this expectation.
    #[must_use]
    pub const fn from_brokered_challenge(
        artifact_commitment: HistoricalEbpfGraphRecoveryCommitment,
        expected: HistoricalEbpfGraphRecoveryExpectedInspectionChallenge,
    ) -> Self {
        Self::new(artifact_commitment, expected.exact_graph_commitment)
    }
}

/// Serializable, redaction-safe expected result of a read-only shipped-25
/// inspection.
///
/// This is not destructive authority. A product obtains it from
/// [`HistoricalEbpfGraphRecoveryGraphInspection`], persists its exact bytes
/// in its broker's maintenance record, then rehydrates it through
/// [`Self::from_serialized`] for a later affine recovery attempt. The live
/// recovery guard must prove that retained broker binding at every effect
/// boundary. It contains no path, map ID, endpoint, key, or payload.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryExpectedInspectionChallenge {
    exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
    generation: HistoricalEbpfGraphGeneration,
    compatibility_contract_digest: HistoricalEbpfGraphRecoveryKatContractDigest,
}

impl HistoricalEbpfGraphRecoveryExpectedInspectionChallenge {
    fn sealed(exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment) -> Self {
        Self {
            exact_graph_commitment,
            generation: HistoricalEbpfGraphGeneration::PreSessionSelectorStampTrafficObservationV1,
            compatibility_contract_digest: crate::historical_ebpf_recovery_compatibility_kat(
                [0; 32],
            )
            .compatibility_contract_digest(),
        }
    }

    /// Rehydrate only a broker-retained expected challenge. The KAT digest is
    /// checked against this SDK build; stale/foreign generation material is
    /// rejected before it can construct recovery authority.
    pub fn from_serialized(
        exact_graph_commitment: [u8; 32],
        compatibility_contract_digest: [u8; 32],
    ) -> Result<Self, HistoricalEbpfGraphRecoveryAuthorityError> {
        let exact_graph_commitment =
            HistoricalEbpfGraphRecoveryCommitment::new(exact_graph_commitment)?;
        let expected = Self::sealed(exact_graph_commitment);
        (expected.compatibility_contract_digest.as_bytes() == compatibility_contract_digest)
            .then_some(expected)
            .ok_or(HistoricalEbpfGraphRecoveryAuthorityError::CompatibilityContractMismatch)
    }

    /// Return the fixed-width opaque bytes that a broker must retain. They
    /// bind the exact SDK-computed graph/map-ID challenge; callers must carry
    /// the accompanying [`Self::compatibility_contract_digest`] too.
    #[must_use]
    pub const fn exact_graph_commitment_bytes(self) -> [u8; 32] {
        self.exact_graph_commitment.bytes()
    }

    /// Return the sealed shipped generation. This variant is fixed rather
    /// than caller selected, so a serialized challenge cannot be relabelled.
    #[must_use]
    pub const fn generation(self) -> HistoricalEbpfGraphGeneration {
        self.generation
    }

    /// Return the sealed R5 KAT/record compatibility digest the broker must
    /// bind with the challenge.
    #[must_use]
    pub const fn compatibility_contract_digest(
        self,
    ) -> HistoricalEbpfGraphRecoveryKatContractDigest {
        self.compatibility_contract_digest
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryExpectedInspectionChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryExpectedInspectionChallenge")
            .field("generation", &self.generation)
            .field("exact_graph_commitment", &"<opaque>")
            .field(
                "compatibility_contract_digest",
                &self.compatibility_contract_digest,
            )
            .finish()
    }
}

/// Read-only, SDK-computed challenge for one exact detached shipped-25 graph.
///
/// A caller obtains this value before constructing
/// [`HistoricalEbpfGraphRecoveryArtifactProvenance`].  The SDK computes it
/// while holding the predecessor graph lock and revalidating the exact graph
/// identity; it deliberately exposes neither paths nor map IDs.  The caller's
/// external product/SDK attestation binds this opaque challenge, and recovery
/// recomputes it under its effect locks before publishing any proof.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryGraphInspection {
    generation: HistoricalEbpfGraphGeneration,
    exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
    artifact_identity: &'static str,
    abi_identity: &'static str,
}

impl HistoricalEbpfGraphRecoveryGraphInspection {
    pub(crate) const fn exact_shipped_25(
        exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
    ) -> Self {
        Self {
            generation: HistoricalEbpfGraphGeneration::PreSessionSelectorStampTrafficObservationV1,
            exact_graph_commitment,
            artifact_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID,
            abi_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID,
        }
    }

    /// Return the sealed shipped generation observed by the SDK.
    #[must_use]
    pub const fn generation(self) -> HistoricalEbpfGraphGeneration {
        self.generation
    }

    /// Return the redaction-safe, SDK-computed exact graph/map-ID commitment.
    #[must_use]
    pub const fn exact_graph_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.exact_graph_commitment
    }

    /// Project the serializable expected challenge a broker must persist
    /// before a separate destructive recovery authority is constructed.
    #[must_use]
    pub fn expected_challenge(self) -> HistoricalEbpfGraphRecoveryExpectedInspectionChallenge {
        HistoricalEbpfGraphRecoveryExpectedInspectionChallenge::sealed(self.exact_graph_commitment)
    }

    /// Return the SDK-issued detached former-link proof for this exact
    /// inspection. This is the only present-graph former-link evidence that
    /// may be supplied to an R5 authority.
    #[must_use]
    pub fn former_link_evidence(self) -> HistoricalEbpfGraphRecoveryFormerLinkEvidence {
        HistoricalEbpfGraphRecoveryFormerLinkEvidence::from_inspection(self)
    }

    #[must_use]
    pub const fn artifact_identity(self) -> &'static str {
        self.artifact_identity
    }

    #[must_use]
    pub const fn abi_identity(self) -> &'static str {
        self.abi_identity
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryGraphInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryGraphInspection")
            .field("generation", &self.generation)
            .field("exact_graph_commitment", &"<opaque>")
            .field("artifact_identity", &self.artifact_identity)
            .field("abi_identity", &self.abi_identity)
            .finish()
    }
}

/// Unforgeable SDK result for a clean, guard-backed historical inspection.
///
/// This token contains no path or graph identity and can only be produced by
/// the SDK after two read-only target snapshots agree while its inspection
/// guard is current. It is required to construct the distinct pristine
/// authority; callers never infer pristine absence from a missing file or an
/// I/O result.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryPristineInspection {
    _private: (),
}

impl HistoricalEbpfGraphRecoveryPristineInspection {
    pub(crate) const fn observed() -> Self {
        Self { _private: () }
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryPristineInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryPristineInspection(<sdk-observed>)")
    }
}

/// Closed, read-only historical graph inspection result.
///
/// `ExactDetached` supplies the SDK-computed challenge required for external
/// artifact provenance. `PristineAbsence` is the only clean-node result and
/// is deliberately distinct from missing/partial/malformed observations,
/// which remain errors or typed recovery refusals.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryInspectionOutcome {
    /// The exact shipped-25 detached graph was locked and revalidated.
    ExactDetached(HistoricalEbpfGraphRecoveryGraphInspection),
    /// The target graph and both target authority leaves were re-proved absent
    /// under the inspection guard without creating any SDK state.
    PristineAbsence(HistoricalEbpfGraphRecoveryPristineInspection),
    /// The inspector observed a bounded, redaction-safe reason it could not
    /// issue either a detached challenge or a pristine token.
    Refused(HistoricalEbpfGraphRecoveryRefusal),
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryArtifactProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryArtifactProvenance(<opaque>)")
    }
}

/// Opaque nonzero operation/attempt identifier bound to one recovery attempt.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryOperationId([u8; 16]);

impl HistoricalEbpfGraphRecoveryOperationId {
    /// Construct a fixed-width, nonzero operation identifier.
    pub fn new(value: [u8; 16]) -> Result<Self, HistoricalEbpfGraphRecoveryAuthorityError> {
        if value == [0; 16] {
            Err(HistoricalEbpfGraphRecoveryAuthorityError::ZeroOperationId)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub(crate) const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryOperationId(<opaque>)")
    }
}

/// Opaque host/root/leaf identity commitments bound to recovery authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryHostCommitments {
    host: HistoricalEbpfGraphRecoveryCommitment,
    root: HistoricalEbpfGraphRecoveryCommitment,
    leaf: HistoricalEbpfGraphRecoveryCommitment,
}

impl HistoricalEbpfGraphRecoveryHostCommitments {
    /// Bind the authority to one committed host, authority root, and leaf.
    #[must_use]
    pub const fn new(
        host: HistoricalEbpfGraphRecoveryCommitment,
        root: HistoricalEbpfGraphRecoveryCommitment,
        leaf: HistoricalEbpfGraphRecoveryCommitment,
    ) -> Self {
        Self { host, root, leaf }
    }

    #[must_use]
    pub const fn host(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.host
    }

    #[must_use]
    pub const fn root(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.root
    }

    #[must_use]
    pub const fn leaf(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.leaf
    }
}

/// Bounded construction failures for external historical recovery authority.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryAuthorityError {
    /// A fixed-width commitment was all zeroes.
    ZeroCommitment,
    /// The fixed-width operation identifier was all zeroes.
    ZeroOperationId,
    /// A broker-supplied inspection challenge did not bind this SDK's sealed
    /// shipped-25 generation and compatibility KAT contract.
    CompatibilityContractMismatch,
}

impl fmt::Display for HistoricalEbpfGraphRecoveryAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCommitment => f.write_str("historical recovery commitment is invalid"),
            Self::ZeroOperationId => f.write_str("historical recovery operation is invalid"),
            Self::CompatibilityContractMismatch => {
                f.write_str("historical recovery compatibility contract is invalid")
            }
        }
    }
}

impl std::error::Error for HistoricalEbpfGraphRecoveryAuthorityError {}

/// Stable result of one mandatory live currentness check.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryAuthorityCurrentness {
    /// The external authority is no longer held by this recovery attempt.
    Changed,
    /// The external authority resolved to a different scope, predecessor
    /// basis, host/root/leaf, epoch, or operation than the bound request.
    Mismatch,
    /// The authority source could not establish currentness.
    Unavailable,
}

/// Affine external authority guard for historical graph recovery.
///
/// The SDK calls this method after taking authority locks, immediately before
/// and after every irreversible recovery effect, and before it returns a
/// successful receipt. A successful check must additionally mean that the
/// caller holds a host-global, target-scoped maintenance exclusion covering
/// every SDK creator of the target graph and both target authority leaves for
/// the full lifetime of this authority. Implementations must consult that live
/// source on every call; returning success at construction time, cached
/// currentness, or a lock that does not exclude a concurrent creator is not a
/// substitute for currentness at an effect boundary. Detached graph proof is
/// intentionally different: the external authority service binds the
/// SDK-issued inspection challenge into the authority, while the SDK alone
/// rechecks exact map-ID program references and hook absence under its locks.
/// A Lease-only guard cannot manufacture or replace that provenance. No
/// implementation may replace these target-scoped facts with a host-global
/// program scan.
pub trait HistoricalEbpfGraphRecoveryCurrentnessGuard: Send + Sync {
    /// Prove that this exact authority remains current at this instant.
    fn verify_current(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), HistoricalEbpfGraphRecoveryAuthorityCurrentness>>
                + Send
                + 'static,
        >,
    >;

    /// Prove that the live broker authority still binds this exact SDK-issued
    /// detached-graph challenge. The value must have been persisted by the
    /// broker between read-only inspection and destructive recovery; a local
    /// KAT result or a freshly fabricated expected challenge is not enough.
    ///
    /// The SDK invokes this with every recovery currentness check, including
    /// all effect-adjacent checks. Inspection-only authorities never invoke
    /// this method because they cannot mutate a graph.
    fn verify_brokered_challenge(
        &self,
        expected: HistoricalEbpfGraphRecoveryExpectedInspectionChallenge,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), HistoricalEbpfGraphRecoveryAuthorityCurrentness>>
                + Send
                + 'static,
        >,
    >;
}

/// Copyable public binding projected from an affine recovery authority.
///
/// It is safe to retain in a receipt, but cannot be used to authorize an
/// effect: the live guard remains private and non-cloneable in
/// [`HistoricalEbpfGraphRecoveryAuthority`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryAuthorityBinding {
    contract_version: u16,
    scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
    predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
    former_link_evidence: HistoricalEbpfGraphRecoveryFormerLinkEvidence,
    artifact_provenance: HistoricalEbpfGraphRecoveryArtifactProvenance,
    fence_epoch: NonZeroU64,
    operation_id: HistoricalEbpfGraphRecoveryOperationId,
    host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
}

/// Redaction-safe provenance for a terminal R5 authority transfer.
///
/// It is populated only when a fully terminal, exact SDK-authored R5 handoff
/// was rebound under a newly live authority for the same committed
/// host/root/leaf. The new receipt's [`HistoricalEbpfGraphRecoveryReceipt::authority`]
/// remains the authority that performed the transfer; this value records only
/// the immediately preceding scope and predecessor-basis commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryTerminalAdoption {
    prior_scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
    prior_predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
    prior_authority: Option<HistoricalEbpfGraphRecoveryAuthorityBinding>,
}

impl HistoricalEbpfGraphRecoveryTerminalAdoption {
    pub(crate) const fn with_full_prior_authority(
        prior_authority: HistoricalEbpfGraphRecoveryAuthorityBinding,
    ) -> Self {
        Self {
            prior_scope_commitment: prior_authority.scope_commitment,
            prior_predecessor_basis_commitment: prior_authority.predecessor_basis_commitment,
            prior_authority: Some(prior_authority),
        }
    }

    /// Return the scope commitment from the immediately preceding terminal
    /// authority. This is opaque and contains no namespace or tenant text.
    #[must_use]
    pub const fn prior_scope_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.prior_scope_commitment
    }

    /// Return the predecessor-basis commitment from the immediately preceding
    /// terminal authority.
    #[must_use]
    pub const fn prior_predecessor_basis_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.prior_predecessor_basis_commitment
    }

    /// Return the complete immediate prior binding preserved by the R5
    /// terminal transfer record.
    #[must_use]
    pub const fn prior_authority(self) -> Option<HistoricalEbpfGraphRecoveryAuthorityBinding> {
        self.prior_authority
    }
}

impl HistoricalEbpfGraphRecoveryAuthorityBinding {
    pub(crate) const fn from_parts(
        scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
        former_link_evidence: HistoricalEbpfGraphRecoveryFormerLinkEvidence,
        artifact_provenance: HistoricalEbpfGraphRecoveryArtifactProvenance,
        fence_epoch: NonZeroU64,
        operation_id: HistoricalEbpfGraphRecoveryOperationId,
        host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
    ) -> Self {
        Self {
            contract_version: HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
            scope_commitment,
            predecessor_basis_commitment,
            former_link_evidence,
            artifact_provenance,
            fence_epoch,
            operation_id,
            host_commitments,
        }
    }

    #[must_use]
    pub const fn contract_version(self) -> u16 {
        self.contract_version
    }

    #[must_use]
    pub const fn scope_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.scope_commitment
    }

    #[must_use]
    pub const fn predecessor_basis_commitment(self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.predecessor_basis_commitment
    }

    /// Return the opaque former-link/never-created evidence commitment.
    #[must_use]
    pub const fn former_link_evidence(self) -> HistoricalEbpfGraphRecoveryFormerLinkEvidence {
        self.former_link_evidence
    }

    /// Return the opaque detached-artifact provenance commitment.
    #[must_use]
    pub const fn artifact_provenance(self) -> HistoricalEbpfGraphRecoveryArtifactProvenance {
        self.artifact_provenance
    }

    #[must_use]
    pub const fn fence_epoch(self) -> NonZeroU64 {
        self.fence_epoch
    }

    #[must_use]
    pub const fn operation_id(self) -> HistoricalEbpfGraphRecoveryOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn host_commitments(self) -> HistoricalEbpfGraphRecoveryHostCommitments {
        self.host_commitments
    }
}

/// Typed external authority for one historical recovery attempt.
///
/// This value is intentionally not `Clone`: the guard is affine and is
/// consumed with the request so a retry must obtain a newly live guard.
pub struct HistoricalEbpfGraphRecoveryAuthority {
    binding: HistoricalEbpfGraphRecoveryAuthorityBinding,
    expected_challenge: Option<HistoricalEbpfGraphRecoveryExpectedInspectionChallenge>,
    guard: Box<dyn HistoricalEbpfGraphRecoveryCurrentnessGuard>,
}

impl HistoricalEbpfGraphRecoveryAuthority {
    /// Construct one R5 authority for an exact SDK-inspected detached graph.
    ///
    /// `expected_challenge` must be the broker-retained serialization of a
    /// prior read-only `ExactDetached` result. It is deliberately not a local
    /// inspection object: the live guard must prove this exact challenge is
    /// still bound by the broker on every currentness check. Recovery then
    /// recomputes it while its effect locks are held before any mutation.
    // Each argument is one independently typed dimension of the affine
    // authority tuple; collapsing them into positional primitives would
    // weaken the public construction boundary.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
        artifact_commitment: HistoricalEbpfGraphRecoveryCommitment,
        expected_challenge: HistoricalEbpfGraphRecoveryExpectedInspectionChallenge,
        fence_epoch: NonZeroU64,
        operation_id: HistoricalEbpfGraphRecoveryOperationId,
        host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
        guard: Box<dyn HistoricalEbpfGraphRecoveryCurrentnessGuard>,
    ) -> Self {
        let former_link_evidence = HistoricalEbpfGraphRecoveryFormerLinkEvidence::for_exact_graph(
            expected_challenge.exact_graph_commitment,
        );
        let artifact_provenance =
            HistoricalEbpfGraphRecoveryArtifactProvenance::from_brokered_challenge(
                artifact_commitment,
                expected_challenge,
            );
        Self {
            binding: HistoricalEbpfGraphRecoveryAuthorityBinding {
                contract_version: HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
                scope_commitment,
                predecessor_basis_commitment,
                former_link_evidence,
                artifact_provenance,
                fence_epoch,
                operation_id,
                host_commitments,
            },
            expected_challenge: Some(expected_challenge),
            guard,
        }
    }

    /// Return the immutable binding retained in a receipt or R5 record.
    #[must_use]
    pub const fn binding(&self) -> HistoricalEbpfGraphRecoveryAuthorityBinding {
        self.binding
    }

    pub(crate) fn verify_current(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), HistoricalEbpfGraphRecoveryAuthorityCurrentness>>
                + Send
                + 'static,
        >,
    > {
        let current = self.guard.verify_current();
        match self.expected_challenge {
            Some(expected_challenge) => {
                let brokered = self.guard.verify_brokered_challenge(expected_challenge);
                Box::pin(async move {
                    current.await?;
                    brokered.await
                })
            }
            None => current,
        }
    }

    /// Construct authority for the only non-persistent clean-node terminal:
    /// a caller must present the SDK-issued pristine inspection token and a
    /// newly live guard. No synthetic graph provenance is created or stored.
    #[must_use]
    pub fn new_pristine_absence(
        scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
        _inspection: HistoricalEbpfGraphRecoveryPristineInspection,
        fence_epoch: NonZeroU64,
        operation_id: HistoricalEbpfGraphRecoveryOperationId,
        host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
        guard: Box<dyn HistoricalEbpfGraphRecoveryCurrentnessGuard>,
    ) -> Self {
        // This private nonzero placeholder is never persisted: pristine
        // recovery returns a read-only receipt with no graph commitment and
        // does not create an R5 record. It prevents a caller from having to
        // invent an observed map-ID commitment for a graph that never existed.
        let pristine = HistoricalEbpfGraphRecoveryCommitment::from_fixed_digest([0xa5; 32]);
        Self {
            binding: HistoricalEbpfGraphRecoveryAuthorityBinding {
                contract_version: HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
                scope_commitment,
                predecessor_basis_commitment,
                // This is a private never-created placeholder. Pristine
                // recovery is read-only and never persists it; an external
                // caller cannot provide arbitrary former-link evidence.
                former_link_evidence:
                    HistoricalEbpfGraphRecoveryFormerLinkEvidence::for_exact_graph(pristine),
                artifact_provenance: HistoricalEbpfGraphRecoveryArtifactProvenance::new(
                    pristine, pristine,
                ),
                fence_epoch,
                operation_id,
                host_commitments,
            },
            expected_challenge: Some(
                HistoricalEbpfGraphRecoveryExpectedInspectionChallenge::sealed(pristine),
            ),
            guard,
        }
    }
}

/// Affine live authority used only for a no-effect historical inspection.
///
/// It deliberately has no artifact/map provenance field: that evidence is
/// created only after an exact SDK graph challenge is returned. Consuming this
/// authority never permits mutation; recovery requires a newly constructed
/// [`HistoricalEbpfGraphRecoveryAuthority`].
pub struct HistoricalEbpfGraphRecoveryInspectionAuthority {
    scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
    predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
    fence_epoch: NonZeroU64,
    operation_id: HistoricalEbpfGraphRecoveryOperationId,
    host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
    guard: Box<dyn HistoricalEbpfGraphRecoveryCurrentnessGuard>,
}

impl HistoricalEbpfGraphRecoveryInspectionAuthority {
    /// Construct one no-effect inspection authority with a live target fence.
    #[must_use]
    pub fn new(
        scope_commitment: HistoricalEbpfGraphRecoveryCommitment,
        predecessor_basis_commitment: HistoricalEbpfGraphRecoveryCommitment,
        fence_epoch: NonZeroU64,
        operation_id: HistoricalEbpfGraphRecoveryOperationId,
        host_commitments: HistoricalEbpfGraphRecoveryHostCommitments,
        guard: Box<dyn HistoricalEbpfGraphRecoveryCurrentnessGuard>,
    ) -> Self {
        Self {
            scope_commitment,
            predecessor_basis_commitment,
            fence_epoch,
            operation_id,
            host_commitments,
            guard,
        }
    }

    fn into_internal(self) -> HistoricalEbpfGraphRecoveryAuthority {
        let inspection = HistoricalEbpfGraphRecoveryCommitment::from_fixed_digest([0x5a; 32]);
        HistoricalEbpfGraphRecoveryAuthority {
            binding: HistoricalEbpfGraphRecoveryAuthorityBinding {
                contract_version: HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_VERSION,
                scope_commitment: self.scope_commitment,
                predecessor_basis_commitment: self.predecessor_basis_commitment,
                former_link_evidence:
                    HistoricalEbpfGraphRecoveryFormerLinkEvidence::for_exact_graph(inspection),
                artifact_provenance: HistoricalEbpfGraphRecoveryArtifactProvenance::new(
                    inspection, inspection,
                ),
                fence_epoch: self.fence_epoch,
                operation_id: self.operation_id,
                host_commitments: self.host_commitments,
            },
            expected_challenge: None,
            guard: self.guard,
        }
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryInspectionAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalEbpfGraphRecoveryInspectionAuthority(<affine-live-guard>)")
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryAuthority")
            .field("binding", &self.binding)
            .field("guard", &"<affine-live-guard>")
            .finish()
    }
}

/// Whether a receipt contains the terminal proof that the exact historical
/// graph and predecessor authority leaf are absent.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphTerminalAbsenceProof {
    /// The exact graph, proof pin, and predecessor authority leaf were
    /// authoritatively absent under the R5 receipt fence.
    Proven,
    /// Recovery is refused or still partial; no terminal absence is claimed.
    NotProven,
}

/// The provenance of a terminal historical-recovery receipt.
///
/// This explicit discriminator prevents a consumer from inferring pristine
/// absence from a loose combination of optional receipt fields. A pristine
/// observation is read-only and has no durable R5 record; an authenticated
/// historical terminal was sealed from an exact shipped graph (and may have
/// been transferred under a new live authority).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryTerminalKind {
    /// No terminal absence was established by this attempt.
    NotTerminal,
    /// A fresh, read-only externally fenced observation found the exact target
    /// graph and target authority leaves genuinely absent.
    PristineAbsence,
    /// An exact shipped historical graph was removed or an authenticated R5
    /// terminal handoff was verified/adopted.
    AuthenticatedHistoricalTerminal,
}

/// Typed receipt returned by every historical recovery attempt.
///
/// It binds the caller's authority contract and the authenticated exact-graph
/// commitment.  It carries no path, endpoint, tenant, object identifier, or
/// payload material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalEbpfGraphRecoveryReceipt {
    authority: Option<HistoricalEbpfGraphRecoveryAuthorityBinding>,
    terminal_adoption: Option<HistoricalEbpfGraphRecoveryTerminalAdoption>,
    generation: HistoricalEbpfGraphGeneration,
    exact_graph_commitment: Option<HistoricalEbpfGraphRecoveryCommitment>,
    recovery_contract_id: &'static str,
    kat_identity: &'static str,
    control_root_identity: &'static str,
    artifact_identity: &'static str,
    abi_identity: &'static str,
    codec_identity: &'static str,
    compatibility_contract_digest: HistoricalEbpfGraphRecoveryKatContractDigest,
    outcome: HistoricalEbpfGraphRecoveryOutcome,
    terminal_absence_proof: HistoricalEbpfGraphTerminalAbsenceProof,
    terminal_kind: HistoricalEbpfGraphRecoveryTerminalKind,
}

impl HistoricalEbpfGraphRecoveryReceipt {
    pub(crate) const fn new(
        authority: HistoricalEbpfGraphRecoveryAuthorityBinding,
        generation: HistoricalEbpfGraphGeneration,
        exact_graph_commitment: Option<HistoricalEbpfGraphRecoveryCommitment>,
        outcome: HistoricalEbpfGraphRecoveryOutcome,
        terminal_absence_proof: HistoricalEbpfGraphTerminalAbsenceProof,
    ) -> Self {
        Self {
            authority: Some(authority),
            terminal_adoption: None,
            generation,
            exact_graph_commitment,
            recovery_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID,
            kat_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID,
            control_root_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID,
            artifact_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID,
            abi_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID,
            codec_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID,
            compatibility_contract_digest:
                HistoricalEbpfGraphRecoveryKatContractDigest::from_fixed_digest([
                    83, 10, 239, 24, 81, 115, 132, 128, 163, 203, 234, 133, 112, 25, 252, 13, 107,
                    220, 223, 108, 126, 28, 200, 87, 244, 102, 57, 148, 215, 208, 231, 24,
                ]),
            outcome,
            terminal_absence_proof,
            terminal_kind: match terminal_absence_proof {
                HistoricalEbpfGraphTerminalAbsenceProof::Proven => {
                    HistoricalEbpfGraphRecoveryTerminalKind::AuthenticatedHistoricalTerminal
                }
                HistoricalEbpfGraphTerminalAbsenceProof::NotProven => {
                    HistoricalEbpfGraphRecoveryTerminalKind::NotTerminal
                }
            },
        }
    }

    pub(crate) const fn with_terminal_adoption(
        authority: HistoricalEbpfGraphRecoveryAuthorityBinding,
        terminal_adoption: HistoricalEbpfGraphRecoveryTerminalAdoption,
        generation: HistoricalEbpfGraphGeneration,
        exact_graph_commitment: HistoricalEbpfGraphRecoveryCommitment,
        outcome: HistoricalEbpfGraphRecoveryOutcome,
    ) -> Self {
        Self {
            authority: Some(authority),
            terminal_adoption: Some(terminal_adoption),
            generation,
            exact_graph_commitment: Some(exact_graph_commitment),
            recovery_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID,
            kat_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID,
            control_root_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID,
            artifact_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID,
            abi_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID,
            codec_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID,
            compatibility_contract_digest:
                HistoricalEbpfGraphRecoveryKatContractDigest::from_fixed_digest([
                    83, 10, 239, 24, 81, 115, 132, 128, 163, 203, 234, 133, 112, 25, 252, 13, 107,
                    220, 223, 108, 126, 28, 200, 87, 244, 102, 57, 148, 215, 208, 231, 24,
                ]),
            outcome,
            terminal_absence_proof: HistoricalEbpfGraphTerminalAbsenceProof::Proven,
            terminal_kind: HistoricalEbpfGraphRecoveryTerminalKind::AuthenticatedHistoricalTerminal,
        }
    }

    pub(crate) const fn authority_required(generation: HistoricalEbpfGraphGeneration) -> Self {
        Self {
            authority: None,
            terminal_adoption: None,
            generation,
            exact_graph_commitment: None,
            recovery_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID,
            kat_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID,
            control_root_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID,
            artifact_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID,
            abi_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID,
            codec_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID,
            compatibility_contract_digest:
                HistoricalEbpfGraphRecoveryKatContractDigest::from_fixed_digest([
                    83, 10, 239, 24, 81, 115, 132, 128, 163, 203, 234, 133, 112, 25, 252, 13, 107,
                    220, 223, 108, 126, 28, 200, 87, 244, 102, 57, 148, 215, 208, 231, 24,
                ]),
            outcome: HistoricalEbpfGraphRecoveryOutcome::Refused(
                HistoricalEbpfGraphRecoveryRefusal::AuthorityRequired,
            ),
            terminal_absence_proof: HistoricalEbpfGraphTerminalAbsenceProof::NotProven,
            terminal_kind: HistoricalEbpfGraphRecoveryTerminalKind::NotTerminal,
        }
    }

    /// Construct the only terminal receipt that deliberately carries no graph
    /// commitment: a read-only, externally fenced observation that the exact
    /// target graph and both authority leaves were pristine absent. It never
    /// manufactures a durable R5 handoff or adoption provenance.
    pub(crate) const fn pristine_absence(
        authority: HistoricalEbpfGraphRecoveryAuthorityBinding,
        generation: HistoricalEbpfGraphGeneration,
    ) -> Self {
        Self {
            authority: Some(authority),
            terminal_adoption: None,
            generation,
            exact_graph_commitment: None,
            recovery_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID,
            kat_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID,
            control_root_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID,
            artifact_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_ARTIFACT_ID,
            abi_identity: HISTORICAL_EBPF_GRAPH_SHIPPED_25_MAP_ABI_ID,
            codec_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID,
            compatibility_contract_digest:
                HistoricalEbpfGraphRecoveryKatContractDigest::from_fixed_digest([
                    83, 10, 239, 24, 81, 115, 132, 128, 163, 203, 234, 133, 112, 25, 252, 13, 107,
                    220, 223, 108, 126, 28, 200, 87, 244, 102, 57, 148, 215, 208, 231, 24,
                ]),
            outcome: HistoricalEbpfGraphRecoveryOutcome::AlreadyAbsent,
            terminal_absence_proof: HistoricalEbpfGraphTerminalAbsenceProof::Proven,
            terminal_kind: HistoricalEbpfGraphRecoveryTerminalKind::PristineAbsence,
        }
    }

    #[must_use]
    pub const fn authority(&self) -> Option<HistoricalEbpfGraphRecoveryAuthorityBinding> {
        self.authority
    }

    /// Return terminal-transfer provenance when this receipt rebound an exact
    /// terminal R5 handoff from a previous external authority.
    #[must_use]
    pub const fn terminal_adoption(&self) -> Option<HistoricalEbpfGraphRecoveryTerminalAdoption> {
        self.terminal_adoption
    }

    #[must_use]
    pub const fn generation(&self) -> HistoricalEbpfGraphGeneration {
        self.generation
    }

    #[must_use]
    pub const fn exact_graph_commitment(&self) -> Option<HistoricalEbpfGraphRecoveryCommitment> {
        self.exact_graph_commitment
    }

    #[must_use]
    pub const fn recovery_contract_id(&self) -> &'static str {
        self.recovery_contract_id
    }

    #[must_use]
    pub const fn kat_identity(&self) -> &'static str {
        self.kat_identity
    }

    /// Return the fixed historical control-root layout identity bound by this
    /// compatibility receipt.
    #[must_use]
    pub const fn control_root_identity(&self) -> &'static str {
        self.control_root_identity
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &'static str {
        self.artifact_identity
    }

    #[must_use]
    pub const fn abi_identity(&self) -> &'static str {
        self.abi_identity
    }

    #[must_use]
    pub const fn codec_identity(&self) -> &'static str {
        self.codec_identity
    }

    /// Return the KAT-bound compatibility digest that was persisted by R5
    /// records and verified before this receipt was issued.
    #[must_use]
    pub const fn compatibility_contract_digest(
        &self,
    ) -> HistoricalEbpfGraphRecoveryKatContractDigest {
        self.compatibility_contract_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> HistoricalEbpfGraphRecoveryOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn terminal_absence_proof(&self) -> HistoricalEbpfGraphTerminalAbsenceProof {
        self.terminal_absence_proof
    }

    /// Return the typed terminal provenance, if this attempt reached a
    /// terminal result. Consumers must use this rather than infer pristine
    /// absence from optional commitment or adoption fields.
    #[must_use]
    pub const fn terminal_kind(&self) -> HistoricalEbpfGraphRecoveryTerminalKind {
        self.terminal_kind
    }
}

impl PartialEq<HistoricalEbpfGraphRecoveryOutcome> for HistoricalEbpfGraphRecoveryReceipt {
    fn eq(&self, other: &HistoricalEbpfGraphRecoveryOutcome) -> bool {
        self.outcome == *other
    }
}

/// One sealed program-section expectation in the unprivileged historical
/// compatibility KAT. Program tags identify frozen artifact expectations;
/// they are not a claim about any loaded kernel program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryKatProgramExpectation {
    section: &'static str,
    tag: u64,
}

/// Fixed-width, non-sensitive compatibility identity for the public shipped-25
/// KAT contract. This is intentionally comparable and serializable by callers
/// that need to pin exact SDK behavior across language boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricalEbpfGraphRecoveryKatContractDigest([u8; 32]);

impl HistoricalEbpfGraphRecoveryKatContractDigest {
    pub(crate) const fn from_fixed_digest(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Return the stable SHA-256 contract digest bytes. These bytes contain no
    /// tenant, host, path, endpoint, key, or runtime object information.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl HistoricalEbpfGraphRecoveryKatProgramExpectation {
    pub(crate) const fn new(section: &'static str, tag: u64) -> Self {
        Self { section, tag }
    }

    #[must_use]
    pub const fn section(self) -> &'static str {
        self.section
    }

    #[must_use]
    pub const fn tag(self) -> u64 {
        self.tag
    }
}

/// Pure compatibility KAT receipt for the shipped 25-map historical artifact.
///
/// It derives only build-time artifact and contract commitments. It neither
/// opens bpffs nor makes a statement about a running kernel, pinned object, or
/// external authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalEbpfGraphRecoveryCompatibilityKatReceipt {
    shipped_generation: HistoricalEbpfGraphGeneration,
    embedded_object_sha256: HistoricalEbpfGraphRecoveryCommitment,
    exact_map_abi_digest: HistoricalEbpfGraphRecoveryCommitment,
    program_expectations: [HistoricalEbpfGraphRecoveryKatProgramExpectation; 2],
    namespace_commitment_vector: [HistoricalEbpfGraphRecoveryCommitment; 25],
    authority_contract_id: &'static str,
    recovery_contract_id: &'static str,
    record_codec_id: &'static str,
    kat_identity: &'static str,
    control_root_identity: &'static str,
    compatibility_contract_digest: HistoricalEbpfGraphRecoveryKatContractDigest,
    challenge_response: HistoricalEbpfGraphRecoveryCommitment,
}

impl HistoricalEbpfGraphRecoveryCompatibilityKatReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        embedded_object_sha256: HistoricalEbpfGraphRecoveryCommitment,
        exact_map_abi_digest: HistoricalEbpfGraphRecoveryCommitment,
        program_expectations: [HistoricalEbpfGraphRecoveryKatProgramExpectation; 2],
        namespace_commitment_vector: [HistoricalEbpfGraphRecoveryCommitment; 25],
        compatibility_contract_digest: HistoricalEbpfGraphRecoveryKatContractDigest,
        challenge_response: HistoricalEbpfGraphRecoveryCommitment,
    ) -> Self {
        Self {
            shipped_generation:
                HistoricalEbpfGraphGeneration::PreSessionSelectorStampTrafficObservationV1,
            embedded_object_sha256,
            exact_map_abi_digest,
            program_expectations,
            namespace_commitment_vector,
            authority_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID,
            recovery_contract_id: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID,
            record_codec_id: HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID,
            kat_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID,
            control_root_identity: HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID,
            compatibility_contract_digest,
            challenge_response,
        }
    }

    #[must_use]
    pub const fn shipped_generation(&self) -> HistoricalEbpfGraphGeneration {
        self.shipped_generation
    }

    #[must_use]
    pub const fn embedded_object_sha256(&self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.embedded_object_sha256
    }

    #[must_use]
    pub const fn exact_map_abi_digest(&self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.exact_map_abi_digest
    }

    #[must_use]
    pub const fn program_expectations(
        &self,
    ) -> [HistoricalEbpfGraphRecoveryKatProgramExpectation; 2] {
        self.program_expectations
    }

    #[must_use]
    pub const fn namespace_commitment_vector(&self) -> [HistoricalEbpfGraphRecoveryCommitment; 25] {
        self.namespace_commitment_vector
    }

    #[must_use]
    pub const fn authority_contract_id(&self) -> &'static str {
        self.authority_contract_id
    }

    #[must_use]
    pub const fn recovery_contract_id(&self) -> &'static str {
        self.recovery_contract_id
    }

    #[must_use]
    pub const fn record_codec_id(&self) -> &'static str {
        self.record_codec_id
    }

    #[must_use]
    pub const fn kat_identity(&self) -> &'static str {
        self.kat_identity
    }

    /// Return the fixed historical control-root layout identity bound by this
    /// compatibility receipt.
    #[must_use]
    pub const fn control_root_identity(&self) -> &'static str {
        self.control_root_identity
    }

    /// Return the stable cross-language compatibility contract digest.
    #[must_use]
    pub const fn compatibility_contract_digest(
        &self,
    ) -> HistoricalEbpfGraphRecoveryKatContractDigest {
        self.compatibility_contract_digest
    }

    #[must_use]
    pub const fn challenge_response(&self) -> HistoricalEbpfGraphRecoveryCommitment {
        self.challenge_response
    }

    /// Verify the domain-separated response for a caller-provided challenge.
    /// This verifies only sealed SDK compatibility material; it makes no
    /// statement about live kernel state or external recovery authority.
    #[must_use]
    pub fn verify_challenge_response(&self, challenge: [u8; 32]) -> bool {
        self.challenge_response
            == Self::challenge_response_for(self.compatibility_contract_digest, challenge)
    }

    pub(crate) fn contract_digest_for(
        embedded_object_sha256: HistoricalEbpfGraphRecoveryCommitment,
        exact_map_abi_digest: HistoricalEbpfGraphRecoveryCommitment,
        program_expectations: [HistoricalEbpfGraphRecoveryKatProgramExpectation; 2],
        namespace_commitment_vector: [HistoricalEbpfGraphRecoveryCommitment; 25],
    ) -> HistoricalEbpfGraphRecoveryKatContractDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"opc.gtpu.historical-ebpf-recovery-kat\0compatibility-contract\0r5");
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_AUTHORITY_CONTRACT_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_CONTRACT_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_RECORD_CODEC_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_KAT_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_CONTROL_ROOT_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_FORMER_LINK_EVIDENCE_ID.as_bytes());
        hasher.update([0]);
        hasher.update(HISTORICAL_EBPF_GRAPH_RECOVERY_ARTIFACT_PROVENANCE_ID.as_bytes());
        hasher.update([0]);
        hasher.update([5]);
        hasher.update(embedded_object_sha256.bytes());
        hasher.update(exact_map_abi_digest.bytes());
        for expectation in program_expectations {
            hasher.update(expectation.section.as_bytes());
            hasher.update([0]);
            hasher.update(expectation.tag.to_be_bytes());
        }
        for namespace in namespace_commitment_vector {
            hasher.update(namespace.bytes());
        }
        HistoricalEbpfGraphRecoveryKatContractDigest(hasher.finalize().into())
    }

    pub(crate) fn challenge_response_for(
        contract_digest: HistoricalEbpfGraphRecoveryKatContractDigest,
        challenge: [u8; 32],
    ) -> HistoricalEbpfGraphRecoveryCommitment {
        let mut hasher = Sha256::new();
        hasher.update(b"opc.gtpu.historical-ebpf-recovery-kat\0challenge-response\0r5");
        hasher.update(contract_digest.0);
        hasher.update(challenge);
        HistoricalEbpfGraphRecoveryCommitment::from_fixed_digest(hasher.finalize().into())
    }
}

impl HistoricalEbpfGraphDrainProof {
    /// Attest that every historical session and its traffic have been drained.
    #[must_use]
    pub const fn sessions_and_traffic_drained() -> Self {
        Self { _private: () }
    }
}

/// Cloneable, non-authorizing description of one historical graph recovery.
///
/// Retry loops retain this intent and obtain a new
/// [`HistoricalEbpfGraphRecoveryAuthority`] for each attempt with
/// [`Self::into_request_with_authority`].  The intent has no guard and cannot
/// itself authorize a kernel or bpffs effect.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoricalEbpfGraphRecoveryIntent {
    generation: HistoricalEbpfGraphGeneration,
    pin_namespace: String,
    replacement_device: Option<GtpDevice>,
    writer_proof: Option<HistoricalEbpfGraphWriterProof>,
    drain_proof: Option<HistoricalEbpfGraphDrainProof>,
}

impl HistoricalEbpfGraphRecoveryIntent {
    /// Build an unprivileged, reusable recovery intent.
    #[must_use]
    pub fn new(
        generation: HistoricalEbpfGraphGeneration,
        pin_namespace: impl Into<String>,
    ) -> Self {
        Self {
            generation,
            pin_namespace: pin_namespace.into(),
            replacement_device: None,
            writer_proof: None,
            drain_proof: None,
        }
    }

    /// Attach the stopped-writer attestation to this reusable intent.
    #[must_use]
    pub const fn with_writer_proof(mut self, writer_proof: HistoricalEbpfGraphWriterProof) -> Self {
        self.writer_proof = Some(writer_proof);
        self
    }

    /// Bind this intent to one exact replacement name and ifindex.
    #[must_use]
    pub fn with_replacement_device(mut self, replacement_device: GtpDevice) -> Self {
        self.replacement_device = Some(replacement_device);
        self
    }

    /// Attach the drained-session/traffic attestation to this reusable intent.
    #[must_use]
    pub const fn with_drain_proof(mut self, drain_proof: HistoricalEbpfGraphDrainProof) -> Self {
        self.drain_proof = Some(drain_proof);
        self
    }

    /// Return the exact frozen generation the inspection/recovery targets.
    #[must_use]
    pub const fn generation(&self) -> HistoricalEbpfGraphGeneration {
        self.generation
    }

    /// Return the redacted stable pin namespace selected by this intent.
    #[must_use]
    pub fn pin_namespace(&self) -> &str {
        &self.pin_namespace
    }

    /// Return the exact replacement identity used for detached observation.
    #[must_use]
    pub const fn replacement_device(&self) -> Option<&GtpDevice> {
        self.replacement_device.as_ref()
    }

    /// Consume this intent into one affine request with a newly live guard.
    #[must_use]
    pub fn into_request_with_authority(
        self,
        authority: HistoricalEbpfGraphRecoveryAuthority,
    ) -> HistoricalEbpfGraphRecoveryRequest {
        HistoricalEbpfGraphRecoveryRequest {
            generation: self.generation,
            pin_namespace: self.pin_namespace,
            replacement_device: self.replacement_device,
            writer_proof: self.writer_proof,
            drain_proof: self.drain_proof,
            authority: Some(authority),
        }
    }

    /// Consume this intent into a no-effect, affine graph-inspection request.
    /// The inspection authority supplies the live target exclusion needed to
    /// distinguish a stable pristine observation from absence observed during
    /// a concurrent creator race. It cannot authorize removal.
    #[must_use]
    pub fn into_inspection_request(
        self,
        authority: HistoricalEbpfGraphRecoveryInspectionAuthority,
    ) -> HistoricalEbpfGraphRecoveryInspectionRequest {
        HistoricalEbpfGraphRecoveryInspectionRequest {
            intent: self,
            authority,
        }
    }

    fn into_unbound_request(self) -> HistoricalEbpfGraphRecoveryRequest {
        HistoricalEbpfGraphRecoveryRequest {
            generation: self.generation,
            pin_namespace: self.pin_namespace,
            replacement_device: self.replacement_device,
            writer_proof: self.writer_proof,
            drain_proof: self.drain_proof,
            authority: None,
        }
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryIntent")
            .field("generation", &self.generation)
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

/// Affine no-effect request for the SDK graph/provenance inspection step.
pub struct HistoricalEbpfGraphRecoveryInspectionRequest {
    intent: HistoricalEbpfGraphRecoveryIntent,
    authority: HistoricalEbpfGraphRecoveryInspectionAuthority,
}

impl HistoricalEbpfGraphRecoveryInspectionRequest {
    /// Return the non-authorizing intent retained by this inspection request.
    #[must_use]
    pub const fn intent(&self) -> &HistoricalEbpfGraphRecoveryIntent {
        &self.intent
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        HistoricalEbpfGraphRecoveryIntent,
        HistoricalEbpfGraphRecoveryAuthority,
    ) {
        (self.intent, self.authority.into_internal())
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryInspectionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryInspectionRequest")
            .field("intent", &self.intent)
            .field("authority", &"<affine-live-inspection-authority>")
            .finish()
    }
}

/// Request to recover one exact historical eBPF graph.
///
/// This is maintenance-only. It is intentionally distinct from
/// [`CurrentEbpfGraphRecoveryRequest`] so a normal restart cannot turn an
/// authenticated old graph into an automatic deletion request.
pub struct HistoricalEbpfGraphRecoveryRequest {
    generation: HistoricalEbpfGraphGeneration,
    pin_namespace: String,
    replacement_device: Option<GtpDevice>,
    writer_proof: Option<HistoricalEbpfGraphWriterProof>,
    drain_proof: Option<HistoricalEbpfGraphDrainProof>,
    authority: Option<HistoricalEbpfGraphRecoveryAuthority>,
}

impl HistoricalEbpfGraphRecoveryRequest {
    /// Build an unprivileged maintenance request.
    ///
    /// Callers must add both independent quiescence attestations before the
    /// backend can remove anything. Keeping incomplete requests representable
    /// lets policy code prepare a request before its drain controller has
    /// completed; it does not make a missing proof an implicit assertion.
    #[must_use]
    pub fn new(
        generation: HistoricalEbpfGraphGeneration,
        pin_namespace: impl Into<String>,
    ) -> Self {
        HistoricalEbpfGraphRecoveryIntent::new(generation, pin_namespace).into_unbound_request()
    }

    /// Attach the explicit stopped-writer attestation required for removal.
    #[must_use]
    pub const fn with_writer_proof(mut self, writer_proof: HistoricalEbpfGraphWriterProof) -> Self {
        self.writer_proof = Some(writer_proof);
        self
    }

    /// Bind recovery to this exact replacement name and ifindex.
    ///
    /// Recovery independently proves that the replacement retains this
    /// identity and that the historical hook state is conclusively detached.
    /// An attached or ambiguous occupant is never maintenance authority.
    #[must_use]
    pub fn with_replacement_device(mut self, replacement_device: GtpDevice) -> Self {
        self.replacement_device = Some(replacement_device);
        self
    }

    /// Authorize removal after all represented traffic and sessions have been
    /// drained by the caller.
    #[must_use]
    pub const fn with_drain_proof(mut self, drain_proof: HistoricalEbpfGraphDrainProof) -> Self {
        self.drain_proof = Some(drain_proof);
        self
    }

    /// Attach the mandatory live external authority for this recovery
    /// attempt.  The authority is affine; an incomplete or retried request
    /// must receive a newly live guard.
    #[must_use]
    pub fn with_authority(mut self, authority: HistoricalEbpfGraphRecoveryAuthority) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Return the requested historical generation.
    #[must_use]
    pub const fn generation(&self) -> HistoricalEbpfGraphGeneration {
        self.generation
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

    /// Return the optional prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> Option<HistoricalEbpfGraphWriterProof> {
        self.writer_proof
    }

    /// Return the optional populated-graph drain attestation.
    #[must_use]
    pub const fn drain_proof(&self) -> Option<HistoricalEbpfGraphDrainProof> {
        self.drain_proof
    }

    /// Return the non-authorizing binding, if a live authority was supplied.
    #[must_use]
    pub fn authority_binding(&self) -> Option<HistoricalEbpfGraphRecoveryAuthorityBinding> {
        self.authority
            .as_ref()
            .map(HistoricalEbpfGraphRecoveryAuthority::binding)
    }

    /// Project a cloneable non-authorizing intent for a future retry.  A
    /// caller must bind that intent to a new authority guard; this method
    /// never duplicates the current guard.
    #[must_use]
    pub fn retry_intent(&self) -> HistoricalEbpfGraphRecoveryIntent {
        HistoricalEbpfGraphRecoveryIntent {
            generation: self.generation,
            pin_namespace: self.pin_namespace.clone(),
            replacement_device: self.replacement_device.clone(),
            writer_proof: self.writer_proof,
            drain_proof: self.drain_proof,
        }
    }

    pub(crate) fn take_authority(&mut self) -> Option<HistoricalEbpfGraphRecoveryAuthority> {
        self.authority.take()
    }
}

impl fmt::Debug for HistoricalEbpfGraphRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalEbpfGraphRecoveryRequest")
            .field("generation", &self.generation)
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
            .field(
                "authority",
                &self.authority.as_ref().map(|_| "<affine-live-authority>"),
            )
            .finish()
    }
}

/// Stable reason historical eBPF graph recovery was refused.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryRefusal {
    /// No live external R5 authority accompanied the request.
    AuthorityRequired,
    /// The current request does not exactly match the authority commitment
    /// persisted by an in-progress R5 recovery.
    AuthorityMismatch,
    /// The mandatory external authority guard changed, mismatched, or became
    /// unavailable at an effect boundary.
    AuthorityChanged,
    /// The caller did not attest that the historical writer is stopped.
    WriterProofRequired,
    /// The caller did not attest that all historical sessions and traffic are
    /// drained.
    DrainProofRequired,
    /// The replacement interface name no longer resolves to the requested
    /// ifindex.
    ReplacementInterfaceIdentityChanged,
    /// This backend instance already manages the requested replacement or pin
    /// namespace.
    ManagedAttachment,
    /// A legacy leaf-hash authority holder remains live.
    ActiveLegacyOwner,
    /// A current root-bound authority holder remains live.
    ActiveCurrentOwner,
    /// One or both historical tc hooks remain attached, so maintenance lacks
    /// conclusive detached-hook authority.
    ActiveHistoricalAttachment,
    /// The graph does not match the named frozen historical generation.
    HistoricalGenerationMismatch,
    /// The independently recomputed locked graph commitment differs from the
    /// typed external shipped-artifact provenance. Exact map shape alone is
    /// never accepted as product provenance.
    ArtifactProvenanceMismatch,
    /// Retained forwarding/session state is populated or cannot be proven
    /// drained.
    PopulatedState,
    /// A pin, program, hook, control directory, or replacement identity is
    /// foreign, replaced, malformed, or ambiguous.
    IdentityMismatch,
    /// Complete stable kernel state, durable proof state, or authority
    /// migration could not be established.
    IndeterminateState,
}

/// Stable progress classification for committed historical graph recovery.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryProgress {
    /// A proof bound to the exact historical graph and authority identities
    /// was committed before map-pin removal.
    ProofCommitted,
    /// At least one recorded historical map pin was removed; retry the exact
    /// request to continue the durable cleanup.
    PinCleanupStarted,
    /// A committed cleanup could not establish its exact final state.
    Indeterminate,
}

/// Classified result of maintenance-only historical eBPF graph recovery.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoricalEbpfGraphRecoveryOutcome {
    /// The exact historical graph and legacy authority child were retired;
    /// an exact current-compatible terminal receipt remains as durable
    /// authority for retries and ordinary startup.
    Removed,
    /// The exact retained terminal receipt proves that the historical graph
    /// and legacy authority are already absent.
    AlreadyAbsent,
    /// Recovery was refused before deletion was committed.
    Refused(HistoricalEbpfGraphRecoveryRefusal),
    /// Cleanup was committed but incomplete; retry the exact request.
    Partial(HistoricalEbpfGraphRecoveryProgress),
}

/// Request to acquire cleanup-only recovery authority over a retained
/// current-schema eBPF graph.
///
/// This is the durable-reconciliation primitive an ePDG-style consumer uses
/// after process loss: it takes ownership of the exact retained pin graph and
/// fences forwarding so stale PDP contexts can be read back and removed
/// without reactivating the stale graph. Unlike
/// [`CurrentEbpfGraphRecoveryRequest`] it never deletes the graph, and unlike
/// ordinary device creation/resolution it never attaches or reattaches the tc
/// forwarding hooks before cleanup is complete.
///
/// The pin namespace is the interface name in `device`; the configured pin
/// root is supplied by the backend. The expected interface identity
/// (`device`) and the configured local endpoint identity (`local_endpoint`)
/// are both validated before any mutation. The prior-writer attestation is
/// intentionally separate from any drain attestation: cleanup-only authority
/// never removes the graph or its retained forwarding entries wholesale, so a
/// drain proof is not required to acquire it.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedGraphCleanupRequest {
    device: GtpDevice,
    local_endpoint: Ipv4Addr,
    writer_proof: CurrentEbpfGraphWriterProof,
}

impl RetainedGraphCleanupRequest {
    /// Build a cleanup-authority request for one exact retained graph.
    ///
    /// `device` is the expected interface identity (name and ifindex) of the
    /// attachment that owns the retained pin namespace. `local_endpoint` is
    /// the configured local S2b-U IPv4 the graph is expected to record.
    /// `writer_proof` attests that the process which previously owned the
    /// graph has stopped.
    #[must_use]
    pub const fn new(
        device: GtpDevice,
        local_endpoint: Ipv4Addr,
        writer_proof: CurrentEbpfGraphWriterProof,
    ) -> Self {
        Self {
            device,
            local_endpoint,
            writer_proof,
        }
    }

    /// Return the expected interface identity of the retained graph.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Return the expected configured local endpoint identity.
    #[must_use]
    pub const fn local_endpoint(&self) -> Ipv4Addr {
        self.local_endpoint
    }

    /// Return the prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> CurrentEbpfGraphWriterProof {
        self.writer_proof
    }
}

impl fmt::Debug for RetainedGraphCleanupRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedGraphCleanupRequest")
            .field("device", &"<redacted-interface-identity>")
            .field("local_endpoint", &"<redacted-local-endpoint>")
            .field("writer_proof", &self.writer_proof)
            .finish()
    }
}

/// Stable reason cleanup-only recovery authority was refused.
///
/// Variants deliberately separate ownership/configuration conflicts,
/// retryable indeterminate evidence, and structural repairs so a consumer can
/// choose between retrying, failing over, or escalating to maintenance.
/// Interface/configuration and retained pin/schema preflight refusals are
/// established before graph mutation. A structural content refusal can follow
/// the forwarding safety fence or exact reduction of a recoverable interrupted
/// commit, and `IndeterminateState` can follow a partially completed fence or
/// uncertain map operation. Callers must not infer an untouched graph from the
/// reason alone.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedGraphCleanupRefusal {
    /// The interface name no longer resolves to the expected ifindex. The
    /// caller's expected interface identity is stale; this is a conflict, not
    /// a retryable state.
    InterfaceIdentityChanged,
    /// The retained graph records a different local endpoint than the one the
    /// caller configured. Ownership/configuration conflict; the graph belongs
    /// to a different endpoint and is never mutated.
    LocalEndpointMismatch,
    /// This backend instance already manages the attachment through the
    /// ordinary device lifecycle or an existing cleanup authority.
    ManagedAttachment,
    /// Another process holds the host-global lease for this pin namespace, or
    /// a prior acquisition is still completing. Retryable once the owner
    /// releases the namespace.
    ActiveOwner,
    /// The graph is not the exact current schema supported by this SDK build,
    /// carries unsupported grouped authority, or contains stable malformed
    /// PDP state. Structural repair (drained reprovisioning or migration) is
    /// required. Malformed PDP state can be diagnosed after safety fencing or
    /// exact interrupted-commit reduction.
    NotCurrentSchema,
    /// Read-only qualification proved the exact frozen historical graph
    /// generation. Ordinary cleanup-only acquisition never adopts or removes
    /// that generation; a dedicated maintenance recovery request is required.
    HistoricalGeneration,
    /// Read-only qualification proved a legacy leaf-hash authority layout.
    /// Ordinary cleanup-only acquisition never migrates or retires that
    /// authority; a dedicated maintenance recovery request is required.
    LegacyAuthorityLayout,
    /// A pin, loaded program, or tc hook is foreign, replaced, or no longer
    /// has the exact SDK-owned identity. Structural repair is required.
    IdentityMismatch,
    /// Complete, stable kernel state or mutation authority could not be
    /// established. Retryable; the caller should re-run the exact request.
    IndeterminateState,
}

impl RetainedGraphCleanupRefusal {
    /// Return whether the refusal is safe to retry with the exact request.
    ///
    /// Retryable refusals represent transient ownership or observation races,
    /// not conflicts or structural damage.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::ActiveOwner | Self::IndeterminateState)
    }
}

/// Classified result of acquiring cleanup-only recovery authority over a
/// retained current-schema eBPF graph.
///
/// `Acquired` is delivered through the supervised completion handle returned
/// by the backend; the handle is affine and its blocking worker converges the
/// graph state even if the observing future is dropped.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedGraphCleanupClassification {
    /// Cleanup authority was acquired. Both forwarding hooks are
    /// authoritatively absent; exact readback and removal are now permitted
    /// while forwarding stays disabled.
    Acquired,
    /// No retained graph exists for the requested namespace, both reserved
    /// hook slots are empty, and no SDK forwarding hook exists at another tc
    /// placement. Nothing was manufactured to prove absence.
    AlreadyAbsent,
    /// Cleanup authority was not granted. Preflight conflicts leave the graph
    /// untouched, but a refusal discovered during fencing or interrupted-
    /// commit recovery can follow safe hook removal or exact map reduction.
    /// No refusal reattaches forwarding. Callers must re-observe kernel state
    /// before deciding whether to retry or enter structural maintenance.
    Refused(RetainedGraphCleanupRefusal),
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
    /// UDP address bound before passing an ordinary GTP-U socket to the
    /// kernel. Linux recoverable creation instead uses the kernel-owned socket
    /// profile and requires wildcard IPv4 (`0.0.0.0`).
    pub bind_address: IpAddr,
    /// UDP port bound before passing an ordinary GTP-U socket to the kernel.
    /// Linux recoverable creation requires the standard GTP-U port 2152 and
    /// also reserves the kernel driver's standard GTPv0 port 3386.
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
    /// An opaque SDK selector admission names another device, group, or graph.
    SelectorAdmissionMismatch,
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
            Self::SelectorAdmissionMismatch => "grouped GTP-U selector admission differs",
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
/// exact source removal must already be proven. The one retired graph must
/// cover every selector newly introduced by the desired reconciliation.
/// Combining selectors from multiple retired groups is deliberately
/// fail-closed by the current single-proof API.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionSelectorReuseProof {
    retired_group: GtpuSessionGroup,
    evidence: GtpuSessionSelectorReuseEvidence,
}

impl GtpuSessionSelectorReuseProof {
    /// Mint trusted traffic-drain evidence inside the SDK/backend boundary.
    ///
    /// A public constructor would let a caller assert a drain it did not
    /// observe. Production issuance is therefore intentionally restricted to
    /// the selector authority and its backend adapters.
    #[must_use]
    #[allow(dead_code)] // Issued by backend-specific trusted evidence paths.
    pub(crate) const fn after_traffic_drain(retired_group: GtpuSessionGroup) -> Self {
        Self {
            retired_group,
            evidence: GtpuSessionSelectorReuseEvidence::TrafficDrained,
        }
    }

    /// Mint trusted RCU-grace evidence inside the SDK/backend boundary.
    #[must_use]
    #[allow(dead_code)] // Issued by backend-specific trusted evidence paths.
    pub(crate) const fn after_rcu_grace_period(retired_group: GtpuSessionGroup) -> Self {
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

/// Read-only classification for an explicit retired-selector reissue.
///
/// Fresh admission is deliberately absent from this public type: only the
/// selector namespace authority can issue it.  `Reused` remains available to
/// backend implementors so they can retain the exact retired-source and
/// drain/grace validation at their dataplane boundary.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuSessionSelectorProvenance {
    /// Reuse after exact removal and explicit drain/grace evidence.
    Reused(GtpuSessionSelectorReuseProof),
}

/// Complete request for grouped-session convergence.
///
/// An opaque SDK-issued selector admission is mandatory because the bounded
/// dataplane journal does not retain permanent selector tombstones.  The
/// admission is affine: constructing this request consumes it, binding this
/// operation to one stable device namespace, exact group, selector set, and
/// SDK-minted generation.
pub struct GtpuSessionGroupReconcileRequest {
    desired: GtpuSessionGroup,
    selector_admission: crate::GtpuSessionSelectorAdmission,
    selector_provenance: Option<GtpuSessionSelectorProvenance>,
}

impl GtpuSessionGroupReconcileRequest {
    /// Construct a request with an SDK-issued selector namespace admission.
    ///
    /// # Errors
    ///
    /// An admission bound to another device, group, or complete selector set
    /// is rejected before a backend can inspect or mutate dataplane state.
    pub(crate) fn new(
        desired: GtpuSessionGroup,
        selector_admission: crate::GtpuSessionSelectorAdmission,
    ) -> Result<Self, GtpuSessionModelError> {
        if !selector_admission.validates(&desired)
            || !selector_admission.authorizes_install_effect()
            || selector_admission.is_retired_reissue()
        {
            return Err(GtpuSessionModelError::SelectorAdmissionMismatch);
        }
        Ok(Self {
            desired,
            selector_admission,
            selector_provenance: None,
        })
    }

    /// Construct an explicitly retired-selector reissue request.
    ///
    /// The opaque admission must have been issued by the authority's distinct
    /// retired-reissue path.  Backends must continue to prove that the exact
    /// old source is absent and that the stated drain/grace condition holds.
    pub(crate) fn new_reused(
        desired: GtpuSessionGroup,
        selector_admission: crate::GtpuSessionSelectorAdmission,
        reuse: GtpuSessionSelectorReuseProof,
    ) -> Result<Self, GtpuSessionModelError> {
        if !selector_admission.validates(&desired)
            || !selector_admission.authorizes_install_effect()
            || !selector_admission.is_retired_reissue()
            || reuse.retired_group.device_id != desired.device_id
            || reuse.retired_group.id == desired.id
        {
            return Err(GtpuSessionModelError::SelectorAdmissionMismatch);
        }
        Ok(Self {
            desired,
            selector_admission,
            selector_provenance: Some(GtpuSessionSelectorProvenance::Reused(reuse)),
        })
    }

    /// Desired canonical semantic graph.
    #[must_use]
    pub const fn desired(&self) -> &GtpuSessionGroup {
        &self.desired
    }

    /// Return the opaque immutable backend binding carried by this SDK-issued
    /// effect request. This exposes no selector material or admission secret.
    #[must_use]
    pub const fn selector_backend_binding(&self) -> crate::GtpuSessionSelectorBackendBinding {
        self.selector_admission.binding()
    }

    pub(crate) const fn selector_admission(&self) -> &crate::GtpuSessionSelectorAdmission {
        &self.selector_admission
    }

    /// Explicit retired-selector evidence, if this is a reissue request.
    #[must_use]
    pub const fn selector_provenance(&self) -> Option<&GtpuSessionSelectorProvenance> {
        self.selector_provenance.as_ref()
    }

    /// Consume the request without discarding mandatory selector admission.
    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        GtpuSessionGroup,
        crate::GtpuSessionSelectorAdmission,
        Option<GtpuSessionSelectorProvenance>,
    ) {
        (
            self.desired,
            self.selector_admission,
            self.selector_provenance,
        )
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
            .field("selector_admission", &self.selector_admission)
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

/// Structural reason an exact PDP-context removal was refused before any
/// mutation.
///
/// These outcomes are fail-closed and deliberately distinct from the
/// retryable [`PdpContextIndeterminateReason`]s: retrying the identical
/// request cannot succeed until the underlying structural condition is
/// repaired (for example, by reprovisioning the durable descriptor against
/// the current device identity). Values are never carried.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdpContextRepairReason {
    /// The expected GTP device identity no longer matches the durable
    /// descriptor: its name, ifindex, or kernel-bound incarnation changed (the
    /// device was replaced, renamed, or removed). The resident state was left
    /// untouched and the descriptor must be reprovisioned.
    DeviceIdentityChanged,
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
    /// A structural precondition failed closed before any mutation; retrying
    /// the identical request cannot succeed without repair.
    RepairRequired(PdpContextRepairReason),
}

/// Opaque, non-reusable identity of one Linux GTP device incarnation.
///
/// Callers must generate this identity with a cryptographically secure random
/// number generator before creating the device, durably persist it with every
/// recovery descriptor for that device, and never reuse it for another device
/// incarnation. The all-zero value is reserved so omitted or uninitialized
/// identity cannot silently authorize recovery.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdpDeviceIncarnation([u8; 16]);

impl PdpDeviceIncarnation {
    /// Decode a persisted device-incarnation identity.
    ///
    /// Returns `None` for the reserved all-zero value.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Return the exact fixed-width representation for durable persistence.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for PdpDeviceIncarnation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PdpDeviceIncarnation(<redacted>)")
    }
}

/// Explicit caller attestation that the process which previously owned a
/// durable Linux kernel-GTP device and its PDP state has stopped.
///
/// Supplying this value authorizes restart recovery over an exact PDP
/// context and identity acquisition of a retained device. It never bypasses
/// device-identity, dual-selector, or cross-process authority validation; it
/// only records the caller's assertion that the prior writer is gone and its
/// durable descriptors may be reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdpRestartRecoveryProof {
    _private: (),
}

impl PdpRestartRecoveryProof {
    /// Attest that the prior writer of the durable PDP descriptor is stopped.
    #[must_use]
    pub const fn previous_writer_stopped() -> Self {
        Self { _private: () }
    }
}

/// Request to acquire exact restart-recovery authority over one durable Linux
/// kernel-GTP PDP context.
///
/// This is the durable-reconciliation primitive an ePDG-style consumer uses
/// after process loss: the kernel-GTP PDP context (and the GTP device that
/// owns it) survive the writer, and the consumer must prove either exact
/// removal or exact absence of the descriptor before protocol egress. The
/// request binds the complete expected identity — the device identity
/// (`device`), its non-reusable incarnation (`incarnation`), and both selector
/// axes and full context (`expected`) — so a resident context is only ever
/// removed when it matches exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct PdpRestartRecoveryRequest {
    device: GtpDevice,
    incarnation: PdpDeviceIncarnation,
    expected: GtpPdpContext,
    writer_proof: PdpRestartRecoveryProof,
}

impl PdpRestartRecoveryRequest {
    /// Build a restart-recovery request for one exact durable PDP context.
    ///
    /// `device` is the expected GTP device identity (name and ifindex) that
    /// the durable descriptor records. `incarnation` is the cryptographically
    /// unpredictable, durably persisted identity minted before that device was
    /// created and never reused. `expected` is the complete expected PDP
    /// context (both selector axes and every identity field). `writer_proof`
    /// attests that the prior writer has stopped.
    #[must_use]
    pub const fn new(
        device: GtpDevice,
        incarnation: PdpDeviceIncarnation,
        expected: GtpPdpContext,
        writer_proof: PdpRestartRecoveryProof,
    ) -> Self {
        Self {
            device,
            incarnation,
            expected,
            writer_proof,
        }
    }

    /// Return the expected GTP device identity of the durable context.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Return the non-reusable identity of the expected device incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> PdpDeviceIncarnation {
        self.incarnation
    }

    /// Return the complete expected PDP context identity.
    #[must_use]
    pub const fn expected(&self) -> &GtpPdpContext {
        &self.expected
    }

    /// Return the prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> PdpRestartRecoveryProof {
        self.writer_proof
    }
}

impl fmt::Debug for PdpRestartRecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpRestartRecoveryRequest")
            .field("device", &"<redacted-device-identity>")
            .field("incarnation", &"<redacted-device-incarnation>")
            .field("expected", &"<redacted-pdp-context>")
            .field("writer_proof", &self.writer_proof)
            .finish()
    }
}

/// Explicit caller attestation that the caller is the current cooperating
/// live writer of a durable Linux kernel-GTP device and its PDP state.
///
/// Supplying this value authorizes live-writer exact removal over an exact PDP
/// context while the writer remains live and continues to own the mutation
/// namespace. Unlike [`PdpRestartRecoveryProof`], it never asserts that a
/// prior writer stopped, so it is the only honest authority for same-process
/// session replacement. It never bypasses recovery-root binding, device
/// identity, dual-selector, incarnation, or writer-lease validation. It records
/// the caller's assertion and binds it to the backend's exact recovery root and
/// network-namespace identity for revalidation before mutation. The
/// restart-recovery authority remains strict and distinct; acquiring this proof
/// does not weaken it.
///
/// A proof is issued only by a backend's attestation boundary. It is affine:
/// callers must move the proof into exactly one removal request, and cannot
/// duplicate or manufacture it through the public API.
///
/// ```compile_fail
/// # use opc_gtpu_dataplane::PdpLiveWriterProof;
/// fn cannot_clone(proof: PdpLiveWriterProof) -> PdpLiveWriterProof {
///     proof.clone()
/// }
/// ```
#[must_use = "carry the live-writer proof into exactly one removal request"]
pub struct PdpLiveWriterProof {
    recovery_root: PathBuf,
    namespace: PdpLiveWriterNamespaceIdentity,
}

impl PdpLiveWriterProof {
    pub(crate) fn bound_to(
        recovery_root: PathBuf,
        namespace: PdpLiveWriterNamespaceIdentity,
    ) -> Self {
        Self {
            recovery_root,
            namespace,
        }
    }

    pub(crate) fn matches(
        &self,
        recovery_root: &Path,
        namespace: PdpLiveWriterNamespaceIdentity,
    ) -> bool {
        self.recovery_root == recovery_root && self.namespace == namespace
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        recovery_root: PathBuf,
        namespace: PdpLiveWriterNamespaceIdentity,
    ) -> Self {
        Self::bound_to(recovery_root, namespace)
    }
}

/// Exact identity of the network namespace in which a live-writer proof was
/// acquired. Linux derives this from `/proc/thread-self/ns/net` metadata.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PdpLiveWriterNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl PdpLiveWriterNamespaceIdentity {
    pub(crate) const fn from_dev_ino(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }
}

impl fmt::Debug for PdpLiveWriterProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpLiveWriterProof")
            .field("recovery_root", &"<redacted-recovery-root>")
            .field("namespace", &"<redacted-network-namespace>")
            .finish()
    }
}

/// Request to remove one exact Linux kernel-GTP PDP context under the
/// authority of the current cooperating live writer.
///
/// This is the same-process replacement primitive an ePDG-style consumer uses
/// while it remains the live writer: a subscriber-session replacement must
/// remove the prior session's kernel-GTP PDP context with exact authority
/// before the replacement dataplane can be proven converged, and the
/// cooperating writer is still live, so the prior-writer stop attestation
/// required by [`PdpRestartRecoveryRequest`] would be false. The request
/// binds the complete expected identity — the device identity (`device`), its
/// non-reusable incarnation (`incarnation`), and both selector axes and full
/// context (`expected`) — so a resident context is only ever removed when it
/// matches exactly. The durable PDP recovery root must already be bound, and
/// the removal serializes under the same topology and per-device writer
/// gates as every other cooperating mutation.
///
/// ```compile_fail
/// # use opc_gtpu_dataplane::PdpLiveWriterRemovalRequest;
/// fn cannot_clone(request: PdpLiveWriterRemovalRequest) -> PdpLiveWriterRemovalRequest {
///     request.clone()
/// }
/// ```
pub struct PdpLiveWriterRemovalRequest {
    device: GtpDevice,
    incarnation: PdpDeviceIncarnation,
    expected: GtpPdpContext,
    writer_proof: PdpLiveWriterProof,
}

impl PdpLiveWriterRemovalRequest {
    /// Build a live-writer exact-removal request for one exact PDP context.
    ///
    /// `device` is the expected GTP device identity (name and ifindex) of the
    /// live writer's device. `incarnation` is the cryptographically
    /// unpredictable, durably persisted identity minted before that device
    /// was created and never reused. `expected` is the complete expected PDP
    /// context (both selector axes and every identity field). `writer_proof`
    /// attests that the caller is the current cooperating writer.
    #[must_use]
    pub const fn new(
        device: GtpDevice,
        incarnation: PdpDeviceIncarnation,
        expected: GtpPdpContext,
        writer_proof: PdpLiveWriterProof,
    ) -> Self {
        Self {
            device,
            incarnation,
            expected,
            writer_proof,
        }
    }

    /// Return the expected GTP device identity of the live writer's device.
    #[must_use]
    pub const fn device(&self) -> &GtpDevice {
        &self.device
    }

    /// Return the non-reusable identity of the expected device incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> PdpDeviceIncarnation {
        self.incarnation
    }

    /// Return the complete expected PDP context identity.
    #[must_use]
    pub const fn expected(&self) -> &GtpPdpContext {
        &self.expected
    }

    /// Return the live-writer ownership attestation.
    #[must_use = "inspect the affine live-writer proof reference"]
    pub const fn writer_proof(&self) -> &PdpLiveWriterProof {
        &self.writer_proof
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        GtpDevice,
        PdpDeviceIncarnation,
        GtpPdpContext,
        PdpLiveWriterProof,
    ) {
        (
            self.device,
            self.incarnation,
            self.expected,
            self.writer_proof,
        )
    }
}

impl fmt::Debug for PdpLiveWriterRemovalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdpLiveWriterRemovalRequest")
            .field("device", &"<redacted-device-identity>")
            .field("incarnation", &"<redacted-device-incarnation>")
            .field("expected", &"<redacted-pdp-context>")
            .field("writer_proof", &self.writer_proof)
            .finish()
    }
}

/// Request to acquire the identity of one retained Linux kernel-GTP device
/// after its previous writer stopped.
///
/// This is the identity-bearing, mutation-free companion of
/// [`PdpRestartRecoveryRequest`]: an ePDG-style consumer that restarts after
/// process loss may hold a durable record of a shared recoverable device that
/// was created but never admitted a PDP effect. Before choosing between
/// serving reuse and fresh creation, the consumer must learn whether the
/// exact device identity survived without reading, installing, or deleting
/// any PDP context and without mutating the device. The request binds the
/// durable device name (`name`), its non-reusable incarnation
/// (`incarnation`), the optional exact ifindex already committed by an active
/// record (`expected_ifindex`), and the prior-writer stop attestation
/// (`writer_proof`). A prepared record intentionally has no expected ifindex:
/// successful acquisition returns the exact live [`GtpDevice`] so the caller
/// can durably complete that record.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedDeviceIdentityRequest {
    name: String,
    expected_ifindex: Option<u32>,
    incarnation: PdpDeviceIncarnation,
    writer_proof: PdpRestartRecoveryProof,
}

impl RetainedDeviceIdentityRequest {
    /// Build an identity-acquisition request for one retained device.
    ///
    /// `name` and `incarnation` must have been durably committed before device
    /// creation. `expected_ifindex` is `None` for a prepared record whose
    /// create result was never durably published, and `Some` only when the
    /// exact returned ifindex was committed. `writer_proof` attests that the
    /// prior writer has stopped.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        expected_ifindex: Option<u32>,
        incarnation: PdpDeviceIncarnation,
        writer_proof: PdpRestartRecoveryProof,
    ) -> Self {
        Self {
            name: name.into(),
            expected_ifindex,
            incarnation,
            writer_proof,
        }
    }

    /// Return the durable expected device name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the exact durably recorded ifindex, when publication completed.
    #[must_use]
    pub const fn expected_ifindex(&self) -> Option<u32> {
        self.expected_ifindex
    }

    /// Return the non-reusable identity of the expected device incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> PdpDeviceIncarnation {
        self.incarnation
    }

    /// Return the prior-writer stop attestation.
    #[must_use]
    pub const fn writer_proof(&self) -> PdpRestartRecoveryProof {
        self.writer_proof
    }
}

impl fmt::Debug for RetainedDeviceIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedDeviceIdentityRequest")
            .field("name", &"<redacted-device-name>")
            .field(
                "expected_ifindex",
                &self.expected_ifindex.map(|_| "<redacted-device-ifindex>"),
            )
            .field("incarnation", &"<redacted-device-incarnation>")
            .field("writer_proof", &self.writer_proof)
            .finish()
    }
}

/// Structural reason a retained-device identity conflicts with the expected
/// identity.
///
/// These outcomes are fail-closed and deliberately distinct from the
/// retryable [`RetainedDeviceIndeterminateReason`]s and from the structural
/// [`RetainedDeviceRepairReason`]s: a live, readable link occupies the
/// expected identity slot but is provably not the expected incarnation.
/// Values are never carried.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedDeviceConflictReason {
    /// The expected name is occupied by a link with a different ifindex, or
    /// the expected name and ifindex are occupied by a link whose
    /// kernel-bound `IFLA_IFALIAS` identity differs from the expected
    /// incarnation (including foreign or malformed alias content). The live
    /// state was left untouched; the durable record must be reconciled
    /// against the replacement identity.
    ReplacementIdentity,
}

/// Stable reason a retained-device identity acquisition could not prove a
/// final state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedDeviceIndeterminateReason {
    /// Topology or per-device writer authority is held by a concurrent
    /// cooperating writer; retry the identical request.
    AuthorityUnavailable,
}

/// Structural reason a retained-device identity acquisition failed closed
/// even though a link matching the expected name and ifindex exists.
///
/// These outcomes are fail-closed and deliberately distinct from the
/// retryable [`RetainedDeviceIndeterminateReason`]s: retrying the identical
/// request cannot succeed until the underlying structural condition is
/// repaired (for example, by removing the unpublished link and creating a
/// fresh recoverable device). Values are never carried.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedDeviceRepairReason {
    /// The live link matching the expected name and ifindex carries no
    /// incarnation stamp in `IFLA_IFALIAS`: it was never published as a
    /// recoverable device, so ownership cannot be proven.
    Unstamped,
}

/// Classified result of an identity-bearing retained-device acquisition.
///
/// The acquisition is mutation-free: no device or PDP context is created,
/// read, installed, renamed, or removed on any path. Every variant is
/// value-free so diagnostics cannot carry device identity, incarnation,
/// endpoint, TEID, packet, or descriptor values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetainedDeviceIdentityOutcome {
    /// The expected name, ifindex, and kernel-bound incarnation were all
    /// proven live under writer authority. The retained device may be reused
    /// as-is; no mutation occurred.
    Retained,
    /// The expected name was proven authoritatively absent under writer
    /// authority. The durable record did not survive as a live device; one
    /// fresh `create_recoverable_device` call with a newly minted incarnation
    /// is the supported next step. No mutation occurred.
    Absent,
    /// Live state conflicts with the expected identity and was left
    /// untouched.
    Conflict(RetainedDeviceConflictReason),
    /// The acquisition could not be completed; a retry of the identical
    /// request may succeed.
    Indeterminate(RetainedDeviceIndeterminateReason),
    /// A structural precondition failed closed before any classification
    /// could authorize reuse; retrying the identical request cannot succeed
    /// without repair.
    RepairRequired(RetainedDeviceRepairReason),
}

/// Completed retained-device identity acquisition.
///
/// [`Self::outcome`] is always a typed, value-free classification. When that
/// classification is [`RetainedDeviceIdentityOutcome::Retained`],
/// [`Self::retained_device`] and [`Self::into_retained_device`] return the
/// exact live [`GtpDevice`] proven under writer authority. Every other
/// classification carries no device. Diagnostics redact the returned device
/// identity.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedDeviceIdentityAcquisition {
    outcome: RetainedDeviceIdentityOutcome,
    retained_device: Option<GtpDevice>,
}

impl RetainedDeviceIdentityAcquisition {
    pub(crate) fn retained(device: GtpDevice) -> Self {
        Self {
            outcome: RetainedDeviceIdentityOutcome::Retained,
            retained_device: Some(device),
        }
    }

    pub(crate) const fn absent() -> Self {
        Self {
            outcome: RetainedDeviceIdentityOutcome::Absent,
            retained_device: None,
        }
    }

    pub(crate) const fn conflict(reason: RetainedDeviceConflictReason) -> Self {
        Self {
            outcome: RetainedDeviceIdentityOutcome::Conflict(reason),
            retained_device: None,
        }
    }

    pub(crate) const fn indeterminate(reason: RetainedDeviceIndeterminateReason) -> Self {
        Self {
            outcome: RetainedDeviceIdentityOutcome::Indeterminate(reason),
            retained_device: None,
        }
    }

    pub(crate) const fn repair_required(reason: RetainedDeviceRepairReason) -> Self {
        Self {
            outcome: RetainedDeviceIdentityOutcome::RepairRequired(reason),
            retained_device: None,
        }
    }

    /// Return the stable, value-free identity classification.
    #[must_use]
    pub const fn outcome(&self) -> RetainedDeviceIdentityOutcome {
        self.outcome
    }

    /// Borrow the exact retained device proven on a `Retained` outcome.
    #[must_use]
    pub const fn retained_device(&self) -> Option<&GtpDevice> {
        self.retained_device.as_ref()
    }

    /// Consume the acquisition and return the exact proven retained device.
    #[must_use]
    pub fn into_retained_device(self) -> Option<GtpDevice> {
        self.retained_device
    }
}

impl fmt::Debug for RetainedDeviceIdentityAcquisition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedDeviceIdentityAcquisition")
            .field("outcome", &self.outcome)
            .field(
                "retained_device",
                &self
                    .retained_device
                    .as_ref()
                    .map(|_| "<redacted-device-identity>"),
            )
            .finish()
    }
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
    /// Demonstrated fragmented outer IPv4 downlink contract for this exact
    /// grouped attachment.
    ///
    /// This is intentionally separate from the legacy backend-global
    /// [`GtpuProbe::downlink_outer_fragment_handling`] field. A grouped
    /// attachment must not inherit the legacy IPv4 reassembly-consumer claim:
    /// that consumer authorizes only the frozen single-context map graph.
    pub downlink_outer_ipv4_fragment_handling: GtpuDownlinkFragmentContract,
    /// Demonstrated fragmented outer IPv6 downlink contract.
    ///
    /// This is independent of [`Self::outer_ipv6`]: a backend may support
    /// complete, unfragmented IPv6 GTP-U transport while lacking an IPv6
    /// reassembly consumer and must then report `Unsupported`.
    pub downlink_outer_ipv6_fragment_handling: GtpuDownlinkFragmentContract,
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
            downlink_outer_ipv4_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
            downlink_outer_ipv6_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
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
    /// The backend's demonstrated contract for fragmented outer IPv4
    /// downlink packets: a bounded kernel-reassembly handoff whose reassembled
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
    fn pdp_device_incarnation_rejects_zero() {
        assert_eq!(PdpDeviceIncarnation::from_bytes([0; 16]), None);
    }

    #[test]
    fn pdp_device_incarnation_round_trips_persisted_bytes() {
        let bytes = [0xa5; 16];
        let incarnation = PdpDeviceIncarnation::from_bytes(bytes).unwrap();

        assert_eq!(incarnation.to_bytes(), bytes);
    }

    #[test]
    fn pdp_device_incarnation_debug_is_redacted() {
        let incarnation = PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap();

        assert_eq!(
            format!("{incarnation:?}"),
            "PdpDeviceIncarnation(<redacted>)"
        );
    }

    #[test]
    fn pdp_restart_recovery_request_binds_incarnation_and_redacts_identity() {
        let device = GtpDevice {
            name: "tenant-sensitive-gtp".to_string(),
            ifindex: 41,
        };
        let incarnation = PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap();
        let expected = reconciliation_context();
        let writer_proof = PdpRestartRecoveryProof::previous_writer_stopped();
        let request = PdpRestartRecoveryRequest::new(
            device.clone(),
            incarnation,
            expected.clone(),
            writer_proof,
        );

        assert_eq!(request.device(), &device);
        assert_eq!(request.incarnation(), incarnation);
        assert_eq!(request.expected(), &expected);
        assert_eq!(request.writer_proof(), writer_proof);

        let debug = format!("{request:?}");
        for sensitive in [
            "tenant-sensitive-gtp",
            "/var/lib/opc/recovery",
            "10.23.0.2",
            "192.0.2.10",
            "12345678",
            "87654321",
            "[165, 165",
        ] {
            assert!(!debug.contains(sensitive));
        }
        assert!(debug.contains("<redacted-device-incarnation>"));
    }

    #[test]
    fn pdp_live_writer_removal_request_binds_incarnation_and_redacts_identity() {
        let device = GtpDevice {
            name: "tenant-sensitive-gtp".to_string(),
            ifindex: 41,
        };
        let incarnation = PdpDeviceIncarnation::from_bytes([0x5a; 16]).unwrap();
        let expected = reconciliation_context();
        let writer_proof = PdpLiveWriterProof::for_test(
            PathBuf::from("/var/lib/opc/recovery"),
            PdpLiveWriterNamespaceIdentity::from_dev_ino(7, 11),
        );
        let request = PdpLiveWriterRemovalRequest::new(
            device.clone(),
            incarnation,
            expected.clone(),
            writer_proof,
        );

        assert_eq!(request.device(), &device);
        assert_eq!(request.incarnation(), incarnation);
        assert_eq!(request.expected(), &expected);
        assert!(format!("{:?}", request.writer_proof()).contains("PdpLiveWriterProof"));

        let debug = format!("{request:?}");
        for sensitive in [
            "tenant-sensitive-gtp",
            "10.23.0.2",
            "192.0.2.10",
            "12345678",
            "87654321",
            "[90, 90",
        ] {
            assert!(
                !debug.contains(sensitive),
                "request debug leaked {sensitive}: {debug}"
            );
        }
        assert!(debug.contains("<redacted-device-identity>"));
        assert!(debug.contains("<redacted-device-incarnation>"));
        assert!(debug.contains("<redacted-pdp-context>"));
    }

    #[test]
    fn retained_device_identity_request_binds_identity_and_redacts_values() {
        let device = GtpDevice {
            name: "tenant-sensitive-gtp".to_string(),
            ifindex: 41,
        };
        let incarnation = PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap();
        let writer_proof = PdpRestartRecoveryProof::previous_writer_stopped();
        let request = RetainedDeviceIdentityRequest::new(
            device.name.clone(),
            Some(device.ifindex),
            incarnation,
            writer_proof,
        );

        assert_eq!(request.name(), device.name);
        assert_eq!(request.expected_ifindex(), Some(device.ifindex));
        assert_eq!(request.incarnation(), incarnation);
        assert_eq!(request.writer_proof(), writer_proof);

        let prepared = RetainedDeviceIdentityRequest::new(
            device.name.clone(),
            None,
            incarnation,
            writer_proof,
        );
        assert_eq!(prepared.name(), device.name);
        assert_eq!(prepared.expected_ifindex(), None);

        let debug = format!("{request:?}");
        for sensitive in ["tenant-sensitive-gtp", "41", "[165, 165"] {
            assert!(
                !debug.contains(sensitive),
                "request debug leaked {sensitive}: {debug}"
            );
        }
        assert!(debug.contains("<redacted-device-name>"));
        assert!(debug.contains("<redacted-device-ifindex>"));
        assert!(debug.contains("<redacted-device-incarnation>"));
    }

    #[test]
    fn retained_device_identity_acquisition_returns_device_only_for_retained() {
        let device = GtpDevice {
            name: "tenant-sensitive-gtp".to_string(),
            ifindex: 41,
        };
        let acquisition = RetainedDeviceIdentityAcquisition::retained(device.clone());

        assert_eq!(
            acquisition.outcome(),
            RetainedDeviceIdentityOutcome::Retained
        );
        assert_eq!(acquisition.retained_device(), Some(&device));
        assert_eq!(
            acquisition.clone().into_retained_device(),
            Some(device.clone())
        );
        let debug = format!("{acquisition:?}");
        for sensitive in ["tenant-sensitive-gtp", "41"] {
            assert!(
                !debug.contains(sensitive),
                "acquisition debug leaked {sensitive}: {debug}"
            );
        }
        assert!(debug.contains("<redacted-device-identity>"));

        let absent = RetainedDeviceIdentityAcquisition::absent();
        assert_eq!(absent.outcome(), RetainedDeviceIdentityOutcome::Absent);
        assert_eq!(absent.retained_device(), None);
        assert_eq!(absent.into_retained_device(), None);
    }

    #[test]
    fn retained_device_identity_outcomes_are_value_free_and_structurally_distinct() {
        let retained = RetainedDeviceIdentityOutcome::Retained;
        let absent = RetainedDeviceIdentityOutcome::Absent;
        let conflict = RetainedDeviceIdentityOutcome::Conflict(
            RetainedDeviceConflictReason::ReplacementIdentity,
        );
        let indeterminate = RetainedDeviceIdentityOutcome::Indeterminate(
            RetainedDeviceIndeterminateReason::AuthorityUnavailable,
        );
        let repair =
            RetainedDeviceIdentityOutcome::RepairRequired(RetainedDeviceRepairReason::Unstamped);

        // Every classification is pairwise distinct: no structural, conflict,
        // or absent state can collapse into transient authority unavailability.
        let outcomes = [retained, absent, conflict, indeterminate, repair];
        for (i, lhs) in outcomes.iter().enumerate() {
            for rhs in &outcomes[i + 1..] {
                assert_ne!(lhs, rhs);
            }
        }

        // Reasons are copyable, hashable, and redaction-safe by
        // construction: their debug carries no device identity or
        // incarnation values.
        let copied = RetainedDeviceConflictReason::ReplacementIdentity;
        assert_eq!(conflict, RetainedDeviceIdentityOutcome::Conflict(copied));
        for rendered in [
            format!("{retained:?}"),
            format!("{absent:?}"),
            format!("{conflict:?}"),
            format!("{indeterminate:?}"),
            format!("{repair:?}"),
        ] {
            for sensitive in ["tenant-sensitive-gtp", "41", "a5a5"] {
                assert!(
                    !rendered.contains(sensitive),
                    "outcome debug leaked {sensitive}: {rendered}"
                );
            }
        }
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
    fn current_terminal_transfer_requires_an_authenticated_wal_receipt() {
        use std::num::NonZeroU64;

        let commitment = |byte| CurrentEbpfGraphRecoveryCommitment::new([byte; 32]).unwrap();
        let binding = CurrentEbpfGraphRecoveryAuthorityBinding::new(
            commitment(0x51),
            commitment(0x52),
            NonZeroU64::new(7).unwrap(),
            CurrentEbpfGraphRecoveryOperationId::new([0x53; 16]).unwrap(),
            CurrentEbpfGraphRecoveryHostCommitments::new(
                commitment(0x54),
                commitment(0x55),
                commitment(0x56),
            ),
        );
        let pristine = CurrentEbpfGraphRecoveryReceipt::pristine_absence(binding);
        assert_eq!(
            CurrentEbpfGraphRecoveryTerminalTransfer::from_authenticated_receipt(pristine),
            None,
            "read-only pristine absence has no durable WAL to transfer"
        );
        let partial = CurrentEbpfGraphRecoveryReceipt::nonterminal(
            binding,
            CurrentEbpfGraphRecoveryOutcome::Partial(
                CurrentEbpfGraphRecoveryProgress::Indeterminate,
            ),
        );
        assert_eq!(
            CurrentEbpfGraphRecoveryTerminalTransfer::from_authenticated_receipt(partial),
            None,
            "partial outcomes cannot become a broker predecessor"
        );
        let terminal = CurrentEbpfGraphRecoveryReceipt::authenticated_terminal(
            binding,
            CurrentEbpfGraphRecoveryOutcome::Removed,
            commitment(0x57),
            CurrentEbpfGraphRecoveryTerminalSource::CurrentGraph,
            None,
        );
        let transfer =
            CurrentEbpfGraphRecoveryTerminalTransfer::from_authenticated_receipt(terminal)
                .expect("only a WAL-backed exact graph terminal is transferable");
        assert_eq!(transfer.prior_authority(), binding);
        assert_eq!(
            transfer.prior_terminal_receipt_commitment(),
            terminal
                .terminal_receipt_commitment()
                .expect("authenticated terminal has a canonical commitment")
        );
    }

    #[test]
    fn historical_graph_recovery_request_requires_explicit_proofs_and_redacts_identity() {
        let request = HistoricalEbpfGraphRecoveryRequest::new(
            HistoricalEbpfGraphGeneration::PreSessionSelectorStampTrafficObservationV1,
            "tenant-sensitive-historical-pin",
        )
        .with_replacement_device(GtpDevice {
            name: "tenant-sensitive-historical-interface".to_string(),
            ifindex: 47,
        });
        assert_eq!(
            request.generation(),
            HistoricalEbpfGraphGeneration::PreSessionSelectorStampTrafficObservationV1
        );
        assert!(request.writer_proof().is_none());
        assert!(request.drain_proof().is_none());
        let complete = request
            .with_writer_proof(HistoricalEbpfGraphWriterProof::previous_writer_stopped())
            .with_drain_proof(HistoricalEbpfGraphDrainProof::sessions_and_traffic_drained());
        assert!(complete.writer_proof().is_some());
        assert!(complete.drain_proof().is_some());
        let debug = format!("{complete:?}");
        for sensitive in [
            "tenant-sensitive-historical-pin",
            "tenant-sensitive-historical-interface",
            "47",
        ] {
            assert!(
                !debug.contains(sensitive),
                "historical recovery request debug leaked {sensitive}: {debug}"
            );
        }
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
        let namespace = crate::selector_namespace::TestGtpuSessionSelectorNamespaceAuthority::new(
            crate::InMemoryGtpuSessionSelectorNamespaceStore::default(),
            [0x53; 32],
            32,
        );
        let admission = namespace.claim(&desired, None).unwrap();
        let reconcile = GtpuSessionGroupReconcileRequest::new(desired.clone(), admission).unwrap();
        assert_eq!(reconcile.desired(), &desired);
        assert!(matches!(
            namespace.claim(&desired, None),
            Err(crate::GtpuSessionSelectorNamespaceError::GroupClaimed)
        ));
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
        assert_eq!(
            capabilities.downlink_outer_ipv4_fragment_handling,
            GtpuDownlinkFragmentContract::Unsupported
        );
        assert_eq!(
            capabilities.downlink_outer_ipv6_fragment_handling,
            GtpuDownlinkFragmentContract::Unsupported
        );
    }
}
