//! Deterministic mock GTP-U dataplane backend for tests and offline development.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::GtpuDataplaneBackend;
use crate::error::GtpuError;
use crate::model::{
    classify_dual_selector_state, CreateGtpDeviceRequest, DualSelectorState, GtpAddressFamily,
    GtpDevice, GtpPdpContext, GtpuCapability, GtpuProbe, PdpContextIndeterminateReason,
    PdpContextInstallOutcome, PdpContextReadback, PdpContextReconciliationCapabilities,
    PdpContextRemovalOutcome, PdpContextSelector, RemovePdpContextRequest,
};
use crate::n3::{
    N3iwfInstalledSession, N3iwfSessionConflict, N3iwfSessionFlowUpdate, N3iwfSessionGeneration,
    N3iwfSessionInstallOutcome, N3iwfSessionIntent, N3iwfSessionLifecycleCapabilities,
    N3iwfSessionOccupancy, N3iwfSessionReadback, N3iwfSessionReconcileOutcome,
    N3iwfSessionRemovalOutcome, N3iwfSessionSelector, N3iwfSessionSelectorKey,
};
use crate::tft_classifier::{
    TftUplinkClassifier, TftUplinkClassifierReadback, TftUplinkClassifierReconcileOutcome,
    TftUplinkClassifierRemovalOutcome,
};

/// Redaction-safe reconciliation fault injected into the deterministic mock.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockPdpContextFault {
    /// Simulate a partial or corrupt multi-map/context graph.
    CorruptState,
    /// Simulate a publication/removal transaction in a non-active phase.
    TransitionalState,
    /// Simulate state changing during a bounded double-read.
    ChangingReadback,
}

/// One recorded call against the mock backend.
#[derive(Clone, PartialEq, Eq)]
pub enum MockOperation {
    /// Device creation.
    CreateDevice {
        /// Request snapshot.
        request: CreateGtpDeviceRequest,
    },
    /// Device resolve by interface name.
    ResolveDevice {
        /// Interface name.
        name: String,
    },
    /// Device removal.
    RemoveDevice {
        /// Device snapshot.
        device: GtpDevice,
    },
    /// PDP-context installation.
    InstallPdpContext {
        /// PDP context snapshot.
        request: GtpPdpContext,
    },
    /// PDP-context removal.
    RemovePdpContext {
        /// Remove request snapshot.
        request: RemovePdpContextRequest,
    },
    /// Capability probe.
    Probe,
}

impl fmt::Debug for MockOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDevice { request } => f
                .debug_struct("CreateDevice")
                .field("request", request)
                .finish(),
            Self::ResolveDevice { name } => {
                f.debug_struct("ResolveDevice").field("name", name).finish()
            }
            Self::RemoveDevice { device } => f
                .debug_struct("RemoveDevice")
                .field("device", device)
                .finish(),
            Self::InstallPdpContext { request } => f
                .debug_struct("InstallPdpContext")
                .field("request", request)
                .finish(),
            Self::RemovePdpContext { request } => f
                .debug_struct("RemovePdpContext")
                .field("request", request)
                .finish(),
            Self::Probe => f.write_str("Probe"),
        }
    }
}

/// One PDP-context reconciliation call recorded by the mock backend.
///
/// Reconciliation calls use a separate log so the additive backend contract
/// does not add variants to the established, externally exhaustive
/// [`MockOperation`] enum.
#[derive(Clone, PartialEq, Eq)]
pub enum MockPdpContextReconciliationOperation {
    /// Typed PDP-context readback.
    Read {
        /// Redacted selector snapshot.
        selector: PdpContextSelector,
    },
    /// Strict classified PDP-context installation.
    InstallClassified {
        /// Redacted desired-context snapshot.
        request: GtpPdpContext,
    },
    /// Exact PDP-context removal.
    RemoveExact {
        /// Redacted expected-context snapshot.
        expected: GtpPdpContext,
    },
}

impl fmt::Debug for MockPdpContextReconciliationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { selector } => f.debug_struct("Read").field("selector", selector).finish(),
            Self::InstallClassified { request } => f
                .debug_struct("InstallClassified")
                .field("request", request)
                .finish(),
            Self::RemoveExact { expected } => f
                .debug_struct("RemoveExact")
                .field("expected", expected)
                .finish(),
        }
    }
}

/// One RFC 021 N3IWF session call recorded by the mock backend.
///
/// These calls use their own log for the same reason as
/// [`MockPdpContextReconciliationOperation`]. Every snapshot redacts its
/// values.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum MockN3iwfSessionOperation {
    /// Session readback.
    Read {
        /// Redacted selector snapshot.
        selector: N3iwfSessionSelector,
    },
    /// Classified session install.
    InstallClassified {
        /// Redacted intent snapshot.
        intent: N3iwfSessionIntent,
    },
    /// Flow-table swap.
    ReconcileFlows {
        /// Redacted update snapshot.
        update: N3iwfSessionFlowUpdate,
    },
    /// Exact session removal.
    RemoveExact {
        /// Redacted expected-session snapshot.
        expected: N3iwfInstalledSession,
    },
}

impl fmt::Debug for MockN3iwfSessionOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { selector } => f.debug_struct("Read").field("selector", selector).finish(),
            Self::InstallClassified { intent } => f
                .debug_struct("InstallClassified")
                .field("intent", intent)
                .finish(),
            Self::ReconcileFlows { update } => f
                .debug_struct("ReconcileFlows")
                .field("update", update)
                .finish(),
            Self::RemoveExact { expected } => f
                .debug_struct("RemoveExact")
                .field("expected", expected)
                .finish(),
        }
    }
}

/// Deterministic in-memory GTP-U dataplane backend.
#[derive(Clone)]
pub struct MockGtpuDataplaneBackend {
    state: Arc<Mutex<MockState>>,
}

impl fmt::Debug for MockGtpuDataplaneBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockGtpuDataplaneBackend")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct MockState {
    operations: Vec<MockOperation>,
    pdp_context_reconciliation_operations: Vec<MockPdpContextReconciliationOperation>,
    probe_result: GtpuProbe,
    failure: Option<GtpuError>,
    next_ifindex: u32,
    devices: BTreeMap<String, GtpDevice>,
    pdp_by_local: BTreeMap<MockLocalSelector, GtpPdpContext>,
    pdp_by_uplink: BTreeMap<MockUplinkSelector, GtpPdpContext>,
    pdp_fault: Option<MockPdpContextFault>,
    tft_uplink_classification_capability: GtpuCapability,
    tft_classifiers: BTreeMap<(u32, std::net::IpAddr), TftUplinkClassifier>,
    n3iwf_sessions: BTreeMap<MockN3iwfKey, N3iwfInstalledSession>,
    n3iwf_marks: BTreeMap<(u32, u32), MockN3iwfKey>,
    n3iwf_session_operations: Vec<MockN3iwfSessionOperation>,
}

/// Composite record key: N3 link, outer family and local TEID (RFC 021
/// section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MockN3iwfKey {
    link_ifindex: u32,
    outer_family: u8,
    local_teid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MockLocalSelector {
    link_ifindex: u32,
    version: u8,
    family: u8,
    local_teid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MockUplinkSelector {
    link_ifindex: u32,
    version: u8,
    ms_address: std::net::IpAddr,
    bearer_mark: Option<u32>,
}

enum MockSelectorKey {
    Local(MockLocalSelector),
    Uplink(MockUplinkSelector),
}

impl MockGtpuDataplaneBackend {
    /// Create a mock backend that reports itself as a dry-run/mock probe.
    #[must_use]
    pub fn new() -> Self {
        Self::with_probe(GtpuProbe::mock())
    }

    /// Create a mock backend with a specific probe result.
    #[must_use]
    pub fn with_probe(probe_result: GtpuProbe) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                operations: Vec::new(),
                pdp_context_reconciliation_operations: Vec::new(),
                probe_result,
                failure: None,
                next_ifindex: 1,
                devices: BTreeMap::new(),
                pdp_by_local: BTreeMap::new(),
                pdp_by_uplink: BTreeMap::new(),
                pdp_fault: None,
                tft_uplink_classification_capability: GtpuCapability::Available,
                tft_classifiers: BTreeMap::new(),
                n3iwf_sessions: BTreeMap::new(),
                n3iwf_marks: BTreeMap::new(),
                n3iwf_session_operations: Vec::new(),
            })),
        }
    }

    /// Inject an error that every subsequent operation will return.
    pub fn set_failure(&self, error: GtpuError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = Some(error);
    }

    /// Clear any injected failure.
    pub fn clear_failure(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = None;
    }

    /// Set the result returned by `probe`.
    pub fn set_probe_result(&self, probe_result: GtpuProbe) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.probe_result = probe_result;
    }

    /// Set the classifier capability reported and enforced by this mock.
    pub fn set_tft_uplink_classification_capability(&self, capability: GtpuCapability) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.tft_uplink_classification_capability = capability;
    }

    /// Return all recorded operations, in order.
    #[must_use]
    pub fn operations(&self) -> Vec<MockOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }

    /// Return all recorded PDP-context reconciliation calls, in order.
    #[must_use]
    pub fn pdp_context_reconciliation_operations(
        &self,
    ) -> Vec<MockPdpContextReconciliationOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pdp_context_reconciliation_operations.clone()
    }

    /// Clear the recorded operation log.
    pub fn clear_operations(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clear();
        state.pdp_context_reconciliation_operations.clear();
        state.n3iwf_session_operations.clear();
    }

    /// Return all recorded RFC 021 N3IWF session calls, in order.
    #[must_use]
    pub fn n3iwf_session_operations(&self) -> Vec<MockN3iwfSessionOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.n3iwf_session_operations.clone()
    }

    /// Inject or clear a redaction-safe PDP reconciliation fault.
    pub fn set_pdp_context_fault(&self, fault: Option<MockPdpContextFault>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pdp_fault = fault;
    }

    fn check_failure(state: &MockState) -> Result<(), GtpuError> {
        if let Some(ref error) = state.failure {
            return Err(error.clone());
        }
        Ok(())
    }

    fn validate_context(context: &GtpPdpContext) -> Result<(), GtpuError> {
        if context.link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        if context.ms_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.ms_address",
                "MS address must not be unspecified",
            ));
        }
        if context.peer_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.peer_address",
                "peer address must not be unspecified",
            ));
        }
        Ok(())
    }

    fn version_key(version: crate::GtpVersion) -> u8 {
        match version {
            crate::GtpVersion::V1 => 1,
        }
    }

    fn family_key(family: GtpAddressFamily) -> u8 {
        match family {
            GtpAddressFamily::Ipv4 => 4,
            GtpAddressFamily::Ipv6 => 6,
        }
    }

    fn local_key(context: &GtpPdpContext) -> MockLocalSelector {
        MockLocalSelector {
            link_ifindex: context.link_ifindex,
            version: Self::version_key(context.gtp_version),
            family: Self::family_key(GtpAddressFamily::from_ip(context.ms_address)),
            local_teid: context.local_teid.get(),
        }
    }

    fn uplink_key(context: &GtpPdpContext) -> MockUplinkSelector {
        MockUplinkSelector {
            link_ifindex: context.link_ifindex,
            version: Self::version_key(context.gtp_version),
            ms_address: context.ms_address,
            bearer_mark: context.bearer_mark.map(crate::GtpBearerMark::get),
        }
    }

    fn selector_key(selector: &PdpContextSelector) -> Result<MockSelectorKey, GtpuError> {
        match selector {
            PdpContextSelector::LocalTeid(selector) => {
                if selector.link_ifindex() == 0 {
                    return Err(GtpuError::invalid_config(
                        "pdp.selector.link_ifindex",
                        "ifindex must be nonzero",
                    ));
                }
                Ok(MockSelectorKey::Local(MockLocalSelector {
                    link_ifindex: selector.link_ifindex(),
                    version: Self::version_key(selector.gtp_version()),
                    family: Self::family_key(selector.address_family()),
                    local_teid: selector.local_teid().get(),
                }))
            }
            PdpContextSelector::Uplink(selector) => {
                if selector.link_ifindex() == 0 {
                    return Err(GtpuError::invalid_config(
                        "pdp.selector.link_ifindex",
                        "ifindex must be nonzero",
                    ));
                }
                Ok(MockSelectorKey::Uplink(MockUplinkSelector {
                    link_ifindex: selector.link_ifindex(),
                    version: Self::version_key(selector.gtp_version()),
                    ms_address: selector.identity().ms_address(),
                    bearer_mark: selector
                        .identity()
                        .bearer_mark()
                        .map(crate::GtpBearerMark::get),
                }))
            }
        }
    }

    fn read_locked(
        state: &MockState,
        selector: &PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        if state.pdp_fault.is_some() {
            return Err(GtpuError::StateIndeterminate {
                operation: "mock_pdp_context_readback",
            });
        }
        match Self::selector_key(selector)? {
            MockSelectorKey::Local(key) => Ok(state
                .pdp_by_local
                .get(&key)
                .cloned()
                .map_or(PdpContextReadback::Absent, PdpContextReadback::Present)),
            MockSelectorKey::Uplink(key) => Ok(state
                .pdp_by_uplink
                .get(&key)
                .cloned()
                .map_or(PdpContextReadback::Absent, PdpContextReadback::Present)),
        }
    }

    fn desired_readback_locked(
        state: &MockState,
        desired: &GtpPdpContext,
    ) -> (PdpContextReadback, PdpContextReadback) {
        (
            state
                .pdp_by_local
                .get(&Self::local_key(desired))
                .cloned()
                .map_or(PdpContextReadback::Absent, PdpContextReadback::Present),
            state
                .pdp_by_uplink
                .get(&Self::uplink_key(desired))
                .cloned()
                .map_or(PdpContextReadback::Absent, PdpContextReadback::Present),
        )
    }

    fn insert_context_locked(state: &mut MockState, context: GtpPdpContext) {
        state
            .pdp_by_local
            .insert(Self::local_key(&context), context.clone());
        state
            .pdp_by_uplink
            .insert(Self::uplink_key(&context), context);
    }

    fn remove_context_locked(state: &mut MockState, context: &GtpPdpContext) {
        state.pdp_by_local.remove(&Self::local_key(context));
        state.pdp_by_uplink.remove(&Self::uplink_key(context));
    }

    fn tft_classifier_readback_locked(
        state: &MockState,
        link_ifindex: u32,
        paa: std::net::IpAddr,
    ) -> TftUplinkClassifierReadback {
        // A read selects by any address the PAA set owns: the IPv4 PAA or any
        // address inside the IPv6 /64.
        state
            .tft_classifiers
            .values()
            .find(|classifier| {
                classifier.link_ifindex() == link_ifindex && classifier.paa_set().contains(paa)
            })
            .cloned()
            .map_or(
                TftUplinkClassifierReadback::Absent,
                TftUplinkClassifierReadback::Present,
            )
    }

    /// Keys of the stored classifiers on `classifier`'s attachment whose PAA
    /// set shares any address with it. Distinct residents never overlap, so
    /// one key is the PDN's own classifier and two or more mean `classifier`
    /// straddles distinct PDNs.
    fn tft_classifier_overlapping_keys_locked(
        state: &MockState,
        classifier: &TftUplinkClassifier,
    ) -> Vec<(u32, std::net::IpAddr)> {
        state
            .tft_classifiers
            .iter()
            .filter(|(_, existing)| {
                existing.link_ifindex() == classifier.link_ifindex()
                    && existing.paa_set().overlaps(&classifier.paa_set())
            })
            .map(|(key, _)| *key)
            .collect()
    }

    fn validate_tft_uplink_classifier_capability(
        capability: GtpuCapability,
    ) -> Result<(), GtpuError> {
        if capability == GtpuCapability::Available {
            Ok(())
        } else {
            Err(GtpuError::UnsupportedFeature {
                feature: "tft_uplink_classification",
            })
        }
    }

    fn n3iwf_key(link_ifindex: u32, local_downlink: crate::n3::LocalN3DownlinkTnl) -> MockN3iwfKey {
        MockN3iwfKey {
            link_ifindex,
            outer_family: if local_downlink.local_address().is_ipv4() {
                4
            } else {
                6
            },
            local_teid: local_downlink.teid().get(),
        }
    }

    fn n3iwf_intent_key(intent: &N3iwfSessionIntent) -> MockN3iwfKey {
        Self::n3iwf_key(intent.n3().link_ifindex(), intent.n3().local_downlink())
    }

    const fn n3iwf_fault_reason(fault: MockPdpContextFault) -> PdpContextIndeterminateReason {
        match fault {
            MockPdpContextFault::ChangingReadback => PdpContextIndeterminateReason::StateChanged,
            MockPdpContextFault::CorruptState | MockPdpContextFault::TransitionalState => {
                PdpContextIndeterminateReason::IncompleteState
            }
        }
    }

    /// The owner of the lowest requested mark that another session holds.
    fn n3iwf_foreign_owner(
        state: &MockState,
        intent: &N3iwfSessionIntent,
        own: MockN3iwfKey,
    ) -> Option<MockN3iwfKey> {
        let link_ifindex = intent.n3().link_ifindex();
        intent.child_sas().iter().find_map(|child_sa| {
            state
                .n3iwf_marks
                .get(&(link_ifindex, child_sa.mark().get()))
                .copied()
                .filter(|owner| *owner != own)
        })
    }

    /// Conflict evidence against the session that owns `owner`, or an
    /// indeterminate result if the index names no record.
    fn n3iwf_mark_conflict(
        state: &MockState,
        owner: MockN3iwfKey,
        desired: &N3iwfSessionIntent,
    ) -> Option<N3iwfSessionConflict> {
        state.n3iwf_sessions.get(&owner).and_then(|occupant| {
            N3iwfSessionConflict::between(
                N3iwfSessionOccupancy::ChildSaMark,
                occupant.intent(),
                desired,
            )
        })
    }

    /// The record equals `expected` and exactly its marks are indexed to it.
    fn n3iwf_is_exact(
        state: &MockState,
        key: MockN3iwfKey,
        expected: &N3iwfInstalledSession,
    ) -> bool {
        let child_sas = expected.intent().child_sas();
        state.n3iwf_sessions.get(&key) == Some(expected)
            && child_sas.iter().all(|child_sa| {
                state
                    .n3iwf_marks
                    .get(&(key.link_ifindex, child_sa.mark().get()))
                    == Some(&key)
            })
            && state
                .n3iwf_marks
                .values()
                .filter(|owner| **owner == key)
                .count()
                == child_sas.len()
    }

    /// Neither a record nor any index entry names `key`.
    fn n3iwf_is_absent(state: &MockState, key: MockN3iwfKey) -> bool {
        !state.n3iwf_sessions.contains_key(&key)
            && !state.n3iwf_marks.values().any(|owner| *owner == key)
    }
}

impl Default for MockGtpuDataplaneBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GtpuDataplaneBackend for MockGtpuDataplaneBackend {
    fn tft_uplink_classification_capability(&self) -> GtpuCapability {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.tft_uplink_classification_capability
    }

    fn validate_tft_uplink_classifier(
        &self,
        _desired: &TftUplinkClassifier,
    ) -> Result<(), GtpuError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::validate_tft_uplink_classifier_capability(state.tft_uplink_classification_capability)
    }

    async fn read_tft_uplink_classifier(
        &self,
        link_ifindex: u32,
        paa: std::net::IpAddr,
    ) -> Result<TftUplinkClassifierReadback, GtpuError> {
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
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if state.pdp_fault.is_some() {
            return Ok(TftUplinkClassifierReadback::Indeterminate);
        }
        Ok(Self::tft_classifier_readback_locked(
            &state,
            link_ifindex,
            paa,
        ))
    }

    async fn reconcile_tft_uplink_classifier(
        &self,
        desired: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierReconcileOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        Self::validate_tft_uplink_classifier_capability(
            state.tft_uplink_classification_capability,
        )?;
        if state.pdp_fault.is_some() {
            return Ok(TftUplinkClassifierReconcileOutcome::Indeterminate);
        }
        let key = (desired.link_ifindex(), desired.paa());
        match Self::tft_classifier_overlapping_keys_locked(&state, &desired).as_slice() {
            [] => {
                state.tft_classifiers.insert(key, desired);
                Ok(TftUplinkClassifierReconcileOutcome::Installed)
            }
            [resident] if state.tft_classifiers.get(resident) == Some(&desired) => {
                Ok(TftUplinkClassifierReconcileOutcome::AlreadyPresent)
            }
            [resident] => {
                // Every classifier in this map was installed by this backend, so
                // replacing the PDN's complete snapshot, including widening or
                // narrowing its PAA families, is within this authority.
                let resident = *resident;
                state.tft_classifiers.remove(&resident);
                state.tft_classifiers.insert(key, desired);
                Ok(TftUplinkClassifierReconcileOutcome::Replaced)
            }
            _ => Ok(TftUplinkClassifierReconcileOutcome::Conflict),
        }
    }

    async fn remove_tft_uplink_classifier_exact(
        &self,
        expected: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierRemovalOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if state.pdp_fault.is_some() {
            return Ok(TftUplinkClassifierRemovalOutcome::Indeterminate);
        }
        // Any resident owning an address of `expected` that is not exactly
        // `expected` is a conflict, whichever family keys it.
        match Self::tft_classifier_overlapping_keys_locked(&state, &expected).as_slice() {
            [] => Ok(TftUplinkClassifierRemovalOutcome::AlreadyAbsent),
            [resident] if state.tft_classifiers.get(resident) == Some(&expected) => {
                let resident = *resident;
                state.tft_classifiers.remove(&resident);
                Ok(TftUplinkClassifierRemovalOutcome::Removed)
            }
            _ => Ok(TftUplinkClassifierRemovalOutcome::Conflict),
        }
    }

    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.name.is_empty() {
            return Err(GtpuError::invalid_config(
                "device.name",
                "name must be nonempty",
            ));
        }
        if request.uplink_mtu_policy.is_some() {
            return Err(GtpuError::UnsupportedFeature {
                feature: "uplink_pmtu_enforcement",
            });
        }
        if state.devices.contains_key(&request.name) {
            return Err(GtpuError::AlreadyExists);
        }
        let ifindex = state.next_ifindex;
        state.next_ifindex = state.next_ifindex.saturating_add(1).max(1);
        state.operations.push(MockOperation::CreateDevice {
            request: request.clone(),
        });
        let device = GtpDevice {
            name: request.name,
            ifindex,
        };
        state.devices.insert(device.name.clone(), device.clone());
        Ok(device)
    }

    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if name.is_empty() {
            return Err(GtpuError::invalid_config(
                "device.name",
                "name must be nonempty",
            ));
        }
        state.operations.push(MockOperation::ResolveDevice {
            name: name.to_string(),
        });
        state.devices.get(name).cloned().ok_or(GtpuError::NotFound)
    }

    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if state.devices.get(&device.name) != Some(device) {
            return Err(GtpuError::NotFound);
        }
        state.devices.remove(&device.name);
        state
            .pdp_by_local
            .retain(|selector, _| selector.link_ifindex != device.ifindex);
        state
            .pdp_by_uplink
            .retain(|selector, _| selector.link_ifindex != device.ifindex);
        state
            .n3iwf_sessions
            .retain(|key, _| key.link_ifindex != device.ifindex);
        state
            .n3iwf_marks
            .retain(|(link_ifindex, _), _| *link_ifindex != device.ifindex);
        state.operations.push(MockOperation::RemoveDevice {
            device: device.clone(),
        });
        Ok(())
    }

    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.bearer_mark.is_some() {
            return Err(GtpuError::UnsupportedFeature {
                feature: "per_bearer_marking",
            });
        }
        if request.egress_dscp.is_some() {
            return Err(GtpuError::UnsupportedFeature {
                feature: "fixed_outer_dscp",
            });
        }
        if request.downlink_inner_mtu.is_some() {
            return Err(GtpuError::UnsupportedFeature {
                feature: "downlink_inner_mtu",
            });
        }
        if request.uplink_source_port_policy != crate::GtpuUplinkSourcePortPolicy::LegacyServicePort
        {
            return Err(GtpuError::UnsupportedFeature {
                feature: "uplink_source_port_selection",
            });
        }
        if request.link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        Self::validate_context(&request)?;
        if state.pdp_fault.is_some() {
            return Err(GtpuError::StateIndeterminate {
                operation: "mock_pdp_context_install",
            });
        }
        let (local, uplink) = Self::desired_readback_locked(&state, &request);
        match classify_dual_selector_state(&local, &uplink, &request) {
            DualSelectorState::BothAbsent => {
                Self::insert_context_locked(&mut state, request.clone());
            }
            DualSelectorState::Exact => {}
            DualSelectorState::Conflict(_) => return Err(GtpuError::AlreadyExists),
            DualSelectorState::Indeterminate => {
                return Err(GtpuError::StateIndeterminate {
                    operation: "mock_pdp_context_install",
                });
            }
        }
        state
            .operations
            .push(MockOperation::InstallPdpContext { request });
        Ok(())
    }

    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        if state.pdp_fault.is_some() {
            return Err(GtpuError::StateIndeterminate {
                operation: "mock_pdp_context_remove",
            });
        }
        let key = MockLocalSelector {
            link_ifindex: request.link_ifindex,
            version: Self::version_key(request.gtp_version),
            family: Self::family_key(request.address_family),
            local_teid: request.local_teid.get(),
        };
        if let Some(context) = state.pdp_by_local.get(&key).cloned() {
            Self::remove_context_locked(&mut state, &context);
        }
        state
            .operations
            .push(MockOperation::RemovePdpContext { request });
        Ok(())
    }

    async fn read_pdp_context(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        let result = Self::read_locked(&state, &selector);
        state
            .pdp_context_reconciliation_operations
            .push(MockPdpContextReconciliationOperation::Read { selector });
        result
    }

    async fn install_pdp_context_classified(
        &self,
        request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        Self::validate_context(&request)?;
        state.pdp_context_reconciliation_operations.push(
            MockPdpContextReconciliationOperation::InstallClassified {
                request: request.clone(),
            },
        );
        if let Some(fault) = state.pdp_fault {
            let reason = match fault {
                MockPdpContextFault::ChangingReadback => {
                    PdpContextIndeterminateReason::StateChanged
                }
                MockPdpContextFault::CorruptState | MockPdpContextFault::TransitionalState => {
                    PdpContextIndeterminateReason::IncompleteState
                }
            };
            return Ok(PdpContextInstallOutcome::Indeterminate(reason));
        }
        let (local, uplink) = Self::desired_readback_locked(&state, &request);
        match classify_dual_selector_state(&local, &uplink, &request) {
            DualSelectorState::BothAbsent => {
                Self::insert_context_locked(&mut state, request.clone());
                let (local, uplink) = Self::desired_readback_locked(&state, &request);
                if matches!(
                    classify_dual_selector_state(&local, &uplink, &request),
                    DualSelectorState::Exact
                ) {
                    Ok(PdpContextInstallOutcome::Installed)
                } else {
                    Ok(PdpContextInstallOutcome::Indeterminate(
                        PdpContextIndeterminateReason::MutationUnconfirmed,
                    ))
                }
            }
            DualSelectorState::Exact => Ok(PdpContextInstallOutcome::ExactAlreadyPresent),
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextInstallOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
        }
    }

    async fn remove_pdp_context_exact(
        &self,
        expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        Self::validate_context(&expected)?;
        state.pdp_context_reconciliation_operations.push(
            MockPdpContextReconciliationOperation::RemoveExact {
                expected: expected.clone(),
            },
        );
        if let Some(fault) = state.pdp_fault {
            let reason = match fault {
                MockPdpContextFault::ChangingReadback => {
                    PdpContextIndeterminateReason::StateChanged
                }
                MockPdpContextFault::CorruptState | MockPdpContextFault::TransitionalState => {
                    PdpContextIndeterminateReason::IncompleteState
                }
            };
            return Ok(PdpContextRemovalOutcome::Indeterminate(reason));
        }
        let (local, uplink) = Self::desired_readback_locked(&state, &expected);
        match classify_dual_selector_state(&local, &uplink, &expected) {
            DualSelectorState::BothAbsent => Ok(PdpContextRemovalOutcome::AlreadyAbsent),
            DualSelectorState::Exact => {
                Self::remove_context_locked(&mut state, &expected);
                let (local, uplink) = Self::desired_readback_locked(&state, &expected);
                if matches!(
                    classify_dual_selector_state(&local, &uplink, &expected),
                    DualSelectorState::BothAbsent
                ) {
                    Ok(PdpContextRemovalOutcome::Removed)
                } else {
                    Ok(PdpContextRemovalOutcome::Indeterminate(
                        PdpContextIndeterminateReason::MutationUnconfirmed,
                    ))
                }
            }
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextRemovalOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
        }
    }

    fn n3iwf_session_lifecycle_capabilities(&self) -> N3iwfSessionLifecycleCapabilities {
        // The mock models the RFC 021 state lifecycle only. It forwards no
        // packets, so the N3IWF forwarding role stays `Missing`, and it has no
        // durable writer authority for recovery or live-writer removal.
        N3iwfSessionLifecycleCapabilities {
            readback: GtpuCapability::Available,
            classified_install: GtpuCapability::Available,
            flow_reconcile: GtpuCapability::Available,
            exact_removal: GtpuCapability::Available,
            restart_recovery: GtpuCapability::Missing,
            live_writer_removal: GtpuCapability::Missing,
        }
    }

    async fn read_n3iwf_session(
        &self,
        selector: N3iwfSessionSelector,
    ) -> Result<N3iwfSessionReadback, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state
            .n3iwf_session_operations
            .push(MockN3iwfSessionOperation::Read { selector });
        let indeterminate = GtpuError::StateIndeterminate {
            operation: "mock_n3iwf_session_readback",
        };
        if state.pdp_fault.is_some() {
            return Err(indeterminate);
        }
        let key = match selector.key() {
            N3iwfSessionSelectorKey::LocalDownlink(local_downlink) => {
                Self::n3iwf_key(selector.link_ifindex(), local_downlink)
            }
            N3iwfSessionSelectorKey::ChildSaMark(mark) => {
                match state
                    .n3iwf_marks
                    .get(&(selector.link_ifindex(), mark.get()))
                {
                    Some(key) => *key,
                    None => return Ok(N3iwfSessionReadback::Absent),
                }
            }
        };
        match state.n3iwf_sessions.get(&key) {
            Some(installed) if Self::n3iwf_is_exact(&state, key, installed) => {
                Ok(N3iwfSessionReadback::Present(installed.clone()))
            }
            None if Self::n3iwf_is_absent(&state, key) => Ok(N3iwfSessionReadback::Absent),
            // Index residue or a partial closure is never collapsed into Absent.
            Some(_) | None => Err(indeterminate),
        }
    }

    async fn install_n3iwf_session_classified(
        &self,
        intent: N3iwfSessionIntent,
    ) -> Result<N3iwfSessionInstallOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state
            .n3iwf_session_operations
            .push(MockN3iwfSessionOperation::InstallClassified {
                intent: intent.clone(),
            });
        if let Some(fault) = state.pdp_fault {
            return Ok(N3iwfSessionInstallOutcome::Indeterminate(
                Self::n3iwf_fault_reason(fault),
            ));
        }
        let key = Self::n3iwf_intent_key(&intent);
        let foreign_owner = Self::n3iwf_foreign_owner(&state, &intent, key);
        if let Some(existing) = state.n3iwf_sessions.get(&key) {
            if existing.intent() == &intent {
                return Ok(N3iwfSessionInstallOutcome::ExactAlreadyPresent(
                    existing.generation(),
                ));
            }
            let occupancy = if foreign_owner.is_some() {
                N3iwfSessionOccupancy::Both
            } else {
                N3iwfSessionOccupancy::LocalTeid
            };
            return Ok(
                N3iwfSessionConflict::between(occupancy, existing.intent(), &intent).map_or(
                    N3iwfSessionInstallOutcome::Indeterminate(
                        PdpContextIndeterminateReason::IncompleteState,
                    ),
                    N3iwfSessionInstallOutcome::Conflict,
                ),
            );
        }
        if let Some(owner) = foreign_owner {
            return Ok(Self::n3iwf_mark_conflict(&state, owner, &intent).map_or(
                N3iwfSessionInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ),
                N3iwfSessionInstallOutcome::Conflict,
            ));
        }
        let installed = N3iwfInstalledSession::new(intent, N3iwfSessionGeneration::FIRST);
        // Index entries authorize nothing until the record is published.
        for child_sa in installed.intent().child_sas() {
            state
                .n3iwf_marks
                .insert((key.link_ifindex, child_sa.mark().get()), key);
        }
        state.n3iwf_sessions.insert(key, installed.clone());
        if Self::n3iwf_is_exact(&state, key, &installed) {
            Ok(N3iwfSessionInstallOutcome::Installed(
                installed.generation(),
            ))
        } else {
            Ok(N3iwfSessionInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::MutationUnconfirmed,
            ))
        }
    }

    async fn reconcile_n3iwf_session_flows(
        &self,
        update: N3iwfSessionFlowUpdate,
    ) -> Result<N3iwfSessionReconcileOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state
            .n3iwf_session_operations
            .push(MockN3iwfSessionOperation::ReconcileFlows {
                update: update.clone(),
            });
        if let Some(fault) = state.pdp_fault {
            return Ok(N3iwfSessionReconcileOutcome::Indeterminate(
                Self::n3iwf_fault_reason(fault),
            ));
        }
        let (expected, desired) = update.into_parts();
        let key = Self::n3iwf_intent_key(&desired);
        let Some(current) = state.n3iwf_sessions.get(&key).cloned() else {
            return Ok(N3iwfSessionReconcileOutcome::Absent);
        };
        if current.intent() == &desired {
            return Ok(N3iwfSessionReconcileOutcome::ExactAlreadyPresent(
                current.generation(),
            ));
        }
        if current != expected {
            return Ok(N3iwfSessionConflict::between_installed(
                N3iwfSessionOccupancy::LocalTeid,
                &current,
                &expected,
            )
            .map_or(
                N3iwfSessionReconcileOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ),
                N3iwfSessionReconcileOutcome::Conflict,
            ));
        }
        if let Some(owner) = Self::n3iwf_foreign_owner(&state, &desired, key) {
            return Ok(Self::n3iwf_mark_conflict(&state, owner, &desired).map_or(
                N3iwfSessionReconcileOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ),
                N3iwfSessionReconcileOutcome::Conflict,
            ));
        }
        let Some(next) = current.generation().next() else {
            // Generations never wrap; exhaustion refuses without mutation.
            return Ok(N3iwfSessionReconcileOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable,
            ));
        };
        let replacement = N3iwfInstalledSession::new(desired, next);
        // Stage new index entries, replace the record once, then drop the
        // entries of Child SAs that left the table.
        for child_sa in replacement.intent().child_sas() {
            state
                .n3iwf_marks
                .insert((key.link_ifindex, child_sa.mark().get()), key);
        }
        state.n3iwf_sessions.insert(key, replacement.clone());
        for child_sa in current.intent().child_sas() {
            let index = (key.link_ifindex, child_sa.mark().get());
            if replacement.intent().child_sa(child_sa.mark()).is_none()
                && state.n3iwf_marks.get(&index) == Some(&key)
            {
                state.n3iwf_marks.remove(&index);
            }
        }
        if Self::n3iwf_is_exact(&state, key, &replacement) {
            Ok(N3iwfSessionReconcileOutcome::Reconciled(next))
        } else {
            Ok(N3iwfSessionReconcileOutcome::Indeterminate(
                PdpContextIndeterminateReason::MutationUnconfirmed,
            ))
        }
    }

    async fn remove_n3iwf_session_exact(
        &self,
        expected: N3iwfInstalledSession,
    ) -> Result<N3iwfSessionRemovalOutcome, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state
            .n3iwf_session_operations
            .push(MockN3iwfSessionOperation::RemoveExact {
                expected: expected.clone(),
            });
        if let Some(fault) = state.pdp_fault {
            return Ok(N3iwfSessionRemovalOutcome::Indeterminate(
                Self::n3iwf_fault_reason(fault),
            ));
        }
        let key = Self::n3iwf_intent_key(expected.intent());
        match state.n3iwf_sessions.get(&key) {
            None if Self::n3iwf_is_absent(&state, key) => {
                return Ok(N3iwfSessionRemovalOutcome::AlreadyAbsent);
            }
            None => {
                return Ok(N3iwfSessionRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ));
            }
            Some(current) if current != &expected => {
                return Ok(N3iwfSessionConflict::between_installed(
                    N3iwfSessionOccupancy::LocalTeid,
                    current,
                    &expected,
                )
                .map_or(
                    N3iwfSessionRemovalOutcome::Indeterminate(
                        PdpContextIndeterminateReason::IncompleteState,
                    ),
                    N3iwfSessionRemovalOutcome::Conflict,
                ));
            }
            Some(_) => {}
        }
        // Withdraw the record first, then its index entries.
        state.n3iwf_sessions.remove(&key);
        state.n3iwf_marks.retain(|_, owner| *owner != key);
        if Self::n3iwf_is_absent(&state, key) {
            Ok(N3iwfSessionRemovalOutcome::Removed)
        } else {
            Ok(N3iwfSessionRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::MutationUnconfirmed,
            ))
        }
    }

    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        PdpContextReconciliationCapabilities {
            readback: GtpuCapability::Available,
            classified_install: GtpuCapability::Available,
            exact_removal: GtpuCapability::Available,
        }
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::Probe);
        Ok(state.probe_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GtpVersion, Teid};
    use std::net::{IpAddr, Ipv4Addr};

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(1),
            peer_teid: teid(2),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
            downlink_inner_mtu: None,
        }
    }

    #[tokio::test]
    async fn mock_records_device_lifecycle() {
        let backend = MockGtpuDataplaneBackend::new();
        let request = CreateGtpDeviceRequest::new("gtp0");
        let device = backend.create_device(request.clone()).await.unwrap();
        backend.remove_device(&device).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::CreateDevice {
                    request: request.clone()
                },
                MockOperation::RemoveDevice { device }
            ]
        );
    }

    #[tokio::test]
    async fn mock_resolves_existing_device_by_name() {
        let backend = MockGtpuDataplaneBackend::new();
        let request = CreateGtpDeviceRequest::new("gtp0");
        let device = backend.create_device(request.clone()).await.unwrap();

        let resolved = backend.resolve_device("gtp0").await.unwrap();

        assert_eq!(resolved, device);
        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::CreateDevice { request },
                MockOperation::ResolveDevice {
                    name: "gtp0".to_string()
                },
            ]
        );
    }

    #[tokio::test]
    async fn mock_resolve_reports_not_found_after_remove() {
        let backend = MockGtpuDataplaneBackend::new();
        let device = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap();
        backend.remove_device(&device).await.unwrap();

        let error = backend.resolve_device("gtp0").await.unwrap_err();

        assert!(matches!(error, GtpuError::NotFound));
    }

    #[tokio::test]
    async fn mock_create_duplicate_device_reports_already_exists() {
        let backend = MockGtpuDataplaneBackend::new();
        backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap();

        let error = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap_err();

        assert!(matches!(error, GtpuError::AlreadyExists));
    }

    #[tokio::test]
    async fn mock_records_pdp_lifecycle() {
        let backend = MockGtpuDataplaneBackend::new();
        let ctx = context();
        let remove = RemovePdpContextRequest::from_context(&ctx);

        backend.install_pdp_context(ctx.clone()).await.unwrap();
        backend.remove_pdp_context(remove.clone()).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::InstallPdpContext { request: ctx },
                MockOperation::RemovePdpContext { request: remove }
            ]
        );
    }

    #[tokio::test]
    async fn mock_truthfully_rejects_fixed_outer_dscp() {
        let backend = MockGtpuDataplaneBackend::new();
        let mut request = context();
        request.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend.install_pdp_context(request).await.unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "fixed_outer_dscp"
            }
        ));
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            crate::GtpuCapability::Missing
        );
    }

    #[tokio::test]
    async fn mock_failure_is_injected_without_recording() {
        let backend = MockGtpuDataplaneBackend::new();
        backend.set_failure(GtpuError::AlreadyExists);
        let err = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap_err();
        assert!(matches!(err, GtpuError::AlreadyExists));
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn mock_operation_debug_redacts_pdp_values() {
        let op = MockOperation::InstallPdpContext { request: context() };
        let debug = format!("{op:?}");
        assert!(!debug.contains("10.23.0.2"));
        assert!(!debug.contains("192.0.2.10"));
    }

    #[tokio::test]
    async fn mock_reconciliation_calls_use_the_separate_redacted_log() {
        let backend = MockGtpuDataplaneBackend::new();
        let desired = context();
        let selector = PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
        );

        assert_eq!(
            backend
                .install_pdp_context_classified(desired.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );
        assert_eq!(
            backend.read_pdp_context(selector.clone()).await.unwrap(),
            PdpContextReadback::Present(desired.clone())
        );
        assert_eq!(
            backend
                .remove_pdp_context_exact(desired.clone())
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Removed
        );

        assert!(backend.operations().is_empty());
        assert_eq!(
            backend.pdp_context_reconciliation_operations(),
            vec![
                MockPdpContextReconciliationOperation::InstallClassified {
                    request: desired.clone(),
                },
                MockPdpContextReconciliationOperation::Read { selector },
                MockPdpContextReconciliationOperation::RemoveExact { expected: desired },
            ]
        );
        let debug = format!("{:?}", backend.pdp_context_reconciliation_operations());
        assert!(!debug.contains("10.23.0.2"));
        assert!(!debug.contains("192.0.2.10"));

        backend.clear_operations();
        assert!(backend.pdp_context_reconciliation_operations().is_empty());
    }

    #[tokio::test]
    async fn mock_reconciliation_round_trip_covers_default_and_marked_contexts() {
        let backend = MockGtpuDataplaneBackend::new();
        let mut default = context();
        default.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        let mut marked = context();
        marked.local_teid = teid(3);
        marked.peer_teid = teid(4);
        marked.bearer_mark = crate::GtpBearerMark::new(0x1001);
        marked.egress_dscp = Some(crate::DscpCodepoint::new(34).unwrap());

        for desired in [&default, &marked] {
            assert_eq!(
                backend
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Installed
            );
            assert_eq!(
                backend
                    .clone()
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::ExactAlreadyPresent
            );
            assert_eq!(
                backend
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        crate::PdpContextLocalTeidSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
            assert_eq!(
                backend
                    .read_pdp_context(PdpContextSelector::Uplink(
                        crate::PdpContextUplinkSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
        }

        assert_eq!(
            backend.pdp_context_reconciliation_capabilities(),
            PdpContextReconciliationCapabilities {
                readback: GtpuCapability::Available,
                classified_install: GtpuCapability::Available,
                exact_removal: GtpuCapability::Available,
            }
        );
    }

    #[tokio::test]
    async fn mock_classifies_both_selector_collision_shapes_without_mutation() {
        let backend = MockGtpuDataplaneBackend::new();
        let installed = context();
        assert_eq!(
            backend
                .install_pdp_context_classified(installed.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );

        let mut same_uplink = installed.clone();
        same_uplink.local_teid = teid(11);
        same_uplink.peer_teid = teid(12);
        let outcome = backend
            .install_pdp_context_classified(same_uplink.clone())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::Uplink
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::LocalTeid)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::PeerTeid)
        ));

        let mut same_local = installed.clone();
        same_local.ms_address = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3));
        same_local.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        let outcome = backend
            .install_pdp_context_classified(same_local.clone())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::LocalTeid
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::MsAddress)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::PeerAddress)
        ));

        assert!(matches!(
            backend.remove_pdp_context_exact(same_uplink).await.unwrap(),
            PdpContextRemovalOutcome::Conflict(_)
        ));
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    crate::PdpContextLocalTeidSelector::from_context(&installed).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(installed)
        );
    }

    #[tokio::test]
    async fn mock_exact_removal_is_idempotent_and_never_deletes_conflicting_state() {
        let backend = MockGtpuDataplaneBackend::new();
        let installed = context();
        backend
            .install_pdp_context_classified(installed.clone())
            .await
            .unwrap();

        assert_eq!(
            backend
                .remove_pdp_context_exact(installed.clone())
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Removed
        );
        assert_eq!(
            backend.remove_pdp_context_exact(installed).await.unwrap(),
            PdpContextRemovalOutcome::AlreadyAbsent
        );
    }

    #[tokio::test]
    async fn mock_reconciliation_faults_fail_closed_with_stable_classification() {
        let backend = MockGtpuDataplaneBackend::new();
        for (fault, expected) in [
            (
                MockPdpContextFault::CorruptState,
                PdpContextIndeterminateReason::IncompleteState,
            ),
            (
                MockPdpContextFault::TransitionalState,
                PdpContextIndeterminateReason::IncompleteState,
            ),
            (
                MockPdpContextFault::ChangingReadback,
                PdpContextIndeterminateReason::StateChanged,
            ),
        ] {
            backend.set_pdp_context_fault(Some(fault));
            assert_eq!(
                backend
                    .install_pdp_context_classified(context())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Indeterminate(expected)
            );
            assert_eq!(
                backend.remove_pdp_context_exact(context()).await.unwrap(),
                PdpContextRemovalOutcome::Indeterminate(expected)
            );
            assert!(matches!(
                backend
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        crate::PdpContextLocalTeidSelector::from_context(&context()).unwrap(),
                    ))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "mock_pdp_context_readback"
                }
            ));
        }
        backend.set_pdp_context_fault(None);
    }

    #[tokio::test]
    async fn mock_tft_classifier_reconciliation_is_exact_and_idempotent() {
        let backend = MockGtpuDataplaneBackend::new();
        let desired = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            vec![crate::TftUplinkBearer::default_bearer()],
        )
        .unwrap();
        assert_eq!(
            backend.tft_uplink_classification_capability(),
            GtpuCapability::Available
        );
        assert!(backend.validate_tft_uplink_classifier(&desired).is_ok());
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Installed
        );
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::AlreadyPresent
        );
        let replacement = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            vec![
                crate::TftUplinkBearer::default_bearer(),
                crate::TftUplinkBearer::dedicated(
                    crate::GtpBearerMark::new(9).unwrap(),
                    opc_proto_tft::TrafficFlowTemplate::create_new(
                        vec![opc_proto_tft::PacketFilter::new(
                            opc_proto_tft::PacketFilterIdentifier::new(1).unwrap(),
                            opc_proto_tft::PacketFilterDirection::UplinkOnly,
                            1,
                            vec![
                                opc_proto_tft::PacketFilterComponent::ProtocolIdentifierNextHeader(
                                    17,
                                ),
                            ],
                        )
                        .unwrap()],
                        vec![],
                    )
                    .unwrap(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(replacement.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Replaced
        );
        assert_eq!(
            backend
                .read_tft_uplink_classifier(desired.link_ifindex(), desired.paa())
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Present(replacement.clone())
        );
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierRemovalOutcome::Conflict
        );
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(replacement.clone())
                .await
                .unwrap(),
            TftUplinkClassifierRemovalOutcome::Removed
        );
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(replacement)
                .await
                .unwrap(),
            TftUplinkClassifierRemovalOutcome::AlreadyAbsent
        );
    }

    #[tokio::test]
    async fn mock_tft_classifier_validation_honors_configured_capability() {
        let backend = MockGtpuDataplaneBackend::new();
        let desired = TftUplinkClassifier::new(
            7,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            vec![crate::TftUplinkBearer::default_bearer()],
        )
        .unwrap();
        backend.set_tft_uplink_classification_capability(GtpuCapability::Missing);

        assert_eq!(
            backend.tft_uplink_classification_capability(),
            GtpuCapability::Missing
        );
        assert!(matches!(
            backend.validate_tft_uplink_classifier(&desired),
            Err(GtpuError::UnsupportedFeature {
                feature: "tft_uplink_classification"
            })
        ));
        assert!(matches!(
            backend.reconcile_tft_uplink_classifier(desired).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "tft_uplink_classification"
            })
        ));
    }

    #[tokio::test]
    async fn mock_tft_classifier_reads_dual_family_set_by_either_family() {
        let backend = MockGtpuDataplaneBackend::new();
        let v4 = Ipv4Addr::new(192, 0, 2, 44);
        let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0, 0, 0, 0x10);
        let desired = TftUplinkClassifier::with_paa_set(
            7,
            crate::TftUplinkPaaSet::new_dual(v4, v6).unwrap(),
            vec![crate::TftUplinkBearer::default_bearer()],
        )
        .unwrap();
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Installed
        );
        let temporary = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0x3c91, 0x7e02, 0xa455, 1);
        for address in [IpAddr::V4(v4), IpAddr::V6(v6), IpAddr::V6(temporary)] {
            assert_eq!(
                backend
                    .read_tft_uplink_classifier(7, address)
                    .await
                    .unwrap(),
                TftUplinkClassifierReadback::Present(desired.clone())
            );
        }
        let outside = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xa, 2, 0, 0, 0, 0x10);
        assert_eq!(
            backend
                .read_tft_uplink_classifier(7, IpAddr::V6(outside))
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Absent
        );
        // A classifier claiming only the already-owned IPv6 prefix is the same
        // PDN narrowed to one family. It replaces the resident, exactly as
        // narrowing to the IPv4 PAA does, and never creates a second owner of
        // that prefix.
        let overlapping = TftUplinkClassifier::new(
            7,
            IpAddr::V6(temporary),
            vec![crate::TftUplinkBearer::default_bearer()],
        )
        .unwrap();
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(overlapping.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Replaced
        );
        assert_eq!(
            backend
                .read_tft_uplink_classifier(7, IpAddr::V4(v4))
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Absent
        );
        assert_eq!(
            backend
                .read_tft_uplink_classifier(7, IpAddr::V6(v6))
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Present(overlapping)
        );
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Replaced
        );
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(desired.clone())
                .await
                .unwrap(),
            TftUplinkClassifierRemovalOutcome::Removed
        );
        assert_eq!(
            backend
                .read_tft_uplink_classifier(7, IpAddr::V6(temporary))
                .await
                .unwrap(),
            TftUplinkClassifierReadback::Absent
        );
    }

    /// The PDN's classifier is the one resident whose PAA set overlaps.
    /// Widening or narrowing its families replaces it the same way for both
    /// families, exact removal by a set that only overlaps it conflicts, and
    /// a set straddling two residents conflicts.
    #[tokio::test]
    async fn mock_tft_classifier_family_transitions_are_symmetric() {
        let v4 = Ipv4Addr::new(192, 0, 2, 44);
        let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0xa, 1, 0, 0, 0, 0x10);
        let bearers = || vec![crate::TftUplinkBearer::default_bearer()];
        let classifier = |set: crate::TftUplinkPaaSet| {
            TftUplinkClassifier::with_paa_set(7, set, bearers()).unwrap()
        };
        let only_v4 = classifier(crate::TftUplinkPaaSet::new_ipv4(v4).unwrap());
        let only_v6 = classifier(crate::TftUplinkPaaSet::new_ipv6(v6).unwrap());
        let dual = classifier(crate::TftUplinkPaaSet::new_dual(v4, v6).unwrap());

        for single in [&only_v4, &only_v6] {
            // Single family to dual, and back, replaces the one resident.
            let backend = MockGtpuDataplaneBackend::new();
            for (desired, outcome) in [
                (single, TftUplinkClassifierReconcileOutcome::Installed),
                (&dual, TftUplinkClassifierReconcileOutcome::Replaced),
                (&dual, TftUplinkClassifierReconcileOutcome::AlreadyPresent),
            ] {
                assert_eq!(
                    backend
                        .reconcile_tft_uplink_classifier(desired.clone())
                        .await
                        .unwrap(),
                    outcome,
                    "{single:?} -> {desired:?}"
                );
            }
            for address in [IpAddr::V4(v4), IpAddr::V6(v6)] {
                assert_eq!(
                    backend
                        .read_tft_uplink_classifier(7, address)
                        .await
                        .unwrap(),
                    TftUplinkClassifierReadback::Present(dual.clone())
                );
            }
            // Exact removal of a set that only overlaps the resident conflicts
            // and leaves it in place.
            assert_eq!(
                backend
                    .remove_tft_uplink_classifier_exact(single.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierRemovalOutcome::Conflict,
                "{single:?}"
            );
            assert_eq!(
                backend
                    .reconcile_tft_uplink_classifier(single.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierReconcileOutcome::Replaced,
                "dual -> {single:?}"
            );
            assert_eq!(
                backend
                    .remove_tft_uplink_classifier_exact(dual.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierRemovalOutcome::Conflict
            );
            assert_eq!(
                backend
                    .remove_tft_uplink_classifier_exact(single.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierRemovalOutcome::Removed
            );
            assert_eq!(
                backend
                    .remove_tft_uplink_classifier_exact(single.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierRemovalOutcome::AlreadyAbsent
            );
        }

        // A dual set straddling two distinct residents conflicts.
        let backend = MockGtpuDataplaneBackend::new();
        for single in [&only_v4, &only_v6] {
            assert_eq!(
                backend
                    .reconcile_tft_uplink_classifier(single.clone())
                    .await
                    .unwrap(),
                TftUplinkClassifierReconcileOutcome::Installed
            );
        }
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(dual.clone())
                .await
                .unwrap(),
            TftUplinkClassifierReconcileOutcome::Conflict
        );
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(dual)
                .await
                .unwrap(),
            TftUplinkClassifierRemovalOutcome::Conflict
        );
    }

    #[tokio::test]
    async fn mock_tft_classifier_readback_rejects_invalid_identity() {
        let backend = MockGtpuDataplaneBackend::new();
        assert!(backend
            .read_tft_uplink_classifier(0, IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)))
            .await
            .is_err());
        assert!(backend
            .read_tft_uplink_classifier(7, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .await
            .is_err());
    }
}
