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
}

impl Default for MockGtpuDataplaneBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GtpuDataplaneBackend for MockGtpuDataplaneBackend {
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
}
