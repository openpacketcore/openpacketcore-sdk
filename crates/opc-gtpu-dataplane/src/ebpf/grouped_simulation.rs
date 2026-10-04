//! Consumer composition fixture. The production codec and inventory validator
//! are reused; simulation effects are atomic and have no kernel readers.

use super::*;
use crate::selector_namespace::*;
use crate::{MockGtpuDataplaneBackend, PdpContextReconciliationCapabilities, GTPU_PORT};

/// Isolated grouped GTP-U simulation for downstream authority/lifecycle tests.
///
/// Attach one device with [`GtpuDataplaneBackend::create_device_with_endpoints`],
/// then pass [`Self::selector_namespace_bootstrap`] and the same shared backend
/// into the real protected selector authority. Clones share every map, TFT
/// classifier and immutable namespace binding. The bootstrap has a private,
/// random simulation identity and cannot adopt a kernel namespace.
///
/// Group records, directional indexes and permanent operation stamps use the
/// real adapter codecs and exact inventory validator. Effects publish atomically
/// in memory; this does not simulate the adapter's staged kernel write faults.
/// TFT admission uses the native eBPF representation validator, while TFT
/// replacement uses the SDK mock's complete-snapshot transaction model.
///
/// This backend reports `Mock`, never reports kernel readiness, refuses raw PDP
/// mutation, and inherits unsupported traffic-proof ports. Structural success
/// cannot be used as TrafficReady evidence. Use the real adapter regression
/// fixtures for staged effects, cancellation and traffic-proof revocation.
#[derive(Clone)]
pub struct GroupedGtpuDataplaneSimulation {
    pin_identity: [u8; 32],
    state: Arc<Mutex<SimulationState>>,
    tft: MockGtpuDataplaneBackend,
}

#[derive(Default)]
struct SimulationState {
    attachment: Option<GtpuSessionAttachmentSelector>,
    binding: Option<GtpuSessionSelectorBackendBinding>,
    records: BTreeMap<[u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
    indexes: BTreeMap<GroupedIndexKey, [u8; GTPU_SESSION_GROUP_REF_LEN]>,
    stamps: BTreeMap<[u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN]>,
}

impl fmt::Debug for GroupedGtpuDataplaneSimulation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GroupedGtpuDataplaneSimulation(<isolated-mock>)")
    }
}

fn unavailable() -> GtpuError {
    state_indeterminate("grouped_simulation_authority")
}

impl GroupedGtpuDataplaneSimulation {
    /// Create an empty simulation. No device, socket or map operations occur.
    pub fn new() -> Result<Self, GtpuError> {
        let mut pin_identity = [0; 32];
        SysRng
            .try_fill_bytes(&mut pin_identity)
            .map_err(|_| unavailable())?;
        if pin_identity == [0; 32] {
            return Err(unavailable());
        }
        Ok(Self {
            pin_identity,
            state: Arc::new(Mutex::new(SimulationState::default())),
            tft: MockGtpuDataplaneBackend::new(),
        })
    }

    /// Qualify only this simulation's attached device for protected provision
    /// or reopen. Callers cannot supply or read the private namespace identity.
    pub async fn selector_namespace_bootstrap(
        &self,
        device: GtpuSessionDeviceId,
    ) -> Result<GtpuSelectorNamespaceBootstrap, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        if state
            .attachment
            .as_ref()
            .is_none_or(|attachment| attachment.device_id() != device)
        {
            return Err(unavailable());
        }
        GtpuSelectorNamespaceBootstrap::from_qualified_backend(device, self.pin_identity)
            .ok_or_else(unavailable)
    }

    fn qualify_tft_attachment(&self, link_ifindex: u32, effect: bool) -> Result<(), GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        if (effect && state.binding.is_none())
            || state
                .attachment
                .as_ref()
                .is_none_or(|attachment| attachment.device().ifindex != link_ifindex)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    fn qualify_binding(
        &self,
        state: &SimulationState,
        binding: GtpuSessionSelectorBackendBinding,
    ) -> Result<(), GtpuError> {
        if state.binding != Some(binding)
            || !binding.matches_qualified_pin_commitment(self.pin_identity)
            || state
                .attachment
                .as_ref()
                .is_none_or(|attachment| attachment.device_id() != binding.stable_device())
        {
            return Err(unavailable());
        }
        Ok(())
    }
}

impl SimulationState {
    fn validate_group(
        &self,
        group: &GtpuSessionGroup,
    ) -> Result<&GtpuSessionAttachmentSelector, GtpuError> {
        let attachment = self.attachment.as_ref().ok_or_else(unavailable)?;
        group
            .validate_attachment(
                attachment.device_id(),
                attachment.device(),
                attachment.local_endpoints(),
            )
            .map_err(|_| unavailable())?;
        Ok(attachment)
    }

    fn indexes_for(
        &self,
        key: [u8; GTPU_SESSION_GROUP_ID_LEN],
    ) -> Result<Vec<GroupedIndexElement>, GtpuError> {
        let mut result = Vec::new();
        for (index, raw) in &self.indexes {
            let reference = GtpuSessionGroupRef::decode(raw).ok_or_else(unavailable)?;
            if reference.group_id().to_bytes() == key {
                result.push(GroupedIndexElement {
                    key: *index,
                    value: *raw,
                });
            }
        }
        Ok(result)
    }

    fn exact_active(
        &self,
        expected: &GtpuSessionGroup,
    ) -> Result<GtpuSessionGroupRecord, GtpuError> {
        let attachment = self.validate_group(expected)?;
        let key = expected.id().to_bytes();
        let record = self
            .records
            .get(&key)
            .and_then(GtpuSessionGroupRecord::decode)
            .ok_or_else(unavailable)?;
        if record.phase() != GtpuSessionGroupPhase::Active
            || grouped_model_from_record(record, attachment.device()).as_ref() != Some(expected)
            || grouped_active_indexes(record).as_ref() != Some(&self.indexes_for(key)?)
        {
            return Err(unavailable());
        }
        Ok(record)
    }

    fn stamp(&self, group: &GtpuSessionGroup) -> Result<SelectorOperationStamp, GtpuError> {
        self.stamps
            .get(&group.id().to_bytes())
            .and_then(SelectorOperationStamp::decode)
            .ok_or_else(unavailable)
    }

    fn read_authorized(
        &self,
        expected: &GtpuSessionGroup,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionGroupReadback, GtpuError> {
        self.validate_group(expected)?;
        if !admission.validates(expected) {
            return Err(unavailable());
        }
        let authority = SelectorOperationStampAuthority::from(admission);
        let stamp = self.stamp(expected)?;
        if self.records.contains_key(&expected.id().to_bytes()) {
            let record = self.exact_active(expected)?;
            let coordinate = if authority.authorizes_retirement_effect() {
                authority.previous_terminal_or_terminal()
            } else {
                authority
            };
            if !stamp.is_exact_terminal_active(coordinate, record.generation()) {
                return Err(unavailable());
            }
            Ok(GtpuSessionGroupReadback::Active(expected.clone()))
        } else if self.indexes_for(expected.id().to_bytes())?.is_empty()
            && stamp.is_exact_terminal_retired(authority)
        {
            Ok(GtpuSessionGroupReadback::Absent)
        } else {
            Err(unavailable())
        }
    }
}

#[async_trait]
impl GtpuDataplaneBackend for GroupedGtpuDataplaneSimulation {
    async fn create_device(
        &self,
        _request: CreateGtpDeviceRequest,
    ) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "grouped_simulation_requires_endpoints",
        })
    }

    async fn create_device_with_endpoints(
        &self,
        request: CreateGtpDeviceEndpointSetRequest,
    ) -> Result<GtpDevice, GtpuError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        if state.attachment.is_some() {
            return Err(GtpuError::AlreadyExists);
        }
        if request.device().name.is_empty()
            || request.device().bind_port != GTPU_PORT
            || request.device().uplink_mtu_policy.is_some()
        {
            return Err(GtpuError::UnsupportedFeature {
                feature: "grouped_simulation_device_policy",
            });
        }
        let device = GtpDevice {
            name: request.device().name.clone(),
            ifindex: 1,
        };
        state.attachment = Some(
            GtpuSessionAttachmentSelector::new(
                request.device_id(),
                device.clone(),
                request.local_endpoints(),
            )
            .map_err(|_| unavailable())?,
        );
        Ok(device)
    }

    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError> {
        self.state
            .lock()
            .map_err(|_| unavailable())?
            .attachment
            .as_ref()
            .filter(|attachment| attachment.device().name == name)
            .map(|attachment| attachment.device().clone())
            .ok_or(GtpuError::NotFound)
    }

    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        if state.binding.is_some() {
            return Err(unavailable());
        }
        if state
            .attachment
            .as_ref()
            .is_none_or(|attachment| attachment.device() != device)
        {
            return Err(GtpuError::NotFound);
        }
        state.attachment = None;
        Ok(())
    }

    async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "grouped_simulation_raw_pdp",
        })
    }

    async fn remove_pdp_context(&self, _request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "grouped_simulation_raw_pdp",
        })
    }

    async fn read_pdp_context(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        let attachment = state.attachment.as_ref().ok_or_else(unavailable)?;
        let mut found = None;
        for raw in state.records.values() {
            let record = GtpuSessionGroupRecord::decode(raw).ok_or_else(unavailable)?;
            let group =
                grouped_model_from_record(record, attachment.device()).ok_or_else(unavailable)?;
            state.exact_active(&group)?;
            for entry in group.entries() {
                let context = entry.context();
                let matches = match &selector {
                    PdpContextSelector::LocalTeid(selector) => {
                        PdpContextLocalTeidSelector::from_context(context).as_ref()
                            == Some(selector)
                    }
                    PdpContextSelector::Uplink(selector) => {
                        PdpContextUplinkSelector::from_context(context).as_ref() == Some(selector)
                    }
                };
                if matches && found.replace(context.clone()).is_some() {
                    return Err(unavailable());
                }
            }
        }
        Ok(found.map_or(PdpContextReadback::Absent, PdpContextReadback::Present))
    }

    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        PdpContextReconciliationCapabilities {
            readback: GtpuCapability::Available,
            classified_install: GtpuCapability::Missing,
            exact_removal: GtpuCapability::Missing,
        }
    }

    async fn acquire_selector_namespace_lease(
        &self,
        lease: GtpuSessionSelectorBindingLease,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, lease.binding())?;
        let stamps = state
            .stamps
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect::<Vec<_>>();
        if !lease.is_current()
            || !selector_operation_stamp_inventory_is_exact(
                lease.binding(),
                lease.operation_stamp_inventory(),
                &stamps,
            )
        {
            return Err(unavailable());
        }
        Ok(lease.confirm())
    }

    async fn provision_selector_namespace_authorized(
        &self,
        request: GtpuSessionSelectorProvisionRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let binding = request.binding();
        if !request.is_current()
            || state.binding.is_some_and(|existing| existing != binding)
            || !state.records.is_empty()
            || !state.indexes.is_empty()
            || !state.stamps.is_empty()
            || !binding.matches_qualified_pin_commitment(self.pin_identity)
            || state
                .attachment
                .as_ref()
                .is_none_or(|attachment| attachment.device_id() != binding.stable_device())
        {
            return Err(unavailable());
        }
        state.binding = Some(binding);
        Ok(request.confirm())
    }

    async fn inspect_installing_selector_no_effect(
        &self,
        request: GtpuSessionSelectorInstallingNoEffectRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, request.admission().binding())?;
        state.validate_group(request.expected_group())?;
        let key = request.expected_group().id().to_bytes();
        if !request.is_current()
            || !request.admission().validates(request.expected_group())
            || state.records.contains_key(&key)
            || state.stamps.contains_key(&key)
            || !state.indexes_for(key)?.is_empty()
        {
            return Err(unavailable());
        }
        request.confirm().ok_or_else(unavailable)
    }

    async fn inspect_retiring_selector_no_effect(
        &self,
        request: GtpuSessionSelectorRetiringNoEffectRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, request.admission().binding())?;
        if !request.is_current()
            || !matches!(
                state.read_authorized(request.expected_group(), request.admission())?,
                GtpuSessionGroupReadback::Active(_)
            )
        {
            return Err(unavailable());
        }
        request.confirm().ok_or_else(unavailable)
    }

    async fn reconcile_pdp_context_group_authorized(
        &self,
        request: GtpuSessionSelectorEffectRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let (request, coordinate, window) = request.into_inner();
        let (desired, admission, _provenance) = request.into_parts();
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, admission.binding())?;
        state.validate_group(&desired)?;
        if !window.is_current()
            || !admission.validates(&desired)
            || !admission.authorizes_install_effect()
        {
            return Err(unavailable());
        }
        if let Some(parent) = admission.bearer_parent() {
            state.exact_active(parent)?;
        }
        let key = desired.id().to_bytes();
        let authority = SelectorOperationStampAuthority::from(&admission);
        let outcome = if state.records.contains_key(&key) {
            let record = state.exact_active(&desired)?;
            if !state
                .stamp(&desired)?
                .is_exact_terminal_active(authority, record.generation())
            {
                return Err(unavailable());
            }
            GtpuSessionGroupReconcileOutcome::ExactAlreadyActive
        } else {
            if state.stamps.contains_key(&key) || !state.indexes_for(key)?.is_empty() {
                return Err(unavailable());
            }
            let record = grouped_record_from_model(&desired, GtpuSessionGeneration::INITIAL)
                .ok_or_else(unavailable)?;
            let indexes = grouped_active_indexes(record).ok_or_else(unavailable)?;
            if indexes
                .iter()
                .any(|index| state.indexes.contains_key(&index.key))
            {
                return Err(unavailable());
            }
            if !window.is_current() {
                return Err(unavailable());
            }
            for index in indexes {
                state.indexes.insert(index.key, index.value);
            }
            state.records.insert(key, record.encode());
            state.stamps.insert(
                key,
                SelectorOperationStamp::terminal_active(authority, record.generation()).encode(),
            );
            state.exact_active(&desired)?;
            GtpuSessionGroupReconcileOutcome::Activated
        };
        if !window.is_current() {
            return Err(unavailable());
        }
        Ok(GtpuSessionSelectorBackendReceipt::effect(
            coordinate,
            outcome,
            window.into_receipt(),
        ))
    }

    async fn read_pdp_context_group_with_lease(
        &self,
        request: GtpuSessionSelectorReadbackRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, request.binding())?;
        if !request.is_current() {
            return Err(unavailable());
        }
        let readback = state.read_authorized(request.expected_group(), request.admission())?;
        if !request.is_current() {
            return Err(unavailable());
        }
        if readback == GtpuSessionGroupReadback::Absent {
            let stamp = state.stamp(request.expected_group())?.encode();
            request
                .complete_terminal_retired(readback, &stamp)
                .ok_or_else(unavailable)
        } else {
            Ok(request.complete(readback))
        }
    }

    async fn remove_pdp_context_group_with_lease(
        &self,
        request: GtpuSessionSelectorRemovalRequest,
    ) -> Result<GtpuSessionSelectorBackendReceipt, GtpuError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, request.binding())?;
        if !request.is_current() || !request.admission().authorizes_retirement_effect() {
            return Err(unavailable());
        }
        let expected = request.expected_group();
        let readback = state.read_authorized(expected, request.admission())?;
        let outcome = if matches!(readback, GtpuSessionGroupReadback::Active(_)) {
            let record = state.exact_active(expected)?;
            let indexes = grouped_active_indexes(record).ok_or_else(unavailable)?;
            let key = expected.id().to_bytes();
            let stamp = SelectorOperationStamp::terminal_retired(
                SelectorOperationStampAuthority::from(request.admission()),
                record.generation(),
            )
            .encode();
            if !request.is_current() {
                return Err(unavailable());
            }
            for index in indexes {
                state.indexes.remove(&index.key);
            }
            state.records.remove(&key);
            state.stamps.insert(key, stamp);
            GtpuSessionGroupRemovalOutcome::Removed
        } else {
            GtpuSessionGroupRemovalOutcome::AlreadyAbsent
        };
        if !request.is_current() {
            return Err(unavailable());
        }
        let stamp = state.stamp(request.expected_group())?.encode();
        request
            .complete_terminal_retired(outcome, &stamp)
            .ok_or_else(unavailable)
    }

    async fn authorize_selector_reuse(
        &self,
        request: GtpuSessionSelectorReuseRequest,
    ) -> Result<GtpuSessionSelectorReuseReceipt, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        self.qualify_binding(&state, request.binding())?;
        let retired = request.retired_group();
        if !request.is_current()
            || state.records.contains_key(&retired.id().to_bytes())
            || !state.indexes_for(retired.id().to_bytes())?.is_empty()
            || !request.verifies_exact_terminal_retired_stamp(&state.stamp(retired)?.encode())
        {
            return Err(unavailable());
        }
        // There are no packet producers/readers in this isolated simulation;
        // the same lock owns the terminal stamp and all virtual selectors.
        Ok(request.confirm_traffic_drained())
    }

    fn tft_uplink_classification_capability(&self) -> GtpuCapability {
        GtpuCapability::Available
    }

    fn validate_tft_uplink_classifier(
        &self,
        desired: &TftUplinkClassifier,
    ) -> Result<(), GtpuError> {
        self.qualify_tft_attachment(desired.link_ifindex(), false)?;
        EbpfGtpuDataplaneBackend::validate_tft_uplink_classifier_native(desired)
    }

    async fn read_tft_uplink_classifier(
        &self,
        link_ifindex: u32,
        paa: IpAddr,
    ) -> Result<TftUplinkClassifierReadback, GtpuError> {
        self.qualify_tft_attachment(link_ifindex, false)?;
        self.tft.read_tft_uplink_classifier(link_ifindex, paa).await
    }

    async fn reconcile_tft_uplink_classifier(
        &self,
        desired: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierReconcileOutcome, GtpuError> {
        self.validate_tft_uplink_classifier(&desired)?;
        self.qualify_tft_attachment(desired.link_ifindex(), true)?;
        self.tft.reconcile_tft_uplink_classifier(desired).await
    }

    async fn remove_tft_uplink_classifier_exact(
        &self,
        expected: TftUplinkClassifier,
    ) -> Result<TftUplinkClassifierRemovalOutcome, GtpuError> {
        self.qualify_tft_attachment(expected.link_ifindex(), true)?;
        self.tft.remove_tft_uplink_classifier_exact(expected).await
    }

    async fn gtpu_ip_family_capabilities(
        &self,
        attachment: GtpuSessionAttachmentSelector,
    ) -> Result<GtpuIpFamilyCapabilities, GtpuError> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        if state.attachment.as_ref() != Some(&attachment) {
            return Err(unavailable());
        }
        Ok(GtpuIpFamilyCapabilities {
            inner_ipv4: GtpuCapability::Available,
            inner_ipv6: GtpuCapability::Available,
            outer_ipv4: GtpuCapability::Available,
            outer_ipv6: GtpuCapability::Available,
            grouped_atomic_reconciliation: GtpuCapability::Available,
            local_endpoint_sets: GtpuCapability::Available,
            ..GtpuIpFamilyCapabilities::unsupported()
        })
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        Ok(GtpuProbe {
            per_bearer_marking: GtpuCapability::Available,
            downlink_endpoint_binding: GtpuCapability::Available,
            uplink_source_port_selection: GtpuCapability::Available,
            egress_dscp_marking: GtpuCapability::Available,
            details: Some("grouped structural simulation; no kernel or traffic proof"),
            ..GtpuProbe::mock()
        })
    }
}
