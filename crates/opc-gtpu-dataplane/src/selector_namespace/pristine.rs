//! Explicit relocation of a namespace with positive, permanent proof that no
//! group has ever acquired authority. This cannot restore a used namespace.

use super::*;

const PREDECESSOR_DOMAIN: &[u8] = b"opc/gtpu-selector/pristine-predecessor/v1\0";
const LINEAGE_DOMAIN: &[u8] = b"opc/gtpu-selector/pristine-lineage/v1\0";

/// Affine readback of a binding whose complete permanent ledger proves no
/// group admission and an exact precommitted relocation. Ordinary callers
/// cannot construct this request or use its receipt as a provisioning receipt.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::GtpuSessionSelectorPristineReadbackRequest;
/// let forged = GtpuSessionSelectorPristineReadbackRequest {};
/// ```
#[must_use = "a pristine binding readback must be consumed into its exact receipt"]
pub struct GtpuSessionSelectorPristineReadbackRequest {
    binding: GtpuSessionSelectorBackendBinding,
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorPristineReadbackRequest {
    /// Exact backend namespace binding authorized for inspection.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_binding_window(
            SelectorBackendRequestKind::PristineReadback,
            self.binding,
            &self.window,
        )
    }

    /// Confirm only after an exact binding, no terminal fence, and the
    /// complete empty authority-map inventory have been read under the
    /// backend's current host lock, with exact graph identity and currentness
    /// checked before releasing the lock. This permits no backend mutation.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt {
            coordinate: self.receipt_coordinate(),
            kind: SelectorBackendReceiptKind::PristineReadback,
            window: self.window.into_receipt(),
        }
    }
}

impl fmt::Debug for GtpuSessionSelectorPristineReadbackRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorPristineReadbackRequest(<redacted>)")
    }
}

#[derive(Clone)]
pub(super) struct PristineRelocation {
    predecessor_commitment: [u8; 32],
    predecessor_pin: [u8; 32],
    predecessor_epoch: [u8; 16],
    successor_pin: [u8; 32],
    successor_epoch: [u8; 16],
}

impl PristineRelocation {
    const ENCODED_BYTES: usize = 128;

    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.predecessor_commitment);
        output.extend_from_slice(&self.predecessor_pin);
        output.extend_from_slice(&self.predecessor_epoch);
        output.extend_from_slice(&self.successor_pin);
        output.extend_from_slice(&self.successor_epoch);
    }

    fn commitment(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(Self::ENCODED_BYTES);
        self.encode(&mut bytes);
        let mut hash = Sha256::new();
        hash.update(LINEAGE_DOMAIN);
        hash.update(bytes);
        hash.finalize().into()
    }
}

impl<B: SessionBackend + SessionLeaseManager> GtpuSessionSelectorNamespaceAuthority<B> {
    pub(super) async fn read_pristine_binding<D>(
        &self,
        backend: &D,
        state: &NamespaceState,
        lease: &mut SelectorWorkerLease,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        if state.lifecycle != NamespaceLifecycle::Initializing
            || !state.is_complete()
            || !state.never_admitted()
            || state.pristine_relocations.is_empty()
            || state.stable_device != Some(self.stable_device.to_bytes())
            || state.storage_scope_commitment != self.storage_scope_commitment
            || state.pin_commitment != self.pin_commitment
            || state.capacity != self.maximum_operation_atoms as u32
        {
            return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
        }
        let request = GtpuSessionSelectorPristineReadbackRequest {
            binding: state.binding_with_scope(self.storage_scope_commitment)?,
            window: self.mint_backend_mutation_window(lease).await?,
        };
        let expected = request.receipt_coordinate();
        let receipt =
            settle_selector_backend_step(backend.read_pristine_selector_namespace(request))
                .await
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if !receipt.window.is_current()
            || !receipt.coordinate.matches(expected)
            || !matches!(receipt.kind, SelectorBackendReceiptKind::PristineReadback)
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        Ok(())
    }

    /// Relocate a protected namespace that has never admitted any group.
    ///
    /// This separate operation requires positive permanent-ledger proof of no
    /// prior admission, under the exclusive fenced worker lease. An empty
    /// replacement backend, missing marker, or new owner alone is insufficient.
    /// Active, retired, unadmitted, poisoned and decommissioned history is refused.
    /// The same protected ledger, device and selector secret are retained;
    /// a versioned precommit binds exactly one predecessor and replacement.
    /// Cancellation may resume only that precommitted replacement. Ordinary
    /// open and provisioning retain their exact-binding behavior.
    ///
    /// This does not recover a namespace that has ever carried traffic and
    /// supplies no predecessor-kernel retirement or packet-continuity proof.
    pub fn relocate_never_admitted_protected<D>(
        store: SessionStore<B>,
        scope: SelectorLedgerStorageScope,
        bootstrap: GtpuSelectorNamespaceBootstrap,
        backend: Arc<D>,
        owner: OwnerId,
        lease_ttl: Duration,
        maximum_atoms: usize,
    ) -> GtpuSessionSelectorOperation<Self, GtpuSessionSelectorNamespaceError>
    where
        B: ProtectedSessionBackend + Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        if lease_ttl != SELECTOR_NAMESPACE_MAX_LEASE_TTL {
            return spawn_selector_operation(
                [0; 32],
                GtpuSessionSelectorNamespaceError::UnsuitableStore,
                async { Err(GtpuSessionSelectorNamespaceError::UnsuitableStore) },
            );
        }
        let Some(base) = store.protected_selector_ledger_base(&scope) else {
            return spawn_selector_operation(
                [0; 32],
                GtpuSessionSelectorNamespaceError::UnsuitableStore,
                async { Err(GtpuSessionSelectorNamespaceError::UnsuitableStore) },
            );
        };
        let derivation = match derive_protected_selector_ledger(base, bootstrap) {
            Ok(derivation) => derivation,
            Err(error) => {
                return spawn_selector_operation([0; 32], error, async move { Err(error) });
            }
        };
        let scope_commitment = derivation.storage_scope_commitment;
        let backend_scope = NamespaceBackendScope::from(&derivation);
        spawn_selector_operation(
            scope_commitment,
            GtpuSessionSelectorNamespaceError::Indeterminate,
            async move {
                let authority = Self::open_with_backend_scope(
                    store,
                    derivation.namespace_key,
                    owner,
                    lease_ttl,
                    maximum_atoms,
                    backend_scope,
                )
                .await?;
                let mut lease = authority.acquire_worker_lease().await?;
                let result = authority
                    .relocate_pristine_with_lease(backend.as_ref(), &mut lease)
                    .await;
                let released = authority.release_worker_lease(lease).await;
                result?;
                released?;
                Ok(authority)
            },
        )
    }

    pub(super) async fn relocate_pristine_with_lease<D>(
        &self,
        backend: &D,
        lease: &mut SelectorWorkerLease,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        for _ in 0..MAX_CAS_RETRIES {
            // Absence is deliberately refused. Only the existing, complete
            // permanent record can supply positive historical no-effect proof.
            let (record, mut state) = self.read_state_for_provision().await?;
            let record = record.ok_or(GtpuSessionSelectorNamespaceError::Unprovisioned)?;
            if !state.never_admitted()
                || state.stable_device != Some(self.stable_device.to_bytes())
                || state.storage_scope_commitment != self.storage_scope_commitment
                || state.capacity != self.maximum_operation_atoms as u32
            {
                return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
            }
            match state.lifecycle {
                NamespaceLifecycle::Bound if state.pin_commitment != self.pin_commitment => {
                    state.precommit_pristine_relocation(self.pin_commitment)?;
                    // No backend call may precede this fenced CAS/readback.
                    // A stale predecessor paused before admission cannot CAS
                    // through the lease or exact-generation check afterward.
                    self.replace_with_lease(Some(&record), state, lease).await?;
                }
                NamespaceLifecycle::Initializing
                    if !state.pristine_relocations.is_empty()
                        && state.pin_commitment == self.pin_commitment =>
                {
                    if self
                        .complete_initializing_binding(backend, Some(&record), state, lease)
                        .await?
                    {
                        return Ok(());
                    }
                }
                NamespaceLifecycle::Bound
                    if !state.pristine_relocations.is_empty()
                        && state.pin_commitment == self.pin_commitment =>
                {
                    self.bound_binding(&state)?;
                    self.ensure_backend_namespace(backend, lease).await?;
                    return Ok(());
                }
                _ => return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch),
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }
}

impl NamespaceState {
    fn never_admitted(&self) -> bool {
        self.generation == 0
            && self.decommission_fence.is_none()
            && self.selectors.is_empty()
            && self.groups.is_empty()
            && self.unadmitted_groups.is_empty()
            && self.reattach_sources.is_empty()
            && self.bearer_parents.is_empty()
            && self.canonical_desired.is_empty()
            && self.published_atoms.is_empty()
            && self.tombstones.is_empty()
    }

    /// Canonical commitment to the complete semantic pristine predecessor:
    /// immutable header, Bound/generation-zero/no-admission predicate, and
    /// the ordered permanent lineage. The length and previous tip commit all
    /// prior rows without quadratic re-encoding during every ledger read.
    fn pristine_predecessor_commitment(
        &self,
        pin: [u8; 32],
        epoch: [u8; 16],
        history_length: u32,
        history_tip: [u8; 32],
    ) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(&self.stable_device.unwrap_or([0; 16]));
        input.extend_from_slice(&self.storage_scope_commitment);
        input.extend_from_slice(&self.ledger_id);
        input.extend_from_slice(&self.capacity.to_be_bytes());
        input.extend_from_slice(&pin);
        input.extend_from_slice(&epoch);
        input.extend_from_slice(&history_length.to_be_bytes());
        input.extend_from_slice(&history_tip);
        keyed_digest(&self.selector_digest_key, PREDECESSOR_DOMAIN, &input)
    }

    fn precommit_pristine_relocation(
        &mut self,
        successor_pin: [u8; 32],
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if self.lifecycle != NamespaceLifecycle::Bound
            || !self.is_complete()
            || !self.never_admitted()
            || successor_pin == [0; 32]
            || successor_pin == self.pin_commitment
            || self.pristine_relocations.iter().any(|row| {
                row.predecessor_pin == successor_pin || row.successor_pin == successor_pin
            })
        {
            return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
        }
        // First promotion adds four explicit optional-section counts. Later
        // records retain those counts even while each admission roster is empty.
        let additional = PristineRelocation::ENCODED_BYTES
            + if self.pristine_relocations.is_empty() {
                16
            } else {
                0
            };
        self.preflight_encoded_growth(additional)?;
        let mut successor_epoch = [0; 16];
        SysRng
            .try_fill_bytes(&mut successor_epoch)
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if successor_epoch == [0; 16]
            || successor_epoch == self.backend_epoch
            || self.pristine_relocations.iter().any(|row| {
                row.predecessor_epoch == successor_epoch || row.successor_epoch == successor_epoch
            })
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let history_tip = self
            .pristine_relocations
            .last()
            .map_or([0; 32], PristineRelocation::commitment);
        let predecessor_commitment = self.pristine_predecessor_commitment(
            self.pin_commitment,
            self.backend_epoch,
            self.pristine_relocations.len() as u32,
            history_tip,
        );
        self.pristine_relocations.push(PristineRelocation {
            predecessor_commitment,
            predecessor_pin: self.pin_commitment,
            predecessor_epoch: self.backend_epoch,
            successor_pin,
            successor_epoch,
        });
        self.pin_commitment = successor_pin;
        self.backend_epoch = successor_epoch;
        self.key_commitment = key_commitment(
            &self.selector_digest_key,
            &self.ledger_id,
            &self.pin_commitment,
            &self.stable_device.unwrap_or([0; 16]),
            &self.storage_scope_commitment,
        );
        self.lifecycle = NamespaceLifecycle::Initializing;
        Ok(())
    }

    pub(super) fn pristine_lineage_is_exact(&self) -> bool {
        let Some(first) = self.pristine_relocations.first() else {
            return true;
        };
        if matches!(
            self.lifecycle,
            NamespaceLifecycle::Unprovisioned | NamespaceLifecycle::Provisioned
        ) || (self.lifecycle == NamespaceLifecycle::Initializing && !self.never_admitted())
            || self.pristine_relocations.len()
                > MAX_RECORD_BYTES / PristineRelocation::ENCODED_BYTES
        {
            return false;
        }
        let mut pin = first.predecessor_pin;
        let mut epoch = first.predecessor_epoch;
        if pin == [0; 32] || epoch == [0; 16] {
            return false;
        }
        let mut pins = BTreeSet::from([pin]);
        let mut epochs = BTreeSet::from([epoch]);
        let mut tip = [0; 32];
        for (index, row) in self.pristine_relocations.iter().enumerate() {
            if row.predecessor_pin != pin
                || row.predecessor_epoch != epoch
                || row.successor_pin == [0; 32]
                || row.successor_epoch == [0; 16]
                || !pins.insert(row.successor_pin)
                || !epochs.insert(row.successor_epoch)
                || row.predecessor_commitment
                    != self.pristine_predecessor_commitment(pin, epoch, index as u32, tip)
            {
                return false;
            }
            pin = row.successor_pin;
            epoch = row.successor_epoch;
            tip = row.commitment();
        }
        self.pin_commitment == pin && self.backend_epoch == epoch
    }

    pub(super) fn encode_pristine_relocations(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&(self.pristine_relocations.len() as u32).to_be_bytes());
        for row in &self.pristine_relocations {
            row.encode(output);
        }
    }

    pub(super) fn decode_pristine_relocations(
        bytes: &[u8],
        cursor: &mut usize,
    ) -> Option<Vec<PristineRelocation>> {
        let count = u32::from_be_bytes(take_array(take(bytes, cursor, 4)?)?) as usize;
        if count == 0 || count > MAX_RECORD_BYTES / PristineRelocation::ENCODED_BYTES {
            return None;
        }
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            rows.push(PristineRelocation {
                predecessor_commitment: take_array(take(bytes, cursor, 32)?)?,
                predecessor_pin: take_array(take(bytes, cursor, 32)?)?,
                predecessor_epoch: take_array(take(bytes, cursor, 16)?)?,
                successor_pin: take_array(take(bytes, cursor, 32)?)?,
                successor_epoch: take_array(take(bytes, cursor, 16)?)?,
            });
        }
        Some(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_pristine() -> NamespaceState {
        let mut state = NamespaceState::provisioned(
            GtpuSessionDeviceId::new([1; 16]).unwrap(),
            [2; 32],
            [3; 32],
        );
        state.initialize(32).unwrap();
        state.lifecycle = NamespaceLifecycle::Bound;
        assert!(state.is_complete());
        state
    }

    #[test]
    fn pristine_namespace_relocation_codec_preserves_secret_and_permanent_chain() {
        let original = bound_pristine();
        assert_eq!(&original.encode()[..7], b"OPCSN15");
        let mut state = original.clone();
        for (index, pin) in [[4; 32], [5; 32], [6; 32]].into_iter().enumerate() {
            state.precommit_pristine_relocation(pin).unwrap();
            assert!(state.is_complete());
            assert_eq!(&state.encode()[..7], b"OPCSN19");
            assert_eq!(state.pristine_relocations.len(), index + 1);
            assert_eq!(state.ledger_id, original.ledger_id);
            assert_eq!(*state.selector_digest_key, *original.selector_digest_key);
            assert_eq!(state.generation, 0);
            let encoded = state.encode();
            state = NamespaceState::decode(&encoded).unwrap();
            assert_eq!(state.encode(), encoded);
            // Only the coordinator's backend receipt may make this transition
            // in production; here the codec is exercised in both phases.
            state.lifecycle = NamespaceLifecycle::Bound;
            assert!(state.is_complete());
        }
        for prior in [[2; 32], [4; 32], [5; 32], [6; 32]] {
            let before = state.encode();
            assert_eq!(
                state.precommit_pristine_relocation(prior),
                Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
            );
            assert_eq!(state.encode(), before);
        }
    }

    #[test]
    fn pristine_namespace_relocation_codec_refuses_truncation_downgrade_and_rebinding() {
        let mut state = bound_pristine();
        state.precommit_pristine_relocation([4; 32]).unwrap();
        state.lifecycle = NamespaceLifecycle::Bound;
        state.precommit_pristine_relocation([5; 32]).unwrap();
        let encoded = state.encode();
        for end in 0..encoded.len() {
            assert!(
                NamespaceState::decode(&encoded[..end]).is_none(),
                "truncation={end}"
            );
        }
        for version in [b"OPCSN15", b"OPCSN16", b"OPCSN17", b"OPCSN18"] {
            let mut changed = encoded.clone();
            changed[..7].copy_from_slice(version);
            assert!(NamespaceState::decode(&changed).is_none());
        }
        // Every retained coordinate is authenticated as part of the ordered
        // chain. A changed old coordinate cannot turn another owner into a
        // predecessor or redirect an interrupted successor.
        for offset in (encoded.len() - 2 * PristineRelocation::ENCODED_BYTES)..encoded.len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                NamespaceState::decode(&changed).is_none(),
                "lineage byte={offset}"
            );
        }
        for field in 0..6 {
            let mut changed = state.clone();
            match field {
                0 => changed.ledger_id[0] ^= 1,
                1 => changed.storage_scope_commitment[0] ^= 1,
                2 => changed.capacity += 1,
                3 => changed.stable_device = Some([9; 16]),
                4 => changed.selector_digest_key[0] ^= 1,
                5 => changed.generation = 1,
                _ => unreachable!(),
            }
            // Recomputing the public binding alone cannot counterfeit the
            // pristine predecessor proof under the retained selector secret.
            changed.key_commitment = key_commitment(
                &changed.selector_digest_key,
                &changed.ledger_id,
                &changed.pin_commitment,
                &changed.stable_device.unwrap(),
                &changed.storage_scope_commitment,
            );
            assert!(
                NamespaceState::decode(&changed.encode()).is_none(),
                "field={field}"
            );
        }
    }

    #[test]
    fn pristine_namespace_relocation_generation_history_is_not_empty_map_proof() {
        let mut state = bound_pristine();
        state.generation = 1;
        assert!(state.is_complete());
        let before = state.encode();
        assert_eq!(
            state.precommit_pristine_relocation([4; 32]),
            Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
        );
        assert_eq!(state.encode(), before);
    }

    #[test]
    fn pristine_namespace_relocation_readback_receipt_cannot_replace_provision_receipt() {
        let state = bound_pristine();
        let binding = state
            .binding_with_scope(state.storage_scope_commitment)
            .unwrap();
        let readback = GtpuSessionSelectorPristineReadbackRequest {
            binding,
            window: SelectorBackendMutationWindow::mint(SELECTOR_NAMESPACE_MAX_EFFECT_DURATION)
                .unwrap(),
        };
        let expected_readback = readback.receipt_coordinate();
        let provision = GtpuSessionSelectorProvisionRequest {
            binding,
            window: SelectorBackendMutationWindow::mint(SELECTOR_NAMESPACE_MAX_EFFECT_DURATION)
                .unwrap(),
        };
        let expected_provision = provision.receipt_coordinate();
        let receipt = readback.confirm();
        assert!(receipt.coordinate.matches(expected_readback));
        assert!(!receipt.confirms_provisioning(expected_provision));
        assert!(!provision.confirm().coordinate.matches(expected_readback));
    }
}
