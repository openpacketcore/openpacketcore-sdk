//! Bounded live marked-bearer composition; the parent's PAA never changes owner.

use super::*;

/// Maximum live or unresolved marked children of one exact IPv4 default group.
pub const GTPU_SHARED_PAA_MAX_LIVE_BEARERS: usize = 1;

impl<B> GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    /// Add one marked IPv4 bearer under the current exact unmarked default.
    ///
    /// The affine parent claim must be current in this protected namespace.
    /// Both groups have one IPv4 entry, the same PAA, exact local and peer
    /// endpoints, link and protocol version, and distinct local TEIDs. The
    /// parent record and all unrelated groups remain unchanged. Only the
    /// recorded parent's PAA is shared; TEID and full-mask mark ownership is
    /// exclusive. At most [`GTPU_SHARED_PAA_MAX_LIVE_BEARERS`] child may be live
    /// or unresolved. A retired group ID is never usable again.
    ///
    /// Recover the parent's claim with [`Self::recover_active`] when needed.
    /// Remove the child with [`Self::retire`]; parent retirement is barred
    /// until all children are exactly retired. Cancellation detaches observation
    /// only: use the existing exact status recovery methods, never replay a
    /// possible effect. Ambiguous child effects retain their permanent debt.
    ///
    /// Child effects invalidate existing parent traffic attempts before map
    /// mutation. Structural success is not traffic evidence: the caller must
    /// rebind its canonical traffic authority after the complete application
    /// transition and obtain fresh traffic proof.
    pub fn reconcile_bearer<D>(
        &self,
        backend: Arc<D>,
        parent_claim: GtpuSessionSelectorActiveClaim,
        parent: GtpuSessionGroup,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        spawn_selector_operation(
            self.storage_scope_commitment,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .reconcile_bearer_owned(backend.as_ref(), parent_claim, parent, desired)
                    .await
            },
        )
    }

    async fn reconcile_bearer_owned<D>(
        &self,
        backend: &D,
        parent_claim: GtpuSessionSelectorActiveClaim,
        parent: GtpuSessionGroup,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.ensure_backend_namespace(backend, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let (_, state) = self
                .read_state()
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            state
                .preflight_bearer_parent(&parent, &parent_claim.0, &desired)
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let admission = self
                .active_admission(&parent)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            self.require_exact_active(backend, parent.clone(), admission, &mut lease)
                .await?;
            let reuse = match state.single_bearer_reattach_source(&desired) {
                Some(source) => {
                    let source_claim = CanonicalClaim::from_group(&source)
                        .with_key(&state.selector_digest_key)
                        .ok_or(GtpuSessionSelectorCoordinatorError::Namespace)?;
                    if state.bearer_parents.get(&source_claim.group_fingerprint)
                        != Some(&parent_claim.0.group_fingerprint)
                    {
                        return Err(GtpuSessionSelectorCoordinatorError::Namespace);
                    }
                    let proof = self
                        .qualify_bearer_reuse(backend, &desired, source, &mut lease)
                        .await?;
                    self.claim_reused_bearer_with_lease(
                        backend,
                        &desired,
                        &proof,
                        Some((&parent, &parent_claim.0)),
                        &mut lease,
                    )
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                    Some(proof)
                }
                None => {
                    self.claim_fresh_bearer_with_lease(
                        backend,
                        &desired,
                        Some((&parent, &parent_claim.0)),
                        &mut lease,
                    )
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                    None
                }
            };
            match self
                .mark_install_backend_started_with_lease(&desired, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?
            {
                BackendStartHandoff::Transitioned(admission) => {
                    self.effect_and_activate_with_lease(
                        backend, desired, admission, reuse, &mut lease,
                    )
                    .await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_install_after_competing_start(
                        backend, desired, admission, &mut lease,
                    )
                    .await
                }
            }
        }
        .await;
        self.finish_worker_operation(lease, result).await
    }

    async fn qualify_bearer_reuse<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
        source: GtpuSessionGroup,
        lease: &mut SelectorWorkerLease,
    ) -> Result<crate::GtpuSessionSelectorReuseProof, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let admission = self
            .retired_admission(&source)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let receipt = settle_selector_backend_step(backend.authorize_selector_reuse(
            GtpuSessionSelectorReuseRequest {
                retired: GtpuSessionSelectorRetiredClaim {
                    group: source,
                    admission,
                },
                desired: desired.clone(),
                window,
            },
        ))
        .await
        .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        let GtpuSessionSelectorReuseReceipt {
            retired,
            desired: received,
            evidence,
            window,
        } = receipt;
        if !window.is_current()
            || received != *desired
            || !retired.admission.validates(&retired.group)
            || retired.admission.phase != SelectorAdmissionPhase::Retired
        {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let proof = match evidence {
            crate::GtpuSessionSelectorReuseEvidence::TrafficDrained => {
                crate::GtpuSessionSelectorReuseProof::after_traffic_drain(retired.group)
            }
            crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed => {
                crate::GtpuSessionSelectorReuseProof::after_rcu_grace_period(retired.group)
            }
        };
        Ok(proof.for_single_bearer_reattach())
    }
}

fn shared_paa_bearer_is_exact(parent: &GtpuSessionGroup, child: &GtpuSessionGroup) -> bool {
    let ([default], [bearer]) = (parent.entries(), child.entries()) else {
        return false;
    };
    let old = default.context();
    let new = bearer.context();
    parent.device_id() == child.device_id()
        && parent.id() != child.id()
        && default.inner_family() == GtpAddressFamily::Ipv4
        && bearer.inner_family() == GtpAddressFamily::Ipv4
        && default.inner_paa() == bearer.inner_paa()
        && default.local_outer_address() == bearer.local_outer_address()
        && old.peer_address == new.peer_address
        && old.link_ifindex == new.link_ifindex
        && old.gtp_version == new.gtp_version
        && old.bearer_mark.is_none()
        && new.bearer_mark.is_some()
        && old.local_teid != new.local_teid
}

impl NamespaceState {
    pub(super) fn preflight_bearer_parent(
        &self,
        parent: &GtpuSessionGroup,
        admission: &GtpuSessionSelectorAdmission,
        desired: &GtpuSessionGroup,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if !shared_paa_bearer_is_exact(parent, desired)
            || admission.phase != SelectorAdmissionPhase::Active
            || !admission.validates(parent)
            || admission.binding != self.binding_with_scope(self.storage_scope_commitment)?
            || self
                .bearer_parents
                .contains_key(&admission.group_fingerprint)
            || !matches!(self.groups.get(&admission.group_fingerprint),
                Some(GroupState::Active { device, selectors, desired, generation, operation_nonce, .. })
                    if *device == admission.device_fingerprint
                        && *selectors == admission.selector_set_fingerprint
                        && *desired == admission.desired_fingerprint
                        && *generation == admission.generation
                        && *operation_nonce == admission.operation_nonce)
            || self.unresolved_bearer_count(admission.group_fingerprint)
                >= GTPU_SHARED_PAA_MAX_LIVE_BEARERS
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        Ok(())
    }

    pub(super) fn unresolved_bearer_count(&self, parent: [u8; 32]) -> usize {
        self.bearer_parents
            .iter()
            .filter(|(child, owner)| {
                **owner == parent
                    && !matches!(self.groups.get(*child), Some(GroupState::Retired { .. }))
            })
            .count()
    }

    /// Keep the RFC016 atoms and complete selector-set fingerprint unchanged.
    /// Only a persisted exact parent relation delegates the PAA reservation.
    pub(super) fn owned_selector_atoms(
        &self,
        claim: &CanonicalClaim,
    ) -> Option<BTreeSet<[u8; 32]>> {
        self.selector_atoms_under_parent(
            claim,
            self.bearer_parents.get(&claim.group_fingerprint).copied(),
        )
    }

    pub(super) fn selector_atoms_under_parent(
        &self,
        claim: &CanonicalClaim,
        parent: Option<[u8; 32]>,
    ) -> Option<BTreeSet<[u8; 32]>> {
        let Some(parent) = parent else {
            return claim.selector_atoms(&self.selector_digest_key);
        };
        let parent = self.canonical_group_for(parent)?;
        let child = decode_canonical_desired(&claim.desired)?;
        if !shared_paa_bearer_is_exact(&parent, &child) {
            return None;
        }
        Some(
            claim
                .atoms
                .iter()
                .filter(|atom| atom.first() != Some(&b'P'))
                .map(|atom| keyed_digest(&self.selector_digest_key, ATOM_DOMAIN, atom))
                .collect(),
        )
    }

    pub(super) fn bearer_relations_are_exact(&self) -> bool {
        self.bearer_parents.len() <= MAX_PERMANENT_GROUPS
            && self.bearer_parents.iter().all(|(child, parent)| {
                if child == parent || self.bearer_parents.contains_key(parent) {
                    return false;
                }
                let (Some(parent_group), Some(child_group)) = (
                    self.canonical_group_for(*parent),
                    self.canonical_group_for(*child),
                ) else {
                    return false;
                };
                if !shared_paa_bearer_is_exact(&parent_group, &child_group)
                    || self.unresolved_bearer_count(*parent) > GTPU_SHARED_PAA_MAX_LIVE_BEARERS
                {
                    return false;
                }
                matches!(self.groups.get(child), Some(GroupState::Retired { .. }))
                    || matches!(
                        self.groups.get(parent),
                        Some(GroupState::Active { .. } | GroupState::Poisoned(_))
                    )
            })
    }
}
