use super::*;

/// Lease transition failure.
///
/// Once acquisition has returned a guard, every synchronous failure retains
/// that guard so callers cannot accidentally release or replace uncertain
/// authority. Dropping an in-flight future abandons the guard until durable
/// expiry while the socket wrapper synchronously retires the local capability.
pub enum LeaseFenceError<E> {
    /// Durable authority acquisition failed before any guard was returned.
    Authority(E),
    /// Local validation failed before any guard was returned.
    Fence(FenceError),
    /// A durable authority operation failed after a guard was returned.
    AuthorityWithLease {
        /// Authority-specific failure, never formatted by this crate.
        error: E,
        /// Exact unreleased guard that must remain fenced until resolved.
        lease: LeaseGuard,
    },
    /// Local validation failed after a guard was returned.
    FenceWithLease {
        /// Value-free local failure.
        error: FenceError,
        /// Exact unreleased guard that must remain fenced until resolved.
        lease: LeaseGuard,
    },
}

impl<E> LeaseFenceError<E> {
    /// Recover a pre-grant authority error without discarding a post-grant
    /// lease.
    pub fn into_authority_error(self) -> Result<E, Self> {
        match self {
            Self::Authority(error) => Ok(error),
            other => Err(other),
        }
    }

    /// Recover the exact unreleased guard from a post-grant failure.
    pub fn into_unreleased_lease(self) -> Option<LeaseGuard> {
        match self {
            Self::Authority(_) | Self::Fence(_) => None,
            Self::AuthorityWithLease { lease, .. } | Self::FenceWithLease { lease, .. } => {
                Some(lease)
            }
        }
    }

    /// Return the value-free fence error when present.
    #[must_use]
    pub const fn fence_error(&self) -> Option<FenceError> {
        match self {
            Self::Authority(_) | Self::AuthorityWithLease { .. } => None,
            Self::Fence(error) | Self::FenceWithLease { error, .. } => Some(*error),
        }
    }
}

impl<E> fmt::Debug for LeaseFenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(_) => formatter.write_str("LeaseFenceError::Authority(<redacted>)"),
            Self::Fence(error) => formatter
                .debug_tuple("LeaseFenceError::Fence")
                .field(error)
                .finish(),
            Self::AuthorityWithLease { .. } => {
                formatter.write_str("LeaseFenceError::AuthorityWithLease(<redacted>)")
            }
            Self::FenceWithLease { error, .. } => formatter
                .debug_struct("LeaseFenceError::FenceWithLease")
                .field("error", error)
                .field("lease", &"<redacted>")
                .finish(),
        }
    }
}

impl<E> fmt::Display for LeaseFenceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(_) | Self::AuthorityWithLease { .. } => {
                formatter.write_str("egress_fence_authority_operation")
            }
            Self::Fence(error) | Self::FenceWithLease { error, .. } => {
                fmt::Display::fmt(error, formatter)
            }
        }
    }
}

impl<E> std::error::Error for LeaseFenceError<E> where E: Send + Sync + 'static {}

#[derive(Clone, PartialEq, Eq)]
struct LeaseBinding {
    key: SessionKey,
    owner: OwnerId,
    lease_fence_token: u64,
    socket_lifecycle_token: NonZeroU64,
    retirement_lifecycle_token: NonZeroU64,
    credential_id: u64,
}

impl LeaseBinding {
    fn from_guard(
        guard: &LeaseGuard,
        socket_lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
    ) -> Self {
        Self {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            lease_fence_token: guard.fence().get(),
            socket_lifecycle_token,
            retirement_lifecycle_token,
            credential_id: guard.credential_id(),
        }
    }

    fn matches(&self, guard: &LeaseGuard) -> bool {
        self.key == *guard.key()
            && self.owner == *guard.owner()
            && self.lease_fence_token == guard.fence().get()
            && self.credential_id == guard.credential_id()
    }
}

impl fmt::Debug for LeaseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LeaseBinding(<redacted>)")
    }
}

enum ActivationPath {
    Immediate,
    Delayed(Duration),
}

/// One socket's lease-bound kernel gate.
///
/// Entries are keyed by the exact `(SO_COOKIE, socket_lifecycle_token)` tuple,
/// so a delayed reclaim for an earlier lifecycle cannot delete a later
/// lifecycle that received the same numeric cookie.
pub(crate) struct LeaseBoundFence {
    kernel: Arc<dyn KernelControl>,
    clock: Arc<dyn BootClock>,
    identity: AttachmentIdentity,
    socket_cookie: u64,
    socket_lifecycle_token: Option<NonZeroU64>,
    retirement_lifecycle_token: Option<NonZeroU64>,
    control_epoch: u64,
    registered: bool,
    binding: Option<LeaseBinding>,
    active_deadline_boot_ns: u64,
    terminal: bool,
    close_verified: bool,
    reclaimed: bool,
}

impl fmt::Debug for LeaseBoundFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseBoundFence")
            .field("registered", &self.registered)
            .field("active", &(self.binding.is_some() && !self.terminal))
            .field("terminal", &self.terminal)
            .field("close_verified", &self.close_verified)
            .field("reclaimed", &self.reclaimed)
            .finish()
    }
}

impl LeaseBoundFence {
    pub(crate) fn from_unregistered(
        kernel: Arc<dyn KernelControl>,
        clock: Arc<dyn BootClock>,
        identity: AttachmentIdentity,
        socket_cookie: u64,
    ) -> Result<Self, FenceError> {
        if socket_cookie == 0 {
            return Err(FenceError::KernelReadback);
        }
        Ok(Self {
            kernel,
            clock,
            identity,
            socket_cookie,
            socket_lifecycle_token: None,
            retirement_lifecycle_token: None,
            control_epoch: 0,
            registered: false,
            binding: None,
            active_deadline_boot_ns: 0,
            terminal: false,
            close_verified: false,
            reclaimed: false,
        })
    }

    #[must_use]
    pub(crate) fn is_active(&self) -> bool {
        self.binding.is_some() && !self.terminal
    }

    pub(crate) async fn acquire<A>(
        &mut self,
        authority: &A,
        key: &SessionKey,
        owner: OwnerId,
        timing: LeaseFenceTiming,
    ) -> Result<LeaseGuard, LeaseFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        if self.binding.is_some() || self.terminal || self.registered {
            return Err(LeaseFenceError::Fence(FenceError::TerminalClosed));
        }
        let mut pending = PendingTransition::new(self);
        let acquisition_start = pending.now().map_err(LeaseFenceError::Fence)?;
        let grant = authority
            .acquire(
                key,
                owner,
                timing.ttl(),
                pending.fence.identity.durable,
                timing.active_gate_lifetime(),
            )
            .await
            .map_err(LeaseFenceError::Authority)?;
        let (
            mut guard,
            lifecycle_token,
            retirement_lifecycle_token,
            prior,
            durable_record_generation,
        ) = grant.into_parts();
        if let Err(error) =
            validate_lifecycle_token_pair(lifecycle_token, retirement_lifecycle_token)
        {
            return Err(fence_with_lease(error, guard));
        }
        let acquisition_completion = match pending.now_not_before(acquisition_start) {
            Ok(now) => now,
            Err(error) => return Err(fence_with_lease(error, guard)),
        };
        let activation_path = match pending.activation_path(
            lifecycle_token,
            retirement_lifecycle_token,
            prior,
            durable_record_generation,
            timing.active_gate_lifetime(),
        ) {
            Ok(path) => path,
            Err(error) => return Err(fence_with_lease(error, guard)),
        };
        let operation_start = match activation_path {
            ActivationPath::Immediate => acquisition_start,
            ActivationPath::Delayed(delay) => {
                guard = pending
                    .supervise_closed_wait(authority, guard, acquisition_completion, delay, timing)
                    .await?;
                let renewal_start = match pending.now() {
                    Ok(now) => now,
                    Err(error) => return Err(fence_with_lease(error, guard)),
                };
                let renewed = match authority.renew(&guard, timing.ttl()).await {
                    Ok(renewed) => renewed,
                    Err(error) => return Err(authority_with_lease(error, guard)),
                };
                if let Err(error) = validate_guard_continuity(&guard, &renewed) {
                    return Err(fence_with_lease(error, guard));
                }
                guard = renewed;
                renewal_start
            }
        };
        let deadline = match timing.deadline_from(operation_start) {
            Ok(deadline) => deadline,
            Err(error) => return Err(fence_with_lease(error, guard)),
        };
        if let Err(error) = pending.publish_register_activate(
            &guard,
            lifecycle_token,
            retirement_lifecycle_token,
            deadline,
            operation_start,
        ) {
            return Err(fence_with_lease(error, guard));
        }
        pending.disarm();
        Ok(guard)
    }

    /// Renew an exact guard and refresh the kernel deadline.
    ///
    /// Ownership of `current` moves into this operation so every synchronous
    /// post-grant failure can return the unreleased guard. Cancellation drops
    /// it without release and therefore leaves durable authority to expire.
    pub(crate) async fn renew<A>(
        &mut self,
        authority: &A,
        current: LeaseGuard,
        timing: LeaseFenceTiming,
    ) -> Result<LeaseGuard, LeaseFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        if self.terminal {
            return Err(fence_with_lease(FenceError::TerminalClosed, current));
        }
        if !self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.matches(&current))
        {
            let _ = self.terminal_close();
            return Err(fence_with_lease(FenceError::LeaseContinuity, current));
        }
        let mut pending = PendingTransition::new(self);
        let operation_start = match pending.now() {
            Ok(now) => now,
            Err(error) => return Err(fence_with_lease(error, current)),
        };
        let deadline = match timing.deadline_from(operation_start) {
            Ok(deadline) => deadline,
            Err(error) => return Err(fence_with_lease(error, current)),
        };
        let renewed = match authority.renew(&current, timing.ttl()).await {
            Ok(renewed) => renewed,
            Err(error) => return Err(authority_with_lease(error, current)),
        };
        if let Err(error) = validate_guard_continuity(&current, &renewed) {
            return Err(fence_with_lease(error, current));
        }
        if let Err(error) = pending.refresh(&renewed, deadline, operation_start) {
            return Err(fence_with_lease(error, renewed));
        }
        pending.disarm();
        Ok(renewed)
    }

    fn activation_path(
        &self,
        lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        prior: DurablePriorFenceState,
        durable_record_generation: NonZeroU64,
        current_gate_lifetime: Duration,
    ) -> Result<ActivationPath, FenceError> {
        let current_gate_ns = validate_prior_gate_lifetime(current_gate_lifetime)?;
        validate_lifecycle_token_pair(lifecycle_token, retirement_lifecycle_token)?;
        let current = self.inspect_current()?;
        validate_current(current)?;
        if lifecycle_token.get() <= current.lifecycle_token {
            return Err(FenceError::InvalidPriorEvidence);
        }
        match prior.kind {
            DurablePriorFenceKind::FreshInstall {
                bootstrap_generation,
            } => {
                if durable_record_generation.get() <= bootstrap_generation.get() {
                    return Err(FenceError::InvalidPriorEvidence);
                }
                match self.identity.inventory {
                    AttachmentInventory::InstalledUnderRevisionGuard => {
                        require_current(current, KernelCurrentPhase::Uninitialized, 0, 0)?;
                        Ok(ActivationPath::Immediate)
                    }
                    AttachmentInventory::AdoptedExact => {
                        Ok(ActivationPath::Delayed(max_gate_lifetime()))
                    }
                }
            }
            DurablePriorFenceKind::VerifiedTerminal {
                attachment,
                socket_lifecycle_token: prior_socket_token,
                retirement_lifecycle_token: prior_retirement_token,
                terminal_generation,
            } => {
                if durable_record_generation.get() <= terminal_generation.get()
                    || lifecycle_token.get() <= prior_retirement_token.get()
                {
                    return Err(FenceError::InvalidPriorEvidence);
                }
                validate_lifecycle_token_pair(prior_socket_token, prior_retirement_token)?;
                if attachment == self.identity.durable {
                    if self.identity.inventory != AttachmentInventory::AdoptedExact {
                        return Err(FenceError::InvalidPriorEvidence);
                    }
                    require_current(
                        current,
                        KernelCurrentPhase::RetirementClosed,
                        prior_retirement_token.get(),
                        0,
                    )?;
                    Ok(ActivationPath::Immediate)
                } else if self.identity.inventory
                    == AttachmentInventory::InstalledUnderRevisionGuard
                {
                    require_current(current, KernelCurrentPhase::Uninitialized, 0, 0)?;
                    Ok(ActivationPath::Immediate)
                } else {
                    Ok(ActivationPath::Delayed(max_gate_lifetime()))
                }
            }
            DurablePriorFenceKind::LastAttachment {
                attachment,
                socket_lifecycle_token: prior_socket_token,
                retirement_lifecycle_token: prior_retirement_token,
                gate_lifetime,
                record_generation,
            } => {
                if durable_record_generation.get() <= record_generation.get()
                    || lifecycle_token.get() <= prior_retirement_token.get()
                {
                    return Err(FenceError::InvalidPriorEvidence);
                }
                validate_lifecycle_token_pair(prior_socket_token, prior_retirement_token)?;
                if attachment == self.identity.durable {
                    if self.identity.inventory != AttachmentInventory::AdoptedExact {
                        return Err(FenceError::InvalidPriorEvidence);
                    }
                    require_current_not_after_prior(current, prior_retirement_token)?;
                    Ok(ActivationPath::Immediate)
                } else {
                    let prior_ns = validate_prior_gate_lifetime(gate_lifetime)?;
                    Ok(ActivationPath::Delayed(Duration::from_nanos(cmp::max(
                        prior_ns,
                        current_gate_ns,
                    ))))
                }
            }
            DurablePriorFenceKind::Unknown => Ok(ActivationPath::Delayed(max_gate_lifetime())),
        }
    }

    pub(crate) fn prepare_release(
        &mut self,
        lease: &LeaseGuard,
    ) -> Result<PendingTerminalClosure, FenceError> {
        let Some(binding) = self
            .binding
            .as_ref()
            .filter(|binding| binding.matches(lease))
            .cloned()
        else {
            let _ = self.terminal_close();
            return Err(FenceError::LeaseContinuity);
        };
        self.terminal_close()?;
        let inspection = self.inspect_exact(binding.socket_lifecycle_token)?;
        require_current(
            inspection.current,
            KernelCurrentPhase::LifecycleOpen,
            binding.socket_lifecycle_token.get(),
            self.socket_cookie,
        )?;
        let terminal = inspection.entry.ok_or(FenceError::KernelReadback)?;
        if terminal.state != KernelEntryState::TerminalClosed
            || terminal.control_epoch != self.control_epoch
        {
            return Err(FenceError::KernelReadback);
        }
        Ok(PendingTerminalClosure {
            attachment: self.identity.durable,
            socket_cookie: self.socket_cookie,
            lease_fence_token: NonZeroU64::new(binding.lease_fence_token)
                .ok_or(FenceError::KernelReadback)?,
            socket_lifecycle_token: binding.socket_lifecycle_token,
            retirement_lifecycle_token: binding.retirement_lifecycle_token,
            control_epoch: NonZeroU64::new(terminal.control_epoch)
                .ok_or(FenceError::KernelReadback)?,
        })
    }

    pub(crate) fn reclaim_after_socket_close(
        &mut self,
        pending: PendingTerminalClosure,
    ) -> Result<TerminalClosureEvidence, FenceError> {
        if !self.terminal
            || !self.close_verified
            || self.reclaimed
            || pending.attachment != self.identity.durable
            || pending.socket_cookie != self.socket_cookie
            || pending.socket_lifecycle_token != self.socket_lifecycle_token_or_error()?
            || pending.retirement_lifecycle_token != self.retirement_lifecycle_token_or_error()?
            || pending.control_epoch.get() != self.control_epoch
        {
            return Err(FenceError::KernelReadback);
        }
        validate_lifecycle_token_pair(
            pending.socket_lifecycle_token,
            pending.retirement_lifecycle_token,
        )?;
        let before_retirement = self.inspect_exact(pending.socket_lifecycle_token)?;
        require_current(
            before_retirement.current,
            KernelCurrentPhase::LifecycleOpen,
            pending.socket_lifecycle_token.get(),
            self.socket_cookie,
        )?;
        if before_retirement.entry.is_none() {
            return Err(FenceError::KernelReadback);
        }
        let publish = self
            .kernel
            .publish_retirement(self.identity, pending.retirement_lifecycle_token.get());
        let retired = self.inspect_exact(pending.socket_lifecycle_token)?;
        if retired.current.lifecycle_token != pending.retirement_lifecycle_token.get()
            || retired.current.phase != KernelCurrentPhase::RetirementClosed
            || retired.current.registered_socket_cookie != 0
            || retired.entry.is_none()
        {
            return Err(match publish {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        let mutation = self.kernel.reclaim(
            self.identity,
            self.socket_cookie,
            pending.socket_lifecycle_token.get(),
            pending.control_epoch.get(),
        );
        let readback = self.inspect_exact(pending.socket_lifecycle_token)?;
        if readback.entry.is_some() {
            return Err(match mutation {
                Ok(()) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        require_current(
            readback.current,
            KernelCurrentPhase::RetirementClosed,
            pending.retirement_lifecycle_token.get(),
            0,
        )?;
        self.reclaimed = true;
        Ok(TerminalClosureEvidence {
            attachment: pending.attachment,
            lease_fence_token: pending.lease_fence_token,
            socket_lifecycle_token: pending.socket_lifecycle_token,
            retirement_lifecycle_token: pending.retirement_lifecycle_token,
            control_epoch: pending.control_epoch,
        })
    }

    pub(crate) fn terminal_close(&mut self) -> Result<(), FenceError> {
        self.terminal = true;
        self.binding = None;
        self.active_deadline_boot_ns = 0;
        if !self.registered {
            self.close_verified = true;
            self.reclaimed = true;
            return Ok(());
        }
        if self.reclaimed || self.close_verified {
            return Ok(());
        }
        let lifecycle_token = self.socket_lifecycle_token_or_error()?;
        let inspection = self.inspect_exact(lifecycle_token)?;
        require_current(
            inspection.current,
            KernelCurrentPhase::LifecycleOpen,
            lifecycle_token.get(),
            self.socket_cookie,
        )?;
        let current = inspection.entry.ok_or(FenceError::KernelReadback)?;
        verify_entry_identity(current, self.socket_cookie, lifecycle_token)?;
        if current.state == KernelEntryState::TerminalClosed {
            self.control_epoch = current.control_epoch;
            self.close_verified = true;
            return Ok(());
        }
        if current.control_epoch != self.control_epoch {
            return Err(FenceError::KernelReadback);
        }
        let expected_epoch = current
            .control_epoch
            .checked_add(1)
            .ok_or(FenceError::KernelReadback)?;
        let mutation = self.kernel.close(
            self.identity,
            self.socket_cookie,
            lifecycle_token.get(),
            current.control_epoch,
        );
        let readback_inspection = self.inspect_exact(lifecycle_token)?;
        require_current(
            readback_inspection.current,
            KernelCurrentPhase::LifecycleOpen,
            lifecycle_token.get(),
            self.socket_cookie,
        )?;
        let readback = readback_inspection
            .entry
            .ok_or(FenceError::KernelReadback)?;
        if readback.state != KernelEntryState::TerminalClosed
            || readback.socket_cookie != self.socket_cookie
            || readback.lifecycle_token != lifecycle_token.get()
            || readback.deadline_boot_ns != 0
            || readback.control_epoch != expected_epoch
        {
            return Err(match mutation {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        self.control_epoch = readback.control_epoch;
        self.close_verified = true;
        Ok(())
    }

    fn publish_register_activate(
        &mut self,
        guard: &LeaseGuard,
        lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        deadline_boot_ns: u64,
        operation_start_boot_ns: u64,
    ) -> Result<(), FenceError> {
        self.verify_operation_budget(deadline_boot_ns, operation_start_boot_ns)?;
        validate_lifecycle_token_pair(lifecycle_token, retirement_lifecycle_token)?;
        if self.registered
            || self.socket_lifecycle_token.is_some()
            || self.retirement_lifecycle_token.is_some()
        {
            return Err(FenceError::TerminalClosed);
        }
        let before = self.inspect_current()?;
        if lifecycle_token.get() <= before.lifecycle_token {
            return Err(FenceError::KernelReadback);
        }
        let publish = self
            .kernel
            .publish_lifecycle(self.identity, lifecycle_token.get());
        let published = self.inspect_current()?;
        if published.lifecycle_token != lifecycle_token.get()
            || published.phase != KernelCurrentPhase::LifecycleOpen
            || published.registered_socket_cookie != 0
        {
            return Err(match publish {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        self.socket_lifecycle_token = Some(lifecycle_token);
        self.retirement_lifecycle_token = Some(retirement_lifecycle_token);

        let register =
            self.kernel
                .register_closed(self.identity, self.socket_cookie, lifecycle_token.get());
        let returned = register.as_ref().ok().copied();
        if returned
            .is_some_and(|entry| initial_entry_matches(entry, self.socket_cookie, lifecycle_token))
        {
            self.registered = true;
            self.control_epoch = INITIAL_CONTROL_EPOCH;
        }
        let registered = self.inspect_exact(lifecycle_token)?;
        if registered
            .entry
            .is_some_and(|entry| initial_entry_matches(entry, self.socket_cookie, lifecycle_token))
        {
            self.registered = true;
            self.control_epoch = INITIAL_CONTROL_EPOCH;
        } else {
            return Err(match register {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        require_current(
            registered.current,
            KernelCurrentPhase::LifecycleOpen,
            lifecycle_token.get(),
            self.socket_cookie,
        )?;

        let expected_epoch = self
            .control_epoch
            .checked_add(1)
            .ok_or(FenceError::KernelReadback)?;
        let activation = self.kernel.activate(
            self.identity,
            self.socket_cookie,
            lifecycle_token.get(),
            deadline_boot_ns,
            self.control_epoch,
        );
        let active_inspection = self.inspect_exact(lifecycle_token)?;
        let active = active_inspection.entry.ok_or(FenceError::KernelReadback)?;
        if active.state != KernelEntryState::Active
            || active.socket_cookie != self.socket_cookie
            || active.lifecycle_token != lifecycle_token.get()
            || active.deadline_boot_ns != deadline_boot_ns
            || active.control_epoch != expected_epoch
        {
            return Err(match activation {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        require_current(
            active_inspection.current,
            KernelCurrentPhase::LifecycleOpen,
            lifecycle_token.get(),
            self.socket_cookie,
        )?;
        self.verify_operation_budget(deadline_boot_ns, operation_start_boot_ns)?;
        self.control_epoch = active.control_epoch;
        self.binding = Some(LeaseBinding::from_guard(
            guard,
            lifecycle_token,
            retirement_lifecycle_token,
        ));
        self.active_deadline_boot_ns = deadline_boot_ns;
        Ok(())
    }

    fn refresh_verified(
        &mut self,
        renewed: &LeaseGuard,
        deadline_boot_ns: u64,
        operation_start_boot_ns: u64,
    ) -> Result<(), FenceError> {
        self.verify_operation_budget(deadline_boot_ns, operation_start_boot_ns)?;
        let Some(binding) = self
            .binding
            .as_ref()
            .filter(|binding| binding.matches(renewed))
            .cloned()
        else {
            return Err(FenceError::LeaseContinuity);
        };
        let before_refresh = self.inspect_exact(binding.socket_lifecycle_token)?;
        require_current(
            before_refresh.current,
            KernelCurrentPhase::LifecycleOpen,
            binding.socket_lifecycle_token.get(),
            self.socket_cookie,
        )?;
        if before_refresh.entry.is_none() {
            return Err(FenceError::KernelReadback);
        }
        let expected_epoch = self
            .control_epoch
            .checked_add(1)
            .ok_or(FenceError::KernelReadback)?;
        let refresh = self.kernel.refresh(
            self.identity,
            self.socket_cookie,
            binding.socket_lifecycle_token.get(),
            deadline_boot_ns,
            self.control_epoch,
        );
        let active_inspection = self.inspect_exact(binding.socket_lifecycle_token)?;
        let active = active_inspection.entry.ok_or(FenceError::KernelReadback)?;
        if active.state != KernelEntryState::Active
            || active.socket_cookie != self.socket_cookie
            || active.lifecycle_token != binding.socket_lifecycle_token.get()
            || active.deadline_boot_ns != deadline_boot_ns
            || active.control_epoch != expected_epoch
        {
            return Err(match refresh {
                Ok(_) => FenceError::KernelReadback,
                Err(failure) => map_kernel_failure(failure),
            });
        }
        require_current(
            active_inspection.current,
            KernelCurrentPhase::LifecycleOpen,
            binding.socket_lifecycle_token.get(),
            self.socket_cookie,
        )?;
        self.verify_operation_budget(deadline_boot_ns, operation_start_boot_ns)?;
        self.control_epoch = active.control_epoch;
        self.binding = Some(LeaseBinding::from_guard(
            renewed,
            binding.socket_lifecycle_token,
            binding.retirement_lifecycle_token,
        ));
        self.active_deadline_boot_ns = deadline_boot_ns;
        Ok(())
    }

    fn verify_operation_budget(
        &self,
        deadline_boot_ns: u64,
        operation_start_boot_ns: u64,
    ) -> Result<(), FenceError> {
        let requested_lifetime = deadline_boot_ns
            .checked_sub(operation_start_boot_ns)
            .ok_or(FenceError::DeadlineOverflow)?;
        if requested_lifetime == 0 || requested_lifetime > MAX_GATE_LIFETIME_NS {
            return Err(FenceError::InvalidTiming);
        }
        let completion = self
            .clock
            .now_boot_ns()
            .map_err(|_| FenceError::ClockUnavailable)?;
        if completion < operation_start_boot_ns {
            return Err(FenceError::ClockUnavailable);
        }
        if completion >= deadline_boot_ns {
            return Err(FenceError::OperationOverBudget);
        }
        Ok(())
    }

    fn socket_lifecycle_token_or_error(&self) -> Result<NonZeroU64, FenceError> {
        self.socket_lifecycle_token
            .ok_or(FenceError::KernelReadback)
    }

    fn retirement_lifecycle_token_or_error(&self) -> Result<NonZeroU64, FenceError> {
        self.retirement_lifecycle_token
            .ok_or(FenceError::KernelReadback)
    }

    fn inspect_current(&self) -> Result<KernelCurrentFence, FenceError> {
        let current = self
            .kernel
            .inspect(self.identity, None)
            .map_err(map_kernel_failure)
            .map(|inspection| inspection.current)?;
        validate_current(current)?;
        Ok(current)
    }

    fn inspect_exact(&self, lifecycle_token: NonZeroU64) -> Result<KernelInspection, FenceError> {
        let inspection = self
            .kernel
            .inspect(
                self.identity,
                Some((self.socket_cookie, lifecycle_token.get())),
            )
            .map_err(map_kernel_failure)?;
        validate_current(inspection.current)?;
        if let Some(entry) = inspection.entry {
            verify_entry_identity(entry, self.socket_cookie, lifecycle_token)?;
        }
        Ok(inspection)
    }
}

impl Drop for LeaseBoundFence {
    fn drop(&mut self) {
        let _ = self.terminal_close();
    }
}

fn initial_entry_matches(
    entry: KernelFenceEntry,
    socket_cookie: u64,
    lifecycle_token: NonZeroU64,
) -> bool {
    entry.state == KernelEntryState::InitialClosed
        && entry.socket_cookie == socket_cookie
        && entry.lifecycle_token == lifecycle_token.get()
        && entry.deadline_boot_ns == 0
        && entry.control_epoch == INITIAL_CONTROL_EPOCH
}

fn verify_entry_identity(
    entry: KernelFenceEntry,
    socket_cookie: u64,
    lifecycle_token: NonZeroU64,
) -> Result<(), FenceError> {
    if entry.socket_cookie == socket_cookie
        && entry.lifecycle_token == lifecycle_token.get()
        && entry.control_epoch != 0
    {
        Ok(())
    } else {
        Err(FenceError::KernelReadback)
    }
}

fn require_current(
    current: KernelCurrentFence,
    phase: KernelCurrentPhase,
    lifecycle_token: u64,
    socket_cookie: u64,
) -> Result<(), FenceError> {
    if current.phase == phase
        && current.lifecycle_token == lifecycle_token
        && current.registered_socket_cookie == socket_cookie
    {
        Ok(())
    } else {
        Err(FenceError::KernelReadback)
    }
}

fn require_current_not_after_prior(
    current: KernelCurrentFence,
    prior_retirement_lifecycle_token: NonZeroU64,
) -> Result<(), FenceError> {
    validate_current(current)?;
    if current.lifecycle_token < prior_retirement_lifecycle_token.get()
        || (current.lifecycle_token == prior_retirement_lifecycle_token.get()
            && current.phase == KernelCurrentPhase::RetirementClosed
            && current.registered_socket_cookie == 0)
    {
        Ok(())
    } else {
        Err(FenceError::KernelReadback)
    }
}

fn validate_current(current: KernelCurrentFence) -> Result<(), FenceError> {
    let canonical = match current.phase {
        KernelCurrentPhase::Uninitialized => {
            current.lifecycle_token == 0 && current.registered_socket_cookie == 0
        }
        KernelCurrentPhase::LifecycleOpen => current.lifecycle_token & 1 == 1,
        KernelCurrentPhase::RetirementClosed => {
            current.lifecycle_token != 0
                && current.lifecycle_token & 1 == 0
                && current.registered_socket_cookie == 0
        }
    };
    if canonical {
        Ok(())
    } else {
        Err(FenceError::KernelReadback)
    }
}

fn validate_guard_continuity(current: &LeaseGuard, renewed: &LeaseGuard) -> Result<(), FenceError> {
    if current.key() == renewed.key()
        && current.owner() == renewed.owner()
        && current.fence() == renewed.fence()
        && current.credential_id() == renewed.credential_id()
    {
        Ok(())
    } else {
        Err(FenceError::LeaseContinuity)
    }
}

fn map_kernel_failure(failure: KernelFailure) -> FenceError {
    match failure {
        KernelFailure::Mutation => FenceError::KernelMutation,
        KernelFailure::Readback => FenceError::KernelReadback,
        KernelFailure::Clock => FenceError::ClockUnavailable,
    }
}

fn authority_with_lease<E>(error: E, lease: LeaseGuard) -> LeaseFenceError<E> {
    LeaseFenceError::AuthorityWithLease { error, lease }
}

fn fence_with_lease<E>(error: FenceError, lease: LeaseGuard) -> LeaseFenceError<E> {
    LeaseFenceError::FenceWithLease { error, lease }
}

struct PendingTransition<'a> {
    fence: &'a mut LeaseBoundFence,
    armed: bool,
}

impl<'a> PendingTransition<'a> {
    fn new(fence: &'a mut LeaseBoundFence) -> Self {
        Self { fence, armed: true }
    }

    fn now(&self) -> Result<u64, FenceError> {
        self.fence
            .clock
            .now_boot_ns()
            .map_err(|_| FenceError::ClockUnavailable)
    }

    fn now_not_before(&self, prior: u64) -> Result<u64, FenceError> {
        let now = self.now()?;
        if now < prior {
            Err(FenceError::ClockUnavailable)
        } else {
            Ok(now)
        }
    }

    fn activation_path(
        &self,
        lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        prior: DurablePriorFenceState,
        durable_record_generation: NonZeroU64,
        current_gate_lifetime: Duration,
    ) -> Result<ActivationPath, FenceError> {
        self.fence.activation_path(
            lifecycle_token,
            retirement_lifecycle_token,
            prior,
            durable_record_generation,
            current_gate_lifetime,
        )
    }

    async fn supervise_closed_wait<A>(
        &mut self,
        authority: &A,
        mut guard: LeaseGuard,
        wait_start_boot_ns: u64,
        delay: Duration,
        timing: LeaseFenceTiming,
    ) -> Result<LeaseGuard, LeaseFenceError<A::Error>>
    where
        A: EgressFenceLeaseAuthority + ?Sized,
    {
        let delay_ns = match validate_prior_gate_lifetime(delay) {
            Ok(delay_ns) => delay_ns,
            Err(error) => return Err(fence_with_lease(error, guard)),
        };
        let target = match wait_start_boot_ns.checked_add(delay_ns) {
            Some(target) => target,
            None => return Err(fence_with_lease(FenceError::DeadlineOverflow, guard)),
        };
        let renew_interval_ns = match u64::try_from(timing.closed_renew_interval().as_nanos()) {
            Ok(interval) if interval != 0 => interval,
            _ => return Err(fence_with_lease(FenceError::InvalidTiming, guard)),
        };
        let mut next_renew = match wait_start_boot_ns.checked_add(renew_interval_ns) {
            Some(next_renew) => next_renew,
            None => return Err(fence_with_lease(FenceError::DeadlineOverflow, guard)),
        };
        let mut last_observed = wait_start_boot_ns;

        loop {
            let now = match self.now_not_before(last_observed) {
                Ok(now) => now,
                Err(error) => return Err(fence_with_lease(error, guard)),
            };
            last_observed = now;
            if now >= target {
                return Ok(guard);
            }
            if now >= next_renew {
                let renewed = match authority.renew(&guard, timing.ttl()).await {
                    Ok(renewed) => renewed,
                    Err(error) => return Err(authority_with_lease(error, guard)),
                };
                if let Err(error) = validate_guard_continuity(&guard, &renewed) {
                    return Err(fence_with_lease(error, guard));
                }
                guard = renewed;
                let completion = match self.now_not_before(now) {
                    Ok(completion) => completion,
                    Err(error) => return Err(fence_with_lease(error, guard)),
                };
                last_observed = completion;
                next_renew = match completion.checked_add(renew_interval_ns) {
                    Some(next_renew) => next_renew,
                    None => {
                        return Err(fence_with_lease(FenceError::DeadlineOverflow, guard));
                    }
                };
                continue;
            }
            let until_target = target - now;
            let until_renew = next_renew - now;
            let configured_poll_ns =
                u64::try_from(timing.boot_poll_interval().as_nanos()).unwrap_or(u64::MAX);
            let poll_ns = cmp::max(
                1,
                cmp::min(cmp::min(until_target, until_renew), configured_poll_ns),
            );
            if self
                .fence
                .clock
                .wait_poll(Duration::from_nanos(poll_ns))
                .await
                .is_err()
            {
                return Err(fence_with_lease(FenceError::ClockUnavailable, guard));
            }
        }
    }

    fn publish_register_activate(
        &mut self,
        guard: &LeaseGuard,
        lifecycle_token: NonZeroU64,
        retirement_lifecycle_token: NonZeroU64,
        deadline_boot_ns: u64,
        operation_start_boot_ns: u64,
    ) -> Result<(), FenceError> {
        self.fence.publish_register_activate(
            guard,
            lifecycle_token,
            retirement_lifecycle_token,
            deadline_boot_ns,
            operation_start_boot_ns,
        )
    }

    fn refresh(
        &mut self,
        renewed: &LeaseGuard,
        deadline_boot_ns: u64,
        operation_start_boot_ns: u64,
    ) -> Result<(), FenceError> {
        self.fence
            .refresh_verified(renewed, deadline_boot_ns, operation_start_boot_ns)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingTransition<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.fence.terminal_close();
        }
    }
}
