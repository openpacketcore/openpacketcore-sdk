use std::{
    collections::{HashMap, VecDeque},
    future::{pending, poll_fn, Future},
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use opc_egress_fence_common::EGRESS_FENCE_MAX_GATE_LIFETIME_NS;
use opc_session_store::{
    FakeSessionBackend, LeaseGuard, OwnerId, SessionKey, SessionKeyType, SessionLeaseManager,
    StableId,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

use crate::lifecycle::{
    AttachmentIdentity, AttachmentInventory, BootClock, DurablePriorFenceState,
    EgressFenceLeaseAuthority, FenceAttachmentIdentity, FenceError, FenceLeaseGrant, KernelControl,
    KernelCurrentFence, KernelCurrentPhase, KernelEntryState, KernelFailure, KernelFenceEntry,
    KernelInspection, LeaseBoundFence, LeaseFenceError, LeaseFenceTiming, TerminalClosureEvidence,
};

const SOCKET_COOKIE: u64 = 13;
const INITIAL_BOOT_NS: u64 = 1_000_000_000;
const SOCKET_TOKEN: u64 = 101;
const RETIREMENT_TOKEN: u64 = 102;

fn expect_lease_fence_error<E>(
    result: Result<LeaseGuard, LeaseFenceError<E>>,
    message: &str,
) -> LeaseFenceError<E> {
    match result {
        Err(error) => error,
        Ok(_guard) => panic!("{message}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelFault {
    None,
    InspectNext,
    PublishBefore,
    PublishAfter,
    CleanupBefore,
    CleanupDelete,
    CleanupAfter,
    RegisterBefore,
    RegisterAfter,
    ActivateBefore,
    ActivateAfter,
    RefreshBefore,
    RefreshAfter,
    CloseBefore,
    CloseAfter,
    ReclaimBefore,
    ReclaimAfter,
    CorruptNextEntryRead,
}

struct TestKernelState {
    current: KernelCurrentFence,
    entries: HashMap<(u64, u64), KernelFenceEntry>,
    capacity: usize,
    mutation_generation: u64,
    mutation_inflight: bool,
    fault: KernelFault,
    events: Vec<&'static str>,
}

struct TestKernel {
    identity: AttachmentIdentity,
    state: Mutex<TestKernelState>,
}

impl TestKernel {
    fn new(
        identity: AttachmentIdentity,
        current: KernelCurrentFence,
        capacity: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            state: Mutex::new(TestKernelState {
                current,
                entries: HashMap::new(),
                capacity,
                mutation_generation: 1,
                mutation_inflight: false,
                fault: KernelFault::None,
                events: Vec::new(),
            }),
        })
    }

    fn empty(identity: AttachmentIdentity) -> Arc<Self> {
        Self::new(
            identity,
            KernelCurrentFence {
                phase: KernelCurrentPhase::Uninitialized,
                lifecycle_token: 0,
                registered_socket_cookie: 0,
            },
            8,
        )
    }

    fn set_fault(&self, fault: KernelFault) {
        self.state.lock().expect("test kernel lock").fault = fault;
    }

    fn set_mutation_barrier(&self, generation: u64, inflight: bool) {
        let mut state = self.state.lock().expect("test kernel lock");
        state.mutation_generation = generation;
        state.mutation_inflight = inflight;
    }

    fn mutation_barrier(&self) -> (u64, bool) {
        let state = self.state.lock().expect("test kernel lock");
        (state.mutation_generation, state.mutation_inflight)
    }

    fn seed_entry(&self, entry: KernelFenceEntry) {
        self.state
            .lock()
            .expect("test kernel lock")
            .entries
            .insert((entry.socket_cookie, entry.lifecycle_token), entry);
    }

    fn entry(&self, cookie: u64, token: u64) -> Option<KernelFenceEntry> {
        self.state
            .lock()
            .expect("test kernel lock")
            .entries
            .get(&(cookie, token))
            .copied()
    }

    fn current(&self) -> KernelCurrentFence {
        self.state.lock().expect("test kernel lock").current
    }

    fn events(&self) -> Vec<&'static str> {
        self.state.lock().expect("test kernel lock").events.clone()
    }

    fn entry_count(&self) -> usize {
        self.state.lock().expect("test kernel lock").entries.len()
    }

    fn validate_identity(&self, identity: AttachmentIdentity) -> Result<(), KernelFailure> {
        if identity == self.identity {
            Ok(())
        } else {
            Err(KernelFailure::Readback)
        }
    }

    fn transition_active(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
        refresh: bool,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        let fault = if refresh {
            KernelFault::RefreshAfter
        } else {
            KernelFault::ActivateAfter
        };
        let before_fault = if refresh {
            KernelFault::RefreshBefore
        } else {
            KernelFault::ActivateBefore
        };
        if state.fault == before_fault {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if state.current
            != (KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token,
                registered_socket_cookie: socket_cookie,
            })
            || deadline_boot_ns == 0
        {
            return Err(KernelFailure::Mutation);
        }
        let current = state
            .entries
            .get(&(socket_cookie, lifecycle_token))
            .copied()
            .ok_or(KernelFailure::Readback)?;
        if current.socket_cookie != socket_cookie
            || current.lifecycle_token != lifecycle_token
            || current.control_epoch != expected_epoch
            || current.state == KernelEntryState::TerminalClosed
            || (!refresh && current.state != KernelEntryState::InitialClosed)
            || (refresh && current.state != KernelEntryState::Active)
        {
            return Err(KernelFailure::Mutation);
        }
        let next = KernelFenceEntry {
            state: KernelEntryState::Active,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            control_epoch: expected_epoch
                .checked_add(1)
                .ok_or(KernelFailure::Mutation)?,
        };
        state.entries.insert((socket_cookie, lifecycle_token), next);
        state
            .events
            .push(if refresh { "refresh" } else { "activate" });
        if state.fault == fault {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(next)
        }
    }
}

impl KernelControl for TestKernel {
    fn inspect(
        &self,
        identity: AttachmentIdentity,
        entry_key: Option<(u64, u64)>,
    ) -> Result<KernelInspection, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Readback)?;
        if state.fault == KernelFault::InspectNext {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Readback);
        }
        if state.mutation_inflight {
            return Err(KernelFailure::Readback);
        }
        let mut entry = entry_key.and_then(|key| state.entries.get(&key).copied());
        if state.fault == KernelFault::CorruptNextEntryRead && entry_key.is_some() {
            state.fault = KernelFault::None;
            if let Some(value) = entry.as_mut() {
                value.socket_cookie ^= 1;
            }
        }
        Ok(KernelInspection {
            current: state.current,
            entry,
        })
    }

    fn publish_lifecycle(
        &self,
        identity: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.fault == KernelFault::PublishBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if state.mutation_inflight
            || lifecycle_token & 1 == 0
            || lifecycle_token <= state.current.lifecycle_token
        {
            return Err(KernelFailure::Mutation);
        }
        let next = KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token,
            registered_socket_cookie: 0,
        };
        state.current = next;
        state.events.push("publish");
        if state.fault == KernelFault::PublishAfter {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(next)
        }
    }

    fn cleanup_superseded(
        &self,
        identity: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<(), KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.mutation_inflight
            || state.current.phase != KernelCurrentPhase::LifecycleOpen
            || state.current.lifecycle_token != lifecycle_token
            || state.current.registered_socket_cookie != 0
        {
            return Err(KernelFailure::Readback);
        }
        if state.fault == KernelFault::CleanupBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        let stale = state
            .entries
            .keys()
            .copied()
            .filter(|(_, token)| *token < lifecycle_token)
            .collect::<Vec<_>>();
        for key in stale {
            let entry = state.entries.get_mut(&key).ok_or(KernelFailure::Readback)?;
            if entry.socket_cookie == 0 || entry.lifecycle_token == 0 || entry.control_epoch == 0 {
                return Err(KernelFailure::Readback);
            }
            entry.state = KernelEntryState::Reclaiming;
            entry.deadline_boot_ns = 0;
            if state.fault == KernelFault::CleanupDelete {
                state.fault = KernelFault::None;
                state.events.push("cleanup_reclaiming");
                return Err(KernelFailure::Mutation);
            }
            state.entries.remove(&key);
            state.events.push("cleanup");
        }
        if state.fault == KernelFault::CleanupAfter {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(())
        }
    }

    fn publish_retirement(
        &self,
        identity: AttachmentIdentity,
        retirement_lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.fault == KernelFault::PublishBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if state.mutation_inflight
            || state.current.phase != KernelCurrentPhase::LifecycleOpen
            || state.current.lifecycle_token.checked_add(1) != Some(retirement_lifecycle_token)
            || retirement_lifecycle_token & 1 != 0
        {
            return Err(KernelFailure::Mutation);
        }
        let next = KernelCurrentFence {
            phase: KernelCurrentPhase::RetirementClosed,
            lifecycle_token: retirement_lifecycle_token,
            registered_socket_cookie: 0,
        };
        state.current = next;
        state.events.push("publish");
        if state.fault == KernelFault::PublishAfter {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(next)
        }
    }

    fn register_closed(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.fault == KernelFault::RegisterBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if socket_cookie == 0
            || lifecycle_token & 1 == 0
            || state.current.phase != KernelCurrentPhase::LifecycleOpen
            || state.current.lifecycle_token != lifecycle_token
            || state.current.registered_socket_cookie != 0
            || state.mutation_inflight
            || state.mutation_generation == u64::MAX
        {
            return Err(KernelFailure::Mutation);
        }
        state.mutation_inflight = true;
        if state
            .entries
            .contains_key(&(socket_cookie, lifecycle_token))
            || state.entries.len() >= state.capacity
        {
            state.mutation_generation += 1;
            state.mutation_inflight = false;
            return Err(KernelFailure::Mutation);
        }
        let entry = KernelFenceEntry {
            state: KernelEntryState::InitialClosed,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns: 0,
            control_epoch: 1,
        };
        state
            .entries
            .insert((socket_cookie, lifecycle_token), entry);
        state.current.registered_socket_cookie = socket_cookie;
        state.events.push("register");
        let result = if state.fault == KernelFault::RegisterAfter {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(entry)
        };
        state.mutation_generation += 1;
        state.mutation_inflight = false;
        result
    }

    fn activate(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.transition_active(
            identity,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            expected_epoch,
            false,
        )
    }

    fn refresh(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.transition_active(
            identity,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            expected_epoch,
            true,
        )
    }

    fn close(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.fault == KernelFault::CloseBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if state.current
            != (KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token,
                registered_socket_cookie: socket_cookie,
            })
        {
            return Err(KernelFailure::Mutation);
        }
        let current = state
            .entries
            .get(&(socket_cookie, lifecycle_token))
            .copied()
            .ok_or(KernelFailure::Readback)?;
        if current.control_epoch != expected_epoch
            || current.socket_cookie != socket_cookie
            || current.lifecycle_token != lifecycle_token
        {
            return Err(KernelFailure::Mutation);
        }
        let terminal = KernelFenceEntry {
            state: KernelEntryState::TerminalClosed,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns: 0,
            control_epoch: expected_epoch
                .checked_add(1)
                .ok_or(KernelFailure::Mutation)?,
        };
        state
            .entries
            .insert((socket_cookie, lifecycle_token), terminal);
        state.events.push("close");
        if state.fault == KernelFault::CloseAfter {
            state.fault = KernelFault::None;
            Err(KernelFailure::Mutation)
        } else {
            Ok(terminal)
        }
    }

    fn reclaim(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<(), KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
        if state.fault == KernelFault::ReclaimBefore {
            state.fault = KernelFault::None;
            return Err(KernelFailure::Mutation);
        }
        if state.mutation_inflight || state.mutation_generation == u64::MAX {
            return Err(KernelFailure::Mutation);
        }
        state.mutation_inflight = true;
        let current = state
            .entries
            .get(&(socket_cookie, lifecycle_token))
            .copied();
        let valid = current.is_some_and(|entry| {
            state.current.lifecycle_token > lifecycle_token
                && entry.state == KernelEntryState::TerminalClosed
                && entry.socket_cookie == socket_cookie
                && entry.lifecycle_token == lifecycle_token
                && entry.control_epoch == expected_epoch
        });
        let result = if !valid {
            Err(if current.is_none() {
                KernelFailure::Readback
            } else {
                KernelFailure::Mutation
            })
        } else {
            state.entries.remove(&(socket_cookie, lifecycle_token));
            state.events.push("reclaim");
            if state.fault == KernelFault::ReclaimAfter {
                state.fault = KernelFault::None;
                Err(KernelFailure::Mutation)
            } else {
                Ok(())
            }
        };
        state.mutation_generation += 1;
        state.mutation_inflight = false;
        result
    }
}

struct TestBootClock {
    now: AtomicU64,
    waits: AtomicUsize,
    fail_reads: AtomicUsize,
    fail_waits: AtomicUsize,
    scripted_reads: Mutex<VecDeque<Result<u64, KernelFailure>>>,
}

impl TestBootClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            waits: AtomicUsize::new(0),
            fail_reads: AtomicUsize::new(0),
            fail_waits: AtomicUsize::new(0),
            scripted_reads: Mutex::new(VecDeque::new()),
        })
    }

    fn advance(&self, duration: Duration) {
        let delta = u64::try_from(duration.as_nanos()).expect("fixture duration");
        self.now.fetch_add(delta, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn fail_next_reads(&self, count: usize) {
        self.fail_reads.store(count, Ordering::SeqCst);
    }

    fn script_reads(&self, reads: impl IntoIterator<Item = Result<u64, KernelFailure>>) {
        self.scripted_reads
            .lock()
            .expect("test clock script lock")
            .extend(reads);
    }
}

#[async_trait]
impl BootClock for TestBootClock {
    fn now_boot_ns(&self) -> Result<u64, KernelFailure> {
        if let Some(scripted) = self
            .scripted_reads
            .lock()
            .map_err(|_| KernelFailure::Clock)?
            .pop_front()
        {
            return scripted;
        }
        if self
            .fail_reads
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            Err(KernelFailure::Clock)
        } else {
            Ok(self.now())
        }
    }

    async fn wait_poll(&self, duration: Duration) -> Result<(), KernelFailure> {
        if self
            .fail_waits
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(KernelFailure::Clock);
        }
        self.waits.fetch_add(1, Ordering::SeqCst);
        self.advance(duration);
        tokio::task::yield_now().await;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityFailure {
    Acquire,
    Renew,
    Release,
    Contract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RenewedGuardMutation {
    None,
    ZeroInterval,
    ShortPositiveInterval,
    UnrepresentableInterval,
    RegressAcquiredAt,
    ZeroFence,
    ZeroCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcquiredGuardMutation {
    None,
    ShortPositiveInterval,
    TimestampArithmeticOverflow,
    ZeroFence,
    ZeroCredential,
}

struct TestAuthorityState {
    prior: Option<DurablePriorFenceState>,
    generation: NonZeroU64,
    socket_token: NonZeroU64,
    retirement_token: NonZeroU64,
    fail_acquire: bool,
    fail_renew: bool,
    fail_release: bool,
    pending_acquire_after_grant: bool,
    pending_renew_after_grant: bool,
    pending_release_before_commit: bool,
    acquire_wrong_key: bool,
    acquire_wrong_owner: bool,
    acquired_guard_mutation: AcquiredGuardMutation,
    return_stale_renewal: bool,
    renewed_guard_mutation: RenewedGuardMutation,
    last_returned_renewal: Option<LeaseGuard>,
    advance_acquire: Duration,
    advance_renew: Duration,
    acquire_calls: usize,
    renew_calls: usize,
    release_calls: usize,
    released_pair: Option<(u64, u64)>,
    release_kernel_probe: Option<Arc<TestKernel>>,
    release_observed_kernel_closed: Option<bool>,
    release_endpoint_probe: Option<SocketAddr>,
    release_observed_socket_closed: Option<bool>,
}

struct TestAuthority {
    backend: FakeSessionBackend,
    clock: Arc<TestBootClock>,
    state: Mutex<TestAuthorityState>,
}

impl TestAuthority {
    fn new(
        clock: Arc<TestBootClock>,
        prior: DurablePriorFenceState,
        generation: u64,
        socket_token: u64,
        retirement_token: u64,
    ) -> Self {
        Self {
            backend: FakeSessionBackend::new(),
            clock,
            state: Mutex::new(TestAuthorityState {
                prior: Some(prior),
                generation: nonzero(generation),
                socket_token: nonzero(socket_token),
                retirement_token: nonzero(retirement_token),
                fail_acquire: false,
                fail_renew: false,
                fail_release: false,
                pending_acquire_after_grant: false,
                pending_renew_after_grant: false,
                pending_release_before_commit: false,
                acquire_wrong_key: false,
                acquire_wrong_owner: false,
                acquired_guard_mutation: AcquiredGuardMutation::None,
                return_stale_renewal: false,
                renewed_guard_mutation: RenewedGuardMutation::None,
                last_returned_renewal: None,
                advance_acquire: Duration::ZERO,
                advance_renew: Duration::ZERO,
                acquire_calls: 0,
                renew_calls: 0,
                release_calls: 0,
                released_pair: None,
                release_kernel_probe: None,
                release_observed_kernel_closed: None,
                release_endpoint_probe: None,
                release_observed_socket_closed: None,
            }),
        }
    }

    fn configure(&self, update: impl FnOnce(&mut TestAuthorityState)) {
        update(&mut self.state.lock().expect("test authority lock"));
    }

    fn renew_calls(&self) -> usize {
        self.state.lock().expect("test authority lock").renew_calls
    }

    fn last_returned_renewal(&self) -> Option<LeaseGuard> {
        self.state
            .lock()
            .expect("test authority lock")
            .last_returned_renewal
            .clone()
    }

    fn acquire_calls(&self) -> usize {
        self.state
            .lock()
            .expect("test authority lock")
            .acquire_calls
    }

    fn release_calls(&self) -> usize {
        self.state
            .lock()
            .expect("test authority lock")
            .release_calls
    }

    fn released_pair(&self) -> Option<(u64, u64)> {
        self.state
            .lock()
            .expect("test authority lock")
            .released_pair
    }

    fn release_observed_kernel_closed(&self) -> Option<bool> {
        self.state
            .lock()
            .expect("test authority lock")
            .release_observed_kernel_closed
    }

    fn release_observed_socket_closed(&self) -> Option<bool> {
        self.state
            .lock()
            .expect("test authority lock")
            .release_observed_socket_closed
    }
}

#[async_trait]
impl EgressFenceLeaseAuthority for TestAuthority {
    type Error = AuthorityFailure;

    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
        _current_attachment: FenceAttachmentIdentity,
        _current_gate_lifetime: Duration,
    ) -> Result<FenceLeaseGrant, Self::Error> {
        let (
            fail,
            pending_after_grant,
            wrong_key,
            wrong_owner,
            guard_mutation,
            advance,
            prior,
            generation,
            socket_token,
            retirement_token,
        ) = {
            let mut state = self.state.lock().expect("test authority lock");
            state.acquire_calls += 1;
            (
                state.fail_acquire,
                state.pending_acquire_after_grant,
                state.acquire_wrong_key,
                state.acquire_wrong_owner,
                state.acquired_guard_mutation,
                state.advance_acquire,
                state.prior.take(),
                state.generation,
                state.socket_token,
                state.retirement_token,
            )
        };
        if fail {
            return Err(AuthorityFailure::Acquire);
        }
        let supplied_key = if wrong_key { other_key() } else { key.clone() };
        let supplied_owner = if wrong_owner { other_owner() } else { owner };
        let guard = SessionLeaseManager::acquire(&self.backend, &supplied_key, supplied_owner, ttl)
            .await
            .map_err(|_| AuthorityFailure::Acquire)?;
        let guard = mutate_acquired_guard(guard, guard_mutation)?;
        self.clock.advance(advance);
        if pending_after_grant {
            let _unreleased_guard = guard;
            return pending::<Result<FenceLeaseGrant, Self::Error>>().await;
        }
        FenceLeaseGrant::from_verified_authority_transaction(
            guard,
            socket_token,
            retirement_token,
            prior.unwrap_or_else(
                DurablePriorFenceState::attachment_unknown_under_continuous_authority,
            ),
            generation,
        )
        .map_err(|_| AuthorityFailure::Contract)
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, Self::Error> {
        let (fail, pending_after_grant, return_stale, mutation, advance) = {
            let mut state = self.state.lock().expect("test authority lock");
            state.renew_calls += 1;
            (
                state.fail_renew,
                state.pending_renew_after_grant,
                state.return_stale_renewal,
                state.renewed_guard_mutation,
                state.advance_renew,
            )
        };
        if fail {
            return Err(AuthorityFailure::Renew);
        }
        if return_stale {
            self.clock.advance(advance);
            let returned = lease.clone();
            self.state
                .lock()
                .expect("test authority lock")
                .last_returned_renewal = Some(returned.clone());
            return Ok(returned);
        }
        let renewed = SessionLeaseManager::renew(&self.backend, lease, ttl)
            .await
            .map_err(|_| AuthorityFailure::Renew)?;
        let renewed = mutate_renewed_guard(renewed, lease, mutation)?;
        self.state
            .lock()
            .expect("test authority lock")
            .last_returned_renewal = Some(renewed.clone());
        self.clock.advance(advance);
        if pending_after_grant {
            let _unreleased_guard = renewed;
            return pending::<Result<LeaseGuard, Self::Error>>().await;
        }
        Ok(renewed)
    }

    async fn release_with_terminal(
        &self,
        lease: LeaseGuard,
        evidence: TerminalClosureEvidence,
    ) -> Result<(), Self::Error> {
        let (fail, pending_before_commit, kernel_probe) = {
            let mut state = self.state.lock().expect("test authority lock");
            state.release_calls += 1;
            state.released_pair = Some((
                evidence.socket_lifecycle_token().get(),
                evidence.retirement_lifecycle_token().get(),
            ));
            (
                state.fail_release,
                state.pending_release_before_commit,
                state.release_kernel_probe.clone(),
            )
        };
        if let Some(kernel) = kernel_probe {
            let observed = kernel.current().phase == KernelCurrentPhase::RetirementClosed
                && kernel.entry_count() == 0
                && kernel.events().ends_with(&["close", "publish", "reclaim"]);
            self.state
                .lock()
                .expect("test authority lock")
                .release_observed_kernel_closed = Some(observed);
        }
        let endpoint_probe = self
            .state
            .lock()
            .expect("test authority lock")
            .release_endpoint_probe;
        if let Some(endpoint) = endpoint_probe {
            let observed = std::net::UdpSocket::bind(endpoint).is_ok();
            self.state
                .lock()
                .expect("test authority lock")
                .release_observed_socket_closed = Some(observed);
        }
        if pending_before_commit {
            let _unreleased_lease = lease;
            let _terminal_evidence = evidence;
            return pending::<Result<(), Self::Error>>().await;
        }
        if fail {
            return Err(AuthorityFailure::Release);
        }
        SessionLeaseManager::release(&self.backend, lease)
            .await
            .map_err(|_| AuthorityFailure::Release)
    }
}

fn mutate_renewed_guard(
    guard: LeaseGuard,
    current: &LeaseGuard,
    mutation: RenewedGuardMutation,
) -> Result<LeaseGuard, AuthorityFailure> {
    if mutation == RenewedGuardMutation::None {
        return Ok(guard);
    }
    let mut encoded = serde_json::to_value(guard).map_err(|_| AuthorityFailure::Contract)?;
    match mutation {
        RenewedGuardMutation::None => {}
        RenewedGuardMutation::ZeroInterval => {
            encoded["expires_at"] = encoded["acquired_at"].clone();
        }
        RenewedGuardMutation::ShortPositiveInterval => {
            let expires_at = opc_session_store::checked_session_deadline(
                current.expires_at(),
                Duration::from_secs(1),
            )
            .map_err(|_| AuthorityFailure::Contract)?;
            encoded["expires_at"] =
                serde_json::to_value(expires_at).map_err(|_| AuthorityFailure::Contract)?;
        }
        RenewedGuardMutation::UnrepresentableInterval => {
            encoded["expires_at"] =
                serde_json::Value::String("9999-12-31T23:59:59.999999999Z".to_owned());
        }
        RenewedGuardMutation::RegressAcquiredAt => {
            encoded["acquired_at"] = serde_json::Value::String("1970-01-01T00:00:00Z".to_owned());
        }
        RenewedGuardMutation::ZeroFence => {
            encoded["fence"] = serde_json::Value::from(0);
        }
        RenewedGuardMutation::ZeroCredential => {
            encoded["credential_id"] = serde_json::Value::from(0);
        }
    }
    serde_json::from_value(encoded).map_err(|_| AuthorityFailure::Contract)
}

fn mutate_acquired_guard(
    guard: LeaseGuard,
    mutation: AcquiredGuardMutation,
) -> Result<LeaseGuard, AuthorityFailure> {
    if mutation == AcquiredGuardMutation::None {
        return Ok(guard);
    }
    let mut encoded = serde_json::to_value(guard).map_err(|_| AuthorityFailure::Contract)?;
    match mutation {
        AcquiredGuardMutation::None => {}
        AcquiredGuardMutation::ShortPositiveInterval => {
            let acquired_at: Timestamp = serde_json::from_value(encoded["acquired_at"].clone())
                .map_err(|_| AuthorityFailure::Contract)?;
            let expires_at =
                opc_session_store::checked_session_deadline(acquired_at, Duration::from_secs(1))
                    .map_err(|_| AuthorityFailure::Contract)?;
            encoded["expires_at"] =
                serde_json::to_value(expires_at).map_err(|_| AuthorityFailure::Contract)?;
        }
        AcquiredGuardMutation::TimestampArithmeticOverflow => {
            encoded["acquired_at"] = serde_json::Value::String("9999-12-31T23:59:59Z".to_owned());
            encoded["expires_at"] =
                serde_json::Value::String("9999-12-31T23:59:59.999999999Z".to_owned());
        }
        AcquiredGuardMutation::ZeroFence => {
            encoded["fence"] = serde_json::Value::from(0);
        }
        AcquiredGuardMutation::ZeroCredential => {
            encoded["credential_id"] = serde_json::Value::from(0);
        }
    }
    serde_json::from_value(encoded).map_err(|_| AuthorityFailure::Contract)
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("nonzero fixture")
}

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("fixture-tenant").expect("fixture tenant"),
        nf_kind: NetworkFunctionKind::from_static("fixture-nf"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"fixture-stable-id"))
            .expect("fixture stable id"),
    }
}

fn other_key() -> SessionKey {
    SessionKey {
        stable_id: StableId::new(Bytes::from_static(b"other-stable-id"))
            .expect("other fixture stable id"),
        ..key()
    }
}

fn owner() -> OwnerId {
    OwnerId::new("fixture-owner").expect("fixture owner")
}

fn other_owner() -> OwnerId {
    OwnerId::new("other-owner").expect("other fixture owner")
}

fn durable_identity(byte: u8) -> FenceAttachmentIdentity {
    FenceAttachmentIdentity::from_live_digest([byte; 32]).expect("nonzero fixture digest")
}

fn attachment(
    durable: FenceAttachmentIdentity,
    inventory: AttachmentInventory,
) -> AttachmentIdentity {
    AttachmentIdentity { durable, inventory }
}

fn timing(ttl_seconds: u64, margin_seconds: u64) -> LeaseFenceTiming {
    LeaseFenceTiming::new(
        Duration::from_secs(ttl_seconds),
        Duration::from_secs(margin_seconds),
    )
    .expect("valid fixture timing")
}

fn unregistered_fence(
    identity: AttachmentIdentity,
    kernel: Arc<TestKernel>,
    clock: Arc<TestBootClock>,
) -> LeaseBoundFence {
    let kernel_boundary: Arc<dyn KernelControl> = kernel;
    let clock_boundary: Arc<dyn BootClock> = clock;
    LeaseBoundFence::from_unregistered(kernel_boundary, clock_boundary, identity, SOCKET_COOKIE)
        .expect("unregistered fixture")
}

async fn activated_fixture(
    identity_byte: u8,
) -> (
    LeaseBoundFence,
    Arc<TestKernel>,
    Arc<TestBootClock>,
    TestAuthority,
    LeaseGuard,
) {
    let durable = durable_identity(identity_byte);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("fixture activation");
    (fence, kernel, clock, authority, guard)
}

#[test]
fn attachment_identity_round_trip_is_redacted() {
    let identity = durable_identity(7);
    assert_eq!(
        FenceAttachmentIdentity::decode(&identity.encode()),
        Some(identity)
    );
    assert_eq!(
        format!("{identity:?}"),
        "FenceAttachmentIdentity(<redacted>)"
    );
}

#[test]
fn timing_rejects_a_gate_above_the_frozen_ceiling() {
    assert_eq!(
        LeaseFenceTiming::new(
            Duration::from_nanos(EGRESS_FENCE_MAX_GATE_LIFETIME_NS + 2),
            Duration::from_nanos(1),
        ),
        Err(FenceError::InvalidTiming)
    );
}

#[tokio::test]
async fn nanosecond_timing_renewal_wait_makes_finite_progress() {
    let durable = durable_identity(60);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel, clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let timing = LeaseFenceTiming::new(Duration::from_nanos(3), Duration::from_nanos(1))
        .expect("nanosecond timing");
    let _guard = fence
        .acquire(&authority, &key(), owner(), timing)
        .await
        .expect("nanosecond activation");
    let before = clock.now();

    tokio::time::timeout(
        Duration::from_millis(100),
        fence.renewal_wait(timing).expect("renewal wait").wait(),
    )
    .await
    .expect("renewal wait must not spin")
    .expect("renewal wait");

    assert_eq!(clock.now(), before + 1);
    assert_eq!(clock.waits.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_prior_rejects_nonincreasing_token_pairs() {
    assert!(matches!(
        DurablePriorFenceState::last_attachment(
            durable_identity(1),
            nonzero(8),
            nonzero(8),
            Duration::from_secs(1),
            nonzero(2),
        ),
        Err(FenceError::InvalidPriorEvidence)
    ));
    assert!(matches!(
        DurablePriorFenceState::verified_terminal(
            durable_identity(1),
            nonzero(9),
            nonzero(8),
            nonzero(2),
        ),
        Err(FenceError::InvalidPriorEvidence)
    ));
}

#[tokio::test]
async fn fresh_install_orders_publish_register_activate_with_distinct_tokens() {
    for inventory in [
        AttachmentInventory::InstalledClosedWithExactReadback,
        AttachmentInventory::AdoptedNeverActivated,
    ] {
        let durable = durable_identity(1);
        let identity = attachment(durable, inventory);
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );

        let guard = fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await
            .expect("fresh activation");

        assert!(fence.is_active());
        assert!(guard.fence().get() != SOCKET_TOKEN);
        assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
        assert_eq!(
            kernel.current(),
            KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token: SOCKET_TOKEN,
                registered_socket_cookie: SOCKET_COOKIE,
            }
        );
        assert_eq!(
            kernel.entry(SOCKET_COOKIE, SOCKET_TOKEN),
            Some(KernelFenceEntry {
                state: KernelEntryState::Active,
                socket_cookie: SOCKET_COOKIE,
                lifecycle_token: SOCKET_TOKEN,
                deadline_boot_ns: INITIAL_BOOT_NS + Duration::from_secs(9).as_nanos() as u64,
                control_epoch: 2,
            })
        );
    }
}

#[tokio::test]
async fn acquisition_rejects_a_guard_for_the_wrong_key_or_owner_before_publication() {
    for configure in [(true, false), (false, true)] {
        let durable = durable_identity(45);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );
        authority.configure(|state| {
            state.acquire_wrong_key = configure.0;
            state.acquire_wrong_owner = configure.1;
        });

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(10, 1))
                .await,
            "misbound durable guard must fail closed",
        );

        assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
        assert!(error.into_unreleased_lease().is_some());
        assert!(kernel.events().is_empty());
        assert_eq!(kernel.entry_count(), 0);
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn acquisition_rejects_zero_fence_or_credential_before_publication() {
    for mutation in [
        AcquiredGuardMutation::ZeroFence,
        AcquiredGuardMutation::ZeroCredential,
    ] {
        let durable = durable_identity(56);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );
        authority.configure(|state| state.acquired_guard_mutation = mutation);

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(10, 1))
                .await,
            "zero authority identity must fail closed",
        );

        assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
        assert!(error.into_unreleased_lease().is_some());
        assert!(kernel.events().is_empty());
        assert_eq!(kernel.entry_count(), 0);
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn acquisition_rejects_a_positive_interval_shorter_than_the_requested_ttl() {
    let durable = durable_identity(57);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| {
        state.acquired_guard_mutation = AcquiredGuardMutation::ShortPositiveInterval;
    });

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "short positive authority interval must fail closed",
    );

    assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
    assert!(error.into_unreleased_lease().is_some());
    assert!(kernel.events().is_empty());
    assert_eq!(kernel.entry_count(), 0);
    assert!(!fence.is_active());
}

#[tokio::test]
async fn acquisition_rejects_timestamp_arithmetic_overflow_before_publication() {
    let durable = durable_identity(59);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| {
        state.acquired_guard_mutation = AcquiredGuardMutation::TimestampArithmeticOverflow;
    });

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "overflowing authority timestamp arithmetic must fail closed",
    );

    assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
    assert!(error.into_unreleased_lease().is_some());
    assert!(kernel.events().is_empty());
    assert_eq!(kernel.entry_count(), 0);
    assert!(!fence.is_active());
}

#[tokio::test]
async fn clock_failure_before_acquisition_never_contacts_authority_or_kernel() {
    let durable = durable_identity(20);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    clock.fail_next_reads(1);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "unavailable BOOTTIME must stop before authority",
    );

    assert_eq!(error.fence_error(), Some(FenceError::ClockUnavailable));
    assert_eq!(authority.acquire_calls(), 0);
    assert!(kernel.events().is_empty());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn clock_failure_or_regression_after_acquisition_retains_authority_closed() {
    for second_read in [
        Err(KernelFailure::Clock),
        Ok(INITIAL_BOOT_NS.saturating_sub(1)),
    ] {
        let durable = durable_identity(21);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        clock.script_reads([Ok(INITIAL_BOOT_NS), second_read]);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(10, 1))
                .await,
            "post-grant clock ambiguity must retain authority",
        );

        assert_eq!(error.fence_error(), Some(FenceError::ClockUnavailable));
        assert!(error.into_unreleased_lease().is_some());
        assert!(kernel.events().is_empty());
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn preapply_kernel_mutations_and_readback_failure_fail_closed() {
    for (fault, expected) in [
        (KernelFault::InspectNext, FenceError::KernelReadback),
        (KernelFault::PublishBefore, FenceError::KernelMutation),
        (KernelFault::RegisterBefore, FenceError::KernelMutation),
        (KernelFault::ActivateBefore, FenceError::KernelMutation),
    ] {
        let durable = durable_identity(22);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        kernel.set_fault(fault);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(10, 1))
                .await,
            "ambiguous kernel transition must not activate",
        );

        assert_eq!(error.fence_error(), Some(expected));
        assert!(error.into_unreleased_lease().is_some());
        assert!(!fence.is_active());
        assert!(!kernel
            .entry(SOCKET_COOKIE, SOCKET_TOKEN)
            .is_some_and(|entry| entry.state == KernelEntryState::Active));
    }
}

#[tokio::test]
async fn exact_applied_errors_are_resolved_by_readback() {
    for fault in [
        KernelFault::PublishAfter,
        KernelFault::RegisterAfter,
        KernelFault::ActivateAfter,
    ] {
        let durable = durable_identity(2);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        kernel.set_fault(fault);
        let mut fence = unregistered_fence(identity, kernel, clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );

        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await
            .expect("exact applied outcome is accepted");
    }
}

#[tokio::test]
async fn redundant_value_identity_mismatch_fails_closed_and_retains_lease() {
    let durable = durable_identity(3);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    kernel.set_fault(KernelFault::CorruptNextEntryRead);
    let mut fence = unregistered_fence(identity, kernel, clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "corrupt redundant identity must fail",
    );

    assert_eq!(error.fence_error(), Some(FenceError::KernelReadback));
    assert!(error.into_unreleased_lease().is_some());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn same_attachment_crash_state_uses_pair_highwater_without_waiting() {
    let durable = durable_identity(4);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let prior_socket = 11;
    let prior_retirement = 12;
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: prior_socket,
            registered_socket_cookie: SOCKET_COOKIE,
        },
        8,
    );
    kernel.seed_entry(KernelFenceEntry {
        state: KernelEntryState::Active,
        socket_cookie: SOCKET_COOKIE,
        lifecycle_token: prior_socket,
        deadline_boot_ns: INITIAL_BOOT_NS + 1,
        control_epoch: 2,
    });
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::last_attachment(
            durable,
            nonzero(prior_socket),
            nonzero(prior_retirement),
            Duration::from_secs(9),
            nonzero(7),
        )
        .expect("valid prior"),
        8,
        13,
        14,
    );

    fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("same attachment replacement");

    assert_eq!(clock.waits.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.current().lifecycle_token, 13);
    assert!(kernel.entry(SOCKET_COOKIE, prior_socket).is_none());
    assert!(kernel.entry(SOCKET_COOKIE, 13).is_some());
    assert_eq!(
        kernel.events(),
        vec!["publish", "cleanup", "register", "activate"]
    );
}

#[tokio::test]
async fn same_attachment_publish_before_register_crash_uses_pair_highwater() {
    let durable = durable_identity(51);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let prior_socket = 11;
    let prior_retirement = 12;
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: prior_socket,
            registered_socket_cookie: 0,
        },
        8,
    );
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::last_attachment(
            durable,
            nonzero(prior_socket),
            nonzero(prior_retirement),
            Duration::from_secs(9),
            nonzero(7),
        )
        .expect("valid prior"),
        8,
        13,
        14,
    );

    fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("published-before-register replacement");

    assert_eq!(clock.waits.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.current().lifecycle_token, 13);
    assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
}

#[tokio::test]
async fn never_activated_adoption_accepts_same_attachment_burned_pair_highwater() {
    let durable = durable_identity(52);
    let identity = attachment(durable, AttachmentInventory::AdoptedNeverActivated);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::last_attachment(
            durable,
            nonzero(11),
            nonzero(12),
            Duration::from_secs(9),
            nonzero(7),
        )
        .expect("valid never-activated prior"),
        8,
        13,
        14,
    );

    fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("never-activated same-attachment replacement");

    assert_eq!(clock.waits.load(Ordering::SeqCst), 0);
    assert_eq!(kernel.current().lifecycle_token, 13);
    assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
}

#[tokio::test]
async fn stale_cleanup_failure_never_registers_or_activates_the_successor() {
    for fault in [
        KernelFault::CleanupBefore,
        KernelFault::CleanupDelete,
        KernelFault::CleanupAfter,
    ] {
        let durable = durable_identity(40);
        let identity = attachment(durable, AttachmentInventory::AdoptedExact);
        let prior_socket = 11;
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::new(
            identity,
            KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token: prior_socket,
                registered_socket_cookie: SOCKET_COOKIE,
            },
            8,
        );
        kernel.seed_entry(KernelFenceEntry {
            state: KernelEntryState::Active,
            socket_cookie: SOCKET_COOKIE,
            lifecycle_token: prior_socket,
            deadline_boot_ns: INITIAL_BOOT_NS + 1,
            control_epoch: 2,
        });
        kernel.set_fault(fault);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::last_attachment(
                durable,
                nonzero(prior_socket),
                nonzero(prior_socket + 1),
                Duration::from_secs(9),
                nonzero(7),
            )
            .expect("valid prior"),
            8,
            13,
            14,
        );

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(10, 1))
                .await,
            "cleanup ambiguity must fail closed",
        );

        assert_eq!(error.fence_error(), Some(FenceError::KernelMutation));
        assert!(error.into_unreleased_lease().is_some());
        assert!(!fence.is_active());
        assert_eq!(
            kernel.current(),
            KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token: 13,
                registered_socket_cookie: 0,
            }
        );
        assert!(kernel.entry(SOCKET_COOKIE, 13).is_none());
        if fault == KernelFault::CleanupDelete {
            assert_eq!(
                kernel.entry(SOCKET_COOKIE, prior_socket),
                Some(KernelFenceEntry {
                    state: KernelEntryState::Reclaiming,
                    socket_cookie: SOCKET_COOKIE,
                    lifecycle_token: prior_socket,
                    deadline_boot_ns: 0,
                    control_epoch: 2,
                })
            );
        }
        kernel
            .cleanup_superseded(identity, 13)
            .expect("retry superseded cleanup");
        assert!(kernel.entry(SOCKET_COOKIE, prior_socket).is_none());
    }
}

#[tokio::test]
async fn verified_terminal_requires_the_reserved_retirement_publication() {
    let durable = durable_identity(5);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: 21,
            registered_socket_cookie: SOCKET_COOKIE,
        },
        8,
    );
    let mut fence = unregistered_fence(identity, kernel, clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::verified_terminal(durable, nonzero(21), nonzero(22), nonzero(7))
            .expect("valid terminal prior"),
        8,
        23,
        24,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "terminal evidence without CURRENT retirement token is invalid",
    );

    assert_eq!(error.fence_error(), Some(FenceError::KernelReadback));
    assert!(error.into_unreleased_lease().is_some());
}

#[tokio::test]
async fn verified_terminal_adopts_the_exact_retirement_closed_attachment() {
    let durable = durable_identity(27);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::RetirementClosed,
            lifecycle_token: 22,
            registered_socket_cookie: 0,
        },
        8,
    );
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::verified_terminal(durable, nonzero(21), nonzero(22), nonzero(7))
            .expect("canonical terminal evidence"),
        8,
        23,
        24,
    );

    fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("exact terminal adoption");

    assert!(fence.is_active());
    assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
    assert_eq!(
        kernel.current(),
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: 23,
            registered_socket_cookie: SOCKET_COOKIE,
        }
    );
}

#[tokio::test]
async fn verified_terminal_allows_a_new_closed_attachment_generation() {
    for inventory in [
        AttachmentInventory::InstalledClosedWithExactReadback,
        AttachmentInventory::AdoptedNeverActivated,
    ] {
        let live = durable_identity(28);
        let identity = attachment(live, inventory);
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::verified_terminal(
                durable_identity(29),
                nonzero(21),
                nonzero(22),
                nonzero(7),
            )
            .expect("canonical terminal evidence"),
            8,
            23,
            24,
        );

        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await
            .expect("offline replacement activation");

        assert!(fence.is_active());
        assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
        assert_eq!(
            kernel.current(),
            KernelCurrentFence {
                phase: KernelCurrentPhase::LifecycleOpen,
                lifecycle_token: 23,
                registered_socket_cookie: SOCKET_COOKIE,
            }
        );
    }
}

#[tokio::test]
async fn unknown_attachment_evidence_fails_closed_without_a_timed_repair() {
    let durable = durable_identity(6);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::attachment_unknown_under_continuous_authority(),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(120, 20))
            .await,
        "unknown attachment evidence must fail closed",
    );

    assert_eq!(error.fence_error(), Some(FenceError::InvalidPriorEvidence));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(clock.now(), INITIAL_BOOT_NS);
    assert_eq!(clock.waits.load(Ordering::SeqCst), 0);
    assert_eq!(authority.renew_calls(), 0);
    assert!(kernel.events().is_empty());
    assert_eq!(kernel.entry_count(), 0);
}

#[tokio::test]
async fn acquisition_over_budget_retains_the_guard_and_inserts_nothing() {
    let durable = durable_identity(7);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| state.advance_acquire = Duration::from_secs(9));

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await,
        "operation consumed full gate budget",
    );

    assert_eq!(error.fence_error(), Some(FenceError::OperationOverBudget));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(kernel.entry_count(), 0);
}

#[tokio::test]
async fn different_live_attachment_identity_is_not_repaired_by_a_delay() {
    for inventory in [
        AttachmentInventory::AdoptedExact,
        AttachmentInventory::AdoptedNeverActivated,
        AttachmentInventory::InstalledClosedWithExactReadback,
    ] {
        let live = durable_identity(8);
        let identity = attachment(live, inventory);
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock.clone(),
            DurablePriorFenceState::last_attachment(
                durable_identity(9),
                nonzero(99),
                nonzero(100),
                Duration::from_secs(9),
                nonzero(1),
            )
            .expect("canonical prior attachment"),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );

        let error = expect_lease_fence_error(
            fence
                .acquire(&authority, &key(), owner(), timing(120, 20))
                .await,
            "mismatched live attachment must fail closed",
        );

        assert_eq!(error.fence_error(), Some(FenceError::InvalidPriorEvidence));
        assert!(error.into_unreleased_lease().is_some());
        assert_eq!(clock.waits.load(Ordering::SeqCst), 0);
        assert_eq!(authority.renew_calls(), 0);
        assert!(kernel.events().is_empty());
        assert_eq!(kernel.entry_count(), 0);
    }
}

#[tokio::test]
async fn verified_terminal_for_a_different_attachment_cannot_adopt_live_state() {
    let live = durable_identity(25);
    let identity = attachment(live, AttachmentInventory::AdoptedExact);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::verified_terminal(
            durable_identity(26),
            nonzero(21),
            nonzero(22),
            nonzero(1),
        )
        .expect("canonical terminal evidence"),
        2,
        23,
        24,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(120, 20))
            .await,
        "terminal evidence for a different attachment cannot authorize adoption",
    );

    assert_eq!(error.fence_error(), Some(FenceError::InvalidPriorEvidence));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(authority.renew_calls(), 0);
    assert_eq!(kernel.entry_count(), 0);
    assert!(kernel.events().is_empty());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn adopted_attachment_rejects_a_fresh_install_claim() {
    let durable = durable_identity(23);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(120, 20))
            .await,
        "adoption cannot use fresh-install evidence",
    );

    assert_eq!(error.fence_error(), Some(FenceError::InvalidPriorEvidence));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(authority.renew_calls(), 0);
    assert_eq!(kernel.entry_count(), 0);
    assert!(kernel.events().is_empty());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn never_activated_inventory_rejects_noninitial_current_for_fresh_claim() {
    let durable = durable_identity(53);
    let identity = attachment(durable, AttachmentInventory::AdoptedNeverActivated);
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: 99,
            registered_socket_cookie: 0,
        },
        8,
    );
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );

    let error = expect_lease_fence_error(
        fence
            .acquire(&authority, &key(), owner(), timing(120, 20))
            .await,
        "never-activated inventory requires exact uninitialized CURRENT",
    );

    assert_eq!(error.fence_error(), Some(FenceError::KernelReadback));
    assert!(error.into_unreleased_lease().is_some());
    assert!(kernel.events().is_empty());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn cancellation_after_ambiguous_authority_acquire_closes_local_capability() {
    let durable = durable_identity(24);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| state.pending_acquire_after_grant = true);
    let session_key = key();
    let mut future = Box::pin(fence.acquire(&authority, &session_key, owner(), timing(10, 1)));

    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("ambiguous acquisition unexpectedly completed"),
    })
    .await;
    drop(future);

    assert_eq!(authority.acquire_calls(), 1);
    assert_eq!(kernel.entry_count(), 0);
    assert!(kernel.events().is_empty());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn renewal_preserves_lifecycle_pair_and_refreshes_without_publication() {
    let durable = durable_identity(9);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("activation");
    let renewed = fence
        .renew(&authority, guard, timing(10, 1))
        .await
        .expect("renewal");

    assert_eq!(renewed.fence().get(), 1);
    assert_eq!(
        kernel.events(),
        vec!["publish", "register", "activate", "refresh"]
    );
    assert_eq!(kernel.current().lifecycle_token, SOCKET_TOKEN);
}

#[tokio::test]
async fn unchanged_successful_renewal_guard_never_refreshes_the_kernel_deadline() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(46).await;
    authority.configure(|state| state.return_stale_renewal = true);

    let error = expect_lease_fence_error(
        fence.renew(&authority, guard, timing(10, 1)).await,
        "unchanged authority expiry is not a renewal",
    );

    assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(
        kernel.events(),
        vec!["publish", "register", "activate", "close"]
    );
    assert!(!fence.is_active());
}

#[tokio::test]
async fn malformed_renewed_guard_time_interval_never_refreshes_the_kernel_deadline() {
    for mutation in [
        RenewedGuardMutation::ZeroInterval,
        RenewedGuardMutation::UnrepresentableInterval,
        RenewedGuardMutation::RegressAcquiredAt,
        RenewedGuardMutation::ZeroFence,
        RenewedGuardMutation::ZeroCredential,
    ] {
        let (mut fence, kernel, _clock, authority, guard) = activated_fixture(55).await;
        authority.configure(|state| state.renewed_guard_mutation = mutation);

        let error = expect_lease_fence_error(
            fence.renew(&authority, guard, timing(10, 1)).await,
            "malformed renewed time interval",
        );

        assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
        let returned = authority
            .last_returned_renewal()
            .expect("successful authority renewal");
        let retained = error
            .into_unreleased_lease()
            .expect("post-renewal failure retains a guard");
        assert!(
            retained == returned,
            "post-renewal validation must retain the returned guard"
        );
        assert!(!kernel.events().contains(&"refresh"));
        assert_eq!(kernel.events().last(), Some(&"close"));
    }
}

#[tokio::test]
async fn renewal_rejects_a_positive_interval_shorter_than_the_requested_ttl() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(58).await;
    fence
        .renewal_wait(timing(10, 1))
        .expect("renewal schedule")
        .wait()
        .await
        .expect("half-window wait");
    authority.configure(|state| {
        state.renewed_guard_mutation = RenewedGuardMutation::ShortPositiveInterval;
    });

    let error = expect_lease_fence_error(
        fence.renew(&authority, guard, timing(10, 1)).await,
        "short positive renewed interval must fail closed",
    );

    assert_eq!(error.fence_error(), Some(FenceError::LeaseContinuity));
    let returned = authority
        .last_returned_renewal()
        .expect("successful authority renewal");
    let retained = error
        .into_unreleased_lease()
        .expect("post-renewal failure retains a guard");
    assert!(
        retained == returned,
        "short renewal must retain the returned guard"
    );
    assert!(!kernel.events().contains(&"refresh"));
    assert_eq!(kernel.events().last(), Some(&"close"));
    assert!(!fence.is_active());
}

#[tokio::test]
async fn renewal_schedule_uses_the_operation_start_kernel_window() {
    let (mut fence, _kernel, clock, _authority, _guard) = activated_fixture(47).await;

    fence
        .renewal_wait(timing(10, 1))
        .expect("renewal schedule")
        .wait()
        .await
        .expect("half-window wait");

    assert_eq!(
        clock.now(),
        INITIAL_BOOT_NS + Duration::from_millis(4_500).as_nanos() as u64
    );
}

#[tokio::test]
async fn clock_regression_after_renewal_wait_never_reaches_authority_or_refresh() {
    let (mut fence, kernel, clock, authority, guard) = activated_fixture(54).await;
    fence
        .renewal_wait(timing(10, 1))
        .expect("renewal schedule")
        .wait()
        .await
        .expect("half-window wait");
    clock.script_reads([Ok(
        INITIAL_BOOT_NS + Duration::from_secs(1).as_nanos() as u64
    )]);

    let error = expect_lease_fence_error(
        fence.renew(&authority, guard, timing(10, 1)).await,
        "regression below the wait observation",
    );

    assert_eq!(error.fence_error(), Some(FenceError::ClockUnavailable));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(authority.renew_calls(), 0);
    assert!(!kernel.events().contains(&"refresh"));
    assert_eq!(kernel.events().last(), Some(&"close"));
}

#[tokio::test]
async fn near_budget_acquisition_makes_renewal_immediately_due() {
    let durable = durable_identity(48);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel, clock.clone());
    let authority = TestAuthority::new(
        clock.clone(),
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| state.advance_acquire = Duration::from_secs(8));
    let _guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("near-budget activation");
    let before = clock.now();

    fence
        .renewal_wait(timing(10, 1))
        .expect("renewal schedule")
        .wait()
        .await
        .expect("already due");

    assert_eq!(clock.now(), before);
}

#[tokio::test]
async fn suspend_jump_past_deadline_fails_the_renewal_wait_closed() {
    let (mut fence, _kernel, clock, _authority, _guard) = activated_fixture(49).await;
    let wait = fence.renewal_wait(timing(10, 1)).expect("renewal schedule");
    clock.advance(Duration::from_secs(9));

    assert_eq!(wait.wait().await, Err(FenceError::GateExpired));
}

#[tokio::test]
async fn renewal_failure_returns_the_exact_unreleased_guard() {
    let durable = durable_identity(10);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel, clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("activation");
    let expected = guard.clone();
    authority.configure(|state| state.fail_renew = true);

    let error = expect_lease_fence_error(
        fence.renew(&authority, guard, timing(10, 1)).await,
        "renewal failure",
    );
    let retained = error
        .into_unreleased_lease()
        .expect("post-grant failure retains lease");

    assert!(retained == expected);
    assert!(!fence.is_active());
}

#[tokio::test]
async fn over_budget_renewal_never_refreshes_and_terminal_closes() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(25).await;
    authority.configure(|state| state.advance_renew = Duration::from_secs(9));

    let error = expect_lease_fence_error(
        fence.renew(&authority, guard, timing(10, 1)).await,
        "renewal completion at the deadline is over budget",
    );

    assert_eq!(error.fence_error(), Some(FenceError::OperationOverBudget));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(
        kernel.events(),
        vec!["publish", "register", "activate", "close"]
    );
    assert_eq!(
        kernel
            .entry(SOCKET_COOKIE, SOCKET_TOKEN)
            .expect("terminal tombstone")
            .state,
        KernelEntryState::TerminalClosed
    );
    assert!(!fence.is_active());
}

#[tokio::test]
async fn renewal_clock_regression_and_failure_close_without_refresh() {
    for reads in [
        vec![Err(KernelFailure::Clock)],
        vec![Ok(INITIAL_BOOT_NS), Ok(INITIAL_BOOT_NS - 1)],
    ] {
        let (mut fence, kernel, clock, authority, guard) = activated_fixture(26).await;
        clock.script_reads(reads);

        let error = expect_lease_fence_error(
            fence.renew(&authority, guard, timing(10, 1)).await,
            "clock ambiguity must stop renewal",
        );

        assert_eq!(error.fence_error(), Some(FenceError::ClockUnavailable));
        assert!(error.into_unreleased_lease().is_some());
        assert!(!kernel.events().contains(&"refresh"));
        assert_eq!(kernel.events().last(), Some(&"close"));
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn renewal_map_and_entry_readback_failures_terminal_close() {
    for (fault, expected) in [
        (KernelFault::RefreshBefore, FenceError::KernelMutation),
        (
            KernelFault::CorruptNextEntryRead,
            FenceError::KernelReadback,
        ),
    ] {
        let (mut fence, kernel, _clock, authority, guard) = activated_fixture(27).await;
        kernel.set_fault(fault);

        let error = expect_lease_fence_error(
            fence.renew(&authority, guard, timing(10, 1)).await,
            "renewal ambiguity must terminal-close",
        );

        assert_eq!(error.fence_error(), Some(expected));
        assert!(error.into_unreleased_lease().is_some());
        assert_eq!(kernel.events().last(), Some(&"close"));
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn cancellation_after_ambiguous_renewal_terminal_closes_without_refresh() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(28).await;
    authority.configure(|state| state.pending_renew_after_grant = true);
    let mut future = Box::pin(fence.renew(&authority, guard, timing(10, 1)));

    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("ambiguous renewal unexpectedly completed"),
    })
    .await;
    drop(future);

    assert_eq!(authority.renew_calls(), 1);
    assert_eq!(
        kernel.events(),
        vec!["publish", "register", "activate", "close"]
    );
    assert!(!fence.is_active());
}

#[tokio::test]
async fn reclaiming_entry_is_nonreopenable_and_fails_exact_preflight() {
    let (mut fence, kernel, _clock, _authority, _guard) = activated_fixture(29).await;
    let active = kernel
        .entry(SOCKET_COOKIE, SOCKET_TOKEN)
        .expect("active fixture");
    kernel.seed_entry(KernelFenceEntry {
        state: KernelEntryState::Reclaiming,
        ..active
    });

    assert_eq!(fence.preflight_send(), Err(FenceError::KernelReadback));
    assert!(!fence.is_active());
    assert_eq!(
        kernel
            .entry(SOCKET_COOKIE, SOCKET_TOKEN)
            .expect("ambiguous reclaiming entry remains closed")
            .state,
        KernelEntryState::Reclaiming
    );
}

#[tokio::test]
async fn every_send_preflight_rechecks_clock_integrity_current_and_exact_entry() {
    for fault in [KernelFault::InspectNext, KernelFault::CorruptNextEntryRead] {
        let (mut fence, kernel, _clock, _authority, _guard) = activated_fixture(30).await;
        kernel.set_fault(fault);

        assert_eq!(fence.preflight_send(), Err(FenceError::KernelReadback));
        assert!(!fence.is_active());
        assert_eq!(kernel.events().last(), Some(&"close"));
    }

    let (mut fence, kernel, clock, _authority, _guard) = activated_fixture(31).await;
    clock.fail_next_reads(1);
    assert_eq!(fence.preflight_send(), Err(FenceError::ClockUnavailable));
    assert!(!fence.is_active());
    assert_eq!(kernel.events().last(), Some(&"close"));

    let (mut fence, kernel, clock, _authority, _guard) = activated_fixture(32).await;
    clock.advance(Duration::from_secs(9));
    assert_eq!(fence.preflight_send(), Err(FenceError::GateExpired));
    assert!(!fence.is_active());
    assert_eq!(kernel.events().last(), Some(&"close"));
}

#[tokio::test]
async fn orderly_retirement_publishes_reserved_token_before_reclaim() {
    let durable = durable_identity(11);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("activation");
    authority.configure(|state| state.release_kernel_probe = Some(kernel.clone()));

    let pending = fence.prepare_release(&guard).expect("terminal readback");
    let evidence = fence
        .reclaim_after_socket_close(pending)
        .expect("fd-death ordered reclaim");
    authority
        .release_with_terminal(guard, evidence)
        .await
        .expect("terminal release");

    assert_eq!(
        kernel.events(),
        vec!["publish", "register", "activate", "close", "publish", "reclaim"]
    );
    assert_eq!(
        kernel.current(),
        KernelCurrentFence {
            phase: KernelCurrentPhase::RetirementClosed,
            lifecycle_token: RETIREMENT_TOKEN,
            registered_socket_cookie: 0,
        }
    );
    assert_eq!(kernel.entry(SOCKET_COOKIE, SOCKET_TOKEN), None);
    assert_eq!(
        authority.released_pair(),
        Some((SOCKET_TOKEN, RETIREMENT_TOKEN))
    );
    assert_eq!(authority.release_observed_kernel_closed(), Some(true));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn socket_fd_and_kernel_gate_are_closed_before_authority_release() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(33);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let mut socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| {
        state.release_kernel_probe = Some(kernel.clone());
        state.release_endpoint_probe = Some(endpoint);
    });
    let guard = socket
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("socket activation");

    socket
        .close_then_release(&authority, guard)
        .await
        .expect("ordered terminal release");

    assert_eq!(authority.release_observed_kernel_closed(), Some(true));
    assert_eq!(authority.release_observed_socket_closed(), Some(true));
    assert_eq!(
        socket
            .local_addr()
            .expect_err("socket must remain closed")
            .kind(),
        std::io::ErrorKind::NotConnected
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn closing_only_the_inbound_consumer_retires_without_waiting_for_traffic() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(50);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    authority.configure(|state| {
        state.release_kernel_probe = Some(kernel.clone());
        state.release_endpoint_probe = Some(endpoint);
    });
    let (channels, ports) =
        crate::fenced_udp_channels(NonZeroUsize::new(1).expect("nonzero capacity"))
            .expect("bounded channels");
    let outbound_stays_open = channels.sender();
    drop(channels);
    let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
    let session_key = key();

    crate::run_fenced_udp_guardian(
        socket,
        &authority,
        &session_key,
        owner(),
        timing(10, 1),
        ports,
        shutdown,
    )
    .await
    .expect("inbound closure performs orderly retirement");
    drop(outbound_stays_open);

    assert_eq!(authority.release_calls(), 1);
    assert_eq!(authority.release_observed_kernel_closed(), Some(true));
    assert_eq!(authority.release_observed_socket_closed(), Some(true));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelling_a_queued_send_before_admission_emits_no_late_datagram() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(51);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let receiver = tokio::net::UdpSocket::bind(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("loopback receiver"),
    )
    .await
    .expect("receiver bind");
    let peer = receiver.local_addr().expect("receiver endpoint");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let (channels, ports) =
        crate::fenced_udp_channels(NonZeroUsize::new(2).expect("nonzero capacity"))
            .expect("bounded channels");
    let sender = channels.sender();
    let mut cancelled = Box::pin(sender.send(vec![0_u8; 1], peer));
    poll_fn(|context| match cancelled.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("queued request completed without a guardian"),
    })
    .await;
    drop(cancelled);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let session_key = key();
    let guardian = crate::run_fenced_udp_guardian(
        socket,
        &authority,
        &session_key,
        owner(),
        timing(10, 1),
        ports,
        shutdown_rx,
    );
    let client = async {
        let sent = sender
            .send(vec![0_u8; 2], peer)
            .await
            .expect("successor request");
        assert_eq!(sent, 2);
        shutdown_tx.send(true).expect("request shutdown");
    };

    let (guardian_result, ()) = tokio::join!(guardian, client);
    guardian_result.expect("orderly guardian shutdown");
    let mut received = [0_u8; 8];
    let (bytes, _) = receiver
        .recv_from(&mut received)
        .await
        .expect("one datagram");
    assert_eq!(bytes, 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.recv_from(&mut received))
            .await
            .is_err(),
        "cancelled queued request emitted a late datagram"
    );
    drop(channels);
    assert_eq!(authority.release_calls(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelling_an_admitted_inflight_send_terminal_closes_without_release() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(52);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let mut socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let barrier = crate::socket::TestSendBarrier::new();
    socket.set_send_barrier(Arc::clone(&barrier));
    let receiver = tokio::net::UdpSocket::bind(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("loopback receiver"),
    )
    .await
    .expect("receiver bind");
    let peer = receiver.local_addr().expect("receiver endpoint");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let (channels, ports) =
        crate::fenced_udp_channels(NonZeroUsize::new(1).expect("nonzero capacity"))
            .expect("bounded channels");
    let sender = channels.sender();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let session_key = key();
    let guardian = crate::run_fenced_udp_guardian(
        socket,
        &authority,
        &session_key,
        owner(),
        timing(10, 1),
        ports,
        shutdown_rx,
    );
    let cancel_after_admission = async {
        let mut in_flight = Box::pin(sender.send(vec![0_u8; 1], peer));
        tokio::select! {
            () = barrier.wait_until_entered() => {}
            result = &mut in_flight => {
                panic!("send completed before the controlled syscall boundary: {result:?}");
            }
        }
        drop(in_flight);
        barrier.release();
    };

    let (guardian_result, ()) = tokio::join!(guardian, cancel_after_admission);
    assert!(matches!(
        guardian_result,
        Err(crate::FencedUdpGuardianError::SendOutcomeUnknown { .. })
    ));
    assert_eq!(authority.release_calls(), 0);
    assert_eq!(kernel.events().last(), Some(&"close"));
    let mut received = [0_u8; 8];
    let (bytes, _) =
        tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
            .await
            .expect("outcome-unknown datagram observation budget")
            .expect("outcome-unknown datagram");
    assert_eq!(bytes, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.recv_from(&mut received))
            .await
            .is_err(),
        "one cancelled request emitted more than one datagram"
    );
    drop(channels);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelling_after_completion_before_observation_terminal_closes_without_release() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(53);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let receiver = tokio::net::UdpSocket::bind(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("loopback receiver"),
    )
    .await
    .expect("receiver bind");
    let peer = receiver.local_addr().expect("receiver endpoint");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let (channels, ports) =
        crate::fenced_udp_channels(NonZeroUsize::new(1).expect("nonzero capacity"))
            .expect("bounded channels");
    let mut sender = channels.sender();
    let observation_barrier = crate::guardian::TestObservationBarrier::new();
    sender.set_observation_barrier(Arc::clone(&observation_barrier));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let session_key = key();
    let guardian = crate::run_fenced_udp_guardian(
        socket,
        &authority,
        &session_key,
        owner(),
        timing(10, 1),
        ports,
        shutdown_rx,
    );
    let cancel_before_observation = async {
        let mut completed = Box::pin(sender.send(vec![0_u8; 1], peer));
        tokio::select! {
            () = observation_barrier.wait_until_entered() => {}
            result = &mut completed => {
                panic!("send escaped the controlled observation boundary: {result:?}");
            }
        }
        drop(completed);
        observation_barrier.release();
    };

    let (guardian_result, ()) = tokio::join!(guardian, cancel_before_observation);
    assert!(matches!(
        guardian_result,
        Err(crate::FencedUdpGuardianError::SendOutcomeUnknown { .. })
    ));
    assert_eq!(authority.release_calls(), 0);
    assert_eq!(kernel.events().last(), Some(&"close"));
    let mut received = [0_u8; 8];
    let (bytes, _) =
        tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
            .await
            .expect("completed datagram observation budget")
            .expect("completed datagram");
    assert_eq!(bytes, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.recv_from(&mut received))
            .await
            .is_err(),
        "one completed request emitted more than one datagram"
    );
    drop(channels);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn send_integrity_failure_terminal_closes_socket_before_syscall() {
    use opc_runtime::bind_udp_socket_with_destination_metadata;

    let durable = durable_identity(37);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let runtime_socket =
        bind_udp_socket_with_destination_metadata("127.0.0.1:0".parse().expect("loopback fixture"))
            .expect("exclusive runtime socket");
    let endpoint = runtime_socket.local_addr().expect("bound endpoint");
    let mut socket = crate::FencedUdpSocket::from_unregistered(runtime_socket, fence, endpoint)
        .expect("exclusive fenced admission");
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let _unreleased_guard = socket
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("socket activation");
    kernel.set_fault(KernelFault::InspectNext);

    let error = socket
        .send_to(&[], endpoint)
        .await
        .expect_err("integrity loss must deny send");

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "egress_fence_send_preflight");
    assert!(!socket.is_active());
    assert_eq!(
        socket
            .local_addr()
            .expect_err("socket must be closed")
            .kind(),
        std::io::ErrorKind::NotConnected
    );
    assert_eq!(kernel.events().last(), Some(&"close"));
}

#[tokio::test]
async fn applied_close_and_reclaim_errors_are_resolved_by_exact_readback() {
    for fault in [KernelFault::CloseAfter, KernelFault::ReclaimAfter] {
        let durable = durable_identity(12);
        let identity = attachment(
            durable,
            AttachmentInventory::InstalledClosedWithExactReadback,
        );
        let clock = TestBootClock::new(INITIAL_BOOT_NS);
        let kernel = TestKernel::empty(identity);
        let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
        let authority = TestAuthority::new(
            clock,
            DurablePriorFenceState::fresh_install(nonzero(1)),
            2,
            SOCKET_TOKEN,
            RETIREMENT_TOKEN,
        );
        let guard = fence
            .acquire(&authority, &key(), owner(), timing(10, 1))
            .await
            .expect("activation");
        kernel.set_fault(fault);

        let pending = fence.prepare_release(&guard).expect("exact close readback");
        fence
            .reclaim_after_socket_close(pending)
            .expect("exact reclaim readback");
    }
}

#[tokio::test]
async fn retirement_publication_or_reclaim_failure_never_releases_authority() {
    for fault in [KernelFault::PublishBefore, KernelFault::ReclaimBefore] {
        let (mut fence, kernel, _clock, authority, guard) = activated_fixture(34).await;
        let pending_closure = fence.prepare_release(&guard).expect("terminal closure");
        kernel.set_fault(fault);

        assert!(matches!(
            fence.reclaim_after_socket_close(pending_closure),
            Err(FenceError::KernelMutation)
        ));
        assert_eq!(authority.release_calls(), 0);
        assert_eq!(
            kernel
                .entry(SOCKET_COOKIE, SOCKET_TOKEN)
                .expect("terminal tombstone retained")
                .state,
            KernelEntryState::TerminalClosed
        );
        assert!(!fence.is_active());
    }
}

#[tokio::test]
async fn durable_release_failure_occurs_only_after_kernel_is_terminal_and_reclaimed() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(35).await;
    let pending_closure = fence.prepare_release(&guard).expect("terminal closure");
    let evidence = fence
        .reclaim_after_socket_close(pending_closure)
        .expect("retirement and reclaim");
    authority.configure(|state| {
        state.fail_release = true;
        state.release_kernel_probe = Some(kernel.clone());
    });

    assert_eq!(
        authority.release_with_terminal(guard, evidence).await,
        Err(AuthorityFailure::Release)
    );
    assert_eq!(authority.release_calls(), 1);
    assert_eq!(authority.release_observed_kernel_closed(), Some(true));
    assert_eq!(kernel.entry_count(), 0);
}

#[tokio::test]
async fn cancellation_during_terminal_release_leaves_kernel_safely_closed() {
    let (mut fence, kernel, _clock, authority, guard) = activated_fixture(36).await;
    let pending_closure = fence.prepare_release(&guard).expect("terminal closure");
    let evidence = fence
        .reclaim_after_socket_close(pending_closure)
        .expect("retirement and reclaim");
    authority.configure(|state| {
        state.pending_release_before_commit = true;
        state.release_kernel_probe = Some(kernel.clone());
    });
    let mut future = Box::pin(authority.release_with_terminal(guard, evidence));

    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("ambiguous release unexpectedly completed"),
    })
    .await;
    drop(future);

    assert_eq!(authority.release_calls(), 1);
    assert_eq!(authority.release_observed_kernel_closed(), Some(true));
    assert_eq!(kernel.entry_count(), 0);
}

#[test]
fn current_entry_cannot_be_reclaimed_until_a_higher_token_is_published() {
    let durable = durable_identity(13);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: SOCKET_TOKEN,
            registered_socket_cookie: SOCKET_COOKIE,
        },
        2,
    );
    kernel.seed_entry(KernelFenceEntry {
        state: KernelEntryState::TerminalClosed,
        socket_cookie: SOCKET_COOKIE,
        lifecycle_token: SOCKET_TOKEN,
        deadline_boot_ns: 0,
        control_epoch: 3,
    });

    assert_eq!(
        kernel.reclaim(identity, SOCKET_COOKIE, SOCKET_TOKEN, 3,),
        Err(KernelFailure::Mutation)
    );
    kernel
        .publish_retirement(identity, RETIREMENT_TOKEN)
        .expect("higher retirement publication");
    kernel
        .reclaim(identity, SOCKET_COOKIE, SOCKET_TOKEN, 3)
        .expect("noncurrent reclaim");
}

#[test]
fn delayed_tuple_delete_cannot_remove_same_cookie_successor() {
    let durable = durable_identity(14);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::RetirementClosed,
            lifecycle_token: RETIREMENT_TOKEN,
            registered_socket_cookie: 0,
        },
        3,
    );
    kernel.seed_entry(KernelFenceEntry {
        state: KernelEntryState::TerminalClosed,
        socket_cookie: SOCKET_COOKIE,
        lifecycle_token: SOCKET_TOKEN,
        deadline_boot_ns: 0,
        control_epoch: 3,
    });
    kernel
        .publish_lifecycle(identity, 103)
        .expect("successor publication");
    kernel
        .register_closed(identity, SOCKET_COOKIE, 103)
        .expect("same numeric cookie, distinct tuple");
    kernel
        .reclaim(identity, SOCKET_COOKIE, SOCKET_TOKEN, 3)
        .expect("old tuple reclaim");

    assert!(kernel.entry(SOCKET_COOKIE, 103).is_some());
    assert_eq!(
        kernel.reclaim(identity, SOCKET_COOKIE, SOCKET_TOKEN, 3),
        Err(KernelFailure::Readback)
    );
    assert!(kernel.entry(SOCKET_COOKIE, 103).is_some());
}

#[test]
fn retirement_token_cannot_be_published_or_registered_as_a_lifecycle() {
    let durable = durable_identity(16);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: SOCKET_TOKEN,
            registered_socket_cookie: SOCKET_COOKIE,
        },
        2,
    );

    assert_eq!(
        kernel.publish_lifecycle(identity, RETIREMENT_TOKEN),
        Err(KernelFailure::Mutation)
    );
    assert_eq!(
        kernel.register_closed(identity, SOCKET_COOKIE + 1, RETIREMENT_TOKEN),
        Err(KernelFailure::Mutation)
    );
    assert_eq!(
        kernel.current(),
        KernelCurrentFence {
            phase: KernelCurrentPhase::LifecycleOpen,
            lifecycle_token: SOCKET_TOKEN,
            registered_socket_cookie: SOCKET_COOKIE,
        }
    );
}

#[test]
fn mutation_barrier_blocks_publication_and_inspection() {
    let durable = durable_identity(17);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::empty(identity);
    kernel.set_mutation_barrier(7, true);

    assert_eq!(
        kernel.publish_lifecycle(identity, SOCKET_TOKEN),
        Err(KernelFailure::Mutation)
    );
    assert_eq!(kernel.inspect(identity, None), Err(KernelFailure::Readback));
    assert_eq!(kernel.mutation_barrier(), (7, true));
}

#[test]
fn failed_structural_mutation_advances_and_clears_the_barrier() {
    let durable = durable_identity(18);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::new(
        identity,
        KernelCurrentFence {
            phase: KernelCurrentPhase::Uninitialized,
            lifecycle_token: 0,
            registered_socket_cookie: 0,
        },
        0,
    );
    kernel
        .publish_lifecycle(identity, SOCKET_TOKEN)
        .expect("fixture lifecycle publication");

    assert_eq!(
        kernel.register_closed(identity, SOCKET_COOKIE, SOCKET_TOKEN),
        Err(KernelFailure::Mutation)
    );
    assert_eq!(kernel.mutation_barrier(), (2, false));
    assert_eq!(kernel.entry_count(), 0);
}

#[test]
fn structural_generation_overflow_fails_closed_without_a_claim() {
    let durable = durable_identity(19);
    let identity = attachment(durable, AttachmentInventory::AdoptedExact);
    let kernel = TestKernel::empty(identity);
    kernel
        .publish_lifecycle(identity, SOCKET_TOKEN)
        .expect("fixture lifecycle publication");
    kernel.set_mutation_barrier(u64::MAX, false);

    assert_eq!(
        kernel.register_closed(identity, SOCKET_COOKIE, SOCKET_TOKEN),
        Err(KernelFailure::Mutation)
    );
    assert_eq!(kernel.mutation_barrier(), (u64::MAX, false));
    assert_eq!(kernel.entry_count(), 0);
}

#[tokio::test]
async fn close_uncertainty_never_produces_terminal_evidence() {
    let durable = durable_identity(15);
    let identity = attachment(
        durable,
        AttachmentInventory::InstalledClosedWithExactReadback,
    );
    let clock = TestBootClock::new(INITIAL_BOOT_NS);
    let kernel = TestKernel::empty(identity);
    let mut fence = unregistered_fence(identity, kernel.clone(), clock.clone());
    let authority = TestAuthority::new(
        clock,
        DurablePriorFenceState::fresh_install(nonzero(1)),
        2,
        SOCKET_TOKEN,
        RETIREMENT_TOKEN,
    );
    let guard = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect("activation");
    kernel.set_fault(KernelFault::CloseBefore);

    assert!(matches!(
        fence.prepare_release(&guard),
        Err(FenceError::KernelMutation)
    ));
    assert_eq!(authority.released_pair(), None);
}

#[test]
fn errors_and_evidence_are_redaction_safe() {
    let error: LeaseFenceError<AuthorityFailure> =
        LeaseFenceError::Authority(AuthorityFailure::Acquire);
    assert_eq!(
        format!("{error:?}"),
        "LeaseFenceError::Authority(<redacted>)"
    );
    assert_eq!(error.to_string(), "egress_fence_authority_operation");

    let entry = KernelFenceEntry {
        state: KernelEntryState::Active,
        socket_cookie: 31_337,
        lifecycle_token: 31_339,
        deadline_boot_ns: 31_341,
        control_epoch: 31_343,
    };
    let current = KernelCurrentFence {
        phase: KernelCurrentPhase::LifecycleOpen,
        lifecycle_token: 31_339,
        registered_socket_cookie: 31_337,
    };
    let debug = format!(
        "{:?}",
        KernelInspection {
            current,
            entry: Some(entry),
        }
    );
    for value in ["31337", "31339", "31341", "31343"] {
        assert!(!format!("{entry:?}").contains(value));
        assert!(!format!("{current:?}").contains(value));
        assert!(!debug.contains(value));
    }
    assert_eq!(
        FenceError::GateExpired.to_string(),
        "egress_fence_gate_expired"
    );
}
