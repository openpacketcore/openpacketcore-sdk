use std::{
    collections::HashMap,
    future::{poll_fn, Future},
    num::NonZeroU64,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    FakeSessionBackend, LeaseGuard, OwnerId, SessionKey, SessionKeyType, SessionLeaseManager,
    StableId,
};
use opc_types::{NetworkFunctionKind, TenantId};

use crate::lifecycle::{
    AttachmentIdentity, AttachmentInventory, BootClock, DurablePriorFenceState,
    EgressFenceLeaseAuthority, FenceAttachmentIdentity, FenceError, FenceLeaseGrant, KernelControl,
    KernelCurrentFence, KernelCurrentPhase, KernelEntryState, KernelFailure, KernelFenceEntry,
    KernelInspection, LeaseBoundFence, LeaseFenceError, LeaseFenceTiming, TerminalClosureEvidence,
    MAX_GATE_LIFETIME_NS,
};

const SOCKET_COOKIE: u64 = 13;
const INITIAL_BOOT_NS: u64 = 1_000_000_000;
const SOCKET_TOKEN: u64 = 101;
const RETIREMENT_TOKEN: u64 = 102;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelFault {
    None,
    PublishAfter,
    RegisterAfter,
    ActivateAfter,
    RefreshAfter,
    CloseBefore,
    CloseAfter,
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

    fn publish_retirement(
        &self,
        identity: AttachmentIdentity,
        retirement_lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        self.validate_identity(identity)?;
        let mut state = self.state.lock().map_err(|_| KernelFailure::Mutation)?;
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
}

impl TestBootClock {
    fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(now),
            waits: AtomicUsize::new(0),
            fail_reads: AtomicUsize::new(0),
        })
    }

    fn advance(&self, duration: Duration) {
        let delta = u64::try_from(duration.as_nanos()).expect("fixture duration");
        self.now.fetch_add(delta, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl BootClock for TestBootClock {
    fn now_boot_ns(&self) -> Result<u64, KernelFailure> {
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

struct TestAuthorityState {
    prior: Option<DurablePriorFenceState>,
    generation: NonZeroU64,
    socket_token: NonZeroU64,
    retirement_token: NonZeroU64,
    fail_acquire: bool,
    fail_renew: bool,
    fail_release: bool,
    advance_acquire: Duration,
    advance_renew: Duration,
    acquire_calls: usize,
    renew_calls: usize,
    release_calls: usize,
    released_pair: Option<(u64, u64)>,
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
                advance_acquire: Duration::ZERO,
                advance_renew: Duration::ZERO,
                acquire_calls: 0,
                renew_calls: 0,
                release_calls: 0,
                released_pair: None,
            }),
        }
    }

    fn configure(&self, update: impl FnOnce(&mut TestAuthorityState)) {
        update(&mut self.state.lock().expect("test authority lock"));
    }

    fn renew_calls(&self) -> usize {
        self.state.lock().expect("test authority lock").renew_calls
    }

    fn released_pair(&self) -> Option<(u64, u64)> {
        self.state
            .lock()
            .expect("test authority lock")
            .released_pair
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
        let (fail, advance, prior, generation, socket_token, retirement_token) = {
            let mut state = self.state.lock().expect("test authority lock");
            state.acquire_calls += 1;
            (
                state.fail_acquire,
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
        let guard = SessionLeaseManager::acquire(&self.backend, key, owner, ttl)
            .await
            .map_err(|_| AuthorityFailure::Acquire)?;
        self.clock.advance(advance);
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
        let (fail, advance) = {
            let mut state = self.state.lock().expect("test authority lock");
            state.renew_calls += 1;
            (state.fail_renew, state.advance_renew)
        };
        if fail {
            return Err(AuthorityFailure::Renew);
        }
        let renewed = SessionLeaseManager::renew(&self.backend, lease, ttl)
            .await
            .map_err(|_| AuthorityFailure::Renew)?;
        self.clock.advance(advance);
        Ok(renewed)
    }

    async fn release_with_terminal(
        &self,
        lease: LeaseGuard,
        evidence: TerminalClosureEvidence,
    ) -> Result<(), Self::Error> {
        let fail = {
            let mut state = self.state.lock().expect("test authority lock");
            state.release_calls += 1;
            state.released_pair = Some((
                evidence.socket_lifecycle_token().get(),
                evidence.retirement_lifecycle_token().get(),
            ));
            state.fail_release
        };
        if fail {
            return Err(AuthorityFailure::Release);
        }
        SessionLeaseManager::release(&self.backend, lease)
            .await
            .map_err(|_| AuthorityFailure::Release)
    }
}

fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("nonzero fixture")
}

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("fixture-tenant").expect("fixture tenant"),
        nf_kind: NetworkFunctionKind::from_static("epdg"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"fixture-stable-id"))
            .expect("fixture stable id"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("fixture-owner").expect("fixture owner")
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
            Duration::from_nanos(MAX_GATE_LIFETIME_NS + 2),
            Duration::from_nanos(1),
        ),
        Err(FenceError::InvalidTiming)
    );
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
    let durable = durable_identity(1);
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
    assert_ne!(guard.fence().get(), SOCKET_TOKEN);
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

#[tokio::test]
async fn exact_applied_errors_are_resolved_by_readback() {
    for fault in [
        KernelFault::PublishAfter,
        KernelFault::RegisterAfter,
        KernelFault::ActivateAfter,
    ] {
        let durable = durable_identity(2);
        let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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

    let error = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect_err("corrupt redundant identity must fail");

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
    assert!(kernel.entry(SOCKET_COOKIE, prior_socket).is_some());
    assert!(kernel.entry(SOCKET_COOKIE, 13).is_some());
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

    let error = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect_err("terminal evidence without CURRENT retirement token is invalid");

    assert_eq!(error.fence_error(), Some(FenceError::KernelReadback));
    assert!(error.into_unreleased_lease().is_some());
}

#[tokio::test]
async fn unknown_attachment_waits_the_full_ceiling_before_any_registration() {
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

    fence
        .acquire(&authority, &key(), owner(), timing(120, 20))
        .await
        .expect("unknown attachment activation");

    assert!(clock.now() >= INITIAL_BOOT_NS + MAX_GATE_LIFETIME_NS);
    assert!(authority.renew_calls() >= 5);
    assert_eq!(kernel.events(), vec!["publish", "register", "activate"]);
}

#[tokio::test]
async fn acquisition_over_budget_retains_the_guard_and_inserts_nothing() {
    let durable = durable_identity(7);
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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

    let error = fence
        .acquire(&authority, &key(), owner(), timing(10, 1))
        .await
        .expect_err("operation consumed full gate budget");

    assert_eq!(error.fence_error(), Some(FenceError::OperationOverBudget));
    assert!(error.into_unreleased_lease().is_some());
    assert_eq!(kernel.entry_count(), 0);
}

#[tokio::test]
async fn cancellation_during_closed_wait_registers_no_cookie() {
    let durable = durable_identity(8);
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
    let session_key = key();
    let mut future = Box::pin(fence.acquire(&authority, &session_key, owner(), timing(120, 20)));

    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("unknown wait unexpectedly completed in one poll"),
    })
    .await;
    drop(future);

    assert!(clock.waits.load(Ordering::SeqCst) > 0);
    assert_eq!(kernel.entry_count(), 0);
    assert_eq!(kernel.events(), Vec::<&'static str>::new());
    assert!(!fence.is_active());
}

#[tokio::test]
async fn renewal_preserves_lifecycle_pair_and_refreshes_without_publication() {
    let durable = durable_identity(9);
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
async fn renewal_failure_returns_the_exact_unreleased_guard() {
    let durable = durable_identity(10);
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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

    let error = fence
        .renew(&authority, guard, timing(10, 1))
        .await
        .expect_err("renewal failure");
    let retained = error
        .into_unreleased_lease()
        .expect("post-grant failure retains lease");

    assert_eq!(retained, expected);
    assert!(!fence.is_active());
}

#[tokio::test]
async fn orderly_retirement_publishes_reserved_token_before_reclaim() {
    let durable = durable_identity(11);
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
}

#[tokio::test]
async fn applied_close_and_reclaim_errors_are_resolved_by_exact_readback() {
    for fault in [KernelFault::CloseAfter, KernelFault::ReclaimAfter] {
        let durable = durable_identity(12);
        let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
    let identity = attachment(durable, AttachmentInventory::InstalledUnderRevisionGuard);
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
}
