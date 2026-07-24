//! Linux CO-RE source and transactional host coordinator.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{
    links::{FdLink, LinkType},
    FEntry, FExit, ProgramError,
};
use aya::{Btf, Ebpf, EbpfLoader};
use nix::libc;
use nix::sys::socket::{getsockopt, socket, AddressFamily, SockFlag, SockType};
use nix::{getsockopt_impl, sockopt_impl};
use opc_ipsec_xfrm_ebpf_common::{
    EspPeerObservationLifecycleValue, EspPeerObservationRecord,
    EspPeerObservationRegistrationValue, EspPeerObservationSaKey, EspPeerObservationSourceState,
    EspPeerObservationState, EspPeerObservationStateKey, ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED,
    ESP_PEER_AUTHORITY_OK, ESP_PEER_DIRECTION_INBOUND, ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN,
    ESP_PEER_OBSERVATION_MAX_SAS, ESP_PEER_OBSERVATION_RECORD_LEN,
    ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN, ESP_PEER_OBSERVATION_RING_BYTES,
    ESP_PEER_OBSERVATION_SA_KEY_LEN, ESP_PEER_OBSERVATION_SOURCE_STATE_LEN,
    ESP_PEER_OBSERVATION_STATE_KEY_LEN, ESP_PEER_OBSERVATION_STATE_LEN, ESP_PEER_STAT_COUNT,
    MAP_ESP_PEER_EVENTS, MAP_ESP_PEER_LIFECYCLES, MAP_ESP_PEER_REGISTRATIONS, MAP_ESP_PEER_SOURCE,
    MAP_ESP_PEER_STATES, MAP_ESP_PEER_STATS, PROG_ESP_PEER_DELETE, PROG_ESP_PEER_GUARD,
    PROG_ESP_PEER_INSERT, PROG_ESP_PEER_OBSERVATION, PROG_ESP_PEER_UPDATE,
};

use super::{
    observation_key_order, source_sealed, EspPeerEventProvenance, EspPeerIngestTally,
    EspPeerObservation, EspPeerObservationBoundary, EspPeerObservationEpoch,
    EspPeerObservationEvent, EspPeerObservationKey, EspPeerObservationScope,
    EspPeerObservationSource, EspPeerObservationSourceLoss, EspPeerObservationSourceRecord,
    EspPeerObservationSourceTerminal, EspPeerObservationTeardown,
};
use crate::{IpAddress, NamespaceBoundLinuxXfrmBackend, XfrmError, XfrmMark};

const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;
const SOURCE_STATE_INDEX: u32 = 0;
const REQUIRED_LINK_COUNT: usize = 5;
const DEFAULT_WATCHDOG_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_POLL_RECORD_BUDGET: usize = 256;
const MAX_POLL_RECORD_BUDGET: usize = (ESP_PEER_OBSERVATION_RING_BYTES as usize
    / ESP_PEER_OBSERVATION_RECORD_LEN)
    + ESP_PEER_OBSERVATION_MAX_SAS as usize;
const DEFAULT_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_TEARDOWN_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const XFRM_REPLAY_CHECK: &str = "xfrm_replay_check";
const XFRM_REPLAY_RECHECK: &str = "xfrm_replay_recheck";
const XFRM_STATE_INSERT: &str = "__xfrm_state_insert";
const XFRM_STATE_DELETE: &str = "__xfrm_state_delete";
const XFRM_STATE_UPDATE: &str = "xfrm_state_update";
const OBSERVATION_OBJECT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/bpf/opc-ipsec-xfrm-observation.bpf.o"
));

sockopt_impl!(
    NetworkNamespaceCookie,
    GetOnly,
    libc::SOL_SOCKET,
    libc::SO_NETNS_COOKIE,
    u64
);

/// Bounded runtime policy for the Linux authenticated ESP peer source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinuxEspPeerObservationConfig {
    capacity: NonZeroUsize,
    poll_record_budget: NonZeroUsize,
    watchdog_interval: Duration,
    teardown_timeout: Duration,
    teardown_poll_interval: Duration,
}

impl LinuxEspPeerObservationConfig {
    /// Create a policy tracking at most `capacity` exact inbound SAs.
    pub fn new(capacity: usize) -> Result<Self, XfrmError> {
        let capacity = NonZeroUsize::new(capacity).ok_or_else(|| {
            XfrmError::invalid_config("esp_peer_observation.capacity", "capacity must be nonzero")
        })?;
        if capacity.get() > ESP_PEER_OBSERVATION_MAX_SAS as usize {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.capacity",
                "capacity exceeds the committed map bound",
            ));
        }
        Ok(Self {
            capacity,
            poll_record_budget: NonZeroUsize::new(DEFAULT_POLL_RECORD_BUDGET)
                .ok_or(XfrmError::Unavailable)?,
            watchdog_interval: DEFAULT_WATCHDOG_INTERVAL,
            teardown_timeout: DEFAULT_TEARDOWN_TIMEOUT,
            teardown_poll_interval: DEFAULT_TEARDOWN_POLL_INTERVAL,
        })
    }

    /// Bound the number of kernel records consumed by one poll.
    pub fn with_poll_record_budget(mut self, records: usize) -> Result<Self, XfrmError> {
        let records = NonZeroUsize::new(records).ok_or_else(|| {
            XfrmError::invalid_config(
                "esp_peer_observation.poll_record_budget",
                "record budget must be nonzero",
            )
        })?;
        if records.get() > MAX_POLL_RECORD_BUDGET {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.poll_record_budget",
                "record budget exceeds the committed source bound",
            ));
        }
        self.poll_record_budget = records;
        Ok(self)
    }

    /// Set the maximum interval between exact GETSA authority rechecks.
    pub fn with_watchdog_interval(mut self, interval: Duration) -> Result<Self, XfrmError> {
        if interval.is_zero() {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.watchdog_interval",
                "watchdog interval must be nonzero",
            ));
        }
        self.watchdog_interval = interval;
        Ok(self)
    }

    /// Set the bounded in-flight-hook drain timeout and polling interval.
    pub fn with_teardown_wait(
        mut self,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, XfrmError> {
        if timeout.is_zero()
            || timeout > MAX_TEARDOWN_TIMEOUT
            || poll_interval.is_zero()
            || poll_interval > timeout
        {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.teardown_wait",
                "waits must be nonzero, bounded, and polling cannot exceed timeout",
            ));
        }
        self.teardown_timeout = timeout;
        self.teardown_poll_interval = poll_interval;
        Ok(self)
    }

    /// Maximum exact SAs admitted by this monitor.
    #[must_use]
    pub const fn capacity(self) -> usize {
        self.capacity.get()
    }

    /// Maximum interval between exact kernel authority rechecks.
    #[must_use]
    pub const fn watchdog_interval(self) -> Duration {
        self.watchdog_interval
    }
}

impl Default for LinuxEspPeerObservationConfig {
    fn default() -> Self {
        let capacity = match NonZeroUsize::new(ESP_PEER_OBSERVATION_MAX_SAS as usize) {
            Some(capacity) => capacity,
            None => NonZeroUsize::MIN,
        };
        let poll_record_budget = match NonZeroUsize::new(DEFAULT_POLL_RECORD_BUDGET) {
            Some(budget) => budget,
            None => NonZeroUsize::MIN,
        };
        Self {
            capacity,
            poll_record_budget,
            watchdog_interval: DEFAULT_WATCHDOG_INTERVAL,
            teardown_timeout: DEFAULT_TEARDOWN_TIMEOUT,
            teardown_poll_interval: DEFAULT_TEARDOWN_POLL_INTERVAL,
        }
    }
}

impl fmt::Debug for LinuxEspPeerObservationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEspPeerObservationConfig")
            .field("capacity", &self.capacity)
            .field("poll_record_budget", &self.poll_record_budget)
            .field("watchdog_interval", &self.watchdog_interval)
            .field("teardown_timeout", &self.teardown_timeout)
            .field("teardown_poll_interval", &self.teardown_poll_interval)
            .finish()
    }
}

/// Opaque live registration returned after GETSA admission and map publication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinuxEspPeerObservationHandle {
    key: EspPeerObservationKey,
    epoch: EspPeerObservationEpoch,
}

impl LinuxEspPeerObservationHandle {
    /// Exact kernel-derived SA key used for drain and teardown.
    #[must_use]
    pub const fn key(self) -> EspPeerObservationKey {
        self.key
    }

    /// Opaque lifecycle epoch preventing stale post-teardown reuse.
    #[must_use]
    pub const fn epoch(self) -> EspPeerObservationEpoch {
        self.epoch
    }
}

impl fmt::Debug for LinuxEspPeerObservationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEspPeerObservationHandle")
            .field("key", &self.key)
            .field("epoch", &self.epoch)
            .finish()
    }
}

struct WatchedRegistration {
    handle: LinuxEspPeerObservationHandle,
    current_source: (IpAddress, u16),
    last_verified: Instant,
}

/// Production Linux coordinator for post-authentication ESP peer observations.
///
/// Construction occurs inside the namespace-bound XFRM actor. The coordinator
/// owns the attached CO-RE programs, exact registration/state maps, ring
/// consumer, namespace-cookie pin, bounded boundary, and periodic GETSA
/// watchdog. Callers cannot obtain or feed the provenance-bearing source
/// independently. Loading requires kernel BTF and permission to attach every
/// required tracing program; any missing program, incompatible map, or lost
/// link fails closed.
///
/// Refresh and teardown are cancellation-resumable transactions. If either
/// future is cancelled after unpublication, ordinary polling refuses to
/// proceed until that same operation is resumed to completion. Dropping the
/// monitor unpublishes registrations best-effort and closes its userspace
/// boundary; products that need positive teardown evidence must await
/// [`Self::close`].
pub struct LinuxEspPeerObservationMonitor {
    backend: NamespaceBoundLinuxXfrmBackend,
    config: LinuxEspPeerObservationConfig,
    boundary: EspPeerObservationBoundary,
    source: LinuxEspPeerObservationKernelSource,
    watched: HashMap<EspPeerObservationKey, WatchedRegistration>,
    terminal: bool,
}

struct PreparedObservationRegistration<'a> {
    source: &'a mut LinuxEspPeerObservationKernelSource,
    boundary: &'a mut EspPeerObservationBoundary,
    handle: LinuxEspPeerObservationHandle,
    committed: bool,
}

impl PreparedObservationRegistration<'_> {
    fn arm_and_commit(mut self) -> Result<(), XfrmError> {
        self.source.arm(self.handle)?;
        self.committed = true;
        Ok(())
    }

    fn reject(self, error: XfrmError) -> Result<(), XfrmError> {
        Err(error)
    }
}

impl Drop for PreparedObservationRegistration<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.source.abort_unarmed(self.handle);
            let _ = self.boundary.teardown(&self.handle.key);
        }
    }
}

impl fmt::Debug for LinuxEspPeerObservationMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEspPeerObservationMonitor")
            .field("config", &self.config)
            .field("tracked", &self.watched.len())
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl LinuxEspPeerObservationMonitor {
    pub(crate) fn from_kernel_source(
        backend: NamespaceBoundLinuxXfrmBackend,
        config: LinuxEspPeerObservationConfig,
        source: LinuxEspPeerObservationKernelSource,
    ) -> Self {
        let boundary = EspPeerObservationBoundary::with_capacity(source.scope, config.capacity());
        Self {
            backend,
            config,
            boundary,
            source,
            watched: HashMap::with_capacity(config.capacity()),
            terminal: false,
        }
    }

    /// Register an exact inbound ESP-in-UDP SA after kernel-derived admission.
    ///
    /// GETSA, not the caller, supplies the raw mark/`if_id`, current peer
    /// address/port, integrity/AEAD proof, replay profile, direction, and
    /// offload status. The returned handle contains the canonical readback key.
    pub async fn register_sa(
        &mut self,
        requested: EspPeerObservationKey,
    ) -> Result<LinuxEspPeerObservationHandle, XfrmError> {
        self.ensure_live()?;
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        let registration = self
            .backend
            .query_esp_peer_observation_registration(requested)
            .await?;
        let epoch = self.boundary.register_sa(registration)?;
        let handle = LinuxEspPeerObservationHandle {
            key: registration.key,
            epoch,
        };
        if let Err(error) = self.source.prepare_unarmed(handle) {
            let _ = self.boundary.teardown(&handle.key);
            return Err(error);
        }
        let backend = self.backend.clone();
        let prepared = PreparedObservationRegistration {
            source: &mut self.source,
            boundary: &mut self.boundary,
            handle,
            committed: false,
        };
        let second = backend
            .query_esp_peer_observation_registration(handle.key)
            .await;
        let arm_result = match second {
            Ok(second) if second == registration => prepared.arm_and_commit(),
            Ok(_) => prepared.reject(XfrmError::StateMismatch {
                operation: "esp_peer_observation_second_getsa",
            }),
            Err(error) => prepared.reject(error),
        };
        if let Err(error) = arm_result {
            if self.source.terminal.is_some() {
                return self.fail_closed(error);
            }
            return Err(error);
        }
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        self.watched.insert(
            handle.key,
            WatchedRegistration {
                handle,
                current_source: (
                    registration.current_outer_source,
                    registration.current_outer_source_port,
                ),
                last_verified: Instant::now(),
            },
        );
        Ok(handle)
    }

    /// Poll a bounded number of source records after revalidating every
    /// watchdog-overdue SA.
    ///
    /// This returns an indeterminate-state error while a cancelled refresh or
    /// teardown remains unpublished; resume the interrupted transaction
    /// instead of treating that condition as an empty poll. Any terminal source
    /// state also fails closed with an error and discards queued observations,
    /// so nothing remains drainable from a monitor whose authority ended.
    pub async fn poll_available(&mut self) -> Result<EspPeerIngestTally, XfrmError> {
        self.ensure_live()?;
        self.source.ensure_pollable()?;
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        self.run_watchdog().await?;
        let tally = self
            .boundary
            .ingest_up_to(&mut self.source, self.config.poll_record_budget.get());
        if tally.source_terminal.is_some() {
            self.source.unpublish_all_best_effort();
            return finalize_poll_exit(
                &mut self.boundary,
                &mut self.watched,
                &mut self.terminal,
                tally,
                Ok(()),
            );
        }
        let exit_authority = self.source.validate_poll_authority();
        if exit_authority.is_err() {
            self.source
                .force_terminal(EspPeerObservationSourceTerminal::AuthorityLost);
            self.source.unpublish_all_best_effort();
        }
        finalize_poll_exit(
            &mut self.boundary,
            &mut self.watched,
            &mut self.terminal,
            tally,
            exit_authority,
        )
    }

    /// Take the pending observation for one exact live registration.
    ///
    /// A successful poll is the lifecycle-authority linearization point.
    /// Products must serialize their own later XFRM writers with draining and
    /// acting on the observation; a previously returned observation does not
    /// authorize a different kernel lifecycle.
    #[must_use]
    pub fn drain(&mut self, handle: LinuxEspPeerObservationHandle) -> Option<EspPeerObservation> {
        (!self.terminal && self.handle_is_current(handle))
            .then(|| self.boundary.drain(&handle.key))
            .flatten()
    }

    /// Take all pending observations in deterministic exact-key order.
    ///
    /// Products must apply the same writer serialization described by
    /// [`Self::drain`] while consuming this batch.
    #[must_use]
    pub fn drain_all(&mut self) -> Vec<EspPeerObservation> {
        if self.terminal {
            Vec::new()
        } else {
            self.boundary.drain_all()
        }
    }

    /// Rebase from exact GETSA after the product completes its authenticated
    /// relocation. Arbitrary caller-supplied baseline tuples are never
    /// accepted.
    ///
    /// Cancellation after this future starts may leave the registration
    /// safely unpublished. Resume this method with the same live handle until
    /// it returns; polling does not bypass an incomplete refresh.
    pub async fn refresh_current_source(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<(), XfrmError> {
        self.ensure_current(handle)?;
        if let Err(error) = self.source.validate_refresh_entry_authority(handle) {
            return self.fail_closed(error);
        }
        let expected_generation = match self.source.rebaseline_generation(handle) {
            Ok(generation) => generation,
            Err(error) => return self.fail_closed(error),
        };
        let registration = self
            .backend
            .query_esp_peer_observation_registration(handle.key)
            .await?;
        if registration.key != handle.key {
            return self.fail_closed(XfrmError::StateMismatch {
                operation: "esp_peer_observation_refresh",
            });
        }
        if let Err(error) = self
            .source
            .confirm_rebaseline_generation(handle, expected_generation)
        {
            return self.fail_closed(error);
        }
        if let Err(error) = self.source.begin_rebaseline(handle, expected_generation) {
            return self.fail_closed(error);
        }
        let deadline = match Instant::now().checked_add(self.config.teardown_timeout) {
            Some(deadline) => deadline,
            None => return self.fail_closed(XfrmError::Unavailable),
        };
        loop {
            if let Err(error) = self.source.validate_links() {
                return self.fail_closed(error);
            }
            let state = match self.source.state(handle) {
                Ok(state) => state,
                Err(error) => return self.fail_closed(error),
            };
            if state.active == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_rebaseline_quiesce",
                });
            }
            tokio::time::sleep(self.config.teardown_poll_interval).await;
        }

        let mut state = match self
            .source
            .adopt_rebaseline_authority(handle, expected_generation)
        {
            Ok(state) => state,
            Err(error) => return self.fail_closed(error),
        };
        loop {
            match self.source.lifecycle_reconciled(handle, state) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => return self.fail_closed(error),
            }
            if Instant::now() >= deadline {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_rebaseline_drain",
                });
            }
            let tally = self
                .boundary
                .ingest_up_to(&mut self.source, self.config.poll_record_budget.get());
            if tally.source_terminal.is_some() {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_rebaseline_drain",
                });
            }
            tokio::task::yield_now().await;
            state = match self.source.state(handle) {
                Ok(state) => state,
                Err(error) => return self.fail_closed(error),
            };
        }
        if let Err(error) = self.source.publish_rebaseline_unarmed(handle) {
            return self.fail_closed(error);
        }
        let second = match self
            .backend
            .query_esp_peer_observation_registration(handle.key)
            .await
        {
            Ok(second) => second,
            Err(error) => return self.fail_closed(error),
        };
        if second != registration {
            return self.fail_closed(XfrmError::StateMismatch {
                operation: "esp_peer_observation_rebaseline_second_getsa",
            });
        }
        if let Err(error) = self.source.arm(handle) {
            return self.fail_closed(error);
        }
        if let Err(error) = self.boundary.update_current_source(
            &handle.key,
            registration.current_outer_source,
            registration.current_outer_source_port,
        ) {
            return self.fail_closed(error);
        }
        let Some(watched) = self.watched.get_mut(&handle.key) else {
            return self.fail_closed(XfrmError::NotFound);
        };
        watched.current_source = (
            registration.current_outer_source,
            registration.current_outer_source_port,
        );
        watched.last_verified = Instant::now();
        if let Err(error) = self.source.commit_rebaseline(handle) {
            return self.fail_closed(error);
        }
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        Ok(())
    }

    /// Unpublish, quiesce, drain, and remove one exact lifecycle.
    ///
    /// Cancellation after this future starts may leave the lifecycle safely
    /// unpublished. Resume teardown with the same handle until it returns
    /// before releasing product-owned SA lifecycle authority.
    pub async fn teardown(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<EspPeerObservationTeardown, XfrmError> {
        self.ensure_current(handle)?;
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        if let Err(error) = self.source.begin_teardown(handle) {
            return self.fail_closed(error);
        }
        let deadline = match Instant::now().checked_add(self.config.teardown_timeout) {
            Some(deadline) => deadline,
            None => return self.fail_closed(XfrmError::Unavailable),
        };
        loop {
            if let Err(error) = self.source.validate_links() {
                return self.fail_closed(error);
            }
            let state = match self.source.state(handle) {
                Ok(state) => state,
                Err(error) => return self.fail_closed(error),
            };
            if state.active == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_teardown",
                });
            }
            tokio::time::sleep(self.config.teardown_poll_interval).await;
        }

        loop {
            if let Err(error) = self.source.validate_links() {
                return self.fail_closed(error);
            }
            if let Err(error) = self.source.validate_lifecycle_authority(handle) {
                return self.fail_closed(error);
            }
            let final_state = match self.source.state(handle) {
                Ok(state) => state,
                Err(error) => return self.fail_closed(error),
            };
            if final_state.active != 0
                || final_state.authority_lost != u64::from(ESP_PEER_AUTHORITY_OK)
            {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_teardown",
                });
            }
            match self.source.lifecycle_reconciled(handle, final_state) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => return self.fail_closed(error),
            }
            if Instant::now() >= deadline {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_teardown",
                });
            }
            let tally = self
                .boundary
                .ingest_up_to(&mut self.source, self.config.poll_record_budget.get());
            if tally.source_terminal.is_some() {
                return self.fail_closed(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_teardown",
                });
            }
            tokio::task::yield_now().await;
        }
        if let Err(error) = self.source.validate_lifecycle_authority(handle) {
            return self.fail_closed(error);
        }
        let final_state = match self.source.state(handle) {
            Ok(state) => state,
            Err(error) => return self.fail_closed(error),
        };
        let reconciled = match self.source.lifecycle_reconciled(handle, final_state) {
            Ok(reconciled) => reconciled,
            Err(error) => return self.fail_closed(error),
        };
        if final_state.active != 0
            || final_state.authority_lost != u64::from(ESP_PEER_AUTHORITY_OK)
            || !reconciled
        {
            return self.fail_closed(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_teardown",
            });
        }
        if let Err(error) = self.source.validate_poll_authority() {
            return self.fail_closed(error);
        }
        if let Err(error) = self.source.finish_teardown(handle) {
            return self.fail_closed(error);
        }
        self.watched.remove(&handle.key);
        match self.boundary.teardown(&handle.key) {
            Ok(teardown) => Ok(teardown),
            Err(error) => self.fail_closed(error),
        }
    }

    /// Number of exact live registrations.
    #[must_use]
    pub fn tracked_len(&self) -> usize {
        self.watched.len()
    }

    /// Close every lifecycle with the same quiescent teardown protocol.
    pub async fn close(&mut self) -> Result<Vec<EspPeerObservationTeardown>, XfrmError> {
        self.ensure_live()?;
        let mut handles: Vec<_> = self.watched.values().map(|entry| entry.handle).collect();
        handles.sort_by_key(|handle| observation_key_order(&handle.key));
        let mut records = Vec::with_capacity(handles.len());
        for handle in handles {
            records.push(self.teardown(handle).await?);
        }
        self.terminal = true;
        Ok(records)
    }

    async fn run_watchdog(&mut self) -> Result<(), XfrmError> {
        let now = Instant::now();
        let mut overdue: Vec<_> = self
            .watched
            .values()
            .filter(|entry| {
                now.duration_since(entry.last_verified) >= self.config.watchdog_interval
            })
            .map(|entry| entry.handle)
            .collect();
        overdue.sort_by_key(|handle| observation_key_order(&handle.key));
        for handle in overdue {
            if let Err(error) = self.source.validate_lifecycle_authority(handle) {
                return self.fail_closed(error);
            }
            let observed = match self
                .backend
                .query_esp_peer_observation_registration(handle.key)
                .await
            {
                Ok(observed) => observed,
                Err(error) => return self.fail_closed(error),
            };
            let Some(watched) = self.watched.get_mut(&handle.key) else {
                return self.fail_closed(XfrmError::NotFound);
            };
            if observed.key != handle.key
                || (
                    observed.current_outer_source,
                    observed.current_outer_source_port,
                ) != watched.current_source
            {
                return self.fail_closed(XfrmError::StateMismatch {
                    operation: "esp_peer_observation_watchdog",
                });
            }
            watched.last_verified = Instant::now();
            if let Err(error) = self.source.validate_lifecycle_authority(handle) {
                return self.fail_closed(error);
            }
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), XfrmError> {
        ensure_monitor_live(self.terminal)
    }

    fn ensure_current(&self, handle: LinuxEspPeerObservationHandle) -> Result<(), XfrmError> {
        self.ensure_live()?;
        if self.handle_is_current(handle) {
            Ok(())
        } else {
            Err(XfrmError::NotFound)
        }
    }

    fn handle_is_current(&self, handle: LinuxEspPeerObservationHandle) -> bool {
        self.watched
            .get(&handle.key)
            .is_some_and(|entry| entry.handle == handle)
    }

    fn fail_closed<T>(&mut self, error: XfrmError) -> Result<T, XfrmError> {
        self.source
            .force_terminal(EspPeerObservationSourceTerminal::AuthorityLost);
        self.source.unpublish_all_best_effort();
        let _ = self.boundary.ingest_available(&mut self.source);
        let _ = self.boundary.close();
        self.watched.clear();
        self.terminal = true;
        Err(error)
    }
}

impl Drop for LinuxEspPeerObservationMonitor {
    fn drop(&mut self) {
        self.source.unpublish_all_best_effort();
        let _ = self.boundary.close();
    }
}

fn finalize_poll_exit(
    boundary: &mut EspPeerObservationBoundary,
    watched: &mut HashMap<EspPeerObservationKey, WatchedRegistration>,
    terminal: &mut bool,
    tally: EspPeerIngestTally,
    authority: Result<(), XfrmError>,
) -> Result<EspPeerIngestTally, XfrmError> {
    if let Some(source_terminal) = tally.source_terminal {
        let _ = boundary.close();
        watched.clear();
        *terminal = true;
        return Err(source_terminal_error(source_terminal));
    }
    if let Err(error) = authority {
        let _ = boundary.close();
        watched.clear();
        *terminal = true;
        return Err(error);
    }
    Ok(tally)
}

fn source_terminal_error(source_terminal: EspPeerObservationSourceTerminal) -> XfrmError {
    let operation = match source_terminal {
        EspPeerObservationSourceTerminal::Closed => "esp_peer_observation_source_closed",
        EspPeerObservationSourceTerminal::IoFailure => "esp_peer_observation_source_io_failure",
        EspPeerObservationSourceTerminal::ProtocolFailure => {
            "esp_peer_observation_source_protocol_failure"
        }
        EspPeerObservationSourceTerminal::AuthorityLost => {
            "esp_peer_observation_source_authority_lost"
        }
    };
    XfrmError::StateIndeterminate { operation }
}

fn ensure_monitor_live(terminal: bool) -> Result<(), XfrmError> {
    if terminal {
        Err(XfrmError::Unavailable)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceLifecyclePhase {
    Unarmed,
    Live,
    Quiescing,
    Rebaselining(u64),
    RebaselineUnarmed,
    RebaselineArmed,
}

struct SourceLifecycle {
    public_key: EspPeerObservationKey,
    sa_key: EspPeerObservationSaKey,
    state_key: EspPeerObservationStateKey,
    epoch: EspPeerObservationEpoch,
    lifecycle_generation: u64,
    last_dropped: u64,
    records_seen: u64,
    phase: SourceLifecyclePhase,
}

fn rebaseline_generation_is_admissible(
    phase: SourceLifecyclePhase,
    admitted_generation: u64,
    observed_generation: u64,
    authority_lost: u64,
) -> bool {
    if observed_generation == 0 {
        return false;
    }
    match phase {
        SourceLifecyclePhase::Live => {
            (observed_generation == admitted_generation
                && authority_lost == u64::from(ESP_PEER_AUTHORITY_OK))
                || (observed_generation > admitted_generation
                    && authority_lost == u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED))
        }
        SourceLifecyclePhase::Rebaselining(expected) => {
            observed_generation == expected
                && matches!(
                    authority_lost,
                    value if value == u64::from(ESP_PEER_AUTHORITY_OK)
                        || value == u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED)
                )
        }
        SourceLifecyclePhase::RebaselineUnarmed | SourceLifecyclePhase::RebaselineArmed => {
            observed_generation == admitted_generation
                && authority_lost == u64::from(ESP_PEER_AUTHORITY_OK)
        }
        SourceLifecyclePhase::Unarmed | SourceLifecyclePhase::Quiescing => false,
    }
}

fn apply_delivered_loss(
    lifecycle: &mut SourceLifecycle,
    loss: EspPeerObservationSourceLoss,
    state: EspPeerObservationState,
) -> Result<(), ()> {
    if lifecycle.epoch != loss.epoch || lifecycle.public_key != loss.key {
        return Err(());
    }
    let delivered = lifecycle
        .last_dropped
        .checked_add(loss.dropped.get())
        .ok_or(())?;
    if delivered > state.dropped {
        return Err(());
    }
    lifecycle.last_dropped = delivered;
    Ok(())
}

fn source_state_has_authority(state: EspPeerObservationSourceState) -> bool {
    state.authority_lost == u64::from(ESP_PEER_AUTHORITY_OK) && state.failures == 0
}

fn lifecycle_counters_reconciled(
    lifecycle: &SourceLifecycle,
    state: EspPeerObservationState,
) -> Result<bool, XfrmError> {
    let successful_records = state
        .cursor
        .checked_sub(state.dropped)
        .ok_or_else(|| observation_data_error("esp_peer_observation_final_counters"))?;
    if lifecycle.records_seen > successful_records || lifecycle.last_dropped > state.dropped {
        return Err(observation_data_error(
            "esp_peer_observation_final_counters",
        ));
    }
    Ok(lifecycle.records_seen == successful_records && lifecycle.last_dropped == state.dropped)
}

struct OwnedObservationLink {
    link: FdLink,
    link_id: u32,
    program_id: u32,
}

impl OwnedObservationLink {
    fn new(link: FdLink) -> Result<Self, XfrmError> {
        let info = link
            .info()
            .map_err(|_| observation_data_error("esp_peer_observation_link_info"))?;
        if info.id() == 0
            || info.program_id() == 0
            || info
                .link_type()
                .map_err(|_| observation_data_error("esp_peer_observation_link_type"))?
                != LinkType::Tracing
        {
            return Err(observation_data_error("esp_peer_observation_link_identity"));
        }
        Ok(Self {
            link,
            link_id: info.id(),
            program_id: info.program_id(),
        })
    }

    fn is_live(&self) -> bool {
        self.link.info().is_ok_and(|info| {
            info.id() == self.link_id
                && info.program_id() == self.program_id
                && matches!(info.link_type(), Ok(LinkType::Tracing))
        })
    }
}

pub(crate) struct LinuxEspPeerObservationKernelSource {
    _ebpf: Ebpf,
    links: Vec<OwnedObservationLink>,
    registrations: BpfHashMap<
        MapData,
        [u8; ESP_PEER_OBSERVATION_SA_KEY_LEN],
        [u8; ESP_PEER_OBSERVATION_REGISTRATION_VALUE_LEN],
    >,
    lifecycles: BpfHashMap<
        MapData,
        [u8; ESP_PEER_OBSERVATION_SA_KEY_LEN],
        [u8; ESP_PEER_OBSERVATION_LIFECYCLE_VALUE_LEN],
    >,
    states: BpfHashMap<
        MapData,
        [u8; ESP_PEER_OBSERVATION_STATE_KEY_LEN],
        [u8; ESP_PEER_OBSERVATION_STATE_LEN],
    >,
    events: RingBuf<MapData>,
    source_state: Array<MapData, [u8; ESP_PEER_OBSERVATION_SOURCE_STATE_LEN]>,
    _namespace_pin: OwnedFd,
    net_cookie: u64,
    scope: EspPeerObservationScope,
    tracked: HashMap<EspPeerObservationKey, SourceLifecycle>,
    pending_losses: VecDeque<EspPeerObservationSourceLoss>,
    loss_reconciled_before_ring: bool,
    terminal: Option<EspPeerObservationSourceTerminal>,
}

impl fmt::Debug for LinuxEspPeerObservationKernelSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxEspPeerObservationKernelSource")
            .field("tracked", &self.tracked.len())
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

impl LinuxEspPeerObservationKernelSource {
    pub(crate) fn load(config: LinuxEspPeerObservationConfig) -> Result<Self, XfrmError> {
        let namespace_pin = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|error| XfrmError::io("esp_peer_observation_namespace_socket", error.into()))?;
        let net_cookie = getsockopt(&namespace_pin, NetworkNamespaceCookie).map_err(|error| {
            XfrmError::io("esp_peer_observation_namespace_cookie", error.into())
        })?;
        if net_cookie == 0 {
            return Err(observation_data_error(
                "esp_peer_observation_namespace_cookie",
            ));
        }

        let btf =
            Btf::from_sys_fs().map_err(|_| observation_data_error("esp_peer_observation_btf"))?;
        let mut ebpf = EbpfLoader::new()
            .load(OBSERVATION_OBJECT)
            .map_err(|_| observation_data_error("esp_peer_observation_object_load"))?;
        let links = load_and_attach_programs(&mut ebpf, &btf)?;
        validate_map_bound(
            &ebpf,
            MAP_ESP_PEER_REGISTRATIONS,
            ESP_PEER_OBSERVATION_MAX_SAS,
        )?;
        validate_map_bound(&ebpf, MAP_ESP_PEER_LIFECYCLES, ESP_PEER_OBSERVATION_MAX_SAS)?;
        validate_map_bound(&ebpf, MAP_ESP_PEER_STATES, ESP_PEER_OBSERVATION_MAX_SAS)?;
        validate_map_bound(&ebpf, MAP_ESP_PEER_EVENTS, ESP_PEER_OBSERVATION_RING_BYTES)?;
        validate_map_bound(&ebpf, MAP_ESP_PEER_STATS, ESP_PEER_STAT_COUNT)?;
        validate_map_bound(&ebpf, MAP_ESP_PEER_SOURCE, 1)?;

        let registrations = take_map(&mut ebpf, MAP_ESP_PEER_REGISTRATIONS)?
            .try_into()
            .map_err(|_| observation_data_error("esp_peer_observation_registration_map"))?;
        let lifecycles = take_map(&mut ebpf, MAP_ESP_PEER_LIFECYCLES)?
            .try_into()
            .map_err(|_| observation_data_error("esp_peer_observation_lifecycle_map"))?;
        let states = take_map(&mut ebpf, MAP_ESP_PEER_STATES)?
            .try_into()
            .map_err(|_| observation_data_error("esp_peer_observation_state_map"))?;
        let events = take_map(&mut ebpf, MAP_ESP_PEER_EVENTS)?
            .try_into()
            .map_err(|_| observation_data_error("esp_peer_observation_event_map"))?;
        let source_state = take_map(&mut ebpf, MAP_ESP_PEER_SOURCE)?
            .try_into()
            .map_err(|_| observation_data_error("esp_peer_observation_source_map"))?;
        let scope = EspPeerObservationScope::try_new()?;

        Ok(Self {
            _ebpf: ebpf,
            links,
            registrations,
            lifecycles,
            states,
            events,
            source_state,
            _namespace_pin: namespace_pin,
            net_cookie,
            scope,
            tracked: HashMap::with_capacity(config.capacity()),
            pending_losses: VecDeque::with_capacity(config.capacity()),
            loss_reconciled_before_ring: false,
            terminal: None,
        })
    }

    fn prepare_unarmed(&mut self, handle: LinuxEspPeerObservationHandle) -> Result<(), XfrmError> {
        if self.terminal.is_some() {
            return Err(XfrmError::Unavailable);
        }
        self.validate_links()?;
        if self.tracked.contains_key(&handle.key) {
            return Err(XfrmError::AlreadyExists);
        }
        let sa_key = common_sa_key(handle.key, self.net_cookie)?;
        let sa_key_bytes = sa_key.encode();
        let lifecycle_generation = 1;
        self.lifecycles
            .insert(
                sa_key_bytes,
                EspPeerObservationLifecycleValue {
                    generation: lifecycle_generation,
                }
                .encode(),
                BPF_NOEXIST,
            )
            .map_err(|_| observation_data_error("esp_peer_observation_lifecycle_publish"))?;
        let state_key = EspPeerObservationStateKey {
            sa: sa_key,
            epoch: handle.epoch.0.get(),
        };
        let state_key_bytes = state_key.encode();
        self.states
            .insert(
                state_key_bytes,
                EspPeerObservationState::empty().encode(),
                BPF_NOEXIST,
            )
            .map_err(|_| {
                let _ = self.lifecycles.remove(&sa_key_bytes);
                observation_data_error("esp_peer_observation_state_publish")
            })?;

        let registration = EspPeerObservationRegistrationValue {
            source_scope: self.scope.0.get(),
            epoch: handle.epoch.0.get(),
            lifecycle_generation,
            armed: 0,
        };
        if self
            .registrations
            .insert(sa_key_bytes, registration.encode(), BPF_NOEXIST)
            .is_err()
        {
            let _ = self.states.remove(&state_key_bytes);
            let _ = self.lifecycles.remove(&sa_key_bytes);
            return Err(observation_data_error(
                "esp_peer_observation_registration_publish",
            ));
        }
        self.tracked.insert(
            handle.key,
            SourceLifecycle {
                public_key: handle.key,
                sa_key,
                state_key,
                epoch: handle.epoch,
                lifecycle_generation,
                last_dropped: 0,
                records_seen: 0,
                phase: SourceLifecyclePhase::Unarmed,
            },
        );
        Ok(())
    }

    fn arm(&mut self, handle: LinuxEspPeerObservationHandle) -> Result<(), XfrmError> {
        self.validate_links()?;
        self.validate_lifecycle_authority(handle)?;
        let lifecycle = self.current_lifecycle(handle)?;
        if !matches!(
            lifecycle.phase,
            SourceLifecyclePhase::Unarmed | SourceLifecyclePhase::RebaselineUnarmed
        ) {
            return Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_arm",
            });
        }
        let armed_phase = match lifecycle.phase {
            SourceLifecyclePhase::Unarmed => SourceLifecyclePhase::Live,
            SourceLifecyclePhase::RebaselineUnarmed => SourceLifecyclePhase::RebaselineArmed,
            _ => {
                return Err(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_arm",
                })
            }
        };
        let sa_key = lifecycle.sa_key.encode();
        let registration = EspPeerObservationRegistrationValue {
            source_scope: self.scope.0.get(),
            epoch: lifecycle.epoch.0.get(),
            lifecycle_generation: lifecycle.lifecycle_generation,
            armed: 1,
        };
        self.registrations
            .insert(sa_key, registration.encode(), BPF_EXIST)
            .map_err(|_| observation_data_error("esp_peer_observation_registration_arm"))?;
        self.tracked
            .get_mut(&handle.key)
            .ok_or(XfrmError::NotFound)?
            .phase = armed_phase;
        if let Err(error) = self.validate_lifecycle_authority(handle) {
            let _ = self.registrations.remove(&sa_key);
            if let Some(lifecycle) = self.tracked.get_mut(&handle.key) {
                lifecycle.phase = SourceLifecyclePhase::Quiescing;
            }
            self.force_terminal(EspPeerObservationSourceTerminal::AuthorityLost);
            return Err(error);
        }
        Ok(())
    }

    fn abort_unarmed(&mut self, handle: LinuxEspPeerObservationHandle) {
        let Some(lifecycle) = self.tracked.get(&handle.key) else {
            return;
        };
        if lifecycle.epoch != handle.epoch || lifecycle.phase != SourceLifecyclePhase::Unarmed {
            return;
        }
        let sa_key = lifecycle.sa_key.encode();
        let state_key = lifecycle.state_key.encode();
        let _ = self.registrations.remove(&sa_key);
        let _ = self.states.remove(&state_key);
        let _ = self.lifecycles.remove(&sa_key);
        self.tracked.remove(&handle.key);
    }

    fn validate_lifecycle_authority(
        &self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<(), XfrmError> {
        let lifecycle = self.current_lifecycle(handle)?;
        let _ = self.lifecycle_snapshot(lifecycle)?;
        Ok(())
    }

    fn validate_all_lifecycle_authority(&self) -> Result<(), XfrmError> {
        let mut keys: Vec<_> = self.tracked.keys().copied().collect();
        keys.sort_by_key(observation_key_order);
        for key in keys {
            let lifecycle = self
                .tracked
                .get(&key)
                .ok_or_else(|| observation_data_error("esp_peer_observation_lifecycle_read"))?;
            let _ = self.lifecycle_snapshot(lifecycle)?;
        }
        Ok(())
    }

    fn validate_source_authority(&self) -> Result<(), XfrmError> {
        self.validate_links()?;
        if !source_state_has_authority(self.stable_source_state()?) {
            return Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_source_authority",
            });
        }
        Ok(())
    }

    fn validate_poll_authority(&self) -> Result<(), XfrmError> {
        self.validate_source_authority()?;
        self.validate_all_lifecycle_authority()
    }

    fn validate_refresh_entry_authority(
        &self,
        target: LinuxEspPeerObservationHandle,
    ) -> Result<(), XfrmError> {
        self.validate_source_authority()?;
        let mut keys: Vec<_> = self
            .tracked
            .keys()
            .copied()
            .filter(|key| *key != target.key)
            .collect();
        keys.sort_by_key(observation_key_order);
        for key in keys {
            let lifecycle = self
                .tracked
                .get(&key)
                .ok_or_else(|| observation_data_error("esp_peer_observation_lifecycle_read"))?;
            let _ = self.lifecycle_snapshot(lifecycle)?;
        }
        Ok(())
    }

    fn rebaseline_generation(
        &self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<u64, XfrmError> {
        self.validate_links()?;
        let lifecycle = self.current_lifecycle(handle)?;
        let generation = self.read_lifecycle_generation(lifecycle)?;
        let state = self.state(handle)?;
        if !rebaseline_generation_is_admissible(
            lifecycle.phase,
            lifecycle.lifecycle_generation,
            generation,
            state.authority_lost,
        ) {
            return Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_rebaseline_generation",
            });
        }
        Ok(generation)
    }

    fn confirm_rebaseline_generation(
        &self,
        handle: LinuxEspPeerObservationHandle,
        expected_generation: u64,
    ) -> Result<(), XfrmError> {
        let observed = self.rebaseline_generation(handle)?;
        if observed == expected_generation {
            Ok(())
        } else {
            Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_rebaseline_generation",
            })
        }
    }

    fn begin_teardown(&mut self, handle: LinuxEspPeerObservationHandle) -> Result<(), XfrmError> {
        let lifecycle = self.current_lifecycle(handle)?;
        let key = lifecycle.sa_key.encode();
        match lifecycle.phase {
            SourceLifecyclePhase::Live
            | SourceLifecyclePhase::RebaselineUnarmed
            | SourceLifecyclePhase::RebaselineArmed
            | SourceLifecyclePhase::Unarmed => {
                self.registrations.remove(&key).map_err(|_| {
                    observation_data_error("esp_peer_observation_registration_unpublish")
                })?;
            }
            SourceLifecyclePhase::Rebaselining(_) | SourceLifecyclePhase::Quiescing => {}
        }
        self.tracked
            .get_mut(&handle.key)
            .ok_or(XfrmError::NotFound)?
            .phase = SourceLifecyclePhase::Quiescing;
        Ok(())
    }

    fn begin_rebaseline(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
        expected_generation: u64,
    ) -> Result<(), XfrmError> {
        self.validate_links()?;
        self.confirm_rebaseline_generation(handle, expected_generation)?;
        let lifecycle = self.current_lifecycle(handle)?;
        let key = lifecycle.sa_key.encode();
        match lifecycle.phase {
            SourceLifecyclePhase::Live
            | SourceLifecyclePhase::RebaselineUnarmed
            | SourceLifecyclePhase::RebaselineArmed => {
                self.registrations.remove(&key).map_err(|_| {
                    observation_data_error("esp_peer_observation_rebaseline_unpublish")
                })?;
            }
            SourceLifecyclePhase::Rebaselining(generation) if generation == expected_generation => {
                return Ok(())
            }
            SourceLifecyclePhase::Rebaselining(_) => {
                return Err(XfrmError::StateMismatch {
                    operation: "esp_peer_observation_rebaseline_generation",
                })
            }
            SourceLifecyclePhase::Unarmed | SourceLifecyclePhase::Quiescing => {
                return Err(XfrmError::StateIndeterminate {
                    operation: "esp_peer_observation_rebaseline",
                });
            }
        }
        self.tracked
            .get_mut(&handle.key)
            .ok_or(XfrmError::NotFound)?
            .phase = SourceLifecyclePhase::Rebaselining(expected_generation);
        Ok(())
    }

    fn adopt_rebaseline_authority(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
        expected_generation: u64,
    ) -> Result<EspPeerObservationState, XfrmError> {
        self.validate_links()?;
        let lifecycle = self.current_lifecycle(handle)?;
        if lifecycle.phase != SourceLifecyclePhase::Rebaselining(expected_generation) {
            return Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_rebaseline",
            });
        }
        let state_key = lifecycle.state_key.encode();
        let generation = self.read_lifecycle_generation(lifecycle)?;
        if generation != expected_generation {
            return Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_rebaseline_generation",
            });
        }
        let mut state = self.state(handle)?;
        if state.active != 0
            || !matches!(
                state.authority_lost,
                value if value == u64::from(ESP_PEER_AUTHORITY_OK)
                    || value == u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED)
            )
        {
            return Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_rebaseline_authority",
            });
        }
        state.authority_lost = u64::from(ESP_PEER_AUTHORITY_OK);
        state = state.clear_last_source();
        self.states
            .insert(state_key, state.encode(), BPF_EXIST)
            .map_err(|_| observation_data_error("esp_peer_observation_rebaseline_state"))?;
        let lifecycle = self
            .tracked
            .get_mut(&handle.key)
            .ok_or(XfrmError::NotFound)?;
        lifecycle.lifecycle_generation = expected_generation;
        self.validate_lifecycle_authority(handle)?;
        Ok(state)
    }

    fn publish_rebaseline_unarmed(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<(), XfrmError> {
        self.validate_links()?;
        self.validate_lifecycle_authority(handle)?;
        let state = self.state(handle)?;
        if !self.lifecycle_reconciled(handle, state)? {
            return Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_rebaseline_drain",
            });
        }
        let lifecycle = self.current_lifecycle(handle)?;
        if !matches!(lifecycle.phase, SourceLifecyclePhase::Rebaselining(_)) {
            return Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_rebaseline",
            });
        }
        let registration = EspPeerObservationRegistrationValue {
            source_scope: self.scope.0.get(),
            epoch: lifecycle.epoch.0.get(),
            lifecycle_generation: lifecycle.lifecycle_generation,
            armed: 0,
        };
        self.registrations
            .insert(
                lifecycle.sa_key.encode(),
                registration.encode(),
                BPF_NOEXIST,
            )
            .map_err(|_| observation_data_error("esp_peer_observation_rebaseline_publish"))?;
        self.tracked
            .get_mut(&handle.key)
            .ok_or(XfrmError::NotFound)?
            .phase = SourceLifecyclePhase::RebaselineUnarmed;
        Ok(())
    }

    fn commit_rebaseline(
        &mut self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<(), XfrmError> {
        self.validate_links()?;
        self.validate_lifecycle_authority(handle)?;
        let lifecycle = self
            .tracked
            .get_mut(&handle.key)
            .filter(|lifecycle| {
                lifecycle.epoch == handle.epoch
                    && lifecycle.phase == SourceLifecyclePhase::RebaselineArmed
            })
            .ok_or(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_rebaseline_commit",
            })?;
        lifecycle.phase = SourceLifecyclePhase::Live;
        Ok(())
    }

    fn read_lifecycle_generation(&self, lifecycle: &SourceLifecycle) -> Result<u64, XfrmError> {
        let encoded = self
            .lifecycles
            .get(&lifecycle.sa_key.encode(), 0)
            .map_err(|_| observation_data_error("esp_peer_observation_lifecycle_read"))?;
        EspPeerObservationLifecycleValue::decode(&encoded)
            .map(|generation| generation.generation)
            .filter(|generation| *generation != 0)
            .ok_or_else(|| observation_data_error("esp_peer_observation_lifecycle_decode"))
    }

    fn state(
        &self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<EspPeerObservationState, XfrmError> {
        let lifecycle = self.current_lifecycle(handle)?;
        let encoded = self
            .states
            .get(&lifecycle.state_key.encode(), 0)
            .map_err(|_| observation_data_error("esp_peer_observation_state_read"))?;
        EspPeerObservationState::decode(&encoded)
            .ok_or_else(|| observation_data_error("esp_peer_observation_state_decode"))
    }

    fn finish_teardown(&mut self, handle: LinuxEspPeerObservationHandle) -> Result<(), XfrmError> {
        let lifecycle = self.current_lifecycle(handle)?;
        if lifecycle.phase != SourceLifecyclePhase::Quiescing {
            return Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_teardown",
            });
        }
        let state_key = lifecycle.state_key.encode();
        let sa_key = lifecycle.sa_key.encode();
        self.states
            .remove(&state_key)
            .map_err(|_| observation_data_error("esp_peer_observation_state_remove"))?;
        if self.lifecycles.remove(&sa_key).is_err() {
            self.force_terminal(EspPeerObservationSourceTerminal::AuthorityLost);
            return Err(observation_data_error(
                "esp_peer_observation_lifecycle_remove",
            ));
        }
        self.tracked.remove(&handle.key);
        Ok(())
    }

    fn current_lifecycle(
        &self,
        handle: LinuxEspPeerObservationHandle,
    ) -> Result<&SourceLifecycle, XfrmError> {
        self.tracked
            .get(&handle.key)
            .filter(|entry| entry.epoch == handle.epoch)
            .ok_or(XfrmError::NotFound)
    }

    fn validate_links(&self) -> Result<(), XfrmError> {
        if self.links.len() == REQUIRED_LINK_COUNT
            && self.links.iter().all(OwnedObservationLink::is_live)
        {
            Ok(())
        } else {
            Err(observation_data_error(
                "esp_peer_observation_link_authority",
            ))
        }
    }

    fn ensure_pollable(&self) -> Result<(), XfrmError> {
        if self
            .tracked
            .values()
            .all(|lifecycle| lifecycle.phase == SourceLifecyclePhase::Live)
        {
            Ok(())
        } else {
            Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_poll",
            })
        }
    }

    fn stable_source_state(&self) -> Result<EspPeerObservationSourceState, XfrmError> {
        let mut previous = self
            .source_state
            .get(&SOURCE_STATE_INDEX, 0)
            .map_err(|_| observation_data_error("esp_peer_observation_source_state_read"))?;
        for _ in 0..3 {
            let current = self
                .source_state
                .get(&SOURCE_STATE_INDEX, 0)
                .map_err(|_| observation_data_error("esp_peer_observation_source_state_read"))?;
            if current == previous {
                return EspPeerObservationSourceState::decode(&current).ok_or_else(|| {
                    observation_data_error("esp_peer_observation_source_state_decode")
                });
            }
            previous = current;
        }
        Err(observation_data_error(
            "esp_peer_observation_source_state_torn",
        ))
    }

    fn next_ring_record(&mut self) -> Option<Result<EspPeerObservationEvent, ()>> {
        let item = self.events.next()?;
        if item.len() != ESP_PEER_OBSERVATION_RECORD_LEN {
            return Some(Err(()));
        }
        let mut encoded = [0; ESP_PEER_OBSERVATION_RECORD_LEN];
        encoded.copy_from_slice(&item);
        drop(item);
        let Some(record) = EspPeerObservationRecord::decode(&encoded) else {
            return Some(Err(()));
        };
        let public_key = match public_key_from_common(record.key) {
            Ok(key) => key,
            Err(()) => return Some(Err(())),
        };
        let Some(lifecycle) = self.tracked.get(&public_key) else {
            return Some(Err(()));
        };
        if self.lifecycle_snapshot(lifecycle).is_err() {
            return Some(Err(()));
        }
        Some(event_from_record(
            record,
            self.net_cookie,
            self.scope,
            &mut self.tracked,
        ))
    }

    fn next_standalone_loss(&mut self) -> Option<Result<EspPeerObservationSourceLoss, ()>> {
        if let Some(loss) = self.pop_pending_loss() {
            return Some(loss);
        }
        if self.loss_reconciled_before_ring {
            return None;
        }
        self.loss_reconciled_before_ring = true;
        let mut keys: Vec<_> = self.tracked.keys().copied().collect();
        keys.sort_by_key(observation_key_order);
        for key in keys {
            let Some(lifecycle) = self.tracked.get(&key) else {
                return Some(Err(()));
            };
            let Ok(state) = self.lifecycle_snapshot(lifecycle) else {
                return Some(Err(()));
            };
            let Some(lifecycle) = self.tracked.get_mut(&key) else {
                return Some(Err(()));
            };
            if state.dropped < lifecycle.last_dropped {
                return Some(Err(()));
            }
            let delta = state.dropped - lifecycle.last_dropped;
            if let Some(dropped) = NonZeroU64::new(delta) {
                self.pending_losses.push_back(EspPeerObservationSourceLoss {
                    scope: self.scope,
                    epoch: lifecycle.epoch,
                    key: lifecycle.public_key,
                    dropped,
                });
            }
        }
        self.pop_pending_loss()
    }

    fn pop_pending_loss(&mut self) -> Option<Result<EspPeerObservationSourceLoss, ()>> {
        let loss = self.pending_losses.pop_front()?;
        if loss.scope != self.scope {
            return Some(Err(()));
        }
        let state = {
            let Some(lifecycle) = self.tracked.get(&loss.key) else {
                return Some(Err(()));
            };
            if lifecycle.epoch != loss.epoch {
                return Some(Err(()));
            }
            match self.lifecycle_snapshot(lifecycle) {
                Ok(state) => state,
                Err(_) => return Some(Err(())),
            }
        };
        let Some(lifecycle) = self.tracked.get_mut(&loss.key) else {
            return Some(Err(()));
        };
        if apply_delivered_loss(lifecycle, loss, state).is_err() {
            return Some(Err(()));
        }
        Some(Ok(loss))
    }

    fn lifecycle_snapshot(
        &self,
        lifecycle: &SourceLifecycle,
    ) -> Result<EspPeerObservationState, XfrmError> {
        let encoded_generation = self
            .lifecycles
            .get(&lifecycle.sa_key.encode(), 0)
            .map_err(|_| observation_data_error("esp_peer_observation_lifecycle_read"))?;
        let generation = EspPeerObservationLifecycleValue::decode(&encoded_generation)
            .ok_or_else(|| observation_data_error("esp_peer_observation_lifecycle_decode"))?;
        let encoded_state = self
            .states
            .get(&lifecycle.state_key.encode(), 0)
            .map_err(|_| observation_data_error("esp_peer_observation_state_read"))?;
        let state = EspPeerObservationState::decode(&encoded_state)
            .ok_or_else(|| observation_data_error("esp_peer_observation_state_decode"))?;
        if generation.generation != lifecycle.lifecycle_generation
            || state.authority_lost != u64::from(ESP_PEER_AUTHORITY_OK)
        {
            return Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_lifecycle_authority",
            });
        }
        Ok(state)
    }

    fn lifecycle_reconciled(
        &self,
        handle: LinuxEspPeerObservationHandle,
        state: EspPeerObservationState,
    ) -> Result<bool, XfrmError> {
        let lifecycle = self.current_lifecycle(handle)?;
        lifecycle_counters_reconciled(lifecycle, state)
    }

    fn force_terminal(&mut self, terminal: EspPeerObservationSourceTerminal) {
        self.terminal = Some(terminal);
    }

    fn unpublish_all_best_effort(&mut self) {
        for lifecycle in self.tracked.values_mut() {
            if matches!(
                lifecycle.phase,
                SourceLifecyclePhase::Live
                    | SourceLifecyclePhase::Unarmed
                    | SourceLifecyclePhase::RebaselineUnarmed
                    | SourceLifecyclePhase::RebaselineArmed
            ) {
                let _ = self.registrations.remove(&lifecycle.sa_key.encode());
                lifecycle.phase = SourceLifecyclePhase::Quiescing;
            }
        }
    }
}

impl source_sealed::Sealed for LinuxEspPeerObservationKernelSource {}

impl EspPeerObservationSource for LinuxEspPeerObservationKernelSource {
    fn next_record(&mut self) -> EspPeerObservationSourceRecord {
        if let Some(terminal) = self.terminal {
            return EspPeerObservationSourceRecord::Terminal(terminal);
        }
        match self.stable_source_state() {
            Ok(state) if !source_state_has_authority(state) => {
                self.terminal = Some(EspPeerObservationSourceTerminal::AuthorityLost);
                return EspPeerObservationSourceRecord::Terminal(
                    EspPeerObservationSourceTerminal::AuthorityLost,
                );
            }
            Ok(_) => {}
            Err(_) => {
                self.terminal = Some(EspPeerObservationSourceTerminal::IoFailure);
                return EspPeerObservationSourceRecord::Terminal(
                    EspPeerObservationSourceTerminal::IoFailure,
                );
            }
        }
        if let Some(loss) = self.next_standalone_loss() {
            return match loss {
                Ok(loss) => EspPeerObservationSourceRecord::Loss(loss),
                Err(()) => {
                    self.terminal = Some(EspPeerObservationSourceTerminal::AuthorityLost);
                    EspPeerObservationSourceRecord::Terminal(
                        EspPeerObservationSourceTerminal::AuthorityLost,
                    )
                }
            };
        }
        if let Some(record) = self.next_ring_record() {
            self.loss_reconciled_before_ring = false;
            return match record {
                Ok(event) => EspPeerObservationSourceRecord::Event(event),
                Err(()) => {
                    self.terminal = Some(EspPeerObservationSourceTerminal::ProtocolFailure);
                    EspPeerObservationSourceRecord::Terminal(
                        EspPeerObservationSourceTerminal::ProtocolFailure,
                    )
                }
            };
        }
        self.loss_reconciled_before_ring = false;
        EspPeerObservationSourceRecord::Idle
    }
}

fn event_from_record(
    record: EspPeerObservationRecord,
    net_cookie: u64,
    scope: EspPeerObservationScope,
    tracked: &mut HashMap<EspPeerObservationKey, SourceLifecycle>,
) -> Result<EspPeerObservationEvent, ()> {
    if record.key.net_cookie != net_cookie || record.source_scope != scope.0.get() {
        return Err(());
    }
    let public_key = public_key_from_common(record.key)?;
    let lifecycle = tracked.get_mut(&public_key).ok_or(())?;
    if lifecycle.sa_key != record.key || lifecycle.epoch.0.get() != record.epoch {
        return Err(());
    }
    let dropped_since_previous = record.dropped_total.saturating_sub(lifecycle.last_dropped);
    lifecycle.last_dropped = lifecycle.last_dropped.max(record.dropped_total);
    lifecycle.records_seen = lifecycle.records_seen.checked_add(1).ok_or(())?;
    Ok(EspPeerObservationEvent {
        scope,
        epoch: lifecycle.epoch,
        key: public_key,
        provenance: EspPeerEventProvenance::PostFinalReplayAccepted,
        outer_source: ip_from_common(record.outer_source_family, record.outer_source_address)?,
        outer_source_port: record.outer_source_port,
        ingress_ifindex: Some(record.ingress_ifindex),
        cursor: record.cursor,
        dropped_since_previous,
    })
}

fn common_sa_key(
    key: EspPeerObservationKey,
    net_cookie: u64,
) -> Result<EspPeerObservationSaKey, XfrmError> {
    if net_cookie == 0 {
        return Err(observation_data_error(
            "esp_peer_observation_namespace_cookie",
        ));
    }
    let (family, destination) = common_address(key.id.destination);
    let (mark_value, mark_mask) = key.mark.map_or((0, 0), |mark| (mark.value, mark.mask));
    let encoded = EspPeerObservationSaKey {
        net_cookie,
        mark_value,
        mark_mask,
        if_id: key.if_id.unwrap_or(0),
        spi_be: key.id.spi.to_be(),
        family,
        protocol: key.id.protocol,
        direction: ESP_PEER_DIRECTION_INBOUND,
        reserved: [0; 4],
        destination,
    };
    EspPeerObservationSaKey::decode(&encoded.encode())
        .ok_or_else(|| observation_data_error("esp_peer_observation_sa_key"))
}

fn public_key_from_common(key: EspPeerObservationSaKey) -> Result<EspPeerObservationKey, ()> {
    let mark = if key.mark_mask == 0 {
        (key.mark_value == 0).then_some(None).ok_or(())?
    } else {
        Some(XfrmMark {
            value: key.mark_value,
            mask: key.mark_mask,
        })
    };
    Ok(EspPeerObservationKey {
        id: crate::XfrmId {
            destination: ip_from_common(key.family, key.destination)?,
            spi: u32::from_be(key.spi_be),
            protocol: key.protocol,
        },
        mark,
        if_id: NonZeroU32::new(key.if_id).map(NonZeroU32::get),
        direction: crate::XfrmDirection::In,
    })
}

fn common_address(address: IpAddress) -> (u16, [u8; 16]) {
    match address {
        IpAddress::Ipv4(address) => {
            let mut out = [0; 16];
            out[..4].copy_from_slice(&address);
            (nix::libc::AF_INET as u16, out)
        }
        IpAddress::Ipv6(address) => (nix::libc::AF_INET6 as u16, address),
    }
}

fn ip_from_common(family: u16, address: [u8; 16]) -> Result<IpAddress, ()> {
    match i32::from(family) {
        nix::libc::AF_INET if address[4..] == [0; 12] => Ok(IpAddress::Ipv4([
            address[0], address[1], address[2], address[3],
        ])),
        nix::libc::AF_INET6 => Ok(IpAddress::Ipv6(address)),
        _ => Err(()),
    }
}

fn load_and_attach_programs(
    ebpf: &mut Ebpf,
    btf: &Btf,
) -> Result<Vec<OwnedObservationLink>, XfrmError> {
    let links = vec![
        load_fentry_link(
            ebpf,
            btf,
            PROG_ESP_PEER_INSERT,
            XFRM_STATE_INSERT,
            "esp_peer_observation_insert",
        )?,
        load_fentry_link(
            ebpf,
            btf,
            PROG_ESP_PEER_DELETE,
            XFRM_STATE_DELETE,
            "esp_peer_observation_delete",
        )?,
        load_fentry_link(
            ebpf,
            btf,
            PROG_ESP_PEER_UPDATE,
            XFRM_STATE_UPDATE,
            "esp_peer_observation_update",
        )?,
        load_fentry_link(
            ebpf,
            btf,
            PROG_ESP_PEER_GUARD,
            XFRM_REPLAY_CHECK,
            "esp_peer_observation_guard",
        )?,
        load_fexit_link(
            ebpf,
            btf,
            PROG_ESP_PEER_OBSERVATION,
            XFRM_REPLAY_RECHECK,
            "esp_peer_observation_program",
        )?,
    ];
    if links.len() != REQUIRED_LINK_COUNT || links.iter().any(|link| !link.is_live()) {
        return Err(observation_data_error(
            "esp_peer_observation_required_links",
        ));
    }
    Ok(links)
}

fn load_fentry_link(
    ebpf: &mut Ebpf,
    btf: &Btf,
    program_name: &str,
    target: &str,
    operation: &'static str,
) -> Result<OwnedObservationLink, XfrmError> {
    let program: &mut FEntry = ebpf
        .program_mut(program_name)
        .ok_or_else(|| observation_data_error(operation))?
        .try_into()
        .map_err(|_: ProgramError| observation_data_error(operation))?;
    program
        .load(target, btf)
        .map_err(|_| observation_data_error(operation))?;
    let link_id = program
        .attach()
        .map_err(|_| observation_data_error(operation))?;
    let link: FdLink = program
        .take_link(link_id)
        .map_err(|_| observation_data_error(operation))?
        .into();
    OwnedObservationLink::new(link)
}

fn load_fexit_link(
    ebpf: &mut Ebpf,
    btf: &Btf,
    program_name: &str,
    target: &str,
    operation: &'static str,
) -> Result<OwnedObservationLink, XfrmError> {
    let program: &mut FExit = ebpf
        .program_mut(program_name)
        .ok_or_else(|| observation_data_error(operation))?
        .try_into()
        .map_err(|_: ProgramError| observation_data_error(operation))?;
    program
        .load(target, btf)
        .map_err(|_| observation_data_error(operation))?;
    let link_id = program
        .attach()
        .map_err(|_| observation_data_error(operation))?;
    let link: FdLink = program
        .take_link(link_id)
        .map_err(|_| observation_data_error(operation))?
        .into();
    OwnedObservationLink::new(link)
}

fn validate_map_bound(ebpf: &Ebpf, name: &str, expected: u32) -> Result<(), XfrmError> {
    let map = ebpf
        .map(name)
        .ok_or_else(|| observation_data_error("esp_peer_observation_map_lookup"))?;
    let data = match (name, map) {
        (
            MAP_ESP_PEER_REGISTRATIONS | MAP_ESP_PEER_LIFECYCLES | MAP_ESP_PEER_STATES,
            aya::maps::Map::HashMap(data),
        )
        | (MAP_ESP_PEER_EVENTS, aya::maps::Map::RingBuf(data))
        | (MAP_ESP_PEER_STATS, aya::maps::Map::PerCpuArray(data))
        | (MAP_ESP_PEER_SOURCE, aya::maps::Map::Array(data)) => data,
        _ => return Err(observation_data_error("esp_peer_observation_map_schema")),
    };
    let info = data
        .info()
        .map_err(|_| observation_data_error("esp_peer_observation_map_info"))?;
    if info.max_entries() != expected {
        return Err(observation_data_error("esp_peer_observation_map_capacity"));
    }
    Ok(())
}

fn take_map(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map, XfrmError> {
    ebpf.take_map(name)
        .ok_or_else(|| observation_data_error("esp_peer_observation_map_take"))
}

fn observation_data_error(operation: &'static str) -> XfrmError {
    XfrmError::io(
        operation,
        io::Error::new(io::ErrorKind::InvalidData, "observation boundary failure"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::{EspPeerIngestOutcome, EspPeerObservationRegistration};
    use crate::{XfrmDirection, XfrmId};

    fn key() -> EspPeerObservationKey {
        EspPeerObservationKey {
            id: XfrmId {
                destination: IpAddress::Ipv4([192, 0, 2, 1]),
                spi: 0x1234_5678,
                protocol: 50,
            },
            mark: Some(XfrmMark {
                value: 0x0102_0000,
                mask: 0xffff_0000,
            }),
            if_id: Some(9),
            direction: XfrmDirection::In,
        }
    }

    fn lifecycle(
        key: EspPeerObservationKey,
        scope_epoch: u64,
        last_dropped: u64,
    ) -> SourceLifecycle {
        let sa_key = common_sa_key(key, 42).unwrap();
        SourceLifecycle {
            public_key: key,
            sa_key,
            state_key: EspPeerObservationStateKey {
                sa: sa_key,
                epoch: scope_epoch,
            },
            epoch: EspPeerObservationEpoch(NonZeroU64::new(scope_epoch).unwrap()),
            lifecycle_generation: 1,
            last_dropped,
            records_seen: 0,
            phase: SourceLifecyclePhase::Live,
        }
    }

    #[test]
    fn common_key_round_trip_preserves_kernel_memory_order() {
        let key = key();
        let common = common_sa_key(key, 42).unwrap();
        assert_eq!(&common.encode()[20..24], &key.id.spi.to_be_bytes());
        assert_eq!(public_key_from_common(common).unwrap(), key);
    }

    #[test]
    fn runtime_record_budget_is_nonzero_and_committed_bound() {
        assert!(LinuxEspPeerObservationConfig::default()
            .with_poll_record_budget(0)
            .is_err());
        assert!(LinuxEspPeerObservationConfig::default()
            .with_poll_record_budget(MAX_POLL_RECORD_BUDGET)
            .is_ok());
        assert!(LinuxEspPeerObservationConfig::default()
            .with_poll_record_budget(MAX_POLL_RECORD_BUDGET + 1)
            .is_err());
    }

    #[test]
    fn poll_source_authority_requires_a_clean_global_snapshot() {
        assert!(source_state_has_authority(
            EspPeerObservationSourceState::empty()
        ));
        assert!(!source_state_has_authority(EspPeerObservationSourceState {
            authority_lost: u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED),
            failures: 0,
        }));
        assert!(!source_state_has_authority(EspPeerObservationSourceState {
            authority_lost: u64::from(ESP_PEER_AUTHORITY_OK),
            failures: 1,
        }));
    }

    #[test]
    fn failed_poll_exit_discards_an_already_ingested_observation() {
        let scope = EspPeerObservationScope::new();
        let key = key();
        let mut boundary = EspPeerObservationBoundary::with_capacity(scope, 1);
        let epoch = boundary
            .register_sa(EspPeerObservationRegistration {
                key,
                current_outer_source: IpAddress::Ipv4([192, 0, 2, 2]),
                current_outer_source_port: 4500,
                integrity_protected: true,
            })
            .unwrap();
        assert_eq!(
            boundary.ingest_event(EspPeerObservationEvent {
                scope,
                epoch,
                key,
                provenance: EspPeerEventProvenance::PostFinalReplayAccepted,
                outer_source: IpAddress::Ipv4([198, 51, 100, 8]),
                outer_source_port: 62_000,
                ingress_ifindex: Some(11),
                cursor: 1,
                dropped_since_previous: 0,
            }),
            EspPeerIngestOutcome::ObservationQueued
        );

        let mut terminal = false;
        let handle = LinuxEspPeerObservationHandle { key, epoch };
        let mut watched = HashMap::from([(
            key,
            WatchedRegistration {
                handle,
                current_source: (IpAddress::Ipv4([192, 0, 2, 2]), 4500),
                last_verified: Instant::now(),
            },
        )]);
        let result = finalize_poll_exit(
            &mut boundary,
            &mut watched,
            &mut terminal,
            EspPeerIngestTally::default(),
            Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_source_authority",
            }),
        );
        assert!(matches!(
            result,
            Err(XfrmError::StateMismatch {
                operation: "esp_peer_observation_source_authority"
            })
        ));
        assert!(terminal);
        assert!(watched.is_empty());
        assert!(boundary.drain(&key).is_none());
        assert_eq!(boundary.tracked_len(), 0);
        assert!(matches!(
            ensure_monitor_live(terminal),
            Err(XfrmError::Unavailable)
        ));
    }

    #[test]
    fn terminal_source_poll_exit_returns_error_and_discards_pending_state() {
        let scope = EspPeerObservationScope::new();
        let key = key();
        let mut boundary = EspPeerObservationBoundary::with_capacity(scope, 1);
        let epoch = boundary
            .register_sa(EspPeerObservationRegistration {
                key,
                current_outer_source: IpAddress::Ipv4([192, 0, 2, 2]),
                current_outer_source_port: 4500,
                integrity_protected: true,
            })
            .unwrap();
        assert_eq!(
            boundary.ingest_event(EspPeerObservationEvent {
                scope,
                epoch,
                key,
                provenance: EspPeerEventProvenance::PostFinalReplayAccepted,
                outer_source: IpAddress::Ipv4([198, 51, 100, 8]),
                outer_source_port: 62_000,
                ingress_ifindex: Some(11),
                cursor: 1,
                dropped_since_previous: 0,
            }),
            EspPeerIngestOutcome::ObservationQueued
        );

        let mut terminal = false;
        let handle = LinuxEspPeerObservationHandle { key, epoch };
        let mut watched = HashMap::from([(
            key,
            WatchedRegistration {
                handle,
                current_source: (IpAddress::Ipv4([192, 0, 2, 2]), 4500),
                last_verified: Instant::now(),
            },
        )]);
        let tally = EspPeerIngestTally {
            source_terminal: Some(EspPeerObservationSourceTerminal::AuthorityLost),
            ..EspPeerIngestTally::default()
        };
        let result = finalize_poll_exit(&mut boundary, &mut watched, &mut terminal, tally, Ok(()));
        assert!(matches!(
            result,
            Err(XfrmError::StateIndeterminate {
                operation: "esp_peer_observation_source_authority_lost"
            })
        ));
        assert!(terminal);
        assert!(watched.is_empty());
        assert!(boundary.drain(&key).is_none());
        assert_eq!(boundary.tracked_len(), 0);
        assert!(matches!(
            ensure_monitor_live(terminal),
            Err(XfrmError::Unavailable)
        ));
    }

    #[test]
    fn event_projection_requires_exact_scope_epoch_and_cumulative_loss() {
        let scope = EspPeerObservationScope::new();
        let epoch = EspPeerObservationEpoch(NonZeroU64::new(7).unwrap());
        let key = key();
        let common = common_sa_key(key, 42).unwrap();
        let mut tracked = HashMap::from([(
            key,
            SourceLifecycle {
                public_key: key,
                sa_key: common,
                state_key: EspPeerObservationStateKey {
                    sa: common,
                    epoch: 7,
                },
                epoch,
                lifecycle_generation: 1,
                last_dropped: 2,
                records_seen: 0,
                phase: SourceLifecyclePhase::Live,
            },
        )]);
        let record = EspPeerObservationRecord {
            key: common,
            source_scope: scope.0.get(),
            epoch: 7,
            cursor: 8,
            dropped_total: 3,
            sequence_low: 99,
            sequence_high: 0,
            ingress_ifindex: 11,
            outer_source_family: nix::libc::AF_INET as u16,
            outer_source_port: 4500,
            outer_source_address: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let event = event_from_record(record, 42, scope, &mut tracked).unwrap();
        assert_eq!(event.cursor, 8);
        assert_eq!(event.dropped_since_previous, 1);

        let mut stale = record;
        stale.cursor = 9;
        stale.dropped_total = 2;
        let older_loss_snapshot = event_from_record(stale, 42, scope, &mut tracked).unwrap();
        assert_eq!(older_loss_snapshot.dropped_since_previous, 0);
        assert_eq!(tracked.get(&key).unwrap().last_dropped, 3);
    }

    #[test]
    fn event_projection_reconciles_concurrent_loss_snapshot_ahead_of_cursor() {
        let scope = EspPeerObservationScope::new();
        let key = key();
        let common = common_sa_key(key, 42).unwrap();
        let mut lifecycle = lifecycle(key, 7, 0);
        lifecycle.sa_key = common;
        lifecycle.state_key = EspPeerObservationStateKey {
            sa: common,
            epoch: 7,
        };
        let mut tracked = HashMap::from([(key, lifecycle)]);
        let record = EspPeerObservationRecord {
            key: common,
            source_scope: scope.0.get(),
            epoch: 7,
            cursor: 1,
            dropped_total: 2,
            sequence_low: 99,
            sequence_high: 0,
            ingress_ifindex: 11,
            outer_source_family: nix::libc::AF_INET as u16,
            outer_source_port: 4500,
            outer_source_address: [198, 51, 100, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        let event = event_from_record(record, 42, scope, &mut tracked).unwrap();
        assert_eq!(event.cursor, 1);
        assert_eq!(event.dropped_since_previous, 2);

        let mut state = EspPeerObservationState::empty();
        state.cursor = 3;
        state.dropped = 2;
        assert!(lifecycle_counters_reconciled(tracked.get(&key).unwrap(), state).unwrap());
    }

    #[test]
    fn budgeted_loss_delivery_does_not_prematurely_reconcile_later_sa() {
        let scope = EspPeerObservationScope::new();
        let first_key = key();
        let mut second_key = key();
        second_key.id.spi += 1;
        let mut first = lifecycle(first_key, 7, 0);
        let mut second = lifecycle(second_key, 8, 0);
        let mut state = EspPeerObservationState::empty();
        state.cursor = 1;
        state.dropped = 1;
        let mut pending = VecDeque::from([
            EspPeerObservationSourceLoss {
                scope,
                epoch: first.epoch,
                key: first_key,
                dropped: NonZeroU64::MIN,
            },
            EspPeerObservationSourceLoss {
                scope,
                epoch: second.epoch,
                key: second_key,
                dropped: NonZeroU64::MIN,
            },
        ]);

        // A poll budget of one returns only the first queued loss. The later
        // SA must remain unreconciled so teardown/rebaseline cannot remove it
        // before its loss reaches the boundary.
        apply_delivered_loss(&mut first, pending.pop_front().unwrap(), state).unwrap();
        assert!(lifecycle_counters_reconciled(&first, state).unwrap());
        assert!(!lifecycle_counters_reconciled(&second, state).unwrap());

        apply_delivered_loss(&mut second, pending.pop_front().unwrap(), state).unwrap();
        assert!(lifecycle_counters_reconciled(&second, state).unwrap());
    }

    #[test]
    fn refresh_refuses_generation_change_after_first_getsa_snapshot() {
        assert!(rebaseline_generation_is_admissible(
            SourceLifecyclePhase::Live,
            1,
            2,
            u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED),
        ));
        assert!(rebaseline_generation_is_admissible(
            SourceLifecyclePhase::Rebaselining(2),
            1,
            2,
            u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED),
        ));
        assert!(!rebaseline_generation_is_admissible(
            SourceLifecyclePhase::Rebaselining(2),
            1,
            3,
            u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED),
        ));
        assert!(!rebaseline_generation_is_admissible(
            SourceLifecyclePhase::RebaselineArmed,
            2,
            3,
            u64::from(ESP_PEER_AUTHORITY_LIFECYCLE_CHANGED),
        ));
    }

    #[test]
    fn public_debug_never_formats_kernel_routing_values() {
        let config = LinuxEspPeerObservationConfig::default();
        let handle = LinuxEspPeerObservationHandle {
            key: key(),
            epoch: EspPeerObservationEpoch(NonZeroU64::new(7).unwrap()),
        };
        let debug = format!("{config:?} {handle:?}");
        for secret in [
            "192.0.2.1",
            "192, 0, 2, 1",
            "305419896",
            "0x12345678",
            "16908288",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
