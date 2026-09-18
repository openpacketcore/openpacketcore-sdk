//! Exact association ownership, distinct from kernel identifiers and peer trust.
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::watch;
use tokio::time::Instant;

use super::{transport_error, N2Error, N2Inbound, UnprotectedN2Association};
use crate::{
    SctpAssociationState, SctpConnectConfig, SctpEvent, SctpPathHealth, SctpReconfigurationStatus,
};

/// Explicit bounds for one caller-requested connection/reconnection operation.
///
/// The policy selects no AMF, peer, address order or active association. A
/// connected candidate remains unusable until explicit successful promotion.
#[derive(Clone, Copy)]
pub struct N2ReconnectPolicy {
    attempts: u32,
    attempt_timeout: Duration,
    total_timeout: Duration,
    retry_delay: Duration,
}

impl N2ReconnectPolicy {
    /// Set attempt count, per-attempt timeout, total timeout and retry delay.
    ///
    /// Zero attempts or zero timeouts return [`N2Error::InvalidConfiguration`].
    /// Zero delay is allowed and yields between attempts. Unrepresentable
    /// deadlines fail before opening a connection.
    pub fn new(
        attempts: u32,
        attempt_timeout: Duration,
        total_timeout: Duration,
        retry_delay: Duration,
    ) -> Result<Self, N2Error> {
        if attempts == 0 || attempt_timeout.is_zero() || total_timeout.is_zero() {
            return Err(N2Error::InvalidConfiguration);
        }
        Ok(Self {
            attempts,
            attempt_timeout,
            total_timeout,
            retry_delay,
        })
    }
}

/// Owner of at most one current, explicitly unprotected N2 association.
///
/// Candidates capture the owner's state before connection begins. Candidates
/// based on the same state race through an atomic promotion: one wins and the
/// others are closed. Replacing or retiring a generation cancels its pending
/// I/O. A kernel association identifier never authorizes another generation.
///
/// Send/receive admission and completion are linearized against promotion.
/// Bytes submitted before replacement may already have reached the peer;
/// cancellation or a retired-generation error cannot retract those bytes.
/// No successful old completion attests the new generation. Results admitted
/// before a transition remain tied to their original generation.
///
/// Dropping this owner closes its current association. It does not select NGAP
/// streams, process NGAP Reset, authenticate peers, or choose an AMF.
pub struct N2AssociationOwner {
    core: Core<UnprotectedN2Association>,
}

/// One connected but unpromoted candidate. Dropping it closes its transport.
///
/// This type is intentionally not `Clone`. It exposes no raw transport I/O.
///
/// ```compile_fail
/// use opc_sctp::n2::N2Candidate;
/// fn duplicate(candidate: N2Candidate) { let _ = candidate.clone(); }
/// ```
pub struct N2Candidate(Candidate<UnprotectedN2Association>);

/// Affine authority for one exact generation of one owner.
///
/// This type is intentionally not `Clone`. Dropping it retires that generation
/// if it is still current; it can never close a replacement. The numeric value
/// returned by [`Self::number`] is readback metadata and cannot mint authority.
///
/// ```compile_fail
/// use opc_sctp::n2::N2Generation;
/// fn duplicate(generation: N2Generation) { let _ = generation.clone(); }
/// ```
pub struct N2Generation(Generation<UnprotectedN2Association>);

impl N2Generation {
    /// Return a monotonically increasing number scoped to this owner.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.0.number
    }
}

/// Exact generation-bound transport readback with redacted diagnostics.
pub struct N2Readback {
    generation: u64,
    transport: TransportReadback,
}

impl N2Readback {
    /// Generation under which the snapshot was admitted; not a capability.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact active local address list in the transport's readback order.
    #[must_use]
    pub fn local_addresses(&self) -> &[SocketAddr] {
        &self.transport.local
    }
    /// Exact active peer address list in the transport's readback order.
    #[must_use]
    pub fn peer_addresses(&self) -> &[SocketAddr] {
        &self.transport.peer
    }
    /// Path health as observed by the existing transport notification owner.
    #[must_use]
    pub fn peer_path_health(&self) -> &[SctpPathHealth] {
        &self.transport.paths
    }
}

/// DATA or a typed event admitted under one exact association generation.
///
/// A terminal event retires its generation before this result is delivered.
/// This record reports the event; it never grants further transport authority.
pub struct N2Received {
    generation: u64,
    retired: bool,
    inbound: N2Inbound,
}

impl N2Received {
    /// Generation under which the item was admitted; not a capability.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Whether this event retired its generation at admission.
    #[must_use]
    pub const fn retired(&self) -> bool {
        self.retired
    }
    /// Borrow the DATA record or transport event.
    #[must_use]
    pub const fn inbound(&self) -> &N2Inbound {
        &self.inbound
    }
    /// Transfer the DATA record or transport event to the caller.
    #[must_use]
    pub fn into_inbound(self) -> N2Inbound {
        self.inbound
    }
}

macro_rules! redacted {
    ($($name:ty),+ $(,)?) => {$(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($name), " { .. }"))
        }
    })+};
}
redacted!(
    N2ReconnectPolicy,
    N2AssociationOwner,
    N2Candidate,
    N2Generation,
    N2Readback,
    N2Received
);

impl Default for N2AssociationOwner {
    fn default() -> Self {
        Self::new()
    }
}

impl N2AssociationOwner {
    /// Create an empty owner. No socket is opened and no peer is selected.
    #[must_use]
    pub fn new() -> Self {
        Self { core: Core::new() }
    }

    /// Consume an existing connected/accepted association as a candidate.
    ///
    /// Lifecycle notifications are required before publication. This subscribes
    /// to events; it does not enable incoming reconfiguration requests. The
    /// candidate captures current owner state and carries no send authority.
    /// Any failure closes the supplied transport and returns a bounded error.
    pub fn candidate(&self, association: UnprotectedN2Association) -> Result<N2Candidate, N2Error> {
        self.core.candidate(prepare(association)?).map(N2Candidate)
    }

    /// Connect within explicit bounds and return a candidate for promotion.
    ///
    /// Owner replacement/retirement/close supersedes the attempt. Cancelling
    /// this future drops the pending socket. Invalid configuration and missing
    /// platform/capability support are not retried. Existing current authority
    /// is preserved on connection failure or cancellation.
    pub async fn connect_candidate(
        &self,
        config: SctpConnectConfig,
        policy: N2ReconnectPolicy,
    ) -> Result<N2Candidate, N2Error> {
        config
            .validate()
            .map_err(|e| transport_error(e, N2Error::InvalidConfiguration))?;
        self.core
            .connect_candidate(policy, || async {
                prepare(UnprotectedN2Association::connect(config.clone()).await?)
            })
            .await
            .map(N2Candidate)
    }

    /// Atomically replace current authority with the caller-selected candidate.
    ///
    /// Only an unchanged owner state and exact owner identity can succeed.
    /// Losing candidates close on every error. Generation exhaustion preserves
    /// the current association. No automatic preference or simultaneous-open
    /// policy is inferred from addresses or kernel association identifiers.
    pub fn promote(&self, candidate: N2Candidate) -> Result<N2Generation, N2Error> {
        self.core.promote(candidate.0).map(N2Generation)
    }

    /// Send on the exact current generation with the existing framing bounds.
    ///
    /// A stale/foreign token fails before admission. In-flight sends may have
    /// submitted bytes even when replacement causes a retired-generation error.
    pub async fn send(
        &self,
        generation: &N2Generation,
        payload: Bytes,
        stream_id: u16,
    ) -> Result<usize, N2Error> {
        self.core.send(&generation.0, payload, stream_id).await
    }

    /// Receive from the exact current generation, serialized through admission.
    ///
    /// Cancelling a receive keeps partial DATA in the socket owner. A restart,
    /// loss, shutdown, successful association reset, partial-delivery abort or
    /// unknown event retires the generation before returning the typed event.
    /// Stream reset/count events carry no NGAP stream-binding authority.
    pub async fn recv(&self, generation: &N2Generation) -> Result<N2Received, N2Error> {
        self.core.recv(&generation.0).await
    }

    /// Read exact transport addresses/path metadata under the current generation.
    ///
    /// Readback is serialized against promotion. It observes kernel state and
    /// the transport's latest processed path events, not authenticated identity.
    /// Readback failure retires the association rather than returning stale data.
    pub fn readback(&self, generation: &N2Generation) -> Result<N2Readback, N2Error> {
        self.core.readback(&generation.0)
    }

    /// Select a current peer path under exact generation authority.
    ///
    /// The existing transport validates membership and reconciles kernel/path
    /// state. Invalid local selection preserves authority; transport uncertainty
    /// retires it. No source tuple or path event can select a generation.
    pub fn set_primary_peer_path(
        &self,
        generation: &N2Generation,
        address: SocketAddr,
    ) -> Result<(), N2Error> {
        self.core.set_primary(&generation.0, address)
    }

    /// Retire exactly this current generation. A stale token cannot close a new one.
    pub fn retire(&self, generation: &N2Generation) -> Result<(), N2Error> {
        self.core.retire(&generation.0)
    }

    /// Permanently close the owner, its current generation and pending connects.
    /// This is immediate and idempotent; reconnect requires a new owner.
    pub fn close(&self) {
        self.core.shared.close();
    }
}

fn prepare(association: UnprotectedN2Association) -> Result<UnprotectedN2Association, N2Error> {
    association
        .association
        .enable_lifecycle_notifications()
        .map_err(|e| transport_error(e, N2Error::TransportUnavailable))?;
    Ok(association)
}

struct TransportReadback {
    local: Vec<SocketAddr>,
    peer: Vec<SocketAddr>,
    paths: Vec<SctpPathHealth>,
}

// Private to keep transport construction from becoming public generation
// authority. Tests replace I/O with independently controlled schedules while
// executing exactly the same ownership and cancellation implementation.
trait Transport: Send + Sync + 'static {
    fn send(
        &self,
        bytes: Bytes,
        stream: u16,
    ) -> impl Future<Output = Result<usize, N2Error>> + Send;
    fn recv(&self) -> impl Future<Output = Result<N2Inbound, N2Error>> + Send;
    fn readback(&self) -> Result<TransportReadback, N2Error>;
    fn set_primary(&self, address: SocketAddr) -> Result<(), N2Error>;
    fn abort(&self);
}

impl Transport for UnprotectedN2Association {
    async fn send(&self, bytes: Bytes, stream: u16) -> Result<usize, N2Error> {
        self.send(bytes, stream).await
    }
    async fn recv(&self) -> Result<N2Inbound, N2Error> {
        self.recv().await
    }
    fn readback(&self) -> Result<TransportReadback, N2Error> {
        if !self.association.health().socket_open {
            return Err(N2Error::ReadbackFailed);
        }
        Ok(TransportReadback {
            local: self.local_addresses()?,
            peer: self.peer_addresses()?,
            paths: self.peer_path_health(),
        })
    }
    fn set_primary(&self, address: SocketAddr) -> Result<(), N2Error> {
        self.association
            .set_primary_peer_path(address)
            .map_err(|e| transport_error(e, N2Error::ReadbackFailed))
    }
    fn abort(&self) {
        self.abort();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    last_generation: u64,
    current: bool,
    closed: bool,
}

struct Entry<T: Transport> {
    number: u64,
    transport: T,
    retired: watch::Sender<bool>,
    receive_gate: tokio::sync::Mutex<()>,
}

impl<T: Transport> Entry<T> {
    fn retire(&self) {
        self.retired.send_replace(true);
        self.transport.abort();
    }
}

struct State<T: Transport> {
    last_generation: u64,
    current: Option<Arc<Entry<T>>>,
    closed: bool,
}

impl<T: Transport> State<T> {
    fn stamp(&self) -> Stamp {
        Stamp {
            last_generation: self.last_generation,
            current: self.current.is_some(),
            closed: self.closed,
        }
    }
    fn entry(&self, number: u64) -> Result<&Arc<Entry<T>>, N2Error> {
        if self.closed {
            return Err(N2Error::OwnerClosed);
        }
        self.current
            .as_ref()
            .filter(|e| e.number == number)
            .ok_or(N2Error::GenerationRetired)
    }
}

struct Shared<T: Transport> {
    state: Mutex<State<T>>,
    changes: watch::Sender<Stamp>,
}

impl<T: Transport> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.closed = true;
                self.detach(&mut state);
                state
            }
        }
    }
    fn detach(&self, state: &mut State<T>) {
        let old = state.current.take();
        self.changes.send_replace(state.stamp());
        if let Some(old) = old {
            old.retire();
        }
    }
    fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        self.detach(&mut state);
    }
}

struct Core<T: Transport> {
    shared: Arc<Shared<T>>,
}
struct Candidate<T: Transport> {
    owner: Weak<Shared<T>>,
    stamp: Stamp,
    transport: Option<T>,
}
struct Generation<T: Transport> {
    owner: Weak<Shared<T>>,
    number: u64,
}

impl<T: Transport> Drop for Core<T> {
    fn drop(&mut self) {
        self.shared.close();
    }
}
impl<T: Transport> Drop for Candidate<T> {
    fn drop(&mut self) {
        if let Some(transport) = &self.transport {
            transport.abort();
        }
    }
}
impl<T: Transport> Drop for Generation<T> {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            let mut state = owner.lock();
            if state
                .current
                .as_ref()
                .is_some_and(|entry| entry.number == self.number)
            {
                owner.detach(&mut state);
            }
        }
    }
}

impl<T: Transport> Core<T> {
    fn new() -> Self {
        let state = State {
            last_generation: 0,
            current: None,
            closed: false,
        };
        let changes = watch::channel(state.stamp()).0;
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(state),
                changes,
            }),
        }
    }
    fn candidate(&self, transport: T) -> Result<Candidate<T>, N2Error> {
        let state = self.shared.lock();
        if state.closed {
            transport.abort();
            return Err(N2Error::OwnerClosed);
        }
        Ok(Candidate {
            owner: Arc::downgrade(&self.shared),
            stamp: state.stamp(),
            transport: Some(transport),
        })
    }
    fn promote(&self, mut candidate: Candidate<T>) -> Result<Generation<T>, N2Error> {
        if !candidate.owner.ptr_eq(&Arc::downgrade(&self.shared)) {
            return Err(N2Error::ForeignOwner);
        }
        let mut state = self.shared.lock();
        if state.closed {
            return Err(N2Error::OwnerClosed);
        }
        if state.stamp() != candidate.stamp {
            return Err(N2Error::CandidateSuperseded);
        }
        let number = state
            .last_generation
            .checked_add(1)
            .ok_or(N2Error::GenerationExhausted)?;
        let transport = candidate
            .transport
            .take()
            .ok_or(N2Error::CandidateSuperseded)?;
        let entry = Arc::new(Entry {
            number,
            transport,
            retired: watch::channel(false).0,
            receive_gate: tokio::sync::Mutex::new(()),
        });
        if let Some(old) = state.current.take() {
            old.retire();
        }
        state.last_generation = number;
        state.current = Some(entry);
        self.shared.changes.send_replace(state.stamp());
        Ok(Generation {
            owner: Arc::downgrade(&self.shared),
            number,
        })
    }
    fn identity(&self, generation: &Generation<T>) -> Result<(), N2Error> {
        if !generation.owner.ptr_eq(&Arc::downgrade(&self.shared)) {
            return Err(N2Error::ForeignOwner);
        }
        Ok(())
    }
    fn entry(&self, generation: &Generation<T>) -> Result<Arc<Entry<T>>, N2Error> {
        self.identity(generation)?;
        Ok(Arc::clone(self.shared.lock().entry(generation.number)?))
    }
    fn retire(&self, generation: &Generation<T>) -> Result<(), N2Error> {
        self.identity(generation)?;
        let mut state = self.shared.lock();
        state.entry(generation.number)?;
        self.shared.detach(&mut state);
        Ok(())
    }
    async fn send(
        &self,
        generation: &Generation<T>,
        bytes: Bytes,
        stream: u16,
    ) -> Result<usize, N2Error> {
        let entry = self.entry(generation)?;
        let mut retired = entry.retired.subscribe();
        tokio::select! {
            biased;
            _ = wait_retired(&mut retired) => Err(N2Error::GenerationRetired),
            result = async {
                self.entry(generation)?;
                let result = entry.transport.send(bytes, stream).await;
                let mut state = self.shared.lock();
                state.entry(generation.number)?;
                if result.as_ref().is_err_and(|e| terminal_error(*e)) { self.shared.detach(&mut state); }
                result
            } => result,
        }
    }
    async fn recv(&self, generation: &Generation<T>) -> Result<N2Received, N2Error> {
        let entry = self.entry(generation)?;
        let mut retired = entry.retired.subscribe();
        tokio::select! {
            biased;
            _ = wait_retired(&mut retired) => Err(N2Error::GenerationRetired),
            result = async {
                // Cover admission/terminal retirement as well as the lower
                // socket receive gate: no queued receiver crosses a reset.
                let _receive = entry.receive_gate.lock().await;
                self.entry(generation)?;
                let result = entry.transport.recv().await;
                let mut state = self.shared.lock();
                state.entry(generation.number)?;
                match result {
                    Err(error) => { self.shared.detach(&mut state); Err(error) }
                    Ok(inbound) => {
                        let retired = matches!(&inbound, N2Inbound::Notification(event) if terminal_event(*event));
                        if retired { self.shared.detach(&mut state); }
                        Ok(N2Received { generation: generation.number, retired, inbound })
                    }
                }
            } => result,
        }
    }
    fn readback(&self, generation: &Generation<T>) -> Result<N2Readback, N2Error> {
        self.identity(generation)?;
        let mut state = self.shared.lock();
        let result = state.entry(generation.number)?.transport.readback();
        match result {
            Ok(transport) => Ok(N2Readback {
                generation: generation.number,
                transport,
            }),
            Err(error) => {
                self.shared.detach(&mut state);
                Err(error)
            }
        }
    }
    fn set_primary(&self, generation: &Generation<T>, address: SocketAddr) -> Result<(), N2Error> {
        self.identity(generation)?;
        let mut state = self.shared.lock();
        let result = state
            .entry(generation.number)?
            .transport
            .set_primary(address);
        if result.as_ref().is_err_and(|e| terminal_error(*e)) {
            self.shared.detach(&mut state);
        }
        result
    }
    async fn connect_candidate<F, Fut>(
        &self,
        policy: N2ReconnectPolicy,
        mut connect: F,
    ) -> Result<Candidate<T>, N2Error>
    where
        F: FnMut() -> Fut + Send,
        Fut: Future<Output = Result<T, N2Error>> + Send,
    {
        let (stamp, mut changes) = {
            let state = self.shared.lock();
            if state.closed {
                return Err(N2Error::OwnerClosed);
            }
            (state.stamp(), self.shared.changes.subscribe())
        };
        let now = Instant::now();
        let deadline = now
            .checked_add(policy.total_timeout)
            .ok_or(N2Error::InvalidConfiguration)?;
        // Validate every duration before invoking the connector.
        now.checked_add(policy.attempt_timeout)
            .ok_or(N2Error::InvalidConfiguration)?;
        now.checked_add(policy.retry_delay)
            .ok_or(N2Error::InvalidConfiguration)?;
        for attempt in 0..policy.attempts {
            check_stamp(*changes.borrow(), stamp)?;
            let now = Instant::now();
            if now >= deadline {
                return Err(N2Error::ReconnectTimeout);
            }
            let attempt_deadline = now
                .checked_add(policy.attempt_timeout)
                .ok_or(N2Error::InvalidConfiguration)?
                .min(deadline);
            let result = tokio::select! {
                biased;
                error = wait_changed(&mut changes, stamp) => return Err(error),
                _ = tokio::time::sleep_until(deadline) => return Err(N2Error::ReconnectTimeout),
                result = tokio::time::timeout_at(attempt_deadline, connect()) => result,
            };
            match result {
                Ok(Ok(transport)) => {
                    let candidate = Candidate {
                        owner: Arc::downgrade(&self.shared),
                        stamp,
                        transport: Some(transport),
                    };
                    check_stamp(self.shared.lock().stamp(), stamp)?;
                    return Ok(candidate);
                }
                Ok(Err(error)) if error != N2Error::ConnectFailed => return Err(error),
                _ => {}
            }
            check_stamp(*changes.borrow(), stamp)?;
            if attempt + 1 == policy.attempts {
                return Err(N2Error::ReconnectExhausted);
            }
            if policy.retry_delay.is_zero() {
                tokio::task::yield_now().await;
            } else {
                let retry = Instant::now()
                    .checked_add(policy.retry_delay)
                    .ok_or(N2Error::InvalidConfiguration)?
                    .min(deadline);
                tokio::select! {
                    biased;
                    error = wait_changed(&mut changes, stamp) => return Err(error),
                    _ = tokio::time::sleep_until(retry) => {}
                }
            }
        }
        Err(N2Error::ReconnectExhausted)
    }
}

fn terminal_error(error: N2Error) -> bool {
    !matches!(
        error,
        N2Error::EmptyPayload | N2Error::MessageTooLarge | N2Error::InvalidConfiguration
    )
}

fn terminal_event(event: SctpEvent) -> bool {
    match event {
        SctpEvent::AssociationChange { state, error, .. } => {
            error != 0
                || SctpAssociationState::from_kernel(state) != SctpAssociationState::Established
        }
        SctpEvent::Shutdown { .. }
        | SctpEvent::PartialDeliveryAborted { .. }
        | SctpEvent::Unknown { .. } => true,
        SctpEvent::AssociationReset { status, .. } => {
            status == SctpReconfigurationStatus::Completed
        }
        SctpEvent::StreamChange {
            status: SctpReconfigurationStatus::Completed,
            inbound_streams,
            outbound_streams,
            ..
        } => inbound_streams == 0 || outbound_streams == 0,
        SctpEvent::PeerAddrChange { .. }
        | SctpEvent::SenderDry { .. }
        | SctpEvent::Authentication { .. }
        | SctpEvent::StreamReset { .. }
        | SctpEvent::StreamChange { .. } => false,
    }
}

async fn wait_retired(retired: &mut watch::Receiver<bool>) {
    while !*retired.borrow_and_update() {
        if retired.changed().await.is_err() {
            return;
        }
    }
}

fn check_stamp(actual: Stamp, expected: Stamp) -> Result<(), N2Error> {
    if actual.closed {
        Err(N2Error::OwnerClosed)
    } else if actual != expected {
        Err(N2Error::CandidateSuperseded)
    } else {
        Ok(())
    }
}

async fn wait_changed(changes: &mut watch::Receiver<Stamp>, stamp: Stamp) -> N2Error {
    loop {
        if let Err(error) = check_stamp(*changes.borrow_and_update(), stamp) {
            return error;
        }
        if changes.changed().await.is_err() {
            return N2Error::OwnerClosed;
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, target_os = "linux"))]
mod native_tests;
