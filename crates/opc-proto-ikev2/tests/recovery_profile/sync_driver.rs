//! RFC 6311 consumer handlers. Event identity precedes any reservation charge;
//! all fields share the row CAS. Only live, acknowledged SDK tokens may send.

use super::{
    authority::Transport,
    driver::{self, Cut, Error, Runtime, State},
    envelope::Provider,
    row::{Outcome, RetryImage, Row, SyncIntent, WindowImage},
    store::{CasStore, Command},
};
use opc_proto_ikev2::{
    recovery::{
        Ikev2ReservationRetry as Retry, Ikev2ReservationRetryPolicy as RetryPolicy,
        Ikev2ReservationRetryRecord as RetryRecord, Ikev2SyncClock as Clock,
        Ikev2SyncDisposition as Disposition, Ikev2SyncInitiatorAction as Action,
        Ikev2SyncRecoveryPolicy as Policy, Ikev2SyncRecoveryStatus as Status,
        Ikev2WindowError as WindowError,
    },
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvReservationError as IvError,
};

#[derive(Clone, Copy)]
pub enum Start {
    New(Policy),
    Retry,
}

fn persist(
    provider: &Provider,
    store: &mut CasStore,
    row: &mut Row,
    pending: &mut Option<Command>,
    update: impl FnOnce(&mut Row),
) -> Result<(), Error> {
    let candidate = row.next_write(store.stamp(), update)?;
    let write = driver::command(provider, store, Some(row.version), &candidate)?;
    *pending = Some(write.clone());
    if !driver::dispatch(store, &write, Cut::Complete)? {
        return Err(Error::Unresolved);
    }
    *row = candidate;
    *pending = None;
    Ok(())
}

fn validate_intent(row: &Row, index: usize, policy: Policy, clock: Clock) -> Result<(), Error> {
    let prior = row.sync_intents[index].as_ref();
    if let Some(prior) = prior {
        if prior.policy != policy {
            let completed = if index == 0 {
                row.window.recovery.as_ref().is_some_and(|event| {
                    event.status == Status::Recovered && event.policy == prior.policy
                })
            } else {
                !prior.pending
                    && (clock.unix_ms() >= prior.policy.deadline_unix_ms()
                        || row.window.sync.as_ref().is_some_and(|sync| {
                            match (sync.peer_request, sync.peer_proposal) {
                                (Some(request), Some(proposal)) => request >= proposal,
                                _ => false,
                            }
                        }))
            };
            if !completed || policy.operation() <= prior.policy.operation() {
                return Err(WindowError::InvalidRecord.into());
            }
        }
    }
    let observed = prior
        .filter(|prior| prior.policy == policy)
        .map_or(policy.started().unix_ms(), |intent| intent.observed);
    if clock.epoch() != policy.started().epoch()
        || clock.unix_ms() < observed
        || clock.unix_ms() >= policy.deadline_unix_ms()
    {
        return Err(WindowError::SyncClosed.into());
    }
    Ok(())
}

fn intent(
    provider: &Provider,
    store: &mut CasStore,
    row: &mut Row,
    pending: &mut Option<Command>,
    index: usize,
    policy: Policy,
    clock: Clock,
) -> Result<(), Error> {
    validate_intent(row, index, policy, clock)?;
    let prior = row.sync_intents[index].as_ref();
    if prior.is_some_and(|prior| {
        prior.policy == policy && prior.observed == clock.unix_ms() && prior.pending
    }) {
        return Ok(());
    }
    persist(provider, store, row, pending, |row| {
        row.sync_intents[index] = Some(SyncIntent {
            policy,
            observed: clock.unix_ms(),
            pending: true,
        })
    })
}

fn reserve(
    provider: &Provider,
    store: &mut CasStore,
    row: &mut Row,
    pending: &mut Option<Command>,
    allocator: &mut Allocator,
    policy: Policy,
    clock: Clock,
) -> Result<(), Error> {
    let (_, iv, records) = row.gcm()?;
    let expected_policy = RetryPolicy::new(
        policy.started().unix_ms(),
        policy.deadline_unix_ms(),
        3,
        policy.retry_delay_ms(),
    )?;
    let record = records
        .into_iter()
        .find(|record| record.operation() == policy.operation())
        .unwrap_or_else(|| {
            RetryRecord::initial(iv.domain().clone(), policy.operation(), expected_policy)
        });
    if record.policy() != expected_policy {
        return Err(WindowError::InvalidRecord.into());
    }
    let mut retry = Retry::restore(iv.domain(), policy.operation(), &record)?;
    let prepared = retry.prepare_attempt(allocator, clock.unix_ms(), false)?;
    let charge = prepared.record().clone();
    persist(provider, store, row, pending, |row| {
        row.iv.as_mut().unwrap().retries.insert(
            policy.operation(),
            RetryImage {
                operation: policy.operation(),
                policy: charge.policy(),
                attempts: charge.attempts(),
                last_attempt: charge.last_attempt_unix_ms(),
            },
        );
    })?;
    let permit = prepared.commit_after_durable(&charge)?;
    let block = permit.prepare(allocator, 1, Purpose::Ordinary, clock.unix_ms(), false)?;
    let record = block.record().clone();
    persist(provider, store, row, pending, |row| {
        row.iv.as_mut().unwrap().end = record.exclusive_end()
    })?;
    block.activate_after_commit(&record, clock.unix_ms(), false)?;
    Ok(())
}

impl Runtime {
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn sync_request(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        start: Start,
        clock: Clock,
        acknowledged: Clock,
        cut: Cut,
        transport: &mut Transport,
    ) -> Result<bool, Error> {
        self.protocol_check()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        let policy = match start {
            Start::New(policy) => policy,
            Start::Retry => self.row.sync_intents[0]
                .as_ref()
                .map(|intent| intent.policy)
                .or_else(|| self.row.window.recovery.as_ref().map(|event| event.policy))
                .ok_or(WindowError::Drop)?,
        };
        validate_intent(&self.row, 0, policy, clock)?;
        let initial_proposal = matches!(start, Start::New(_))
            || self
                .row
                .window
                .recovery
                .as_ref()
                .is_none_or(|event| event.policy != policy);
        let permit = self.permit();
        macro_rules! finish {
            ($window:ident, $prepared:expr, $capture:ident) => {{
                let prepared = $prepared?;
                let record = prepared.record().clone();
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record);
                    row.sync_intents[0].as_mut().unwrap().pending = false;
                })?;
                let write = driver::command(provider, store, Some(self.row.version), &candidate)?;
                self.pending = Some(write.clone());
                if !driver::dispatch(store, &write, cut)? {
                    return Ok(false);
                }
                self.row = candidate;
                self.pending = None;
                let token = prepared.commit_after_durable(&record, acknowledged)?;
                match $window.release_sync_action(token, acknowledged)? {
                    Action::SendRequest(bytes) => transport.submit(&permit, &bytes)?,
                    _ => return Err(WindowError::InvalidRecord.into()),
                }
                Ok(true)
            }};
        }
        match &mut self.state {
            State::Gcm { window, allocator } => {
                let admitted = if initial_proposal {
                    window.begin_sync(policy, clock, None)?
                } else {
                    window.retry_sync(clock)?
                };
                intent(
                    provider,
                    store,
                    &mut self.row,
                    &mut self.pending,
                    0,
                    policy,
                    clock,
                )?;
                let prepared = loop {
                    match allocator.allocate(Purpose::Ordinary) {
                        Ok(allocation) => {
                            break admitted.prepare(self.row.profile, &self.row.keys, allocation)
                        }
                        Err(IvError::ReservationRequired) => reserve(
                            provider,
                            store,
                            &mut self.row,
                            &mut self.pending,
                            allocator,
                            policy,
                            clock,
                        )?,
                        Err(error) => return Err(error.into()),
                    }
                };
                finish!(window, prepared, gcm)
            }
            State::Cbc { window, .. } => {
                let admitted = if initial_proposal {
                    window.begin_sync(policy, clock, None)?
                } else {
                    window.retry_sync(clock)?
                };
                intent(
                    provider,
                    store,
                    &mut self.row,
                    &mut self.pending,
                    0,
                    policy,
                    clock,
                )?;
                finish!(
                    window,
                    admitted.prepare(self.row.profile, &self.row.keys),
                    cbc
                )
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn sync_response(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        admitted_inbound: Option<&[u8]>,
        policy: Policy,
        clock: Clock,
        cut: Cut,
        transport: &mut Transport,
    ) -> Result<Option<Disposition>, Error> {
        self.protocol_check()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        // Reject an unusable policy before SDK admission creates a cutover
        // witness. A refused policy must not leave an uncertain receive window.
        validate_intent(&self.row, 1, policy, clock)?;
        let permit = self.permit();
        macro_rules! finish {
            ($window:ident, $prepared:expr, $capture:ident) => {{
                let prepared = $prepared?;
                let record = prepared.record().clone();
                let disposition = record
                    .sync_state()
                    .ok_or(WindowError::InvalidRecord)?
                    .disposition();
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record);
                    row.sync_intents[1].as_mut().unwrap().pending = false;
                    if disposition == Disposition::OutcomeUncertain {
                        let pending: Vec<_> = row
                            .operations
                            .values()
                            .filter(|op| op.outcome == Outcome::Pending)
                            .map(|op| op.id)
                            .collect();
                        for id in pending {
                            super::ke::finish_operation(row, id, Outcome::Uncertain, None);
                        }
                    }
                })?;
                let write = driver::command(provider, store, Some(self.row.version), &candidate)?;
                self.pending = Some(write.clone());
                if !driver::dispatch(store, &write, cut)? {
                    return Ok(None);
                }
                self.row = candidate;
                self.pending = None;
                let token = prepared.commit_after_durable(&record)?;
                let (bytes, disposition) = $window.release_sync_response(token)?.into_parts();
                transport.submit(&permit, &bytes)?;
                Ok(Some(disposition))
            }};
        }
        match &mut self.state {
            State::Gcm { window, allocator } => {
                let inbound = admitted_inbound
                    .map(|packet| window.open_peer(self.row.profile, &self.row.keys, packet))
                    .transpose()?;
                let admitted = window.begin_sync_response(
                    self.row.profile,
                    &self.row.keys,
                    packet,
                    None,
                    inbound.as_ref(),
                )?;
                intent(
                    provider,
                    store,
                    &mut self.row,
                    &mut self.pending,
                    1,
                    policy,
                    clock,
                )?;
                let prepared = loop {
                    match allocator.allocate(Purpose::Ordinary) {
                        Ok(allocation) => {
                            break admitted.prepare(self.row.profile, &self.row.keys, allocation)
                        }
                        Err(IvError::ReservationRequired) => reserve(
                            provider,
                            store,
                            &mut self.row,
                            &mut self.pending,
                            allocator,
                            policy,
                            clock,
                        )?,
                        Err(error) => return Err(error.into()),
                    }
                };
                finish!(window, prepared, gcm)
            }
            State::Cbc { window, .. } => {
                let inbound = admitted_inbound
                    .map(|packet| window.open_peer(self.row.profile, &self.row.keys, packet))
                    .transpose()?;
                let admitted = window.begin_sync_response(
                    self.row.profile,
                    &self.row.keys,
                    packet,
                    None,
                    inbound.as_ref(),
                )?;
                intent(
                    provider,
                    store,
                    &mut self.row,
                    &mut self.pending,
                    1,
                    policy,
                    clock,
                )?;
                finish!(
                    window,
                    admitted.prepare(self.row.profile, &self.row.keys),
                    cbc
                )
            }
        }
    }

    pub fn sync_complete(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        admitted: Clock,
        acknowledged: Clock,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.protocol_check()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        macro_rules! complete {
            ($window:ident, $capture:ident) => {{
                let prepared =
                    $window.complete_sync(self.row.profile, &self.row.keys, packet, admitted)?;
                let record = prepared.record().clone();
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record)
                })?;
                let write = driver::command(provider, store, Some(self.row.version), &candidate)?;
                self.pending = Some(write.clone());
                if !driver::dispatch(store, &write, cut)? {
                    return Ok(false);
                }
                self.row = candidate;
                self.pending = None;
                let token = prepared.commit_after_durable(&record, acknowledged)?;
                if !matches!(
                    $window.release_sync_action(token, acknowledged)?,
                    Action::Recovered
                ) {
                    return Err(WindowError::InvalidRecord.into());
                }
                Ok(true)
            }};
        }
        match &mut self.state {
            State::Gcm { window, .. } => complete!(window, gcm),
            State::Cbc { window, .. } => complete!(window, cbc),
        }
    }

    pub fn sync_deadline(&mut self, clock: Clock) -> Result<(), Error> {
        self.check()?;
        let mut preproposal = false;
        for (index, intent) in self.row.sync_intents.iter().enumerate() {
            if let Some(intent) = intent.as_ref().filter(|intent| intent.pending) {
                validate_intent(&self.row, index, intent.policy, clock)?;
                preproposal = true;
            }
        }
        if preproposal && self.row.window.recovery.is_none() {
            return Ok(());
        }
        match &mut self.state {
            State::Gcm { window, .. } => window.check_sync_deadline(clock)?,
            State::Cbc { window, .. } => window.check_sync_deadline(clock)?,
        }
        Ok(())
    }

    pub fn sync_close(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.check()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        let image = if self
            .row
            .window
            .sync
            .as_ref()
            .is_some_and(|sync| sync.disposition == Disposition::OutcomeUncertain)
            || (self.row.window.recovery.is_none()
                && self.row.sync_intents.iter().any(Option::is_some))
        {
            self.row.window.clone()
        } else {
            match &mut self.state {
                State::Gcm { window, .. } => {
                    let prepared = window.close_sync()?;
                    WindowImage::gcm(prepared.record())
                }
                State::Cbc { window, .. } => {
                    let prepared = window.close_sync()?;
                    WindowImage::cbc(prepared.record())
                }
            }
        };
        let candidate = self.row.next_write(store.stamp(), |row| {
            row.window = image;
            let pending: Vec<_> = row
                .operations
                .values()
                .filter(|op| op.outcome == Outcome::Pending)
                .map(|op| op.id)
                .collect();
            for id in pending {
                super::ke::finish_operation(row, id, Outcome::Abandoned, None);
            }
            row.closed = true;
        })?;
        let write = driver::command(provider, store, Some(self.row.version), &candidate)?;
        self.terminal_intent = true;
        self.pending = Some(write.clone());
        if !driver::dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve(provider, store, &write)?;
        Ok(true)
    }
}
