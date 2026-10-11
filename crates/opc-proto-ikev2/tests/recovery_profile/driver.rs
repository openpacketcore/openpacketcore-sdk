//! Test consumer of public APIs. Complete-row CAS, ownership and transport are
//! explicit boundaries; cloned SDK records are never storage acknowledgements.
//! Store dispatch owns its candidate after dropping every prepared-window borrow.
//! Even an immediate acknowledgement takes fenced in-place readback, creating no
//! SDK completion token. Outcome application needs the separate consumer fence
//! and idempotency boundary as it does after a lost acknowledgement.

use super::{
    authority::{self, EpochOwners, Owner, SendPermit, Transport},
    codec::ProfileCodec,
    envelope::{self, Provider},
    row::{RetryImage, Row, WindowImage},
    store::{self, CasStore, Command, CurrentCut, Mutation, Version},
};
use bytes::Bytes;
use opc_proto_ikev2::{
    canonical::{Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalPolicy as Policy},
    recovery::{
        Ikev2CbcEpochRecord as CbcEpoch, Ikev2CbcRecoveryProfile as Cbc,
        Ikev2CommittedWindow as Window, Ikev2EmptyReplyObservation as Observation,
        Ikev2OrdinaryRequestDisposition as Disposition, Ikev2ReservationRetry as Retry,
        Ikev2ReservationRetryError as RetryError, Ikev2ReservationRetryPolicy as RetryPolicy,
        Ikev2ReservationRetryRecord as RetryRecord, Ikev2WindowError as WindowError,
    },
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvReservationError as IvError, Ikev2ExchangeKind as Exchange, PayloadChain,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Store(store::Error),
    Key(envelope::Error),
    Owner(authority::Error),
    Window(WindowError),
    Iv(IvError),
    Retry(RetryError),
    Closed,
    Unresolved,
    NotCommittedDelete,
}
macro_rules! from {
    ($source:ty, $variant:ident) => {
        impl From<$source> for Error {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
from!(store::Error, Store);
from!(envelope::Error, Key);
from!(authority::Error, Owner);
from!(WindowError, Window);
from!(IvError, Iv);
from!(RetryError, Retry);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    BeforeDispatch,
    Dispatched,
    Applied,
    Acknowledged,
    Complete,
}

pub fn command(
    provider: &Provider,
    store: &CasStore,
    prior: Option<Version>,
    row: &Row,
) -> Result<Command, Error> {
    command_bundle(provider, store, prior, row, None)
}

/// The old window/result and the fresh rekey epoch occupy one child CAS.
fn command_bundle(
    provider: &Provider,
    store: &CasStore,
    prior: Option<Version>,
    row: &Row,
    new_epoch: Option<&Row>,
) -> Result<Command, Error> {
    let encoded = ProfileCodec::encode(row)?;
    let sealed = envelope::seal(provider, row.key, row.version, row.sealed_stamp, &encoded)?;
    let mut mutations = vec![Mutation {
        key: row.key,
        expected: prior,
        value: Some(sealed),
    }];
    if let Some(epoch) = new_epoch {
        let encoded = ProfileCodec::encode(epoch)?;
        let sealed = envelope::seal(
            provider,
            epoch.key,
            epoch.version,
            epoch.sealed_stamp,
            &encoded,
        )?;
        mutations.push(Mutation {
            key: epoch.key,
            expected: None,
            value: Some(sealed),
        });
    }
    Ok(Command::new(store.next_request(), mutations)?)
}

/// Fault cuts deliberately omit the SDK acknowledgement even when storage has
/// applied. An outstanding observer never holds an exclusive window borrow.
pub(super) fn dispatch(store: &mut CasStore, command: &Command, cut: Cut) -> Result<bool, Error> {
    if cut == Cut::BeforeDispatch {
        return Ok(false);
    }
    store.dispatch(command.clone())?;
    if cut == Cut::Dispatched {
        return Ok(false);
    }
    store.apply(command.request())?;
    if cut == Cut::Applied {
        return Ok(false);
    }
    let receipt = store.acknowledge(command)?;
    receipt.acknowledges(command)?;
    for mutation in command.mutations() {
        if receipt.version(mutation.key) != mutation.value.as_ref().map(|row| row.version) {
            return Err(store::Error::AcknowledgementMismatch.into());
        }
    }
    Ok(cut == Cut::Complete)
}

pub fn create(provider: &Provider, store: &mut CasStore, row: &Row) -> Result<Command, Error> {
    let command = command(provider, store, None, row)?;
    assert!(dispatch(store, &command, Cut::Complete)?);
    Ok(command)
}

fn decode(provider: &Provider, cut: &CurrentCut) -> Result<Row, Error> {
    let stored = cut.row().ok_or(Error::Closed)?;
    let plain = envelope::unseal(provider, cut.key(), stored)?;
    Ok(ProfileCodec::decode(
        &plain,
        cut.key(),
        stored.version,
        stored.sealed_stamp,
    )?)
}

pub(super) enum State {
    Gcm {
        window: Box<Window>,
        allocator: Box<Allocator>,
    },
    Cbc {
        window: Box<Window<Cbc>>,
        epoch: Box<CbcEpoch>,
    },
}

pub struct Runtime {
    // The owner remains alive for the entire window/allocator lifetime.
    pub(super) state: State,
    owner: Owner,
    pub row: Row,
    pub pending: Option<Command>,
    pub(super) terminal_intent: bool,
}

macro_rules! with_window {
    ($self:expr, $window:ident, $body:expr) => {
        match &mut $self.state {
            State::Gcm {
                window: $window, ..
            } => $body,
            State::Cbc {
                window: $window, ..
            } => $body,
        }
    };
}

impl Runtime {
    pub fn restore(
        provider: &Provider,
        owners: &EpochOwners,
        cut: &CurrentCut,
        enable_empty: bool,
    ) -> Result<Self, Error> {
        let row = decode(provider, cut)?;
        if row.closed {
            return Err(Error::Closed);
        }
        let owner = owners.acquire(cut)?;
        owner.permit().check()?;
        super::ke::validate_row(&row)?;
        let policy = Policy::explicitly_allow_declared_validated();
        let state = if row.profile.encryption().is_aead() {
            let (record, iv, _) = row.gcm()?;
            Canonical::preflight(row.profile.encryption(), policy)
                .map_err(|e| Error::Window(WindowError::Canonical(e)))?;
            let mut window =
                Window::restore(record.domain(), row.profile, &row.keys, &record, &iv)?;
            let allocator = Allocator::restore(iv.domain(), &iv)?;
            if enable_empty && window.ready().is_ok() {
                window.enable_empty_replies(policy)?;
            }
            State::Gcm {
                window: Box::new(window),
                allocator: Box::new(allocator),
            }
        } else {
            let (record, epoch) = row.cbc()?;
            Canonical::preflight_cbc(row.profile, policy)
                .map_err(|e| Error::Window(WindowError::Canonical(e)))?;
            let mut window =
                Window::<Cbc>::restore(record.domain(), row.profile, &row.keys, &record, &epoch)?;
            if enable_empty && window.ready().is_ok() {
                window.enable_empty_replies(policy)?;
            }
            State::Cbc {
                window: Box::new(window),
                epoch: Box::new(epoch),
            }
        };
        Ok(Self {
            state,
            owner,
            row,
            pending: None,
            terminal_intent: false,
        })
    }

    pub fn permit(&self) -> SendPermit {
        self.owner.permit()
    }
    pub fn revoke(&self) {
        self.owner.revoke();
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.owner.permit().check()?;
        if self.row.closed {
            return Err(Error::Closed);
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|command| command.mutations().iter().any(|m| m.value.is_none()))
        {
            return Err(Error::Unresolved);
        }
        Ok(())
    }
    pub(super) fn protocol_check(&self) -> Result<(), Error> {
        self.check()?;
        if self.terminal_intent {
            return Err(Error::Closed);
        }
        Ok(())
    }
    fn ordinary(&self) -> Result<(), Error> {
        self.protocol_check()?;
        if self
            .row
            .sync_intents
            .iter()
            .flatten()
            .any(|intent| intent.pending)
        {
            return Err(WindowError::SyncInProgress.into());
        }
        Ok(())
    }
    fn writable(&mut self) -> Result<(), Error> {
        self.ordinary()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        with_window!(self, window, window.ready())?;
        Ok(())
    }

    /// In-place readback retains the live allocator and canonical reply cache.
    /// A pruned receipt is resolved only by the store's fenced latest cut.
    pub fn resolve(
        &mut self,
        provider: &Provider,
        store: &CasStore,
        prior: &Command,
    ) -> Result<(), Error> {
        self.check()?;
        let cut = store.fenced_read(prior, self.row.key)?;
        let row = decode(provider, &cut)?;
        super::ke::validate_row(&row)?;
        if cut.stamp() != self.permit().binding().2 || row.version.birth != self.row.version.birth {
            return Err(authority::Error::Revoked.into());
        }
        match &mut self.state {
            State::Gcm { window, .. } => {
                let (record, iv, _) = row.gcm()?;
                window.reconcile(row.profile, &row.keys, &record, &iv)?;
            }
            State::Cbc { window, epoch } => {
                let (record, stored_epoch) = row.cbc()?;
                window.reconcile(row.profile, &row.keys, &record, &stored_epoch)?;
                **epoch = stored_epoch;
            }
        }
        if row.closed {
            self.owner.revoke();
        }
        self.row = row;
        self.pending = None;
        Ok(())
    }

    fn is_delete_entry(
        &self,
        entry: &opc_proto_ikev2::recovery::Ikev2CommittedExchangeRecord,
        local: bool,
    ) -> bool {
        let sending = if local {
            crate::canonical_fixtures::opposite(self.row.direction)
        } else {
            self.row.direction
        };
        super::wire::Wire::new(self.row.profile, &self.row.keys, self.row.spis, sending)
            .open(entry.request())
            .is_ok_and(|packet| {
                packet.header.exchange_type == 37
                    && packet.first == opc_proto_ikev2::PayloadType::Delete
                    && packet.body.as_ref() == crate::canonical_fixtures::DELETE
            })
    }

    fn has_delete_intent(&self) -> bool {
        self.row
            .window
            .inbound
            .as_ref()
            .is_some_and(|entry| entry.outcome() == Some(b"invalid-syntax".as_slice()))
            || [
                (&self.row.window.outbound, true),
                (&self.row.window.inbound, false),
            ]
            .into_iter()
            .any(|(entry, local)| {
                entry
                    .as_ref()
                    .is_some_and(|entry| self.is_delete_entry(entry, local))
            })
    }

    /// The old epoch survives until its ordinary Delete result commits. This
    /// removes only the exact old birth/generation and leaves its successor.
    pub fn erase_after_delete(&mut self, store: &mut CasStore, cut: Cut) -> Result<bool, Error> {
        // The committed Delete result already revoked packet/effect authority.
        // Scoped cleanup still needs this execution stamp and exact row CAS.
        if self.permit().binding().2 != store.stamp() {
            return Err(authority::Error::Revoked.into());
        }
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        let settled = [
            (&self.row.window.outbound, true),
            (&self.row.window.inbound, false),
        ]
        .into_iter()
        .any(|(entry, local)| {
            entry.as_ref().is_some_and(|entry| {
                self.is_delete_entry(entry, local)
                    && entry.response().is_some()
                    && entry.outcome() == Some(b"ike-deleted".as_slice())
            })
        });
        if !settled || !self.row.closed {
            return Err(Error::NotCommittedDelete);
        }
        let write = Command::new(
            store.next_request(),
            vec![Mutation {
                key: self.row.key,
                expected: Some(self.row.version),
                value: None,
            }],
        )?;
        self.pending = Some(write.clone());
        if !dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve_deletion(store, &write)?;
        Ok(true)
    }

    pub fn resolve_deletion(&mut self, store: &CasStore, prior: &Command) -> Result<(), Error> {
        if !self.row.closed || self.permit().binding().2 != store.stamp() {
            return Err(Error::NotCommittedDelete);
        }
        if prior.mutations().len() != 1
            || prior.mutations()[0].key != self.row.key
            || prior.mutations()[0].expected != Some(self.row.version)
            || prior.mutations()[0].value.is_some()
        {
            return Err(store::Error::AcknowledgementMismatch.into());
        }
        let cut = store.fenced_read(prior, self.row.key)?;
        if cut.stamp() != self.permit().binding().2 || cut.row().is_some() {
            return Err(Error::NotCommittedDelete);
        }
        self.owner.revoke();
        self.row.closed = true;
        self.pending = None;
        Ok(())
    }

    /// Permanent cleanup differs from dropping a runtime for later readback.
    pub fn delete(self) -> Result<(), Error> {
        if !self.row.closed || self.pending.is_some() {
            return Err(Error::NotCommittedDelete);
        }
        self.owner.revoke();
        match self.state {
            State::Gcm { window, .. } => window.delete(),
            State::Cbc { window, .. } => window.delete(),
        }
        Ok(())
    }

    pub fn next_receive(&mut self) -> Option<u32> {
        with_window!(self, window, window.next_receive())
    }
    pub fn reconstructing(&mut self) -> bool {
        with_window!(self, window, window.is_reconstructing())
    }

    /// Keep borrowed SDK bytes and the current owner check through submission.
    pub fn dispatch_replay(&mut self, transport: &mut Transport) -> Result<bool, Error> {
        self.ordinary()?;
        let permit = self.permit();
        with_window!(self, window, {
            let Some(replay) = window.replay_request()? else {
                return Ok(false);
            };
            transport.submit(&permit, replay.bytes())?;
        });
        Ok(true)
    }

    pub fn reply_empty(
        &mut self,
        packet: &[u8],
        transport: &mut Transport,
    ) -> Result<Observation, Error> {
        self.ordinary()?;
        let permit = self.permit();
        with_window!(self, window, {
            let opened = window.open_peer(self.row.profile, &self.row.keys, packet)?;
            let reply = window.reply_empty(&opened)?;
            let observation = reply.observation();
            transport.submit(&permit, reply.bytes())?;
            Ok(observation)
        })
    }

    pub fn request_disposition(&mut self, packet: &[u8]) -> Result<Disposition, Error> {
        self.ordinary()?;
        with_window!(self, window, {
            let opened = window.open_peer(self.row.profile, &self.row.keys, packet)?;
            Ok(window.request_disposition(&opened)?)
        })
    }

    pub fn replay_response(
        &mut self,
        packet: &[u8],
        transport: &mut Transport,
    ) -> Result<(), Error> {
        self.ordinary()?;
        let permit = self.permit();
        with_window!(self, window, {
            let opened = window.open_peer(self.row.profile, &self.row.keys, packet)?;
            if window.request_disposition(&opened)? != Disposition::CachedResponse {
                return Err(WindowError::Drop.into());
            }
            let replay = window.replay_response(&opened)?;
            transport.submit(&permit, replay.bytes())?;
        });
        Ok(())
    }

    /// Charge and reserve an ordinary block for an existing real operation. The
    /// complete enclosing row carries every independent pending checkpoint.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn reserve(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        operation: u64,
        count: u64,
        now: u64,
        charge_cut: Cut,
        block_cut: Cut,
    ) -> Result<bool, Error> {
        self.reserve_inner(
            provider,
            store,
            operation,
            count,
            now,
            Purpose::Ordinary,
            charge_cut,
            block_cut,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn reserve_control(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        operation: u64,
        count: u64,
        now: u64,
        charge_cut: Cut,
        block_cut: Cut,
    ) -> Result<bool, Error> {
        self.reserve_inner(
            provider,
            store,
            operation,
            count,
            now,
            Purpose::Control,
            charge_cut,
            block_cut,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    fn reserve_inner(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        operation: u64,
        count: u64,
        now: u64,
        purpose: Purpose,
        charge_cut: Cut,
        block_cut: Cut,
    ) -> Result<bool, Error> {
        self.writable()?;
        let State::Gcm { window, allocator } = &mut self.state else {
            return Ok(true);
        };
        let (_, iv, records) = self.row.gcm()?;
        let retry_record = records
            .into_iter()
            .find(|r| r.operation() == operation)
            .unwrap_or_else(|| {
                RetryRecord::initial(
                    iv.domain().clone(),
                    operation,
                    RetryPolicy::new(now, now + 10_000, 3, 10).unwrap(),
                )
            });
        let mut retry = Retry::restore(iv.domain(), operation, &retry_record)?;
        let charge = retry.prepare_attempt(allocator, now, false)?;
        let charged = charge.record().clone();
        let candidate = self.row.next_write(store.stamp(), |row| {
            row.iv.as_mut().unwrap().retries.insert(
                operation,
                RetryImage {
                    operation,
                    policy: charged.policy(),
                    attempts: charged.attempts(),
                    last_attempt: charged.last_attempt_unix_ms(),
                },
            );
        })?;
        let write = command(provider, store, Some(self.row.version), &candidate)?;
        self.pending = Some(write.clone());
        if !dispatch(store, &write, charge_cut)? {
            return Ok(false);
        }
        let permit = charge.commit_after_durable(&charged)?;
        self.row = candidate;
        self.pending = None;
        let block = permit.prepare(allocator, count, purpose, now, false)?;
        let reserved = block.record().clone();
        let candidate = self.row.next_write(store.stamp(), |row| {
            row.iv.as_mut().unwrap().end = reserved.exclusive_end();
        })?;
        let write = command(provider, store, Some(self.row.version), &candidate)?;
        self.pending = Some(write.clone());
        if !dispatch(store, &write, block_cut)? {
            return Ok(false);
        }
        block.activate_after_commit(&reserved, now, false)?;
        let (record, iv, _) = candidate.gcm()?;
        window.reconcile(candidate.profile, &candidate.keys, &record, &iv)?;
        self.row = candidate;
        self.pending = None;
        Ok(true)
    }

    pub fn publish_request(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        exchange: Exchange,
        payload: PayloadChain<'_>,
        update: impl FnOnce(&mut Row),
        cut: Cut,
    ) -> Result<bool, Error> {
        self.publish_request_inner(
            provider,
            store,
            exchange,
            payload,
            update,
            Purpose::Ordinary,
            cut,
        )
    }

    pub fn publish_control_request(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        exchange: Exchange,
        payload: PayloadChain<'_>,
        update: impl FnOnce(&mut Row),
        cut: Cut,
    ) -> Result<bool, Error> {
        self.publish_request_inner(
            provider,
            store,
            exchange,
            payload,
            update,
            Purpose::Control,
            cut,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    fn publish_request_inner(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        exchange: Exchange,
        payload: PayloadChain<'_>,
        update: impl FnOnce(&mut Row),
        purpose: Purpose,
        cut: Cut,
    ) -> Result<bool, Error> {
        if self.has_delete_intent() {
            return Err(Error::Closed);
        }
        self.writable()?;
        macro_rules! publish {
            ($window:ident, $prepared:expr, $capture:ident) => {{
                let prepared = $prepared?;
                let record = prepared.record().clone();
                drop(prepared);
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record);
                    update(row);
                })?;
                let write = command(provider, store, Some(self.row.version), &candidate)?;
                self.pending = Some(write.clone());
                if !dispatch(store, &write, cut)? {
                    return Ok(false);
                }
                self.resolve(provider, store, &write)?;
                if self.row.version != candidate.version {
                    return Err(store::Error::AcknowledgementMismatch.into());
                }
            }};
        }
        match &mut self.state {
            State::Gcm { window, allocator } => publish!(
                window,
                window.prepare_request(
                    self.row.profile,
                    &self.row.keys,
                    allocator.allocate(purpose)?,
                    exchange,
                    payload
                ),
                gcm
            ),
            State::Cbc { window, .. } => publish!(
                window,
                window.prepare_request(self.row.profile, &self.row.keys, exchange, payload),
                cbc
            ),
        }
        Ok(true)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn publish_response(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        payload: PayloadChain<'_>,
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.publish_response_inner(
            provider,
            store,
            packet,
            payload,
            outcome,
            update,
            None,
            Purpose::Ordinary,
            cut,
        )
    }

    pub fn publish_delete_response(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        let opened = super::wire::Wire::new(
            self.row.profile,
            &self.row.keys,
            self.row.spis,
            self.row.direction,
        )
        .open(packet)
        .map_err(|_| envelope::Error::Integrity)?;
        if opened.header.flags.response()
            || opened.header.exchange_type != 37
            || opened.first != opc_proto_ikev2::PayloadType::Delete
            || opened.body.as_ref() != crate::canonical_fixtures::DELETE
        {
            return Err(Error::NotCommittedDelete);
        }
        self.publish_response_inner(
            provider,
            store,
            packet,
            crate::canonical_fixtures::empty(),
            Bytes::from_static(b"ike-deleted"),
            |_| {},
            None,
            Purpose::Control,
            cut,
        )
    }

    pub fn publish_error_response(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        payload: PayloadChain<'_>,
        update: impl FnOnce(&mut Row),
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.publish_response_inner(
            provider,
            store,
            packet,
            payload,
            Bytes::from_static(b"invalid-syntax"),
            update,
            None,
            Purpose::Control,
            cut,
        )
    }

    /// A responder commits and releases its exact Delete reply before closing
    /// packet authority. A lost process before closure can replay that reply;
    /// after the closure CAS no encryption or retransmission is authorized.
    pub fn close_after_delete_reply(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        transport: &Transport,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.close_after_terminal_reply(provider, store, transport, false, cut)
    }

    pub fn close_after_invalid_syntax_reply(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        transport: &Transport,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.close_after_terminal_reply(provider, store, transport, true, cut)
    }

    fn close_after_terminal_reply(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        transport: &Transport,
        invalid_syntax: bool,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.writable()?;
        let entry = self
            .row
            .window
            .inbound
            .as_ref()
            .ok_or(Error::NotCommittedDelete)?;
        let terminal = if invalid_syntax {
            entry.outcome() == Some(b"invalid-syntax".as_slice())
                && self.row.operations.values().any(|operation| {
                    !operation.initiated_here
                        && operation.outcome == super::row::Outcome::InvalidSyntax
                })
        } else {
            self.is_delete_entry(entry, false) && entry.outcome() == Some(b"ike-deleted".as_slice())
        };
        if !terminal
            || entry.response().is_none_or(|reply| {
                !transport
                    .submitted
                    .iter()
                    .any(|packet| packet.as_ref() == reply)
            })
        {
            return Err(Error::NotCommittedDelete);
        }
        let candidate = self.row.next_write(store.stamp(), |row| {
            super::ke::close_row(row);
        })?;
        let write = command(provider, store, Some(self.row.version), &candidate)?;
        self.pending = Some(write.clone());
        if !dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve(provider, store, &write)?;
        Ok(true)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn publish_rekey_response(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        payload: PayloadChain<'_>,
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        new_epoch: &Row,
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.publish_response_inner(
            provider,
            store,
            packet,
            payload,
            outcome,
            update,
            Some(new_epoch),
            Purpose::Control,
            cut,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    fn publish_response_inner(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        payload: PayloadChain<'_>,
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        new_epoch: Option<&Row>,
        purpose: Purpose,
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        if self.has_delete_intent() {
            return Err(Error::Closed);
        }
        self.writable()?;
        macro_rules! publish {
            ($window:ident, $opened:ident, $prepared:expr, $capture:ident) => {{
                let $opened = $window.open_peer(self.row.profile, &self.row.keys, packet)?;
                if $window.request_disposition(&$opened)? != Disposition::New {
                    return Err(WindowError::Drop.into());
                }
                let prepared = $prepared?;
                let record = prepared.record().clone();
                drop(prepared);
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record);
                    update(row);
                })?;
                let write = command_bundle(
                    provider,
                    store,
                    Some(self.row.version),
                    &candidate,
                    new_epoch,
                )?;
                self.pending = Some(write.clone());
                if !dispatch(store, &write, cut)? {
                    return Ok(None);
                }
                self.resolve(provider, store, &write)?;
                if self.row.version != candidate.version {
                    return Err(store::Error::AcknowledgementMismatch.into());
                }
                self.row
                    .window
                    .inbound
                    .as_ref()
                    .and_then(|entry| entry.outcome())
                    .map(Bytes::copy_from_slice)
            }};
        }
        Ok(match &mut self.state {
            State::Gcm { window, allocator } => publish!(
                window,
                opened,
                window.prepare_response(
                    self.row.profile,
                    &self.row.keys,
                    allocator.allocate(purpose)?,
                    &opened,
                    payload,
                    outcome
                ),
                gcm
            ),
            State::Cbc { window, .. } => publish!(
                window,
                opened,
                window.prepare_response(
                    self.row.profile,
                    &self.row.keys,
                    &opened,
                    payload,
                    outcome
                ),
                cbc
            ),
        })
    }

    /// Scoped terminal cleanup is a complete-row CAS. No checkpoint is
    /// removed from the live operation and no owner is revoked before readback
    /// proves this result committed. An unavailable envelope/store is retryable.
    pub fn retire_operation(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        id: u64,
        outcome: super::row::Outcome,
        cut: Cut,
    ) -> Result<bool, Error> {
        self.check()?;
        if self.pending.is_some() {
            return Err(Error::Unresolved);
        }
        if matches!(
            outcome,
            super::row::Outcome::Pending
                | super::row::Outcome::Success
                | super::row::Outcome::CrossedLoss
        ) || !self.row.operations.contains_key(&id)
        {
            return Err(envelope::Error::Format.into());
        }
        let candidate = self.row.next_write(store.stamp(), |row| {
            let pending: Vec<_> = row
                .operations
                .values()
                .filter(|operation| operation.outcome == super::row::Outcome::Pending)
                .map(|operation| operation.id)
                .collect();
            for id in pending {
                super::ke::finish_operation(row, id, outcome, None);
            }
            row.closed = true;
        })?;
        let write = command(provider, store, Some(self.row.version), &candidate)?;
        self.terminal_intent = true;
        self.pending = Some(write.clone());
        if !dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve(provider, store, &write)?;
        Ok(true)
    }

    pub fn complete(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.complete_inner(provider, store, packet, outcome, update, None, cut)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn complete_rekey(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        new_epoch: &Row,
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.complete_inner(
            provider,
            store,
            packet,
            outcome,
            update,
            Some(new_epoch),
            cut,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    fn complete_inner(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        outcome: Bytes,
        update: impl FnOnce(&mut Row),
        new_epoch: Option<&Row>,
        cut: Cut,
    ) -> Result<Option<Bytes>, Error> {
        self.writable()?;
        macro_rules! complete {
            ($window:ident, $capture:ident) => {{
                let opened = $window.open_peer(self.row.profile, &self.row.keys, packet)?;
                let prepared = $window.prepare_completion(&opened, outcome)?;
                let record = prepared.record().clone();
                drop(prepared);
                let candidate = self.row.next_write(store.stamp(), |row| {
                    row.window = WindowImage::$capture(&record);
                    update(row);
                })?;
                let write = command_bundle(
                    provider,
                    store,
                    Some(self.row.version),
                    &candidate,
                    new_epoch,
                )?;
                self.pending = Some(write.clone());
                if !dispatch(store, &write, cut)? {
                    return Ok(None);
                }
                self.resolve(provider, store, &write)?;
                if self.row.version != candidate.version {
                    return Err(store::Error::AcknowledgementMismatch.into());
                }
                self.row
                    .window
                    .outbound
                    .as_ref()
                    .and_then(|entry| entry.outcome())
                    .map(Bytes::copy_from_slice)
            }};
        }
        Ok(match &mut self.state {
            State::Gcm { window, .. } => complete!(window, gcm),
            State::Cbc { window, .. } => complete!(window, cbc),
        })
    }
}
