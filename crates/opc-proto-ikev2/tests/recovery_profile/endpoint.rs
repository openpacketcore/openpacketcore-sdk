//! Endpoint evidence is separate from the zero-write empty response. A committed
//! candidate destination permits one real request; it is not an accepted route.
use super::{
    authority::{SendPermit, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime, State},
    envelope::{self, Provider},
    row::Challenge,
    store::{CasStore, CurrentCut, RowKey},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{Ikev2EmptyReplyObservation as Observation, Ikev2WindowError as Window},
    Ikev2ExchangeKind as Exchange, PayloadChain,
};
use std::collections::BTreeMap;

pub type Address = (u32, u16);
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    PeerNat,
    LocalNat,
    Mobike,
}

pub struct Probe {
    permit: SendPermit,
    request: Bytes,
    destination: Address,
}
#[derive(Default)]
pub struct Routes {
    accepted: BTreeMap<(RowKey, u64), Address>,
    pub changes: usize,
}
impl Routes {
    pub fn get(&self, runtime: &Runtime) -> Option<Address> {
        self.accepted
            .get(&(runtime.row.key, runtime.row.version.birth))
            .copied()
    }
    pub fn adopt(
        &mut self,
        provider: &Provider,
        store: &CasStore,
        joined: &CurrentCut,
        runtime: &Runtime,
    ) -> Result<bool, driver::Error> {
        runtime.protocol_check()?;
        if runtime.pending.is_some() {
            return Err(driver::Error::Unresolved);
        }
        let current = store.refresh_fenced(joined)?;
        let stored = current.row().ok_or(envelope::Error::Format)?;
        let plain = envelope::unseal(provider, current.key(), stored)?;
        let row = ProfileCodec::decode(&plain, current.key(), stored.version, stored.sealed_stamp)?;
        if row.version != runtime.row.version
            || row.closed
            || runtime.permit().binding() != (row.key, row.version.birth, current.stamp())
        {
            return Err(envelope::Error::Format.into());
        }
        let destination = row.endpoint.ok_or(envelope::Error::Format)?;
        let key = (row.key, row.version.birth);
        runtime
            .permit()
            .while_current(|| {
                if self.accepted.get(&key) == Some(&destination) {
                    return false;
                }
                self.accepted.insert(key, destination);
                self.changes += 1;
                true
            })
            .map_err(Into::into)
    }
}
impl Runtime {
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep storage boundaries and fault cuts explicit in the composition fixture."
    )]
    pub fn endpoint_empty(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        packet: &[u8],
        source: Address,
        topology: Topology,
        cut: Cut,
        transport: &mut Transport,
    ) -> Result<bool, driver::Error> {
        let observation = self.reply_empty(packet, transport)?;
        if topology != Topology::PeerNat
            || observation != Observation::Fresh
            || self.row.endpoint == Some(source)
        {
            return Ok(false);
        }
        let opened = Wire::new(
            self.row.profile,
            &self.row.keys,
            self.row.spis,
            self.row.direction,
        )
        .open(packet)
        .map_err(|_| Window::Drop)?;
        if opened.header.message_id.checked_add(1) != self.next_receive() {
            return Ok(false);
        }
        if self.pending.is_some() {
            return Err(driver::Error::Unresolved);
        }
        let candidate = self
            .row
            .next_write(store.stamp(), |row| row.endpoint = Some(source))?;
        let write = driver::command(provider, store, Some(self.row.version), &candidate)?;
        self.pending = Some(write.clone());
        if !driver::dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve(provider, store, &write)?;
        Ok(true)
    }
    pub fn begin_probe(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        destination: Address,
        payload: PayloadChain<'_>,
        cut: Cut,
    ) -> Result<Option<Probe>, driver::Error> {
        self.protocol_check()?;
        if self
            .row
            .window
            .outbound
            .as_ref()
            .is_some_and(|entry| entry.response().is_none())
        {
            return Err(Window::RequestOutstanding.into());
        }
        if !self.publish_request(
            provider,
            store,
            Exchange::Informational,
            payload,
            |row| {
                row.challenge = Some(Challenge {
                    destination,
                    request: Bytes::copy_from_slice(
                        row.window.outbound.as_ref().unwrap().request(),
                    ),
                });
            },
            cut,
        )? {
            return Ok(None);
        }
        let challenge = self.row.challenge.as_ref().unwrap();
        Ok(Some(Probe {
            permit: self.permit(),
            request: challenge.request.clone(),
            destination,
        }))
    }
    pub fn dispatch_probe(
        &mut self,
        probe: &Probe,
        transport: &mut Transport,
    ) -> Result<(), driver::Error> {
        self.protocol_check()?;
        probe.permit.check()?;
        if self.pending.is_some()
            || probe.permit.binding() != self.permit().binding()
            || self.row.challenge.as_ref().is_none_or(|intent| {
                intent.request != probe.request || intent.destination != probe.destination
            })
        {
            return Err(Window::StaleCompletion.into());
        }
        let permit = self.permit();
        macro_rules! send {
            ($window:ident) => {{
                let replay = $window.replay_request()?.ok_or(Window::Drop)?;
                if replay.bytes() != probe.request {
                    return Err(Window::Drop.into());
                }
                transport.submit_to(&permit, replay.bytes(), probe.destination)?;
            }};
        }
        match &mut self.state {
            State::Gcm { window, .. } => send!(window),
            State::Cbc { window, .. } => send!(window),
        }
        Ok(())
    }
    pub fn complete_probe(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        probe: &Probe,
        response: &[u8],
        source: Address,
        cut: Cut,
    ) -> Result<bool, driver::Error> {
        self.protocol_check()?;
        probe.permit.check()?;
        if probe.permit.binding() != self.permit().binding()
            || source != probe.destination
            || self.row.challenge.as_ref().is_none_or(|intent| {
                intent.request != probe.request || intent.destination != source
            })
        {
            return Err(Window::Drop.into());
        }
        Ok(self
            .complete(
                provider,
                store,
                response,
                Bytes::from_static(b"fresh-endpoint-operation-completed"),
                |row| {
                    row.endpoint = Some(source);
                    row.challenge = None;
                },
                cut,
            )?
            .is_some())
    }
}
