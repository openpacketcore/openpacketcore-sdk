//! INITIAL_CONTACT is held through authentication, including the fixture's
//! EAP completion AUTH. Sealed cleanup intents accompany the final result.
//! This exercises the hand-off from an authenticated handshake, not an AAA/EAP
//! implementation or a real consumer's identity index.
use super::{
    auth,
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    peer::{Event, PeerModel},
    row::{ContactVictim, Row},
    store::{CasStore, Command, CurrentCut, Mutation, RowKey},
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, decode_ike_auth_cleartext_payloads,
    decode_ikev2_initial_contact_notify, Ikev2ExchangeKind as Exchange,
    Ikev2IkeAuthPayloadBuild as Payload, PayloadChain, PayloadType,
};
use std::collections::BTreeSet;

pub struct Pending {
    key: RowKey,
    birth: u64,
    identity: Vec<u8>,
    namespace: u64,
}
pub struct Authenticated {
    key: RowKey,
    birth: u64,
    identity: u64,
    namespace: u64,
    final_wire: Bytes,
}

/// A sender with parallel independent instances omits the notification. This
/// sender policy supplies no receiving-side identity or cleanup authority.
pub fn first_payload(row: &Row, parallel_instances: bool) -> (PayloadType, Bytes) {
    let response = auth::initiator(row);
    let mut entries = vec![Payload {
        payload_type: if response {
            PayloadType::IdentificationResponder
        } else {
            PayloadType::IdentificationInitiator
        },
        body: auth::identity(response),
    }];
    if !parallel_instances {
        entries.push(Payload {
            payload_type: PayloadType::Notify,
            body: vec![0, 0, 0x40, 0],
        });
    }
    build_ike_auth_cleartext_payload_chain(&entries).unwrap()
}
pub fn begin(row: &Row, packet: &[u8], namespace: u64) -> Result<Option<Pending>, driver::Error> {
    let opened = Wire::new(row.profile, &row.keys, row.spis, row.direction)
        .open(packet)
        .map_err(|_| envelope::Error::Integrity)?;
    if opened.header.exchange_type != 35
        || opened.header.message_id != 1
        || opened.header.flags.response() != auth::initiator(row)
    {
        return Err(envelope::Error::Format.into());
    }
    let payloads = decode_ike_auth_cleartext_payloads(opened.first, &opened.body)
        .map_err(|_| envelope::Error::Format)?;
    let identity = if auth::initiator(row) {
        &payloads.identification_responders
    } else {
        &payloads.identification_initiators
    };
    let foreign = if auth::initiator(row) {
        &payloads.identification_initiators
    } else {
        &payloads.identification_responders
    };
    if identity.len() != 1 || !foreign.is_empty() {
        return Err(envelope::Error::Format.into());
    }
    let mut contacts = 0;
    for notify in payloads.notifies {
        if decode_ikev2_initial_contact_notify(notify)
            .map_err(|_| envelope::Error::Format)?
            .is_some()
        {
            contacts += 1;
        }
    }
    if contacts == 0 {
        return Ok(None);
    }
    if contacts != 1 {
        return Err(envelope::Error::Format.into());
    }
    let id = identity[0];
    let mut exact = vec![id.id_type];
    exact.extend_from_slice(&id.reserved);
    exact.extend_from_slice(id.id_data);
    Ok(Some(Pending {
        key: row.key,
        birth: row.version.birth,
        identity: exact,
        namespace,
    }))
}
impl Pending {
    pub fn complete(self, row: &Row, final_packet: &[u8]) -> Result<Authenticated, driver::Error> {
        if self.key != row.key || self.birth != row.version.birth {
            return Err(envelope::Error::Format.into());
        }
        let response = auth::initiator(row);
        let opened = Wire::new(row.profile, &row.keys, row.spis, row.direction)
            .open(final_packet)
            .map_err(|_| envelope::Error::Integrity)?;
        auth::verify(row, &opened, response)?;
        // The prior authenticated/EAP context authorizes this exact ID body. The
        // numeric identity is a test authorization-index value, never an IP/SPI.
        if self.identity != auth::identity(response) {
            return Err(envelope::Error::Integrity.into());
        }
        Ok(Authenticated {
            key: self.key,
            birth: self.birth,
            identity: 11,
            namespace: self.namespace,
            final_wire: Bytes::copy_from_slice(final_packet),
        })
    }
}
impl Authenticated {
    fn plan(
        &self,
        provider: &Provider,
        store: &CasStore,
        joined: &CurrentCut,
        new: &Row,
        candidates: &[RowKey],
    ) -> Result<Vec<ContactVictim>, driver::Error> {
        if self.key != new.key
            || self.birth != new.version.birth
            || self.identity != new.identity
            || self.namespace != new.namespace
        {
            return Err(envelope::Error::Format.into());
        }
        let mut seen = BTreeSet::new();
        let mut victims = Vec::new();
        for &key in candidates {
            if key == new.key || !seen.insert(key) {
                continue;
            }
            let current = store.current_after_join(joined, key)?;
            let Some(stored) = current.row() else {
                continue;
            };
            let plain = envelope::unseal(provider, key, stored)?;
            let row = ProfileCodec::decode(&plain, key, stored.version, stored.sealed_stamp)?;
            if !row.closed && row.identity == self.identity && row.namespace == self.namespace {
                victims.push(ContactVictim {
                    key,
                    birth: row.version.birth,
                    identity: row.identity,
                    namespace: row.namespace,
                });
            }
        }
        Ok(victims)
    }
    pub fn commit(
        self,
        provider: &Provider,
        store: &mut CasStore,
        joined: &CurrentCut,
        runtime: &mut Runtime,
        candidates: &[RowKey],
        cut: Cut,
    ) -> Result<bool, driver::Error> {
        runtime.protocol_check()?;
        let victims = self.plan(provider, store, joined, &runtime.row, candidates)?;
        let outcome = Bytes::from_static(b"contact-auth-established");
        if auth::initiator(&runtime.row) {
            Ok(runtime
                .complete(
                    provider,
                    store,
                    &self.final_wire,
                    outcome,
                    |row| {
                        row.contact_cleanup = victims;
                        row.contact_auth = Some(self.final_wire.clone());
                    },
                    cut,
                )?
                .is_some())
        } else {
            let (first, response) = auth::payload(&runtime.row, true);
            runtime
                .publish_response(
                    provider,
                    store,
                    &self.final_wire,
                    PayloadChain::new(first, &response),
                    outcome,
                    |row| {
                        row.contact_cleanup = victims;
                        row.contact_auth = Some(self.final_wire.clone());
                    },
                    cut,
                )
                .map(|result| result.is_some())
        }
    }
}

pub fn cleanup(
    provider: &Provider,
    store: &mut CasStore,
    owners: &EpochOwners,
    joined: &CurrentCut,
    new: &Runtime,
    victim: RowKey,
    cut: Cut,
) -> Result<Option<Command>, driver::Error> {
    new.protocol_check()?;
    if new.pending.is_some() {
        return Err(driver::Error::Unresolved);
    }
    let current = store.refresh_fenced(joined)?;
    let stored = current.row().ok_or(envelope::Error::Format)?;
    let plain = envelope::unseal(provider, current.key(), stored)?;
    let row = ProfileCodec::decode(&plain, current.key(), stored.version, stored.sealed_stamp)?;
    if row.closed
        || row.key != new.row.key
        || row.version != new.row.version
        || new.permit().binding() != (row.key, row.version.birth, current.stamp())
    {
        return Err(envelope::Error::Format.into());
    }
    // The final exchange cache may already contain later traffic. Its sealed
    // authentication proof was committed with these immutable cleanup intents.
    let packet = row.contact_auth.as_ref().ok_or(envelope::Error::Format)?;
    let opened = Wire::new(row.profile, &row.keys, row.spis, row.direction)
        .open(packet)
        .map_err(|_| envelope::Error::Integrity)?;
    auth::verify(&row, &opened, auth::initiator(&row))?;
    let intent = row
        .contact_cleanup
        .iter()
        .find(|intent| intent.key == victim)
        .ok_or(envelope::Error::Format)?;
    if victim == row.key || intent.identity != row.identity || intent.namespace != row.namespace {
        return Err(envelope::Error::Format.into());
    }
    let target = store.current_after_join(&current, victim)?;
    let Some(stored) = target.row() else {
        return Ok(None);
    };
    let plain = envelope::unseal(provider, victim, stored)?;
    let target_row = ProfileCodec::decode(&plain, victim, stored.version, stored.sealed_stamp)?;
    if target_row.version.birth != intent.birth
        || target_row.identity != intent.identity
        || target_row.namespace != intent.namespace
    {
        return Ok(None);
    }
    let target_owner = owners.acquire(&target)?;
    let write = Command::new(
        store.next_request(),
        vec![Mutation {
            key: victim,
            expected: Some(target_row.version),
            value: None,
        }],
    )?;
    new.permit()
        .while_both_current(&target_owner.permit(), || {
            driver::dispatch(store, &write, cut)
        })??;
    Ok(Some(write))
}

pub fn final_exchange(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    peer: &mut PeerModel<'_>,
    transport: &mut Transport,
) -> Bytes {
    runtime
        .reserve(provider, store, 19, 1, 100, Cut::Complete, Cut::Complete)
        .unwrap();
    if auth::initiator(&runtime.row) {
        let (first, request) = auth::payload(&runtime.row, false);
        runtime
            .publish_request(
                provider,
                store,
                Exchange::IkeAuth,
                PayloadChain::new(first, &request),
                |_| {},
                Cut::Complete,
            )
            .unwrap();
        runtime.dispatch_replay(transport).unwrap();
        assert_eq!(
            peer.receive(transport.submitted.last().unwrap()),
            Ok(Event::NewRequest(auth::FINAL_ID))
        );
    }
    let response = auth::initiator(&runtime.row);
    let (first, body) = auth::payload(&runtime.row, response);
    if response {
        peer.respond(auth::FINAL_ID, PayloadChain::new(first, &body))
            .unwrap()
    } else {
        peer.request(35, PayloadChain::new(first, &body)).unwrap()
    }
}
