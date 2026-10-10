//! Packet-driven RFC 7296 §§2.8, 2.8.2 epoch/Child-SA model. No SDK window,
//! recovery record, operation outcome or consumer handoff selects its winner.

use super::wire::{Packet, Wire, WireError};
use bytes::Bytes;
use opc_proto_ikev2::{Ikev2NoncePayload, Ikev2SaPayload, PayloadChain, PayloadType};
use std::collections::BTreeMap;

pub type Epoch = (u64, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Wire(WireError),
    InvalidRekey,
    UnmatchedResponse,
    ChangedBytes,
    UnknownEpoch,
    AfterDelete,
    AlreadyRekeyed,
    NonceTie,
}

#[derive(Clone)]
struct Offer {
    request: Bytes,
    spi_i: u64,
    nonce_i: Vec<u8>,
    response: Option<Bytes>,
    spi_r: Option<u64>,
    nonce_r: Option<Vec<u8>>,
}

#[derive(Clone)]
struct Delete {
    sender: bool,
    id: u32,
    request: Bytes,
    response: Option<Bytes>,
}

#[derive(Clone)]
pub struct PeerEpochs {
    old: Epoch,
    offers: BTreeMap<(bool, u32), Offer>,
    // Presence means established; false is an authenticated completed Delete.
    epochs: BTreeMap<Epoch, bool>,
    deletes: BTreeMap<Epoch, Delete>,
    children: BTreeMap<u64, Epoch>,
    loser: Option<Epoch>,
}

fn rekey_fields(packet: &Packet) -> Result<(u64, Vec<u8>), Error> {
    let entries = PayloadChain::new(packet.first, &packet.body)
        .iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::InvalidRekey)?;
    if entries.len() != 3
        || entries[0].payload_type != PayloadType::SecurityAssociation
        || entries[1].payload_type != PayloadType::Nonce
        || entries[2].payload_type != PayloadType::KeyExchange
    {
        return Err(Error::InvalidRekey);
    }
    let sa = Ikev2SaPayload::decode_body(entries[0].body).map_err(|_| Error::InvalidRekey)?;
    if sa.proposals.len() != 1 || sa.proposals[0].protocol_id != 1 {
        return Err(Error::InvalidRekey);
    }
    let spi = u64::from_be_bytes(
        sa.proposals[0]
            .spi
            .try_into()
            .map_err(|_| Error::InvalidRekey)?,
    );
    let nonce = Ikev2NoncePayload::decode_body(entries[1].body)
        .map_err(|_| Error::InvalidRekey)?
        .nonce;
    if spi == 0 || !(16..=256).contains(&nonce.len()) || entries[2].body.len() <= 4 {
        return Err(Error::InvalidRekey);
    }
    Ok((spi, nonce.to_vec()))
}

impl PeerEpochs {
    pub fn new(old: Epoch, children: &[u64]) -> Self {
        Self {
            old,
            offers: BTreeMap::new(),
            epochs: BTreeMap::from([(old, true)]),
            deletes: BTreeMap::new(),
            children: children.iter().map(|id| (*id, old)).collect(),
            loser: None,
        }
    }

    pub fn established(&self, epoch: Epoch) -> bool {
        self.epochs.get(&epoch) == Some(&true)
    }

    pub fn child_owner(&self, child: u64) -> Epoch {
        self.children[&child]
    }

    pub fn loser(&self) -> Option<Epoch> {
        self.loser
    }

    /// The receiving wire adapter authenticates every transition, including
    /// observations of the model peer's own outgoing packets.
    pub fn observe(&mut self, receiver: &Wire<'_>, bytes: &[u8]) -> Result<(), Error> {
        let packet = receiver.open(bytes).map_err(Error::Wire)?;
        let mut candidate = self.clone();
        candidate.apply(packet)?;
        *self = candidate;
        Ok(())
    }

    fn apply(&mut self, packet: Packet) -> Result<(), Error> {
        let epoch = (packet.header.initiator_spi, packet.header.responder_spi);
        let sender = packet.header.flags.initiator();
        let response = packet.header.flags.response();
        let id = packet.header.message_id;
        if let Some(delete) = self.deletes.get_mut(&epoch) {
            if response && id == delete.id && sender != delete.sender {
                if packet.header.exchange_type != 37
                    || packet.first != PayloadType::NoNext
                    || !packet.body.is_empty()
                {
                    return Err(Error::UnmatchedResponse);
                }
                if delete
                    .response
                    .as_ref()
                    .is_some_and(|old| old != &packet.wire)
                {
                    return Err(Error::ChangedBytes);
                }
                delete.response = Some(packet.wire);
                self.epochs.insert(epoch, false);
                return Ok(());
            }
            if !response && id == delete.id && sender == delete.sender {
                return if delete.request == packet.wire {
                    Ok(())
                } else {
                    Err(Error::ChangedBytes)
                };
            }
            return Err(Error::AfterDelete);
        }
        if !self.established(epoch) {
            return Err(Error::UnknownEpoch);
        }
        if !response
            && packet.header.exchange_type == 37
            && packet.first == PayloadType::Delete
            && packet.body.as_ref() == [0, 0, 0, 8, 1, 0, 0, 0]
        {
            // No invented transfer: only a completed rekey moves children.
            self.deletes.insert(
                epoch,
                Delete {
                    sender,
                    id,
                    request: packet.wire,
                    response: None,
                },
            );
            return Ok(());
        }
        if packet.header.exchange_type != 36 {
            return Ok(());
        }
        if epoch != self.old {
            return Err(Error::InvalidRekey);
        }
        let (spi, nonce) = rekey_fields(&packet)?;
        let exchange = (if response { !sender } else { sender }, id);
        if !response {
            if let Some(old) = self.offers.get(&exchange) {
                return if old.request == packet.wire {
                    Ok(())
                } else {
                    Err(Error::ChangedBytes)
                };
            }
            if self.offers.values().any(|offer| offer.response.is_some()) {
                return Err(Error::AlreadyRekeyed);
            }
            if self
                .offers
                .keys()
                .any(|(direction, _)| *direction == sender)
            {
                return Err(Error::InvalidRekey);
            }
            self.offers.insert(
                exchange,
                Offer {
                    request: packet.wire,
                    spi_i: spi,
                    nonce_i: nonce,
                    response: None,
                    spi_r: None,
                    nonce_r: None,
                },
            );
            return Ok(());
        }
        let offer = self
            .offers
            .get_mut(&exchange)
            .ok_or(Error::UnmatchedResponse)?;
        if let Some(previous) = &offer.response {
            return if previous == &packet.wire {
                Ok(())
            } else {
                Err(Error::ChangedBytes)
            };
        }
        let created = (offer.spi_i, spi);
        if self.epochs.contains_key(&created) {
            return Err(Error::InvalidRekey);
        }
        offer.response = Some(packet.wire);
        offer.spi_r = Some(spi);
        offer.nonce_r = Some(nonce);
        self.epochs.insert(created, true);
        // Both requests are known before either result in a crossed exchange.
        // Until both finish, no model state guesses the survivor from one pair.
        if self.offers.values().any(|offer| offer.response.is_none()) {
            return Ok(());
        }
        let winner = if self.offers.len() == 1 {
            created
        } else {
            let mut minima: Vec<_> = self
                .offers
                .values()
                .map(|offer| {
                    let minimum = offer
                        .nonce_i
                        .as_slice()
                        .min(offer.nonce_r.as_ref().unwrap());
                    (minimum, (offer.spi_i, offer.spi_r.unwrap()))
                })
                .collect();
            // RFC 7296 §2.8.1 compares octets. A shared-prefix shorter
            // nonce is smaller, exactly as slice lexicographic ordering does.
            minima.sort_by(|a, b| a.0.cmp(b.0));
            if minima[0].0 == minima[1].0 {
                return Err(Error::NonceTie);
            }
            self.loser = Some(minima[0].1);
            minima[1].1
        };
        for owner in self.children.values_mut() {
            *owner = winner;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_fixtures as fixtures, inputs, ke, row::KeKind};
    use opc_proto_ikev2::{
        Ikev2MessageIdSyncMode as Mode, Ikev2ProtectedPayloadDirection as Direction,
    };

    #[test]
    fn crossed_rekey_uses_all_four_nonces_and_keeps_three_epochs_until_delete() {
        for minimum in 0..4 {
            for reverse in [false, true] {
                let row = inputs::fresh(
                    880_000 + minimum * 2 + u64::from(reverse),
                    fixtures::profile(fixtures::ALGORITHMS[0]),
                    Direction::InitiatorToResponder,
                    Mode::Negotiated,
                );
                let a = Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    Direction::InitiatorToResponder,
                );
                let b = Wire::new(
                    row.profile,
                    &row.keys,
                    row.spis,
                    Direction::ResponderToInitiator,
                );
                let values: Vec<_> = (0..4)
                    .map(|n| vec![if n == minimum { 1 } else { 128 }; 64])
                    .collect();
                let public = vec![0x22; row.profile.dh_group().public_value_len()];
                let mut packets = Vec::new();
                for (n, response, spi) in [
                    (0, false, 101),
                    (1, true, 102),
                    (2, false, 201),
                    (3, true, 202),
                ] {
                    let (first, body) = ke::payload(
                        &row,
                        KeKind::IkeRekey,
                        response,
                        row.profile.dh_group(),
                        spi,
                        &values[n],
                        &public,
                    );
                    let wire = if n == 0 || n == 3 { &a } else { &b };
                    packets.push(wire.seal(0, response, 36, PayloadChain::new(first, &body)));
                }
                let mut ledger = PeerEpochs::new(row.spis, &[11, 12]);
                assert_eq!(
                    ledger.observe(&a, &packets[1]),
                    Err(Error::UnmatchedResponse)
                );
                let mut forged = packets[0].to_vec();
                *forged.last_mut().unwrap() ^= 1;
                assert!(matches!(ledger.observe(&b, &forged), Err(Error::Wire(_))));
                assert_eq!(ledger.child_owner(11), row.spis);
                ledger.observe(&b, &packets[0]).unwrap();
                ledger.observe(&a, &packets[2]).unwrap();
                ledger.observe(&b, &packets[0]).unwrap();
                let order = if reverse { [3, 1] } else { [1, 3] };
                for (index, n) in order.into_iter().enumerate() {
                    ledger
                        .observe(if n == 1 { &a } else { &b }, &packets[n])
                        .unwrap();
                    if index == 0 {
                        assert_eq!(ledger.child_owner(11), row.spis);
                    }
                }
                let (loser, winner) = if minimum < 2 {
                    ((101, 102), (201, 202))
                } else {
                    ((201, 202), (101, 102))
                };
                assert_eq!(ledger.loser(), Some(loser));
                assert_eq!(ledger.child_owner(11), winner);
                assert_eq!(ledger.child_owner(12), winner);
                for epoch in [row.spis, loser, winner] {
                    assert!(ledger.established(epoch));
                }
                let delete = a.seal(1, false, 37, fixtures::delete());
                ledger.observe(&b, &delete).unwrap();
                assert!(ledger.established(row.spis));
                assert_eq!(
                    ledger.observe(&b, &a.seal(2, false, 37, fixtures::empty())),
                    Err(Error::AfterDelete)
                );
                let reply = b.seal(1, true, 37, fixtures::empty());
                ledger.observe(&a, &reply).unwrap();
                ledger.observe(&a, &reply).unwrap();
                assert!(!ledger.established(row.spis));
                assert!(ledger.established(winner));
                assert!(ledger.established(loser));
                assert_eq!(ledger.child_owner(11), winner);
            }
        }
    }
}
