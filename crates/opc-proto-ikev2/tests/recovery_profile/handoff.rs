//! Consumer atomic rekey boundary. Complete old operation and new epoch data
//! enter one CAS; materializing the new runtime still requires its issued cut.

use super::{
    driver::{self, Cut, Runtime},
    envelope::{Error, Provider},
    ke,
    row::{KeKind, Operation, Outcome, Row},
    store::{CasStore, RowKey},
};
use bytes::Bytes;
use opc_proto_ikev2::{
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys, PayloadChain,
};

pub fn keys_from_bytes(profile: Profile, bytes: &[u8]) -> Result<Keys, Error> {
    let n = profile.prf().output_len();
    let a = profile.integrity_key_len();
    let e = profile.encryption().key_material_len();
    if bytes.len() != 3 * n + 2 * a + 2 * e {
        return Err(Error::Format);
    }
    let mut offset = 0;
    let mut take = |len| {
        let start = offset;
        offset += len;
        &bytes[start..offset]
    };
    Keys::from_established_keys(
        profile,
        false,
        take(n),
        take(a),
        take(a),
        take(e),
        take(e),
        take(n),
        take(n),
    )
    .map_err(|_| Error::Format)
}

fn new_epoch(old: &Row, operation: &Operation, key: RowKey, stamp: u64) -> Result<Row, Error> {
    if operation.kind != KeKind::IkeRekey
        || operation.outcome != Outcome::Success
        || operation.checkpoint.is_some()
        || old.key == key
    {
        return Err(Error::Format);
    }
    let keys = keys_from_bytes(
        old.profile,
        operation.derived.as_ref().ok_or(Error::Format)?,
    )?;
    let direction = if operation.initiated_here {
        Direction::InitiatorToResponder
    } else {
        Direction::ResponderToInitiator
    };
    let mut row = Row::fresh(
        key,
        stamp,
        old.profile,
        keys,
        operation.spis,
        direction,
        old.mode,
    );
    row.agreement = old
        .agreement
        .inherit_rekey(row.agreement.sa(), true)
        .ok_or(Error::Format)?;
    if let Some(sync) = &mut row.window.sync {
        sync.agreement = row.agreement;
    }
    row.identity = old.identity;
    row.namespace = old.namespace;
    row.endpoint = old.endpoint;
    row.validate()?;
    Ok(row)
}

fn crossed_loser(old: &Row, completed: &Operation) -> Result<Option<u64>, Error> {
    let mut other = old.operations.values().filter(|operation| {
        operation.kind == KeKind::IkeRekey
            && operation.id != completed.id
            && operation.initiated_here != completed.initiated_here
            && operation.outcome == Outcome::Success
    });
    let Some(prior) = other.next() else {
        return Ok(None);
    };
    if other.next().is_some() {
        return Err(Error::Format);
    }
    let minimum = |operation: &Operation| operation.nonce_i.clone().min(operation.nonce_r.clone());
    use std::cmp::Ordering;
    match minimum(completed).cmp(&minimum(prior)) {
        Ordering::Less => Ok(Some(completed.id)),
        Ordering::Greater => Ok(Some(prior.id)),
        Ordering::Equal => Err(Error::Format),
    }
}

fn commit_operation(row: &mut Row, operation: Operation, loser: Option<u64>) {
    row.operations.insert(operation.id, operation);
    if let Some(id) = loser {
        // Both successor epochs remain independently usable until Delete. The
        // losing operation's private checkpoint and obsolete result copy do
        // not survive the same CAS which records its terminal disposition.
        ke::finish_operation(row, id, Outcome::CrossedLoss, None);
    }
}

pub fn finish_initiator(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    operation_id: u64,
    new_key: RowKey,
    response: &[u8],
    cut: Cut,
) -> Result<bool, driver::Error> {
    let operation = ke::plan_initiator(runtime, operation_id, response)?;
    if operation.outcome != Outcome::Success {
        return Ok(
            ke::commit_initiator_plan(runtime, provider, store, operation, response, cut)?
                .is_some(),
        );
    }
    let epoch = new_epoch(&runtime.row, &operation, new_key, store.stamp())?;
    let loser = crossed_loser(&runtime.row, &operation)?;
    Ok(runtime
        .complete_rekey(
            provider,
            store,
            response,
            Bytes::from_static(b"ike-rekeyed"),
            |row| {
                commit_operation(row, operation, loser);
            },
            &epoch,
            cut,
        )?
        .is_some())
}

pub fn finish_responder(
    runtime: &mut Runtime,
    provider: &Provider,
    store: &mut CasStore,
    operation_id: u64,
    new_key: RowKey,
    request: &[u8],
    cut: Cut,
) -> Result<bool, driver::Error> {
    let (operation, first, reply) =
        ke::plan_responder(runtime, operation_id, KeKind::IkeRekey, request)?;
    if operation.outcome != Outcome::Success {
        return Ok(ke::commit_responder_plan(
            runtime, provider, store, operation, request, first, &reply, cut,
        )?
        .is_some());
    }
    let epoch = new_epoch(&runtime.row, &operation, new_key, store.stamp())?;
    let loser = crossed_loser(&runtime.row, &operation)?;
    Ok(runtime
        .publish_rekey_response(
            provider,
            store,
            request,
            PayloadChain::new(first, &reply),
            Bytes::from_static(b"ike-rekeyed"),
            |row| {
                commit_operation(row, operation, loser);
            },
            &epoch,
            cut,
        )?
        .is_some())
}
