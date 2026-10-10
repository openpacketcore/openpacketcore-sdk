//! Checks of the fault harness itself. Lifecycle composition uses this model
//! with real SDK windows below; these tests alone do not qualify recovery.

use super::{
    authority::{EpochOwners, Transport},
    envelope::{self, Fault, Provider},
    store::*,
};
use zeroize::Zeroizing;

fn command(
    provider: &Provider,
    request: RequestId,
    key: RowKey,
    expected: Option<Version>,
    value: &[u8],
) -> Command {
    let version = expected.map_or(
        Version {
            birth: key.0 + 100,
            generation: 1,
        },
        Version::next,
    );
    let row = envelope::seal(
        provider,
        key,
        version,
        request.stamp,
        &Zeroizing::new(value.to_vec()),
    )
    .unwrap();
    Command::new(
        request,
        vec![Mutation {
            key,
            expected,
            value: Some(row),
        }],
    )
    .unwrap()
}

fn initialized() -> (Provider, CasStore, RowKey, Command) {
    let provider = Provider::new();
    let mut store = CasStore::new(7);
    let key = RowKey(19);
    let initial = command(&provider, store.next_request(), key, None, b"initial");
    store.commit(&initial).unwrap();
    (provider, store, key, initial)
}

#[test]
fn envelope_provider_keeps_transient_failures_distinct_from_missing_keys_and_corruption() {
    let provider = Provider::new();
    let key = RowKey(1);
    let version = Version {
        birth: 101,
        generation: 1,
    };
    let plaintext = Zeroizing::new(b"test row content".to_vec());
    let row = envelope::seal(&provider, key, version, 7, &plaintext).unwrap();
    assert_eq!(provider.calls(), (1, 0));
    for fault in [Fault::Unavailable, Fault::Timeout, Fault::Throttled] {
        provider.fail(fault);
        assert_eq!(
            envelope::seal(&provider, key, version, 7, &plaintext)
                .err()
                .unwrap(),
            envelope::Error::Backpressure
        );
        assert_eq!(
            envelope::unseal(&provider, key, &row).err().unwrap(),
            envelope::Error::Backpressure
        );
        provider.fail(Fault::Healthy);
        assert!(envelope::unseal(&provider, key, &row).unwrap().as_slice() == plaintext.as_slice());
    }
    for fault in [Fault::Missing, Fault::Revoked] {
        provider.fail(fault);
        assert_eq!(
            envelope::unseal(&provider, key, &row).err().unwrap(),
            envelope::Error::KeyLost
        );
    }
    provider.fail(Fault::Healthy);
    for changed in 0..5 {
        let mut invalid = row.clone();
        let mut key = key;
        match changed {
            0 => key.0 += 1,
            1 => invalid.version.birth += 1,
            2 => invalid.version.generation += 1,
            3 => invalid.sealed_stamp += 1,
            4 => *invalid.envelope.last_mut().unwrap() ^= 1,
            _ => unreachable!(),
        }
        assert_eq!(
            envelope::unseal(&provider, key, &invalid).err().unwrap(),
            envelope::Error::Integrity
        );
    }
    assert_eq!(
        format!("{row:?}"),
        "StoredRow { version: Version { birth: 101, generation: 1 }, sealed_stamp: 7, .. }"
    );
}

#[test]
fn cas_model_separates_apply_acknowledgement_exact_retry_and_pruned_outcomes() {
    let (provider, mut store, key, initial) = initialized();
    let initial_cut = store.fenced_read(&initial, key).unwrap();
    let version = store.inspect(key).unwrap().version;
    let write = command(
        &provider,
        store.next_request(),
        key,
        Some(version),
        b"candidate",
    );
    store.dispatch(write.clone()).unwrap();
    assert_eq!(store.inspect(key).unwrap().version, version);
    assert_eq!(store.acknowledge(&write), Err(Error::Unknown));
    assert!(matches!(
        store.fenced_read(&write, key),
        Err(Error::PriorMayStillApply)
    ));
    assert!(matches!(
        store.refresh_fenced(&initial_cut),
        Err(Error::PriorMayStillApply)
    ));
    store.apply(write.request()).unwrap();
    let receipt = store.acknowledge(&write).unwrap();
    assert_eq!(receipt.version(key), Some(version.next()));
    assert_eq!(
        receipt.acknowledges(&initial),
        Err(Error::AcknowledgementMismatch)
    );
    let publications = store.publications;
    assert_eq!(store.commit(&write).unwrap(), receipt);
    assert_eq!(
        store.publications, publications,
        "exact retry cannot publish twice"
    );
    let changed = command(
        &provider,
        write.request(),
        key,
        Some(version),
        b"replacement",
    );
    assert_eq!(store.dispatch(changed), Err(Error::RequestDigestMismatch));
    store.prune(write.request());
    assert_eq!(store.acknowledge(&write), Err(Error::Unknown));
    let cut = store.fenced_read(&write, key).unwrap();
    assert_eq!(cut.row().unwrap().version, version.next());
    assert_eq!(
        store
            .refresh_fenced(&initial_cut)
            .unwrap()
            .row()
            .unwrap()
            .version,
        version.next()
    );
    store.succeed(8);
    assert!(matches!(
        store.refresh_fenced(&cut),
        Err(Error::StampFenced)
    ));
}

#[test]
fn cas_model_checks_birth_and_generation_independently_of_the_execution_stamp() {
    let (provider, mut store, key, _) = initialized();
    let version = store.inspect(key).unwrap().version;
    let first = command(
        &provider,
        store.next_request(),
        key,
        Some(version),
        b"delayed first",
    );
    store.dispatch(first.clone()).unwrap();
    assert!(matches!(
        store.fenced_read(&first, key),
        Err(Error::PriorMayStillApply)
    ));
    store.succeed(8);
    let cut = store.fenced_read(&first, key).unwrap();
    assert_eq!(cut.row().unwrap().version, version);
    let second = command(
        &provider,
        store.next_request(),
        key,
        Some(version),
        b"committed second",
    );
    store.commit(&second).unwrap();
    assert_eq!(store.apply(first.request()), Err(Error::StampFenced));
    assert_eq!(store.apply_child(&first, false), Err(Error::CasConflict));
    let restored = envelope::unseal(&provider, key, store.inspect(key).unwrap()).unwrap();
    assert!(restored.as_slice() == b"committed second");
    let wrong_birth = Version {
        birth: version.birth + 1,
        generation: version.next().generation,
    };
    let wrong = command(
        &provider,
        store.next_request(),
        key,
        Some(wrong_birth),
        b"foreign birth",
    );
    assert_eq!(store.commit(&wrong), Err(Error::CasConflict));
}

#[test]
fn rekey_model_publishes_the_old_result_and_new_epoch_in_one_cut() {
    let (provider, mut store, old_key, _) = initialized();
    let old_version = store.inspect(old_key).unwrap().version;
    let new_key = RowKey(20);
    let request = store.next_request();
    let old = command(
        &provider,
        request,
        old_key,
        Some(old_version),
        b"old rekey result",
    );
    let new = command(&provider, request, new_key, None, b"new epoch");
    let mut mutations = old.mutations().to_vec();
    mutations.extend_from_slice(new.mutations());
    let rekey = Command::new(request, mutations).unwrap();
    store.dispatch(rekey.clone()).unwrap();
    assert_eq!(
        store.apply_with_cut(request, true),
        Err(Error::InterruptedBeforePublish)
    );
    assert!(store.inspect(new_key).is_none());
    assert_eq!(store.inspect(old_key).unwrap().version, old_version);
    assert!(matches!(
        store.fenced_read(&rekey, new_key),
        Err(Error::PriorMayStillApply)
    ));
    let receipt = store.commit(&rekey).unwrap();
    assert_eq!(receipt.version(old_key), Some(old_version.next()));
    assert_eq!(receipt.version(new_key).unwrap().generation, 1);
    assert_eq!(
        store.publications, 2,
        "initial creation plus one atomic hand-off"
    );
}

#[test]
fn ownership_model_refuses_duplicates_and_revokes_copied_packets_before_submission() {
    let (provider, mut store, key, initial) = initialized();
    let owners = EpochOwners::new(store.stamp());
    let cut = store.fenced_read(&initial, key).unwrap();
    let owner = owners.acquire(&cut).unwrap();
    assert!(matches!(
        owners.acquire(&cut),
        Err(super::authority::Error::DuplicateOwner)
    ));
    let permit = owner.permit();
    let copied = bytes::Bytes::from_static(b"already copied packet");
    let mut transport = Transport::default();
    transport.submit(&permit, &copied).unwrap();
    owner.revoke();
    assert_eq!(
        transport.submit(&permit, &copied),
        Err(super::authority::Error::Revoked)
    );
    assert!(matches!(
        owners.acquire(&cut),
        Err(super::authority::Error::DuplicateOwner)
    ));
    drop(owner);
    let owner = owners.acquire(&cut).unwrap();
    assert_eq!(
        transport.submit(&permit, &copied),
        Err(super::authority::Error::Revoked)
    );
    let current = owner.permit();
    transport.submit(&current, &copied).unwrap();
    store.succeed(8);
    owners.learn_succession(8);
    assert_eq!(
        transport.submit(&current, &copied),
        Err(super::authority::Error::Revoked)
    );
    assert!(matches!(
        owners.acquire(&cut),
        Err(super::authority::Error::Revoked)
    ));
    drop(owner);
    let current_cut = store.fenced_read(&initial, key).unwrap();
    let owner = owners.acquire(&current_cut).unwrap();
    assert_eq!(
        owner.permit().binding(),
        (key, cut.row().unwrap().version.birth, 8)
    );
    assert!(
        envelope::unseal(&provider, key, current_cut.row().unwrap()).is_ok(),
        "a newly fenced owner must still read the older committed envelope"
    );
    transport.submit(&owner.permit(), &copied).unwrap();
    assert_eq!(transport.submitted.len(), 3);
}

#[test]
fn sibling_cut_refuses_queued_writes_and_an_old_execution_stamp() {
    let (provider, mut store, key, initial) = initialized();
    let anchor = store.fenced_read(&initial, key).unwrap();
    let sibling = RowKey(23);
    let pending = command(
        &provider,
        store.next_request(),
        sibling,
        None,
        b"new sibling",
    );
    store.dispatch(pending.clone()).unwrap();
    assert!(matches!(
        store.current_after_join(&anchor, sibling),
        Err(Error::PriorMayStillApply)
    ));
    assert!(store.current_after_join(&anchor, key).is_ok());
    store.apply(pending.request()).unwrap();
    let current = store.current_after_join(&anchor, sibling).unwrap();
    assert_eq!(
        current.row().unwrap().version,
        store.inspect(sibling).unwrap().version
    );
    store.succeed(8);
    assert!(matches!(
        store.current_after_join(&anchor, sibling),
        Err(Error::StampFenced)
    ));
}
