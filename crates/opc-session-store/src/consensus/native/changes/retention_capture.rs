//! Retained key changes preserve their exact endpoints in real captured cuts.
use super::*;
use crate::consensus::native::key_retention_tests::{
    acquired_fixture, command as ordinary_command, prune_intent,
};

fn append_command(
    pilot: &mut NativeStorage,
    entries: &mut Vec<Entry<SessionRaftTypeConfig>>,
    intent: SessionMutationIntent,
) -> SessionMutationOutcome {
    let index = pilot.business.applied().unwrap().index + 1;
    let entry = ordinary_command(index, intent);
    let result = apply(pilot, std::slice::from_ref(&entry));
    let outcome = result.responses[0].result.clone().unwrap();
    entries.push(entry);
    outcome
}

// All preceding commands fit two resident rows. Only the final acquire
// exceeds that limit, so its unpublished command finalizer rotates regardless
// of whether those commands arrived separately or in one apply delivery.
fn apply_final_capacity_command(
    storage: &mut NativeStorage,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> NativeApplied {
    let encoded: Vec<_> = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().into())
        .collect();
    for chunk in encoded.chunks(LOG_RPC_ENTRIES) {
        storage
            .log
            .project(&Operation::Append(chunk.to_vec()), &storage.business, None)
            .unwrap();
    }
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    let mut delta = storage.business.prepare(entries).unwrap();
    // The production policy helper keeps its actual N; only this resident
    // limit is small, as in the native capacity regression fixtures.
    delta.rotate_key_capacity_at(2).unwrap();
    let applied = Publication::prepare(delta)
        .unwrap()
        .publish(&mut storage.business)
        .unwrap();
    storage.validate_image().unwrap();
    applied
}

#[test]
fn native_key_retirement_capture_records_exact_predecessors_and_eliminates_transients() {
    for retained_before in [true, false] {
        for batched in [true, false] {
            let (mut storage, mut guard) = if retained_before {
                acquired_fixture()
            } else {
                let (storage, _, live) = fixture();
                (storage, live.lease().clone())
            };
            let mut key = guard.key().clone();
            if !retained_before {
                key.stable_id = Bytes::from_static(b"transient-journal-key")
                    .try_into()
                    .unwrap();
            }
            let predecessor = Arc::clone(storage.business.require_business_proof().unwrap());
            let before = storage.business.keys.get(&key).cloned();
            assert_eq!(before.is_some(), retained_before);
            // Build the exact request stream on an independent state copy so
            // every later guard is an actual deterministic command outcome.
            let mut pilot = storage.clone();
            let mut entries = Vec::new();
            if !retained_before {
                let acquired = append_command(
                    &mut pilot,
                    &mut entries,
                    SessionMutationIntent::AcquireLease {
                        key: key.clone(),
                        owner: guard.owner().clone(),
                        ttl: Duration::from_secs(60),
                    },
                );
                let SessionMutationOutcome::Lease(lease) = acquired else {
                    panic!("acquire must issue a lease")
                };
                guard = lease;
            }
            let renewed = append_command(
                &mut pilot,
                &mut entries,
                SessionMutationIntent::RenewLease {
                    lease: guard,
                    ttl: Duration::from_secs(60),
                },
            );
            let SessionMutationOutcome::Lease(guard) = renewed else {
                panic!("renew must issue its current guard")
            };
            append_command(
                &mut pilot,
                &mut entries,
                SessionMutationIntent::ReleaseLease(guard),
            );
            for _ in 0..2 {
                let intent = prune_intent(&pilot);
                append_command(&mut pilot, &mut entries, intent);
            }
            assert_eq!(pilot.business.keys.len(), 2);
            assert_eq!(
                pilot.business.keys.get(&key).unwrap().retired_epoch,
                Some(0)
            );
            // Keep the original create/update/retire endpoint proof. The exact
            // window now requires rotation before this key can be forgotten.
            let mut replacement = key.clone();
            replacement.stable_id = Bytes::from_static(b"retirement-capture-capacity")
                .try_into()
                .unwrap();
            let index = pilot.business.applied().unwrap().index + 1;
            let capacity = ordinary_command(
                index,
                SessionMutationIntent::AcquireLease {
                    key: replacement.clone(),
                    owner: crate::OwnerId::new("capture-owner").unwrap(),
                    ttl: Duration::from_secs(60),
                },
            );
            let applied = apply_final_capacity_command(&mut pilot, std::slice::from_ref(&capacity));
            assert!(matches!(
                applied.responses[0].result,
                Ok(SessionMutationOutcome::Lease(_))
            ));
            entries.push(capacity);
            assert!(!pilot.business.keys.contains_key(&key));
            assert_eq!(pilot.business.frontiers.retention.keys.epoch, 2);
            assert_eq!(
                pilot.business.frontiers.retention.keys.last_rotation,
                Some(crate::key_retention::RotationReason::Capacity)
            );
            storage.begin_changes().unwrap();
            if batched {
                apply_final_capacity_command(&mut storage, &entries);
            } else {
                for entry in &entries[..entries.len() - 1] {
                    apply(&mut storage, std::slice::from_ref(entry));
                }
                apply_final_capacity_command(&mut storage, &entries[entries.len() - 1..]);
            }
            storage.validate_image().unwrap();
            assert!(storage.business.frontiers == pilot.business.frontiers);
            assert!(!storage.business.keys.contains_key(&key));
            let captured = storage.take_changes().unwrap();
            assert!(Arc::ptr_eq(&captured.business.base, &predecessor));
            assert!(Arc::ptr_eq(
                &captured.business.target,
                storage.business.require_business_proof().unwrap()
            ));
            if let Some(before) = before {
                let change = captured.business.keys.get(&key).unwrap();
                assert!(change.before.as_deref().unwrap().ptr_eq(&before));
                assert!(change.before_hash == Some(stamp(0, &key, &before).unwrap()));
                assert!(change.after.is_none() && change.after_hash.is_none());
                assert_eq!(
                    captured.business.keys.len(),
                    3,
                    "one removal, the surviving live-key refresh and new capacity-triggering authority"
                );
                assert_eq!(
                    captured.business.target.tables[0].count,
                    predecessor.tables[0].count
                );
            } else {
                assert!(!captured.business.keys.contains_key(&key), "a create/update/retire transient has neither endpoint: retained_before={retained_before}, batched={batched}");
                assert_eq!(
                    captured.business.keys.len(),
                    2,
                    "the surviving live-key refresh and new capacity-triggering authority remain"
                );
                assert_eq!(
                    captured.business.target.tables[0].count,
                    predecessor.tables[0].count + 1
                );
            }
            let added = captured.business.keys.get(&replacement).unwrap();
            assert!(added.before.is_none() && added.before_hash.is_none());
            assert!(added.after.as_ref().unwrap().lease.is_some());
            assert!(added.after_hash.is_some());
            captured.validate(&|| Ok(())).unwrap();
        }
    }
}
