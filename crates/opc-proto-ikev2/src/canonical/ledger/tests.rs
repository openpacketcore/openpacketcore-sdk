use super::*;

fn key(index: u64) -> KeyFingerprint {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&index.to_be_bytes());
    KeyFingerprint(value)
}
fn binding(index: u64) -> BindingFingerprint {
    let mut value = [0; 32];
    value[8..16].copy_from_slice(&index.to_be_bytes());
    BindingFingerprint(value)
}

fn retained_counts(registry: &Registry) -> Result<(usize, usize), Error> {
    let entries = registry.entries.lock().map_err(|_| Error::Unavailable)?;
    assert_eq!(entries.deleted.len(), entries.deletion_order.len());
    Ok((entries.live.len(), entries.deleted.len()))
}

#[test]
fn deletion_churn_does_not_spend_live_capacity() -> Result<(), Error> {
    let registry = Registry::new(64, 64);
    for epoch in 0..4096 {
        let acquired = registry.acquire(key(epoch), binding(epoch));
        assert!(
            !matches!(&acquired, Err(Error::RegistryFull)),
            "deletion history refused fresh epoch {epoch}"
        );
        let (state, owner) = acquired?;
        registry.revoke(key(epoch), true);
        assert_eq!(
            state
                .lock()
                .map_err(|_| Error::Unavailable)?
                .check_instance(&owner),
            Err(Error::Invalidated)
        );
        assert_eq!(
            retained_counts(&registry)?,
            (
                0,
                usize::try_from(epoch + 1)
                    .map_err(|_| Error::Unavailable)?
                    .min(64)
            )
        );
    }
    for epoch in 4032..4096 {
        assert!(matches!(
            registry.acquire(key(epoch), binding(epoch)),
            Err(Error::Invalidated)
        ));
    }
    // Restoring a deleted SA after its fingerprint ages out is a consumer bug,
    // but is deliberately no longer refused for the lifetime of the process.
    let (state, _) = registry.acquire(key(0), binding(0))?;
    let state = state.lock().map_err(|_| Error::Unavailable)?;
    assert!(state.closed_through.is_none());
    assert!(state.entries.is_empty());
    assert_eq!(retained_counts(&registry)?, (1, 64));
    Ok(())
}

#[test]
fn live_capacity_and_release_history_survive_tombstone_churn() -> Result<(), Error> {
    let registry = Registry::new(64, 64);
    let mut live = Vec::new();
    for epoch in 0..64 {
        live.push(registry.acquire(key(epoch), binding(epoch))?);
    }
    {
        let mut first = live[0].0.lock().map_err(|_| Error::Unavailable)?;
        first.entries.insert(
            7,
            Entry {
                attempts: 3,
                released: false,
                bytes: None,
            },
        );
        first.entries.insert(
            9,
            Entry {
                attempts: 1,
                released: true,
                bytes: None,
            },
        );
        first.retire_through(5);
    }
    assert!(matches!(
        registry.acquire(key(64), binding(64)),
        Err(Error::RegistryFull)
    ));
    registry.revoke(key(63), true);
    for epoch in 64..4096 {
        let (_, owner) = registry.acquire(key(epoch), binding(epoch))?;
        registry.revoke(key(epoch), true);
        drop(owner);
        assert_eq!(retained_counts(&registry)?.0, 63);
        assert!(retained_counts(&registry)?.1 <= 64);
    }
    let _new = registry.acquire(key(4096), binding(4096))?;
    assert!(matches!(
        registry.acquire(key(4097), binding(4097)),
        Err(Error::RegistryFull)
    ));
    for (epoch, (state, owner)) in (0..63).zip(live) {
        assert_eq!(
            state
                .lock()
                .map_err(|_| Error::Unavailable)?
                .check_instance(&owner),
            Ok(())
        );
        drop(owner);
        let (restored, _) = registry.acquire(key(epoch), binding(epoch))?;
        assert!(Arc::ptr_eq(&state, &restored));
        if epoch == 0 {
            let first = restored.lock().map_err(|_| Error::Unavailable)?;
            assert_eq!(first.closed_through, Some(5));
            assert_eq!(first.entries[&7].attempts, 3);
            assert!(first.entries[&9].released);
        }
    }
    Ok(())
}

#[test]
fn recent_deletions_and_trust_loss_use_fifo_without_duplicate_refresh() -> Result<(), Error> {
    let registry = Registry::new(1, 4);
    registry.revoke(key(0), true); // Trust loss before any capability existed.
    for epoch in 1..4 {
        let _live = registry.acquire(key(epoch), binding(epoch))?;
        registry.revoke(key(epoch), true);
    }
    registry.revoke(key(0), true); // Idempotent deletion neither grows nor reorders.
    assert!(matches!(
        registry.acquire(key(0), binding(0)),
        Err(Error::Invalidated)
    ));
    registry.revoke(key(4), true);
    assert_eq!(retained_counts(&registry)?, (0, 4));
    let _oldest = registry.acquire(key(0), binding(0))?;
    for epoch in 1..5 {
        assert!(matches!(
            registry.acquire(key(epoch), binding(epoch)),
            Err(Error::Invalidated)
        ));
    }
    registry.revoke(key(0), true); // It was live again: a new deletion joins the tail.
    let _next_oldest = registry.acquire(key(1), binding(1))?;
    for epoch in [2, 3, 4, 0] {
        assert!(matches!(
            registry.acquire(key(epoch), binding(epoch)),
            Err(Error::Invalidated)
        ));
    }
    assert_eq!(retained_counts(&registry)?, (1, 4));
    Ok(())
}

#[test]
fn delayed_revocation_cannot_delete_a_readmitted_ledger() -> Result<(), Error> {
    let registry = Registry::new(1, 1);
    let (old, old_owner) = registry.acquire(key(0), binding(0))?;
    registry.revoke(key(0), true);
    registry.revoke(key(1), true); // The old fingerprint ages out.
    let (new, new_owner) = registry.acquire(key(0), binding(0))?;
    assert!(!Arc::ptr_eq(&old, &new));
    // A second revocation of the old ledger may finish after FIFO churn and
    // re-admission. It must compare the ledger identity before removing a key.
    registry.finish_revocation(key(0), &old);
    assert_eq!(
        old.lock()
            .map_err(|_| Error::Unavailable)?
            .check_instance(&old_owner),
        Err(Error::Invalidated)
    );
    assert_eq!(
        new.lock()
            .map_err(|_| Error::Unavailable)?
            .check_instance(&new_owner),
        Ok(())
    );
    assert_eq!(retained_counts(&registry)?, (1, 1));
    assert!(matches!(
        registry.acquire(key(0), binding(0)),
        Err(Error::CapabilityActive)
    ));
    Ok(())
}

#[test]
fn compaction_and_deletion_bound_state_over_many_keys_and_ids() -> Result<(), Error> {
    let registry = Registry::new(128, 128);
    for epoch in 0..128 {
        let (state, owner) = registry.acquire(key(epoch), binding(epoch))?;
        {
            let mut state = state.lock().map_err(|_| Error::Unavailable)?;
            for id in 0..2048 {
                state.entries.insert(
                    id,
                    Entry {
                        attempts: 1,
                        released: true,
                        bytes: Some(Zeroizing::new([0; 57])),
                    },
                );
                state.retire_through(id);
                assert_eq!(state.closed_through, Some(id));
                assert!(state.entries.is_empty());
            }
            for id in 2048..2064 {
                state.entries.insert(id, Entry::default());
            }
            state.retire_through(1024); // A lower floor cannot undo compaction.
            assert_eq!(state.closed_through, Some(2047));
            assert_eq!(state.entries.len(), 16);
        }
        registry.revoke(key(epoch), true);
        let state = state.lock().map_err(|_| Error::Unavailable)?;
        assert!(state.entries.is_empty());
        assert_eq!(state.check_instance(&owner), Err(Error::Invalidated));
    }
    let entries = registry.entries.lock().map_err(|_| Error::Unavailable)?;
    assert!(entries.live.is_empty());
    assert_eq!(entries.deleted.len(), 128);
    assert_eq!(entries.deletion_order.len(), 128);
    drop(entries);
    assert!(matches!(
        registry.acquire(key(0), binding(0)),
        Err(Error::Invalidated)
    ));
    let _next_live = registry.acquire(key(128), binding(128))?;
    registry.revoke(key(129), true); // An unknown trust loss also uses the bounded FIFO.
    assert!(matches!(
        registry.acquire(key(129), binding(129)),
        Err(Error::Invalidated)
    ));
    assert_eq!(retained_counts(&registry)?, (1, 128));
    Ok(())
}

#[test]
fn floor_keeps_above_floor_attempts_and_release_history() -> Result<(), Error> {
    let registry = Registry::new(2, 2);
    let (state, owner) = registry.acquire(key(0), binding(0))?;
    {
        let mut state = state.lock().map_err(|_| Error::Unavailable)?;
        state.entries.insert(
            7,
            Entry {
                attempts: 3,
                released: false,
                bytes: None,
            },
        );
        state.entries.insert(
            9,
            Entry {
                attempts: 1,
                released: true,
                bytes: None,
            },
        );
        state.retire_through(5);
        assert_eq!(state.entries[&7].attempts, 3);
        assert!(state.entries[&9].released);
        state.revoke(false);
    }
    drop(owner);
    let (_, second_owner) = registry.acquire(key(1), binding(1))?;
    drop(second_owner); // Existing live entries remain usable at registry capacity.
    let (restored, _) = registry.acquire(key(0), binding(0))?;
    assert!(Arc::ptr_eq(&state, &restored));
    let mut state = restored.lock().map_err(|_| Error::Unavailable)?;
    assert_eq!(state.closed_through, Some(5));
    assert_eq!(state.entries[&7].attempts, 3);
    assert!(state.entries[&9].released);
    state.retire_through(u32::MAX);
    assert_eq!(state.closed_through, Some(u32::MAX));
    assert!(state.entries.is_empty());
    Ok(())
}

#[test]
fn many_restores_use_hash_lookups_instead_of_scanning_other_keys() -> Result<(), Error> {
    let registry = Registry::new(4096, 4096);
    for epoch in 0..4096 {
        let (_, owner) = registry.acquire(key(epoch), binding(epoch))?;
        drop(owner);
    }
    KEY_COMPARISONS.with(|count| count.set(0));
    for epoch in 0..4096 {
        let (_, owner) = registry.acquire(key(epoch), binding(epoch))?;
        drop(owner);
    }
    // Count structural key comparisons, not elapsed time. A scan takes about
    // 8 million comparisons; hashing needs only bounded probes per lookup.
    let comparisons = KEY_COMPARISONS.with(std::cell::Cell::get);
    assert!(
        comparisons < 32 * 4096,
        "registry performed {comparisons} comparisons"
    );
    Ok(())
}

#[test]
fn static_registry_graph_contains_only_fingerprints_and_non_key_metadata() -> Result<(), Error> {
    // A compile-time whitelist and exhaustive destructuring pin the entire
    // retained object graph. Adding a key-bearing field breaks this test's build.
    // Inspecting freed memory would require unsafe code and would not prove this.
    trait KeyFree {}
    impl KeyFree for KeyFingerprint {}
    impl KeyFree for BindingFingerprint {}
    impl KeyFree for u8 {}
    impl KeyFree for u32 {}
    impl KeyFree for usize {}
    impl KeyFree for bool {}
    impl KeyFree for Weak<()> {}
    impl KeyFree for Zeroizing<[u8; 57]> {} // Verified ciphertext only.
    impl<T: KeyFree> KeyFree for Option<T> {}
    fn key_free<T: KeyFree>(_: &T) {}
    fn entry_fields(entry: &Entry) {
        let Entry {
            attempts,
            released,
            bytes,
        } = entry;
        key_free(attempts);
        key_free(released);
        key_free(bytes);
    }
    fn ledger_fields(ledger: &Ledger) {
        let Ledger {
            binding,
            entries,
            owner,
            revoked,
            closed_through,
        } = ledger;
        key_free(binding);
        key_free(owner);
        key_free(revoked);
        key_free(closed_through);
        for (id, entry) in entries {
            key_free(id);
            entry_fields(entry);
        }
    }
    let registry = Registry::new(2, 2);
    let (live, owner) = registry.acquire(key(1), binding(1))?;
    drop(owner);
    let Registry {
        entries,
        live_limit,
        tombstone_limit,
    } = &registry;
    key_free(live_limit);
    key_free(tombstone_limit);
    let entries = entries.lock().map_err(|_| Error::Unavailable)?;
    let RegistryEntries {
        live: ledgers,
        deleted,
        deletion_order,
    } = &*entries;
    let _: &HashMap<KeyFingerprint, Arc<Mutex<Ledger>>> = ledgers;
    let _: &HashSet<KeyFingerprint> = deleted;
    let _: &VecDeque<KeyFingerprint> = deletion_order;
    for (key, ledger) in ledgers {
        key_free(key);
        ledger_fields(&*ledger.lock().map_err(|_| Error::Unavailable)?);
    }
    for key in deleted.iter().chain(deletion_order.iter()) {
        key_free(key);
    }
    drop(entries);
    registry.revoke(key(1), true);
    let entries = registry.entries.lock().map_err(|_| Error::Unavailable)?;
    assert!(!entries.live.contains_key(&key(1)));
    assert!(entries.deleted.contains(&key(1)));
    ledger_fields(&*live.lock().map_err(|_| Error::Unavailable)?);
    Ok(())
}
