use super::*;
use crate::{RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};

fn retained_options(
    directory: &std::path::Path,
    initial: VoterSlotTable,
    local: ConsensusNodeId,
) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        directory.join("config.sqlite"),
        RetainedConfigBinding::for_voter_slots(initial, local, [41; 32], [42; 32])
            .expect("retained incarnation binding"),
        RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("retained options")
}

fn audit_key() -> crate::AuditKey {
    crate::AuditKey::new([42; 32]).unwrap()
}

#[tokio::test]
async fn retained_voter_profile_reopens_and_refuses_legacy_admission() {
    let directory = tempfile::tempdir().unwrap();
    let local = member(1, 1).identity.node_id();
    let options = retained_options(directory.path(), genesis(), local);
    let backend = SqliteBackend::provision_config_authority(options.clone(), audit_key())
        .await
        .expect("provision the admitted genesis incarnation");
    let legacy = ConsensusConfigStore::open(
        ConfigConsensusTopology::for_voter_slots(&genesis(), local).unwrap(),
        backend.clone(),
        directory.path().join("legacy-snapshots"),
        BTreeMap::new(),
    )
    .await;
    assert!(matches!(
        legacy,
        Err(ConfigConsensusOpenError::InvalidRuntimeConfiguration)
    ));
    let network = Arc::new(Network::default());
    let open = |backend| {
        ConsensusConfigStore::open_with_voter_slots(
            genesis(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
    };
    let store = open(backend)
        .await
        .expect("open retained incarnation profile");
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &genesis());
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .expect("reopen exact retained incarnation binding");
    let store = open(backend)
        .await
        .expect("reopen retained incarnation profile");
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &genesis());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn retained_replacement_candidate_preserves_nonvoting_admission_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut prepared = genesis();
    let request = verified_request(&prepared, 3).request().clone();
    prepared
        .apply_control(
            &VoterSlotControl::Begin(Box::new(request)),
            VoterSlotLogId { term: 1, index: 1 },
        )
        .expect("fixture models a committed Prepare");
    let local = member(3, 2).identity.node_id();
    assert_ne!(local, member(3, 1).identity.node_id());
    let options = retained_options(directory.path(), prepared.clone(), local);
    let backend = SqliteBackend::provision_config_member_repair(options.clone(), audit_key())
        .await
        .expect("provision selected candidate storage");
    assert!(backend.retained_repair_only);
    let network = Arc::new(Network::default());
    let open = |backend| {
        ConsensusConfigStore::open_with_voter_slots(
            prepared.clone(),
            local,
            backend,
            directory.path().join("snapshots"),
            Arc::new(Resolver(network.clone())),
        )
    };
    let store = open(backend).await.expect("open retained candidate");
    assert!(!store
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &prepared);
    assert!(store.inner.raft.metrics().borrow().last_applied.is_none());
    store.shutdown().await.unwrap();
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, audit_key())
        .await
        .expect("reopen pending candidate without provisioning again");
    assert!(backend.retained_repair_only);
    let store = open(backend).await.expect("resume retained candidate");
    assert!(!store
        .inner
        .voter_profile
        .as_ref()
        .unwrap()
        .admission
        .local_voting_admitted());
    assert_eq!(store.voter_slot_state().await.unwrap().table(), &prepared);
    assert!(store.inner.raft.metrics().borrow().last_applied.is_none());
    store.shutdown().await.unwrap();
}
