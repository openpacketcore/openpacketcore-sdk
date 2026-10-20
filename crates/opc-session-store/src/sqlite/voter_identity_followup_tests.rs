use super::*;
use opc_consensus::voter_slots::{VoterSlotPhase, VoterSlotRecord, VoterSlotTable};
use opc_consensus::ConsensusConfigurationEpoch;

fn installation() -> ConsensusClusterId {
    ConsensusClusterId::from_bytes([0xb1; 32])
}

fn identity() -> VoterSlotIdentity {
    VoterSlotIdentity::new(SlotId::new(1).unwrap(), VoterIncarnation::new(1).unwrap())
}

fn member(signer: &VoterIdentitySigner) -> VoterSlotMember {
    VoterSlotMember {
        identity: signer.identity(),
        key_digest: signer.key_digest(),
        descriptor_digest: [0xb2; 32],
        admission_generation: 1,
    }
}

fn seed(signer: &VoterIdentitySigner) -> consensus::voter_slots::Seed {
    consensus::voter_slots::Seed::genesis(VoterSlotTable {
        cluster_instance: installation(),
        manifest_digest: [0xb3; 32],
        revision: 1,
        configuration_epoch: ConsensusConfigurationEpoch::new(1).unwrap(),
        slots: (1..=3)
            .map(|slot| VoterSlotRecord {
                member: if slot == 1 {
                    member(signer)
                } else {
                    VoterSlotMember {
                        identity: VoterSlotIdentity::new(
                            SlotId::new(slot).unwrap(),
                            VoterIncarnation::new(1).unwrap(),
                        ),
                        key_digest: [slot as u8; 32],
                        descriptor_digest: [slot as u8 + 3; 32],
                        admission_generation: 1,
                    }
                },
                phase: VoterSlotPhase::Voting,
                retired_through: 0,
                last_result: None,
            })
            .collect(),
        replacement: None,
    })
    .unwrap()
}

#[tokio::test]
async fn voter_anchor_busy_remains_retryable_through_signer_preflight_and_seed() {
    use crate::consensus::storage::SessionConsensusStorageError;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("voter.sqlite");
    let mut backend = SqliteSessionBackend::open(&path).unwrap();
    let signer = backend
        .enroll_voter_identity(installation(), identity())
        .await
        .unwrap();
    let seed = seed(&signer);
    backend.voter_signer = Some(signer.clone());
    backend.voter_seed = Some(Arc::new(seed.clone()));
    {
        let conn = backend.conn.lock().await;
        conn.pragma_update(None, "journal_mode", "DELETE").unwrap();
        conn.busy_timeout(Duration::ZERO).unwrap();
    }
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let reopened = backend
        .voter_identity_signer(installation(), &member(&signer))
        .await
        .map(|_| ());
    let preflight = backend.voter_profile_preflight().await.map(|_| ());
    let seed_result = {
        let conn = backend.conn.lock().await;
        require_seed_enrollment(&conn, &seed, false)
    };
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        (reopened, preflight, seed_result),
        (
            Err(ConsensusSessionStoreOpenError::StorageUnavailable),
            Err(SessionConsensusStorageError::BackendUnavailable),
            Err(SessionConsensusStorageError::BackendUnavailable),
        ),
        "SQLite contention must never become evidence of voter loss"
    );
    assert_eq!(
        backend
            .voter_identity_signer(installation(), &member(&signer))
            .await
            .unwrap()
            .key_digest(),
        signer.key_digest()
    );
    assert!(backend.voter_profile_preflight().await.is_ok());
    let conn = backend.conn.lock().await;
    assert!(require_seed_enrollment(&conn, &seed, false).is_ok());
}

#[test]
fn voter_private_record_io_failure_is_retryable_but_truncation_requires_replacement() {
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        }
    }
    assert_eq!(
        read_private_record(&mut FailedRead).map(|_| ()),
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    );
    assert_eq!(
        read_private_record(&mut std::io::empty()).map(|_| ()),
        Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn voter_private_anchor_descriptor_exhaustion_is_retryable() {
    use crate::test_process::CommandExt;
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    const CHILD: &str = "OPC_VOTER_ANCHOR_RESOURCE_TEST";
    const TEST: &str = "sqlite::voter_identity::followup_tests::voter_private_anchor_descriptor_exhaustion_is_retryable";
    if std::env::var(CHILD).as_deref() != Ok(TEST) {
        let output = std::process::Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=5", "120"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, TEST)
            .test_output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored"),
            "{stdout}\n{stderr}"
        );
        return;
    }
    struct Limit((nix::sys::resource::rlim_t, nix::sys::resource::rlim_t));
    impl Drop for Limit {
        fn drop(&mut self) {
            setrlimit(Resource::RLIMIT_NOFILE, self.0 .0, self.0 .1).unwrap();
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("voter.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let signer = backend
        .enroll_voter_identity(installation(), identity())
        .await
        .unwrap();
    let limit = Limit(getrlimit(Resource::RLIMIT_NOFILE).unwrap());
    setrlimit(Resource::RLIMIT_NOFILE, 0, limit.0 .1).unwrap();
    let os_error = File::open(key_path(&path)).unwrap_err();
    let result = read_private_anchor(&path).map(|_| ());
    drop(limit);
    assert_eq!(os_error.raw_os_error(), Some(libc::EMFILE));
    assert_eq!(
        result,
        Err(ConsensusSessionStoreOpenError::StorageUnavailable)
    );
    assert_eq!(
        read_private_anchor(&path).unwrap().key_digest(),
        signer.key_digest()
    );
}

#[tokio::test]
async fn voter_public_binding_survives_restart_before_digest_collection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("voter.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    drop(
        backend
            .enroll_voter_identity(installation(), identity())
            .await
            .unwrap(),
    );
    drop(backend);
    let private_before = Zeroizing::new(std::fs::read(key_path(&path)).unwrap());
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let binding = backend
        .voter_identity_binding()
        .await
        .expect("completed enrollment must be discoverable without its lost return value");
    assert_eq!(binding.cluster_instance(), installation());
    assert_eq!(binding.identity(), identity());
    let selected = VoterSlotMember {
        identity: binding.identity(),
        key_digest: binding.key_digest(),
        descriptor_digest: [0xb2; 32],
        admission_generation: 1,
    };
    let signer = backend
        .voter_identity_signer(binding.cluster_instance(), &selected)
        .await
        .unwrap();
    assert_eq!(signer.key_digest(), binding.key_digest());
    assert_eq!(format!("{binding:?}"), "VoterIdentityBinding { .. }");
    assert!(
        std::fs::read(key_path(&path)).unwrap() == *private_before,
        "public inspection must not rewrite the private record"
    );
    assert!(matches!(
        backend
            .enroll_voter_identity(installation(), identity())
            .await,
        Err(ConsensusSessionStoreOpenError::VoterIdentityAlreadyEnrolled)
    ));
    std::fs::remove_file(key_path(&path)).unwrap();
    assert_eq!(
        backend.voter_identity_binding().await.unwrap(),
        binding,
        "public metadata is not proof that the private key is present"
    );
    assert!(matches!(
        backend
            .voter_identity_signer(installation(), &selected)
            .await,
        Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
    ));
}
