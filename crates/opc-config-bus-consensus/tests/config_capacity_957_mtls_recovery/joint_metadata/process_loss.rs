//! Native Durable recovery after SIGKILL of this fixture's own child process.

use super::*;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};

const ROOT_ENV: &str = "OPC_CONFIG_CAPACITY_957_PROCESS_ROOT";
const MODE_ENV: &str = "OPC_CONFIG_CAPACITY_957_PROCESS_AUDITED";
const READY: &str = "CONFIG_CAPACITY_957_PROCESS_READY";
const CHILD_TEST: &str = "joint_metadata::process_loss::config_capacity_957_child_process_entry";
// This new fixture has multiple separately bounded SDK operations. It does not
// change their deadlines or the existing leader-convergence qualification.
const CHILD_FIXTURE_HANG_GUARD: Duration = Duration::from_secs(120);

fn new_file(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("new private synthetic fixture file")
}

fn save<T: Serialize>(path: &Path, value: &T) {
    let mut file = new_file(path);
    serde_json::to_writer(&mut file, value).expect("serialize synthetic recovery evidence");
    file.sync_all().expect("retain original recovery evidence");
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let file = File::open(path).expect("original private recovery evidence");
    serde_json::from_reader(BufReader::new(file)).expect("decode original synthetic evidence")
}

fn retained_pki(directory: &Path) -> Pki {
    let pem = std::fs::read_to_string(directory.join("synthetic-ca-key.pem"))
        .expect("original synthetic fixture CA key");
    let key = rcgen::KeyPair::from_pem(&pem).expect("original synthetic CA key encoding");
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "synthetic config process recovery CA",
    );
    Pki {
        issuer: rcgen::CertifiedIssuer::self_signed(params, key)
            .expect("same synthetic CA signing key and subject"),
    }
}

#[derive(Serialize, Deserialize)]
struct Original {
    record: CommitRecord,
    handle: Vec<u8>,
}

impl Original {
    fn recover(&self, audited: bool) -> Recovery {
        if audited {
            Recovery::Audited(Box::new(
                AuditOperationHandle::decode(&self.handle).expect("original audited handle bytes"),
            ))
        } else {
            Recovery::Ordinary(
                ConfigCommitRecoveryHandle::from_bytes(&self.handle)
                    .expect("original ordinary handle bytes"),
            )
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Authority {
    history_audit_outcomes: [i64; 3],
    ledger_hmac: Option<Vec<u8>>,
    capacity_proofs: i64,
}

fn authority(path: &Path) -> Authority {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only original native authority");
    let counts = effect_counts(path);
    Authority {
        history_audit_outcomes: [counts[0], counts[1], counts[3]],
        ledger_hmac: connection
            .query_row(
                "SELECT state_hmac FROM config_raft_management_audit WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .expect("optional original authenticated ledger"),
        capacity_proofs: connection
            .query_row(
                "SELECT COUNT(*) FROM config_raft_capacity_records",
                [],
                |row| row.get(0),
            )
            .expect("original retained capacity evidence"),
    }
}

// The guard never discovers or targets another process. Its Child handle is
// returned directly by spawning this exact test binary below.
struct FixtureChild {
    child: Child,
    reader: Option<std::thread::JoinHandle<()>>,
    reaped: bool,
}

impl FixtureChild {
    fn kill_and_reap(&mut self) {
        self.child
            .kill()
            .expect("SIGKILL this fixture's live child");
        let status = self.child.wait().expect("reap only the fixture child");
        self.reaped = true;
        assert_eq!(
            status.signal(),
            Some(9),
            "actual unclean process termination"
        );
        self.reader
            .take()
            .expect("owned stdout observer")
            .join()
            .expect("bounded stdout observer completed");
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn spawn_fixture(
    directory: &Path,
    audited: bool,
) -> (FixtureChild, tokio::sync::oneshot::Receiver<bool>) {
    let mut log = new_file(&directory.join("child-stdout.log"));
    let child = Command::new(std::env::current_exe().expect("current native test binary"))
        .args([
            "--ignored",
            "--exact",
            CHILD_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROOT_ENV, directory)
        .env(MODE_ENV, if audited { "true" } else { "false" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(new_file(&directory.join("child-stderr.log"))))
        .spawn()
        .expect("spawn only the owned native fixture child");
    let mut guard = FixtureChild {
        child,
        reader: None,
        reaped: false,
    };
    let stdout = guard
        .child
        .stdout
        .take()
        .expect("owned child readiness pipe");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let reader = std::thread::spawn(move || {
        // The fixed byte bound applies across all lines, including harness text.
        let lines = BufReader::new(stdout).take(16_384).lines();
        for line in lines {
            let Ok(line) = line else {
                break;
            };
            writeln!(log, "{line}").expect("retain child fixture output");
            if line == READY {
                let _ = sender.send(true);
                return;
            }
        }
        let _ = sender.send(false);
    });
    guard.reader = Some(reader);
    (guard, receiver)
}

native_case!(config_capacity_957_joint_ordinary_unclean_process_reopen, {
    run_parent(false).await;
});

native_case!(config_capacity_957_joint_audited_unclean_process_reopen, {
    run_parent(true).await;
});

async fn run_parent(audited: bool) {
    let directory = disk_fixture();
    let key = rcgen::KeyPair::generate().expect("private synthetic CA key");
    let mut key_file = new_file(&directory.join("synthetic-ca-key.pem"));
    key_file
        .write_all(key.serialize_pem().as_bytes())
        .expect("retain same synthetic CA key for both processes");
    key_file.sync_all().expect("retain fixture trust anchor");
    drop((key_file, key));
    let pki = retained_pki(&directory);
    let (mut child, ready) = spawn_fixture(&directory, audited);
    assert!(
        matches!(
            tokio::time::timeout(CHILD_FIXTURE_HANG_GUARD, ready).await,
            Ok(Ok(true))
        ),
        "child must prove acknowledged control and exact ambiguous successor before process loss"
    );
    child.kill_and_reap();
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let retained: [Authority; 3] = load(&directory.join("authority.json"));
    assert!(
        databases.each_ref().map(|path| authority(path)) == retained,
        "acknowledged native authority survives SIGKILL before SDK reopening"
    );
    let originals: [Original; 2] =
        [1, 2].map(|version| load(&directory.join(format!("original-{version}.json"))));
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let stores = open_members(
        &directory,
        &manifest,
        &pki,
        &addresses,
        &faults,
        true,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
    assert!(
        databases.each_ref().map(|path| authority(path)) == retained,
        "original configuration, audit, outcomes and proofs restore before transport catch-up"
    );
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let before = databases.each_ref().map(|path| effect_counts(path));
    let principal = principal(audited);
    let expected = &originals[1].record;
    let aad = aad(expected, 0);
    let plaintext = plaintext(0);
    for store in &stores {
        for original in &originals {
            recover(
                store,
                &original.recover(audited),
                &principal,
                original.record.version.get(),
            )
            .await;
        }
        let value = store
            .load_latest()
            .await
            .expect("post-process-loss native quorum read")
            .expect("original retained successor");
        assert_readback(&value, expected, &aad, &plaintext);
    }
    assert!(databases.each_ref().map(|path| authority(path)) == retained);
    assert_eq!(databases.each_ref().map(|path| effect_counts(path)), before);
    assert_eq!(
        faults
            .iter()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst))
            .sum::<usize>(),
        0,
        "original-result recovery after process loss never resubmits a mutation"
    );
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_PROCESS_LOSS audited={audited} signal=9 native_wal=true mtls=true original_paths=true original_handles=true acknowledged_control=true ambiguous_successor=true resubmitted=false power_loss_claim=false");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "internal child entry point invoked exactly once by each process-loss parent"]
async fn config_capacity_957_child_process_entry() {
    let directory = PathBuf::from(std::env::var_os(ROOT_ENV).expect("own fixture parent root"));
    let audited = match std::env::var(MODE_ENV).as_deref() {
        Ok("true") => true,
        Ok("false") => false,
        _ => panic!("own fixture parent mode"),
    };
    let pki = retained_pki(&directory);
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let stores = open_members(
        &directory,
        &manifest,
        &pki,
        &addresses,
        &faults,
        false,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("original child leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .expect("original child leader member");
    let follower = (leader + 1) % 3;
    let principal = principal(audited);
    if audited {
        stores[leader]
            .initialize_audit_authority(
                &privacy(),
                AuditLedgerLimits::new(12, 4).expect("original bounded audit limits"),
            )
            .await
            .expect("original child replicated audited authority");
    }
    let mut parent = None;
    for version in [1, 2] {
        let uncertain = version == 2;
        let source = if uncertain { follower } else { leader };
        let (input, aad, plaintext) = input(&stores[source], version, parent, &principal, 0).await;
        let expected = input.record().clone();
        if audited {
            let prepared = stores[source]
                .prepare_audited_commit(
                    &privacy(),
                    &event(version, &principal),
                    input,
                    Duration::from_secs(60),
                )
                .expect("one original audited process-loss preparation");
            let original = Original {
                record: expected.clone(),
                handle: prepared.handle().encode().expect("original audited handle"),
            };
            save(
                &directory.join(format!("original-{version}.json")),
                &original,
            );
            let handle = prepared.handle().clone();
            let admission = if uncertain {
                stores[source]
                    .admit_audit_operation(&handle, caller(&principal))
                    .await
            } else {
                stores[source]
                    .admit_audit_operation_local(&handle, caller(&principal))
                    .await
            };
            let AuditAdmission::Applied(admission) = admission else {
                panic!("original audit intent acknowledged before effect fault");
            };
            assert_eq!(admission.state(), AuditOperationState::Intent);
            if uncertain {
                faults[source].armed.store(true, Ordering::SeqCst);
                let result = stores[source]
                    .submit_audited_mutation(&prepared, &admission, caller(&principal))
                    .await;
                let AuditAdmission::Unknown(unknown) = result else {
                    panic!("lost audited effect result stays ambiguous before process loss");
                };
                assert!(
                    unknown == handle,
                    "preserve original uncertain audited operation"
                );
            } else {
                let result = stores[source]
                    .submit_audited_mutation_local(&prepared, &admission, caller(&principal))
                    .await;
                let AuditAdmission::Applied(acknowledged) = result else {
                    panic!("original audited control must be acknowledged before process loss");
                };
                assert_eq!(
                    acknowledged.state(),
                    AuditOperationState::Committed { version }
                );
            }
        } else {
            let prepared = stores[source]
                .prepare_recoverable_commit(
                    ConfigConsensusRequestId::from_bytes([0xC5 + version as u8; 16]),
                    input,
                    &principal,
                )
                .expect("one original ordinary process-loss preparation");
            let original = Original {
                record: expected.clone(),
                handle: prepared.recovery_handle().as_bytes().to_vec(),
            };
            save(
                &directory.join(format!("original-{version}.json")),
                &original,
            );
            if uncertain {
                faults[source].armed.store(true, Ordering::SeqCst);
                let error = stores[source]
                    .append_prepared_commit(prepared)
                    .await
                    .expect_err("lost original ordinary effect response");
                assert!(matches!(error.kind(), PersistErrorKind::OutcomeUnknown));
            } else {
                stores[source]
                    .append_prepared_commit_local(prepared)
                    .await
                    .expect("original ordinary control durably acknowledged before process loss");
            }
        }
        for store in &stores {
            let value = store
                .load_latest()
                .await
                .expect("child quorum read")
                .expect("child head");
            assert_readback(&value, &expected, &aad, &plaintext);
        }
        parent = Some(expected.tx_id);
    }
    assert_eq!(faults[follower].lost_responses.load(Ordering::SeqCst), 1);
    assert_eq!(
        faults[follower].actual_forwards.load(Ordering::SeqCst),
        if audited { 2 } else { 1 }
    );
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let retained = databases.each_ref().map(|path| authority(path));
    for member in &retained {
        assert_eq!(member.history_audit_outcomes[0], 2);
        assert_eq!(member.history_audit_outcomes[1], (2 * AUDIT_RECORDS) as i64);
        assert_eq!(member.capacity_proofs, 2);
    }
    save(&directory.join("authority.json"), &retained);
    // A leading newline also separates the signal from the test harness label.
    println!("\n{READY}");
    std::io::stdout()
        .flush()
        .expect("flush bounded readiness signal");
    // Keep every store, accepted handler and listener alive. The parent kills
    // this process; no native checkpoint, shutdown or destructor is requested.
    std::future::pending::<()>().await;
    drop((stores, servers, released));
    panic!("process-loss fixture must never return normally");
}
