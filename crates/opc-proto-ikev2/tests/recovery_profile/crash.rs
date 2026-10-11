//! Actual process-loss qualification. The parent is only the independent peer:
//! it never creates or retains the initiator's private DH handle. Child exits
//! skip Rust destructors, and replacement processes read encrypted rows only.

use super::{
    authority::{EpochOwners, Transport},
    codec::ProfileCodec,
    driver::{self, Cut, Runtime},
    envelope::{self, Provider},
    inputs, ke,
    lifecycle::child_delete,
    module,
    peer::{Event, PeerModel},
    row::{KeKind, Outcome, Row},
    store::CasStore,
    wire::Wire,
};
use bytes::Bytes;
use opc_proto_ikev2::{
    Ikev2EphemeralDhKey as Dh, Ikev2MessageIdSyncMode as Mode, Ikev2SaInitCryptoProfile as Profile,
    PayloadChain,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CRASH_EXIT: i32 = 83;
const CHILD_WATCHDOG: Duration = Duration::from_secs(15 * 60);

pub struct RunDir(pub PathBuf);
impl RunDir {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ike-process-loss-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).unwrap();
        Self(root)
    }
}
impl Drop for RunDir {
    fn drop(&mut self) {
        // These are temporary encrypted runtime rows, never diagnostic evidence.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

pub fn write(root: &Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
}
pub fn read(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join(name)).unwrap()
}
pub fn packet_name(kind: &str, tag: u64) -> String {
    format!("{kind}-{tag}.packet")
}

struct Case {
    row: Row,
    kind: KeKind,
}
fn cases(selection: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut serial = 0;
    for (profile_id, base) in inputs::profiles().enumerate() {
        for group in ke::GROUPS {
            for direction in crate::canonical_fixtures::DIRECTIONS {
                for mode in [Mode::BaseFallback, Mode::Negotiated] {
                    for kind in ke::KINDS {
                        serial += 1;
                        if selection.ends_with("smoke") && ![0, 3].contains(&profile_id) {
                            continue;
                        }
                        let profile = Profile::from_transform_ids(
                            base.prf().transform_id(),
                            group.transform_id(),
                            base.encryption().transform_id(),
                            Some(base.encryption().key_bits()),
                            base.integrity().map(|i| i.transform_id()),
                        )
                        .unwrap();
                        cases.push(Case {
                            row: inputs::fresh(
                                (if selection == "responder-smoke" {
                                    500_000
                                } else if selection.starts_with("responder") {
                                    400_000
                                } else if selection.ends_with("smoke") {
                                    300_000
                                } else {
                                    200_000
                                }) + serial,
                                profile,
                                direction,
                                mode,
                            ),
                            kind,
                        });
                    }
                }
            }
        }
    }
    cases
}

fn process_command(root: &Path, stage: &str, selection: &str, build: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "crash::process_entry",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("OPC_RECOVERY_PROCESS", stage)
        .env("OPC_RECOVERY_DIRECTORY", root)
        .env("OPC_RECOVERY_MATRIX", selection)
        .env("OPC_RECOVERY_MODULE_BUILD", build);
    command
}

struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _kill = self.0.kill();
        let _reap = self.0.wait();
    }
}

fn output_with_watchdog(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    let mut child = ReapedChild(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    std::thread::scope(|scope| {
        // Drain both pipes while waiting so diagnostics cannot block the child.
        let out = scope.spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let err = scope.spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let started = Instant::now();
        let status = loop {
            match child.0.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(error) => break Err(error),
                Ok(None) => {}
            }
            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "recovery process watchdog expired",
                ));
            };
            // Wall time is exclusively a hang guard: expiration always fails.
            // Protocol decisions use the injected clocks in the child.
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        };
        // Kill and reap on timeout or wait failure before joining pipe readers.
        drop(child);
        let stdout = out
            .join()
            .map_err(|_| io::Error::other("stdout reader failed"))?;
        let stderr = err
            .join()
            .map_err(|_| io::Error::other("stderr reader failed"))?;
        Ok(Output {
            status: status?,
            stdout: stdout?,
            stderr: stderr?,
        })
    })
}

pub fn child(root: &Path, stage: &str, selection: &str, build: &str) {
    let output = output_with_watchdog(
        &mut process_command(root, stage, selection, build),
        CHILD_WATCHDOG,
    )
    .expect("recovery child failed or exceeded its watchdog");
    // Do not reproduce child diagnostics in a panic or an evidence archive.
    // Every child assertion is fieldless or concerns public protocol metadata.
    assert!(
        output.status.code() == Some(CRASH_EXIT),
        "process stage {stage} failed: {}; assertion location: {}",
        output.status,
        fs::read_to_string(root.join("failure.location")).unwrap_or_default()
    );
    assert!(!output.stdout.windows(11).any(|s| s == b"Zeroizing(["));
    assert!(!output.stderr.windows(11).any(|s| s == b"Zeroizing(["));
}

#[test]
fn process_watchdog_kills_a_hung_child_and_returns_failure() {
    let root = RunDir::new();
    let error = output_with_watchdog(
        &mut process_command(&root.0, "watchdog-hang", "smoke", "1"),
        Duration::ZERO,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn process_entry() {
    let Ok(stage) = std::env::var("OPC_RECOVERY_PROCESS") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("OPC_RECOVERY_DIRECTORY").unwrap());
    let selection = std::env::var("OPC_RECOVERY_MATRIX").unwrap();
    let failure_root = root.clone();
    std::panic::set_hook(Box::new(move |info| {
        // Retain the assertion site, never panic payloads or secret values.
        if let Some(location) = info.location() {
            let _result = fs::write(failure_root.join("failure.location"), location.to_string());
        }
    }));
    if stage == "watchdog-hang" {
        loop {
            std::thread::park();
        }
    }
    module::install();
    let provider = Provider::new();
    match stage.as_str() {
        value if value.starts_with("terminal-") => {
            super::terminal_process::run(&root, value, &selection, &provider)
        }
        value if value.starts_with("sync-") => {
            super::sync_process::run(&root, value, &selection, &provider)
        }
        value if value.starts_with("handoff-") => {
            super::handoff_process::run(&root, value, &selection, &provider)
        }
        "pending" => {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            for case in cases(&selection) {
                let row = case.row;
                let initial = driver::create(&provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let operation = ke::draft(&runtime.row, 19, case.kind);
                let before = provider.calls();
                assert!(ke::persist_ke(
                    &mut runtime,
                    &provider,
                    &mut store,
                    operation,
                    Cut::Complete
                )
                .unwrap());
                let after = provider.calls();
                // One enclosing envelope; readback adds one ordinary unseal.
                assert_eq!(after, (before.0 + 1, before.1 + 1));
                let mut transport = Transport::default();
                runtime.dispatch_replay(&mut transport).unwrap();
                write(
                    &root,
                    &packet_name("request", row.key.0),
                    transport.submitted.last().unwrap(),
                );
                // A committed IV-only row write and a committed inbound result
                // intervene while the initiator's checkpoint is still required.
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        29,
                        1,
                        120,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let inbound = read(&root, &packet_name("inbound", row.key.0));
                runtime
                    .publish_response(
                        &provider,
                        &mut store,
                        &inbound,
                        crate::canonical_fixtures::empty(),
                        Bytes::from_static(b"peer-child-deleted"),
                        |_| {},
                        Cut::Complete,
                    )
                    .unwrap();
                runtime.replay_response(&inbound, &mut transport).unwrap();
                write(
                    &root,
                    &packet_name("inbound-reply", row.key.0),
                    transport.submitted.last().unwrap(),
                );
                assert!(runtime.row.operations[&19].checkpoint.is_some());
                assert!(runtime.row.operations[&19].derived.is_none());
                assert_eq!(runtime.row.window.next_receive, Some(1));
            }
            write(&root, "pending.rows", &store.encrypted_snapshot());
        }
        "complete" => {
            let (mut store, cuts) =
                CasStore::reopen_after_join(&read(&root, "pending.rows"), 8).unwrap();
            let owners = EpochOwners::new(8);
            let before = module::counts();
            let count = cuts.len();
            for cut in cuts {
                let mut runtime = Runtime::restore(&provider, &owners, &cut, false).unwrap();
                let response = read(&root, &packet_name("response", cut.key().0));
                assert_eq!(
                    ke::complete_initiator(
                        &mut runtime,
                        &provider,
                        &mut store,
                        19,
                        &response,
                        Cut::Complete
                    )
                    .unwrap(),
                    Some(Bytes::from_static(b"ke-established"))
                );
                assert_eq!(runtime.row.operations[&19].outcome, Outcome::Success);
                assert!(runtime.row.operations[&19].checkpoint.is_none());
                assert!(!runtime.dispatch_replay(&mut Transport::default()).unwrap());
            }
            let after = module::counts();
            assert_eq!(
                after.dh_generate, before.dh_generate,
                "restart must not invent initiator KE material"
            );
            assert_eq!(after.dh_import - before.dh_import, count as u64);
            write(&root, "complete.rows", &store.encrypted_snapshot());
        }
        "responder" => {
            let mut store = CasStore::new(7);
            let owners = EpochOwners::new(7);
            for case in cases(&selection) {
                let row = case.row;
                let initial = driver::create(&provider, &mut store, &row).unwrap();
                let mut runtime = Runtime::restore(
                    &provider,
                    &owners,
                    &store.fenced_read(&initial, row.key).unwrap(),
                    false,
                )
                .unwrap();
                let request = read(&root, &packet_name("request", row.key.0));
                assert_eq!(
                    runtime.request_disposition(&request).unwrap(),
                    opc_proto_ikev2::recovery::Ikev2OrdinaryRequestDisposition::New
                );
                runtime
                    .reserve(
                        &provider,
                        &mut store,
                        19,
                        1,
                        100,
                        Cut::Complete,
                        Cut::Complete,
                    )
                    .unwrap();
                let before = store.publications;
                let key_calls = provider.calls();
                assert!(ke::commit_responder(
                    &mut runtime,
                    &provider,
                    &mut store,
                    19,
                    case.kind,
                    &request,
                    Cut::Applied
                )
                .unwrap()
                .is_none());
                assert_eq!(store.publications, before + 1);
                assert_eq!(provider.calls(), (key_calls.0 + 1, key_calls.1));
            }
            write(&root, "responder.rows", &store.encrypted_snapshot());
        }
        "responder-replay" => {
            let (store, cuts) =
                CasStore::reopen_after_join(&read(&root, "responder.rows"), 8).unwrap();
            let owners = EpochOwners::new(8);
            let before = module::counts();
            for cut in cuts {
                let mut runtime = Runtime::restore(&provider, &owners, &cut, false).unwrap();
                let operation = &runtime.row.operations[&19];
                assert!(!operation.initiated_here);
                assert_eq!(operation.outcome, Outcome::Success);
                assert!(operation.checkpoint.is_none());
                assert!(operation.derived.is_some());
                let request = read(&root, &packet_name("request", cut.key().0));
                let mut transport = Transport::default();
                runtime.replay_response(&request, &mut transport).unwrap();
                write(
                    &root,
                    &packet_name("response", cut.key().0),
                    transport.submitted.last().unwrap(),
                );
                runtime.replay_response(&request, &mut transport).unwrap();
                assert_eq!(transport.submitted[0], transport.submitted[1]);
            }
            let after = module::counts();
            assert_eq!(after.dh_generate, before.dh_generate);
            assert_eq!(after.dh_import, before.dh_import);
            write(
                &root,
                "responder-replayed.rows",
                &store.encrypted_snapshot(),
            );
        }
        stage if stage.starts_with("auth-") => super::auth_process::run(&root, stage, &provider),
        stage if stage.starts_with("gcm-") => super::iv_process::run(&root, stage, &provider),
        _ => panic!("unknown process stage"),
    }
    // Intentionally skip all remaining Rust destructors, then let the parent
    // join this process before creating the next owner/incarnation.
    std::process::exit(CRASH_EXIT);
}

fn pending_batch(selection: &str) {
    let root = RunDir::new();
    let cases = cases(selection);
    assert_eq!(
        cases.len(),
        if selection.ends_with("smoke") {
            144
        } else {
            3_672
        }
    );
    let mut peers = Vec::new();
    for case in &cases {
        let row = &case.row;
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        let inbound = peer.request(37, child_delete()).unwrap();
        write(&root.0, &packet_name("inbound", row.key.0), &inbound);
        peers.push(peer);
    }
    child(&root.0, "pending", selection, "checkpoint-export-build");
    let mut expected: BTreeMap<_, Zeroizing<Vec<u8>>> = BTreeMap::new();
    for (case, peer) in cases.iter().zip(&mut peers) {
        let row = &case.row;
        let request = read(&root.0, &packet_name("request", row.key.0));
        assert_eq!(peer.receive(&request), Ok(Event::NewRequest(0)));
        let packet = peer.wire.open(&request).unwrap();
        let fields = ke::parts(row, case.kind, row.profile.dh_group(), &packet, false).unwrap();
        let inbound_reply = read(&root.0, &packet_name("inbound-reply", row.key.0));
        assert_eq!(peer.receive(&inbound_reply), Ok(Event::Completed(0)));
        let dh = Dh::generate(row.profile.dh_group()).unwrap();
        let secret = dh.agree(&fields.public).unwrap();
        let spi = if case.kind == KeKind::IkeRekey {
            0x5152_5354_5556_5758
        } else {
            0x5152_5354
        };
        let nonce = [0x82; 64];
        let (first, payload) = ke::payload(
            row,
            case.kind,
            true,
            row.profile.dh_group(),
            spi,
            &nonce,
            dh.public_value(),
        );
        let response = peer.respond(0, PayloadChain::new(first, &payload)).unwrap();
        expected.insert(
            row.key,
            ke::derive(
                row,
                case.kind,
                (fields.spi, spi),
                &fields.nonce,
                &nonce,
                &secret,
            ),
        );
        drop(secret);
        drop(dh);
        write(&root.0, &packet_name("response", row.key.0), &response);
    }
    child(
        &root.0,
        "complete",
        selection,
        "checkpoint-import-new-build",
    );
    let (store, cuts) = CasStore::reopen_after_join(&read(&root.0, "complete.rows"), 9).unwrap();
    assert_eq!(cuts.len(), cases.len());
    let provider = Provider::new();
    for cut in cuts {
        let stored = store.inspect(cut.key()).unwrap();
        let plaintext = envelope::unseal(&provider, cut.key(), stored).unwrap();
        let row = ProfileCodec::decode(&plaintext, cut.key(), stored.version, stored.sealed_stamp)
            .unwrap();
        let operation = &row.operations[&19];
        assert_eq!(operation.outcome, Outcome::Success);
        assert!(operation.checkpoint.is_none());
        assert!(operation.derived.as_ref().unwrap().as_slice() == expected[&cut.key()].as_slice());
        assert_eq!(row.window.next_receive, Some(1));
        assert_eq!(row.window.next_send, Some(1));
        if let Some(iv) = row.iv {
            assert_eq!(iv.retries[&19].attempts, 1);
            assert_eq!(iv.retries[&29].attempts, 1);
            assert_eq!(iv.end, 2);
        }
    }
}

#[test]
fn pending_ke_restart_across_profiles_groups_roles_and_modes() {
    pending_batch("all");
}

#[test]
fn pending_ke_process_smoke_with_intervening_inbound_and_iv_writes() {
    pending_batch("smoke");
}

fn responder_batch(selection: &str) {
    let root = RunDir::new();
    let cases = cases(selection);
    assert_eq!(
        cases.len(),
        if selection.ends_with("smoke") {
            144
        } else {
            3_672
        }
    );
    let mut peers = Vec::new();
    let mut private = Vec::new();
    for case in &cases {
        let row = &case.row;
        let mut peer = PeerModel::new(
            Wire::new(
                row.profile,
                &row.keys,
                row.spis,
                crate::canonical_fixtures::opposite(row.direction),
            ),
            0,
            0,
            row.mode == Mode::Negotiated,
        );
        // This is the independent peer's initiator handle. The local child is
        // the responder and must never acquire or persist this private value.
        let dh = Dh::generate(row.profile.dh_group()).unwrap();
        let spi = if case.kind == KeKind::IkeRekey {
            0x3132_3334_3536_3738
        } else {
            0x3132_3334
        };
        let nonce = [0x41; 64];
        let (first, payload) = ke::payload(
            row,
            case.kind,
            false,
            row.profile.dh_group(),
            spi,
            &nonce,
            dh.public_value(),
        );
        let request = peer
            .request(36, PayloadChain::new(first, &payload))
            .unwrap();
        write(&root.0, &packet_name("request", row.key.0), &request);
        peers.push(peer);
        private.push(dh);
    }
    child(&root.0, "responder", selection, "responder-before-loss");
    for case in &cases {
        assert!(!root
            .0
            .join(packet_name("response", case.row.key.0))
            .exists());
    }
    child(
        &root.0,
        "responder-replay",
        selection,
        "responder-after-loss",
    );
    let provider = Provider::new();
    let (store, _) =
        CasStore::reopen_after_join(&read(&root.0, "responder-replayed.rows"), 9).unwrap();
    for ((case, peer), dh) in cases.iter().zip(&mut peers).zip(private) {
        let row = &case.row;
        let response = read(&root.0, &packet_name("response", row.key.0));
        assert_eq!(peer.receive(&response), Ok(Event::Completed(0)));
        // The replacement released this exact cached response twice.
        assert_eq!(peer.receive(&response), Ok(Event::Ignored));
        let packet = peer.wire.open(&response).unwrap();
        let fields = ke::parts(row, case.kind, row.profile.dh_group(), &packet, true).unwrap();
        let secret = dh.agree(&fields.public).unwrap();
        drop(dh);
        let spi = if case.kind == KeKind::IkeRekey {
            0x3132_3334_3536_3738
        } else {
            0x3132_3334
        };
        let expected = ke::derive(
            row,
            case.kind,
            (spi, fields.spi),
            &[0x41; 64],
            &fields.nonce,
            &secret,
        );
        drop(secret);
        let stored = store.inspect(row.key).unwrap();
        let plaintext = envelope::unseal(&provider, row.key, stored).unwrap();
        let restored =
            ProfileCodec::decode(&plaintext, row.key, stored.version, stored.sealed_stamp).unwrap();
        let operation = &restored.operations[&19];
        assert!(operation.checkpoint.is_none());
        assert!(operation.derived.as_ref().unwrap().as_slice() == expected.as_slice());
    }
}

#[test]
fn responder_ke_restart_replays_committed_response_and_keys_without_checkpoint() {
    responder_batch("responder-all");
}

#[test]
fn responder_ke_process_smoke_without_checkpoint_or_new_derivation() {
    responder_batch("responder-smoke");
}
