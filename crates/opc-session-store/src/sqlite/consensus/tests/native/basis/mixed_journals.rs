use super::super::{lifecycle::maintenance, roster};
use super::*;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, roster_v2_fresh_wal_persistence_fixture,
    ConsensusRosterAdmissionOutcome, ConsensusRosterTerminalOutcome, RosterV2PersistenceFixture,
};
use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
use crate::fenced_mutation_roster::{Phase, Profile, RosterAttestationTrustRootV1};
use crate::sqlite::consensus::wal::native::Opening;

fn timestamp(second: u8) -> Timestamp {
    // Match the signed roster fixture's clock while its authority is live.
    Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(i64::from(second)),
    )
}

fn isolated(case: &str) -> bool {
    const CHILD: &str = "OPC_MIXED_JOURNAL_TEST";
    if std::env::var(CHILD).as_deref() == Ok(case) {
        return false;
    }
    let name = format!("sqlite::consensus::tests::native::basis::mixed_journals::{case}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--test-threads=1", "--nocapture"])
        .env(CHILD, case)
        .test_output_with_deadline(std::time::Duration::from_secs(1800))
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for line in String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.starts_with("native_mixed_journal_"))
    {
        eprintln!("{line}");
    }
    true
}

fn history(remaining: usize, generation: u64, bound: usize) -> FencedTransitionV2HistoryState {
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    FencedTransitionV2HistoryState::new(
        Some(epoch(2)),
        Some(epoch(1)),
        Some(epoch(1)),
        remaining,
        generation,
        bound,
        (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - remaining) as u64,
    )
    .unwrap()
}

fn scoped(
    identity: SessionConsensusIdentity,
    mut entry: Entry<SessionRaftTypeConfig>,
) -> Entry<SessionRaftTypeConfig> {
    if let EntryPayload::Normal(command) = &mut entry.payload {
        command.identity = identity;
    }
    entry
}

struct MixedFixture {
    directory: tempfile::TempDir,
    wal: Wal,
    signed: RosterV2PersistenceFixture,
    root: Arc<RosterAttestationTrustRootV1>,
}

impl MixedFixture {
    fn new(control: IoControl) -> Self {
        let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
        let root = Arc::new(signed.root.clone());
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteSessionBackend::open(directory.path().join("basis.sqlite")).unwrap();
        roster::initialize(&backend, &signed);
        let path = directory.path().join("wal");
        let wal = Wal::create_native_with_root(
            &path,
            &backend.conn.blocking_lock(),
            signed.identity,
            [0xD4; 32],
            Some(Arc::clone(&root)),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        let mut lease = roster::ordinary(
            &signed,
            1,
            SessionMutationIntent::AcquireLease {
                key: signed.authority.key().clone(),
                owner: signed.authority.owner().clone(),
                ttl: Duration::from_secs(60),
            },
        );
        let EntryPayload::Normal(command) = &mut lease.payload else {
            unreachable!()
        };
        command.logical_time = signed.authority.acquired_at();
        let profile = Profile::v2();
        let roster_activation = roster::ordinary(
            &signed,
            2,
            SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                schema_version: profile.schema(),
                consumer_revision: profile.consumer_revision(),
                scope_identity: signed.identity,
                voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                    signed.identity,
                    &fixed_members(),
                ),
                profile_digest: profile.digest(),
            },
        );
        let initial = fenced_transition_v2_request(0xD4, 1, "mixed-journal-history");
        let entries = [
            formation(),
            lease,
            roster_activation,
            roster::admission(&signed),
            activating_fenced_transition_v2_authorized_entry(
                4,
                initial,
                timestamp(2),
                node_id(),
                signed.identity,
                signed.identity,
                &fixed_members(),
            ),
        ]
        .map(|entry| scoped(signed.identity, entry));
        roster::commit(&wal, &entries);
        let applied = wal.native_apply_committed(&entries).unwrap();
        assert!(matches!(
            &applied.responses[3].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        assert!(applied.responses[4].result.is_ok());
        let binding = wal.binding();
        wal.shutdown().unwrap();
        drop(wal);
        let wal = Wal::open_reclaim_fixture_with_root_for_test(
            &path,
            binding,
            Arc::clone(&root),
            history(4096, 1, 0),
            timestamp(2),
            control,
        )
        .unwrap();
        Self {
            directory,
            wal,
            signed,
            root,
        }
    }
}

fn consumer(row: u64, slot: usize) -> FencedTransitionV2Request {
    let request = sdk741_component_request(Sdk741Payload::Create, row, slot, None);
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(2).unwrap(),
        crate::FencedTransitionV2CallerNonce::from_bytes(
            (u128::from(row) * 8 + slot as u128).to_be_bytes(),
        ),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .unwrap()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CrashReport {
    directory: PathBuf,
    basis: [u8; 32],
    digest: [u8; 32],
    consumer: FencedTransitionV2Request,
    fill_peak: usize,
    retirement_peak: usize,
}

#[test]
fn native_journal_pressure_mixed_captured_and_live_crash_reopens() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(1800), || {
        const CASE: &str = "native_journal_pressure_mixed_captured_and_live_crash_reopens";
        if isolated(CASE) {
            return;
        }
        const CRASH: &str = "OPC_MIXED_JOURNAL_CRASH";
        if let Some(report) = std::env::var_os(CRASH) {
            let gate = Gate::new(Point::BeforeNativeGenerationAppend, 1);
            let fixture = MixedFixture::new(gate.control());
            let entries = [
                roster::terminal(&fixture.signed, 5),
                fenced_transition_v2_entry(6, consumer(1, 0), timestamp(3)),
                maintenance(7, history(4096, 1, 1), timestamp(3)),
            ]
            .map(|entry| scoped(fixture.signed.identity, entry));
            roster::commit(&fixture.wal, &entries);
            VerificationMemory::begin_retirement_phase_for_test();
            let applied = fixture.wal.native_apply_committed(&entries).unwrap();
            assert!(applied
                .responses
                .iter()
                .all(|response| response.result.is_ok()));
            let owners = fixture.wal.native_journal_owners_for_test().unwrap();
            assert!(owners[..3].iter().all(|bytes| *bytes > 0));
            std::thread::scope(|scope| {
                let _checkpoint = scope.spawn(|| fixture.wal.checkpoint());
                gate.entered();
                assert_eq!(
                    fixture.wal.native_journal_owners_for_test().unwrap()[..3],
                    [0; 3]
                );
                let _other_images = VerificationMemory::reserve(56 * 1024 * 1024).unwrap();
                let late = timestamp(3).add_seconds(24 * 60 * 60).unwrap();
                let mut clock = roster::ordinary(
                    &fixture.signed,
                    8,
                    SessionMutationIntent::AdvanceLogicalTime,
                );
                let EntryPayload::Normal(command) = &mut clock.payload else {
                    unreachable!()
                };
                command.logical_time = late;
                let request = consumer(2, 0);
                let entries = [
                    clock,
                    fenced_transition_v2_entry(9, request.clone(), late),
                    maintenance(10, history(3072, 2, 2), late),
                ]
                .map(|entry| scoped(fixture.signed.identity, entry));
                roster::commit(&fixture.wal, &entries);
                let applied = fixture.wal.native_apply_committed(&entries).unwrap();
                assert!(applied
                    .responses
                    .iter()
                    .all(|response| response.result.is_ok()));
                let owners = fixture.wal.native_journal_owners_for_test().unwrap();
                assert!(
                    owners[..3].iter().all(|bytes| *bytes > 0),
                    "live business, roster and log journals coexist with the captured cut"
                );
                assert!(matches!(
                    status(&fixture.wal, &request),
                    FencedTransitionV2Status::Recorded(_)
                ));
                let [_, fill_peak, cap] = VerificationMemory::usage_for_test();
                let retirement_peak = VerificationMemory::retirement_peak_for_test();
                assert!(fill_peak <= cap && retirement_peak <= cap);
                let report_value = CrashReport {
                    directory: fixture.directory.path().join("wal"),
                    basis: fixture.wal.binding().basis,
                    digest: fixture
                        .wal
                        .with_native_read(|state| Ok(state.clone()))
                        .unwrap()
                        .mixed_business_digest_for_test()
                        .unwrap(),
                    consumer: request,
                    fill_peak,
                    retirement_peak,
                };
                std::fs::write(report, serde_json::to_vec(&report_value).unwrap()).unwrap();
                std::process::exit(73); // Both journals and the blocked writer still exist.
            });
            unreachable!();
        }
        let directory = tempfile::tempdir().unwrap();
        let report_path = directory.path().join("crash.json");
        let test = format!("sqlite::consensus::tests::native::basis::mixed_journals::{CASE}");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--test-threads=1", "--nocapture"])
            .env(CRASH, &report_path)
            .env("TMPDIR", directory.path())
            .test_output_with_deadline(std::time::Duration::from_secs(1800))
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: CrashReport =
            serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
        let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
        let binding = crate::sqlite::consensus::wal::Binding {
            identity: signed.identity,
            generation: [0xD4; 32],
            basis: report.basis,
            native: true,
            persistence: crate::SessionPersistenceMode::Durable,
            async_closed_format: false,
            async_recovery_format: false,
        };
        let (wal, observation) =
            Wal::open_mixed_replay_for_test(&report.directory, binding, Arc::new(signed.root))
                .unwrap();
        assert_eq!(
            wal.with_native_read(|state| Ok(state.clone()))
                .unwrap()
                .mixed_business_digest_for_test()
                .unwrap(),
            report.digest
        );
        assert!(matches!(
            status(&wal, &report.consumer),
            FencedTransitionV2Status::Recorded(_)
        ));
        assert_eq!(
            wal.with_native_read(|state| state.history_state()).unwrap(),
            history(2048, 3, 2)
        );
        let entry = scoped(
            signed.identity,
            maintenance(
                11,
                history(2048, 3, 2),
                timestamp(4).add_seconds(24 * 60 * 60).unwrap(),
            ),
        );
        roster::commit(&wal, std::slice::from_ref(&entry));
        assert!(wal.native_apply_committed(&[entry]).unwrap().responses[0]
            .result
            .is_ok());
        wal.checkpoint().unwrap();
        let stopping = Instant::now();
        wal.shutdown().unwrap();
        assert!(stopping.elapsed() < Duration::from_secs(5));
        assert!(observation[3] <= PROCESS_VERIFICATION_BYTES);
        eprintln!("native_mixed_journal_crash fill_peak={} retirement_peak={} cold_peak={} cap={PROCESS_VERIFICATION_BYTES}", report.fill_peak, report.retirement_peak, observation[3]);
    });
}

#[test]
fn native_journal_pressure_large_mixed_cold_replay_rebases_before_exhaustion() {
    crate::test_process::with_completion_deadline(std::time::Duration::from_secs(1800), || {
        const CASE: &str =
            "native_journal_pressure_large_mixed_cold_replay_rebases_before_exhaustion";
        if isolated(CASE) {
            return;
        }
        let MixedFixture {
            directory,
            wal,
            signed,
            root,
        } = MixedFixture::new(IoControl::default());
        let first = roster::terminal(&signed, 5);
        wal.submit(append(&[first])).unwrap().wait().unwrap();
        const BATCHES: u64 = 8192;
        let mut pending = Vec::new();
        for batch in 0..BATCHES {
            let requests = (0..8).map(|slot| consumer(batch + 1, slot)).collect();
            pending.push(scoped(
                signed.identity,
                fenced_transition_v2_batch_entry(6 + batch, requests, timestamp(3)),
            ));
            if pending.len() == 64 {
                wal.submit(append(&pending)).unwrap().wait().unwrap();
                pending.clear();
            }
        }
        assert!(pending.is_empty());
        let last = 6 + BATCHES;
        let retirement = scoped(
            signed.identity,
            maintenance(last, history(4096, 1, BATCHES as usize * 8), timestamp(4)),
        );
        roster::commit(&wal, std::slice::from_ref(&retirement));
        wal.checkpoint().unwrap(); // The complete committed log is cold; business remains at entry 4.
        assert_eq!(
            wal.with_native_read(|state| Ok(state.applied())).unwrap(),
            Some(log_id(4))
        );
        let fill_peak = VerificationMemory::usage_for_test()[1];
        let binding = wal.binding();
        wal.shutdown().unwrap();
        drop(wal);
        let (wal, observation) = Wal::open_mixed_replay_for_test(
            &directory.path().join("wal"),
            binding,
            Arc::clone(&root),
        )
        .unwrap();
        assert_eq!(
            observation[0], 1,
            "large recovery must authenticate and release complete journals"
        );
        assert!(observation[1] < 24 * 1024 * 1024);
        assert!(
            observation[3] < 96 * 1024 * 1024,
            "cold peak={}",
            observation[3]
        );
        assert_eq!(
            wal.with_native_read(|state| Ok(state.applied())).unwrap(),
            Some(log_id(last))
        );
        assert_eq!(
            wal.with_native_read(|state| state.history_state()).unwrap(),
            history(3072, 2, BATCHES as usize * 8)
        );
        for row in [1, BATCHES / 2, BATCHES] {
            for slot in [0, 7] {
                assert!(matches!(
                    status(&wal, &consumer(row, slot)),
                    FencedTransitionV2Status::Recorded(_)
                ));
            }
        }
        let retry = roster::terminal(&signed, last + 1);
        roster::commit(&wal, std::slice::from_ref(&retry));
        assert!(matches!(
            &wal.native_apply_committed(&[retry]).unwrap().responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
            ))
        ));
        wal.checkpoint().unwrap();
        let stopping = Instant::now();
        wal.shutdown().unwrap();
        assert!(stopping.elapsed() < Duration::from_secs(5));
        drop(wal);
        let reopened = Opening::new(
            &directory.path().join("wal"),
            binding,
            Some(root),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap()
        .finish(|| Ok(()))
        .unwrap();
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(log_id(last + 1))
        );
        reopened.shutdown().unwrap();
        eprintln!("native_mixed_journal_replay receipts={} fill_peak={fill_peak} journal={} retained={} cold_peak={} cap={PROCESS_VERIFICATION_BYTES}", BATCHES * 8, observation[1], observation[2], observation[3]);
    });
}
