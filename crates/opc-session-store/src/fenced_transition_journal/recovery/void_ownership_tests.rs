use super::*;
use crate::test_process::CommandExt as _;
use crate::{
    FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
    Generation, LeaseGuard, OwnerId, SessionKey, SessionKeyType, StableId,
};
use bytes::Bytes;
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::{
    process::{Command, Stdio},
    time::Duration,
};

const SCOPE: [u8; 32] = [0x5c; 32];
const CHILD: &str =
    "fenced_transition_journal::recovery::void_ownership_tests::owned_journal_process_child";

fn key() -> FencedTransitionV2RecoveryJournalKey {
    FencedTransitionV2RecoveryJournalKey::from_bytes([0x31; 32])
}

fn directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn request() -> FencedTransitionV2Request {
    let key = SessionKey {
        tenant: TenantId::from_static("void-journal"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"void-journal-key")).unwrap(),
    };
    let acquired = Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
    );
    let expires = Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(70),
    );
    let guard = LeaseGuard::new(
        key,
        OwnerId::new("void-journal-owner").unwrap(),
        FenceToken::new(1),
        acquired,
        expires,
        1,
    );
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes([7; 16]),
        FencedTransitionLease::renew(guard, Duration::from_secs(30)).unwrap(),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .unwrap()
}

#[test]
fn baseline_journal_concurrent_creation_ignores_other_directory_owners() {
    let directory = directory();
    // Model another creator in this directory deterministically, while two
    // independent baseline creates start together. Schema 1 owns only its file.
    let _directory_owner = nix::fcntl::Flock::lock(
        std::fs::File::open(directory.path()).unwrap(),
        nix::fcntl::FlockArg::LockExclusiveNonblock,
    )
    .unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            FencedTransitionV2RecoveryJournal::create_new(
                directory.path().join("one.sqlite3"),
                key(),
            )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            FencedTransitionV2RecoveryJournal::create_new(
                directory.path().join("two.sqlite3"),
                key(),
            )
        });
        assert!(first.join().unwrap().is_ok(), "first baseline create");
        assert!(second.join().unwrap().is_ok(), "second baseline create");
    });
}

#[test]
fn baseline_journal_open_does_not_require_directory_lock_support() {
    let directory = directory();
    let path = directory.path().join("baseline.sqlite3");
    drop(FencedTransitionV2RecoveryJournal::create_new(&path, key()).unwrap());
    creation::REFUSE_DIRECTORY_LOCK.with(|refuse| refuse.set(true));
    let result = FencedTransitionV2RecoveryJournal::open_existing(&path, key());
    creation::REFUSE_DIRECTORY_LOCK.with(|refuse| refuse.set(false));
    assert!(
        result.is_ok(),
        "baseline open does not lock or scan its directory: {:?}",
        result.err()
    );
}

#[test]
fn baseline_journal_second_open_keeps_the_original_coarse_error() {
    let directory = directory();
    let path = directory.path().join("baseline.sqlite3");
    let _journal = FencedTransitionV2RecoveryJournal::create_new(&path, key()).unwrap();
    assert_eq!(
        FencedTransitionV2RecoveryJournal::open_existing(&path, key())
            .err()
            .unwrap(),
        recovery_unavailable()
    );
}

#[tokio::test]
async fn owned_journal_void_waits_for_current_call_and_accepts_inherited_rows() {
    let directory = directory();
    let path = directory.path().join("owned.sqlite3");
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(&path, key()).unwrap();
    journal.ensure_scope(SCOPE).await.unwrap();
    let id = FencedTransitionRequestId::from_bytes([1; 16]);
    let request = request();
    let call = journal
        .begin_call(id, tokio::time::Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    journal.insert(SCOPE, id, &request).await.unwrap();
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::WaitingCaller
    );
    assert_eq!(
        journal
            .clone()
            .void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::WaitingCaller
    );
    call.returned();
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
    drop(call);
    drop(journal);
    assert!(FencedTransitionV2RecoveryJournal::open_existing(&path, key()).is_err());
    let reopened = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).unwrap();
    assert_eq!(
        reopened.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
    assert!(reopened.remove_if_exact(SCOPE, id, &request).await.unwrap());
    // A direct low-level preparation has no known call deadline in this owner.
    reopened.insert(SCOPE, id, &request).await.unwrap();
    assert_eq!(
        reopened.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::WaitingCaller
    );
    assert!(!reopened.try_begin_void(id, request.request_id()));
    drop(reopened);
    let inherited = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).unwrap();
    assert_eq!(
        inherited.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
    assert!(inherited.try_begin_void(id, request.request_id()));
}

#[tokio::test]
async fn owned_journal_void_deadline_and_cancelled_preparation_are_process_local() {
    let directory = directory();
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(
        directory.path().join("owned.sqlite3"),
        key(),
    )
    .unwrap();
    journal.ensure_scope(SCOPE).await.unwrap();
    let id = FencedTransitionRequestId::from_bytes([2; 16]);
    let request = request();
    let call = journal
        .begin_call(id, tokio::time::Instant::now())
        .await
        .unwrap();
    journal.insert(SCOPE, id, &request).await.unwrap();
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
    drop(call);
    journal.remove_if_exact(SCOPE, id, &request).await.unwrap();
    for _ in 0..=FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
        drop(
            journal
                .begin_call(id, tokio::time::Instant::now() + Duration::from_secs(60))
                .await
                .unwrap(),
        );
    }
    let call = journal
        .begin_call(id, tokio::time::Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    journal.insert(SCOPE, id, &request).await.unwrap();
    drop(call);
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
}

#[tokio::test(start_paused = true)]
async fn owned_journal_void_serializes_redispatch_with_reclamation() {
    let directory = directory();
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(
        directory.path().join("calls.sqlite3"),
        key(),
    )
    .unwrap();
    journal.ensure_scope(SCOPE).await.unwrap();
    let id = FencedTransitionRequestId::from_bytes([0x41; 16]);
    let request = request();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let call = journal.begin_call(id, deadline).await.unwrap();
    journal.insert(SCOPE, id, &request).await.unwrap();
    assert!(call.dispatch_started());
    assert!(!journal.try_begin_void(id, request.request_id()));
    // Cancellation before dispatch permits reclamation, but a new dispatch
    // clears that state before any original request can be sent.
    call.returned();
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::Ready
    );
    assert!(call.dispatch_started());
    assert_eq!(
        journal.void_reclamation_eligibility(id, request.request_id()),
        FencedTransitionV2VoidEligibility::WaitingCaller
    );
    assert!(!journal.try_begin_void(id, request.request_id()));
    // An unknown attempt does not call returned(). The original deadline
    // alone then makes the row eligible, without a restart.
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(!journal.try_begin_void(id, request.request_id()));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(journal.try_begin_void(id, request.request_id()));
    assert!(
        !call.dispatch_started(),
        "a claimed void can still be in flight"
    );
    assert!(
        journal.try_begin_void(id, request.request_id()),
        "exact void retry"
    );
}

#[test]
fn owned_journal_void_never_converts_a_legacy_journal() {
    let directory = directory();
    let path = directory.path().join("legacy.sqlite3");
    let legacy = FencedTransitionV2RecoveryJournal::create_new(&path, key()).unwrap();
    assert!(FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).is_err());
    drop(legacy);
    assert!(FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).is_err());
    assert!(FencedTransitionV2RecoveryJournal::open_existing(&path, key()).is_ok());
}

#[tokio::test]
async fn owned_journal_void_late_completion_cannot_recreate_a_removed_call() {
    let directory = directory();
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(
        directory.path().join("owned.sqlite3"),
        key(),
    )
    .unwrap();
    journal.ensure_scope(SCOPE).await.unwrap();
    let id = FencedTransitionRequestId::from_bytes([3; 16]);
    let request = request();
    let call = journal
        .begin_call(id, tokio::time::Instant::now())
        .await
        .unwrap();
    journal.insert(SCOPE, id, &request).await.unwrap();
    let status = crate::FencedTransitionV2Status::Recorded(Box::new(Err(
        StoreError::FencedTransitionVoided,
    )));
    journal.record_terminal(id, request.request_id(), &status);
    assert!(call.notice().was_voided());
    journal.remove_if_exact(SCOPE, id, &request).await.unwrap();
    // Another sweep's already admitted void response arrives after removal.
    journal.record_terminal(id, request.request_id(), &status);
    let next = journal
        .begin_call(id, tokio::time::Instant::now())
        .await
        .unwrap();
    assert!(!next.notice().was_voided());
    assert!(call.notice().was_voided());
}

#[test]
#[ignore = "controlled subprocess for journal creation crash boundaries"]
fn owned_journal_creation_child() {
    let path = std::env::var_os("OPC_VOID_JOURNAL_TEST_PATH").unwrap();
    let _journal = FencedTransitionV2RecoveryJournal::create_new_owned(path, key()).unwrap();
}

#[test]
fn owned_journal_creation_is_crash_atomic() {
    for point in [
        "created",
        "locked",
        "opened",
        "initialized",
        "checkpointed",
        "closed",
        "synced",
        "published",
        "directory_synced",
    ] {
        let directory = directory();
        let path = directory.path().join("atomic.sqlite3");
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fenced_transition_journal::recovery::void_ownership_tests::owned_journal_creation_child"])
            .env("OPC_VOID_JOURNAL_TEST_PATH", &path)
            .env("OPC_RECOVERY_CREATION_CRASH_POINT", point)
            .test_output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(73),
            "{point}; stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        );
        let recovered = if path.exists() {
            FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key())
        } else {
            FencedTransitionV2RecoveryJournal::create_new_owned(&path, key())
        };
        assert!(
            recovered.is_ok(),
            "{point}: no manual removal after a crash"
        );
        drop(recovered);
        assert!(FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).is_ok());
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".opc-v2-recovery-")),
            "{point}: predecessor staging files cleaned"
        );
    }
}

#[test]
fn owned_journal_live_owner_and_corruption_have_distinct_reasons() {
    let directory = directory();
    let path = directory.path().join("reason.sqlite3");
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(&path, key()).unwrap();
    let locked = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key())
        .err()
        .unwrap();
    drop(journal);
    std::fs::write(&path, b"corrupt").unwrap();
    let corrupt = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key())
        .err()
        .unwrap();
    assert_eq!(locked, recovery_owner_locked());
    assert_ne!(locked, corrupt);
}

#[test]
#[ignore = "controlled subprocess for exclusive journal ownership"]
fn owned_journal_process_child() {
    let path = std::env::var_os("OPC_VOID_JOURNAL_TEST_PATH").unwrap();
    let result = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key());
    if std::env::var_os("OPC_VOID_JOURNAL_TEST_EXPECT_DENIED").is_some() {
        assert!(result.is_err());
        return;
    }
    let _journal = result.unwrap();
    std::fs::write(
        std::env::var_os("OPC_VOID_JOURNAL_TEST_READY").unwrap(),
        b"ready",
    )
    .unwrap();
    let mut byte = [0_u8; 1];
    let _ = std::io::Read::read(&mut std::io::stdin(), &mut byte);
}

#[tokio::test]
async fn owned_journal_void_lookup_retains_its_notice_across_row_removal() {
    let directory = directory();
    let path = directory.path().join("owned.sqlite3");
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(&path, key()).unwrap();
    journal.ensure_scope(SCOPE).await.unwrap();
    let id = FencedTransitionRequestId::from_bytes([4; 16]);
    let request = request();
    journal.insert(SCOPE, id, &request).await.unwrap();
    drop(journal);
    let journal = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).unwrap();
    let (recovered, notice) = journal
        .lookup_with_notice(SCOPE, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered, request);
    // Reclamation finishes before the caller can construct its recovered
    // handle from the lookup result, including while a legacy lookup awaits.
    journal.record_terminal(
        id,
        request.request_id(),
        &crate::FencedTransitionV2Status::Recorded(Box::new(Err(
            StoreError::FencedTransitionVoided,
        ))),
    );
    journal.remove_if_exact(SCOPE, id, &request).await.unwrap();
    assert!(notice.unwrap().was_voided());
    assert!(journal.lookup(SCOPE, id).await.unwrap().is_none());
}

#[test]
fn owned_journal_void_excludes_another_process_and_recovers_after_crash() {
    let directory = directory();
    let path = directory.path().join("owned.sqlite3");
    let journal = FencedTransitionV2RecoveryJournal::create_new_owned(&path, key()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", CHILD])
        .env("OPC_VOID_JOURNAL_TEST_PATH", &path)
        .stdout(Stdio::null());
    let denied = command
        .env("OPC_VOID_JOURNAL_TEST_EXPECT_DENIED", "1")
        .test_output()
        .unwrap();
    assert!(
        denied.status.success(),
        "owned journal exclusion child; stdout={} stderr={}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr),
    );
    drop(journal);
    let ready = directory.path().join("ready");
    let mut child = command
        .env_remove("OPC_VOID_JOURNAL_TEST_EXPECT_DENIED")
        .env("OPC_VOID_JOURNAL_TEST_READY", &ready)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .test_spawn(|_| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !ready.exists() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !ready.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned journal child did not signal readiness",
                ));
            }
            Ok(())
        })
        .unwrap();
    let was_ready = ready.exists();
    let denied = FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).is_err();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(was_ready);
    assert!(denied);
    assert!(FencedTransitionV2RecoveryJournal::open_existing_owned(&path, key()).is_ok());
}
