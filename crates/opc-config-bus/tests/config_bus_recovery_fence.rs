#![allow(unused_imports)]
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{ConfigBus, DriftState};
use opc_config_model::{CommitErrorCode, RequestSource};
use opc_types::ConfigVersion;

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_submit_still_raises_worker_commit_alarm() {
    let store = Arc::new(BlockingAppendFailureStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "next",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };

    store.wait_until_append_started().await;
    submit.abort();
    assert!(submit
        .await
        .expect_err("submit task should be aborted")
        .is_cancelled());
    store.release();

    let alarm = wait_for_single_active_alarm(&alarms, "config-bus.commit.failure").await;
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "persist_failed");
    assert!(!serde_json::to_string(&alarms.all_alarms())
        .expect("alarm history serializes")
        .contains("secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_submit_worker_panic_still_raises_state_machine_alarm() {
    let store = Arc::new(BlockingAppendPanicStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "next",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };

    store.wait_until_append_started().await;
    submit.abort();
    assert!(submit
        .await
        .expect_err("submit task should be aborted")
        .is_cancelled());
    store.release();

    let alarm = wait_for_single_active_alarm(&alarms, "config-bus.commit.failure").await;
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "state_machine_fault");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_panic_raises_state_machine_fault_alarm_and_fences_recovery() {
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        PanicStore,
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let first = bus
        .submit(commit_request(
            "first",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("worker panic should surface as state machine fault");
    assert_eq!(first.code, CommitErrorCode::StateMachineFault);
    assert_eq!(first.message, "config commit worker panicked");
    let first_alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(first_alarm.severity, Severity::Major);
    assert_eq!(first_alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&first_alarm, "state_machine_fault");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);

    let second = bus
        .submit(commit_request(
            "second",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("fenced worker should reject later submissions");
    assert_eq!(second.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        second.message,
        "config commit worker panicked; recovery is required before the next write"
    );

    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "recovery_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_append_worker_panic_fences_recovery_until_restart() {
    let store = Arc::new(PostAppendPanicStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "persisted-before-panic",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("post-append panic should surface as state machine fault");

    assert_eq!(err.code, CommitErrorCode::StateMachineFault);
    assert_eq!(err.message, "config commit worker panicked");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert!(history[0].recovery_required);
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "state_machine_fault");

    let follow_up = bus
        .submit(commit_request(
            "must-fail-closed",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("recovery fence should reject later writes");

    assert_eq!(follow_up.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        follow_up.message,
        "config commit worker panicked; recovery is required before the next write"
    );
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_persist_deadline_fences_future_writes_before_publish() {
    let store = Arc::new(SlowAppendStore::new(Duration::from_millis(60)));
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "persisted-too-late",
            Instant::now() + Duration::from_millis(20),
        ))
        .await
        .expect_err("late durable append should fence the bus");

    assert_eq!(err.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert!(history[0].recovery_required);

    let restore_err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("late durable append should fail closed on restart"),
            Err(err) => err,
        };
    assert_eq!(restore_err.code, StoreErrorCode::RestoreRecoveryRequired);
    assert_eq!(
        restore_err.message,
        "stored running config requires recovery reconciliation"
    );

    let follow_up = bus
        .submit(commit_request(
            "should-be-rejected",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("fenced bus should reject later writes");

    assert_eq!(follow_up.code, CommitErrorCode::RecoveryRequired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_recovery_required_failures_fence_future_writes() {
    let bus = ConfigBus::new_dev_only(
        TestConfig::new("initial"),
        Arc::new(ErrorStore::clear_recovery_fails("backend update failed")),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("recovery-marker failure should fence the bus");

    assert_eq!(err.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        err.message,
        "commit was published but the recovery marker could not be cleared durably"
    );
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");

    let follow_up = bus
        .submit(commit_request(
            "later",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("fenced bus should reject later writes");

    assert_eq!(follow_up.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        follow_up.message,
        "commit was published but the recovery marker could not be cleared durably"
    );
}
