use opc_alarm::{ProbableCause, Severity};
use opc_config_model::{CommitErrorCode, CommitStatus};
use opc_runtime::task::TaskError;
use opc_runtime::{Criticality, Readiness, RestartPolicy, RuntimePhase, TaskKind, TaskName};
use opc_sdk_integration::{
    ToyConfig, ToyNetworkFunction, ALARMS_ARTIFACT, HEALTH_ARTIFACT, SCENARIO_STATE_ARTIFACT,
};
use serde_json::Value;
use std::time::Duration;

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_runtime_commit_alarm_and_scenario_evidence_integrate() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    let commit = toy
        .commit_config(ToyConfig::new("toy-runtime", "nrf://ready"))
        .await
        .expect("config commit succeeds");
    assert_eq!(commit.status, CommitStatus::Committed);

    let new_version = commit.new_version.expect("new config version assigned");
    let observed = toy
        .wait_for_config_version(new_version, Duration::from_secs(1))
        .await
        .expect("watcher observes committed config");
    assert_eq!(observed.version, new_version.get());
    assert_eq!(observed.hostname, "toy-runtime");
    assert_eq!(observed.peer_endpoint, "nrf://ready");

    let health = toy.health().await.expect("health snapshot available");
    assert_eq!(health.response.status, "ok");
    let details = health
        .response
        .details
        .as_ref()
        .expect("ready health includes details");
    assert_eq!(details.readiness, "Ready");
    assert_eq!(health.config.version, new_version.get());
    assert_eq!(health.active_alarm_count, 0);

    let alarm = toy.raise_redacted_alarm().expect("alarm raise succeeds");
    assert_eq!(alarm.probable_cause, ProbableCause::PeerUnreachable);
    assert_eq!(
        alarm.text.as_str(),
        "Toy NF registration path for subscriber [redacted] timed out"
    );

    let health_after_alarm = toy.health().await.expect("health snapshot after alarm");
    assert_eq!(health_after_alarm.active_alarm_count, 1);
    assert_eq!(health_after_alarm.response.status, "degraded");
    let details_after_alarm = health_after_alarm
        .response
        .details
        .as_ref()
        .expect("post-alarm health includes details");
    assert_eq!(details_after_alarm.readiness, "Degraded");

    let run = toy
        .run_scenario(include_str!("fixtures/toy-scenario.yaml"))
        .await
        .expect("scenario run succeeds");

    let actual: Value =
        serde_json::from_str(&run.evidence_json).expect("generated evidence json parses");
    let expected: Value = serde_json::from_str(include_str!("fixtures/toy-evidence.json"))
        .expect("fixture json parses");
    assert_eq!(actual["scenario_id"], expected["scenario_id"]);
    assert_eq!(actual["requirements"], expected["requirements"]);
    assert_eq!(actual["mode"], expected["mode"]);
    assert_eq!(actual["seed"], expected["seed"]);
    assert_eq!(actual["artifacts"], expected["artifacts"]);
    assert_eq!(actual["outcome"], expected["outcome"]);
    assert_eq!(actual["started_at"], expected["started_at"]);
    assert_eq!(actual["finished_at"], expected["finished_at"]);

    let records = run
        .evidence
        .to_evidence_records()
        .expect("scenario evidence converts to RFC 006 records");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].test_refs[0],
        "crates/opc-testbed/scenario/TOY-NF-001:run"
    );

    assert!(run.artifacts.contains_key(HEALTH_ARTIFACT));
    assert!(run.artifacts.contains_key(ALARMS_ARTIFACT));
    assert!(run.artifacts.contains_key(SCENARIO_STATE_ARTIFACT));
    assert_eq!(
        run.artifacts
            .get(SCENARIO_STATE_ARTIFACT)
            .expect("scenario-state artifact exists"),
        "{\n  \"toy-nf.last_ngap\": \"registration\",\n  \"toy-nf.state\": \"REGISTERED\"\n}"
    );

    toy.shutdown().await;
    assert_eq!(toy.phase().await, RuntimePhase::Stopped);
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_config_commit_alarm_uses_runtime_shared_manager() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    let err = toy
        .commit_config(ToyConfig::new("", "nrf://ready"))
        .await
        .expect_err("invalid config should fail validation");
    match err {
        opc_sdk_integration::ToyIntegrationError::Commit(err) => {
            assert_eq!(err.code, CommitErrorCode::SyntaxValidationFailed);
        }
        other => panic!("expected commit error, got {other:?}"),
    }

    let history = toy.alarm_history();
    assert_eq!(history.len(), 1);
    let alarm = &history[0];
    assert_eq!(alarm.alarm_type.as_str(), "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Warning);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    let details = alarm
        .details
        .as_value()
        .expect("config-bus alarm details are structured");
    assert_eq!(details["component"], "config-bus");
    assert_eq!(details["error_code"], "syntax_validation_failed");

    let health_after_failure = toy.health().await.expect("health after commit failure");
    assert_eq!(health_after_failure.active_alarm_count, 1);
    assert_eq!(health_after_failure.response.status, "ok");

    toy.commit_config(ToyConfig::new("toy-runtime", "nrf://ready"))
        .await
        .expect("valid config retry should clear config-bus alarm");
    let health_after_recovery = toy.health().await.expect("health after retry");
    assert_eq!(health_after_recovery.active_alarm_count, 0);
    assert_eq!(health_after_recovery.response.status, "ok");

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_health_returns_to_ready_after_alarm_cleared() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    let health_before = toy.health().await.expect("health before alarm");
    assert_eq!(health_before.active_alarm_count, 0);
    assert_eq!(health_before.response.status, "ok");

    let _alarm = toy.raise_redacted_alarm().expect("alarm raise succeeds");
    let health_during = toy.health().await.expect("health during alarm");
    assert_eq!(health_during.active_alarm_count, 1);
    assert_eq!(health_during.response.status, "degraded");
    assert_eq!(
        health_during
            .response
            .details
            .as_ref()
            .expect("details present")
            .readiness,
        "Degraded"
    );

    toy.clear_redacted_alarm().expect("alarm clear succeeds");
    let health_after = toy.health().await.expect("health after alarm cleared");
    assert_eq!(health_after.active_alarm_count, 0);
    assert_eq!(health_after.response.status, "ok");
    assert_eq!(
        health_after
            .response
            .details
            .as_ref()
            .expect("details present")
            .readiness,
        "Ready"
    );

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_health_reports_degraded_when_runtime_task_fails() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    let health_before = toy.health().await.expect("health before task failure");
    assert_eq!(health_before.response.status, "ok");
    assert_eq!(health_before.runtime_readiness, "Ready");

    let supervisor = toy.supervisor();
    let task_name = TaskName::new("degrade-fail-test");
    supervisor
        .register(
            task_name.clone(),
            TaskKind::Listener,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
        )
        .await
        .expect("register task");

    supervisor
        .spawn(
            task_name.clone(),
            TaskKind::Listener,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    Err(TaskError::Failed(
                        "injected test task failure".to_string(),
                        std::sync::Arc::new(std::io::Error::other("test")),
                    ))
                })
            },
        )
        .await
        .expect("spawn task");

    // Yield to allow the supervisor to process the task failure.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let readiness = toy.readiness().await;

    assert_eq!(
        readiness,
        Readiness::Degraded,
        "runtime readiness must be Degraded after degrade-criticality task fails"
    );

    let health_after = toy.health().await.expect("health after task failure");
    assert_eq!(
        health_after.response.status, "degraded",
        "health probe must report degraded when runtime readiness is Degraded"
    );
    assert_eq!(health_after.runtime_readiness, "Degraded");
    // The local health model remains Ready because no alarm was raised; the
    // degraded status comes from the aggregate readiness which includes the
    // runtime supervisor state.
    assert_eq!(
        health_after
            .response
            .details
            .as_ref()
            .expect("details present")
            .readiness,
        "Ready"
    );

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_rejects_unobservable_expectation_steps() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    for (kind, field) in [
        ("expect_sbi", "operation: nrf-register"),
        (
            "expect_ngap",
            "message: InitialUEMessage.registration_request",
        ),
    ] {
        let scenario = format!(
            r#"schema_version: "0.1.0"
id: TOY-NF-{kind}
title: unsupported expectation
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    toy-nf:
      simulator: "fake"
steps:
  - kind: {kind}
    from: ran-1
    to: toy-nf
    {field}
"#
        );

        let err = toy
            .run_scenario(&scenario)
            .await
            .expect_err("unobservable expectation must fail");

        assert!(err.to_string().contains(kind));
        assert!(err.to_string().contains("toy-nf"));
    }

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_maps_realistic_ngap_message_names_to_fake_simulator_steps() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    for (scenario_id, message, expected_state) in [
        (
            "TOY-NF-NGAP-REG-001",
            "InitialUEMessage.registration_request",
            "REGISTERED",
        ),
        (
            "TOY-NF-NGAP-SESSION-001",
            "PDUSessionResourceSetup.session_establishment",
            "SESSION_ACTIVE",
        ),
    ] {
        let run = toy
            .run_scenario(&format!(
                r#"schema_version: "0.1.0"
id: {scenario_id}
title: realistic ngap message name
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    toy-nf:
      simulator: "fake"
steps:
  - kind: send_ngap
    from: ran-1
    to: toy-nf
    message: {message}
assertions:
  - expr: "toy-nf.state == {expected_state}"
"#
            ))
            .await
            .expect("scenario with realistic ngap message succeeds");

        assert_eq!(
            run.artifacts
                .get(SCENARIO_STATE_ARTIFACT)
                .expect("scenario-state artifact exists"),
            &format!(
                "{{\n  \"toy-nf.last_ngap\": \"{message}\",\n  \"toy-nf.state\": \"{expected_state}\"\n}}"
            )
        );
    }

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn toy_nf_rejects_unsupported_ngap_control_plane_outcomes() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    for message in [
        "DownlinkNASTransport.registration_reject",
        "PDUSessionReleaseCommand.session_teardown",
    ] {
        let err = toy
            .run_scenario(&format!(
                r#"schema_version: "0.1.0"
id: TOY-NF-NGAP-UNSUPPORTED
title: unsupported ngap message
requirements:
  - REQ-3GPP-TS23502-R17-4.2.2-001
topology:
  nfs:
    toy-nf:
      simulator: "fake"
steps:
  - kind: send_ngap
    from: ran-1
    to: toy-nf
    message: {message}
"#
            ))
            .await
            .expect_err("unsupported ngap message must fail");

        assert!(err.to_string().contains("does not support NGAP message"));
        assert!(err.to_string().contains(message));
    }

    toy.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_runtime_alarm_testkit_integration() {
    let toy = ToyNetworkFunction::start(ToyConfig::default())
        .await
        .expect("toy runtime starts");

    // 1. Raise a redacted alarm in the toy runtime
    let alarm = toy.raise_redacted_alarm().expect("raise succeeds");

    // 2. Fetch history
    let history = toy.alarm_history();

    // 3. Assert on the alarms using the testkit
    opc_alarm_testkit::AlarmAsserter::new(&history)
        .has_severity(Severity::Major)
        .has_cause(ProbableCause::PeerUnreachable)
        .has_tenant(alarm.tenant.as_deref());

    // Verify that the alarm is redacted
    opc_alarm_testkit::assert_redacted(&alarm);

    // 4. Eventually cleared:
    toy.clear_redacted_alarm().expect("clear succeeds");
    let fetch_history = || {
        let history = toy.alarm_history();
        std::future::ready(history)
    };
    opc_alarm_testkit::assert_eventually_cleared(
        fetch_history,
        alarm.alarm_id,
        Duration::from_millis(100),
    )
    .await;

    toy.shutdown().await;
}
