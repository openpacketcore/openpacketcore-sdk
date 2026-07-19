use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::Arc;

use async_trait::async_trait;

use super::*;
use crate::qualification::{QualificationNodeCommand, QualificationNodeReply};
use crate::qualification_kubernetes_campaign::{
    QualificationKubernetesPortError, QualificationKubernetesReadinessCondition,
};
use crate::qualification_kubernetes_concurrent_v5::tests::{
    active_cancelled_artifact_result, cancelled_artifact_outcome, passing_outcome_for_artifact_test,
};

struct NeverInvokedPort;

#[async_trait]
impl QualificationKubernetesCampaignPort for NeverInvokedPort {
    async fn invoke_command(
        &self,
        _namespace: &str,
        _pod_name: &str,
        _command: &QualificationNodeCommand,
        _cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<QualificationNodeReply, QualificationKubernetesPortError> {
        unreachable!("artifact preflight must run before a Kubernetes command")
    }

    async fn publish_readiness(
        &self,
        _namespace: &str,
        _pod_name: &str,
        _condition: &QualificationKubernetesReadinessCondition,
        _cancellation: &QualificationKubernetesCampaignCancellation,
    ) -> Result<(), QualificationKubernetesPortError> {
        unreachable!("artifact preflight must run before a Kubernetes status update")
    }
}

struct NeverInvokedClock;

#[async_trait]
impl QualificationKubernetesCampaignClock for NeverInvokedClock {
    fn elapsed_ns(&self) -> u64 {
        unreachable!("artifact preflight must run before the campaign clock")
    }

    async fn sleep(&self, _duration: Duration) {
        unreachable!("artifact preflight must run before the campaign clock")
    }
}

fn artifact_config(
    root: &Path,
    interpreter: PathBuf,
) -> QualificationKubernetesConcurrentV5ArtifactConfig {
    QualificationKubernetesConcurrentV5ArtifactConfig {
        output_directory: root.join("candidate-v5"),
        checker_interpreter: interpreter,
        expected_checker_sha256: embedded_v5_checker_sha256(),
        expected_workload_verifier_sha256: embedded_v5_workload_verifier_sha256(),
        candidate: QualificationKubernetesConcurrentV5CandidateBinding {
            asserted_source_revision: "a".repeat(40),
            asserted_source_tree_status: QualificationCandidateSourceTreeStatus::DirtyUnqualified,
            asserted_artifact_name: "opc-session-quorum-node".to_owned(),
            asserted_artifact_version: "0.2.0-test".to_owned(),
            asserted_artifact_sha256: QualificationSha256::digest(b"candidate artifact"),
        },
    }
}

fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("opc-session-v5-artifact-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("private artifact root")
}

fn system_python() -> PathBuf {
    fs::canonicalize("/usr/bin/python3").expect("canonical system Python")
}

fn write_interpreter(path: &Path, body: &str) {
    fs::write(path, body).expect("write fake interpreter");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make fake interpreter executable");
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn assert_no_staging(root: &Path) {
    let staging = fs::read_dir(root)
        .expect("read artifact root")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(".opc-session-v5-staging-"))
        .collect::<Vec<_>>();
    assert!(
        staging.is_empty(),
        "staging directories leaked: {staging:?}"
    );
}

fn staging_path(root: &Path) -> PathBuf {
    let paths = fs::read_dir(root)
        .expect("read artifact root")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".opc-session-v5-staging-"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "expected exactly one staging directory");
    paths.into_iter().next().expect("one staging path")
}

async fn wait_for_file(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fake interpreter did not reach checker invocation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn assert_process_gone(pid_file: &Path) {
    wait_for_file(pid_file).await;
    let raw = fs::read_to_string(pid_file).expect("read descendant PID");
    let raw_pid = raw.trim().parse::<i32>().expect("parse descendant PID");
    let pid = Pid::from_raw(raw_pid).expect("positive descendant PID");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match rustix::process::test_kill_process(pid) {
            Err(rustix::io::Errno::SRCH) => return,
            Ok(()) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            result => panic!("descendant process survived private-group cleanup: {result:?}"),
        }
    }
}

#[tokio::test]
async fn conclusive_campaign_publishes_private_digest_bound_bundle_once() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let config = artifact_config(&root_path, system_python());
    let outcome = passing_outcome_for_artifact_test(3).await;
    let cancellation = QualificationKubernetesCampaignCancellation::new();
    assert_eq!(
        embedded_v5_checker_sha256().as_str(),
        "sha256:e0061e53e9686624cffa1c2c970e6d1c35b69f66f1ab2dc4149968e34428282a"
    );

    let summary =
        publish_qualification_kubernetes_concurrent_v5_artifacts(&config, &outcome, &cancellation)
            .await
            .expect("publish conclusive candidate bundle");
    assert!(summary.experimental);
    assert!(!summary.qualification_complete);
    assert!(!summary.counts_for_production);
    assert_eq!(
        summary.schema_version,
        "opc-session-kubernetes-concurrent-v5-artifacts/v2"
    );
    assert!(summary.cleanup_complete);
    assert_eq!(summary.checker_status, "pass");
    assert_eq!(summary.workload_verifier_status, "pass");
    assert_eq!(
        summary.history_operations,
        summary.history_operations_checked
    );
    assert_eq!(
        summary.operation_counts.total(),
        Some(summary.history_operations)
    );
    assert_eq!(
        summary.workload_verifier.sha256,
        embedded_v5_workload_verifier_sha256()
    );
    assert_eq!(
        summary.profile.sha256,
        QualificationSha256::digest(SESSION_HA_CANDIDATE_PROFILE_V5_JSON.as_bytes())
    );

    let destination = &config.output_directory;
    assert_eq!(
        fs::metadata(destination).expect("bundle metadata").mode() & 0o777,
        0o700
    );
    for name in [
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_HISTORY_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_FAULT_SCHEDULE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE,
        QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE,
    ] {
        assert_eq!(
            fs::metadata(destination.join(name))
                .expect("published file metadata")
                .mode()
                & 0o777,
            0o600,
            "{name} is not private"
        );
    }
    assert_eq!(
        fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_PROFILE_FILE))
            .expect("retained profile"),
        SESSION_HA_CANDIDATE_PROFILE_V5_JSON.as_bytes()
    );
    assert_eq!(
        fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_FILE))
            .expect("retained checker"),
        EMBEDDED_CHECKER
    );
    assert_eq!(
        fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE))
            .expect("retained workload verifier"),
        EMBEDDED_WORKLOAD_VERIFIER
    );
    let evidence: serde_json::Value = serde_json::from_slice(
        &fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE))
            .expect("retained evidence"),
    )
    .expect("closed evidence JSON");
    assert_eq!(evidence["experimental"], true);
    assert_eq!(evidence["qualification_complete"], false);
    assert_eq!(evidence["counts_for_production"], false);
    assert_eq!(
        evidence["checker"]["sha256"],
        embedded_v5_checker_sha256().as_str()
    );
    let checker_output: CheckerOutput = serde_json::from_slice(
        &fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_CHECKER_OUTPUT_FILE))
            .expect("retained checker output"),
    )
    .expect("closed checker output");
    assert!(checker_output.status == VerificationStatus::Pass);
    let workload_verifier_output_bytes = fs::read(
        destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_OUTPUT_FILE),
    )
    .expect("retained workload verifier output");
    let workload_verifier_output: WorkloadVerifierOutput =
        serde_json::from_slice(&workload_verifier_output_bytes)
            .expect("closed workload verifier output");
    assert!(workload_verifier_output.status == VerificationStatus::Pass);
    assert_eq!(
        summary.workload_verifier_output.sha256,
        QualificationSha256::digest(&workload_verifier_output_bytes)
    );
    assert_no_staging(&root_path);

    let original_summary =
        fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE))
            .expect("original summary");
    assert_eq!(
        publish_qualification_kubernetes_concurrent_v5_artifacts(&config, &outcome, &cancellation,)
            .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::DestinationExists)
    );
    assert_eq!(
        fs::read(destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_SUMMARY_FILE))
            .expect("unchanged summary"),
        original_summary
    );

    let workload_path =
        destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_SCHEDULE_FILE);
    let original_workload: serde_json::Value =
        serde_json::from_slice(&fs::read(&workload_path).expect("retained workload schedule"))
            .expect("workload JSON");
    let evidence_path = destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_EVIDENCE_FILE);
    let original_evidence: serde_json::Value =
        serde_json::from_slice(&fs::read(&evidence_path).expect("retained evidence"))
            .expect("evidence JSON");
    let checker = destination.join(QUALIFICATION_KUBERNETES_CONCURRENT_V5_WORKLOAD_VERIFIER_FILE);

    let mut type_confused_workload = original_workload.clone();
    type_confused_workload["initial_state_empty"] = serde_json::json!(1);
    let mut type_confused_bytes =
        serde_json::to_vec_pretty(&type_confused_workload).expect("encode type-confused workload");
    type_confused_bytes.push(b'\n');
    fs::write(&workload_path, &type_confused_bytes).expect("replace workload with integer boolean");
    let mut type_confused_evidence = original_evidence.clone();
    type_confused_evidence["workload"]["schedule_sha256"] =
        serde_json::json!(QualificationSha256::digest(&type_confused_bytes).as_str());
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&type_confused_evidence)
            .expect("encode type-confused evidence binding"),
    )
    .expect("replace evidence binding for type-confusion test");
    let output = std::process::Command::new(system_python())
        .args(["-I", "-B", "-S"])
        .arg(&checker)
        .arg("--evidence")
        .arg(&evidence_path)
        .arg("--workload-schedule")
        .arg(&workload_path)
        .output()
        .expect("run workload verifier against a type-confused workload");
    assert_eq!(output.status.code(), Some(3));

    let mut workload = original_workload;
    workload["operations"] = serde_json::json!(["cleanup"]);
    let mut workload_bytes = serde_json::to_vec_pretty(&workload).expect("encode workload");
    workload_bytes.push(b'\n');
    fs::write(&workload_path, &workload_bytes).expect("replace workload for negative test");
    let mut evidence = original_evidence;
    evidence["workload"]["schedule_sha256"] =
        serde_json::json!(QualificationSha256::digest(&workload_bytes).as_str());
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&evidence).expect("encode mutated evidence"),
    )
    .expect("replace evidence for negative test");
    let output = std::process::Command::new(system_python())
        .args(["-I", "-B", "-S"])
        .arg(checker)
        .arg("--evidence")
        .arg(evidence_path)
        .arg("--workload-schedule")
        .arg(workload_path)
        .output()
        .expect("run workload verifier against contradictory workload");
    assert_eq!(output.status.code(), Some(3));
}

#[tokio::test]
async fn descriptor_pinned_proc_path_survives_interpreter_path_replacement() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let interpreter = root_path.join("python-wrapper");
    let original =
        "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\nexec /usr/bin/python3 \"$@\"\n";
    write_interpreter(&interpreter, original);
    let config = artifact_config(&root_path, interpreter.clone());
    let cancellation = QualificationKubernetesCampaignCancellation::new();
    let prepared = prepare_publication(&config, &cancellation)
        .await
        .expect("descriptor-pinned procfs preflight");
    assert!(descriptor_proc_path(&prepared.interpreter.descriptor)
        .starts_with(format!("/proc/{}/fd", std::process::id())));
    fs::rename(&interpreter, root_path.join("original-python-wrapper"))
        .expect("move configured interpreter path");
    write_interpreter(&interpreter, "#!/bin/sh\nexit 99\n");
    let outcome = passing_outcome_for_artifact_test(3).await;
    let summary = publish_prepared(&config, &outcome, prepared, &cancellation)
        .await
        .expect("pinned interpreter remains executable through procfs");
    assert_eq!(
        summary.checker_interpreter.sha256,
        QualificationSha256::digest(original.as_bytes())
    );
}

#[tokio::test]
async fn destination_is_invisible_until_the_complete_bundle_is_committed() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let marker = root_path.join("checker-started");
    let interpreter = root_path.join("python-wrapper");
    write_interpreter(
        &interpreter,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\n: > {}\nsleep 1\nexec /usr/bin/python3 \"$@\"\n",
            shell_quote(&marker)
        ),
    );
    let config = Arc::new(artifact_config(&root_path, interpreter));
    let outcome = Arc::new(passing_outcome_for_artifact_test(3).await);
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let task = {
        let config = Arc::clone(&config);
        let outcome = Arc::clone(&outcome);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                config.as_ref(),
                outcome.as_ref(),
                cancellation.as_ref(),
            )
            .await
        })
    };
    wait_for_file(&marker).await;
    assert!(!config.output_directory.exists());

    task.await
        .expect("publisher task")
        .expect("atomic publication succeeds");
    assert!(config.output_directory.is_dir());
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn a_racing_destination_is_never_replaced() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let marker = root_path.join("checker-started");
    let interpreter = root_path.join("python-wrapper");
    write_interpreter(
        &interpreter,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\n: > {}\nsleep 1\nexec /usr/bin/python3 \"$@\"\n",
            shell_quote(&marker)
        ),
    );
    let config = Arc::new(artifact_config(&root_path, interpreter));
    let outcome = Arc::new(passing_outcome_for_artifact_test(3).await);
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let task = {
        let config = Arc::clone(&config);
        let outcome = Arc::clone(&outcome);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                config.as_ref(),
                outcome.as_ref(),
                cancellation.as_ref(),
            )
            .await
        })
    };
    wait_for_file(&marker).await;
    fs::create_dir(&config.output_directory).expect("create racing destination");
    fs::write(config.output_directory.join("sentinel"), b"do not replace")
        .expect("write racing sentinel");
    assert_eq!(
        task.await.expect("publisher task"),
        Err(QualificationKubernetesConcurrentV5ArtifactError::DestinationExists)
    );
    assert_eq!(
        fs::read(config.output_directory.join("sentinel")).expect("racing sentinel"),
        b"do not replace"
    );
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn cancellation_during_checker_withholds_and_cleans_the_bundle() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let marker = root_path.join("checker-started");
    let interpreter = root_path.join("python-wrapper");
    write_interpreter(
        &interpreter,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\n: > {}\nexec sleep 20\n",
            shell_quote(&marker)
        ),
    );
    let config = Arc::new(artifact_config(&root_path, interpreter));
    let outcome = Arc::new(passing_outcome_for_artifact_test(3).await);
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let task = {
        let config = Arc::clone(&config);
        let outcome = Arc::clone(&outcome);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                config.as_ref(),
                outcome.as_ref(),
                cancellation.as_ref(),
            )
            .await
        })
    };
    wait_for_file(&marker).await;
    cancellation.cancel();
    assert_eq!(
        task.await.expect("publisher task"),
        Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled)
    );
    assert!(!config.output_directory.exists());
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn oversized_or_nonpassing_workload_verifier_output_never_publishes() {
    for (name, checker_body, expected) in [
        (
            "oversized",
            "/usr/bin/python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 70000)'\n",
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierOutputTooLarge,
        ),
        (
            "nonpass",
            "printf '%s\\n' '{\"verifier\":\"check-session-ha-kubernetes-concurrent-v5-workload-v1.py\",\"verifier_version\":\"1\",\"status\":\"fail\",\"violation_codes\":[\"synthetic\"]}'\nexit 1\n",
            QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierRejected,
        ),
    ] {
        let root = trusted_tempdir();
        let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
        let interpreter = root_path.join(name);
        write_interpreter(
            &interpreter,
            &format!(
                "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\n{checker_body}"
            ),
        );
        let config = artifact_config(&root_path, interpreter);
        let outcome = passing_outcome_for_artifact_test(3).await;
        assert_eq!(
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                &config,
                &outcome,
                &QualificationKubernetesCampaignCancellation::new(),
            )
            .await,
            Err(expected)
        );
        assert!(!config.output_directory.exists());
        assert_no_staging(&root_path);
    }
}

#[tokio::test]
async fn digest_mismatch_and_process_timeout_fail_closed() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let mut config = artifact_config(&root_path, system_python());
    config.expected_checker_sha256 = QualificationSha256::digest(b"different checker");
    assert_eq!(
        preflight_qualification_kubernetes_concurrent_v5_artifacts(
            &config,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch)
    );
    assert!(!config.output_directory.exists());

    config.expected_checker_sha256 = embedded_v5_checker_sha256();
    config.expected_workload_verifier_sha256 =
        QualificationSha256::digest(b"different workload verifier");
    assert_eq!(
        preflight_qualification_kubernetes_concurrent_v5_artifacts(
            &config,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch)
    );
    assert!(!config.output_directory.exists());

    let interpreter = root_path.join("slow-process");
    write_interpreter(&interpreter, "#!/bin/sh\nexec sleep 20\n");
    assert!(matches!(
        run_bounded_process(
            &interpreter,
            &[],
            Duration::from_millis(50),
            16,
            16,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(BoundedProcessError::Timeout)
    ));
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn bounded_process_timeout_kills_group_before_reaping_leader() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let descendant_pid = root_path.join("descendant-pid");
    let executable = root_path.join("forking-process");
    write_interpreter(
        &executable,
        &format!(
            "#!/bin/sh\nsleep 20 &\necho $! > {}\nwait\n",
            shell_quote(&descendant_pid)
        ),
    );
    let output = run_bounded_process(
        &executable,
        &[],
        Duration::from_secs(1),
        32,
        32,
        &QualificationKubernetesCampaignCancellation::new(),
    )
    .await;
    assert!(matches!(output, Err(BoundedProcessError::Timeout)));
    assert_process_gone(&descendant_pid).await;
}

#[tokio::test]
async fn aborting_publication_future_cleans_staging_and_checker_group() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let marker = root_path.join("checker-started");
    let checker_pid = root_path.join("checker-pid");
    let descendant_pid = root_path.join("checker-descendant-pid");
    let interpreter = root_path.join("forking-python-wrapper");
    write_interpreter(
        &interpreter,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\necho $$ > {}\nsleep 20 >/dev/null 2>&1 &\necho $! > {}\n: > {}\nwait\n",
            shell_quote(&checker_pid),
            shell_quote(&descendant_pid),
            shell_quote(&marker),
        ),
    );
    let config = Arc::new(artifact_config(&root_path, interpreter));
    let outcome = Arc::new(passing_outcome_for_artifact_test(3).await);
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let task = {
        let config = Arc::clone(&config);
        let outcome = Arc::clone(&outcome);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                config.as_ref(),
                outcome.as_ref(),
                cancellation.as_ref(),
            )
            .await
        })
    };
    wait_for_file(&marker).await;
    task.abort();
    assert!(task
        .await
        .expect_err("publisher task is aborted")
        .is_cancelled());
    assert!(!config.output_directory.exists());
    assert_no_staging(&root_path);
    assert_process_gone(&checker_pid).await;
    assert_process_gone(&descendant_pid).await;
}

#[tokio::test]
async fn unexpected_staging_entry_reports_cleanup_outcome_unknown() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let marker = root_path.join("checker-started");
    let interpreter = root_path.join("slow-python-wrapper");
    write_interpreter(
        &interpreter,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *\" --version \"*) echo 'Python 3.13-test'; exit 0;; esac\n: > {}\nexec sleep 20\n",
            shell_quote(&marker)
        ),
    );
    let config = Arc::new(artifact_config(&root_path, interpreter));
    let outcome = Arc::new(passing_outcome_for_artifact_test(3).await);
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let task = {
        let config = Arc::clone(&config);
        let outcome = Arc::clone(&outcome);
        let cancellation = Arc::clone(&cancellation);
        tokio::spawn(async move {
            publish_qualification_kubernetes_concurrent_v5_artifacts(
                config.as_ref(),
                outcome.as_ref(),
                cancellation.as_ref(),
            )
            .await
        })
    };
    wait_for_file(&marker).await;
    let staging = staging_path(&root_path);
    fs::write(staging.join("unexpected-entry"), b"quarantine").expect("inject unknown entry");
    cancellation.cancel();
    assert_eq!(
        task.await.expect("publisher task"),
        Err(QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown)
    );
    assert!(!config.output_directory.exists());
    fs::remove_file(staging.join("unexpected-entry")).expect("audited test cleanup file");
    fs::remove_dir(staging).expect("audited test cleanup directory");
}

#[tokio::test]
async fn untrusted_parent_or_interpreter_is_rejected_before_staging() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let config = artifact_config(&root_path, system_python());
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o770))
        .expect("make parent group-writable");
    assert_eq!(
        preflight_qualification_kubernetes_concurrent_v5_artifacts(
            &config,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination)
    );
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700))
        .expect("restore private parent");

    let interpreter = root_path.join("writable-python");
    write_interpreter(&interpreter, "#!/bin/sh\necho 'Python 3.13-test'\n");
    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o722))
        .expect("make interpreter writable by others");
    let config = artifact_config(&root_path, interpreter);
    assert_eq!(
        preflight_qualification_kubernetes_concurrent_v5_artifacts(
            &config,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable)
    );
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn preflight_precedes_kubernetes_and_inconclusive_outcomes_never_publish() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let mut config = artifact_config(&root_path, system_python());
    config.expected_checker_sha256 = QualificationSha256::digest(b"wrong checker");
    let campaign = QualificationKubernetesConcurrentV5Config {
        namespace: "qualification".to_owned(),
        member_count: 3,
        history_id: "preflight-before-kubernetes".to_owned(),
    };
    assert_eq!(
        run_and_publish_qualification_kubernetes_concurrent_v5_campaign(
            &campaign,
            &config,
            &NeverInvokedPort,
            &NeverInvokedClock,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch)
    );

    config.expected_checker_sha256 = embedded_v5_checker_sha256();
    let outcome = cancelled_artifact_outcome().await;
    assert_eq!(
        publish_qualification_kubernetes_concurrent_v5_artifacts(
            &config,
            &outcome,
            &QualificationKubernetesCampaignCancellation::new(),
        )
        .await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::CampaignInconclusive)
    );
    assert!(!config.output_directory.exists());
    assert_no_staging(&root_path);
}

#[tokio::test]
async fn active_campaign_cancellation_is_typed_after_complete_cleanup() {
    let root = trusted_tempdir();
    let root_path = fs::canonicalize(root.path()).expect("canonical artifact root");
    let config = artifact_config(&root_path, system_python());

    assert_eq!(
        active_cancelled_artifact_result(&config).await,
        Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled)
    );
    assert!(!config.output_directory.exists());
    assert_no_staging(&root_path);
}

#[test]
fn post_rename_sync_failure_is_explicitly_outcome_unknown() {
    assert_eq!(
        map_post_rename_sync(Err(rustix::io::Errno::IO)),
        Err(QualificationKubernetesConcurrentV5ArtifactError::PublicationOutcomeUnknown)
    );
}
