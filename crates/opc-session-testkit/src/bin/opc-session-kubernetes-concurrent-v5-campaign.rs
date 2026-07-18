//! Executable candidate-only deployed Kubernetes v5 HA campaign.

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use opc_session_testkit::qualification::{
    QualificationCandidateSourceTreeStatus, QualificationSha256,
};
use opc_session_testkit::qualification_kubernetes_campaign::{
    KubectlQualificationKubernetesCampaignPort, QualificationKubernetesCampaignCancellation,
    QualificationKubernetesSystemClock,
};
use opc_session_testkit::qualification_kubernetes_concurrent_v5::QualificationKubernetesConcurrentV5Config;
use opc_session_testkit::qualification_kubernetes_concurrent_v5_artifacts::{
    embedded_v5_checker_sha256, embedded_v5_workload_verifier_sha256,
    run_and_publish_qualification_kubernetes_concurrent_v5_campaign,
    QualificationKubernetesConcurrentV5ArtifactConfig,
    QualificationKubernetesConcurrentV5ArtifactError,
    QualificationKubernetesConcurrentV5CandidateBinding,
};

const USAGE: &str = "usage: opc-session-kubernetes-concurrent-v5-campaign --namespace <dns-label> --members <3|5> --history-id <unique-id> --output-directory <new-absolute-path> --checker-interpreter <absolute-python-path> --asserted-source-revision <40-lower-hex> --asserted-source-tree-status <clean|dirty_unqualified> --asserted-artifact-name <name> --asserted-artifact-version <version> --asserted-artifact-sha256 <sha256:lower-hex>";

struct Arguments {
    campaign: QualificationKubernetesConcurrentV5Config,
    artifact: QualificationKubernetesConcurrentV5ArtifactConfig,
}

#[tokio::main]
async fn main() {
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(()) => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
    let signal_task = match spawn_signal_task(Arc::clone(&cancellation)) {
        Ok(task) => task,
        Err(()) => {
            eprintln!("qualification Kubernetes v5 signal registration failed");
            std::process::exit(1);
        }
    };
    let result = run_and_publish_qualification_kubernetes_concurrent_v5_campaign(
        &arguments.campaign,
        &arguments.artifact,
        &KubectlQualificationKubernetesCampaignPort::new(),
        &QualificationKubernetesSystemClock::new(),
        cancellation.as_ref(),
    )
    .await;
    signal_task.abort();
    let _ = signal_task.await;

    match result {
        Ok(_) => {}
        Err(QualificationKubernetesConcurrentV5ArtifactError::Cancelled) => {
            eprintln!("qualification Kubernetes v5 campaign cancelled without publication");
            std::process::exit(130);
        }
        Err(QualificationKubernetesConcurrentV5ArtifactError::PublicationOutcomeUnknown) => {
            eprintln!(
                "qualification Kubernetes v5 publication outcome is unknown; quarantine it, never accept or overwrite it, and use an audited operator procedure"
            );
            std::process::exit(1);
        }
        Err(QualificationKubernetesConcurrentV5ArtifactError::StagingCleanupOutcomeUnknown) => {
            eprintln!(
                "qualification Kubernetes v5 staging cleanup outcome is unknown; quarantine the parent and use an audited operator procedure"
            );
            std::process::exit(1);
        }
        Err(
            QualificationKubernetesConcurrentV5ArtifactError::InvalidConfiguration
            | QualificationKubernetesConcurrentV5ArtifactError::InvalidDestination
            | QualificationKubernetesConcurrentV5ArtifactError::CampaignConfiguration
            | QualificationKubernetesConcurrentV5ArtifactError::CheckerDigestMismatch
            | QualificationKubernetesConcurrentV5ArtifactError::WorkloadVerifierDigestMismatch
            | QualificationKubernetesConcurrentV5ArtifactError::InterpreterUnavailable
            | QualificationKubernetesConcurrentV5ArtifactError::UnsupportedAtomicPublication,
        ) => {
            eprintln!("qualification Kubernetes v5 campaign configuration rejected");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!(
                "qualification Kubernetes v5 campaign failed closed without a passing publication"
            );
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
fn spawn_signal_task(
    cancellation: Arc<QualificationKubernetesCampaignCancellation>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| ())?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| ())?;
    Ok(tokio::spawn(async move {
        loop {
            let received = tokio::select! {
                signal = interrupt.recv() => signal,
                signal = terminate.recv() => signal,
            };
            if received.is_none() {
                break;
            }
            cancellation.cancel();
        }
    }))
}

#[cfg(not(unix))]
fn spawn_signal_task(
    cancellation: Arc<QualificationKubernetesCampaignCancellation>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    Ok(tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancellation.cancel();
        }
    }))
}

fn parse_arguments() -> Result<Arguments, ()> {
    parse_arguments_from(env::args_os().skip(1))
}

fn parse_arguments_from<I>(mut arguments: I) -> Result<Arguments, ()>
where
    I: Iterator<Item = OsString>,
{
    let mut namespace = None;
    let mut member_count = None;
    let mut history_id = None;
    let mut output_directory = None;
    let mut checker_interpreter = None;
    let mut asserted_source_revision = None;
    let mut source_tree_status = None;
    let mut asserted_artifact_name = None;
    let mut asserted_artifact_version = None;
    let mut asserted_artifact_sha256 = None;

    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(())?;
        let flag = flag.into_string().map_err(|_| ())?;
        match flag.as_str() {
            "--namespace" if namespace.is_none() => {
                namespace = Some(value.into_string().map_err(|_| ())?);
            }
            "--members" if member_count.is_none() => {
                member_count = Some(parse_usize(value)?);
            }
            "--history-id" if history_id.is_none() => {
                history_id = Some(value.into_string().map_err(|_| ())?);
            }
            "--output-directory" if output_directory.is_none() => {
                output_directory = Some(PathBuf::from(value));
            }
            "--checker-interpreter" if checker_interpreter.is_none() => {
                checker_interpreter = Some(PathBuf::from(value));
            }
            "--asserted-source-revision" if asserted_source_revision.is_none() => {
                asserted_source_revision = Some(value.into_string().map_err(|_| ())?);
            }
            "--asserted-source-tree-status" if source_tree_status.is_none() => {
                source_tree_status = Some(parse_source_tree_status(value)?);
            }
            "--asserted-artifact-name" if asserted_artifact_name.is_none() => {
                asserted_artifact_name = Some(value.into_string().map_err(|_| ())?);
            }
            "--asserted-artifact-version" if asserted_artifact_version.is_none() => {
                asserted_artifact_version = Some(value.into_string().map_err(|_| ())?);
            }
            "--asserted-artifact-sha256" if asserted_artifact_sha256.is_none() => {
                asserted_artifact_sha256 = Some(parse_digest(value)?);
            }
            _ => return Err(()),
        }
    }

    let campaign = QualificationKubernetesConcurrentV5Config {
        namespace: namespace.ok_or(())?,
        member_count: member_count.ok_or(())?,
        history_id: history_id.ok_or(())?,
    };
    campaign.validate().map_err(|_| ())?;
    let artifact = QualificationKubernetesConcurrentV5ArtifactConfig {
        output_directory: output_directory.ok_or(())?,
        checker_interpreter: checker_interpreter.ok_or(())?,
        expected_checker_sha256: embedded_v5_checker_sha256(),
        expected_workload_verifier_sha256: embedded_v5_workload_verifier_sha256(),
        candidate: QualificationKubernetesConcurrentV5CandidateBinding {
            asserted_source_revision: asserted_source_revision.ok_or(())?,
            asserted_source_tree_status: source_tree_status.ok_or(())?,
            asserted_artifact_name: asserted_artifact_name.ok_or(())?,
            asserted_artifact_version: asserted_artifact_version.ok_or(())?,
            asserted_artifact_sha256: asserted_artifact_sha256.ok_or(())?,
        },
    };
    artifact.validate().map_err(|_| ())?;
    Ok(Arguments { campaign, artifact })
}

fn parse_usize(value: OsString) -> Result<usize, ()> {
    value.into_string().map_err(|_| ())?.parse().map_err(|_| ())
}

fn parse_digest(value: OsString) -> Result<QualificationSha256, ()> {
    QualificationSha256::new(value.into_string().map_err(|_| ())?).map_err(|_| ())
}

fn parse_source_tree_status(value: OsString) -> Result<QualificationCandidateSourceTreeStatus, ()> {
    match value.into_string().map_err(|_| ())?.as_str() {
        "clean" => Ok(QualificationCandidateSourceTreeStatus::Clean),
        "dirty_unqualified" => Ok(QualificationCandidateSourceTreeStatus::DirtyUnqualified),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_arguments(output: &std::path::Path) -> Vec<OsString> {
        vec![
            "--namespace".into(),
            "qualification".into(),
            "--members".into(),
            "3".into(),
            "--history-id".into(),
            "candidate-attempt-1".into(),
            "--output-directory".into(),
            output.to_path_buf().into_os_string(),
            "--checker-interpreter".into(),
            "/usr/bin/python3".into(),
            "--asserted-source-revision".into(),
            "a".repeat(40).into(),
            "--asserted-source-tree-status".into(),
            "dirty_unqualified".into(),
            "--asserted-artifact-name".into(),
            "opc-session-quorum-node".into(),
            "--asserted-artifact-version".into(),
            "0.2.0-candidate".into(),
            "--asserted-artifact-sha256".into(),
            QualificationSha256::digest(b"artifact").as_str().into(),
        ]
    }

    #[test]
    fn parser_accepts_one_complete_closed_candidate_configuration() {
        let root = tempfile::tempdir().expect("argument root");
        let output = std::fs::canonicalize(root.path())
            .expect("canonical argument root")
            .join("candidate-attempt-1");
        let arguments = complete_arguments(&output);
        let parsed = parse_arguments_from(arguments.into_iter()).expect("complete arguments");
        assert_eq!(parsed.campaign.member_count, 3);
        assert_eq!(parsed.artifact.output_directory, output);
        assert_eq!(
            parsed.artifact.candidate.asserted_artifact_name,
            "opc-session-quorum-node"
        );
    }

    #[test]
    fn parser_rejects_missing_duplicate_and_ambiguous_values() {
        let root = tempfile::tempdir().expect("argument root");
        let output = std::fs::canonicalize(root.path())
            .expect("canonical argument root")
            .join("candidate-attempt-1");
        let complete = complete_arguments(&output);
        assert!(parse_arguments_from(complete[..complete.len() - 2].iter().cloned()).is_err());

        let mut duplicate = complete.clone();
        duplicate.extend([OsString::from("--members"), OsString::from("5")]);
        assert!(parse_arguments_from(duplicate.into_iter()).is_err());

        let mut legacy_claim = complete;
        legacy_claim.extend([
            OsString::from("--exact-release-artifact"),
            OsString::from("true"),
        ]);
        assert!(parse_arguments_from(legacy_claim.into_iter()).is_err());
    }

    #[test]
    fn usage_exposes_no_network_control_or_secret_input() {
        assert!(USAGE.contains("--output-directory"));
        assert!(USAGE.contains("--checker-interpreter"));
        for forbidden in ["token", "password", "private-key", "address", "port"] {
            assert!(!USAGE.contains(forbidden));
        }
    }
}
