//! Bounded external Kubernetes sequential-HA campaign for the experimental
//! session-HA candidate profile.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opc_session_testkit::qualification_kubernetes_campaign::{
    persist_qualification_kubernetes_campaign, run_qualification_kubernetes_probe_campaign,
    validate_qualification_kubernetes_campaign_artifact_destination,
    KubectlQualificationKubernetesCampaignPort, QualificationKubernetesCampaignCancellation,
    QualificationKubernetesCampaignConfig, QualificationKubernetesCampaignStatus,
    QualificationKubernetesSystemClock,
};

const USAGE: &str = "usage: opc-session-kubernetes-campaign --namespace <dns-label> --members <3|5> --rounds <count> --interval-ms <250..60000> --history-id <id> --output-directory <new-absolute-path>";

struct Arguments {
    config: QualificationKubernetesCampaignConfig,
    output_directory: PathBuf,
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
            eprintln!("qualification Kubernetes campaign signal registration failed");
            std::process::exit(1);
        }
    };

    let outcome = run_qualification_kubernetes_probe_campaign(
        &arguments.config,
        &KubectlQualificationKubernetesCampaignPort::new(),
        &QualificationKubernetesSystemClock::new(),
        cancellation.as_ref(),
    )
    .await;
    signal_task.abort();
    let _ = signal_task.await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(_) => {
            eprintln!("qualification Kubernetes campaign configuration rejected");
            std::process::exit(2);
        }
    };

    if persist_qualification_kubernetes_campaign(
        &arguments.output_directory,
        &arguments.config,
        &outcome,
    )
    .is_err()
    {
        eprintln!("qualification Kubernetes campaign artifact publication failed");
        std::process::exit(1);
    }

    match outcome.status() {
        QualificationKubernetesCampaignStatus::Passed => {}
        QualificationKubernetesCampaignStatus::Failed => {
            eprintln!("qualification Kubernetes campaign failed closed");
            std::process::exit(1);
        }
        QualificationKubernetesCampaignStatus::Cancelled => {
            eprintln!("qualification Kubernetes campaign cancelled and readiness cleared");
            std::process::exit(130);
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
    I: Iterator<Item = std::ffi::OsString>,
{
    let mut namespace = None;
    let mut member_count = None;
    let mut rounds = None;
    let mut interval_millis = None;
    let mut history_id = None;
    let mut output_directory = None;
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
            "--rounds" if rounds.is_none() => {
                rounds = Some(parse_usize(value)?);
            }
            "--interval-ms" if interval_millis.is_none() => {
                interval_millis = Some(parse_u64(value)?);
            }
            "--history-id" if history_id.is_none() => {
                history_id = Some(value.into_string().map_err(|_| ())?);
            }
            "--output-directory" if output_directory.is_none() => {
                output_directory = Some(PathBuf::from(value));
            }
            _ => return Err(()),
        }
    }
    let config = QualificationKubernetesCampaignConfig {
        namespace: namespace.ok_or(())?,
        member_count: member_count.ok_or(())?,
        rounds: rounds.ok_or(())?,
        probe_interval: Duration::from_millis(interval_millis.ok_or(())?),
        history_id: history_id.ok_or(())?,
    };
    config.validate().map_err(|_| ())?;
    let output_directory = output_directory.ok_or(())?;
    validate_qualification_kubernetes_campaign_artifact_destination(&output_directory)
        .map_err(|_| ())?;
    Ok(Arguments {
        config,
        output_directory,
    })
}

fn parse_usize(value: std::ffi::OsString) -> Result<usize, ()> {
    value.into_string().map_err(|_| ())?.parse().map_err(|_| ())
}

fn parse_u64(value: std::ffi::OsString) -> Result<u64, ()> {
    value.into_string().map_err(|_| ())?.parse().map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_requests_campaign_cancellation() {
        let cancellation = Arc::new(QualificationKubernetesCampaignCancellation::new());
        let signal_task =
            spawn_signal_task(Arc::clone(&cancellation)).expect("register campaign signals");
        let signal_status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(std::process::id().to_string())
            .status()
            .expect("send SIGTERM");
        assert!(signal_status.success());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !cancellation.is_cancelled() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "SIGTERM did not request cancellation"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        signal_task.abort();
        let _ = signal_task.await;
    }

    #[test]
    fn usage_never_advertises_a_network_control_endpoint() {
        assert!(USAGE.contains("--output-directory"));
        assert!(!USAGE.contains("address"));
        assert!(!USAGE.contains("port"));
        assert!(!USAGE.contains("token"));
    }

    #[test]
    fn parser_accepts_only_complete_bounded_arguments_and_a_new_absolute_output() {
        let root = tempfile::tempdir().expect("argument output root");
        let output = std::fs::canonicalize(root.path())
            .expect("canonical output root")
            .join("candidate-1");
        let arguments = [
            "--namespace".into(),
            "qualification".into(),
            "--members".into(),
            "3".into(),
            "--rounds".into(),
            "2".into(),
            "--interval-ms".into(),
            "1000".into(),
            "--history-id".into(),
            "candidate-1".into(),
            "--output-directory".into(),
            output.clone().into_os_string(),
        ];
        let parsed = parse_arguments_from(arguments.clone().into_iter()).expect("valid arguments");
        assert_eq!(parsed.config.member_count, 3);
        assert_eq!(parsed.config.rounds, 2);
        assert_eq!(parsed.output_directory, output);

        let mut duplicate = arguments;
        duplicate[2] = "--namespace".into();
        assert!(parse_arguments_from(duplicate.into_iter()).is_err());
    }
}
