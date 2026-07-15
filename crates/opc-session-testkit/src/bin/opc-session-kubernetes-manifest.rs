//! Render the experimental deployed-CNF session-HA manifest foundation.

use std::env;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use opc_session_testkit::qualification_kubernetes::{
    render_qualification_kubernetes_manifest, QualificationKubernetesManifestConfig,
};

#[derive(Debug, thiserror::Error)]
#[error("qualification Kubernetes manifest rendering failed")]
struct RenderFailure;

fn arguments() -> Result<QualificationKubernetesManifestConfig, RenderFailure> {
    let mut arguments = env::args_os();
    let _program = arguments.next().ok_or(RenderFailure)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--members")) {
        return Err(RenderFailure);
    }
    let member_count = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(RenderFailure)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--namespace")) {
        return Err(RenderFailure);
    }
    let namespace = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(RenderFailure)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--image")) {
        return Err(RenderFailure);
    }
    let image = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(RenderFailure)?;
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--trust-domain")) {
        return Err(RenderFailure);
    }
    let trust_domain = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(RenderFailure)?;
    if arguments.next().is_some() {
        return Err(RenderFailure);
    }
    Ok(QualificationKubernetesManifestConfig {
        member_count,
        namespace,
        image,
        trust_domain,
    })
}

fn run() -> Result<(), RenderFailure> {
    let manifest =
        render_qualification_kubernetes_manifest(&arguments()?).map_err(|_| RenderFailure)?;
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut writer, &manifest).map_err(|_| RenderFailure)?;
    writer.write_all(b"\n").map_err(|_| RenderFailure)?;
    writer.flush().map_err(|_| RenderFailure)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("qualification Kubernetes manifest rendering failed");
            ExitCode::FAILURE
        }
    }
}
