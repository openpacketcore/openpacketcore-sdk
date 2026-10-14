use super::cases::{Case, Key, Profile};
use opc_yanggen::rust::generate_rust;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const RUNTIME_SUPPORT: &str = r#"
use opc_config_model::{
    CommitMode, ConfigOperation, OpcConfig, RequestId, RequestSource, TransportType,
    TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
};
use serde_json::json;

fn context<C: OpcConfig>() -> ValidationContext<C> {
    ValidationContext {
        request_id: RequestId::new(),
        principal: TrustedPrincipal::new(
            WorkloadIdentity::Internal("test".into()),
            opc_types::TenantId::new("example").unwrap(),
        ),
        transport: TransportType::Internal,
        source: RequestSource::Northbound,
        operation: ConfigOperation::Replace,
        mode: CommitMode::Commit,
        base_version: opc_types::ConfigVersion::INITIAL,
        previous: None,
    }
}
"#;

fn cargo(directory: &Path, target: &Path, args: &[&str], deny_warnings: bool) -> Output {
    let mut command = Command::new("cargo");
    command
        .current_dir(directory)
        .env("CARGO_TARGET_DIR", target)
        .env_remove("RUSTFLAGS")
        .args(args);
    if deny_warnings {
        command.env("RUSTFLAGS", "-Dwarnings");
    }
    command.output().unwrap()
}

fn save_output(directory: &Path, name: &str, output: &Output) {
    fs::write(directory.join(format!("{name}.stdout")), &output.stdout).unwrap();
    fs::write(directory.join(format!("{name}.stderr")), &output.stderr).unwrap();
}

pub fn check_batch(profile: Profile, key: Key, cases: &[Case]) -> Result<(), String> {
    let batch = format!("{}_{}", profile.name(), key.name());
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let directory = scratch.path();
    let target = workspace.join("target/yanggen-generated");
    let src = directory.join("src");
    fs::create_dir(&src).unwrap();
    let evidence = std::env::var_os("OPC_YANGGEN_LINT_MATRIX_EVIDENCE_DIR")
        .map(|root| std::path::PathBuf::from(root).join(&batch));
    if let Some(evidence) = &evidence {
        fs::create_dir_all(evidence).unwrap();
    }
    let mut lib = String::new();
    let mut runtime = RUNTIME_SUPPORT.to_string();
    let mut coverage = Vec::new();
    let mut sources = serde_json::Map::new();
    for case in cases {
        let input = case.input();
        coverage.push(case.coverage(&input));
        let module = src.join(&case.name);
        fs::create_dir(&module).unwrap();
        for (file, content) in generate_rust(&input).unwrap() {
            sources.insert(
                format!("{}/{file}", case.name),
                json!(Sha256::digest(content.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()),
            );
            fs::write(module.join(&file), &content).unwrap();
            if let Some(evidence) = &evidence {
                let output = evidence.join("generated").join(&case.name);
                fs::create_dir_all(&output).unwrap();
                fs::write(output.join(file), content).unwrap();
                fs::write(output.join("fixture.yang"), case.schema()).unwrap();
            }
        }
        lib.push_str(&format!("pub mod {};\n", case.name));
        runtime.push_str(&case.runtime_test());
    }
    lib.push_str("#[cfg(test)] mod runtime;\n");
    fs::write(src.join("lib.rs"), lib).unwrap();
    fs::write(src.join("runtime.rs"), &runtime).unwrap();
    let dependencies = [
        "opc-config-model",
        "opc-types",
        "opc-data-governance",
        "opc-mgmt-schema",
        "opc-mgmt-limits",
        "opc-redaction",
        "opc-gnmi-server",
        "opc-netconf-server",
    ]
    .into_iter()
    .map(|name| {
        format!(
            "{name} = {{ path = {:?} }}\n",
            workspace.join("crates").join(name)
        )
    })
    .collect::<String>();
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            r#"[package]
name = "generated-lint-{batch}"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
time = "={}"
{dependencies}"#,
            super::common::locked_version(workspace, "time"),
        ),
    )
    .unwrap();
    let runtime_args = ["test", "--no-fail-fast", "--", "--test-threads=4"];
    let runtime_output = cargo(directory, &target, &runtime_args, true);
    // Only the two lint classes under repair are errors. All other Clippy
    // diagnostics remain enabled and are retained for the separate lint work.
    let clippy_args = [
        "clippy",
        "--all-targets",
        "--message-format=json",
        "--",
        "-D",
        "clippy::clone_on_copy",
        "-D",
        "clippy::for_kv_map",
    ];
    let clippy_output = cargo(directory, &target, &clippy_args, false);
    let diagnostics: Vec<Value> = String::from_utf8_lossy(&clippy_output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-message")
        .map(|message| message["message"].clone())
        .collect();
    let targeted: Vec<_> = diagnostics
        .iter()
        .filter(|message| {
            matches!(
                message["code"]["code"].as_str(),
                Some("clippy::clone_on_copy" | "clippy::for_kv_map")
            )
        })
        .collect();
    let other_lints: std::collections::BTreeSet<_> = diagnostics
        .iter()
        .filter_map(|message| message["code"]["code"].as_str())
        .filter(|code| {
            code.starts_with("clippy::")
                && !matches!(*code, "clippy::clone_on_copy" | "clippy::for_kv_map")
        })
        .collect();
    eprintln!(
        "matrix {batch}: {} cells, runtime={}, clippy={}, targeted={}, other={other_lints:?}",
        cases.len(),
        runtime_output.status,
        clippy_output.status,
        targeted.len(),
    );
    if let Some(evidence) = &evidence {
        save_output(evidence, "runtime", &runtime_output);
        save_output(evidence, "clippy", &clippy_output);
        fs::write(evidence.join("runtime.rs"), runtime).unwrap();
        fs::write(
            evidence.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "batch": batch, "coverage": coverage, "source_sha256": sources,
                "runtime_command": runtime_args, "clippy_command": clippy_args,
                "runtime_exit": runtime_output.status.code(),
                "clippy_exit": clippy_output.status.code(),
                "targeted_diagnostics": targeted.len(), "other_lints": other_lints,
                "diagnostics": diagnostics,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    if !runtime_output.status.success() {
        eprintln!(
            "{}\n{}",
            String::from_utf8_lossy(&runtime_output.stdout),
            String::from_utf8_lossy(&runtime_output.stderr),
        );
    }
    if !clippy_output.status.success() {
        for message in &diagnostics {
            if message["level"] == "error" {
                eprintln!("{}", message["rendered"].as_str().unwrap_or(""));
            }
        }
        eprintln!("{}", String::from_utf8_lossy(&clippy_output.stderr));
    }
    if runtime_output.status.success() && clippy_output.status.success() && targeted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{batch}: runtime={}, clippy={}, {} forbidden lint diagnostics",
            runtime_output.status,
            clippy_output.status,
            targeted.len(),
        ))
    }
}
