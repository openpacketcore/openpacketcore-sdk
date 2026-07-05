use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use opc_yanggen::{
    generation_input_from_yang_sources, schema_digest, schema_digest_from_canonical,
    validate_generation_input_yang_sources, Diagnostic, DiagnosticCode, GenerationInput,
    YangSource, YangSourceLocation,
};
use serde::Serialize;

#[derive(Debug)]
enum Command {
    ValidateSource {
        input: PathBuf,
        yang_files: Vec<PathBuf>,
    },
    IngestSource {
        profile: String,
        yang_files: Vec<PathBuf>,
    },
    GenerateRust {
        profile: String,
        yang_files: Vec<PathBuf>,
        out_dir: PathBuf,
        check: bool,
        prune: bool,
    },
    Help,
}

#[derive(Serialize)]
struct ValidateOk {
    status: &'static str,
    schema_digest: String,
}

#[derive(Serialize)]
struct GenerateRustOk {
    status: &'static str,
    schema_digest: String,
    files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
}

#[derive(Serialize)]
struct ErrorResponse {
    status: &'static str,
    diagnostic: Diagnostic,
}

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}

fn run() -> Result<(), i32> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_command(&args) {
        Ok(Command::ValidateSource { input, yang_files }) => {
            let input = match read_generation_input(&input) {
                Ok(input) => input,
                Err(diagnostic) => {
                    write_diagnostic(diagnostic);
                    return Err(2);
                }
            };
            let sources = match read_yang_sources(&yang_files) {
                Ok(sources) => sources,
                Err(diagnostic) => {
                    write_diagnostic(diagnostic);
                    return Err(2);
                }
            };
            match validate_generation_input_yang_sources(&input, &sources) {
                Ok(()) => write_json(&ValidateOk {
                    status: "ok",
                    schema_digest: schema_digest(&input),
                })
                .map_err(|_| 2),
                Err(diagnostic) => {
                    write_diagnostic(diagnostic);
                    Err(1)
                }
            }
        }
        Ok(Command::IngestSource {
            profile,
            yang_files,
        }) => {
            let sources = match read_yang_sources(&yang_files) {
                Ok(sources) => sources,
                Err(diagnostic) => {
                    write_diagnostic(diagnostic);
                    return Err(2);
                }
            };
            match generation_input_from_yang_sources(profile, &sources) {
                Ok(input) => write_json(&input).map_err(|_| 2),
                Err(diagnostic) => {
                    write_diagnostic(diagnostic);
                    Err(1)
                }
            }
        }
        Ok(Command::GenerateRust {
            profile,
            yang_files,
            out_dir,
            check,
            prune,
        }) => match generate_rust_artifacts(&profile, &yang_files, &out_dir, check, prune) {
            Ok(response) => write_json(&response).map_err(|_| 2),
            Err(diagnostic) => {
                write_diagnostic(diagnostic);
                Err(1)
            }
        },
        Ok(Command::Help) => {
            print_usage();
            Ok(())
        }
        Err(diagnostic) => {
            write_diagnostic(diagnostic);
            Err(2)
        }
    }
}

fn parse_command(args: &[String]) -> Result<Command, Diagnostic> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match command {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "validate-source" => {
            let mut input = None;
            let mut yang_files = Vec::new();
            parse_common_flags(&args[1..], &mut input, None, &mut yang_files)?;
            let input =
                input.ok_or_else(|| usage_diagnostic("validate-source requires --input"))?;
            if yang_files.is_empty() {
                return Err(usage_diagnostic(
                    "validate-source requires at least one --yang",
                ));
            }
            Ok(Command::ValidateSource { input, yang_files })
        }
        "ingest-source" => {
            let mut input = None;
            let mut profile = None;
            let mut yang_files = Vec::new();
            parse_common_flags(&args[1..], &mut input, Some(&mut profile), &mut yang_files)?;
            if input.is_some() {
                return Err(usage_diagnostic("--input is not valid for ingest-source"));
            }
            let profile =
                profile.ok_or_else(|| usage_diagnostic("ingest-source requires --profile"))?;
            if yang_files.is_empty() {
                return Err(usage_diagnostic(
                    "ingest-source requires at least one --yang",
                ));
            }
            Ok(Command::IngestSource {
                profile,
                yang_files,
            })
        }
        "generate-rust" => parse_generate_rust(&args[1..]),
        other => Err(usage_diagnostic(format!("unknown command `{other}`"))),
    }
}

fn parse_generate_rust(args: &[String]) -> Result<Command, Diagnostic> {
    let mut profile = None;
    let mut yang_files = Vec::new();
    let mut out_dir = None;
    let mut check = false;
    let mut prune = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--profile" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--profile requires a value"))?;
                profile = Some(value.clone());
            }
            "--yang" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--yang requires a path"))?;
                yang_files.push(PathBuf::from(value));
            }
            "--out-dir" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--out-dir requires a path"))?;
                out_dir = Some(PathBuf::from(value));
            }
            "--check" => check = true,
            "--prune" => prune = true,
            other => return Err(usage_diagnostic(format!("unknown flag `{other}`"))),
        }
        index += 1;
    }

    if check && prune {
        return Err(usage_diagnostic(
            "--prune cannot be combined with generate-rust --check",
        ));
    }

    let profile = profile.ok_or_else(|| usage_diagnostic("generate-rust requires --profile"))?;
    if yang_files.is_empty() {
        return Err(usage_diagnostic(
            "generate-rust requires at least one --yang",
        ));
    }
    let out_dir = out_dir.ok_or_else(|| usage_diagnostic("generate-rust requires --out-dir"))?;

    Ok(Command::GenerateRust {
        profile,
        yang_files,
        out_dir,
        check,
        prune,
    })
}

fn parse_common_flags(
    args: &[String],
    input: &mut Option<PathBuf>,
    mut profile: Option<&mut Option<String>>,
    yang_files: &mut Vec<PathBuf>,
) -> Result<(), Diagnostic> {
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--input requires a path"))?;
                *input = Some(PathBuf::from(value));
            }
            "--profile" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--profile requires a value"))?;
                match profile {
                    Some(ref mut profile_slot) => **profile_slot = Some(value.clone()),
                    None => {
                        return Err(usage_diagnostic("--profile is not valid for this command"))
                    }
                }
            }
            "--yang" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| usage_diagnostic("--yang requires a path"))?;
                yang_files.push(PathBuf::from(value));
            }
            other => return Err(usage_diagnostic(format!("unknown flag `{other}`"))),
        }
        index += 1;
    }
    Ok(())
}

fn generate_rust_artifacts(
    profile: &str,
    yang_files: &[PathBuf],
    out_dir: &Path,
    check: bool,
    prune: bool,
) -> Result<GenerateRustOk, Diagnostic> {
    let sources = read_yang_sources(yang_files)?;
    let input = generation_input_from_yang_sources(profile, &sources)?;
    let canonical = input.to_canonical();
    let rust_canonical =
        opc_yanggen::rust::normalize_for_rust_generation(&canonical).map_err(|err| {
            Diagnostic::new(
                DiagnosticCode::UnsupportedYangFeature,
                format!("failed to generate Rust artifacts: {err}"),
                None,
                Some("adjust the source YANG to the Rust projection subset"),
            )
        })?;
    let schema_digest = schema_digest_from_canonical(&rust_canonical);
    let files = opc_yanggen::rust::generate_rust(&rust_canonical).map_err(|err| {
        Diagnostic::new(
            DiagnosticCode::UnsupportedYangFeature,
            format!("failed to generate Rust artifacts: {err}"),
            None,
            Some("adjust the source YANG to the Rust projection subset"),
        )
    })?;
    let files = sorted_generated_files(files)?;
    let file_names = files
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();

    if check {
        check_generated_files(out_dir, &files)?;
    } else {
        write_generated_files(out_dir, &files, prune)?;
    }

    Ok(GenerateRustOk {
        status: "ok",
        schema_digest,
        files: file_names,
        mode: check.then_some("check"),
    })
}

fn sorted_generated_files(
    files: std::collections::HashMap<String, String>,
) -> Result<Vec<(String, String)>, Diagnostic> {
    let mut sorted = files.into_iter().collect::<Vec<_>>();
    sorted.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (name, _) in &sorted {
        let path = Path::new(name);
        if path.is_absolute() || path.components().count() != 1 {
            return Err(Diagnostic::new(
                DiagnosticCode::YangSourceMismatch,
                format!("generated Rust artifact name `{name}` is not a flat file name"),
                None,
                Some("report the generator bug or choose an output directory without nested artifacts"),
            ));
        }
    }
    Ok(sorted)
}

fn check_generated_files(out_dir: &Path, files: &[(String, String)]) -> Result<(), Diagnostic> {
    let expected = expected_file_names(files);
    reject_stale_rs_files(out_dir, &expected)?;

    for (name, content) in files {
        let path = out_dir.join(name);
        let existing = fs::read(&path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                generated_artifact_diagnostic(
                    name,
                    "is missing",
                    "run `opc-yanggen generate-rust` to refresh committed generated files",
                )
            } else {
                artifact_io_diagnostic(&path, err)
            }
        })?;
        if existing != content.as_bytes() {
            return Err(generated_artifact_diagnostic(
                name,
                "differs from expected output",
                "rerun `opc-yanggen generate-rust` and commit the updated file",
            ));
        }
    }

    Ok(())
}

fn write_generated_files(
    out_dir: &Path,
    files: &[(String, String)],
    prune: bool,
) -> Result<(), Diagnostic> {
    fs::create_dir_all(out_dir).map_err(|err| artifact_io_diagnostic(out_dir, err))?;

    let expected = expected_file_names(files);
    if prune {
        for stale in stale_rs_files(out_dir, &expected)? {
            fs::remove_file(out_dir.join(&stale))
                .map_err(|err| artifact_io_diagnostic(&out_dir.join(&stale), err))?;
        }
    } else {
        reject_stale_rs_files(out_dir, &expected)?;
    }

    for (name, content) in files {
        let path = out_dir.join(name);
        fs::write(&path, content.as_bytes()).map_err(|err| artifact_io_diagnostic(&path, err))?;
    }

    Ok(())
}

fn expected_file_names(files: &[(String, String)]) -> BTreeSet<String> {
    files.iter().map(|(name, _)| name.clone()).collect()
}

fn reject_stale_rs_files(out_dir: &Path, expected: &BTreeSet<String>) -> Result<(), Diagnostic> {
    if let Some(stale) = stale_rs_files(out_dir, expected)?.into_iter().next() {
        return Err(generated_artifact_diagnostic(
            &stale,
            "is stale",
            "remove the file or rerun `opc-yanggen generate-rust --prune`",
        ));
    }
    Ok(())
}

fn stale_rs_files(out_dir: &Path, expected: &BTreeSet<String>) -> Result<Vec<String>, Diagnostic> {
    let entries = fs::read_dir(out_dir).map_err(|err| artifact_io_diagnostic(out_dir, err))?;
    let mut stale = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|err| artifact_io_diagnostic(out_dir, err))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !expected.contains(name) {
            stale.push(name.to_string());
        }
    }

    stale.sort();
    Ok(stale)
}

fn read_generation_input(path: &Path) -> Result<GenerationInput, Diagnostic> {
    let text = fs::read_to_string(path).map_err(|err| io_diagnostic(path, err))?;
    serde_json::from_str(&text).map_err(|err| {
        Diagnostic::new(
            DiagnosticCode::YangSourceSyntaxError,
            format!(
                "failed to parse GenerationInput JSON `{}`: {err}",
                path.display()
            ),
            Some(YangSourceLocation::new(path.display().to_string(), 1, 1)),
            Some("pass a JSON serialization of opc_yanggen::GenerationInput"),
        )
    })
}

fn read_yang_sources(paths: &[PathBuf]) -> Result<Vec<YangSource>, Diagnostic> {
    paths
        .iter()
        .map(|path| {
            fs::read_to_string(path)
                .map(|text| YangSource::new(path.display().to_string(), text))
                .map_err(|err| io_diagnostic(path, err))
        })
        .collect()
}

fn generated_artifact_diagnostic(file_name: &str, state: &str, help: &str) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceMismatch,
        format!("generated Rust artifact `{file_name}` {state}"),
        None,
        Some(help),
    )
}

fn artifact_io_diagnostic(path: &Path, err: io::Error) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        format!(
            "failed to access generated Rust artifact `{}`: {err}",
            path.display()
        ),
        Some(YangSourceLocation::new(path.display().to_string(), 1, 1)),
        Some("check that the output directory exists and is readable or writable"),
    )
}

fn io_diagnostic(path: &Path, err: io::Error) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        format!("failed to read `{}`: {err}", path.display()),
        Some(YangSourceLocation::new(path.display().to_string(), 1, 1)),
        Some("check that the path exists and is readable"),
    )
}

fn usage_diagnostic(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        DiagnosticCode::YangSourceSyntaxError,
        message,
        None,
        Some("run `opc-yanggen --help` for usage"),
    )
}

fn write_json<T: Serialize>(value: &T) -> io::Result<()> {
    serde_json::to_writer_pretty(io::stdout(), value)?;
    println!();
    Ok(())
}

fn write_diagnostic(diagnostic: Diagnostic) {
    let _ = serde_json::to_writer_pretty(
        io::stderr(),
        &ErrorResponse {
            status: "error",
            diagnostic,
        },
    );
    eprintln!();
}

fn print_usage() {
    eprintln!(
        "usage:\n  opc-yanggen validate-source --input generation-input.json --yang module.yang [--yang import.yang ...]\n  opc-yanggen ingest-source --profile PROFILE --yang module.yang [--yang import.yang ...]\n  opc-yanggen generate-rust --profile PROFILE --yang module.yang [--yang import.yang ...] --out-dir DIR [--check] [--prune]"
    );
}
