use std::fs;
use std::io;
use std::path::PathBuf;

use opc_yanggen::{
    generation_input_from_yang_sources, schema_digest, validate_generation_input_yang_sources,
    Diagnostic, DiagnosticCode, GenerationInput, YangSource, YangSourceLocation,
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
    Help,
}

#[derive(Serialize)]
struct ValidateOk {
    status: &'static str,
    schema_digest: String,
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
        Ok(Command::Help) => {
            print_usage();
            Ok(())
        }
        Err(diagnostic) => {
            write_diagnostic(diagnostic);
            print_usage();
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
        other => Err(usage_diagnostic(format!("unknown command `{other}`"))),
    }
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

fn read_generation_input(path: &PathBuf) -> Result<GenerationInput, Diagnostic> {
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

fn io_diagnostic(path: &PathBuf, err: io::Error) -> Diagnostic {
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
        "usage:\n  opc-yanggen validate-source --input generation-input.json --yang module.yang [--yang import.yang ...]\n  opc-yanggen ingest-source --profile PROFILE --yang module.yang [--yang import.yang ...]"
    );
}
