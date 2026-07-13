//! Count-only offline audit for persisted `opc-session-store` SQLite state.

use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use opc_session_store::sqlite::audit::{
    audit_sqlite_identity_invariants_at, SqliteIdentityAuditError, SqliteIdentityAuditLimits,
    SqliteIdentityAuditStatus, SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
};
use opc_types::Timestamp;
use serde::Serialize;

const USAGE: &str = "usage: opc-session-store-audit identity-invariants \
    --database PATH --max-rows N --max-entry-json-bytes N --max-total-json-bytes N \
    [--expiry-reference RFC3339]";

#[derive(Serialize)]
struct ErrorResponse {
    report_version: u32,
    status: &'static str,
    reason: &'static str,
}

struct AuditArgs {
    database: PathBuf,
    limits: SqliteIdentityAuditLimits,
    expiry_reference: Timestamp,
}

enum Command {
    Audit(AuditArgs),
    Help,
    Version,
}

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(reason) => {
            write_error(reason);
            return 2;
        }
    };

    match command {
        Command::Help => {
            let response = serde_json::json!({
                "report_version": SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
                "status": "help",
                "usage": USAGE,
            });
            if write_json(io::stdout(), &response).is_ok() {
                0
            } else {
                write_error("output_failed");
                2
            }
        }
        Command::Version => {
            let response = serde_json::json!({
                "report_version": SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
                "status": "version",
                "crate_version": env!("CARGO_PKG_VERSION"),
            });
            if write_json(io::stdout(), &response).is_ok() {
                0
            } else {
                write_error("output_failed");
                2
            }
        }
        Command::Audit(args) => {
            match audit_sqlite_identity_invariants_at(
                args.database,
                args.limits,
                args.expiry_reference,
            ) {
                Ok(report) => {
                    let status = report.status();
                    if write_json(io::stdout(), &report).is_err() {
                        write_error("output_failed");
                        return 2;
                    }
                    match status {
                        SqliteIdentityAuditStatus::Compliant => 0,
                        SqliteIdentityAuditStatus::ViolationsFound => 1,
                        SqliteIdentityAuditStatus::Incomplete => 2,
                        _ => 2,
                    }
                }
                Err(error) => {
                    write_audit_error(error);
                    2
                }
            }
        }
    }
}

fn parse_command(args: &[OsString]) -> Result<Command, &'static str> {
    match args {
        [flag] if arg_is(flag, "--help") || arg_is(flag, "-h") => return Ok(Command::Help),
        [flag] if arg_is(flag, "--version") || arg_is(flag, "-V") => return Ok(Command::Version),
        [] => return Err("invalid_arguments"),
        _ => {}
    }
    if !args
        .first()
        .is_some_and(|arg| arg_is(arg, "identity-invariants"))
    {
        return Err("invalid_arguments");
    }

    let mut database = None;
    let mut max_rows = None;
    let mut max_entry_json_bytes = None;
    let mut max_total_json_bytes = None;
    let mut expiry_reference = None;
    let mut index = 1;
    while index < args.len() {
        let flag = &args[index];
        let Some(value) = args.get(index + 1) else {
            return Err("invalid_arguments");
        };
        if arg_is(flag, "--database") && database.is_none() {
            database = Some(PathBuf::from(value));
        } else if arg_is(flag, "--max-rows") && max_rows.is_none() {
            max_rows = parse_u64(value);
            if max_rows.is_none() {
                return Err("invalid_arguments");
            }
        } else if arg_is(flag, "--max-entry-json-bytes") && max_entry_json_bytes.is_none() {
            max_entry_json_bytes = parse_u64(value);
            if max_entry_json_bytes.is_none() {
                return Err("invalid_arguments");
            }
        } else if arg_is(flag, "--max-total-json-bytes") && max_total_json_bytes.is_none() {
            max_total_json_bytes = parse_u64(value);
            if max_total_json_bytes.is_none() {
                return Err("invalid_arguments");
            }
        } else if arg_is(flag, "--expiry-reference") && expiry_reference.is_none() {
            expiry_reference = value
                .to_str()
                .and_then(|value| Timestamp::from_str(value).ok());
            if expiry_reference.is_none() {
                return Err("invalid_arguments");
            }
        } else {
            return Err("invalid_arguments");
        }
        index += 2;
    }

    let database = database.ok_or("invalid_arguments")?;
    let limits = SqliteIdentityAuditLimits::try_new(
        max_rows.ok_or("invalid_arguments")?,
        max_entry_json_bytes.ok_or("invalid_arguments")?,
        max_total_json_bytes.ok_or("invalid_arguments")?,
    )
    .map_err(|_| "invalid_limits")?;
    Ok(Command::Audit(AuditArgs {
        database,
        limits,
        expiry_reference: expiry_reference.unwrap_or_else(Timestamp::now_utc),
    }))
}

fn arg_is(value: &OsStr, expected: &str) -> bool {
    value == OsStr::new(expected)
}

fn parse_u64(value: &OsStr) -> Option<u64> {
    value.to_str()?.parse().ok()
}

fn write_audit_error(error: SqliteIdentityAuditError) {
    write_error(error.reason_code());
}

fn write_error(reason: &'static str) {
    let response = ErrorResponse {
        report_version: SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
        status: "error",
        reason,
    };
    let _ = write_json(io::stderr(), &response);
}

fn write_json(mut writer: impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")
}
