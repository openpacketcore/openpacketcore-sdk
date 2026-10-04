//! Repository catalog validator. Emits only stable, redacted result codes.

use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("n3iwf_fixture_invalid_arguments");
        return ExitCode::FAILURE;
    }
    match opc_n3iwf_fixtures::FixtureCatalog::load() {
        Ok(_) => {
            println!("n3iwf_fixture_catalog_valid");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
