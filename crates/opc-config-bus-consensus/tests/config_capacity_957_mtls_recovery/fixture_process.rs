//! Keep independent native fixtures out of each other's process-wide budgets.
//!
//! The parent libtest process still runs four cases concurrently. Each case
//! re-executes this same test binary once with its exact selector and retains
//! the four-worker Tokio runtime, original scenario and operation deadlines.
//! The production four-worker retained startup gate remains unchanged.

use std::future::Future;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};

const CASE_ENV: &str = "OPC_CONFIG_CAPACITY_957_NATIVE_CASE";
const PARENT_ENV: &str = "OPC_CONFIG_CAPACITY_957_NATIVE_PARENT";
const COMPLETE: &str = "CONFIG_CAPACITY_FIXTURE_PROCESS completed=true isolated=true";
static PARENT_ENTERED: AtomicBool = AtomicBool::new(false);

pub(super) fn run(qualified_name: &str, scenario: impl Future<Output = ()>) {
    let (target, name) = qualified_name
        .split_once("::")
        .expect("native case includes its integration target");
    assert_eq!(target, "config_capacity_957_mtls_recovery");
    match (std::env::var(CASE_ENV), std::env::var(PARENT_ENV)) {
        (Ok(selected), Ok(parent)) => {
            assert_eq!(selected, name, "exactly the selected native case executes");
            let parent = parent.parse().expect("own fixture parent process");
            run_scenario(parent, scenario);
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
            PARENT_ENTERED.store(true, Ordering::SeqCst);
            let output = Command::new(std::env::current_exe().expect("current native test binary"))
                .args([
                    "--exact",
                    name,
                    "--quiet",
                    "--nocapture",
                    "--test-threads=4",
                ])
                .env(CASE_ENV, name)
                .env(PARENT_ENV, std::process::id().to_string())
                .output()
                .expect("run exactly one owned native fixture process");
            // Preserve the child's observations and failures in the original
            // libtest capture; an empty selection can never become a pass.
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            assert!(
                completed_case(&output),
                "native child must pass one case and complete its isolation receipt"
            );
        }
        _ => panic!("incomplete native fixture process context"),
    }
}

fn run_scenario(parent: u32, scenario: impl Future<Output = ()>) {
    assert!(
        parent != std::process::id(),
        "native case needs its own process"
    );
    assert!(
        !PARENT_ENTERED.load(Ordering::SeqCst),
        "native case needs a fresh process-wide startup gate"
    );
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("original four-worker native runtime")
        .block_on(scenario);
    println!("{COMPLETE}");
}

fn completed_case(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut summaries = stdout
        .lines()
        .filter(|line| line.starts_with("test result:"));
    output.status.success()
        && stdout.lines().filter(|line| *line == COMPLETE).count() == 1
        && summaries.next().is_some_and(|line| {
            line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
        })
        && summaries.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn result(code: i32, receipt: &str, summary: &str) -> Output {
        Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: format!("{receipt}\n{summary}\n").into_bytes(),
            stderr: Vec::new(),
        }
    }

    const ONE_PASS: &str =
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 32 filtered out;";

    #[test]
    fn failed_child_cannot_be_reported_as_a_pass() {
        assert!(completed_case(&result(0, COMPLETE, ONE_PASS)));
        assert!(!completed_case(&result(1, COMPLETE, ONE_PASS)));
    }

    #[test]
    fn native_case_requires_execution_and_completion() {
        assert!(!completed_case(&result(0, "", ONE_PASS)));
        assert!(!completed_case(&result(
            0,
            COMPLETE,
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 33 filtered out;"
        )));
        assert!(!completed_case(&result(
            0,
            &format!("{COMPLETE}\n{COMPLETE}"),
            ONE_PASS
        )));
        assert!(!completed_case(&result(
            0,
            COMPLETE,
            &format!("{ONE_PASS}\n{ONE_PASS}")
        )));
    }
}
