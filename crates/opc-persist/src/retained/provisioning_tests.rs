//! Behavioral recovery oracle: the same authorized request must survive process loss.

use super::tests::{key, options, work};
use super::*;

const REQUEST: [u8; 32] = [0x53; 32];

fn request(
    path: &Path,
    resume: bool,
    request_id: [u8; 32],
    work: &Arc<AdmissionWork>,
) -> Result<SqliteBackend, RetainedConfigError> {
    let request = RetainedConfigProvisionRequest::new_authority(request_id)?;
    let mode = if resume {
        provisioning::OpenMode::Resume
    } else {
        provisioning::OpenMode::Provision
    };
    open_authority_sync(
        options(path),
        key(),
        OpenIntent::Transaction(request, mode),
        work,
    )
}

#[test]
fn transaction_crash_child() {
    let Some(path) = std::env::var_os("OPC_TRANSACTION_TEST_DATABASE") else {
        return;
    };
    let stage = std::env::var("OPC_TRANSACTION_TEST_CRASH_STAGE").expect("stage");
    let mut work = work();
    work.hook = Some(Arc::new(move |_, observed| {
        if observed == stage {
            std::process::exit(92);
        }
    }));
    let _ = request(Path::new(&path), false, REQUEST, &Arc::new(work));
    panic!("crash boundary not reached");
}

#[test]
fn same_request_resumes_after_every_provisioning_crash() {
    for stage in [
        "lock_created",
        "database_created",
        "base_initialized",
        "consensus_initialized",
        "binding_stored",
        "database_synced",
        "record_written",
        "record_synced",
    ] {
        let dir = tempfile::tempdir().expect("storage");
        let path = dir.path().join("retained.sqlite");
        let output = std::process::Command::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "retained::provisioning_tests::transaction_crash_child",
                "--nocapture",
            ])
            .env("OPC_TRANSACTION_TEST_DATABASE", &path)
            .env("OPC_TRANSACTION_TEST_CRASH_STAGE", stage)
            .output()
            .expect("crash child");
        assert_eq!(output.status.code(), Some(92), "{stage}");
        let resumed = request(&path, true, REQUEST, &Arc::new(work()));
        assert!(
            resumed.is_ok(),
            "same request must resume after {stage}: {resumed:?}"
        );
        let retained = resumed.expect("resumed authority");
        assert!(request(&path, true, REQUEST, &Arc::new(work())).is_err());
        drop(retained);
        let retry = request(&path, true, REQUEST, &Arc::new(work()));
        assert!(
            retry.is_ok(),
            "completed request retries after {stage}: {retry:?}"
        );
        drop(retry);
        assert!(request(&path, true, [0x54; 32], &Arc::new(work())).is_err());
    }
}

#[path = "provisioning_contract_tests.rs"]
mod contracts;
