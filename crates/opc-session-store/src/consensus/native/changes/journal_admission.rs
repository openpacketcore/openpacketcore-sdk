//! Test-fixture admission of a bounded native operation before publication.
use super::*;

pub(super) fn admit<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
    mut on_pressure: impl FnMut(),
) -> std::io::Result<T> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match operation() {
            Err(error)
                if crate::consensus::verified_snapshot::VerificationMemory::journal_pressure(
                    &error,
                )
                .is_some()
                    && std::time::Instant::now() < deadline =>
            {
                on_pressure();
            }
            result => return result,
        }
    }
}

#[test]
fn native_fixture_append_retries_typed_pressure_without_partial_publication() {
    const CHILD: &str = "OPC_NATIVE_FIXTURE_ADMISSION_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = format!(
            "{}::native_fixture_append_retries_typed_pressure_without_partial_publication",
            module_path!().split_once("::").unwrap().1,
        );
        use crate::test_process::CommandExt as _;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "typed admission child must pass: {} {}",
            stdout,
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(
            stdout.contains(&format!("test {name} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "the exact enabled child test must execute",
        );
        return;
    }
    use crate::consensus::verified_snapshot::{VerificationMemory, PROCESS_VERIFICATION_BYTES};
    let (mut storage, _, _) = fixture();
    let previous = storage.log.last();
    let entry = clock(previous.unwrap().index + 1, time(2));
    let operation = Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]);
    let occupied = PROCESS_VERIFICATION_BYTES * 7 / 8 + 64 * 1024;
    let mut held = Some(
        VerificationMemory::reserve(
            occupied
                .checked_sub(VerificationMemory::used_bytes())
                .unwrap(),
        )
        .unwrap(),
    );
    let attempts = std::cell::Cell::new(0);
    admit(
        || {
            attempts.set(attempts.get() + 1);
            let result = storage.log.project(&operation, &storage.business, None);
            if result.is_err() {
                assert_eq!(storage.log.last(), previous, "refusal is atomic");
            }
            result
        },
        || drop(held.take()),
    )
    .expect("fixture append succeeds after independent pressure is released");
    assert_eq!(attempts.get(), 2);
    assert_eq!(storage.log.last(), Some(entry.log_id));
    assert_eq!(storage.business.applied(), previous);
    storage.validate_image().unwrap();
}

#[test]
fn native_fixture_admission_does_not_retry_untyped_or_invalid_errors() {
    for error in [
        std::io::Error::other("portable snapshot verification memory limit reached"),
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid native row"),
    ] {
        let kind = error.kind();
        let mut error = Some(error);
        let attempts = std::cell::Cell::new(0);
        let waits = std::cell::Cell::new(0);
        let result: std::io::Result<()> = admit(
            || {
                attempts.set(attempts.get() + 1);
                Err(error.take().expect("unrelated errors must not be retried"))
            },
            || waits.set(waits.get() + 1),
        );
        assert_eq!(result.unwrap_err().kind(), kind);
        assert_eq!(attempts.get(), 1);
        assert_eq!(waits.get(), 0);
    }
}
