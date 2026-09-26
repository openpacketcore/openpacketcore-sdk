//! Actual JSON transaction-boundary controls. These are encoder/partition
//! checks, not evidence that a public configuration reaches every JSON ceiling.

use super::*;

#[test]
fn capacity_apply_partition_preserves_exact_transaction_byte_limit() {
    assert_eq!(CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES, 16_777_216);
    assert_eq!(CONFIG_CONSENSUS_LOG_APPEND_MAX_BYTES, 67_108_864);
    let text = "x".repeat(16_777_214);
    let cancellation = SqliteWorkCancellation::new();
    let at_limit = [text.as_str(); 4];
    assert_eq!(
        json_length_bounded_cancellable(&text, 16_777_216, "synthetic entry limit", &cancellation,)
            .unwrap(),
        16_777_216
    );
    assert_eq!(
        committed_apply_batch_end(&at_limit, &cancellation).unwrap(),
        4
    );
    let over = [text.as_str(); 5];
    let end = committed_apply_batch_end(&over, &cancellation).unwrap();
    assert_eq!(
        end, 4,
        "CONFIG_CAPACITY_APPLY_BYTES: a committed prefix must split before exceeding the original transaction byte limit"
    );
    assert_eq!(
        committed_apply_batch_end(&over[end..], &cancellation).unwrap(),
        1
    );
}

#[test]
fn capacity_apply_partition_rejects_oversized_single_entry_and_collection() {
    let cancellation = SqliteWorkCancellation::new();
    let over = "x".repeat(16_777_215);
    let error = committed_apply_batch_end(&[over.as_str()], &cancellation).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "config consensus apply entry exceeds storage limit"
    );
    let entries = [(); 1_025];
    assert_eq!(
        committed_apply_batch_end(&entries[..1_024], &cancellation).unwrap(),
        1_024
    );
    assert!(committed_apply_batch_end(&entries, &cancellation).is_err());
    assert_eq!(
        committed_apply_batch_end::<()>(&[], &cancellation).unwrap(),
        0
    );
}

#[test]
fn capacity_apply_partition_obeys_the_existing_cancellation_deadline() {
    let cancellation = SqliteWorkCancellation::with_deadline(std::time::Instant::now());
    assert_eq!(
        committed_apply_batch_end(&["synthetic"], &cancellation)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        committed_apply_batch_end::<()>(&[], &cancellation)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}
