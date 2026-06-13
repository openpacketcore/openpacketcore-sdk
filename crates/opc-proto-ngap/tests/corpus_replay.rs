//! Deterministic corpus-replay regression guard.
//!
//! Replays every committed fuzz corpus input — plus byte-truncations of each
//! entry and a set of hostile constant inputs — through the same decode entry
//! point as the libFuzzer target in `fuzz/fuzz_targets/decode_ngap.rs`.
//!
//! Unlike the fuzzer, this runs on stable Rust in ordinary `cargo test`/CI:
//! it requires no nightly toolchain and no libFuzzer. Its job is regression
//! protection — if a future change makes the decode path panic on a known
//! input, this test fails and names the offending input.

use bytes::Bytes;
use opc_proto_ngap::Pdu;
use opc_protocol::{DecodeContext, OwnedDecode};

/// The decode entry point the fuzz target exercises. Must never panic,
/// regardless of input. Decode returning `Err` is expected and fine.
fn exercise(data: &[u8]) {
    let _ = Pdu::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());
}

// --- shared replay harness (kept self-contained per crate) ---------------

/// Read every committed corpus file under `<crate>/fuzz/corpus`, recursively.
fn corpus_files() -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.push((path, bytes));
            }
        }
    }
    out
}

/// Hostile constant inputs that should never appear in a real corpus but must
/// still decode without panicking: empty, single bytes, long zero/0xFF runs,
/// a byte ramp, and a header-shaped probe claiming a large length over a short
/// body.
fn adversarial_seeds() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0x00; 8],
        vec![0xFF; 8],
        vec![0x00; 4096],
        vec![0xFF; 4096],
        (0..=255u8).collect(),
        vec![0x20, 0x01, 0xFF, 0xFF, 0x00, 0x00],
    ]
}

#[test]
fn corpus_and_adversarial_inputs_never_panic() {
    let corpus = corpus_files();
    assert!(
        !corpus.is_empty(),
        "expected committed seed corpus under fuzz/corpus; found none"
    );

    let mut failures: Vec<String> = Vec::new();
    let mut checked: usize = 0;

    for (path, data) in &corpus {
        if std::panic::catch_unwind(|| exercise(data)).is_err() {
            failures.push(format!("corpus:{}", path.display()));
        }
        checked += 1;
        // Truncations of each corpus entry exercise "length says N, only M
        // bytes present" paths, the classic source of decode panics.
        for i in 0..=data.len().min(256) {
            let slice = &data[..i];
            if std::panic::catch_unwind(|| exercise(slice)).is_err() {
                failures.push(format!("truncation:{}[..{}]", path.display(), i));
            }
            checked += 1;
        }
    }

    for (idx, seed) in adversarial_seeds().iter().enumerate() {
        if std::panic::catch_unwind(|| exercise(seed)).is_err() {
            failures.push(format!("adversarial#{idx}"));
        }
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "decode panicked on {} of {} known input(s): {:#?}",
        failures.len(),
        checked,
        failures
    );
}
