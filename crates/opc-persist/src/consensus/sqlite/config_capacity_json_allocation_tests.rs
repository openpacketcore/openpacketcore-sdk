//! Exact native JSON buffer allocation without changing log or WAL semantics.

use super::*;
use std::cell::Cell;

#[test]
fn capacity_native_json_reserves_actual_decimal_expansion_once() {
    let bytes = vec![255u8; 1_638_400];
    let original = serde_json::to_vec(&bytes).unwrap();
    let encoded = encode_json_bounded_cancellable(
        &bytes,
        16_777_216,
        "synthetic entry limit",
        &SqliteWorkCancellation::new(),
    )
    .unwrap();
    assert_eq!(encoded, original);
    assert_eq!(
        encoded.capacity(),
        encoded.len(),
        "native output must not retain geometric growth headroom"
    );
    eprintln!(
        "CAPACITY_NATIVE_JSON bytes={} capacity={}",
        encoded.len(),
        encoded.capacity()
    );
}

#[test]
fn capacity_native_json_exact_ceiling_and_changed_second_pass_are_rejected() {
    let text = "x".repeat(16_777_214);
    let encoded = encode_json_bounded_cancellable(
        &text,
        16_777_216,
        "synthetic entry limit",
        &SqliteWorkCancellation::new(),
    )
    .unwrap();
    assert_eq!(encoded.len(), 16_777_216);
    assert_eq!(encoded.capacity(), 16_777_216);
    assert_eq!(encoded, serde_json::to_vec(&text).unwrap());
    let error = encode_json_bounded_cancellable(
        &text,
        16_777_215,
        "synthetic entry limit",
        &SqliteWorkCancellation::new(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "synthetic entry limit");

    // Production callers serialize closed immutable DTOs. Still fail safely
    // if a future caller violates the two-pass length assumption.
    struct Changing {
        calls: Cell<usize>,
        grow: bool,
    }
    impl Serialize for Changing {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let first = self.calls.replace(self.calls.get() + 1) == 0;
            serializer.serialize_str(if first == self.grow { "x" } else { "xxxxxxxx" })
        }
    }
    for grow in [false, true] {
        let value = Changing {
            calls: Cell::new(0),
            grow,
        };
        assert!(encode_json_bounded_cancellable(
            &value,
            128,
            "synthetic entry limit",
            &SqliteWorkCancellation::new(),
        )
        .is_err());
        assert_eq!(value.calls.get(), 2);
    }
}

#[test]
fn capacity_native_json_preserves_cancellation_on_both_passes() {
    struct CancelOnPass<'a> {
        cancellation: &'a SqliteWorkCancellation,
        calls: Cell<usize>,
        cancel_at: usize,
    }
    impl Serialize for CancelOnPass<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == self.cancel_at {
                assert!(self.cancellation.cancel_before_commit());
            }
            serializer.serialize_str("synthetic")
        }
    }
    for cancel_at in [1, 2] {
        let cancellation = SqliteWorkCancellation::new();
        let value = CancelOnPass {
            cancellation: &cancellation,
            calls: Cell::new(0),
            cancel_at,
        };
        let error =
            encode_json_bounded_cancellable(&value, 128, "synthetic entry limit", &cancellation)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(cancellation.is_cancelled());
        assert!(cancellation.authorize_commit().is_err());
    }
}
