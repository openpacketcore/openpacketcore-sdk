//! Detect numeric JSON drift, unbounded sink work, and lost I/O errors.

use super::*;
use std::cell::Cell;

pub(crate) struct Bytes<'a>(pub(crate) &'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

thread_local! {
    // Counts bytes actually constructed in the numeric payload buffer,
    // including commas. Each scope is synchronous and retains no payload.
    static EMITTED: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn record_emitted_batch(bytes: usize) {
    EMITTED.with(|emitted| {
        if let Some(total) = emitted.get() {
            emitted.set(Some(total.checked_add(bytes).expect("emission count")));
        }
    });
}

pub(crate) fn observe_emission<T>(work: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            EMITTED.with(|emitted| emitted.set(None));
        }
    }
    EMITTED.with(|emitted| {
        assert!(
            emitted.get().is_none(),
            "synchronous observation cannot nest"
        );
        emitted.set(Some(0));
    });
    let reset = Reset;
    let result = work();
    let bytes = EMITTED.with(|emitted| emitted.get().expect("active observation"));
    drop(reset);
    (result, bytes)
}

pub(crate) fn byte_cases() -> Vec<Vec<u8>> {
    let mut cases = vec![Vec::new()];
    cases.extend((0..=255).map(|byte| vec![byte]));
    for length in [255, 256, 257, 511, 512, 1023, 1024, 1025, 16_384] {
        cases.push((0..=255).cycle().take(length).collect());
    }
    for byte in [0, 9, 10, 99, 100, 255] {
        for length in [256, 257, 341, 342, 512, 513, 1024, 1025] {
            cases.push(vec![byte; length]);
        }
    }
    cases
}

#[derive(Default)]
struct ObservedWriter {
    bytes: Vec<u8>,
    lengths: Vec<usize>,
    calls: usize,
    largest: usize,
    short: bool,
    fail_at: Option<usize>,
}

impl io::Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.lengths.push(bytes.len());
        self.calls += 1;
        self.largest = self.largest.max(bytes.len());
        if self.fail_at == Some(self.calls) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let length = if self.short {
            bytes.len().min(3)
        } else {
            bytes.len()
        };
        self.bytes.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn config_capacity_numeric_json_batches_bounded_sink_work() {
    for length in [0, 1, 255, 256, 257, 511, 512, 1023, 1024, 1025, 16_384] {
        let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
        let original = serde_json::to_vec(&bytes).unwrap();
        let mut writer = ObservedWriter::default();
        let (result, emitted) = observe_emission(|| to_writer(&mut writer, &Bytes(&bytes)));
        result.unwrap();
        assert_eq!(
            emitted,
            original.len() - 2,
            "observe real digit construction"
        );
        assert!(
            writer.bytes == original,
            "CONFIG_CAPACITY_BATCH_JSON_COMPATIBILITY_RED"
        );
        assert!(writer.largest <= 1024, "bounded stack flush");
        assert!(
            writer.calls <= 2 + original.len().div_ceil(512),
            "CONFIG_CAPACITY_BATCH_JSON_SINK_WORK_RED"
        );
    }
}

#[test]
fn config_capacity_numeric_json_preserves_short_writes() {
    let bytes: Vec<u8> = (0..=255).cycle().take(4097).collect();
    let mut writer = ObservedWriter {
        short: true,
        ..ObservedWriter::default()
    };
    to_writer(&mut writer, &Bytes(&bytes)).unwrap();
    assert!(writer.bytes == serde_json::to_vec(&bytes).unwrap());
}

#[test]
fn config_capacity_numeric_json_stops_at_the_first_sink_error() {
    let bytes: Vec<u8> = (0..=255).cycle().take(4097).collect();
    for fail_at in 1..=4 {
        let mut writer = ObservedWriter {
            fail_at: Some(fail_at),
            ..ObservedWriter::default()
        };
        let error = to_writer(&mut writer, &Bytes(&bytes)).unwrap_err();
        assert_eq!(error.io_error_kind(), Some(io::ErrorKind::PermissionDenied));
        assert_eq!(writer.calls, fail_at);
    }
}

#[test]
fn config_capacity_count_only_preserves_every_emission_checkpoint() {
    for bytes in byte_cases() {
        let original = serde_json::to_vec(&bytes).unwrap();
        for short in [false, true] {
            let mut emitted = ObservedWriter {
                short,
                ..ObservedWriter::default()
            };
            to_writer(&mut emitted, &Bytes(&bytes)).unwrap();
            assert_eq!(emitted.bytes, original);
            let mut counted = ObservedWriter {
                short,
                ..ObservedWriter::default()
            };
            let (result, digit_bytes) =
                observe_emission(|| count_to_writer(&mut counted, &Bytes(&bytes)));
            result.unwrap();
            assert_eq!(counted.bytes.len(), original.len());
            assert_eq!(counted.lengths, emitted.lengths);
            assert!(counted.largest <= 1024);
            assert_eq!(digit_bytes, 0);
        }
    }
}

#[test]
fn config_capacity_count_only_preserves_first_error_and_bounded_checks() {
    let bytes: Vec<u8> = [0, 9, 10, 99, 100, 255]
        .into_iter()
        .cycle()
        .take(4097)
        .collect();
    let mut complete = ObservedWriter::default();
    to_writer(&mut complete, &Bytes(&bytes)).unwrap();
    for fail_at in 1..=complete.calls {
        let mut emitted = ObservedWriter {
            fail_at: Some(fail_at),
            ..ObservedWriter::default()
        };
        let original_error = to_writer(&mut emitted, &Bytes(&bytes)).unwrap_err();
        let mut counted = ObservedWriter {
            fail_at: Some(fail_at),
            ..ObservedWriter::default()
        };
        let error = count_to_writer(&mut counted, &Bytes(&bytes)).unwrap_err();
        assert_eq!(error.io_error_kind(), Some(io::ErrorKind::PermissionDenied));
        assert_eq!(error.io_error_kind(), original_error.io_error_kind());
        assert_eq!(counted.calls, fail_at);
        assert_eq!(counted.lengths, emitted.lengths);
        assert_eq!(counted.bytes.len(), emitted.bytes.len());
    }
}

#[test]
fn config_capacity_count_only_preserves_other_json_fields() {
    #[derive(Serialize)]
    enum Payload<'a> {
        Empty,
        Bytes(Bytes<'a>),
        Fields {
            name: &'a str,
            boolean: bool,
            signed: i64,
            unsigned: u64,
            float: f64,
            present: Option<&'a str>,
            absent: Option<&'a str>,
        },
    }
    let bytes: Vec<_> = (0..=255).collect();
    let values = [
        Payload::Empty,
        Payload::Bytes(Bytes(&bytes)),
        Payload::Fields {
            name: "synthetic\0\n\r\t\"\\\u{0001}é🦀",
            boolean: true,
            signed: i64::MIN,
            unsigned: u64::MAX,
            float: -0.125,
            present: Some("escaped\nvalue"),
            absent: None,
        },
    ];
    let original = serde_json::to_vec(&values).unwrap();
    let mut counted = ObservedWriter::default();
    count_to_writer(&mut counted, &values).unwrap();
    assert_eq!(counted.bytes.len(), original.len());
}
