//! Detect numeric JSON drift, unbounded sink work, and lost I/O errors.

use super::*;

struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

#[derive(Default)]
struct ObservedWriter {
    bytes: Vec<u8>,
    calls: usize,
    largest: usize,
    short: bool,
    fail_at: Option<usize>,
}

impl io::Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
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
        to_writer(&mut writer, &Bytes(&bytes)).unwrap();
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
