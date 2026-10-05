use super::*;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct ByteValue<'a>(#[serde(serialize_with = "bytes")] &'a [u8]);

fn bytes<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(value)
}

#[test]
fn byte_arrays_preserve_all_decimal_widths_and_buffer_boundaries() {
    for length in [
        0, 1, 2, 9, 10, 99, 100, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 8192,
    ] {
        let bytes: Vec<_> = (0..length).map(|n| n as u8).collect();
        let original = serde_json::to_vec(&bytes).unwrap();
        let mut output = Vec::new();
        to_writer(&mut output, &ByteValue(&bytes)).unwrap();
        assert_eq!(output, original);
        let mut count = ByteCount::new(original.len());
        to_writer(&mut count, &ByteValue(&bytes)).unwrap();
        assert_eq!(count.bytes, original.len());
        let mut too_short = ByteCount::new(original.len() - 1);
        assert!(to_writer(&mut too_short, &ByteValue(&bytes)).is_err());
        let mut hash = Sha256::new();
        digest_json(&mut hash, &ByteValue(&bytes)).unwrap();
        assert_eq!(hash.finalize(), Sha256::digest(&original));
    }
}

struct Broken;
impl Serialize for Broken {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("synthetic serializer failure"))
    }
}

#[test]
fn serializer_failure_is_not_a_successful_digest() {
    assert!(digest_json(&mut Sha256::new(), &Broken).is_err());
    assert!(to_writer(Vec::new(), &Broken).is_err());
}

struct ShortWriter {
    bytes: Vec<u8>,
    fail_at: usize,
}
impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len() >= self.fail_at {
            return Err(io::Error::other("synthetic failure"));
        }
        let count = bytes.len().min(3).min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn short_writes_are_completed_and_sink_errors_propagate() {
    let input = vec![255; 1025];
    let expected = serde_json::to_vec(&input).unwrap();
    let mut sink = ShortWriter {
        bytes: Vec::new(),
        fail_at: usize::MAX,
    };
    to_writer(&mut sink, &ByteValue(&input)).unwrap();
    assert_eq!(sink.bytes, expected);
    for limit in [0, 1, 100, 1024, expected.len() - 1] {
        let mut sink = ShortWriter {
            bytes: Vec::new(),
            fail_at: limit,
        };
        assert!(to_writer(&mut sink, &ByteValue(&input)).is_err());
    }
    let mut counter = ByteCount {
        bytes: usize::MAX,
        limit: usize::MAX,
    };
    assert!(counter.write_all(b"x").is_err());
}
