//! Independent legacy-byte/MAC oracles and scoped observations of actual sinks.
//! These synchronous probes are inactive in the existing heap/continuity tests.

use super::*;
use std::cell::{Cell, RefCell};
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Authentication,
    RetainedCount,
    RetainedOutput,
    CanonicalComparison,
}

#[derive(Default)]
pub(crate) struct Writes {
    pub(crate) calls: usize,
    pub(crate) bytes: usize,
    pub(crate) largest: usize,
}

#[derive(Default)]
pub(crate) struct Observation {
    stages: [Writes; 4],
    // Test-only captures used for literal byte equality, never production reuse.
    authentication_bytes: Vec<u8>,
    authentication_capacities: Vec<usize>,
}

impl Observation {
    pub(crate) fn stage(&self, stage: Stage) -> &Writes {
        &self.stages[stage as usize]
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

pub(crate) fn observe<T>(work: impl FnOnce() -> T) -> (T, Observation) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
        }
    }
    ACTIVE.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "synchronous observation cannot nest"
        );
        *slot.borrow_mut() = Some(Observation::default());
    });
    let reset = Reset;
    let result = work();
    let observation = ACTIVE.with(|slot| slot.borrow_mut().take().unwrap());
    drop(reset);
    (result, observation)
}

pub(crate) fn record(stage: Stage, bytes: &[u8]) {
    ACTIVE.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            let writes = &mut observation.stages[stage as usize];
            writes.calls += 1;
            writes.bytes += bytes.len();
            writes.largest = writes.largest.max(bytes.len());
            if matches!(stage, Stage::Authentication) {
                observation.authentication_bytes.extend_from_slice(bytes);
            }
        }
    });
}

fn record_capacity(capacity: usize) {
    ACTIVE.with(|slot| {
        if let Some(observation) = slot.borrow_mut().as_mut() {
            observation.authentication_capacities.push(capacity);
        }
    });
}

pub(crate) struct AuthenticationWriter<'a>(&'a mut Vec<u8>);

impl<'a> AuthenticationWriter<'a> {
    pub(crate) fn new(bytes: &'a mut Vec<u8>) -> Self {
        record_capacity(bytes.capacity());
        Self(bytes)
    }
}

impl Write for AuthenticationWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let capacity = self.0.capacity();
        let written = self.0.write(bytes)?;
        record(Stage::Authentication, &bytes[..written]);
        if self.0.capacity() != capacity {
            record_capacity(self.0.capacity());
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub(crate) struct CountingWriter<'a, W>(&'a mut W);

impl<'a, W> CountingWriter<'a, W> {
    pub(crate) fn new(writer: &'a mut W) -> Self {
        Self(writer)
    }
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.0.write(bytes)?;
        record(Stage::RetainedCount, &bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub(crate) struct Bytes<'a>(pub(crate) &'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

// This oracle intentionally never calls the SDK formatter or authenticator.
pub(crate) fn original_mac<T: Serialize>(key: &AuditKey, domain: &[u8], value: &T) -> [u8; 32] {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes()).unwrap();
    mac.update(domain);
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    mac.finalize().into_bytes().into()
}

struct OriginalVec {
    bytes: Vec<u8>,
    capacities: Vec<usize>,
}

impl OriginalVec {
    fn new() -> Self {
        // Pinned serde_json 1.0.151 ser.rs:2218 uses this initial capacity.
        let bytes = Vec::with_capacity(128);
        let capacities = vec![bytes.capacity()];
        Self { bytes, capacities }
    }
}

impl Write for OriginalVec {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let capacity = self.bytes.capacity();
        let written = self.bytes.write(bytes)?;
        if self.bytes.capacity() != capacity {
            self.capacities.push(self.bytes.capacity());
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.bytes.flush()
    }
}

#[derive(Serialize)]
struct Sample<'a> {
    prefix: &'a str,
    bytes: Bytes<'a>,
    suffix: &'a str,
    numbers: [i64; 4],
}

#[test]
fn native_cost_authentication_matches_original_bytes_mac_and_vec_growth() {
    let key = AuditKey::new([0x41; 32]).unwrap();
    let domain = b"synthetic/native-cost/v1\0";
    let mut cases = vec![Vec::new()];
    cases.extend((0..=255).map(|byte| vec![byte]));
    for length in [31, 32, 33, 63, 64, 65, 127, 128, 129, 511, 1024, 16_384] {
        for byte in [0, 9, 10, 99, 100, 255] {
            cases.push(vec![byte; length]);
        }
        cases.push((0..=255).cycle().take(length).collect());
    }
    let large_string = "x".repeat(777);
    for bytes in cases {
        for (prefix, suffix) in [
            ("\\\"\n\tλ", "end"),
            (large_string.as_str(), "tail"),
            ("head", large_string.as_str()),
        ] {
            let value = Sample {
                prefix,
                bytes: Bytes(&bytes),
                suffix,
                numbers: [i64::MIN, -1, 0, i64::MAX],
            };
            let original = serde_json::to_vec(&value).unwrap();
            let mut allocation_oracle = OriginalVec::new();
            serde_json::to_writer(&mut allocation_oracle, &value).unwrap();
            assert_eq!(allocation_oracle.bytes, original);
            assert_eq!(allocation_oracle.bytes.capacity(), original.capacity());
            let (actual, observation) = observe(|| authenticate(&key, domain, &value));
            assert_eq!(
                actual.unwrap(),
                original_mac(&key, domain, &value),
                "NATIVE_COST_ORIGINAL_MAC"
            );
            assert_eq!(
                observation.authentication_bytes, original,
                "NATIVE_COST_ORIGINAL_BYTES"
            );
            assert_eq!(observation.authentication_capacities[0], 128);
            assert_eq!(
                observation.authentication_capacities, allocation_oracle.capacities,
                "NATIVE_COST_ORIGINAL_VEC_GROWTH"
            );
        }
    }
}

#[test]
fn native_cost_authentication_is_single_pass_and_rejects_tampering() {
    struct Once<'a>(&'a Cell<usize>);
    impl Serialize for Once<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let count = self.0.get();
            self.0.set(count + 1);
            if count != 0 {
                return Err(serde::ser::Error::custom("second serialization refused"));
            }
            serializer.serialize_bytes(&[0, 9, 10, 99, 100, 255])
        }
    }
    struct Refused;
    impl Serialize for Refused {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("synthetic refusal"))
        }
    }
    let key = AuditKey::new([0x41; 32]).unwrap();
    let domain = b"synthetic/native-cost/v1\0";
    let calls = Cell::new(0);
    let expected = original_mac(&key, domain, &Bytes(&[0, 9, 10, 99, 100, 255]));
    assert_eq!(authenticate(&key, domain, &Once(&calls)).unwrap(), expected);
    assert_eq!(calls.get(), 1, "NATIVE_COST_ONE_SERIALIZATION");
    assert!(matches!(
        authenticate(&key, domain, &Refused),
        Err(AuditAuthorityError::InvalidInput)
    ));
    let value = Bytes(&[0, 9, 10, 99, 100, 255]);
    verify(&key, domain, &value, &expected).unwrap();
    assert!(verify(
        &AuditKey::new([0x42; 32]).unwrap(),
        domain,
        &value,
        &expected
    )
    .is_err());
    assert!(verify(&key, b"synthetic/other/v1\0", &value, &expected).is_err());
    assert!(verify(&key, domain, &Bytes(&[0, 9, 10, 99, 100, 254]), &expected).is_err());
    let mut corrupt_mac = expected;
    corrupt_mac[0] ^= 1;
    assert!(verify(&key, domain, &value, &corrupt_mac).is_err());
    // Domain and exact BE length prefix are part of the independent oracle.
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut wrong_length = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes()).unwrap();
    wrong_length.update(domain);
    wrong_length.update(&((bytes.len() as u64) + 1).to_be_bytes());
    wrong_length.update(&bytes);
    let wrong_length: [u8; 32] = wrong_length.finalize().into_bytes().into();
    assert!(verify(&key, domain, &value, &wrong_length).is_err());
}

#[test]
fn native_cost_authentication_preserves_existing_state_byte_fence() {
    let key = AuditKey::new([0x41; 32]).unwrap();
    let domain = b"synthetic/native-cost/v1\0";
    let mut value = "x".repeat(MAX_STATE_BYTES - 2);
    assert_eq!(serde_json::to_vec(&value).unwrap().len(), MAX_STATE_BYTES);
    assert_eq!(
        authenticate(&key, domain, &value).unwrap(),
        original_mac(&key, domain, &value)
    );
    value.push('x');
    assert_eq!(
        serde_json::to_vec(&value).unwrap().len(),
        MAX_STATE_BYTES + 1
    );
    assert!(matches!(
        authenticate(&key, domain, &value),
        Err(AuditAuthorityError::InvalidInput)
    ));
    // This qualifies the existing result fence, not a preallocation/heap bound.
}

#[test]
fn native_cost_authentication_bounds_actual_sink_work() {
    let key = AuditKey::new([0x41; 32]).unwrap();
    let value: Vec<u8> = (0..=255).cycle().take(65_536).collect();
    let original = serde_json::to_vec(&value).unwrap();
    let (actual, observation) = observe(|| authenticate(&key, b"synthetic/cost\0", &Bytes(&value)));
    assert_eq!(
        actual.unwrap(),
        original_mac(&key, b"synthetic/cost\0", &Bytes(&value))
    );
    assert_eq!(observation.authentication_bytes, original);
    let writes = observation.stage(Stage::Authentication);
    assert_eq!(writes.bytes, original.len());
    assert!(writes.largest <= 128, "NATIVE_COST_AUTH_BATCH_BOUND");
    assert!(
        writes.calls <= 2 + original.len().div_ceil(124),
        "NATIVE_COST_AUTH_SINK_WORK_RED: {} calls for {} bytes",
        writes.calls,
        writes.bytes
    );
    // The original default byte-array serializer performs two writes per byte.
    eprintln!(
        "NATIVE_COST_AUTH_SINK_WORK calls={} bytes={}",
        writes.calls, writes.bytes
    );
}
