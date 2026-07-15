//! Stable-Rust regression replay for the TFT libFuzzer surfaces.

use std::panic::{catch_unwind, AssertUnwindSafe};

use bytes::BytesMut;
use opc_proto_tft::TrafficFlowTemplate;
use opc_protocol::DecodeContext;

const VALID_SEEDS: &[&[u8]] = &[
    &[0x00],
    &[0x40],
    &[0x21, 0x31, 0x20, 0x02, 0x30, 0x11],
    &[0xa2, 0x01, 0x02],
    &[0xd0, 0xfe, 0x01, 0xaa],
];

fn exercise(data: &[u8]) {
    let constrained = DecodeContext {
        max_message_len: 64,
        max_ies: 8,
        ..DecodeContext::conservative()
    };
    let _ = TrafficFlowTemplate::decode_value_with_context(data, constrained);

    if let Ok(value) = TrafficFlowTemplate::decode_value(data) {
        let mut encoded = BytesMut::new();
        assert!(value.encode_value(&mut encoded).is_ok());
        assert_eq!(encoded.as_ref(), data);
        assert_eq!(TrafficFlowTemplate::decode_value(&encoded), Ok(value));
    }
}

fn corpus_files() -> Vec<Vec<u8>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let mut files = Vec::new();
    let mut directories = vec![root];
    while let Some(directory) = directories.pop() {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                directories.push(path);
            } else if let Ok(bytes) = std::fs::read(path) {
                files.push(bytes);
            }
        }
    }
    files
}

#[test]
fn corpus_valid_fixtures_truncations_and_hostile_inputs_never_panic() {
    let corpus = corpus_files();
    assert!(!corpus.is_empty(), "committed TFT fuzz corpus is empty");

    let mut cases = corpus;
    cases.extend(VALID_SEEDS.iter().map(|seed| seed.to_vec()));
    cases.extend([
        Vec::new(),
        vec![0xff],
        vec![0; 256],
        vec![0xff; 256],
        (0..=u8::MAX).collect(),
    ]);

    for data in cases {
        assert!(
            catch_unwind(AssertUnwindSafe(|| exercise(&data))).is_ok(),
            "TFT replay panicked for a {}-octet input",
            data.len()
        );
        for cut in 0..data.len().min(256) {
            assert!(
                catch_unwind(AssertUnwindSafe(|| exercise(&data[..cut]))).is_ok(),
                "TFT replay panicked at truncation {cut} of {} octets",
                data.len()
            );
        }
    }
}
