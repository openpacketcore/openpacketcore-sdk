#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{FqCsid, RawIe};

fuzz_target!(|data: &[u8]| {
    if let Ok((_, raw)) = RawIe::decode(data) {
        if let Ok(Some(value)) = FqCsid::decode_from_raw(&raw) {
            let canonical = value.to_raw_ie(raw.instance).unwrap();
            assert_eq!(canonical.spare, 0);
            let mut wire = BytesMut::new();
            canonical.encode(&mut wire).unwrap();
            let (tail, decoded) = RawIe::decode(&wire).unwrap();
            assert!(tail.is_empty());
            assert_eq!(FqCsid::decode_from_raw(&decoded), Ok(Some(value)));
        }
    }
});
