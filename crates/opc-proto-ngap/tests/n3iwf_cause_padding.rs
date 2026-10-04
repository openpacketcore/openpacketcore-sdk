//! Independent root Causes must reject every nonzero unused final bit.
use opc_proto_ngap::n3iwf::release::Cause;
use opc_protocol::{DecodeContext, EncodeContext, ValidationLevel};
use serde_json::Value;

#[test]
fn independent_root_causes_reject_each_nonzero_padding_bit() {
    let oracle: Value = serde_json::from_str(include_str!("fixtures/n3iwf-release.json")).unwrap();
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let mut roots = 0;
    let mut mutations = 0;
    for row in oracle["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["type"] == "Cause")
    {
        let hex = row["wire_hex"].as_str().unwrap();
        let wire: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let value = Cause::decode(&wire, ctx).unwrap();
        assert!(value.encode(EncodeContext::default()).unwrap().as_bytes() == wire);
        let bits = 4 + match row["group"].as_str().unwrap() {
            "radioNetwork" => 6,
            "transport" => 1,
            "nas" => 2,
            _ => 3,
        };
        for bit in 0..wire.len() * 8 - bits {
            let mut changed = wire.clone();
            *changed.last_mut().unwrap() |= 1 << bit;
            assert!(
                Cause::decode(&changed, ctx).is_err(),
                "nonzero Cause padding admitted"
            );
            mutations += 1;
        }
        roots += 1;
    }
    assert_eq!(roots, 64);
    assert_eq!(mutations, 297);
}
