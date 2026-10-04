//! Reviewed #784 GRE bytes through the explicitly directional runtime codec.
use opc_n3iwf_fixtures::FixtureCatalog;
use opc_proto_gre::{Direction, NwuGrePacket, Qfi};
use opc_protocol::{DecodeContext, Encode, EncodeContext};

#[test]
fn reviewed_gre_subset_matches_the_runtime_boundary() {
    let catalog = FixtureCatalog::load().expect("catalog");
    let mut count = 0;
    for (manifest, wire) in catalog.manifests().filter(|(m, _)| m.subset == "gre-qfi") {
        count += 1;
        if manifest.encoding == "construction-argument" {
            assert_eq!(wire, &[64]);
            assert!(Qfi::new(wire[0]).is_err());
            continue;
        }
        let direction = match manifest.direction.as_str() {
            "ue-to-n3iwf" => Direction::Uplink,
            "n3iwf-to-ue" => Direction::Downlink,
            _ => panic!("fixture direction"),
        };
        let decoded = NwuGrePacket::decode(wire, direction, DecodeContext::default());
        if manifest.expected_outcome == "reject" {
            assert!(decoded.is_err());
        } else {
            let packet = decoded.expect("published admission");
            assert_eq!(packet.qos().qfi().value(), 9);
            assert_eq!(packet.payload(), &wire[8..]);
            let mut encoded = Default::default();
            packet
                .encode(&mut encoded, EncodeContext::default())
                .expect("canonical");
            let mut expected = wire.to_vec();
            expected[2..4].fill(0);
            assert_eq!(encoded.as_ref(), expected);
        }
    }
    assert_eq!(count, 8);
}
