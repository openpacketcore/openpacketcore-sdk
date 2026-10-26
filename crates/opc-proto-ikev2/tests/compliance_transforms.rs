use opc_proto_ikev2::{Ikev2DhGroup, Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalOffer};

mod support;

#[test]
fn rfc3526_groups_15_through_18_have_exact_wire_widths() {
    for (id, width) in [(15, 384), (16, 512), (17, 768), (18, 1024)] {
        let group = Ikev2DhGroup::from_transform_id(id).expect("RFC 3526 group");
        assert_eq!(group.transform_id(), id);
        assert_eq!(group.public_value_len(), width);
        assert_eq!(group.shared_secret_len(), width);
    }
}

#[test]
fn sha512_and_identity_offers_have_executable_algorithms() {
    support::ensure_ike_crypto();
    for hash in [
        Ikev2SignatureHashAlgorithm::Sha2_512,
        Ikev2SignatureHashAlgorithm::Identity,
    ] {
        let offer = Ikev2SignatureHashLocalOffer::new(&[hash]).expect("executable hash offer");
        assert_eq!(offer.algorithms(), &[hash]);
    }
}
