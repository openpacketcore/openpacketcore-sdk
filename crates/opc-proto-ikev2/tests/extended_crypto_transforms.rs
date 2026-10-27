//! Executable transform contracts from RFC 3526 sections 4–7.

use opc_proto_ikev2::{Ikev2DhGroup, Ikev2EphemeralDhKey};

#[test]
fn modp_groups_15_through_18_agree_and_restore() {
    // Private checkpoint custody is separately opt-in, even for admitted DH.
    let mut requirements = opc_proto_ikev2::Ikev2CryptoRequirements::all_software_supported();
    for id in 15..=18 {
        let group = Ikev2DhGroup::from_transform_id(id).expect("RFC 3526 group");
        requirements.require_dh_checkpoint(group);
    }
    let policy = opc_crypto_provider::ProviderPolicy::new()
        .require_all(requirements.required_capabilities());
    let _admission = opc_proto_ikev2::install_ikev2_software_crypto_module(policy, requirements)
        .expect("admit groups and checkpoints");
    for (id, width) in [(15, 384), (16, 512), (17, 768), (18, 1024)] {
        let group = Ikev2DhGroup::from_transform_id(id).expect("RFC 3526 group");
        assert_eq!(group.transform_id(), id);
        assert_eq!(group.public_value_len(), width);
        assert_eq!(group.shared_secret_len(), width);
        let mut initiator = Ikev2EphemeralDhKey::generate(group).expect("initiator KE");
        let responder = Ikev2EphemeralDhKey::generate(group).expect("responder KE");
        let shared = initiator
            .agree(responder.public_value())
            .expect("agreement");
        assert_eq!(shared.len(), width);
        assert_eq!(shared, responder.agree(initiator.public_value()).unwrap());
        let checkpoint = initiator.export_private_checkpoint().expect("checkpoint");
        let restored = Ikev2EphemeralDhKey::import_private_checkpoint(
            group,
            &checkpoint,
            initiator.public_value(),
        )
        .expect("restored KE");
        assert_eq!(shared, restored.agree(responder.public_value()).unwrap());
        assert!(initiator.agree(&vec![0; width]).is_err());
        assert!(initiator.agree(&vec![0xff; width]).is_err());
        assert!(initiator.agree(&vec![2; width - 1]).is_err());
    }
}
