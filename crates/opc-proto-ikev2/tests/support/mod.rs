use std::sync::OnceLock;

use opc_crypto_provider::ProviderPolicy;
use opc_proto_ikev2::{install_ikev2_software_crypto_module, Ikev2CryptoRequirements};

pub(crate) fn ensure_ike_crypto() {
    static INSTALL: OnceLock<Result<(), &'static str>> = OnceLock::new();
    let result = INSTALL.get_or_init(|| {
        let requirements = Ikev2CryptoRequirements::all_software_supported();
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        install_ikev2_software_crypto_module(policy, requirements)
            .map(|_| ())
            .map_err(|_| "explicit IKEv2 software module admission failed")
    });
    if let Err(message) = result {
        panic!("{message}");
    }
}
