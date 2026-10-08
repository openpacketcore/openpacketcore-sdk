//! CBC provider admission and private byte checks, without persisted epochs.

use std::process::Command;

use super::{
    block_on, install_ikev2_crypto_module, policy, Arc, CountingModule, CryptoCapability,
    Ikev2CryptoRequirements, Ikev2EncryptionAlgorithm as Encryption, Ordering,
};
use crate::crypto_module::canonical_module_declares_validation;
use crate::{
    canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as Error,
        Ikev2CanonicalPolicy as Policy,
    },
    Ikev2DhGroup, Ikev2IntegrityAlgorithm as Integrity, Ikev2PrfAlgorithm as Prf,
    Ikev2SaInitCryptoProfile as Profile,
};

const CBC: [Encryption; 3] = [
    Encryption::AesCbc128,
    Encryption::AesCbc192,
    Encryption::AesCbc256,
];

#[test]
fn cbc_validation_inspection_accepts_admitted_ciphers_and_preserves_module_policy() {
    for case in ["unvalidated", "validated"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto_module::admission_tests::cbc_tests::cbc_module_child",
                "--nocapture",
            ])
            .env("OPC_CBC_PRIMITIVE_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "CBC case {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed")
        );
    }
}

#[test]
fn cbc_preflight_checks_the_whole_profile_and_retains_validated_opt_in() {
    for case in ["cbc-preflight", "cbc-preflight-validated"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto_module::admission_tests::cbc_tests::cbc_module_child",
                "--nocapture",
            ])
            .env("OPC_CBC_PRIMITIVE_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed")
        );
    }
}

#[test]
fn cbc_provider_iv_fault_is_withheld_and_failed_qualification_stays_latched() {
    for case in ["cbc-iv-fault", "cbc-qualification-fault", "cbc-mac-entropy"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto_module::admission_tests::cbc_tests::cbc_module_child",
                "--nocapture",
            ])
            .env("OPC_CBC_PRIMITIVE_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed; 0 failed")
        );
    }
}

fn cbc_profile(encryption: Encryption) -> Profile {
    Profile::new_encrypt_then_mac(
        Prf::HmacSha2_256,
        Ikev2DhGroup::Modp2048,
        encryption,
        Integrity::HmacSha2_256_128,
    )
    .unwrap()
}

fn provider_iv_fault_is_withheld(module: &CountingModule) {
    use crate::canonical::cbc::{Inputs, Recipe};
    let sk_d: Vec<_> = (0xd0..0xf0).collect();
    let sk_e: Vec<_> = (0..16).collect();
    let sk_a: Vec<_> = (0x80..0xa0).collect();
    let recipe = Recipe::new(Inputs {
        initiator_spi: 0x0102_0304_0506_0708,
        responder_spi: 0x1112_1314_1516_1718,
        direction: crate::Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        profile: cbc_profile(Encryption::AesCbc128),
        sk_d: &sk_d,
        sk_e: &sk_e,
        sk_a: &sk_a,
    })
    .unwrap();
    let expected = recipe.seal(0x1234_5678).unwrap();
    module.canonical_cbc_iv_fault.store(true, Ordering::SeqCst);
    assert_eq!(recipe.seal(0x1234_5678), Err(Error::InvalidOutput));
    assert_eq!(module.canonical_cbc_iv_faults.load(Ordering::SeqCst), 1);
    module.canonical_cbc_iv_fault.store(false, Ordering::SeqCst);
    assert_eq!(recipe.seal(0x1234_5678).unwrap(), expected);
    assert_eq!(module.counts.entropy.load(Ordering::SeqCst), 0);
}

fn qualification_failure_is_latched(module: &CountingModule) {
    let profile = cbc_profile(Encryption::AesCbc128);
    module.canonical_cbc_iv_fault.store(true, Ordering::SeqCst);
    assert_eq!(
        Canonical::preflight_cbc(profile, Policy::default()),
        Err(Error::QualificationFailed)
    );
    assert_eq!(module.canonical_cbc_iv_faults.load(Ordering::SeqCst), 1);
    module.canonical_cbc_iv_fault.store(false, Ordering::SeqCst);
    let before = module.counts.snapshot();
    assert_eq!(
        Canonical::preflight_cbc(profile, Policy::default()),
        Err(Error::QualificationFailed)
    );
    assert_eq!(module.counts.snapshot(), before);
    Canonical::preflight_cbc(cbc_profile(Encryption::AesCbc192), Policy::default()).unwrap();
    assert_eq!(module.counts.entropy.load(Ordering::SeqCst), 0);
}

fn mac_precedes_traffic_decrypt_and_ordinary_sealing_draws_one_iv(module: &CountingModule) {
    use crate::{
        canonical::cbc::{Inputs, Recipe},
        derive_ike_sa_init_key_material, seal_ikev2_sa_init_aes_cbc_protected_payload,
        Ikev2ProtectedPayloadDirection as Direction, ProtectedPayloadKind,
        ProtectedPayloadSealContext,
    };
    let profile = cbc_profile(Encryption::AesCbc128);
    let keys = derive_ike_sa_init_key_material(
        profile,
        1_u64.to_be_bytes(),
        2_u64.to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        None,
    )
    .unwrap();
    let recipe = Recipe::new(Inputs {
        initiator_spi: 1,
        responder_spi: 2,
        direction: Direction::InitiatorToResponder,
        profile,
        sk_d: keys.sk_d(),
        sk_e: keys.sk_ei(),
        sk_a: keys.sk_ai(),
    })
    .unwrap();
    let packet = recipe.seal(11).unwrap();
    assert_eq!(module.counts.entropy.load(Ordering::SeqCst), 0);
    let mut bad_mac = packet.clone();
    bad_mac[64] ^= 1;
    let before = module.counts.snapshot();
    assert_eq!(recipe.verify(11, &bad_mac), Err(Error::InvalidOutput));
    let after = module.counts.snapshot();
    assert_eq!(after[3] - before[3], 1, "one admitted MAC verification");
    assert_eq!(
        after[4] - before[4],
        1,
        "IV inverse only; no traffic decrypt"
    );
    module.sync_entropy_mode.store(1, Ordering::SeqCst);
    for iv_byte in [0, 0xff, 0xa5] {
        module.sync_entropy_byte.store(iv_byte, Ordering::SeqCst);
        let before = module.counts.snapshot();
        let entropy_bytes = module.counts.entropy_bytes.load(Ordering::SeqCst);
        let body = seal_ikev2_sa_init_aes_cbc_protected_payload(
            profile,
            &keys,
            Direction::InitiatorToResponder,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &packet[..32],
            },
            &[],
        )
        .unwrap();
        let after = module.counts.snapshot();
        assert_eq!(&body[..16], &[iv_byte; 16]);
        assert_eq!(
            after[1] - before[1],
            1,
            "one entropy draw, no rejection loop"
        );
        assert_eq!(
            module.counts.entropy_bytes.load(Ordering::SeqCst) - entropy_bytes,
            16
        );
        assert_eq!(after[2], before[2], "ordinary traffic derives no IV key");
        assert_eq!(
            after[4] - before[4],
            1,
            "one encrypt and no inverse/decrypt"
        );
    }
}

#[test]
fn cbc_module_child() {
    let Ok(case) = std::env::var("OPC_CBC_PRIMITIVE_CASE") else {
        return;
    };
    let declared = case == "validated" || case == "cbc-preflight-validated";
    let module = Arc::new(CountingModule::new());
    module.drift_validation.store(declared, Ordering::SeqCst);
    let requirements = Ikev2CryptoRequirements::all_software_supported();
    let _report = block_on(install_ikev2_crypto_module(
        module.clone(),
        policy(&requirements),
        requirements,
    ))
    .unwrap();

    match case.as_str() {
        "cbc-iv-fault" => return provider_iv_fault_is_withheld(&module),
        "cbc-qualification-fault" => return qualification_failure_is_latched(&module),
        "cbc-mac-entropy" => {
            return mac_precedes_traffic_decrypt_and_ordinary_sealing_draws_one_iv(&module)
        }
        _ => (),
    }

    if case.starts_with("cbc-preflight") {
        let profile = Profile::new_encrypt_then_mac(
            Prf::HmacSha2_256,
            Ikev2DhGroup::Modp2048,
            Encryption::AesCbc128,
            Integrity::HmacSha2_256_128,
        )
        .unwrap();
        let allowed = Policy::explicitly_allow_declared_validated();
        if declared {
            assert_eq!(
                Canonical::preflight_cbc(profile, Policy::default()),
                Err(Error::ValidationOptInRequired)
            );
        } else {
            Canonical::preflight_cbc(profile, Policy::default()).unwrap();
        }
        Canonical::preflight_cbc(profile, allowed).unwrap();
        let before = module.counts.snapshot();
        for capability in [
            CryptoCapability::IkeEncryption,
            CryptoCapability::IkeIntegrity,
            CryptoCapability::IkePrf,
        ] {
            module.set_serviceable(module.capabilities().without(capability));
            assert_eq!(
                Canonical::preflight_cbc(profile, allowed),
                Err(Error::Unavailable)
            );
            module.set_serviceable(module.capabilities());
            Canonical::preflight_cbc(profile, allowed).unwrap();
        }
        // No entropy is drawn, but the process-wide admission policy still
        // requires every granted capability to remain serviceable.
        module.set_serviceable(
            module
                .capabilities()
                .without(CryptoCapability::ApprovedEntropy),
        );
        assert_eq!(
            Canonical::preflight_cbc(profile, allowed),
            Err(Error::Unavailable)
        );
        module.set_serviceable(module.capabilities());
        module
            .reject_integrity_support
            .store(true, Ordering::SeqCst);
        assert_eq!(
            Canonical::preflight_cbc(profile, allowed),
            Err(Error::Unavailable)
        );
        module
            .reject_integrity_support
            .store(false, Ordering::SeqCst);
        module.reject_prf_support.store(true, Ordering::SeqCst);
        assert_eq!(
            Canonical::preflight_cbc(profile, allowed),
            Err(Error::Unavailable)
        );
        module.reject_prf_support.store(false, Ordering::SeqCst);
        Canonical::preflight_cbc(profile, allowed).unwrap();
        assert_eq!(
            module.counts.snapshot(),
            before,
            "cached admission executes no crypto"
        );
        assert_eq!(module.counts.entropy.load(Ordering::SeqCst), 0);
        return;
    }

    // K5: the validation declaration is a property of the admitted module;
    // an AEAD-only check must not reject an otherwise admitted CBC cipher.
    // Inspecting it neither qualifies a recipe nor grants canonical authority.
    let before = module.counts.snapshot();
    for encryption in CBC {
        assert_eq!(
            canonical_module_declares_validation(encryption).unwrap(),
            declared
        );
    }
    module.set_serviceable(
        module
            .capabilities()
            .without(CryptoCapability::IkeEncryption),
    );
    for encryption in CBC {
        assert!(canonical_module_declares_validation(encryption).is_err());
    }
    module.set_serviceable(module.capabilities());
    for encryption in CBC {
        assert_eq!(
            canonical_module_declares_validation(encryption).unwrap(),
            declared
        );
    }
    assert_eq!(module.counts.snapshot(), before);
}
