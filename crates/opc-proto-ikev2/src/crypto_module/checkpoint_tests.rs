//! Process-isolated admission and hostile-output checks for private checkpoints.
//! Export refusal assertions discard unexpected successes before panicking: a
//! faulty provider must never make diagnostics render a secret-bearing buffer.

use super::*;
use opc_crypto_provider::CryptoOperationErrorCode as Code;

fn counts(module: &CountingModule) -> (usize, usize) {
    (
        module.counts.checkpoint_export.load(Ordering::SeqCst),
        module.counts.checkpoint_import.load(Ordering::SeqCst),
    )
}

fn operation_code(error: Ikev2SaInitCryptoError) -> Code {
    match error {
        Ikev2SaInitCryptoError::CryptoModuleFailure { error } => error.operation_code().unwrap(),
        _ => panic!("expected a stable provider operation code"),
    }
}

fn install(module: Arc<CountingModule>, requirements: Ikev2CryptoRequirements) {
    let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
    let _report = block_on(install_ikev2_crypto_module(module, policy, requirements)).unwrap();
}

#[test]
fn checkpoint_admission_faults_are_process_isolated() {
    for case in [
        "no-opt-in",
        "unsupported",
        "not-preflighted",
        "all-groups",
        "runtime-faults",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crypto_module::admission_tests::checkpoint_tests::checkpoint_module_child",
                "--nocapture",
            ])
            .env("OPC_DH_CHECKPOINT_CASE", case)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {case}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("CHECKPOINT_ADMISSION_COMPLETE"));
    }
}

#[test]
fn checkpoint_module_child() {
    let Ok(case) = std::env::var("OPC_DH_CHECKPOINT_CASE") else {
        return;
    };
    let group = Ikev2DhGroup::Ecp256;
    assert_eq!(
        Ikev2EphemeralDhKey::checkpoint_readiness(group)
            .unwrap_err()
            .code(),
        Ikev2CryptoModuleErrorCode::NotInstalled
    );
    let module = Arc::new(CountingModule::new());
    let mut requirements = Ikev2CryptoRequirements::all_software_supported();
    assert!(!requirements
        .required_capabilities()
        .contains(CryptoCapability::IkeDhCheckpoint));
    if case == "no-opt-in" {
        install(module.clone(), requirements);
        let mut key = Ikev2EphemeralDhKey::generate(group).unwrap();
        assert_module_failure(
            key.export_private_checkpoint().err().unwrap(),
            Ikev2CryptoModuleErrorCode::CapabilityNotAdmitted,
        );
        assert_module_failure(
            Ikev2EphemeralDhKey::import_private_checkpoint(group, &[], key.public_value())
                .unwrap_err(),
            Ikev2CryptoModuleErrorCode::CapabilityNotAdmitted,
        );
        assert_eq!(counts(&module), (0, 0));
        println!("CHECKPOINT_ADMISSION_COMPLETE");
        return;
    }
    requirements.require_dh_checkpoint(group);
    assert!(requirements
        .required_capabilities()
        .contains(CryptoCapability::IkeDhCheckpoint));
    assert!(!requirements
        .required_capabilities()
        .contains(CryptoCapability::SealedKeyStorage));
    if case == "unsupported" {
        module
            .reject_checkpoint_support
            .store(true, Ordering::SeqCst);
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        let object: Arc<dyn IkeCryptoModule> = module.clone();
        assert!(matches!(
            block_on(install_ikev2_crypto_module(
                object,
                policy,
                requirements.clone()
            )),
            Err(Ikev2CryptoModuleInstallError::AlgorithmUnsupported { .. })
        ));
        assert_eq!(counts(&module), (0, 0));
        module
            .reject_checkpoint_support
            .store(false, Ordering::SeqCst);
        module.set_advertised(
            module
                .capabilities()
                .without(CryptoCapability::IkeDhCheckpoint),
        );
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        assert!(block_on(install_ikev2_crypto_module(
            module.clone(),
            policy,
            requirements
        ))
        .is_err());
        assert_eq!(counts(&module), (0, 0));
        println!("CHECKPOINT_ADMISSION_COMPLETE");
        return;
    }
    let groups = [
        Ikev2DhGroup::Modp768,
        Ikev2DhGroup::Modp1024,
        Ikev2DhGroup::Modp2048,
        Ikev2DhGroup::Ecp256,
        Ikev2DhGroup::Ecp384,
        Ikev2DhGroup::Ecp521,
    ];
    if case == "all-groups" {
        for group in groups {
            requirements.require_dh_checkpoint(group);
        }
    }
    install(module.clone(), requirements);
    if case == "all-groups" {
        for group in groups {
            Ikev2EphemeralDhKey::checkpoint_readiness(group).unwrap();
            let mut original = Ikev2EphemeralDhKey::generate(group).unwrap();
            let peer = Ikev2EphemeralDhKey::generate(group).unwrap();
            let public = original.public_value().to_vec();
            let checkpoint = original.export_private_checkpoint().unwrap();
            drop(original);
            let imported =
                Ikev2EphemeralDhKey::import_private_checkpoint(group, &checkpoint, &public)
                    .unwrap();
            assert!(
                imported.agree(peer.public_value()).unwrap().as_slice()
                    == peer.agree(&public).unwrap().as_slice()
            );
        }
        assert_eq!(counts(&module), (6, 6));
        println!("CHECKPOINT_ADMISSION_COMPLETE");
        return;
    }
    if case == "not-preflighted" {
        let mut key = Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp384).unwrap();
        assert_eq!(
            Ikev2EphemeralDhKey::checkpoint_readiness(Ikev2DhGroup::Ecp384)
                .unwrap_err()
                .code(),
            Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted
        );
        assert_module_failure(
            key.export_private_checkpoint().err().unwrap(),
            Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted,
        );
        assert_module_failure(
            Ikev2EphemeralDhKey::import_private_checkpoint(
                Ikev2DhGroup::Ecp384,
                &[],
                key.public_value(),
            )
            .unwrap_err(),
            Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted,
        );
        assert_eq!(counts(&module), (0, 0));
        println!("CHECKPOINT_ADMISSION_COMPLETE");
        return;
    }
    assert_eq!(case, "runtime-faults");
    Ikev2EphemeralDhKey::checkpoint_readiness(group).unwrap();
    let mut key = Ikev2EphemeralDhKey::generate(group).unwrap();
    let peer = Ikev2EphemeralDhKey::generate(group).unwrap();
    let public = key.public_value().to_vec();
    module.checkpoint_fault.store(1, Ordering::SeqCst);
    assert_eq!(
        operation_code(key.export_private_checkpoint().err().unwrap()),
        Code::Unavailable
    );
    module.checkpoint_fault.store(0, Ordering::SeqCst);
    let checkpoint = key.export_private_checkpoint().unwrap();
    assert_eq!(counts(&module), (2, 0));
    assert_eq!(
        operation_code(key.export_private_checkpoint().err().unwrap()),
        Code::CheckpointAlreadyExported
    );
    assert_eq!(counts(&module), (2, 0));
    drop(key);
    module.checkpoint_fault.store(1, Ordering::SeqCst);
    assert_eq!(
        operation_code(
            Ikev2EphemeralDhKey::import_private_checkpoint(group, &checkpoint, &public)
                .unwrap_err()
        ),
        Code::Unavailable
    );
    module.checkpoint_fault.store(0, Ordering::SeqCst);
    let mut imported =
        Ikev2EphemeralDhKey::import_private_checkpoint(group, &checkpoint, &public).unwrap();
    assert_eq!(counts(&module), (2, 2));
    assert!(
        imported.agree(peer.public_value()).unwrap().as_slice()
            == peer.agree(&public).unwrap().as_slice()
    );
    assert_eq!(
        operation_code(imported.export_private_checkpoint().err().unwrap()),
        Code::CheckpointAlreadyExported
    );
    assert_eq!(counts(&module), (2, 2));

    for fault in [2, 3, 4] {
        let mut key = Ikev2EphemeralDhKey::generate(group).unwrap();
        module.checkpoint_fault.store(fault, Ordering::SeqCst);
        assert_module_failure(
            key.export_private_checkpoint().err().unwrap(),
            Ikev2CryptoModuleErrorCode::InvalidOutput,
        );
    }
    module.checkpoint_fault.store(0, Ordering::SeqCst);
    for fault in [
        MalformedOutput::DhGroup,
        MalformedOutput::DhPublic,
        MalformedOutput::DhSemanticPublic,
    ] {
        module.set_malformed_output(fault);
        assert_module_failure(
            Ikev2EphemeralDhKey::import_private_checkpoint(group, &checkpoint, &public)
                .unwrap_err(),
            Ikev2CryptoModuleErrorCode::InvalidOutput,
        );
    }
    module.set_malformed_output(MalformedOutput::None);

    for withdrawal in [0, 1, 2] {
        let mut key = Ikev2EphemeralDhKey::generate(group).unwrap();
        let before = counts(&module);
        if withdrawal == 0 {
            module.set_serviceable(
                module
                    .capabilities()
                    .without(CryptoCapability::IkeDhCheckpoint),
            );
        } else if withdrawal == 1 {
            module.set_advertised(
                module
                    .capabilities()
                    .without(CryptoCapability::IkeDhCheckpoint),
            );
        } else {
            module
                .reject_checkpoint_support
                .store(true, Ordering::SeqCst);
        }
        let expected = if withdrawal == 2 {
            Ikev2CryptoModuleErrorCode::AlgorithmUnsupported
        } else {
            Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
        };
        assert_eq!(
            Ikev2EphemeralDhKey::checkpoint_readiness(group)
                .unwrap_err()
                .code(),
            expected
        );
        assert_module_failure(key.export_private_checkpoint().err().unwrap(), expected);
        assert_module_failure(
            Ikev2EphemeralDhKey::import_private_checkpoint(group, &checkpoint, &public)
                .unwrap_err(),
            expected,
        );
        assert_eq!(counts(&module), before);
        module.set_serviceable(module.capabilities());
        module.set_advertised(module.capabilities());
        module
            .reject_checkpoint_support
            .store(false, Ordering::SeqCst);
    }
    for malformed in [&[][..], &checkpoint[..checkpoint.len() - 1]] {
        let before = counts(&module);
        assert_eq!(
            operation_code(
                Ikev2EphemeralDhKey::import_private_checkpoint(group, malformed, &public)
                    .unwrap_err()
            ),
            Code::InvalidCheckpoint
        );
        assert_eq!(counts(&module), before);
    }
    for changed in [0, 2] {
        let mut invalid = checkpoint.clone();
        invalid[changed] ^= 1;
        let before = counts(&module);
        assert_eq!(
            operation_code(
                Ikev2EphemeralDhKey::import_private_checkpoint(group, &invalid, &public)
                    .unwrap_err()
            ),
            Code::InvalidCheckpoint
        );
        assert_eq!(counts(&module), before);
    }
    for diagnostic in [
        format!("{imported:?}"),
        Code::Unavailable.to_string(),
        format!("{:?}", Code::CheckpointPublicValueMismatch),
    ] {
        assert!(!diagnostic.contains(HOSTILE_PROVIDER_DIAGNOSTIC));
    }
    println!("CHECKPOINT_ADMISSION_COMPLETE");
}
