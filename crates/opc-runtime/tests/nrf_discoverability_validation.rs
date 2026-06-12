use opc_runtime::profile::RuntimeProfile;
use opc_runtime::shutdown::DrainHook;
use opc_runtime::Builder;
use std::sync::Arc;

struct DummyNrfDrainHook;

#[async_trait::async_trait]
impl DrainHook for DummyNrfDrainHook {
    fn name(&self) -> &'static str {
        "NrfDrainHook"
    }

    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[tokio::test]
async fn test_nrf_discoverability_validation_all_modes_and_nfs() {
    let target_nfs = vec!["amf", "smf", "upf"];
    let other_nfs = vec!["nrf", "udm", "nssf", "ausf"];

    // 1. Confirm that Registering an NrfDrainHook allows production bootstrap of AMF/SMF/UPF runtime to succeed.
    for nf in &target_nfs {
        let mut profile = RuntimeProfile::production(*nf, uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget::default());
        assert!(
            profile.requires_nrf_drain_hook,
            "Profile for {nf} must require NrfDrainHook"
        );

        let result = Builder::new(profile)
            .with_drain_hook(Arc::new(DummyNrfDrainHook))
            .build()
            .await;

        assert!(
            result.is_ok(),
            "Production bootstrap for {} must succeed when NrfDrainHook is registered, got: {:?}",
            nf,
            result.err()
        );
        let handle = result.unwrap();
        handle.shutdown().await;
    }

    // 2. Confirm that Omitting NrfDrainHook in AMF/SMF/UPF runtime causes bootstrap to fail in production/conformance mode.
    for nf in &target_nfs {
        // Production Mode
        let mut profile_prod = RuntimeProfile::production(*nf, uuid::Uuid::new_v4());
        profile_prod.budget = Some(opc_runtime::ResourceBudget::default());
        let result_prod = Builder::new(profile_prod).build().await;
        assert!(
            result_prod.is_err(),
            "Production bootstrap for {nf} must fail when NrfDrainHook is omitted"
        );
        let err_prod = result_prod.unwrap_err().to_string();
        assert!(
            err_prod.contains("missing required drain hook: NrfDrainHook"),
            "Expected MissingRequiredDrainHook error message, got: {err_prod}"
        );

        // Conformance Mode
        let profile_conf = RuntimeProfile::conformance(*nf);
        let result_conf = Builder::new(profile_conf).build().await;
        assert!(
            result_conf.is_err(),
            "Conformance bootstrap for {nf} must fail when NrfDrainHook is omitted"
        );
        let err_conf = result_conf.unwrap_err().to_string();
        assert!(
            err_conf.contains("missing required drain hook: NrfDrainHook"),
            "Expected MissingRequiredDrainHook error message, got: {err_conf}"
        );
    }

    // 3. Confirm that Omitting NrfDrainHook in AMF/SMF/UPF runtime succeeds in dev mode.
    for nf in &target_nfs {
        let profile = RuntimeProfile::dev(*nf);
        let result = Builder::new(profile).build().await;
        assert!(
            result.is_ok(),
            "Dev bootstrap for {nf} must succeed when NrfDrainHook is omitted"
        );
        let handle = result.unwrap();
        handle.shutdown().await;
    }

    // 4. Confirm that other NFs do not require NrfDrainHook in production mode.
    for nf in &other_nfs {
        let mut profile = RuntimeProfile::production(*nf, uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget::default());
        assert!(
            !profile.requires_nrf_drain_hook,
            "Profile for {nf} must not require NrfDrainHook"
        );

        let result = Builder::new(profile).build().await;
        assert!(
            result.is_ok(),
            "Production bootstrap for {nf} must succeed without NrfDrainHook"
        );
        let handle = result.unwrap();
        handle.shutdown().await;
    }
}
