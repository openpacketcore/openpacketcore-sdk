//! Minimal CNF using the OpenPacketCore SDK.
//!
//! This example demonstrates:
//! 1. Runtime chassis startup with health endpoints.
//! 2. Mock NRF registration (SBI testkit).
//! 3. Alarm raise and clear.
//! 4. Graceful drain on SIGTERM.
//!
//! Run with: `cargo run -p opc-sdk --example minimal_cnf --features testkit`

use std::net::SocketAddr;
use std::time::Duration;

use opc_sdk::opc_alarm::{
    AffectedObject, AlarmDetails, AlarmType, ProbableCause, RedactedText, Severity,
};
use opc_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ------------------------------------------------------------------
    // 1. Runtime profile and chassis startup
    // ------------------------------------------------------------------
    let profile = RuntimeProfile::dev("minimal-cnf");
    let alarms = SharedAlarmManager::default();

    let handle = Builder::new(profile.clone())
        .with_alarm_manager(alarms.clone())
        .build()
        .await?;

    tracing::info!("Runtime reached phase {:?}", handle.phase().await);

    // ------------------------------------------------------------------
    // 2. Admin server (health probes)
    // ------------------------------------------------------------------
    let admin_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let admin_handle = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = opc_sdk::opc_runtime::admin::start_admin_server(
            admin_handle,
            admin_addr,
            profile.mode,
            None,
        )
        .await
        {
            tracing::error!("Admin server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // ------------------------------------------------------------------
    // 3. Mock NRF registration
    // ------------------------------------------------------------------
    let nrf = opc_sdk::opc_sbi::testkit::MockNrf::new();
    let nf_profile = opc_sdk::opc_sbi::nrf::NfProfile {
        nf_instance_id: NfInstanceId::new("minimal-cnf-01").unwrap(),
        nf_type: NfType::new("amf").unwrap(),
        nf_status: opc_sdk::opc_sbi::nrf::NfStatus::Registered,
        ipv4_addresses: vec!["127.0.0.1".into()],
        fqdn: None,
        plmn_list: vec![],
        s_nssais: vec![],
        nf_services: vec![],
        priority: 10,
        capacity: 100,
    };
    nrf.register(nf_profile)?;
    tracing::info!("Registered with mock NRF");

    // ------------------------------------------------------------------
    // 4. Raise and clear an alarm
    // ------------------------------------------------------------------
    let affected = AffectedObject::NfInstance {
        kind: "minimal-cnf".into(),
        instance: "minimal-cnf-01".into(),
    };
    alarms.raise(
        AlarmType::new("minimal-cnf.test.alarm"),
        Severity::Warning,
        ProbableCause::Other("test".into()),
        affected.clone(),
        Some("system".into()),
        None,
        None,
        RedactedText::new("test alarm raised"),
        AlarmDetails::empty(),
    );
    tracing::info!("Alarm raised");

    alarms.clear(
        &AlarmType::new("minimal-cnf.test.alarm"),
        ProbableCause::Other("test".into()),
        &affected,
        Some("system"),
        None,
        None,
    );
    tracing::info!("Alarm cleared");

    // ------------------------------------------------------------------
    // 5. Wait for SIGTERM (or a 5 s timeout for demo)
    // ------------------------------------------------------------------
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
            _ = sigint.recv() => tracing::info!("Received SIGINT"),
            _ = tokio::time::sleep(Duration::from_secs(5)) => tracing::info!("Demo timeout reached"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    tracing::info!("Initiating graceful drain...");
    handle.shutdown_token().request_shutdown();
    // Wait briefly for drain to complete in demo mode.
    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("Drain complete. Exiting.");

    Ok(())
}
