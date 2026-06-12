//! NRF registration/heartbeat/deregister test using the SBI testkit mock.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use opc_sbi::nrf::{HeartbeatDriver, NfProfile, NfStatus, NrfOperations};
use opc_sbi::testkit::MockNrf;
use opc_types::{NfInstanceId, NfType, PlmnId, Snssai};
use tokio::sync::watch;

fn sample_profile(id: &str) -> NfProfile {
    NfProfile {
        nf_instance_id: NfInstanceId::new(id).expect("valid instance id"),
        nf_type: NfType::new("smf").expect("valid nf type"),
        nf_status: NfStatus::Registered,
        ipv4_addresses: vec!["127.0.0.1".into()],
        fqdn: None,
        plmn_list: vec![PlmnId::new("001", "01").expect("valid plmn")],
        s_nssais: vec![Snssai::new(1, Some("010203")).expect("valid snssai")],
        nf_services: vec!["nsmf-pdusession".into()],
        priority: 10,
        capacity: 100,
    }
}

#[tokio::test]
async fn mock_nrf_register_heartbeat_deregister() {
    let nrf: Arc<dyn NrfOperations> = Arc::new(MockNrf::new());
    let profile = sample_profile("smf-ref-01");
    let instance_id = profile.nf_instance_id.clone();

    let interval = NrfOperations::register(nrf.as_ref(), &profile)
        .await
        .expect("register succeeds");
    assert_eq!(interval, Duration::from_secs(5));

    let instance_id_clone = instance_id.clone();
    let heartbeat_ok = NrfOperations::heartbeat(nrf.as_ref(), &instance_id_clone).await;
    assert!(heartbeat_ok.is_ok());

    let deregister_ok = NrfOperations::deregister(nrf.as_ref(), &instance_id).await;
    assert!(deregister_ok.is_ok());

    // After deregistration, heartbeats are rejected as NotFound.
    let heartbeat_after = NrfOperations::heartbeat(nrf.as_ref(), &instance_id).await;
    assert!(heartbeat_after.is_err());
}

#[tokio::test]
async fn heartbeat_driver_runs_and_deregisters_on_shutdown() {
    let nrf: Arc<dyn NrfOperations> = Arc::new(MockNrf::new());
    let profile = sample_profile("smf-ref-02");
    let instance_id = profile.nf_instance_id.clone();

    NrfOperations::register(nrf.as_ref(), &profile)
        .await
        .expect("register succeeds");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (degraded_tx, _degraded_rx) = watch::channel(false);

    let driver = HeartbeatDriver::new(
        nrf.clone(),
        instance_id.clone(),
        Duration::from_millis(100),
        shutdown_rx,
        degraded_tx,
    );

    let driver_handle = tokio::spawn(driver.run());

    // Let a heartbeat fire.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(NrfOperations::heartbeat(nrf.as_ref(), &instance_id)
        .await
        .is_ok());

    // Signal shutdown; the driver should deregister before exiting.
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), driver_handle)
        .await
        .expect("driver exits");

    assert!(NrfOperations::heartbeat(nrf.as_ref(), &instance_id)
        .await
        .is_err());
}
