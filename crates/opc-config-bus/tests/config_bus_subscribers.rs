use std::sync::Arc;
use std::time::{Duration, Instant};

use opc_config_bus::{ConfigBus, ConfigEvent, ConfigSnapshot, SubscriberLagPolicy};
use opc_types::ConfigVersion;

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_oldest_lag_policy_stays_bounded() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    for name in ["v1", "v2", "v3"] {
        bus.submit(
            commit_request(name, Instant::now() + Duration::from_secs(1))
                .with_base_version(bus.version()),
        )
        .await
        .expect("commit succeeds");
    }

    assert_eq!(subscriber.len(), 1);
    match subscriber.try_recv().expect("one queued event") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(3));
            assert_eq!(change.current.name, "v3");
        }
        ConfigEvent::ResyncRequired { .. } => panic!("expected direct change event"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_newest_lag_policy_stays_bounded() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropNewest, 1);

    bus.submit(
        commit_request("v1", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("first commit succeeds");
    bus.submit(
        commit_request("v2", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("second commit succeeds");

    assert_eq!(subscriber.len(), 1);
    assert!(!subscriber.is_empty());
    match subscriber.try_recv().expect("first event retained") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(1));
            assert_eq!(change.current.name, "v1");
        }
        ConfigEvent::ResyncRequired { .. } => panic!("expected direct change event"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_on_lag_policy_closes_receiver() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DisconnectOnLag, 1);

    bus.submit(
        commit_request("v1", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("first commit succeeds");
    bus.submit(
        commit_request("v2", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("second commit succeeds");

    assert!(subscriber.is_closed());
    assert_eq!(subscriber.len(), 1);
    assert!(matches!(
        subscriber.try_recv(),
        Some(ConfigEvent::Change(change)) if change.version == ConfigVersion::new(1)
    ));
    assert!(subscriber.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn force_resync_lag_policy_stays_bounded() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::ForceResync, 1);

    bus.submit(
        commit_request("v1", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("first commit succeeds");
    bus.submit(
        commit_request("v2", Instant::now() + Duration::from_secs(1))
            .with_base_version(bus.version()),
    )
    .await
    .expect("second commit succeeds");

    assert_eq!(subscriber.len(), 1);
    match subscriber.try_recv().expect("single resync event queued") {
        ConfigEvent::ResyncRequired { latest_version } => {
            assert_eq!(latest_version, ConfigVersion::new(2));
        }
        ConfigEvent::Change(_) => panic!("expected resync marker"),
    }
    assert!(subscriber.is_empty());
}
