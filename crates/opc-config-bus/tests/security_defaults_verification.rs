use async_trait::async_trait;
use opc_alarm::SharedAlarmManager;
use opc_config_bus::{
    AuthorizationContext, AuthorizationError, ConfigAuthorizer, ConfigBus, MockManagedDatastore,
};
use opc_config_model::{ConfigError, OpcConfig, ValidationContext, ValidationError, YangPath};
use opc_types::SchemaDigest;
use std::sync::Arc;

#[derive(Clone)]
struct MockConfig;

impl OpcConfig for MockConfig {
    type Delta = ();
    fn schema_digest(&self) -> SchemaDigest {
        use std::str::FromStr;
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap()
    }
    fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(vec![])
    }
    fn changed_paths(
        &self,
        _previous: &Self,
        _deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        Ok(vec![])
    }
    fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
        Ok(())
    }
    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

struct MockAuthorizer;
#[async_trait]
impl ConfigAuthorizer for MockAuthorizer {
    async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_production_constructors_with_mock_authorizer() {
    let initial = MockConfig;
    let authorizer = Arc::new(MockAuthorizer);

    // Test 1: ConfigBus::new
    {
        let store = MockManagedDatastore::new();
        let bus = ConfigBus::new(initial.clone(), store, authorizer.clone()).await;
        assert!(bus.is_ok());
    }

    // Test 2: ConfigBus::restore_or_new
    {
        let store = MockManagedDatastore::new();
        let bus = ConfigBus::restore_or_new(initial.clone(), store, authorizer.clone()).await;
        assert!(bus.is_ok());
    }

    // Test 3: ConfigBus::with_queue_capacity
    {
        let store = MockManagedDatastore::new();
        let bus =
            ConfigBus::with_queue_capacity(initial.clone(), store, 10, authorizer.clone()).await;
        assert!(bus.is_ok());
    }

    // Test 4: ConfigBus::new_with_alarm_manager
    {
        let store = MockManagedDatastore::new();
        let alarm_mgr = SharedAlarmManager::default();
        let bus = ConfigBus::new_with_alarm_manager(
            initial.clone(),
            store,
            authorizer.clone(),
            alarm_mgr,
        )
        .await;
        assert!(bus.is_ok());
    }

    // Test 5: ConfigBus::with_queue_capacity_and_alarm_manager
    {
        let store = MockManagedDatastore::new();
        let alarm_mgr = SharedAlarmManager::default();
        let bus = ConfigBus::with_queue_capacity_and_alarm_manager(
            initial.clone(),
            store,
            10,
            authorizer.clone(),
            alarm_mgr,
        )
        .await;
        assert!(bus.is_ok());
    }

    // Test 6: ConfigBus::restore_or_new_with_alarm_manager
    {
        let store = MockManagedDatastore::new();
        let alarm_mgr = SharedAlarmManager::default();
        let bus = ConfigBus::restore_or_new_with_alarm_manager(
            initial.clone(),
            store,
            authorizer.clone(),
            alarm_mgr,
        )
        .await;
        assert!(bus.is_ok());
    }
}
