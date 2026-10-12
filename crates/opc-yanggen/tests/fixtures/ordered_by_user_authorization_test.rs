use std::sync::Arc;
use std::time::{Duration, Instant};

use generated_ordered_test::collections as model;
use model::types::Root;
use opc_config_bus::{ConfigBus, MockManagedDatastore};
use opc_config_model::{
    AuthStrength, CommitErrorCode, CommitRequest, ConfigOperation, OpcConfig, RequestId,
    RequestSource, TransportType, TrustedPrincipal, WorkloadIdentity, YangPath,
};
use opc_mgmt_authz::{AuthzError, ConfigWriteAuthorizer, PolicySource};
use opc_nacm::{ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern};
use opc_types::TenantId;
use serde_json::{json, Value};

#[derive(Clone)]
struct Policy(NacmPolicy);

impl PolicySource for Policy {
    fn active_policy(&self, _tenant: &str) -> Result<Arc<NacmPolicy>, AuthzError> {
        Ok(Arc::new(self.0.clone()))
    }
}

fn policy(leaf_only: bool) -> Policy {
    let mut modules = ModuleRegistry::new();
    modules
        .register_module("ordered-collections", "oc")
        .unwrap();
    let mut builder = NacmPolicy::builder(PolicyVersion::new(1));
    for action in [
        NacmAction::Create,
        NacmAction::Update,
        NacmAction::Replace,
        NacmAction::Delete,
    ] {
        for list in ["server", "system-server"] {
            if leaf_only {
                builder = builder.add_rule(NacmRule::allow(
                    action,
                    YangPathPattern::parse(&format!("/oc:root/oc:{list}/*"), &modules).unwrap(),
                ));
            } else {
                builder = builder.add_rule(NacmRule::deny(
                    action,
                    YangPathPattern::parse(&format!("/oc:root/oc:{list}/oc:port"), &modules)
                        .unwrap(),
                ));
            }
        }
        if !leaf_only {
            for allowed in ["/oc:root", "/oc:root/**"] {
                builder = builder.add_rule(NacmRule::allow(
                    action,
                    YangPathPattern::parse(allowed, &modules).unwrap(),
                ));
            }
        }
    }
    Policy(builder.build())
}

fn config(rows: Value, system: bool) -> Root {
    serde_json::from_value(if system {
        json!({"system-server": rows})
    } else {
        json!({"server": rows})
    })
    .unwrap()
}

async fn commit(
    policy: Policy,
    running: Root,
    candidate: Root,
    operation: ConfigOperation,
) -> Result<Root, CommitErrorCode> {
    let store = Arc::new(MockManagedDatastore::new());
    let authorizer =
        Arc::new(ConfigWriteAuthorizer::new(model::schema_registry::registry(), policy).unwrap());
    let bus = ConfigBus::new(running, store, authorizer).await.unwrap();
    let principal = TrustedPrincipal::new(
        WorkloadIdentity::User("operator".into()),
        TenantId::new("fixture").unwrap(),
    )
    .with_auth_strength(AuthStrength::MutualTls);
    let request = CommitRequest::commit(
        RequestId::new(),
        principal,
        TransportType::Internal,
        RequestSource::Northbound,
        operation,
        candidate,
        vec![YangPath::new("/oc:root").unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    bus.submit(request).await.map_err(|error| error.code)?;
    Ok(bus.current_snapshot().config.as_ref().clone())
}

#[tokio::test]
async fn config_bus_denies_protected_leaf_on_append_and_mid_list_insert() {
    for operation in [ConfigOperation::Patch, ConfigOperation::Replace] {
        for system in [true, false] {
            for rows in [
                json!([{"name":"z","port":53},{"name":"a","port":853},{"name":"m","port":5353}]),
                json!([{"name":"z","port":53},{"name":"m","port":5353},{"name":"a","port":853}]),
            ] {
                let running = config(
                    json!([{"name":"z","port":53},{"name":"a","port":853}]),
                    system,
                );
                assert_eq!(
                    commit(policy(false), running, config(rows, system), operation).await,
                    Err(CommitErrorCode::AuthorizationDenied),
                    "operation={operation:?}, system={system}",
                );
            }
        }
    }
}

#[tokio::test]
async fn config_bus_denies_protected_leaf_changed_together_with_reorder() {
    for operation in [ConfigOperation::Patch, ConfigOperation::Replace] {
        let running = config(
            json!([{"name":"z","port":53},{"name":"a","port":853}]),
            false,
        );
        let candidate = config(
            json!([{"name":"a","port":853},{"name":"z","port":5353}]),
            false,
        );
        assert_eq!(
            commit(policy(false), running, candidate, operation).await,
            Err(CommitErrorCode::AuthorizationDenied),
        );
    }
}

#[tokio::test]
async fn config_bus_leaf_only_permission_allows_appending_rows() {
    for operation in [ConfigOperation::Patch, ConfigOperation::Replace] {
        for system in [true, false] {
            let running = config(json!([{"name":"z","port":53}]), system);
            let candidate = config(
                json!([{"name":"z","port":53},{"name":"m","port":853}]),
                system,
            );
            assert_eq!(
                commit(policy(true), running, candidate.clone(), operation)
                    .await
                    .unwrap(),
                candidate,
            );
        }
    }
}

#[test]
fn membership_and_reorder_diffs_keep_changed_leaf_paths() {
    let running = config(
        json!([{"name":"z","port":53},{"name":"a","port":853}]),
        false,
    );
    for (rows, expected) in [
        (
            json!([{"name":"z","port":53},{"name":"a","port":853},{"name":"m","port":5353}]),
            vec![
                "/oc:root/oc:server[name='m']/oc:name",
                "/oc:root/oc:server[name='m']/oc:port",
            ],
        ),
        (
            json!([{"name":"a","port":853},{"name":"z","port":5353}]),
            vec!["/oc:root/oc:server", "/oc:root/oc:server[name='z']/oc:port"],
        ),
        (
            json!([{"name":"z","port":53},{"name":"m","port":5353},{"name":"a","port":853}]),
            vec![
                "/oc:root/oc:server",
                "/oc:root/oc:server[name='m']/oc:name",
                "/oc:root/oc:server[name='m']/oc:port",
            ],
        ),
        (
            json!([{"name":"a","port":853}]),
            vec!["/oc:root/oc:server[name='z']"],
        ),
    ] {
        let candidate = config(rows, false);
        let deltas = candidate.diff(&running).unwrap();
        let paths = candidate.changed_paths(&running, &deltas).unwrap();
        assert_eq!(
            paths.iter().map(YangPath::as_str).collect::<Vec<_>>(),
            expected
        );
        let mut applied = running.clone();
        model::patch::apply_patch(&mut applied, &deltas).unwrap();
        assert_eq!(applied, candidate);
    }
}
