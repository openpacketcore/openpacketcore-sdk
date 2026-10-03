#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::future::Future;
use std::path::PathBuf;
use std::task::{Context, Waker};
use std::time::Duration;

use opc_ipsec_xfrm::{
    test_support::{MockLinuxXfrmKernel, MockXfrmMutationFault},
    Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, PolicyParameters, QueryPolicyRequest, QuerySaRequest, SaParameters, XfrmAction,
    XfrmBackend, XfrmDirection, XfrmError, XfrmId, XfrmMode, XfrmObjectInstallRequest,
    XfrmObjectRosterDurableOutcome, XfrmObjectRosterDurablePhase, XfrmObjectRosterGroupId,
    XfrmObjectRosterMemberRequest, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterRequest, XfrmRequestId, XfrmSelector,
    XfrmTemplate,
};

fn sa_parameters() -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(
            IpAddress::Ipv4([10, 0, 0, 1]),
            IpAddress::Ipv4([10, 0, 0, 2]),
            17,
        ),
        id: XfrmId {
            destination: IpAddress::Ipv4([192, 0, 2, 2]),
            spi: 0x1020_3040,
            protocol: 50,
        },
        source_address: IpAddress::Ipv4([192, 0, 2, 1]),
        request_id: XfrmRequestId::new(7),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x11; 32]),
        )),
        crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0x22; 16]))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn policy_parameters(sa: &SaParameters) -> PolicyParameters {
    PolicyParameters {
        selector: sa.selector.clone(),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: sa.id,
            source_address: sa.source_address,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
        mark: None,
        if_id: None,
    }
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let opaque = XfrmObjectRosterGroupId::generate().unwrap();
        let suffix = opaque
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self(std::env::temp_dir().join(format!("opc-xfrm-mock-kernel-{suffix}")))
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

// Catches a fixture accidentally scoped to an actor instead of kernel lifetime,
// and an install/query fixture that bypasses production netlink codecs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linux_queries_observe_installs_after_actor_recreation() {
    let kernel = MockLinuxXfrmKernel::new();
    let original = kernel.backend().bind_current_network_namespace().unwrap();
    let sa = sa_parameters();
    let query = QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi);
    original
        .install_sa(InstallSaRequest {
            parameters: sa.clone(),
        })
        .await
        .unwrap();
    drop(original);

    let successor = kernel.backend().bind_current_network_namespace().unwrap();
    let observed = successor.query_sa(query).await.unwrap();
    assert_eq!(observed.id, sa.id);
    assert_eq!(observed.source_address, sa.source_address);
    assert_eq!(observed.request_id, XfrmRequestId::new(7));
    assert_eq!(observed.replay_window, 32);
}

// Catches a fixture that models public backend calls but swallows the physical
// mutations issued inside a durable roster. This characterizes retained kernel
// state; it does not assert that a lifetime cleanup inventory exists yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_roster_objects_remain_after_consumer_state_is_dropped() {
    let root = TestRoot::new();
    let kernel = MockLinuxXfrmKernel::new();
    let sa = sa_parameters();
    let policy = policy_parameters(&sa);
    let sa_query = QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi);
    let policy_query = QueryPolicyRequest::new(policy.selector.clone(), policy.direction);

    {
        let (backend, store) = kernel
            .backend()
            .bind_current_network_namespace_with_object_roster_recovery(
                root.0.clone(),
                XfrmObjectRosterRecoveryProofKey::new([0x35; 32]).unwrap(),
            )
            .unwrap();
        let group = XfrmObjectRosterGroupId::generate().unwrap();
        let generation = XfrmObjectRosterOperationGeneration::new(1).unwrap();
        let roster = XfrmObjectRosterRequest::new(vec![
            XfrmObjectRosterMemberRequest::new(XfrmObjectInstallRequest::Sa(InstallSaRequest {
                parameters: sa,
            })),
            XfrmObjectRosterMemberRequest::new(XfrmObjectInstallRequest::Policy(
                InstallPolicyRequest {
                    parameters: policy.clone(),
                },
            )),
        ])
        .unwrap();
        let admission = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let outcome = backend.run_durable_object_roster(admission).await.unwrap();
        assert!(matches!(
            outcome,
            XfrmObjectRosterDurableOutcome::Applied { .. }
        ));
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }

    let successor = kernel.backend().bind_current_network_namespace().unwrap();
    let observed = successor.query_sa(sa_query).await.unwrap();
    assert_eq!(observed.id.spi, 0x1020_3040);
    assert_eq!(successor.query_policy(policy_query).await.unwrap(), policy);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_ack_keeps_the_installed_object_visible_to_the_real_backend() {
    let kernel = MockLinuxXfrmKernel::new();
    let backend = kernel.backend().bind_current_network_namespace().unwrap();
    let sa = sa_parameters();
    let query = QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi);
    kernel
        .fail_next_mutation(MockXfrmMutationFault::AfterEffectLostAck)
        .unwrap();
    assert!(matches!(
        backend.query_sa(query).await,
        Err(XfrmError::NotFound)
    ));
    assert!(matches!(
        backend
            .install_sa(InstallSaRequest { parameters: sa })
            .await,
        Err(XfrmError::StateIndeterminate { .. })
    ));
    assert_eq!(backend.query_sa(query).await.unwrap().id.spi, 0x1020_3040);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn before_effect_fault_preserves_absence_and_can_be_retried() {
    let kernel = MockLinuxXfrmKernel::new();
    let backend = kernel.backend().bind_current_network_namespace().unwrap();
    let sa = sa_parameters();
    let query = QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi);
    kernel
        .fail_next_mutation(MockXfrmMutationFault::BeforeEffectUnavailable)
        .unwrap();
    assert!(matches!(
        backend
            .install_sa(InstallSaRequest {
                parameters: sa.clone()
            })
            .await,
        Err(XfrmError::Unavailable)
    ));
    assert!(matches!(
        backend.query_sa(query).await,
        Err(XfrmError::NotFound)
    ));
    backend
        .install_sa(InstallSaRequest { parameters: sa })
        .await
        .unwrap();
    assert_eq!(backend.query_sa(query).await.unwrap().id.spi, 0x1020_3040);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_wait_keeps_namespace_restart_after_transport_release() {
    let kernel = MockLinuxXfrmKernel::new();
    let backend = kernel.backend().bind_current_network_namespace().unwrap();
    let mut wait = Box::pin(kernel.wait_for_idle());
    let mut context = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    drop(backend);
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap();
}
