use super::*;
use crate::scope::{
    clock::AuthenticationClock,
    lifecycle::EffectGate,
    proof::{StartupMode, StartupRequest},
    startup_tests::{material, Clock, ISSUER, WORKER},
    wire::*,
    ScopeRpcError, StartupError,
};
use opc_session_store::{
    consensus::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity,
    },
    scope_authority::{ScopeExecution, ScopeId},
    SessionConsumerIdentity,
};
use opc_tls::{PeerPolicy, TlsConfigBuilder};
use opc_types::{InstanceId, NetworkFunctionKind, TenantId};
use std::{collections::HashSet, time::Duration};

#[test]
fn startup_and_scope_signing_recheck_creator_pid_and_dumpability() {
    const NAME: &str =
        "scope::boot::tests::startup_and_scope_signing_recheck_creator_pid_and_dumpability";
    const CHILD: &str = "OPC_SCOPE_PROTECTION_RECHECK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let before = rustix::process::dumpable_behavior().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(rustix::process::dumpable_behavior().unwrap(), before);
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut boot = BootIdentity::generate().unwrap();
            let scope = ScopeId::new(
                SessionConsensusIdentity::new(
                    SessionConsensusClusterId::from_bytes([1; 32]),
                    SessionConsensusConfigurationId::from_bytes([2; 32]),
                    SessionConsensusConfigurationEpoch::new(1).unwrap(),
                ),
                TenantId::new("test").unwrap(),
                NetworkFunctionKind::new("smf").unwrap(),
                [3; 32],
            )
            .unwrap();
            let binding = ScopeBinding::from_scope(&scope).unwrap();
            let execution = ScopeExecution::new(
                SessionConsumerIdentity::new(WORKER).unwrap(),
                1,
                [4; 16],
                *boot.process_nonce(),
                boot.key_digest(),
            )
            .unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca =
                rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap())
                    .unwrap();
            let (_client_source, client_rx) =
                tokio::sync::watch::channel(Some(material(WORKER, &ca)));
            let (_server_source, server_rx) =
                tokio::sync::watch::channel(Some(material(ISSUER, &ca)));
            let client = TlsConfigBuilder::new(client_rx)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("issuer-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_client_config()
                .unwrap()
                .begin_handshake()
                .unwrap();
            let server = TlsConfigBuilder::new(server_rx)
                .with_policy(PeerPolicy {
                    allowed_instances: Some(HashSet::from([InstanceId::new("worker-0").unwrap()])),
                    ..Default::default()
                })
                .build_authenticated_server_config()
                .unwrap()
                .begin_handshake()
                .unwrap();
            let (outgoing, incoming) = tokio::io::duplex(16 * 1024);
            let (connection, server_connection) =
                tokio::time::timeout(Duration::from_secs(10), async {
                    tokio::join!(
                        client.connect_scope(outgoing, binding.tls_domain().unwrap()),
                        server.accept_scope(incoming, binding.tls_domain().unwrap())
                    )
                })
                .await
                .unwrap();
            let connection = connection.unwrap();
            let _server_connection = server_connection.unwrap();
            let startup = StartupRequest {
                scope: binding.clone(),
                workload: [4; 16],
                observation: [5; 32],
                challenge: [6; 32],
            };
            let canonical = scope.encode_canonical().unwrap();
            let call = Header {
                kind: FrameKind::Call,
                class: Class::SafetyControl,
                method: Method::Current,
                installation: *binding.installation(),
                scope: binding.commitment(),
                request_id: [7; 16],
                digest: transport_request_digest(Method::Current, &[7; 16], &canonical).unwrap(),
                payload_len: 36 + canonical.len(),
            };
            let gate = EffectGate::new();
            let candidate = gate.candidate().await.unwrap();
            let start = |boot: &BootIdentity, mode| {
                boot.startup_proof(
                    &connection,
                    Clock.interval().unwrap(),
                    &startup,
                    mode,
                    b"synthetic.bootstrap.token".to_vec(),
                    (mode == StartupMode::Candidate).then_some(&candidate),
                )
            };
            let scope_proof = |boot: &BootIdentity| {
                boot.scope_proof(
                    &connection,
                    Clock.interval().unwrap(),
                    &scope,
                    &execution,
                    &call,
                    [8; 32],
                    &canonical,
                    None,
                    [9; 32],
                    None,
                )
            };
            for mode in [StartupMode::Liveness, StartupMode::Candidate] {
                assert!(start(&boot, mode).is_ok());
            }
            assert!(scope_proof(&boot).is_ok());

            // A fork retains the creator PID in memory. Inject that mismatch without
            // unsafe fork operations in the threaded Rust test process.
            boot.process = std::process::id().wrapping_add(1);
            for mode in [StartupMode::Liveness, StartupMode::Candidate] {
                assert!(
                    matches!(start(&boot, mode), Err(StartupError::GateClosed)),
                    "a changed PID cannot sign startup proofs"
                );
            }
            assert!(
                matches!(scope_proof(&boot), Err(ScopeRpcError::Unauthorized)),
                "a changed PID cannot sign scope proofs"
            );
            boot.process = std::process::id();
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
                .unwrap();
            for mode in [StartupMode::Liveness, StartupMode::Candidate] {
                assert!(
                    matches!(start(&boot, mode), Err(StartupError::GateClosed)),
                    "re-enabling dumps cannot restore startup signing"
                );
            }
            assert!(
                matches!(scope_proof(&boot), Err(ScopeRpcError::Unauthorized)),
                "re-enabling dumps cannot restore scope signing"
            );
        });
}
