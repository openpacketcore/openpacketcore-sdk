use super::*;
use crate::XfrmBackend;
use opc_linux_gtpu_sys::tc::{
    ContainmentBank, LocalHookSpec, LocalKernelScope, LocalScopeSpec, TcHook, TcSlot,
};
use opc_local_kernel_lifecycle::{LocalResetParticipants, LocalStartupState, NoLocalCompanions};
use opc_route_steering::LinuxRouteSteeringBackend;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Cleanup(PathBuf, PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(&self.1);
    }
}
fn scope() -> (Cleanup, LocalKernelLifecycle) {
    scope_for(&["lo"])
}
fn scope_for(interfaces: &[&str]) -> (Cleanup, LocalKernelLifecycle) {
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let root = PathBuf::from(format!("/sys/fs/bpf/opc-local-xfrm-{}", std::process::id()));
    let locks = std::env::temp_dir().join(format!("opc-local-xfrm-lock-{}", std::process::id()));
    let cleanup = Cleanup(root.clone(), locks.clone());
    for path in [&root, &locks] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut hooks = vec![];
    let mut egresses = vec![];
    for interface in interfaces {
        aya::programs::tc::qdisc_add_clsact(interface).unwrap();
        let ifindex = opc_linux_gtpu_sys::ifindex_by_name(interface).unwrap();
        let slot = |p, proto| TcSlot::new(ifindex, TcHook::Egress, 0, proto, p, 1).unwrap();
        hooks.push(
            LocalHookSpec::new(
                ContainmentBank::new(slot(1, 0x806), slot(2, 3)).unwrap(),
                ContainmentBank::new(slot(3, 0x806), slot(4, 3)).unwrap(),
            )
            .unwrap(),
        );
        egresses.push(ifindex);
    }
    let scope = LocalKernelScope::open(
        LocalScopeSpec::new(root, locks.join("guard"), [74; 16], hooks, vec![]).unwrap(),
    )
    .unwrap();
    (
        cleanup,
        LocalKernelLifecycle::new(scope, vec![], vec![], egresses).unwrap(),
    )
}
fn backend(lifecycle: &LocalKernelLifecycle) -> NamespaceBoundLinuxXfrmBackend {
    NamespaceBoundLinuxXfrmBackend::for_local_scope(
        lifecycle.clone(),
        LinuxXfrmBackendConfig::default(),
        None,
        ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state(),
    )
    .unwrap()
}
fn participants(
    lifecycle: &LocalKernelLifecycle,
    backend: &NamespaceBoundLinuxXfrmBackend,
) -> LocalResetParticipants {
    LocalResetParticipants::new(
        backend.local_reset_participant().unwrap(),
        Arc::new(LinuxRouteSteeringBackend::new()),
        Arc::new(NoLocalCompanions::new(lifecycle.local_scope().clone())),
    )
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_effect_uses_real_quorum_and_preserves_publication_during_store_loss() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::local_scope_quorum::{child_key, execution, Quorum};
            use opc_local_kernel_lifecycle::ScopeKernelAuthority;
            let quorum = Quorum::open().await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .unwrap();
            let activation = quorum.create_request(10).await;
            assert!(backend.local_namespace_empty().await.unwrap());
            let effect = authority
                .commit_activation(activation.clone(), child_key(10))
                .await
                .unwrap();
            let (sa, policy) = request::fixture();
            let request = ScopedXfrmRequest::new(sa.clone(), policy.clone()).unwrap();
            let receipt = backend
                .install_scoped(&profile, effect.clone(), request.clone())
                .await
                .unwrap();
            assert!(backend.read_scoped(&receipt).await.unwrap());
            let retry = backend
                .install_scoped(&profile, effect.clone(), request.clone())
                .await
                .unwrap();
            assert!(backend.read_scoped(&retry).await.unwrap());
            let mut changed = sa.clone();
            changed.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(vec![0x44; 20]);
            assert!(matches!(
                backend
                    .install_scoped(
                        &profile,
                        effect.clone(),
                        ScopedXfrmRequest::new(changed, policy.clone()).unwrap()
                    )
                    .await,
                Err(XfrmError::StateMismatch {
                    operation: "local_scope_receipt"
                })
            ));
            assert!(backend.read_scoped(&receipt).await.unwrap());

            // A second committed child and a different if_id still alias the
            // Linux SA deletion key. It waits; cancellation cannot delete the
            // already published occupant or leave an admission permit stuck.
            let other = authority
                .commit_activation(quorum.create_request(11).await, child_key(11))
                .await
                .unwrap();
            let mut alias_sa = sa;
            let mut alias_policy = policy;
            alias_sa.if_id = Some(56);
            alias_policy.if_id = Some(56);
            let (waiting_backend, waiting_profile) = (backend.clone(), profile.clone());
            let wait = tokio::spawn(async move {
                waiting_backend
                    .install_scoped(
                        &waiting_profile,
                        other,
                        ScopedXfrmRequest::new(alias_sa, alias_policy).unwrap(),
                    )
                    .await
            });
            while !backend
                .scoped_cleanup_progress()
                .await
                .unwrap()
                .iter()
                .any(|progress| progress.first_failure_age.is_some())
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(
                !wait.is_finished(),
                "key collision must wait instead of rejecting attach"
            );
            wait.abort();
            assert!(wait.await.unwrap_err().is_cancelled());
            while !backend.scoped_cleanup_progress().await.unwrap().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(backend.read_scoped(&receipt).await.unwrap());

            quorum.set_available(false);
            assert!(
                effect.recheck().await.is_err(),
                "actual full-round store proof is unavailable"
            );
            assert!(
                backend.read_scoped(&receipt).await.unwrap(),
                "store loss cannot expire published forwarding"
            );
            let retry = backend
                .install_scoped(&profile, effect.clone(), request.clone())
                .await
                .unwrap();
            assert!(backend.read_scoped(&retry).await.unwrap());
            backend.remove_scoped(&receipt).await.unwrap();
            backend.remove_scoped(&receipt).await.unwrap();
            assert!(!backend.read_scoped(&receipt).await.unwrap());
            assert!(
                backend
                    .install_scoped(&profile, effect.clone(), request)
                    .await
                    .is_err(),
                "exact retired operation must never reset SA sequence counters"
            );
            assert!(backend.local_namespace_empty().await.unwrap());
            let replacement = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert!(profile.recheck().is_err());
            assert!(effect.recheck_local_execution().is_err());
            assert!(backend.remove_scoped(&receipt).await.is_err());
            backend.admit_scoped_profile(&replacement).await.unwrap();
            authority.close_execution().await;
            quorum.close().await;
        });
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_rebuilt_authority_cannot_reinstall_a_removed_effect() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::local_scope_quorum::{child_key, execution, Quorum};
            use opc_local_kernel_lifecycle::ScopeKernelAuthority;
            let quorum = Quorum::open().await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let activation = quorum.create_request(19).await;
            let (sa, policy) = request::fixture();
            let request = ScopedXfrmRequest::new(sa, policy).unwrap();
            {
                let authority = ScopeKernelAuthority::new(
                    lifecycle.clone(),
                    execution(),
                    quorum.committed.clone(),
                    quorum.authority.clone(),
                    quorum.batches.clone(),
                )
                .await
                .unwrap();
                let effect = authority
                    .commit_activation(activation.clone(), child_key(19))
                    .await
                    .unwrap();
                let receipt = backend
                    .install_scoped(&profile, effect, request.clone())
                    .await
                    .unwrap();
                assert!(backend.read_scoped(&receipt).await.unwrap());
                backend.remove_scoped(&receipt).await.unwrap();
                assert!(!backend.read_scoped(&receipt).await.unwrap());
                assert_eq!(backend.scoped_test_retained().await, 0);
            }
            // All tokens, receipts and adapter clones are gone. The same
            // lifecycle and store outcome remain, without another reset.
            assert!(backend.local_namespace_empty().await.unwrap());
            let rebuilt = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .expect("dropping the old adapter releases its owner registration");
            let replay = rebuilt
                .commit_activation(activation, child_key(19))
                .await
                .unwrap();
            assert!(
                matches!(
                    backend.install_scoped(&profile, replay, request).await,
                    Err(XfrmError::StateMismatch {
                        operation: "local_scope_receipt"
                    })
                ),
                "rebuilding the adapter must not allow a removed activation to reinstall"
            );
            assert!(backend.local_namespace_empty().await.unwrap());
            assert_eq!(backend.scoped_test_retained().await, 0);
            rebuilt.close_execution().await;
            quorum.close().await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_actor_owns_partial_panic_cancellation_and_lost_publication_reply() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::local_scope_quorum::{child_key, execution, Quorum};
            use opc_local_kernel_lifecycle::ScopeKernelAuthority;
            use operations::{TestFault, TestPause};
            let quorum = Quorum::open().await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .unwrap();
            let healthy_effect = authority
                .commit_activation(quorum.create_request(20).await, child_key(20))
                .await
                .unwrap();
            let (sa, policy) = request::fixture();
            let healthy = backend
                .install_scoped(
                    &profile,
                    healthy_effect,
                    ScopedXfrmRequest::new(sa.clone(), policy.clone()).unwrap(),
                )
                .await
                .unwrap();
            let request = |n: u8| {
                let mut sa = sa.clone();
                let mut policy = policy.clone();
                sa.id.spi += u32::from(n);
                sa.mark = Some(crate::XfrmLookupMark::full(100 + u32::from(n)));
                policy.mark = sa.mark;
                ScopedXfrmRequest::new(sa, policy).unwrap()
            };
            for (n, fault) in [
                (21, TestFault::PanicAfterPolicy),
                (22, TestFault::PanicAfterSa),
            ] {
                let effect = authority
                    .commit_activation(quorum.create_request(n).await, child_key(n))
                    .await
                    .unwrap();
                backend.scoped_test_fault(fault).await;
                assert!(backend
                    .install_scoped(&profile, effect, request(n))
                    .await
                    .is_err());
                assert!(backend.scoped_cleanup_progress().await.unwrap().is_empty());
                assert!(backend.read_scoped(&healthy).await.unwrap());
            }
            let effect = authority
                .commit_activation(quorum.create_request(23).await, child_key(23))
                .await
                .unwrap();
            let pause = Arc::new(TestPause::default());
            backend
                .scoped_test_fault(TestFault::PauseAfterSa(pause.clone()))
                .await;
            let task = tokio::spawn({
                let backend = backend.clone();
                let profile = profile.clone();
                let request = request(23);
                async move { backend.install_scoped(&profile, effect, request).await }
            });
            pause.entered.notified().await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            pause.resume.notify_one();
            loop {
                if backend.scoped_cleanup_progress().await.unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(backend.read_scoped(&healthy).await.unwrap());
            for (id, fault) in [
                (24, TestFault::DropPublishedReply),
                (25, TestFault::PanicAfterPublication),
            ] {
                let effect = authority
                    .commit_activation(quorum.create_request(id).await, child_key(id))
                    .await
                    .unwrap();
                backend.scoped_test_fault(fault).await;
                assert!(backend
                    .install_scoped(&profile, effect.clone(), request(id))
                    .await
                    .is_err());
                quorum.set_available(false);
                let retry = backend
                    .install_scoped(&profile, effect, request(id))
                    .await
                    .unwrap();
                assert!(backend.read_scoped(&retry).await.unwrap());
                backend.remove_scoped(&retry).await.unwrap();
                quorum.set_available(true);
                while quorum
                    .authority
                    .current(execution().identity())
                    .await
                    .is_err()
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            backend.remove_scoped(&healthy).await.unwrap();
            // Keep receipts and tokens alive at the caller while the
            // actor must discard every completed activation request.
            let mut completed = Vec::new();
            for id in 100..116 {
                let activation = quorum.create_request(id).await;
                let effect = authority
                    .commit_activation(activation.clone(), child_key(id))
                    .await
                    .unwrap();
                let receipt = backend
                    .install_scoped(&profile, effect.clone(), request(id))
                    .await
                    .unwrap();
                backend.remove_scoped(&receipt).await.unwrap();
                backend.remove_scoped(&receipt).await.unwrap();
                assert!(!backend.read_scoped(&receipt).await.unwrap());
                let replay = authority
                    .commit_activation(activation, child_key(id))
                    .await
                    .unwrap();
                assert!(backend
                    .install_scoped(&profile, replay, request(id))
                    .await
                    .is_err());
                completed.push((effect, receipt));
                assert_eq!(
                    backend.scoped_test_retained().await,
                    0,
                    "completed churn must not increase memory or lookup work"
                );
            }
            assert!(
                backend.local_namespace_empty().await.unwrap(),
                "every cancelled partial effect is retired without a namespace reset"
            );
            authority.close_execution().await;
            quorum.close().await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_unknown_committed_reply_never_mints_effect_and_stale_child_cannot_install() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::local_scope_quorum::{child_key, execution, value, Quorum};
            use opc_local_kernel_lifecycle::{LocalEffectError, ScopeKernelAuthority};
            use opc_session_store::scope_batch::{ScopeBatchRequest, ScopeChildMutation};
            let quorum = Quorum::open().await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .unwrap();
            let activation = ScopeBatchRequest::in_lane(
                quorum.committed.stamp(),
                [30; 16],
                2,
                1,
                vec![ScopeChildMutation::Create {
                    key: child_key(30),
                    value: value(30),
                    claims: vec![],
                }],
                vec![],
            )
            .unwrap();
            assert!(activation.expected_revision().is_none());
            quorum.lose_next_commit_reply();
            let uncertain = authority
                .commit_activation(activation.clone(), child_key(30))
                .await;
            assert!(
                quorum.lost_commit_reply(),
                "the real committed forward response was dropped"
            );
            assert!(
                matches!(
                    uncertain,
                    Err(LocalEffectError::OutcomeUnknown | LocalEffectError::Unavailable)
                ),
                "{uncertain:?}"
            );
            assert!(backend.local_namespace_empty().await.unwrap());
            quorum.set_available(true);
            loop {
                if quorum
                    .authority
                    .current(execution().identity())
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(
                quorum
                    .batches
                    .read(execution().identity(), child_key(30))
                    .await
                    .unwrap()
                    .is_some(),
                "lost reply did not roll back the committed child"
            );
            let effect = authority
                .commit_activation(activation.clone(), child_key(30))
                .await
                .unwrap();
            let changed = ScopeBatchRequest::in_lane(
                activation.stamp(),
                *activation.request_id(),
                activation.lane(),
                activation.sequence(),
                vec![ScopeChildMutation::Create {
                    key: child_key(30),
                    value: value(31),
                    claims: vec![],
                }],
                vec![],
            )
            .unwrap();
            assert!(authority
                .commit_activation(changed, child_key(30))
                .await
                .is_err());
            let unrelated = ScopeBatchRequest::in_lane(
                quorum.committed.stamp(),
                [31; 16],
                3,
                1,
                vec![ScopeChildMutation::Create {
                    key: child_key(31),
                    value: value(31),
                    claims: vec![],
                }],
                vec![],
            )
            .unwrap();
            authority
                .commit_activation(unrelated, child_key(31))
                .await
                .unwrap();
            effect
                .recheck()
                .await
                .expect("another lane preserves this child");
            let successor = ScopeBatchRequest::in_lane(
                quorum.committed.stamp(),
                [32; 16],
                activation.lane(),
                activation.sequence() + 1,
                vec![ScopeChildMutation::CompareAndSet {
                    key: child_key(30),
                    expected: effect.key().revision(),
                    value: value(32),
                    claims: vec![],
                }],
                vec![],
            )
            .unwrap();
            let current = authority
                .commit_activation(successor, child_key(30))
                .await
                .unwrap();
            assert!(effect.recheck().await.is_err());
            let (sa, policy) = request::fixture();
            let request = ScopedXfrmRequest::new(sa, policy).unwrap();
            assert!(backend
                .install_scoped(&profile, effect, request.clone())
                .await
                .is_err());
            assert!(backend.local_namespace_empty().await.unwrap());
            let receipt = backend
                .install_scoped(&profile, current, request)
                .await
                .unwrap();
            backend.remove_scoped(&receipt).await.unwrap();
            assert!(backend.local_namespace_empty().await.unwrap());
            authority.close_execution().await;
            quorum.close().await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_expiration_and_spi_zero_acquire_do_not_block_exact_live_undo() {
    fn ip(arguments: &[&str]) -> String {
        let output = std::process::Command::new("ip")
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "ip fixture command failed");
        String::from_utf8(output.stdout).unwrap()
    }
    struct Listener(std::process::Child);
    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "scopeacq0", "type", "dummy"]);
    ip(&["address", "add", "198.18.0.1/16", "dev", "scopeacq0"]);
    ip(&["link", "set", "scopeacq0", "up"]);
    let (_cleanup, lifecycle) = scope_for(&["lo", "scopeacq0"]);
    let backend = backend(&lifecycle);
    // Keep larval acquisition alive beyond the runner's entire 120-second case.
    fs::write("/proc/sys/net/core/xfrm_acq_expires", "600\n").unwrap();
    let _listener = Listener(
        std::process::Command::new("ip")
            .args(["xfrm", "monitor", "acquire"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use crate::local_scope_quorum::{child_key, execution, Quorum};
            use opc_local_kernel_lifecycle::ScopeKernelAuthority;
            use operations::{TestFault, TestPause};
            loop {
                let joined = fs::read_to_string("/proc/net/netlink")
                    .unwrap()
                    .lines()
                    .skip(1)
                    .any(|line| {
                        let fields = line.split_whitespace().collect::<Vec<_>>();
                        fields.len() > 3
                            && fields[1] == "6"
                            && u32::from_str_radix(fields[3], 16)
                                .is_ok_and(|groups| groups & 1 != 0)
                    });
                if joined {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let quorum = Quorum::open().await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = ScopeKernelAuthority::new(
                lifecycle.clone(),
                execution(),
                quorum.committed.clone(),
                quorum.authority.clone(),
                quorum.batches.clone(),
            )
            .await
            .unwrap();
            let healthy_effect = authority
                .commit_activation(quorum.create_request(40).await, child_key(40))
                .await
                .unwrap();
            let (healthy_sa, healthy_policy) = request::fixture();
            let healthy = backend
                .install_scoped(
                    &profile,
                    healthy_effect,
                    ScopedXfrmRequest::new(healthy_sa, healthy_policy).unwrap(),
                )
                .await
                .unwrap();
            let (mut sa, mut policy) = request::fixture();
            sa.source_address = crate::IpAddress::Ipv4([198, 18, 0, 1]);
            sa.id.destination = crate::IpAddress::Ipv4([198, 18, 0, 2]);
            sa.id.spi = 5000;
            sa.selector = crate::XfrmSelector::new(sa.source_address, sa.id.destination, 17);
            sa.if_id = None;
            sa.mark = Some(crate::XfrmLookupMark::full(90));
            sa.mode = crate::XfrmMode::Transport;
            sa.lifetime.hard_add_expires_seconds = 1;
            policy.selector = sa.selector.clone();
            policy.if_id = None;
            policy.mark = sa.mark;
            policy.templates[0].source_address = sa.source_address;
            policy.templates[0].id.destination = sa.id.destination;
            policy.templates[0].mode = sa.mode;
            assert_eq!(policy.templates[0].id.spi, 0);
            let effect = authority
                .commit_activation(quorum.create_request(41).await, child_key(41))
                .await
                .unwrap();
            let pause = Arc::new(TestPause::default());
            backend
                .scoped_test_fault(TestFault::PauseAfterSa(pause.clone()))
                .await;
            let task = tokio::spawn({
                let backend = backend.clone();
                let profile = profile.clone();
                let request = ScopedXfrmRequest::new(sa.clone(), policy.clone()).unwrap();
                async move { backend.install_scoped(&profile, effect, request).await }
            });
            pause.entered.notified().await;
            let reader = LinuxXfrmBackend::new();
            loop {
                if matches!(
                    reader
                        .query_sa(crate::QuerySaRequest {
                            destination: sa.id.destination,
                            protocol: sa.id.protocol,
                            spi: sa.id.spi,
                            mark: sa.mark
                        })
                        .await,
                    Err(XfrmError::NotFound)
                ) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            let socket = std::net::UdpSocket::bind("198.18.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &90_u32)
                .unwrap();
            let _sent = socket.send_to(b"acquire", "198.18.0.2:9");
            let count = || {
                ip(&["xfrm", "state", "count"])
                    .split_whitespace()
                    .last()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            };
            assert!(
                count() > 1,
                "a real larval ACQUIRE must coexist with the unrelated healthy SA"
            );
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            pause.resume.notify_one();
            while !backend.scoped_cleanup_progress().await.unwrap().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(
                count() > 1,
                "cleanup did not rely on expiration of the larval state"
            );
            assert!(backend.read_scoped(&healthy).await.unwrap());
            sa.lifetime.hard_add_expires_seconds = 0;
            sa.aead.as_mut().unwrap().1 = crate::KeyMaterial::new(vec![0x54; 20]);
            let next = authority
                .commit_activation(quorum.create_request(42).await, child_key(42))
                .await
                .unwrap();
            let receipt = backend
                .install_scoped(&profile, next, ScopedXfrmRequest::new(sa, policy).unwrap())
                .await
                .unwrap();
            assert!(backend.read_scoped(&receipt).await.unwrap());
            backend.remove_scoped(&receipt).await.unwrap();
            assert!(backend.read_scoped(&healthy).await.unwrap());
            backend.remove_scoped(&healthy).await.unwrap();
            authority.close_execution().await;
            lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert!(backend.local_namespace_empty().await.unwrap());
            quorum.close().await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scope_refuses_duplicate_coordinator() {
    let (_cleanup, lifecycle) = scope();
    let duplicate = LocalKernelLifecycle::new(
        lifecycle.local_scope().clone(),
        vec![],
        vec![],
        vec![opc_linux_gtpu_sys::ifindex_by_name("lo").unwrap()],
    );
    assert!(
        matches!(duplicate, Err(LocalLifecycleError::InvalidPlan)),
        "a second coordinator would have an independent reset barrier"
    );
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_profile_proves_keys_cleans_probe_and_refuses_allocspi() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            profile.recheck().unwrap();
            assert!(
                backend.local_namespace_empty().await.unwrap(),
                "the noncandidate probe must be gone before admission returns"
            );
            let allocated = backend
                .allocate_spi(crate::AllocateSpiRequest {
                    destination: crate::IpAddress::Ipv4([127, 0, 0, 2]),
                    protocol: 50,
                    min_spi: 4096,
                    max_spi: 8192,
                })
                .await;
            assert!(matches!(
                allocated,
                Err(XfrmError::UnsupportedFeature {
                    feature: "local_scope_requires_scoped_operation"
                })
            ));
            assert!(backend.local_namespace_empty().await.unwrap());
            let replacement = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert!(
                profile.recheck().is_err(),
                "a profile cannot outlive its reset epoch"
            );
            assert!(backend.admit_scoped_profile(&reset).await.is_err());
            backend.admit_scoped_profile(&replacement).await.unwrap();
        });
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scope_refuses_independent_xfrm_producer_until_actor_stops() {
    let (_cleanup, lifecycle) = scope();
    let first = backend(&lifecycle);
    let retained = first.clone();
    drop(first);
    let create = || {
        NamespaceBoundLinuxXfrmBackend::for_local_scope(
        lifecycle.clone(), LinuxXfrmBackendConfig::default(), None,
        ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state())
    };
    assert!(
        matches!(
            create(),
            Err(XfrmError::UnsupportedFeature {
                feature: "local_scope_xfrm_actor_busy"
            })
        ),
        "the independent producer must refuse before any effect"
    );
    let stopped = retained.test_actor_join();
    drop(retained);
    stopped
        .join()
        .expect("the drained actor exits before another producer binds");
    drop(create().unwrap());
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_actor_refuses_legacy_reset_and_dscp_activation() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
        let reset = backend.reset_exclusively_owned_namespace(
            ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state()).await;
        assert!(matches!(reset, Err(XfrmError::UnsupportedFeature { feature: "local_scope_requires_scoped_operation" })), "{reset:?}");
            assert!(matches!(backend.activate_dscp_marking().await, Err(XfrmError::UnsupportedFeature { feature: "local_scope_requires_scoped_operation" })));
            assert!(matches!(backend.sa_relocation_capability().await, Err(XfrmError::UnsupportedFeature { feature: "local_scope_requires_scoped_operation" })), "a relocation probe sends a mutation-class netlink request");
    });
    assert!(lifecycle
        .local_scope()
        .inventory()
        .unwrap()
        .iter()
        .all(|dump| dump.entries().is_empty()));
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_unknown_root_contents_refuse_empty_observation_and_reset_before_effects() {
    let (cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    let unknown = cleanup.0.join("unregistered");
    fs::create_dir(&unknown).unwrap();
    fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            assert!(
                lifecycle
                    .observe_empty(participants(&lifecycle, &backend))
                    .await
                    .is_err(),
                "an unregistered pin tree cannot supply whole-scope empty evidence"
            );
            assert!(
                lifecycle
                    .reset(participants(&lifecycle, &backend))
                    .await
                    .is_err(),
                "an unregistered tree must refuse reset before containment or destructive effects"
            );
            assert!(unknown.is_dir());
            assert!(lifecycle
                .local_scope()
                .inventory()
                .unwrap()
                .iter()
                .all(|dump| dump.entries().is_empty()));
            fs::remove_dir(&unknown).unwrap();
            assert!(lifecycle
                .observe_empty(participants(&lifecycle, &backend))
                .await
                .unwrap()
                .is_some());
        });
}
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_readonly_inspection_classifies_predecessor_banks_without_kernel_effects() {
    use opc_linux_gtpu_sys::tc::{ScopeError, TcClient, TcVerdict};
    use opc_local_kernel_lifecycle::{LocalLifecycleError, LocalScopeInspection};
    fn qdiscs() -> Vec<u8> {
        let output = std::process::Command::new("tc")
            .args(["-j", "qdisc", "show", "dev", "lo"])
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    }
    async fn inspect(
        lifecycle: &LocalKernelLifecycle,
        backend: &NamespaceBoundLinuxXfrmBackend,
        expected: Result<LocalScopeInspection, LocalLifecycleError>,
        foreign_filters_present: bool,
    ) {
        let filters = || {
            lifecycle
                .local_scope()
                .inventory()
                .unwrap()
                .into_iter()
                .map(|dump| {
                    dump.entries()
                        .iter()
                        .map(|entry| {
                            (
                                entry.slot(),
                                entry.kind().to_vec(),
                                entry.gact().cloned(),
                                entry.bpf().cloned(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let before = (
            qdiscs(),
            filters(),
            lifecycle.local_scope().pin_root_entries().unwrap(),
        );
        assert!(backend.local_namespace_empty().await.unwrap());
        let observed = lifecycle
            .inspect_scope(participants(lifecycle, backend))
            .await;
        if let Ok(value) = observed.as_ref() {
            assert_eq!(value.foreign_filters_present(), foreign_filters_present);
        }
        assert_eq!(observed.map(|value| value.state()), expected);
        assert_eq!(
            (
                qdiscs(),
                filters(),
                lifecycle.local_scope().pin_root_entries().unwrap()
            ),
            before
        );
        assert!(backend.local_namespace_empty().await.unwrap());
        assert!(lifecycle.cleanup_progress().unwrap().is_empty());
    }
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    assert!(std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", "lo", "clsact"])
        .status()
        .unwrap()
        .success());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Even without clsact, inspection must query the kernel and leave it absent.
            inspect(&lifecycle, &backend, Ok(LocalScopeInspection::Empty), false).await;
            aya::programs::tc::qdisc_add_clsact("lo").unwrap();
            let banks = lifecycle.local_scope().spec().hooks()[0].banks();
            let mut tc = TcClient::new().unwrap();
            let neighbor = tc
                .create_gact(
                    TcSlot::new(1, TcHook::Egress, 0, 3, 60, 1).unwrap(),
                    [80; 16],
                    TcVerdict::Pass,
                )
                .unwrap();
            inspect(&lifecycle, &backend, Ok(LocalScopeInspection::Empty), true).await;
            assert_eq!(
                lifecycle
                    .observe_empty(participants(&lifecycle, &backend))
                    .await
                    .unwrap()
                    .unwrap()
                    .state(),
                LocalStartupState::ExclusionHeldAndEmpty
            );
            // The predecessor may have stopped after either component of either bank.
            for bank in banks {
                for (slot, verdict) in [
                    (bank.arp_slot(), TcVerdict::Pass),
                    (bank.drop_slot(), TcVerdict::Drop),
                ] {
                    let partial = tc.create_gact(slot, [74; 16], verdict).unwrap();
                    inspect(
                        &lifecycle,
                        &backend,
                        Ok(LocalScopeInspection::OwnedPartialContainment),
                        true,
                    )
                    .await;
                    assert!(matches!(
                        lifecycle
                            .observe_empty(participants(&lifecycle, &backend))
                            .await,
                        Err(LocalLifecycleError::Scope(ScopeError::Coverage))
                    ));
                    tc.delete_exact(&partial).unwrap();
                }
            }
            tc.create_gact(banks[0].arp_slot(), [74; 16], TcVerdict::Pass)
                .unwrap();
            tc.create_gact(banks[0].drop_slot(), [74; 16], TcVerdict::Drop)
                .unwrap();
            inspect(
                &lifecycle,
                &backend,
                Ok(LocalScopeInspection::OwnedAndContained),
                true,
            )
            .await;
            let partial_alternate = tc
                .create_gact(banks[1].arp_slot(), [74; 16], TcVerdict::Pass)
                .unwrap();
            inspect(
                &lifecycle,
                &backend,
                Ok(LocalScopeInspection::OwnedPartialContainment),
                true,
            )
            .await;
            tc.delete_exact(&partial_alternate).unwrap();
            let foreign = tc
                .create_gact(banks[1].arp_slot(), [75; 16], TcVerdict::Pass)
                .unwrap();
            inspect(
                &lifecycle,
                &backend,
                Err(LocalLifecycleError::Scope(ScopeError::OwnerCookieMismatch)),
                true,
            )
            .await;
            tc.delete_exact(&foreign).unwrap();
            // Repair is a separate, explicitly disruptive operation after inspection.
            let drop = tc
                .dump(1, TcHook::Egress)
                .unwrap()
                .find(banks[0].drop_slot())
                .unwrap()
                .clone();
            tc.delete_exact(&drop).unwrap();
            inspect(
                &lifecycle,
                &backend,
                Ok(LocalScopeInspection::OwnedPartialContainment),
                true,
            )
            .await;
            let receipt = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert_eq!(
                receipt.startup_observation().unwrap().state(),
                LocalStartupState::ExclusionHeldAndContained
            );
            inspect(
                &lifecycle,
                &backend,
                Ok(LocalScopeInspection::OwnedAndContained),
                true,
            )
            .await;
            tc.delete_exact(&neighbor).unwrap();
            inspect(
                &lifecycle,
                &backend,
                Ok(LocalScopeInspection::OwnedAndContained),
                false,
            )
            .await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_empty_startup_needs_no_containment_but_reset_covers_dscp_disabled_egress() {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(async {
            let observed = lifecycle
                .observe_empty(participants(&lifecycle, &backend))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(observed.state(), LocalStartupState::ExclusionHeldAndEmpty);
            assert!(lifecycle
                .local_scope()
                .inventory()
                .unwrap()
                .iter()
                .all(|dump| dump.entries().is_empty()));
            let receipt = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert_eq!(
                receipt.startup_observation().unwrap().state(),
                LocalStartupState::ExclusionHeldAndContained
            );
            assert_eq!(receipt.residue_count().unwrap(), 0);
            assert_eq!(
                lifecycle
                    .observe_empty(participants(&lifecycle, &backend))
                    .await
                    .unwrap()
                    .unwrap()
                    .state(),
                LocalStartupState::ExclusionHeldAndContained,
                "exit-time containment must never be reported as an empty startup"
            );
            assert_eq!(
                lifecycle
                    .local_scope()
                    .inventory()
                    .unwrap()
                    .iter()
                    .flat_map(|dump| dump.entries())
                    .filter(|entry| entry.slot().handle() != 0)
                    .count(),
                2
            );
            let _next = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            assert!(
                receipt.startup_observation().is_err(),
                "a stale reset receipt cannot supply new startup evidence"
            );
            // Simulate a predecessor left under another installation cookie.
            // Reset must refuse in preflight, preserving its filters instead
            // of entering the containment retry loop forever.
            let scope = lifecycle.local_scope();
            let bank = scope.spec().hooks()[0].banks()[0];
            let mut tc = opc_linux_gtpu_sys::tc::TcClient::new().unwrap();
            for filter in tc
                .dump(bank.arp_slot().ifindex(), TcHook::Egress)
                .unwrap()
                .entries()
            {
                if !filter.is_summary() {
                    tc.delete_exact(filter).unwrap();
                }
            }
            tc.create_gact(
                bank.arp_slot(),
                [75; 16],
                opc_linux_gtpu_sys::tc::TcVerdict::Pass,
            )
            .unwrap();
            tc.create_gact(
                bank.drop_slot(),
                [75; 16],
                opc_linux_gtpu_sys::tc::TcVerdict::Drop,
            )
            .unwrap();
            assert_eq!(
                lifecycle
                    .reset(participants(&lifecycle, &backend))
                    .await
                    .unwrap_err(),
                opc_local_kernel_lifecycle::LocalLifecycleError::Scope(
                    opc_linux_gtpu_sys::tc::ScopeError::OwnerCookieMismatch
                )
            );
            assert_eq!(
                tc.dump(bank.arp_slot().ifindex(), TcHook::Egress)
                    .unwrap()
                    .entries()
                    .iter()
                    .filter(|filter| filter.gact().is_some())
                    .count(),
                2
            );
        });
}
