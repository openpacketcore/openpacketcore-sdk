//! Real traffic, repeated rekeys and interrupted actor observations.
use super::successor_traffic::{self as traffic, install_initial_scoped, request, Traffic};
use super::*;
use crate::local_scope_quorum::{child_key, Quorum, TestAuthority};
use crate::*;
use opc_local_kernel_lifecycle::CommittedScopeEffect;
use std::sync::atomic::Ordering;
use std::time::Duration;

async fn grant(authority: &TestAuthority, quorum: &Quorum, id: u8) -> CommittedScopeEffect {
    authority
        .commit_activation(quorum.create_request(id).await, child_key(id))
        .await
        .unwrap()
}
fn candidate(previous: &ScopedXfrmRequest, generation: u32) -> ScopedXfrmRequest {
    let mut sa = previous.sa.clone();
    let mut policy = previous.policy.clone();
    sa.id.spi += generation;
    sa.replay_state = None;
    if policy.direction == XfrmDirection::Out {
        sa.request_id = XfrmRequestId::new(sa.request_id.unwrap().get() + generation);
        policy.templates[0].request_id = sa.request_id;
    }
    ScopedXfrmRequest::new(sa, policy).unwrap()
}
async fn settle(backend: &NamespaceBoundLinuxXfrmBackend) {
    while !backend.scoped_cleanup_progress().await.unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Clone, Copy)]
enum Case {
    Inbound,
    Outbound,
    Generations,
    Retry,
    Readback,
    ExpiredGroup,
    Abandon,
    HoldSa,
    HoldPolicy,
    Panic,
}
fn exercise(case: Case, native: bool) {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let quorum = Quorum::open(native).await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = TestAuthority::new(lifecycle.clone(), &quorum)
                .await
                .unwrap();
            traffic::prepare_loopback();
            // Reset closes every egress hook. Exercise packets only after the
            // ordinary activation-bound opening has removed that containment.
            let opening = lifecycle
                .open(&reset, grant(&authority, &quorum, 140).await)
                .await
                .unwrap();
            opening.recheck().unwrap();
            match case {
                Case::Inbound | Case::Outbound => {
                    overlap(
                        &backend,
                        &profile,
                        &authority,
                        &quorum,
                        if matches!(case, Case::Inbound) {
                            XfrmDirection::In
                        } else {
                            XfrmDirection::Out
                        },
                    )
                    .await;
                }
                Case::Generations => generations(&backend, &profile, &authority, &quorum).await,
                Case::Retry => retry(&backend, &profile, &authority, &quorum).await,
                Case::Readback => readback(&backend, &profile, &authority, &quorum).await,
                Case::ExpiredGroup => expired_group(&backend, &profile, &authority, &quorum).await,
                Case::Abandon => abandon(&backend, &profile, &authority, &quorum).await,
                Case::HoldSa | Case::HoldPolicy => {
                    cancelled(
                        &backend,
                        &profile,
                        &authority,
                        &quorum,
                        matches!(case, Case::HoldPolicy),
                    )
                    .await;
                }
                Case::Panic => panic_recovery(&backend, &profile, &authority, &quorum).await,
            }
            assert!(backend.local_namespace_empty().await.unwrap());
            assert_eq!(backend.scoped_test_retained().await, 0);
            opening.recheck().unwrap();
            authority.close_execution().await;
            quorum.close().await;
        });
}

async fn overlap(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
    direction: XfrmDirection,
) {
    let old_request = request(145, direction);
    let next_request = candidate(&old_request, 1);
    let old = install_initial_scoped(
        backend,
        profile,
        authority,
        quorum,
        145,
        old_request.clone(),
    )
    .await;
    let traffic = Traffic::start(&old_request, &next_request, old_request.sa.id.spi);
    traffic.checkpoint(old_request.sa.id.spi);
    let next = backend
        .install_scoped_successor(
            profile,
            grant(authority, quorum, 146).await,
            &old,
            next_request.clone(),
        )
        .await
        .unwrap();
    let status = backend.scoped_successor_status(&old).await.unwrap();
    assert!(status.successor_sa_installed() && status.traffic_moved() && status.published());
    assert!(!status.predecessor_retired());
    assert_eq!(
        backend.read_scoped(&old).await.unwrap(),
        direction == XfrmDirection::In
    );
    assert_sa_live(backend, &old_request).await;
    assert!(backend.read_scoped(&next).await.unwrap());
    let traffic = if direction == XfrmDirection::In {
        traffic.checkpoint(old_request.sa.id.spi);
        assert!(traffic.finish().0 >= 2);
        Traffic::start(&old_request, &next_request, next_request.sa.id.spi)
    } else {
        traffic
    };
    traffic.checkpoint(next_request.sa.id.spi);
    backend.remove_scoped(&old).await.unwrap();
    traffic.checkpoint(next_request.sa.id.spi);
    assert!(traffic.finish().1 >= 2);
    assert!(backend
        .scoped_successor_status(&old)
        .await
        .unwrap()
        .predecessor_retired());
    assert!(!backend.read_scoped(&old).await.unwrap());
    assert!(backend.read_scoped(&next).await.unwrap());
    backend.remove_scoped(&next).await.unwrap();
}

async fn generations(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    for (id, retire_first) in [(150, false), (154, true)] {
        let first_request = request(id, XfrmDirection::Out);
        let first = install_initial_scoped(
            backend,
            profile,
            authority,
            quorum,
            id,
            first_request.clone(),
        )
        .await;
        let second_request = candidate(&first_request, 1);
        let second = backend
            .install_scoped_successor(
                profile,
                grant(authority, quorum, id + 1).await,
                &first,
                second_request.clone(),
            )
            .await
            .unwrap();
        if retire_first {
            backend.remove_scoped(&first).await.unwrap();
        }
        let third_request = candidate(&second_request, 1);
        let third = backend
            .install_scoped_successor(
                profile,
                grant(authority, quorum, id + 2).await,
                &second,
                third_request.clone(),
            )
            .await
            .unwrap();
        let traffic = Traffic::start(&second_request, &third_request, second_request.sa.id.spi);
        traffic.checkpoint(third_request.sa.id.spi);
        backend.remove_scoped(&third).await.unwrap();
        traffic.checkpoint(second_request.sa.id.spi);
        let counts = traffic.finish();
        assert!(counts.0 >= 1 && counts.1 >= 1);
        assert!(backend.read_scoped(&second).await.unwrap());
        if !retire_first {
            assert!(!backend.read_scoped(&first).await.unwrap());
            assert_sa_live(backend, &first_request).await;
            backend.remove_scoped(&first).await.unwrap();
        }
        backend.remove_scoped(&second).await.unwrap();
    }
}

async fn assert_sa_live(backend: &NamespaceBoundLinuxXfrmBackend, request: &ScopedXfrmRequest) {
    let observed = backend
        .query_sa(QuerySaRequest {
            destination: request.sa.id.destination,
            spi: request.sa.id.spi,
            protocol: request.sa.id.protocol,
            mark: request.sa.mark,
        })
        .await
        .unwrap();
    assert_eq!(observed.id, request.sa.id);
    assert_eq!(observed.request_id, request.sa.request_id);
}

async fn expired_group(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    for (id, successor_first) in [(190, false), (194, true)] {
        let old_request = request(id, XfrmDirection::Out);
        let old =
            install_initial_scoped(backend, profile, authority, quorum, id, old_request.clone())
                .await;
        let next_request = candidate(&old_request, 1);
        let next = backend
            .install_scoped_successor(
                profile,
                grant(authority, quorum, id + 1).await,
                &old,
                next_request.clone(),
            )
            .await
            .unwrap();
        for request in [&old_request, &next_request] {
            LinuxXfrmBackend::new()
                .remove_sa(RemoveSaRequest {
                    destination: request.sa.id.destination,
                    spi: request.sa.id.spi,
                    protocol: request.sa.id.protocol,
                    mark: request.sa.mark,
                })
                .await
                .unwrap();
        }
        let (first, last) = if successor_first {
            (&next, &old)
        } else {
            (&old, &next)
        };
        backend.remove_scoped(first).await.unwrap();
        assert!(first.is_retired());
        assert!(!last.is_retired());
        backend.remove_scoped(last).await.unwrap();
        assert!(last.is_retired());
        assert!(backend.local_namespace_empty().await.unwrap());
        assert_eq!(backend.scoped_test_retained().await, 0);
    }
}

async fn retry(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    let old_request = request(160, XfrmDirection::Out);
    let old = install_initial_scoped(
        backend,
        profile,
        authority,
        quorum,
        160,
        old_request.clone(),
    )
    .await;
    let next_request = candidate(&old_request, 1);
    let effect = grant(authority, quorum, 161).await;
    let next = backend
        .install_scoped_successor(profile, effect.clone(), &old, next_request.clone())
        .await
        .unwrap();
    quorum.set_available(false);
    let recovered = backend
        .install_scoped_successor(profile, effect.clone(), &old, next_request.clone())
        .await
        .unwrap();
    assert!(recovered.same_as(&next));
    backend.remove_scoped(&old).await.unwrap();
    let recovered = backend
        .install_scoped_successor(profile, effect, &old, next_request)
        .await
        .unwrap();
    assert!(recovered.same_as(&next));
    assert!(backend
        .scoped_successor_status(&old)
        .await
        .unwrap()
        .predecessor_retired());
    backend.remove_scoped(&recovered).await.unwrap();
}

async fn readback(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    let old_request = request(165, XfrmDirection::Out);
    let old = install_initial_scoped(
        backend,
        profile,
        authority,
        quorum,
        165,
        old_request.clone(),
    )
    .await;
    let next_request = candidate(&old_request, 1);
    let next = backend
        .install_scoped_successor(
            profile,
            grant(authority, quorum, 166).await,
            &old,
            next_request.clone(),
        )
        .await
        .unwrap();
    // Model hard expiry without trusting the actor's publication flags.
    LinuxXfrmBackend::new()
        .remove_sa(RemoveSaRequest {
            destination: next_request.sa.id.destination,
            spi: next_request.sa.id.spi,
            protocol: next_request.sa.id.protocol,
            mark: next_request.sa.mark,
        })
        .await
        .unwrap();
    let status = backend.scoped_successor_status(&old).await.unwrap();
    assert!(!status.successor_sa_installed());
    assert!(!status.traffic_moved());
    assert!(!status.predecessor_retired());
    assert!(matches!(
        backend.remove_scoped(&old).await,
        Err(XfrmError::StateMismatch {
            operation: "local_scope_successor_not_live"
        })
    ));
    backend.remove_scoped(&next).await.unwrap();
    assert!(backend.read_scoped(&old).await.unwrap());
    let traffic = Traffic::start(&old_request, &next_request, old_request.sa.id.spi);
    traffic.checkpoint(old_request.sa.id.spi);
    assert!(traffic.finish().0 >= 1);
    backend.remove_scoped(&old).await.unwrap();
}

async fn abandon(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    for (id, direction) in [(170, XfrmDirection::Out), (174, XfrmDirection::In)] {
        let old_request = request(id, direction);
        let old =
            install_initial_scoped(backend, profile, authority, quorum, id, old_request.clone())
                .await;
        let next_request = candidate(&old_request, 1);
        let next = backend
            .install_scoped_successor(
                profile,
                grant(authority, quorum, id + 1).await,
                &old,
                next_request.clone(),
            )
            .await
            .unwrap();
        let traffic = Traffic::start(&old_request, &next_request, old_request.sa.id.spi);
        traffic.checkpoint(if direction == XfrmDirection::Out {
            next_request.sa.id.spi
        } else {
            old_request.sa.id.spi
        });
        backend.remove_scoped(&next).await.unwrap();
        traffic.checkpoint(old_request.sa.id.spi);
        let counts = traffic.finish();
        assert!(counts.0 >= 1);
        assert!(backend.read_scoped(&old).await.unwrap());
        let another = backend
            .install_scoped_successor(
                profile,
                grant(authority, quorum, id + 2).await,
                &old,
                candidate(&old_request, 2),
            )
            .await
            .unwrap();
        backend.remove_scoped(&old).await.unwrap();
        assert!(backend.read_scoped(&another).await.unwrap());
        backend.remove_scoped(&another).await.unwrap();
    }
}

async fn cancelled(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
    after_selection: bool,
) {
    let old_request = request(180, XfrmDirection::Out);
    let old = install_initial_scoped(
        backend,
        profile,
        authority,
        quorum,
        180,
        old_request.clone(),
    )
    .await;
    let next_request = candidate(&old_request, 1);
    let effect = grant(authority, quorum, 181).await;
    let other_effect = grant(authority, quorum, 182).await;
    let sibling_request = request(183, XfrmDirection::Out);
    let sibling = install_initial_scoped(
        backend,
        profile,
        authority,
        quorum,
        183,
        sibling_request.clone(),
    )
    .await;
    let sibling_traffic = Traffic::start(
        &sibling_request,
        &candidate(&sibling_request, 1),
        sibling_request.sa.id.spi,
    );
    sibling_traffic.checkpoint(sibling_request.sa.id.spi);
    let hold = Arc::new(operations::TestHold::default());
    backend
        .scoped_test_fault(if after_selection {
            operations::TestFault::HoldSuccessorSelection(hold.clone())
        } else {
            operations::TestFault::HoldSuccessorSa(hold.clone())
        })
        .await;
    let task = tokio::spawn({
        let backend = backend.clone();
        let profile = profile.clone();
        let old = old.clone();
        let next = next_request.clone();
        let effect = effect.clone();
        async move {
            backend
                .install_scoped_successor(&profile, effect, &old, next)
                .await
        }
    });
    hold.entered.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let status = backend.scoped_successor_status(&old).await.unwrap();
    assert!(status.successor_sa_installed());
    assert_eq!(status.traffic_moved(), after_selection);
    assert!(!status.predecessor_retired() && !status.published());
    assert!(backend.read_scoped(&sibling).await.unwrap());
    sibling_traffic.checkpoint(sibling_request.sa.id.spi);
    assert!(matches!(
        backend
            .install_scoped_successor(profile, other_effect, &old, candidate(&old_request, 2))
            .await,
        Err(XfrmError::AlreadyExists)
    ));
    let traffic = Traffic::start(&old_request, &next_request, old_request.sa.id.spi);
    traffic.checkpoint(if after_selection {
        next_request.sa.id.spi
    } else {
        old_request.sa.id.spi
    });
    hold.resume.store(true, Ordering::Release);
    settle(backend).await;
    let next = backend
        .install_scoped_successor(profile, effect, &old, next_request.clone())
        .await
        .unwrap();
    traffic.checkpoint(next_request.sa.id.spi);
    assert!(traffic.finish().1 >= 1);
    sibling_traffic.checkpoint(sibling_request.sa.id.spi);
    assert!(sibling_traffic.finish().0 >= 3);
    backend.remove_scoped(&sibling).await.unwrap();
    backend.remove_scoped(&old).await.unwrap();
    backend.remove_scoped(&next).await.unwrap();
}

async fn panic_recovery(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
) {
    for (id, fault) in [
        (185, operations::TestFault::PanicAfterSuccessorSa),
        (187, operations::TestFault::PanicAfterSuccessorSelection),
        (189, operations::TestFault::DropSuccessorReply),
    ] {
        let old_request = request(id, XfrmDirection::Out);
        let old =
            install_initial_scoped(backend, profile, authority, quorum, id, old_request.clone())
                .await;
        let next_request = candidate(&old_request, 1);
        let effect = grant(authority, quorum, id + 1).await;
        backend.scoped_test_fault(fault).await;
        assert!(backend
            .install_scoped_successor(profile, effect.clone(), &old, next_request.clone())
            .await
            .is_err());
        settle(backend).await;
        let next = backend
            .install_scoped_successor(profile, effect, &old, next_request)
            .await
            .unwrap();
        assert!(backend.read_scoped(&old).await.unwrap());
        assert!(backend.read_scoped(&next).await.unwrap());
        backend.remove_scoped(&old).await.unwrap();
        backend.remove_scoped(&next).await.unwrap();
    }
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_inbound_overlap() {
    exercise(Case::Inbound, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_inbound_overlap() {
    exercise(Case::Inbound, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_outbound_atomic_selection() {
    exercise(Case::Outbound, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_outbound_atomic_selection() {
    exercise(Case::Outbound, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_repeated_generations() {
    exercise(Case::Generations, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_repeated_generations() {
    exercise(Case::Generations, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_exact_retry() {
    exercise(Case::Retry, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_exact_retry() {
    exercise(Case::Retry, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_fresh_status() {
    exercise(Case::Readback, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_fresh_status() {
    exercise(Case::Readback, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_expired_group_cleans_up_in_both_orders() {
    exercise(Case::ExpiredGroup, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_expired_group_cleans_up_in_both_orders() {
    exercise(Case::ExpiredGroup, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_abandonment_restores_traffic() {
    exercise(Case::Abandon, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_abandonment_restores_traffic() {
    exercise(Case::Abandon, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_cancel_after_sa() {
    exercise(Case::HoldSa, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_cancel_after_sa() {
    exercise(Case::HoldSa, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_cancel_after_policy() {
    exercise(Case::HoldPolicy, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_cancel_after_policy() {
    exercise(Case::HoldPolicy, true);
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_panic_forward_completion() {
    exercise(Case::Panic, false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_panic_forward_completion() {
    exercise(Case::Panic, true);
}

fn exercise_expired_successor_refusal_releases_reset(native: bool) {
    let (_cleanup, lifecycle) = scope();
    let backend = backend(&lifecycle);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let quorum = Quorum::open(native).await;
            let reset = lifecycle
                .reset(participants(&lifecycle, &backend))
                .await
                .unwrap();
            let profile = backend.admit_scoped_profile(&reset).await.unwrap();
            let authority = TestAuthority::new(lifecycle.clone(), &quorum)
                .await
                .unwrap();
            let old_request = request(200, XfrmDirection::Out);
            let old = backend
                .install_scoped(
                    &profile,
                    grant(&authority, &quorum, 200).await,
                    old_request.clone(),
                )
                .await
                .unwrap();
            let next_request = candidate(&old_request, 1);
            let mut next_sa = next_request.sa.clone();
            next_sa.lifetime.hard_add_expires_seconds = 1;
            let next_request =
                ScopedXfrmRequest::new(next_sa, next_request.policy.clone()).unwrap();
            let next = backend
                .install_scoped_successor(
                    &profile,
                    grant(&authority, &quorum, 201).await,
                    &old,
                    next_request.clone(),
                )
                .await
                .unwrap();
            // Let the kernel hard lifetime expire the SA, with no external
            // DELSA and no receipt cleanup that could release a leaked guard.
            let reader = LinuxXfrmBackend::new();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match reader
                        .query_sa(QuerySaRequest {
                            destination: next_request.sa.id.destination,
                            spi: next_request.sa.id.spi,
                            protocol: next_request.sa.id.protocol,
                            mark: next_request.sa.mark,
                        })
                        .await
                    {
                        Err(XfrmError::NotFound) => break,
                        Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                        Err(error) => panic!("unexpected expiry readback: {error:?}"),
                    }
                }
            })
            .await
            .expect("successor must reach its kernel hard lifetime");
            assert!(matches!(
                backend.remove_scoped(&old).await,
                Err(XfrmError::StateMismatch {
                    operation: "local_scope_successor_not_live"
                })
            ));
            let retained = reader
                .query_sa(QuerySaRequest {
                    destination: old_request.sa.id.destination,
                    spi: old_request.sa.id.spi,
                    protocol: old_request.sa.id.protocol,
                    mark: old_request.sa.mark,
                })
                .await
                .unwrap();
            assert_eq!(retained.id, old_request.sa.id);
            assert!(!old.is_retired() && !next.is_retired());
            authority.close_execution().await;
            tokio::time::timeout(
                Duration::from_secs(5),
                lifecycle.reset(participants(&lifecycle, &backend)),
            )
            .await
            .expect("retirement refusal must release the reset barrier")
            .unwrap();
            assert!(backend.local_namespace_empty().await.unwrap());
            assert!(backend.read_scoped(&old).await.is_err());
            assert!(backend.read_scoped(&next).await.is_err());
            quorum.close().await;
        });
}

#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_scoped_successor_expiry_refusal_releases_reset() {
    exercise_expired_successor_refusal_releases_reset(false);
}

#[cfg(feature = "native-scope")]
#[test]
#[ignore = "requires CAP_NET_ADMIN, private bpffs and private netns"]
fn native_transport_scoped_successor_expiry_refusal_releases_reset() {
    exercise_expired_successor_refusal_releases_reset(true);
}
