mod fenced_non_execution {
    use super::*;
    use crate::XfrmObjectRosterMemberPhase;

    // Commit the original store identity before admission or any preparation.
    fn settlement_roster(
        store: &XfrmObjectRosterRecoveryStore,
        group: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: XfrmObjectRosterRequest,
    ) -> XfrmObjectRosterRequest {
        let roster = roster.with_settlement_identity(store.settlement_identity());
        let identity =
            register_object_roster_settlement(store, group, generation, &roster).unwrap();
        roster.with_settlement_identity(identity)
    }

    // Exercise the production publication outside the namespace actor queue.
    async fn close_generation(
        backend: &NamespaceBoundLinuxXfrmBackend,
        store: &XfrmObjectRosterRecoveryStore,
        group: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterFenceObservation, XfrmObjectRosterDurableError> {
        backend
            .fence_durable_object_roster(store, group, generation, roster)
            .await
    }

    // The consumer has durably terminalized before surrendering retention.
    async fn release_settled(
        backend: &NamespaceBoundLinuxXfrmBackend,
        store: &XfrmObjectRosterRecoveryStore,
        group: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        backend
            .release_durable_object_roster_settlement(store, group, generation, roster)
            .await
    }

    #[derive(Debug, Default)]
    struct EffectGate {
        entered: tokio::sync::Notify,
        released: Mutex<bool>,
        wake: Condvar,
    }

    impl EffectGate {
        fn hold(&self) {
            let mut released = self.released.lock().unwrap();
            self.entered.notify_one();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.wake.notify_all();
        }

        async fn wait_entered(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.entered.notified())
                .await
                .expect("actor must reach the explicit test latch");
        }
    }

    struct ReleaseOnDrop(Arc<EffectGate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[derive(Debug, Clone)]
    struct PreEffectTransport {
        gate: Arc<EffectGate>,
        query_ordinal: Arc<AtomicUsize>,
        block_query: usize,
        effects: Arc<AtomicUsize>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    impl PreEffectTransport {
        fn new(block_query: usize) -> Self {
            Self {
                gate: Arc::new(EffectGate::default()),
                query_ordinal: Arc::new(AtomicUsize::new(0)),
                block_query,
                effects: Arc::new(AtomicUsize::new(0)),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl LinuxXfrmTransport for PreEffectTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            _: &[u8],
            _: u32,
            _: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations.lock().unwrap().push(operation);
            match class {
                crate::linux::NetlinkOperationClass::ReadOnly => {
                    if self.query_ordinal.fetch_add(1, Ordering::SeqCst) == self.block_query {
                        self.gate.hold();
                    }
                    Err(XfrmError::NotFound)
                }
                crate::linux::NetlinkOperationClass::Mutation => {
                    if operation == "install_sa" || operation == "install_policy" {
                        self.effects.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(None)
                }
            }
        }
        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    fn closed_without_effect(
        result: &Result<XfrmObjectRosterFenceObservation, XfrmObjectRosterDurableError>,
    ) -> bool {
        result
            .as_ref()
            .is_ok_and(XfrmObjectRosterFenceObservation::closed_without_effect)
    }

    #[derive(Debug, Clone)]
    struct InstalledGateTransport {
        inner: RecordingSuccessTransport,
        installed: Arc<EffectGate>,
    }

    impl LinuxXfrmTransport for InstalledGateTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            request: &[u8],
            sequence: u32,
            config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            let result = self
                .inner
                .transact(operation, class, request, sequence, config);
            if operation == "install_sa" {
                self.installed.hold();
            }
            result
        }

        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    async fn run_across_forced_store_contention(after_install: bool) {
        let root = DurableTestRoot::new();
        let installed = Arc::new(EffectGate::default());
        let _installed_release = ReleaseOnDrop(Arc::clone(&installed));
        if !after_install {
            installed.release();
        }
        let transport = InstalledGateTransport {
            inner: RecordingSuccessTransport::default(),
            installed: Arc::clone(&installed),
        };
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB7);
        let group = roster_group(0xB8);
        let generation = roster_generation(37);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let mut authority = Some(authority);
        let held = Arc::new(EffectGate::default());
        let contended = Arc::new(EffectGate::default());
        let _held_release = ReleaseOnDrop(Arc::clone(&held));
        let _contention_release = ReleaseOnDrop(Arc::clone(&contended));
        let run = if after_install {
            let actor = backend.clone();
            let authority = authority.take().unwrap();
            let run = tokio::spawn(async move { actor.run_durable_object_roster(authority).await });
            installed.wait_entered().await;
            Some(run)
        } else {
            None
        };
        let holder = std::thread::spawn({
            let store = store.clone();
            let held = Arc::clone(&held);
            move || {
                let _lock = store.hold_process_lock_for_test();
                held.hold();
            }
        });
        held.wait_entered().await;
        store.on_next_lease_contention_for_test({
            let contended = Arc::clone(&contended);
            Arc::new(move || contended.hold())
        });
        let run = match run {
            Some(run) => {
                installed.release();
                run
            }
            None => {
                let actor = backend.clone();
                let authority = authority.take().unwrap();
                tokio::spawn(async move { actor.run_durable_object_roster(authority).await })
            }
        };
        contended.wait_entered().await;
        held.release();
        holder.join().unwrap();
        contended.release();
        let outcome = run.await.unwrap();
        assert!(
            outcome
                .as_ref()
                .is_ok_and(|outcome| outcome.as_str() == "applied"),
            "store contention must preserve the run and its affine authority: {outcome:?}"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        assert_eq!(
            transport
                .inner
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_lock_contention_before_run_preserves_authority() {
        run_across_forced_store_contention(false).await;
    }

    #[tokio::test]
    async fn fenced_non_execution_lock_contention_after_install_completes_publication() {
        run_across_forced_store_contention(true).await;
    }

    #[tokio::test]
    async fn fenced_non_execution_caller_deadlines_leave_fence_and_release_owned() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB9);
        let group = roster_group(0xB9);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(1));
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        for index in 1..=29 {
            let unrelated = XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(
                roster_policy_request(index),
            )])
            .unwrap();
            drop(
                backend
                    .prepare_durable_object_roster(
                        &store,
                        roster_group(index as u8),
                        generation,
                        unrelated,
                    )
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(backend.prepare_durable_object_roster(
            &store, roster_group(0xFA), generation, sa_roster(1),
        ).await.unwrap_err(), XfrmObjectRosterDurableError::CapacityExceeded);
        for releasing in [false, true] {
            let held = Arc::new(EffectGate::default());
            let contended = Arc::new(EffectGate::default());
            let _held_release = ReleaseOnDrop(Arc::clone(&held));
            let _contention_release = ReleaseOnDrop(Arc::clone(&contended));
            let holder = std::thread::spawn({
                let store = store.clone();
                let held = Arc::clone(&held);
                move || {
                    let _lock = store.hold_process_lock_for_test();
                    held.hold();
                }
            });
            held.wait_entered().await;
            store.on_next_lease_contention_for_test({
                let contended = Arc::clone(&contended);
                Arc::new(move || contended.hold())
            });
            let publications_before = store.publication_ledger().unwrap().len();
            let expired = {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                let call = async {
                    if releasing {
                        release_settled(&backend, &store, group, generation, &roster).await
                    } else {
                        let observed =
                            close_generation(&backend, &store, group, generation, &roster).await?;
                        assert!(observed.closed_without_effect());
                        Ok(())
                    }
                };
                let mut caller = Box::pin(tokio::time::timeout_at(deadline, call));
                tokio::select! {
                    () = contended.wait_entered() => {},
                    _ = &mut caller => panic!("the caller must reach the held store lock"),
                }
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(2)).await;
                let expired = caller.await.is_err();
                tokio::time::resume();
                expired
            };
            assert!(
                expired,
                "the caller future is dropped at its original deadline"
            );
            assert_eq!(
                store.publication_ledger().unwrap().len(),
                publications_before
            );
            held.release();
            holder.join().unwrap();
            contended.release();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let ledger = store.publication_ledger().unwrap();
                    if ledger.iter().skip(publications_before).any(|publication| {
                        if releasing {
                            publication.class
                                == crate::durable_roster::XfrmObjectRosterPublicationClass::Release
                        } else {
                            publication.phase == XfrmObjectRosterDurablePhase::Closed
                        }
                    }) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("accepted work publishes without another caller or retry");
        }
        assert!(backend
            .prepare_durable_object_roster(&store, group, generation, roster)
            .await
            .is_err());
        drop(
            backend
                .prepare_durable_object_roster(&store, roster_group(0xFA), generation, sa_roster(1))
                .await
                .unwrap(),
        );
        assert!(transport.operations().is_empty());
        assert_eq!(store.publication_ledger().unwrap().len(), 33);
    }

    #[tokio::test]
    async fn fenced_non_execution_concurrent_settlement_preserves_one_hundred_unrelated_runs() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB6);
        for index in 1..=100 {
            let generation = roster_generation(index);
            let settled_group = roster_group(0xB5);
            let settled = settlement_roster(&store, settled_group, generation, policy_roster(1));
            drop(
                backend
                    .prepare_durable_object_roster(
                        &store,
                        settled_group,
                        generation,
                        settled.clone(),
                    )
                    .await
                    .unwrap(),
            );
            let settlement = async {
                assert!(
                    close_generation(&backend, &store, settled_group, generation, &settled)
                        .await
                        .unwrap()
                        .closed_without_effect()
                );
                release_settled(&backend, &store, settled_group, generation, &settled)
                    .await
                    .unwrap();
            };
            let independent = async {
                let group = roster_group(0xB4);
                let roster = sa_roster(1);
                let authority = backend
                    .prepare_durable_object_roster(&store, group, generation, roster.clone())
                    .await
                    .unwrap();
                assert_eq!(
                    backend
                        .run_durable_object_roster(authority)
                        .await
                        .unwrap()
                        .as_str(),
                    "applied"
                );
                assert_eq!(
                    backend
                        .finalize_durable_object_roster(&store, group, generation, &roster)
                        .await
                        .unwrap(),
                    XfrmObjectRosterDurablePhase::Committed
                );
            };
            tokio::join!(settlement, independent);
        }
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            100
        );
        assert!(!transport.operations().contains(&"remove_sa"));
    }

    #[tokio::test]
    async fn fenced_non_execution_identical_untransmitted_retry_registers_before_execution() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB3);
        let group = roster_group(0xB2);
        let generation = roster_generation(37);
        let roster = sa_roster(1);
        let identity = backend
            .register_durable_object_roster_settlement(&store, group, generation, &roster)
            .await
            .unwrap();
        let roster = roster.with_settlement_identity(identity);
        backend
            .discard_unadmitted_durable_object_roster_settlement(&store, group, generation, &roster)
            .await
            .unwrap();
        assert!(backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .is_err());
        assert_eq!(
            backend
                .register_durable_object_roster_settlement(&store, group, generation, &roster)
                .await
                .unwrap(),
            identity
        );
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        release_settled(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(backend
            .prepare_durable_object_roster(&store, group, generation, roster)
            .await
            .is_err());
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_full_store_closes_absent_members_without_a_live_slot() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xBA);
        let generation = roster_generation(37);
        let mut admissions = Vec::new();
        for index in 0..30 {
            let prepared_group = roster_group(u8::try_from(index + 1).unwrap());
            let absent_group = roster_group(u8::try_from(index + 101).unwrap());
            let prepared = settlement_roster(
                &store,
                prepared_group,
                generation,
                XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(
                    roster_sa_request(index),
                )])
                .unwrap(),
            );
            let absent = settlement_roster(
                &store,
                absent_group,
                generation,
                XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(
                    roster_policy_request(index),
                )])
                .unwrap(),
            );
            drop(
                backend
                    .prepare_durable_object_roster(
                        &store,
                        prepared_group,
                        generation,
                        prepared.clone(),
                    )
                    .await
                    .unwrap(),
            );
            admissions.push((prepared_group, absent_group, prepared, absent));
        }
        let publications = store.publication_ledger().unwrap().len();
        for (prepared_group, absent_group, prepared, absent) in admissions {
            let before = store.publication_ledger().unwrap().len();
            let closed =
                close_generation(&backend, &store, absent_group, generation, &absent).await;
            assert!(
                closed_without_effect(&closed),
                "a full store must close absence without a slot: {closed:?}"
            );
            assert_eq!(store.publication_ledger().unwrap().len(), before);
            assert!(closed_without_effect(
                &close_generation(&backend, &store, prepared_group, generation, &prepared).await
            ));
            release_settled(&backend, &store, prepared_group, generation, &prepared)
                .await
                .unwrap();
            release_settled(&backend, &store, absent_group, generation, &absent)
                .await
                .unwrap();
        }
        assert_eq!(store.publication_ledger().unwrap().len(), publications + 60);
        drop(
            backend
                .prepare_durable_object_roster(&store, roster_group(0xFE), generation, sa_roster(1))
                .await
                .unwrap(),
        );
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_reset_applied_held_finalizes_as_retired() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xBB);
        let group = roster_group(0xBC);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(1));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        store.reset_after_namespace_empty().unwrap();
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Retired
        );
        release_settled(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(!transport.operations().contains(&"remove_sa"));
    }

    #[tokio::test]
    async fn fenced_non_execution_preserves_ordinary_unstarted_recovery() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xA1);
        let group = roster_group(0xA2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        let retired = backend
            .recover_durable_object_roster(&store, group, generation, &roster)
            .await
            .unwrap();
        assert!(matches!(
            retired,
            XfrmObjectRosterRestartOutcome::NoMutation { .. }
        ));
        for _ in 0..2 {
            let observed = close_generation(&backend, &store, group, generation, &roster)
                .await
                .unwrap();
            assert!(observed.closed_without_effect());
            assert_eq!(observed.phase(), XfrmObjectRosterDurablePhase::Retired);
            assert_eq!(observed.members(), retired.members());
            assert!(!observed.namespace_was_cleared());
        }
        assert!(backend
            .prepare_durable_object_roster(&store, group, generation, roster)
            .await
            .is_err());
        assert!(transport.operations().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_excludes_provider_dispatch_paused_before_actor_admission() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB1);
        let group = roster_group(0xB2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // Retain the original affine authority without polling its run future.
        let fence = close_generation(&backend, &store, group, generation, &roster).await;
        let fenced = closed_without_effect(&fence);
        let label = match &fence {
            Ok(outcome) => outcome.as_str(),
            Err(error) => error.as_str(),
        };
        let delayed = backend.run_durable_object_roster(authority).await;
        let effects = transport
            .operations()
            .iter()
            .filter(|operation| **operation == "install_sa")
            .count();
        // Retire any late run so the assertion reports effects, not leftovers.
        let _ = backend
            .recover_durable_object_roster(&store, group, generation, &roster)
            .await;
        assert!(fenced && delayed.is_err() && effects == 0,
            "exact closure must precede delayed provider dispatch: fence={label}, late_effects={effects}, refused={}", delayed.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_settles_before_releasing_the_pre_effect_actor_latch() {
        let root = DurableTestRoot::new();
        // Two sweep queries, then member zero's adjacent read. No physical
        // mutation has been submitted when that last pre-effect read is held.
        let transport = PreEffectTransport::new(2);
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB3);
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xB4);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let run = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_object_roster(authority).await }
        });
        transport.gate.wait_entered().await;
        assert_eq!(transport.effects.load(Ordering::SeqCst), 0);
        let fence = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        let fenced_while_held = fence.as_ref().is_ok_and(closed_without_effect);
        assert!(
            !*transport.gate.released.lock().unwrap(),
            "the fence cannot release the test latch"
        );
        transport.gate.release();
        let delayed = run.await.unwrap();
        // Let queued actor work finish before reading counters.
        let _ = backend.query_sa(query_request()).await;
        let effects = transport.effects.load(Ordering::SeqCst);
        assert!(fenced_while_held && delayed.is_err() && effects == 0,
            "closure must finish while pre-effect writer is paused: completed_before_release={fenced_while_held}, late_effects={effects}, refused={}", delayed.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_excludes_roster_work_queued_before_the_fence_request() {
        let root = DurableTestRoot::new();
        let transport = PreEffectTransport::new(0);
        let (backend, _, _, store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            1,
            None,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0xB5; 32]).unwrap(),
            )),
        )
        .unwrap();
        let store = store.unwrap();
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xB6);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let blocking_read = tokio::spawn({
            let backend = backend.clone();
            async move { backend.query_sa(query_request()).await }
        });
        transport.gate.wait_entered().await;
        let queued_run = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_object_roster(authority).await }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;
        let fence = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        let fenced_while_queued = fence.as_ref().is_ok_and(closed_without_effect);
        transport.gate.release();
        let _ = blocking_read.await.unwrap();
        let delayed = queued_run.await.unwrap();
        let effects = transport.effects.load(Ordering::SeqCst);
        let _ = backend
            .recover_durable_object_roster(&store, group, generation, &roster)
            .await;
        assert!(fenced_while_queued && delayed.is_err() && effects == 0,
            "queue admission is not physical acceptance: fenced_while_queued={fenced_while_queued}, late_effects={effects}, refused={}", delayed.is_err());
    }
    /// The object becomes visible before its acknowledgement is released.
    /// Exact readback remains available after the observer disappears.
    #[derive(Debug, Clone, Default)]
    struct AcceptedEffectTransport {
        gate: Arc<EffectGate>,
        accepted: Arc<AtomicUsize>,
        removals: Arc<AtomicUsize>,
        visible: Arc<AtomicBool>,
    }

    impl LinuxXfrmTransport for AcceptedEffectTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            _: &[u8],
            _: u32,
            _: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            match class {
                crate::linux::NetlinkOperationClass::ReadOnly => {
                    if self.visible.load(Ordering::SeqCst) {
                        Ok(Some(durable_object_readback_body(&roster_sa_request(0))))
                    } else {
                        Err(XfrmError::NotFound)
                    }
                }
                crate::linux::NetlinkOperationClass::Mutation => {
                    match operation {
                        "install_sa" => {
                            self.visible.store(true, Ordering::SeqCst);
                            self.accepted.fetch_add(1, Ordering::SeqCst);
                            self.gate.hold();
                        }
                        "remove_sa" => {
                            self.removals.fetch_add(1, Ordering::SeqCst);
                            self.visible.store(false, Ordering::SeqCst);
                        }
                        _ => panic!("unexpected synthetic transport mutation"),
                    }
                    Ok(None)
                }
            }
        }

        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_joins_accepted_work_without_granting_compensation() {
        let root = DurableTestRoot::new();
        let transport = AcceptedEffectTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xC1);
        let _release = ReleaseOnDrop(Arc::clone(&transport.gate));
        let group = roster_group(0xC2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(1));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let observer = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .detector_cut_roster_issuing_at_member(authority, 0, true)
                    .await
            }
        });
        transport.gate.wait_entered().await;
        assert_eq!(transport.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        // Lose the outer acknowledgement while the physically accepted work
        // remains owned by the actor. Cancellation cannot prove non-execution.
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        let pending = tokio::time::timeout(
            Duration::from_secs(2),
            close_generation(&backend, &store, group, generation, &roster),
        )
        .await;
        assert!(
            !pending.as_ref().is_ok_and(closed_without_effect),
            "an accepted, unquiesced effect cannot produce a negative receipt"
        );
        assert_eq!(transport.removals.load(Ordering::SeqCst), 0);
        transport.gate.release();
        // Drain accepted work and any retained closure after caller timeout.
        let _ = backend.query_sa(query_request()).await;
        let observed = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&observed),
            "a lost acknowledgement must never relabel accepted work as never-started"
        );
        assert_eq!(
            transport.accepted.load(Ordering::SeqCst),
            1,
            "reconciliation must not replay the effect"
        );
        assert_eq!(transport.removals.load(Ordering::SeqCst), 0,
            "closure alone cannot compensate an accepted object; complete abort authority is absent");
        assert!(
            transport.visible.load(Ordering::SeqCst),
            "the accepted object remains available for normal exact adoption"
        );
    }
    #[tokio::test]
    async fn fenced_non_execution_preserves_applied_state_for_exact_adoption() {
        let root = DurableTestRoot::new();
        let transport = RosterConvergenceTransport::new();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD1);
        let group = roster_group(0xD2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();
        transport
            .converge((0..2).map(|index| durable_object_readback_body(&roster_sa_request(index))));
        let before = transport.operations().len();
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&closure),
            "Applied can never become a never-started receipt"
        );
        let after = transport.operations();
        let mutations = after[before..]
            .iter()
            .filter(|operation| **operation != "query_sa")
            .count();
        assert_eq!(
            mutations, 0,
            "closing execution must preserve Applied; it grants no aborting proof set"
        );
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        transport
            .converge((0..2).map(|index| durable_object_readback_body(&roster_sa_request(index))));
        assert_eq!(
            backend
                .adopt_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "adopted"
        );
        let repeated = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(!closed_without_effect(&repeated));
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Committed)
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_preserves_partially_issued_prefix_without_compensation_authority()
    {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD3);
        let group = roster_group(0xD4);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(3));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_issuing_at_member(authority, 1, false)
            .await
            .unwrap();
        let before = transport.operations();
        assert_eq!(
            before
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1
        );
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&closure),
            "a partially issued roster is not never-started"
        );
        let after = transport.operations();
        assert!(after[before.len()..].iter().all(|operation| *operation == "query_sa"),
            "closure must leave the owned prefix for separately authorized recovery; extra operations={:?}", &after[before.len()..]);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
    }

    #[tokio::test]
    async fn fenced_non_execution_conflicting_foreign_object_is_never_deleted() {
        let root = DurableTestRoot::new();
        let transport = RosterConvergenceTransport::new();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD5);
        let group = roster_group(0xD6);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(1));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // Even an equal-looking object predating our effect is foreign.
        transport.converge([durable_object_readback_body(&roster_sa_request(0))]);
        let run = backend.run_durable_object_roster(authority).await.unwrap();
        assert_eq!(run.as_str(), "no_mutation");
        let closure = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert_eq!(closure.as_str(), "foreign_untouched");
        assert!(transport
            .operations()
            .iter()
            .all(|operation| *operation == "query_sa"));
        assert!(closure.members().has_conflict());
    }

    #[derive(Debug, Clone, Default)]
    struct UnavailableAfterCutTransport {
        inner: RecordingSuccessTransport,
        unavailable: Arc<AtomicBool>,
    }

    impl LinuxXfrmTransport for UnavailableAfterCutTransport {
        fn transact(
            &self,
            operation: &'static str,
            class: crate::linux::NetlinkOperationClass,
            request: &[u8],
            sequence: u32,
            config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            if matches!(class, crate::linux::NetlinkOperationClass::ReadOnly)
                && self.unavailable.load(Ordering::SeqCst)
            {
                return Err(XfrmError::Unavailable);
            }
            self.inner
                .transact(operation, class, request, sequence, config)
        }
        fn probe(&self, _: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test]
    async fn fenced_non_execution_unavailable_issuing_readback_stays_unresolved() {
        let root = DurableTestRoot::new();
        let transport = UnavailableAfterCutTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xD7);
        let group = roster_group(0xD8);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(1));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_issuing_at_member(authority, 0, false)
            .await
            .unwrap();
        transport.unavailable.store(true, Ordering::SeqCst);
        let before = transport.inner.operations();
        let closure = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(!closed_without_effect(&closure));
        assert_eq!(closure.unwrap().as_str(), "indeterminate");
        assert_eq!(
            transport.inner.operations(),
            before,
            "unavailable readback grants no mutation authority"
        );
        assert!(store.has_unresolved_writer_authority().unwrap());
    }
    #[tokio::test]
    async fn fenced_non_execution_survives_terminal_pruning_and_unrelated_preparation() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE1);
        let group = roster_group(0xE2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        // Simulate a lost closure reply: wait for publication, discard its body.
        let _lost = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        let repeated = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(repeated
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        let unrelated = backend
            .prepare_durable_object_roster(&store, roster_group(0xE3), generation, policy_roster(2))
            .await
            .unwrap();
        // Preparing the independent binding exercises normal terminal pruning.
        let replay = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await;
        let excluded = replay.is_err();
        drop(replay);
        drop(unrelated);
        assert!(
            excluded,
            "a closed binding became executable again after its terminal record was pruned"
        );
        let after_prune = close_generation(&backend, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(after_prune
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_closed_binding_survives_real_store_reopen_and_empty_reset() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE4);
        let binding = backend.network_namespace_binding().durable_bytes().unwrap();
        let group = roster_group(0xE5);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        assert!(closed_without_effect(
            &close_generation(&backend, &store, group, generation, &roster).await
        ));
        // No effect was ever submitted: the namespace-empty precondition is
        // proved by this transport's complete log, not guessed from a missing file.
        assert!(transport.operations().is_empty());
        store.reset_after_namespace_empty().unwrap();
        drop(store);
        drop(backend);
        // Waiting for the lease release also joins the old actor's ownership.
        wait_until(|| {
            XfrmObjectRosterRecoveryStore::open_bound(
                root.path(),
                XfrmObjectRosterRecoveryProofKey::new([0xE4; 32]).unwrap(),
                binding,
            )
            .is_ok()
        })
        .await;
        let (reopened, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE4);
        let replay = reopened
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await;
        let excluded = replay.is_err();
        drop(replay);
        assert!(
            excluded,
            "store reopen after empty reset forgot execution closure for the exact binding"
        );
        let recovered = close_generation(&reopened, &store, group, generation, &roster)
            .await
            .unwrap();
        assert!(recovered
            .members()
            .iter()
            .all(|member| member.member_phase() == XfrmObjectRosterMemberPhase::Pending));
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_never_calls_pruned_applied_history_never_started() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xE6);
        let group = roster_group(0xE7);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        drop(
            backend
                .prepare_durable_object_roster(
                    &store,
                    roster_group(0xE8),
                    generation,
                    policy_roster(2),
                )
                .await
                .unwrap(),
        );
        let observed = close_generation(&backend, &store, group, generation, &roster).await;
        assert!(
            !closed_without_effect(&observed),
            "pruned Applied history cannot become non-execution evidence"
        );
        assert!(
            observed.is_ok(),
            "immutable applied disposition must survive normal pruning; observed={observed:?}"
        );
        assert_eq!(observed.unwrap().as_str(), "committed");
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            2
        );
        assert!(!transport.operations().contains(&"remove_sa"));
    }
    #[tokio::test]
    async fn fenced_non_execution_release_reuses_slots_beyond_thirty_without_reviving_prepares() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xF3);
        let generation = roster_generation(37);
        let mut late_prepares = 0;
        let mut release_publications = 0;
        // More than two complete turns of the existing thirty live slots.
        for identity in 1..=64 {
            let group = roster_group(identity);
            let roster = settlement_roster(&store, group, generation, sa_roster(1));
            drop(
                backend
                    .prepare_durable_object_roster(&store, group, generation, roster.clone())
                    .await
                    .expect("settled admissions must free their live slots"),
            );
            assert!(closed_without_effect(
                &close_generation(&backend, &store, group, generation, &roster).await
            ));
            let before = store.publication_ledger().unwrap().len();
            release_settled(&backend, &store, group, generation, &roster)
                .await
                .unwrap();
            let after = store.publication_ledger().unwrap().len();
            release_publications += after - before;
            // Lost release acknowledgements are retried with the same binding.
            release_settled(&backend, &store, group, generation, &roster)
                .await
                .unwrap();
            assert_eq!(store.publication_ledger().unwrap().len(), after);
            let late = backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await;
            late_prepares += usize::from(late.is_ok());
            drop(late);
            // Retire any late preparation before the next iteration.
            let _ = backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await;
        }
        assert_eq!(
            late_prepares, 0,
            "released settlement reopened a delayed prepare"
        );
        assert_eq!(
            release_publications, 64,
            "one provider-local durable release publication per settled roster"
        );
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_absent_descriptor_cannot_substitute_a_new_store_incarnation() {
        let original_root = DurableTestRoot::new();
        let other_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (original, original_store) =
            bind_with_roster_recovery(transport.clone(), &original_root, 0xF4);
        let (other, other_store) = bind_with_roster_recovery(transport.clone(), &other_root, 0xF4);
        let group = roster_group(0xF5);
        let generation = roster_generation(37);
        // This exact retained request is bound before SDK admission, without
        // making an XFRM intent record. Reusing the proof key is insufficient.
        let roster = settlement_roster(&original_store, group, generation, sa_roster(1));
        let closed = close_generation(&original, &original_store, group, generation, &roster).await;
        assert!(
            closed_without_effect(&closed),
            "the admitted store must settle its own unstarted binding"
        );
        assert!(
            matches!(
                close_generation(&other, &other_store, group, generation, &roster).await,
                Err(XfrmObjectRosterDurableError::WrongBinding)
            ),
            "an empty replacement store cannot prove the old admission never started"
        );
        assert!(transport.operations().is_empty());
    }

    #[tokio::test]
    async fn fenced_non_execution_rejects_substituted_roster_and_store_before_any_io() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xF1);
        let group = roster_group(0xF2);
        let generation = roster_generation(37);
        let roster = settlement_roster(&store, group, generation, sa_roster(2));
        drop(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap(),
        );
        assert_eq!(
            close_generation(
                &backend,
                &store,
                group,
                generation,
                &policy_roster(2).with_settlement_identity(store.settlement_identity())
            )
            .await
            .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        let other_root = DurableTestRoot::new();
        let (other_actor, other_store) =
            bind_with_roster_recovery(transport.clone(), &other_root, 0xF3);
        assert_eq!(
            close_generation(&backend, &other_store, group, generation, &roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        assert!(transport.operations().is_empty());
        assert!(closed_without_effect(
            &close_generation(&backend, &store, group, generation, &roster).await
        ));
        // A refused substituted request cannot poison an independent binding.
        let independent = other_actor
            .prepare_durable_object_roster(
                &other_store,
                group,
                generation,
                settlement_roster(&other_store, group, generation, roster.clone()),
            )
            .await
            .unwrap();
        assert_eq!(
            other_actor
                .run_durable_object_roster(independent)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            2
        );
    }
}
