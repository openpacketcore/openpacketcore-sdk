mod fenced_non_execution {
    use super::*;

    // Baseline composition seam. During implementation this one call is wired
    // to the proposed close-and-observe actor API. It must never synthesize
    // intent, treat NotFound as a proof, or weaken the assertions below.
    async fn close_generation(
        backend: &NamespaceBoundLinuxXfrmBackend,
        store: &XfrmObjectRosterRecoveryStore,
        group: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError> {
        backend
            .recover_durable_object_roster(store, group, generation, roster)
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
        result: &Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>,
    ) -> bool {
        matches!(
            result,
            Ok(XfrmObjectRosterRestartOutcome::NoMutation { .. })
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_non_execution_excludes_provider_dispatch_paused_before_actor_admission() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0xB1);
        let group = roster_group(0xB2);
        let generation = roster_generation(37);
        let roster = sa_roster(2);
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
        // Drain/retire the baseline's unsafe late run before the RED assertion.
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
        let roster = sa_roster(2);
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
        // The baseline's queued recover must finish before inspecting counters.
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
        let roster = sa_roster(2);
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
        let roster = sa_roster(1);
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
}
