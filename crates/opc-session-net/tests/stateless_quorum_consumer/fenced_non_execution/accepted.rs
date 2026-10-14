use super::*;
use opc_ipsec_xfrm::XfrmError;
use std::sync::Condvar;

#[derive(Default)]
struct AcceptedPolicy {
    entered: tokio::sync::Notify,
    released: Mutex<bool>,
    wake: Condvar,
    visible: Mutex<Option<Vec<u8>>>,
    installs: AtomicUsize,
    removals: AtomicUsize,
}

impl AcceptedPolicy {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, XfrmError> {
        match operation {
            "query_policy" => self
                .visible
                .lock()
                .unwrap()
                .clone()
                .map(Some)
                .ok_or(XfrmError::NotFound),
            "install_policy" => {
                // The actual actor has published Prepared -> Issuing before
                // it submits this install. The physical effect is still held.
                let mut released = self.released.lock().unwrap();
                self.entered.notify_one();
                while !*released {
                    released = self.wake.wait(released).unwrap();
                }
                *self.visible.lock().unwrap() = Some(request[16..].to_vec());
                self.installs.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            "remove_policy" => {
                assert!(self.visible.lock().unwrap().take().is_some());
                self.removals.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            _ => panic!("unexpected instrumented policy operation"),
        }
    }
}

struct ReleaseAccepted(Arc<AcceptedPolicy>);

impl Drop for ReleaseAccepted {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_non_execution_two_members_join_accepted_work_then_guarded_abort() {
    let kernel = Arc::new(AcceptedPolicy::default());
    let _release = ReleaseAccepted(Arc::clone(&kernel));
    let backend = LinuxXfrmBackend::with_instrumented_transport({
        let kernel = Arc::clone(&kernel);
        move |operation, request| kernel.transact(operation, request)
    });
    let mut fixture = SettlementFixture::start_with_backend(false, 2, backend, Some(1)).await;
    let mut active = match fixture.client.admit(&mut fixture.input).await.unwrap() {
        AdmissionOutcome::Admitted(active) => active,
        _ => panic!("deliver the original admission reply"),
    };
    let mut ready = active.member(MemberOrdinal::new(1).unwrap()).unwrap();
    assert!(matches!(
        fixture.client.prepare_member(&mut ready).await.unwrap(),
        MemberPrepareOutcome::Prepared
    ));
    let mut recovered = fixture.readback().await;
    assert_eq!(recovered.members().len(), 2);
    let executing = tokio::spawn({
        let client = fixture.client.clone();
        async move { client.execute(&mut ready).await }
    });
    tokio::time::timeout(Duration::from_secs(2), kernel.entered.notified())
        .await
        .unwrap();
    assert_eq!(kernel.installs.load(Ordering::SeqCst), 0);
    let mut never_started = recovered.member(MemberOrdinal::new(0).unwrap()).unwrap();
    let negative = match tokio::time::timeout(
        Duration::from_secs(2),
        fixture.client.reconcile(&mut never_started),
    )
    .await
    {
        Ok(Ok(MemberRecoveryOutcome::Conclusive(proof))) => Some(*proof),
        _ => None,
    };
    let closed_member_zero = negative.is_some();
    let mut accepted = recovered.member(MemberOrdinal::new(1).unwrap()).unwrap();
    if closed_member_zero {
        assert!(
            matches!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    fixture.client.reconcile(&mut accepted)
                )
                .await
                .unwrap()
                .unwrap(),
                MemberRecoveryOutcome::Ambiguous(_)
            ),
            "accepted work cannot become a non-execution proof"
        );
        assert!(fixture
            .client
            .compensate_member(&mut accepted)
            .await
            .is_err());
        assert_eq!(fixture.provider.compensations.load(Ordering::SeqCst), 0);
        assert_eq!(kernel.installs.load(Ordering::SeqCst), 0);
    }
    kernel.release();
    let reply = executing.await.unwrap();
    assert!(
        !matches!(reply, Ok(ExecuteOutcome::Conclusive(_))),
        "the execute acknowledgement was lost"
    );
    assert_eq!(kernel.installs.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.removals.load(Ordering::SeqCst), 0);
    if let Some(negative) = negative {
        let applied = fixture.client.status(&mut accepted).await.unwrap();
        assert!(
            matches!(applied, MemberRecoveryOutcome::Conclusive(_)),
            "joined Applied evidence is required before compensation"
        );
        assert_eq!(kernel.removals.load(Ordering::SeqCst), 0);
        let compensated = match fixture
            .client
            .compensate_member(&mut accepted)
            .await
            .unwrap()
        {
            MemberRecoveryOutcome::Conclusive(proof) => *proof,
            _ => panic!("the complete aborting proof view must permit exact compensation"),
        };
        assert_eq!(kernel.removals.load(Ordering::SeqCst), 1);
        assert!(kernel.visible.lock().unwrap().is_none());
        fixture
            .finish_aborted(&recovered, vec![negative, compensated])
            .await;
    }
    fixture.shutdown().await;
    assert!(
        closed_member_zero,
        "member 0 needs a non-execution proof while member 1 is accepted and paused before install"
    );
}
