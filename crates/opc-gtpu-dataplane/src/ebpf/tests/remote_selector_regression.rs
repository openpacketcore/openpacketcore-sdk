//! Composed SDK regression: public protected selector operations, local payload
//! AEAD, real mTLS consumer sockets, and three distinct file-backed fixed voters.
//! Raft transport is in-process and snapshots are PortableVerified. FakeRuntime
//! exercises the production eBPF adapter algorithm, not Linux forwarding/readiness.

use std::future::Future;
use std::sync::Condvar;
use std::time::Duration;

use bytes::Bytes;

use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation, OwnerId,
    ProtectedSessionBackend, SelectorLedgerStorageScope, SessionBackend,
    SessionConsumerTenantNfScope, SessionKey, SessionKeyType, SessionLeaseManager, SessionStore,
    StateClass, StateType, StoredSessionRecord,
};
use opc_session_testkit::authenticated_consumer_fixture::AuthenticatedPreparedFencedTransitionFixture as RemoteFixture;
use opc_types::{NetworkFunctionKind, TenantId};
use tokio::time::{timeout, timeout_at, Instant};

use crate::selector_namespace::GtpuSessionSelectorNamespaceAuthority;

use super::*;

const REQUEST_BUDGET: Duration = Duration::from_secs(1);
// This is an owned cleanup/functional containment bound, never a request budget.
const CLEANUP_BOUND: Duration = Duration::from_secs(20);

type Authority<B> = GtpuSessionSelectorNamespaceAuthority<B>;

fn checked<T, E>(result: Result<T, E>, category: &'static str) -> T {
    // Never print an underlying TLS/store/key/runtime error or opaque value.
    result.ok().expect(category)
}

/// A single test-owned gate inside the existing SDK fake runtime. Its four
/// second fail-closed bound is below the selector backend's five second section
/// budget, and dropping the test-side owner always releases a pending worker.
#[derive(Default)]
pub(super) struct ReadbackGate {
    entered: tokio::sync::Notify,
    released: Mutex<Option<bool>>,
    wake: Condvar,
}

impl ReadbackGate {
    pub(super) fn wait(&self) -> Result<(), GtpuError> {
        self.entered.notify_one();
        let released = self.released.lock().expect("readback release lock");
        let (released, _) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(4), |value| value.is_none())
            .expect("bounded readback wait");
        if *released == Some(true) {
            Ok(())
        } else {
            Err(state_indeterminate("fixture_exact_readback_unavailable"))
        }
    }

    fn release(&self, exact: bool) {
        *self.released.lock().expect("readback release lock") = Some(exact);
        self.wake.notify_all();
    }
}

struct OwnedReadbackGate(Arc<ReadbackGate>);

impl Drop for OwnedReadbackGate {
    fn drop(&mut self) {
        self.0.release(false);
    }
}

struct Lab<B: ProtectedSessionBackend> {
    fixture: RemoteFixture,
    store: SessionStore<B>,
    authority: Authority<B>,
    backend: Arc<EbpfGtpuDataplaneBackend>,
    runtime: Arc<FakeRuntime>,
    group: GtpuSessionGroup,
    scope: SelectorLedgerStorageScope,
    descriptor: SessionKey,
}

async fn start_lab(seed: u8) -> Lab<impl ProtectedSessionBackend + Clone + 'static> {
    let tenant = TenantId::from_static("sdk-selector-regression");
    let nf = NetworkFunctionKind::smf();
    let scope = SelectorLedgerStorageScope::new(tenant.clone(), nf.clone());
    let fixture = checked(
        RemoteFixture::start_fixed_durable([SessionConsumerTenantNfScope::new(
            tenant.clone(),
            nf.clone(),
        )])
        .await,
        "fixed remote fixture startup",
    );
    let provider = Arc::new(MemoryKeyProvider::new());
    checked(
        provider.insert_active_key(
            checked(KeyId::new("sdk-selector-regression"), "fixture key ID"),
            KeyPurpose::Session,
            tenant.clone(),
            Zeroizing::new([0x6a; 32]),
        ),
        "fixture payload AEAD key",
    );
    let general = checked(
        fixture
            .open_protected_local_aead(provider, "sdk-selector-regression")
            .await,
        "sealed mTLS consumer pair",
    );
    // The pair constructor performs its production-required exact-voter
    // readiness activation. There is no extra selector or descriptor warm-up.
    let store = SessionStore::new(general);
    let (backend, runtime) = backend_with_fake();
    let backend = Arc::new(backend);
    let device = grouped_device_id(seed);
    let endpoints = checked(
        GtpuLocalEndpointSet::new(IpAddr::V6(ipv6_local()), None),
        "fixture local endpoints",
    );
    checked(
        backend
            .create_device_with_endpoints(grouped_device_request("s2bu", device, endpoints))
            .await,
        "SDK grouped attachment",
    );
    let owner = checked(OwnerId::new("sdk-selector-owner"), "fixture owner");
    let bootstrap = checked(
        backend.selector_namespace_bootstrap(device).await,
        "SDK protected provisioning bootstrap",
    );
    let provisioned = checked(
        Authority::provision_protected(
            store.clone(),
            scope.clone(),
            bootstrap,
            backend.clone(),
            owner.clone(),
            Duration::from_secs(30),
            32,
        )
        .await,
        "public protected namespace provisioning",
    );
    drop(provisioned);
    let bootstrap = checked(
        backend.selector_namespace_bootstrap(device).await,
        "SDK protected opening bootstrap",
    );
    let authority = checked(
        Authority::open_protected(
            store.clone(),
            scope.clone(),
            bootstrap,
            backend.clone(),
            owner,
            Duration::from_secs(30),
            32,
        )
        .await,
        "public protected namespace open",
    );
    let group = grouped_group(
        seed,
        device,
        vec![grouped_v6_entry(4101, 5101, ipv6_peer())],
    );
    let descriptor = SessionKey {
        tenant,
        nf_kind: nf,
        key_type: SessionKeyType::PduSession,
        stable_id: checked(
            Bytes::from_static(b"singleton-descriptor").try_into(),
            "descriptor ID",
        ),
    };
    Lab {
        fixture,
        store,
        authority,
        backend,
        runtime,
        group,
        scope,
        descriptor,
    }
}

impl<B: ProtectedSessionBackend + 'static> Lab<B> {
    async fn successor(&self) -> Authority<B> {
        let bootstrap = checked(
            self.backend
                .selector_namespace_bootstrap(self.group.device_id())
                .await,
            "successor SDK bootstrap",
        );
        checked(
            Authority::open_protected(
                self.store.clone(),
                self.scope.clone(),
                bootstrap,
                self.backend.clone(),
                checked(OwnerId::new("sdk-selector-successor"), "successor owner"),
                Duration::from_secs(30),
                32,
            )
            .await,
            "successor public protected open",
        )
    }

    fn hold_active_readback(&self) -> OwnedReadbackGate {
        let gate = Arc::new(ReadbackGate::default());
        *self
            .runtime
            .selector_readback_gate
            .lock()
            .expect("readback gate lock") = Some(gate.clone());
        OwnedReadbackGate(gate)
    }

    fn active_mutations(&self) -> usize {
        self.runtime
            .state()
            .operations
            .iter()
            .filter(|operation| **operation == "session_group_put_active")
            .count()
    }

    async fn drain(&self) {
        // Same-scope detached operations are FIFO-serialized. This public opener
        // is a terminal barrier behind any observer that the request dropped.
        checked(
            timeout(CLEANUP_BOUND, self.successor()).await,
            "owned selector cleanup",
        );
    }

    async fn shutdown(self) {
        checked(
            timeout(CLEANUP_BOUND, self.fixture.shutdown()).await,
            "fixture shutdown bound",
        )
        .ok()
        .expect("fixture shutdown");
    }
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    DescriptorReadBefore,
    ReconcileFresh,
    RecoverActive,
    DescriptorCommit,
    DescriptorReadAfter,
}

#[derive(Clone, Copy, Debug)]
enum Classification {
    Complete,
    Deadline,
    Rejected,
}

struct RequestTiming {
    start: Instant,
    deadline: Instant,
    steps: Vec<(Stage, Duration, Classification)>,
}

impl RequestTiming {
    fn new() -> Self {
        let start = Instant::now();
        Self {
            start,
            deadline: start + REQUEST_BUDGET,
            steps: Vec::new(),
        }
    }

    async fn step<T, E, F: Future<Output = Result<T, E>>>(
        &mut self,
        stage: Stage,
        work: impl FnOnce() -> F,
    ) -> Result<T, Classification> {
        let start = Instant::now();
        let result = if start >= self.deadline {
            Err(Classification::Deadline)
        } else {
            match timeout_at(self.deadline, work()).await {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(_)) => Err(Classification::Rejected),
                Err(_) => Err(Classification::Deadline),
            }
        };
        self.steps.push((
            stage,
            start.elapsed(),
            result
                .as_ref()
                .map_or_else(|error| *error, |_| Classification::Complete),
        ));
        result
    }

    fn report(&self, classification: Classification) {
        let total = self.start.elapsed();
        for (stage, elapsed, result) in &self.steps {
            eprintln!(
                "sdk_selector_singleton stage={stage:?} elapsed_us={} result={result:?}",
                elapsed.as_micros()
            );
        }
        eprintln!("sdk_selector_singleton stage=Total elapsed_us={} budget_us={} result={classification:?} setup=Excluded qualification=LocalObservation",
            total.as_micros(), REQUEST_BUDGET.as_micros());
    }
}

async fn descriptor_commit<B: ProtectedSessionBackend>(
    store: SessionStore<B>,
    descriptor: SessionKey,
) -> Result<StoredSessionRecord, ()> {
    let lease = store
        .acquire(
            &descriptor,
            checked(OwnerId::new("sdk-descriptor-owner"), "descriptor owner"),
            Duration::from_secs(30),
        )
        .await
        .map_err(|_| ())?;
    let record = StoredSessionRecord {
        key: descriptor.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-selector-descriptor"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([0x31, 0x02]),
    };
    let result = store
        .compare_and_set(CompareAndSet {
            key: descriptor.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await;
    let release = store.release(lease).await;
    match (result, release) {
        (Ok(CompareAndSetResult::Success), Ok(())) => Ok(record),
        _ => Err(()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn singleton_public_protected_flow_keeps_original_request_deadline() {
    let lab = start_lab(0x91).await;
    // Startup, required voter activation, stopped namespace provisioning, and
    // protected open precede this request. All ordinary request storage calls
    // share this one original deadline. 830ms is NOT an SDK API constant.
    let mut timing = RequestTiming::new();
    let mut pending_descriptor_commit = None;
    let outcome = async {
        let before = timing
            .step(Stage::DescriptorReadBefore, || {
                lab.store.get(&lab.descriptor)
            })
            .await?;
        assert!(before.is_none(), "descriptor must not be pre-warmed");
        // Own the ordinary lease/CAS/release sequence beyond observer timeout.
        // A late result is drained below and never restarts the request budget.
        let mut commit = None;
        let committed = timing
            .step(Stage::DescriptorCommit, || async {
                let task = commit.insert(tokio::spawn(descriptor_commit(
                    lab.store.clone(),
                    lab.descriptor.clone(),
                )));
                task.await.map_err(|_| ())?
            })
            .await;
        if matches!(committed, Err(Classification::Deadline)) {
            pending_descriptor_commit = commit;
        }
        let expected = committed?;
        drop(
            timing
                .step(Stage::ReconcileFresh, || {
                    lab.authority
                        .reconcile_fresh(lab.backend.clone(), lab.group.clone())
                })
                .await?,
        );
        let actual = timing
            .step(Stage::DescriptorReadAfter, || {
                lab.store.get(&lab.descriptor)
            })
            .await?;
        assert!(
            actual.as_ref() == Some(&expected),
            "exact decrypted descriptor readback"
        );
        drop(
            timing
                .step(Stage::RecoverActive, || {
                    lab.authority
                        .recover_active(lab.backend.clone(), lab.group.clone())
                })
                .await?,
        );
        Ok::<_, Classification>(())
    }
    .await;
    timing.report(
        outcome
            .as_ref()
            .map_or_else(|error| *error, |_| Classification::Complete),
    );
    // A late worker is drained for ownership hygiene, never reclassified green.
    if let Some(commit) = pending_descriptor_commit {
        let _late_result = checked(
            timeout(CLEANUP_BOUND, commit).await,
            "owned descriptor cleanup",
        );
    }
    lab.drain().await;
    let mutations = lab.active_mutations();
    lab.shutdown().await;
    assert!(
        outcome.is_ok(),
        "singleton original request budget or storage failure; retain fixed timing categories"
    );
    assert_eq!(mutations, 1, "one active dataplane publication");
}

async fn cancelled_readback(seed: u8, exact: bool) {
    let lab = start_lab(seed).await;
    let successor = lab.successor().await;
    let gate = lab.hold_active_readback();
    let mut first = lab
        .authority
        .reconcile_fresh(lab.backend.clone(), lab.group.clone());
    // Timing qualification belongs to the separate normal case. This case uses
    // a deterministic post-mutation fault boundary, then cancels its observer.
    checked(
        timeout(CLEANUP_BOUND, gate.0.entered.notified()).await,
        "active readback entry",
    );
    assert_eq!(lab.active_mutations(), 1);
    assert!(lab
        .runtime
        .selector_namespace_effect_held
        .load(Ordering::Acquire));
    assert!(
        timeout(Duration::from_millis(25), &mut first)
            .await
            .is_err(),
        "no active claim before exact readback"
    );
    drop(first);
    let mut second = successor.reconcile_fresh(lab.backend.clone(), lab.group.clone());
    let mut recovery = successor.recover_active(lab.backend.clone(), lab.group.clone());
    assert!(
        timeout(Duration::from_millis(25), &mut second)
            .await
            .is_err(),
        "successor must remain queued behind the owned backend worker"
    );
    assert!(
        timeout(Duration::from_millis(25), &mut recovery)
            .await
            .is_err(),
        "active recovery cannot outrun pending readback"
    );
    assert_eq!(lab.active_mutations(), 1);
    assert!(
        lab.runtime
            .selector_namespace_effect_held
            .load(Ordering::Acquire),
        "observer cancellation must retain the effect fence"
    );
    gate.0.release(exact);
    let second = checked(timeout(CLEANUP_BOUND, second).await, "successor cleanup");
    let recovered = checked(timeout(CLEANUP_BOUND, recovery).await, "recovery cleanup");
    assert!(
        second.is_err(),
        "successor must not receive a second fresh mutation authority"
    );
    assert_eq!(
        recovered.is_ok(),
        exact,
        "only exact readback may settle Active"
    );
    drop(recovered);
    lab.drain().await;
    assert_eq!(
        lab.active_mutations(),
        1,
        "no mutation replay after canceled observation"
    );
    assert!(!lab
        .runtime
        .selector_namespace_effect_held
        .load(Ordering::Acquire));
    drop(gate);
    lab.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_observer_retains_fence_until_exact_readback() {
    cancelled_readback(0x92, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_readback_after_observer_timeout_cannot_publish_active() {
    cancelled_readback(0x93, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_backend_mutation_acknowledgement_settles_only_by_exact_readback() {
    for (seed, exact) in [(0x94, true), (0x95, false)] {
        let lab = start_lab(seed).await;
        let successor = lab.successor().await;
        let gate = lab.hold_active_readback();
        // Existing SDK fault seam: apply the Active map write, then lose its
        // ACK. put_grouped_authority_exact intentionally settles that unknown
        // syscall outcome with exact readback, without issuing another write.
        lab.runtime
            .fail_after_in_order(["session_group_put_active"]);
        let mut first = lab
            .authority
            .reconcile_fresh(lab.backend.clone(), lab.group.clone());
        checked(
            timeout(CLEANUP_BOUND, gate.0.entered.notified()).await,
            "lost ACK readback entry",
        );
        assert_eq!(lab.active_mutations(), 1);
        assert!(
            lab.runtime.state().failures_after.is_empty(),
            "post-write ACK fault consumed"
        );
        assert!(
            timeout(Duration::from_millis(25), &mut first)
                .await
                .is_err(),
            "unsettled mutation ACK must not yield an active claim"
        );
        gate.0.release(exact);
        let first = checked(timeout(CLEANUP_BOUND, first).await, "lost ACK cleanup");
        assert_eq!(
            first.is_ok(),
            exact,
            "only exact readback can settle a lost ACK"
        );
        drop(first);
        assert!(
            successor
                .reconcile_fresh(lab.backend.clone(), lab.group.clone())
                .await
                .is_err(),
            "lost ACK cannot reissue fresh mutation authority"
        );
        let recovered = successor
            .recover_active(lab.backend.clone(), lab.group.clone())
            .await;
        assert_eq!(
            recovered.is_ok(),
            exact,
            "unconfirmed effect cannot be guessed Active"
        );
        drop(recovered);
        assert_eq!(
            lab.active_mutations(),
            1,
            "lost ACK grants no replay authority"
        );
        lab.drain().await;
        drop(gate);
        lab.shutdown().await;
    }
}

fn ordinary_cas_require(condition: bool, category: &'static str) -> Result<(), &'static str> {
    condition.then_some(()).ok_or(category)
}

async fn ordinary_remote_cas_lost_success(seed: u8, exact: bool) {
    let lab = start_lab(seed).await;
    let successor = lab.successor().await;
    let map_gate = lab.hold_active_readback();
    let mut first = Some(
        lab.authority
            .reconcile_fresh(lab.backend.clone(), lab.group.clone()),
    );
    let mut fresh = None;
    let mut recovery = None;
    let mut fault = None;
    let result = async {
        timeout(CLEANUP_BOUND, map_gate.0.entered.notified())
            .await
            .map_err(|_| "ordinary CAS map phase entry")?;
        ordinary_cas_require(lab.active_mutations() == 1, "one pre-CAS map install")?;
        // The existing precise SDK map gate has reached the final Active
        // write. Its exact readback succeeds normally; no map ACK is lost.
        // Provisioning and all earlier Installing ledger CASes are complete.
        fault = Some(
            lab.fixture
                .hold_next_ordinary_cas_response(
                    SessionConsumerTenantNfScope::new(
                        lab.scope.tenant().clone(),
                        lab.scope.nf_kind().clone(),
                    ),
                    StateType::from_static("gtpu-selector-namespace-v1"),
                )
                .map_err(|_| "ordinary CAS fault arming")?,
        );
        map_gate.0.release(true);
        let fault = fault.as_ref().ok_or("ordinary CAS fault owner")?;
        // The real ordinary consumer's unchanged 10-second operation timeout
        // loses a genuinely committed success. This is functional containment,
        // not a restarted request budget or a claim of socket EOF.
        let pending = timeout(CLEANUP_BOUND, fault.wait_for_pending_readback())
            .await
            .map_err(|_| "ordinary CAS lost response containment")?
            .map_err(|_| "ordinary CAS exact request evidence")?;
        ordinary_cas_require(
            pending.request_correlated
                && pending.durable_success
                && pending.client_outcome_unknown
                && pending.suppressed_response_finished
                && pending.target_cas_dispatches == 1
                && pending.namespace_cas_dispatches == 1
                && pending.pending_readback_responses == 1
                && pending.delivered_exact_readbacks == 0
                && !pending.failed,
            "committed exact request lost success before durable read delivery",
        )?;
        ordinary_cas_require(
            timeout(
                Duration::from_millis(25),
                first.as_mut().ok_or("ordinary CAS initial observer")?,
            )
            .await
            .is_err(),
            "no Active before exact durable readback",
        )?;
        drop(first.take());
        fresh = Some(successor.reconcile_fresh(lab.backend.clone(), lab.group.clone()));
        recovery = Some(successor.recover_active(lab.backend.clone(), lab.group.clone()));
        ordinary_cas_require(
            timeout(
                Duration::from_millis(25),
                fresh.as_mut().ok_or("ordinary CAS fresh observer")?,
            )
            .await
            .is_err(),
            "fresh successor stays behind the owned namespace worker",
        )?;
        ordinary_cas_require(
            timeout(
                Duration::from_millis(25),
                recovery.as_mut().ok_or("ordinary CAS recovery observer")?,
            )
            .await
            .is_err(),
            "Active recovery stays behind pending durable readback",
        )?;
        let held = fault.evidence();
        ordinary_cas_require(
            held.namespace_mutation_dispatches == pending.namespace_mutation_dispatches
                && held.target_cas_dispatches == 1
                && held.namespace_cas_dispatches == 1
                && held.pending_readback_responses == 1
                && held.delivered_exact_readbacks == 0
                && lab.active_mutations() == 1
                && !held.failed,
            "observer drop retains namespace serialization without another mutation",
        )?;
        // The backend effect section has already finished. Its semaphore is
        // not the owner here; the detached selector worker holds the scope.
        fault.release_readback(exact);
        let fresh_result = timeout(
            CLEANUP_BOUND,
            fresh
                .as_mut()
                .ok_or("ordinary CAS fresh cleanup observer")?,
        )
        .await
        .map_err(|_| "ordinary CAS fresh cleanup")?;
        drop(fresh.take());
        let recovered = timeout(
            CLEANUP_BOUND,
            recovery
                .as_mut()
                .ok_or("ordinary CAS recovery cleanup observer")?,
        )
        .await
        .map_err(|_| "ordinary CAS recovery cleanup")?;
        drop(recovery.take());
        ordinary_cas_require(fresh_result.is_err(), "no second fresh selector authority")?;
        ordinary_cas_require(
            recovered.is_ok() == exact,
            "public recovery requires its own exact durable and backend readback",
        )?;
        drop(recovered);
        // Supplementary fleet evidence uses the very same authenticated
        // clients. It cannot replace the public recovery checked above, and
        // the unavailable latch stays installed through poison/successors.
        let settled = timeout(
            CLEANUP_BOUND,
            fault.verify_released_readback_on_all_voters(exact),
        )
        .await
        .map_err(|_| "ordinary CAS all-voter readback containment")?
        .map_err(|_| "ordinary CAS all-voter readback evidence")?;
        ordinary_cas_require(
            settled.target_cas_dispatches == 1
                && settled.namespace_cas_dispatches == 1
                && settled.exact_readbacks.iter().all(|count| *count != 0)
                && settled.pending_readback_responses == 0
                && (settled.delivered_exact_readbacks != 0) == exact
                && (exact
                    || settled
                        .unavailable_readbacks
                        .iter()
                        .all(|count| *count != 0))
                && lab.active_mutations() == 1
                && !settled.failed,
            "one original CAS and map install with exact per-voter readback evidence",
        )?;
        Ok::<_, &'static str>(())
    }
    .await;

    // Every assertion above is fallible evidence collection. Even on failure,
    // release owned gates, let all detached workers reach a terminal result,
    // and await the real listener/store shutdown before asserting the verdict.
    if result.is_err() {
        if let Some(fault) = &fault {
            fault.release_readback(false);
        }
        map_gate.0.release(false);
    }
    drop((first, fresh, recovery));
    let drained = timeout(
        CLEANUP_BOUND,
        successor.recover_active(lab.backend.clone(), lab.group.clone()),
    )
    .await;
    let cleanup_recovered_active = matches!(&drained, Ok(Ok(_)));
    let evidence = fault.as_ref().map(|fault| fault.evidence());
    let mutations = lab.active_mutations();
    // Unavailable reads remain unavailable through the FIFO drain; an
    // error-completed worker need not retain the gate indefinitely.
    drop(fault);
    drop(map_gate);
    let shutdown = timeout(CLEANUP_BOUND, lab.fixture.shutdown()).await;
    eprintln!(
        "sdk_selector_ordinary_cas fault=CommittedSuccessWithheldUntilExistingTransportTimeout exact={exact} result={result:?} evidence={evidence:?} cleanup_drained={} cleanup_recovered_active={cleanup_recovered_active} shutdown_complete={} qualification=FunctionalOnly",
        drained.is_ok(),
        matches!(shutdown, Ok(Ok(()))),
    );
    assert!(
        result.is_ok(),
        "ordinary remote CAS response-loss regression"
    );
    assert!(drained.is_ok(), "ordinary CAS owned worker cleanup");
    assert_eq!(
        cleanup_recovered_active, exact,
        "cleanup recovery cannot bypass unavailable durable reads",
    );
    assert!(
        matches!(shutdown, Ok(Ok(()))),
        "ordinary CAS fixture shutdown"
    );
    assert_eq!(mutations, 1, "no repeated Active install during cleanup");
    assert!(
        evidence.is_some_and(|evidence| !evidence.failed
            && evidence.suppressed_response_finished
            && evidence.pending_readback_responses == 0
            && evidence.target_cas_dispatches == 1
            && evidence.namespace_cas_dispatches == 1),
        "ordinary CAS response/readback gates reached owned terminal cleanup",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_remote_cas_lost_success_retains_owner_until_exact_readback() {
    ordinary_remote_cas_lost_success(0x96, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordinary_remote_cas_lost_success_unavailable_readback_denies_active() {
    ordinary_remote_cas_lost_success(0x97, false).await;
}
