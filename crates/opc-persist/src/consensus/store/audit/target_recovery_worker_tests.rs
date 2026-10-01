//! Blocking-read ownership tests on the real retained backend/ledger codec.
//! Joint opening, the target reducer and external checkpoint I/O stay outside
//! this fixture; no target operation is submitted through an unsupported mode.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::{AuditKeyRing, AuditSigningKey};
use crate::audit_authority::AuditPrivacyKey;
use crate::consensus::audit_mutation::joint_running::tests::prepared_for_store;
use crate::{
    AuditKey, ConfigConsensusTopology, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions, SqliteBackend,
};
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusNodeId, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_crypto::{ConfigCapacityProfile, ConfigPreparationPool};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, Weak};
use tokio::sync::{Notify, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::consensus::store) enum Point {
    BeforeDecode,
    AfterDecode,
}

struct Gate {
    point: Point,
    reads_to_skip: AtomicUsize,
    entered: Notify,
    drained: Notify,
    decoded: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn hold(&self, point: Point) {
        if self.point != point {
            return;
        }
        self.entered.notify_one();
        let mut released = self.released.lock().expect("gate mutex");
        while !*released {
            released = self.changed.wait(released).expect("gate wait");
        }
    }

    fn release(&self) {
        *self.released.lock().expect("gate mutex") = true;
        self.changed.notify_all();
    }
}

fn observers() -> &'static Mutex<BTreeMap<usize, Weak<Gate>>> {
    static OBSERVERS: OnceLock<Mutex<BTreeMap<usize, Weak<Gate>>>> = OnceLock::new();
    OBSERVERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

// The registration pins this backend's actual worker-gate allocation, so its
// address cannot be reused while the scoped registration exists. The observer
// stores no payload, reservation or callback that supplies a ledger result.
pub(in crate::consensus::store) struct Registration {
    key: usize,
    gate: Arc<Gate>,
    _worker_gate: Arc<Semaphore>,
}

impl Registration {
    fn new(backend: &SqliteBackend, point: Point) -> Self {
        Self::nth(backend, point, 1)
    }

    pub(in crate::consensus::store) fn nth(
        backend: &SqliteBackend,
        point: Point,
        ordinal: usize,
    ) -> Self {
        assert!(ordinal > 0);
        let worker_gate = backend.config_consensus_worker_gate();
        let key = Arc::as_ptr(&worker_gate) as usize;
        let gate = Arc::new(Gate {
            point,
            reads_to_skip: AtomicUsize::new(ordinal - 1),
            entered: Notify::new(),
            drained: Notify::new(),
            decoded: AtomicBool::new(false),
            released: Mutex::new(false),
            changed: Condvar::new(),
        });
        let mut registered = observers().lock().expect("observer registry");
        match registered.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(&gate));
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                panic!("one scoped observer per backend")
            }
        }
        Self {
            key,
            gate,
            _worker_gate: worker_gate,
        }
    }

    pub(in crate::consensus::store) async fn entered(&self) {
        tokio::time::timeout(
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            self.gate.entered.notified(),
        )
        .await
        .expect("real SQL worker reached retained decoding gate");
    }

    pub(in crate::consensus::store) async fn drained(&self) {
        tokio::time::timeout(
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            self.gate.drained.notified(),
        )
        .await
        .expect("worker/result allocations and reservation drained");
    }

    pub(in crate::consensus::store) fn release(&self) {
        self.gate.release();
    }

    pub(in crate::consensus::store) fn decoded(&self) -> bool {
        self.gate.decoded.load(Ordering::Acquire)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Unblock a real blocking worker on every assertion/unwind path.
        self.gate.release();
        let mut registered = observers().lock().expect("observer registry");
        if registered
            .get(&self.key)
            .and_then(Weak::upgrade)
            .is_some_and(|gate| Arc::ptr_eq(&gate, &self.gate))
        {
            registered.remove(&self.key);
        }
    }
}

pub(super) struct ReadObservation(Arc<Gate>);

pub(super) fn observe(backend: &SqliteBackend) -> Option<ReadObservation> {
    let worker_gate = backend.config_consensus_worker_gate();
    let key = Arc::as_ptr(&worker_gate) as usize;
    let mut registered = observers().lock().expect("observer registry");
    let gate = registered.get(&key)?.upgrade()?;
    if gate
        .reads_to_skip
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return None;
    }
    registered.remove(&key);
    Some(ReadObservation(gate))
}

impl ReadObservation {
    pub(super) fn before_decode(&self) {
        self.0.hold(Point::BeforeDecode);
    }

    pub(super) fn after_decode(&self) {
        self.0.decoded.store(true, Ordering::Release);
        self.0.hold(Point::AfterDecode);
    }
}

impl Drop for ReadObservation {
    fn drop(&mut self) {
        // The production result's field order, or the worker's reverse local
        // drop order on error, has already dropped its ledger and reservation.
        self.0.drained.notify_one();
    }
}

struct Fixture {
    backend: SqliteBackend,
    identity: ConsensusIdentity,
    key: AuditKey,
    caller: AuditCaller,
    handle: AuditOperationHandle,
    encoded: Vec<u8>,
    _directory: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let root = std::env::var_os("TMPDIR")
        .or_else(|| std::env::var_os("RUNNER_TEMP"))
        .expect("on-disk TMPDIR or RUNNER_TEMP");
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem observation");
    assert!(filesystem.status.success());
    let filesystem = String::from_utf8(filesystem.stdout).expect("filesystem type");
    assert!(!matches!(filesystem.trim(), "tmpfs" | "ramfs"));
    let directory = tempfile::tempdir_in(root).expect("private retained fixture");
    let identity = ConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x91; 32]),
        ConsensusConfigurationId::from_bytes([0x92; 32]),
        ConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let node = ConsensusNodeId::new(1).expect("node");
    let topology =
        ConfigConsensusTopology::try_new(identity, node, [node].into()).expect("topology");
    let binding = RetainedConfigBinding::new(topology, [0x93; 32], [0x94; 32])
        .expect("binding")
        .with_capacity_profile(ConfigCapacityProfile::BoundedV1);
    let options = RetainedConfigOptions::new(
        directory.path().join("retained-read.db"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .expect("unchanged retained admission bounds");
    let key = AuditKey::new([0x95; 32]).expect("synthetic authority key");
    let backend = SqliteBackend::provision_config_authority(options, key.clone())
        .await
        .expect("supported capacity8 retained backend");
    let keys = Arc::new(
        AuditKeyRing::new(vec![
            AuditSigningKey::new(1, [0x96; 32]).expect("signing key")
        ])
        .expect("independent keys"),
    );
    backend
        .attach_management_audit_keys(keys.clone())
        .expect("actual independent continuity verification");
    let caller = AuditCaller::project(
        &AuditPrivacyKey::new([0x75; 32]).expect("fixture privacy key"),
        "synthetic",
        "synthetic-principal",
    )
    .expect("independent caller");
    let source = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&source, identity, &key).await;
    let handle = prepared.handle().clone();
    let encoded = prepared.encode().expect("original protected encoding");
    let mut ledger = LedgerState::new(
        identity,
        handle.body.event.projection,
        AuditLedgerLimits::new(6, 2).expect("ledger limits"),
    );
    ledger.continuity = Some(ContinuityState::new(1));
    // Real authenticated transitions are component setup, not native target
    // admission or an assertion that an external checkpoint already covers it.
    ledger
        .admit_target(&key, prepared.command(), 110)
        .expect("TARGET_RETAINED_WORKER_FIXTURE_ADMISSION");
    ledger.seal_continuity(Some(&keys)).expect("sealed chain");
    ledger
        .validate(&key, identity)
        .expect("exact retained original");
    ledger
        .validate_continuity(Some(&keys))
        .expect("independent chain");
    assert!(ledger
        .continuity
        .as_ref()
        .expect("continuity")
        .checkpoint
        .is_none());
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("native Durable"));
        crate::consensus::audit::write_sync(&conn, &key, identity, Some(ledger), false)
            .expect("actual native ledger codec write");
    }
    drop(prepared);
    all_slots_available(&source);
    Fixture {
        backend,
        identity,
        key,
        caller,
        handle,
        encoded,
        _directory: directory,
    }
}

fn all_slots_available(pool: &ConfigPreparationPool) {
    let slots: Vec<_> = (0..8)
        .map(|_| {
            pool.try_reserve()
                .expect("all eight destination slots returned")
        })
        .collect();
    assert!(pool.try_reserve().is_err(), "original eight-slot bound");
    drop(slots);
}

pub(in crate::consensus::store) async fn worker_drained(backend: &SqliteBackend) {
    let gate = backend.config_consensus_worker_gate();
    let permit = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, gate.acquire_owned())
        .await
        .expect("real worker permit drained")
        .expect("worker gate open");
    let shared = backend.conn();
    let conn = tokio::time::timeout(DURABLE_CONSENSUS_OPERATION_TIMEOUT, shared.lock())
        .await
        .expect("real worker connection drained");
    drop(conn);
    drop(shared);
    drop(permit);
}

fn assert_original(read: &AuditLedgerRead, fixture: &Fixture) {
    let ledger = read.ledger.as_ref().expect("retained ledger");
    let prepared = ledger
        .recover_target(&fixture.key, &fixture.handle, fixture.caller)
        .expect("original authenticated target");
    assert_eq!(prepared.handle(), &fixture.handle);
    assert_eq!(
        serde_json::to_vec(&prepared).expect("same original bytes"),
        fixture.encoded
    );
    assert!(
        prepared.encode().is_err(),
        "decoded bytes grant no local encoding authority"
    );
    assert!(ledger
        .continuity
        .as_ref()
        .expect("continuity")
        .checkpoint
        .is_none());
}

#[tokio::test]
async fn retained_target_cancelled_read_keeps_worker_reservation() {
    let fixture = fixture().await;
    let mut ownership_observations = Vec::new();
    for point in [Point::BeforeDecode, Point::AfterDecode] {
        let destination = ConfigPreparationPool::bounded_v1();
        let occupied: Vec<_> = (0..7)
            .map(|_| destination.try_reserve().expect("seven slots"))
            .collect();
        let registration = Registration::new(&fixture.backend, point);
        let backend = fixture.backend.clone();
        let identity = fixture.identity;
        let reservation = destination.try_reserve().expect("eighth slot before read");
        let caller = tokio::spawn(async move {
            read_audit_ledger_worker(
                &backend,
                identity,
                DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                Some(reservation),
            )
            .await
        });
        registration.entered().await;
        assert!(
            destination.try_reserve().is_err(),
            "read owns eighth slot before cancellation"
        );
        if point == Point::AfterDecode {
            assert!(
                registration.gate.decoded.load(Ordering::Acquire),
                "real authenticated decode completed"
            );
        }
        caller.abort();
        let Err(cancelled) = caller.await else {
            panic!("caller must be cancelled while its real worker is gated")
        };
        assert!(cancelled.is_cancelled());
        let refused_while_worker_owned = destination.try_reserve().is_err();
        // Finish real work before the causal assertion, including on a mutant.
        registration.gate.release();
        registration.drained().await;
        worker_drained(&fixture.backend).await;
        let read = read_audit_ledger_worker(
            &fixture.backend,
            fixture.identity,
            DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            Some(
                destination
                    .try_reserve()
                    .expect("drained worker returned eighth slot"),
            ),
        )
        .await
        .expect("authenticated retry of the unchanged original");
        assert_original(&read, &fixture);
        drop(read);
        drop(occupied);
        all_slots_available(&destination);
        eprintln!(
            "TARGET_RETAINED_WORKER_DRAINED {point:?}: authenticated original; ninth_refused={refused_while_worker_owned}"
        );
        ownership_observations.push((point, refused_while_worker_owned));
    }
    assert!(
        ownership_observations.iter().all(|(_, refused)| *refused),
        "TARGET_RETAINED_WORKER_CANCEL_OWNER: {ownership_observations:?}"
    );
}

#[tokio::test]
async fn retained_target_read_result_transfers_exact_reservation_to_hydration() {
    let fixture = fixture().await;
    let destination = ConfigPreparationPool::bounded_v1();
    let occupied: Vec<_> = (0..7)
        .map(|_| destination.try_reserve().expect("seven slots"))
        .collect();
    let mut read = read_audit_ledger_worker(
        &fixture.backend,
        fixture.identity,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        Some(
            destination
                .try_reserve()
                .expect("original eighth reservation"),
        ),
    )
    .await
    .expect("real owned SQL read");
    assert_original(&read, &fixture);
    assert!(
        destination.try_reserve().is_err(),
        "TARGET_RETAINED_WORKER_RESULT_OWNER"
    );
    let prepared = read
        .ledger
        .as_ref()
        .expect("ledger")
        .recover_target(&fixture.key, &fixture.handle, fixture.caller)
        .expect("authenticate original before hydration");
    let recovered = crate::consensus::audit_mutation::joint_running::hydrate(
        prepared,
        read.reservation
            .take()
            .expect("same original owner returned by worker"),
        &destination,
        fixture.identity,
        &fixture.key,
        fixture.caller,
    )
    .expect("move exact destination owner into hydration");
    drop(read);
    assert_eq!(recovered.handle(), &fixture.handle);
    assert_eq!(
        recovered.encode().expect("protected recovered bytes"),
        fixture.encoded
    );
    assert!(
        destination.try_reserve().is_err(),
        "TARGET_RETAINED_WORKER_HYDRATED_OWNER"
    );
    let alias = recovered.clone();
    drop(recovered);
    assert!(
        destination.try_reserve().is_err(),
        "recovered alias retains original owner"
    );
    drop(alias);
    drop(occupied);
    all_slots_available(&destination);
    eprintln!(
        "TARGET_RETAINED_WORKER_HYDRATION_COMPLETE: exact original and all eight slots returned"
    );
}
