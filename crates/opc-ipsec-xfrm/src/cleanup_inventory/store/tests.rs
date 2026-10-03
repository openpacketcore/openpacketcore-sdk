use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

use super::*;

// Test observation uses the production root and record validation paths.
impl<I: SnapshotIo> SnapshotStore<I> {
    pub(in crate::cleanup_inventory) fn record(
        &self,
        position: u32,
    ) -> Result<Option<InventoryRecord>, InventoryError> {
        self.check_current()?;
        self.read_record(position)
    }
}
use crate::cleanup_inventory::{node::NodeKind, tree::ChildReference, ObjectPhase};

#[derive(Clone)]
struct Inode {
    bytes: Vec<u8>,
    durable: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
struct DiskState {
    names: BTreeMap<NodeName, u64>,
    durable_names: BTreeMap<NodeName, u64>,
    inodes: BTreeMap<u64, Inode>,
    next_inode: u64,
    leased: bool,
    sequence: usize,
    fail: Option<(usize, bool)>,
    trace: Vec<&'static str>,
}

#[derive(Clone, Default)]
struct MemoryDisk(Rc<RefCell<DiskState>>);

impl MemoryDisk {
    fn fork(&self) -> Self {
        let mut state = self.0.borrow().clone();
        assert!(!state.leased);
        state.trace.clear();
        state.sequence = 0;
        state.fail = None;
        Self(Rc::new(RefCell::new(state)))
    }
    fn acquire(&self) -> Result<MemoryIo, InventoryError> {
        let mut state = self.0.borrow_mut();
        if state.leased {
            return Err(InventoryError::Unavailable);
        }
        state.leased = true;
        Ok(MemoryIo(self.clone()))
    }

    fn arm(&self, sequence: usize, after: bool) {
        let mut state = self.0.borrow_mut();
        state.sequence = 0;
        state.trace.clear();
        state.fail = Some((sequence, after));
    }

    fn disarm(&self) {
        self.0.borrow_mut().fail = None;
    }

    fn power_loss(&self) {
        let mut state = self.0.borrow_mut();
        assert!(!state.leased);
        state.names = state.durable_names.clone();
        for inode in state.inodes.values_mut() {
            if let Some(bytes) = &inode.durable {
                inode.bytes = bytes.clone();
            }
        }
        state.fail = None;
    }

    // A filesystem may persist one rename without persisting an earlier rename
    // in that directory. Tests must not assume all-or-none directory rollback.
    fn persist_one_name(&self, name: NodeName) {
        let mut state = self.0.borrow_mut();
        if let Some(inode) = state.names.get(&name).copied() {
            state.durable_names.insert(name, inode);
        } else {
            state.durable_names.remove(&name);
        }
    }
}

struct MemoryIo(MemoryDisk);

impl Drop for MemoryIo {
    fn drop(&mut self) {
        self.0 .0.borrow_mut().leased = false;
    }
}

impl MemoryIo {
    fn operation<T>(
        &self,
        name: &'static str,
        action: impl FnOnce(&mut DiskState) -> Result<T, InventoryError>,
    ) -> Result<T, InventoryError> {
        let mut state = self.0 .0.borrow_mut();
        state.sequence += 1;
        state.trace.push(name);
        if state.fail == Some((state.sequence, false)) {
            return Err(InventoryError::Unavailable);
        }
        let result = action(&mut state)?;
        if state.fail == Some((state.sequence, true)) {
            return Err(InventoryError::Unavailable);
        }
        Ok(result)
    }
}

impl SnapshotIo for MemoryIo {
    type Handle = u64;

    fn check_binding(&self) -> Result<(), InventoryError> {
        self.operation("binding", |_| Ok(()))
    }
    fn account(
        &self,
        _limits: InventoryLimits,
        _format: FormatBudget,
    ) -> Result<(), InventoryError> {
        self.operation("account", |_| Ok(()))
    }

    fn read(
        &self,
        name: NodeName,
        maximum: usize,
    ) -> Result<(Self::Handle, Vec<u8>), InventoryError> {
        self.operation("read", |state| {
            let inode = state
                .names
                .get(&name)
                .copied()
                .ok_or(InventoryError::Malformed)?;
            let bytes = &state
                .inodes
                .get(&inode)
                .ok_or(InventoryError::Malformed)?
                .bytes;
            if bytes.len() > maximum {
                return Err(InventoryError::Capacity);
            }
            Ok((inode, bytes.clone()))
        })
    }

    fn stabilize_root(
        &mut self,
        handle: &Self::Handle,
        digest: [u8; 32],
    ) -> Result<(), InventoryError> {
        self.operation("revalidate_root", |state| {
            if state.names.get(&NodeName::Root) != Some(handle)
                || state.inodes.get(handle).is_none_or(|inode| {
                    super::super::node::ciphertext_digest(&inode.bytes) != digest
                })
            {
                return Err(InventoryError::WrongBinding);
            }
            Ok(())
        })?;
        self.operation("sync_accepted_root", |state| {
            let inode = state
                .inodes
                .get_mut(handle)
                .ok_or(InventoryError::Malformed)?;
            inode.durable = Some(inode.bytes.clone());
            Ok(())
        })
    }

    fn write_temporary(&mut self, bytes: &[u8]) -> Result<(), InventoryError> {
        self.operation("write_temporary", |state| {
            if state.names.contains_key(&NodeName::Temporary) {
                return Err(InventoryError::Malformed);
            }
            state.next_inode += 1;
            let inode = state.next_inode;
            state.inodes.insert(
                inode,
                Inode {
                    bytes: bytes.to_vec(),
                    durable: None,
                },
            );
            state.names.insert(NodeName::Temporary, inode);
            Ok(())
        })
    }

    fn sync_temporary(&mut self) -> Result<(), InventoryError> {
        self.operation("sync_temporary", |state| {
            let id = state
                .names
                .get(&NodeName::Temporary)
                .ok_or(InventoryError::Malformed)?;
            let inode = state.inodes.get_mut(id).ok_or(InventoryError::Malformed)?;
            inode.durable = Some(inode.bytes.clone());
            Ok(())
        })
    }

    fn rename_temporary(&mut self, destination: NodeName) -> Result<(), InventoryError> {
        self.operation(
            match destination {
                NodeName::Root => "rename_root",
                NodeName::Branch(_, _) => "rename_branch",
                _ => "rename_leaf",
            },
            |state| {
                let inode = state
                    .names
                    .remove(&NodeName::Temporary)
                    .ok_or(InventoryError::Malformed)?;
                state.names.insert(destination, inode);
                Ok(())
            },
        )
    }

    fn sync_directory(&mut self) -> Result<(), InventoryError> {
        self.operation("sync_directory", |state| {
            state.durable_names = state.names.clone();
            Ok(())
        })
    }

    fn remove_temporary(&mut self) -> Result<(), InventoryError> {
        self.operation("remove_temporary", |state| {
            state.names.remove(&NodeName::Temporary);
            Ok(())
        })
    }
}

fn binding() -> NodeContext {
    NodeContext {
        namespace: [1; 40],
        incarnation: [2; 16],
        device: 3,
        inode: 4,
        generation: 1,
        revision: 1,
        kind: NodeKind::Root,
        position: 0,
        slot: 0,
    }
}

fn limits() -> InventoryLimits {
    InventoryLimits {
        objects: 130,
        images: 260,
        coverage: 16,
        batch_records: 9,
        storage_bytes: 8 * 1024 * 1024,
        index_bytes: 64 * 1024,
        working_bytes: 4 * 1024 * 1024,
    }
}

fn stores() -> [Option<[u8; 16]>; 3] {
    [None, None, Some([6; 16])]
}

fn create(disk: &MemoryDisk) -> SnapshotStore<MemoryIo> {
    SnapshotStore::create(
        disk.acquire().unwrap(),
        InventoryKey::new([7; 32]),
        binding(),
        RootPage {
            completion: [0; 4096],
            next_serial: 1,
            limits: limits(),
            stores: stores(),
            children: [ChildReference::EMPTY; 256],
        },
        super::super::tests::proposed_format(),
    )
    .unwrap()
}

fn reopen(disk: &MemoryDisk) -> Result<SnapshotStore<MemoryIo>, InventoryError> {
    SnapshotStore::reopen(
        disk.acquire().unwrap(),
        InventoryKey::new([7; 32]),
        binding(),
        limits(),
        stores(),
        super::super::tests::proposed_format(),
    )
}

fn object(serial: u64, discriminator: u16) -> InventoryRecord {
    let mut record = super::super::tests::object_record(super::super::CleanupImage::Policy(
        super::super::tests::maximum_policy(),
    ));
    if let InventoryRecord::Object(object) = &mut record {
        object.serial = serial;
        object.coverage = None;
        object.phase = ObjectPhase::Owned;
        for candidate in &mut object.candidates {
            if let super::super::CleanupImage::Policy(policy) = &mut candidate.image {
                policy.selector.source_port = discriminator;
            }
        }
    }
    record
}

#[test]
fn complete_snapshot_reopens_with_mixed_child_revisions() {
    let disk = MemoryDisk::default();
    let mut store = create(&disk);
    store
        .apply(
            vec![
                Change {
                    absence: None,
                    position: 0,
                    expected_serial: None,
                    record: Some(object(1, 10)),
                },
                Change {
                    absence: None,
                    position: 64,
                    expected_serial: None,
                    record: Some(object(2, 11)),
                },
            ],
            false,
        )
        .unwrap();
    drop(store);
    let mut store = reopen(&disk).unwrap();
    assert_eq!(store.record(0).unwrap(), Some(object(1, 10)));
    assert_eq!(store.record(64).unwrap(), Some(object(2, 11)));
    let mut updated = object(1, 10);
    if let InventoryRecord::Object(object) = &mut updated {
        object.phase = ObjectPhase::Indeterminate;
    }
    store
        .apply(
            vec![Change {
                absence: None,
                position: 0,
                expected_serial: Some(1),
                record: Some(updated.clone()),
            }],
            false,
        )
        .unwrap();
    store.apply(Vec::new(), true).unwrap();
    drop(store);
    disk.power_loss();
    let store = reopen(&disk).unwrap();
    assert_eq!(store.record(0).unwrap(), Some(updated));
    assert_eq!(store.record(64).unwrap(), Some(object(2, 11)));
    assert_eq!(store.context.generation, 2);
}

#[test]
fn configured_storage_and_working_reservations_are_checked_before_publication() {
    for (storage_bytes, working_bytes) in [(1, limits().working_bytes), (limits().storage_bytes, 1)]
    {
        let disk = MemoryDisk::default();
        let configured = InventoryLimits {
            storage_bytes,
            working_bytes,
            ..limits()
        };
        let result = SnapshotStore::create(
            disk.acquire().unwrap(),
            InventoryKey::new([7; 32]),
            binding(),
            RootPage {
                completion: [0; 4096],
                next_serial: 1,
                limits: configured,
                stores: stores(),
                children: [ChildReference::EMPTY; 256],
            },
            super::super::tests::proposed_format(),
        );
        assert!(matches!(result, Err(InventoryError::Capacity)));
        assert!(disk.0.borrow().names.is_empty());
    }
}

fn changed_object(serial: u64, discriminator: u16) -> InventoryRecord {
    let mut record = object(serial, discriminator);
    if let InventoryRecord::Object(object) = &mut record {
        object.phase = ObjectPhase::Indeterminate;
    }
    record
}

fn one_update() -> Vec<Change> {
    vec![Change {
        absence: None,
        position: 0,
        expected_serial: Some(1),
        record: Some(changed_object(1, 10)),
    }]
}

fn seeded_disk() -> MemoryDisk {
    let disk = MemoryDisk::default();
    let mut store = create(&disk);
    store
        .apply(
            vec![Change {
                absence: None,
                position: 0,
                expected_serial: None,
                record: Some(object(1, 10)),
            }],
            false,
        )
        .unwrap();
    drop(store);
    disk
}

#[test]
fn every_publication_cut_is_atomic_and_poisoned_until_leased_reopen() {
    let base = seeded_disk();
    let reference = base.fork();
    let mut store = reopen(&reference).unwrap();
    reference.arm(usize::MAX, false);
    store.apply(one_update(), false).unwrap();
    let trace = reference.0.borrow().trace.clone();
    let first_write = trace
        .iter()
        .position(|event| *event == "write_temporary")
        .unwrap()
        + 1;
    drop(store);
    for cut in 1..=trace.len() {
        for after in [false, true] {
            for power_loss in [false, true] {
                let disk = base.fork();
                let mut store = reopen(&disk).unwrap();
                disk.arm(cut, after);
                assert!(
                    store.apply(one_update(), false).is_err(),
                    "cut {cut}, after {after}"
                );
                disk.disarm();
                if cut >= first_write {
                    assert!(store.apply(Vec::new(), true).is_err());
                    assert!(store.record(0).is_err());
                }
                drop(store);
                if power_loss {
                    disk.power_loss();
                }
                let store = reopen(&disk).unwrap();
                let record = store.record(0).unwrap().unwrap();
                assert!(record == object(1, 10) || record == changed_object(1, 10));
            }
        }
    }
    println!(
        "publication_fault_cases {} io_steps {}",
        trace.len() * 4,
        trace.len()
    );
}

#[test]
fn reopen_stabilizes_visible_root_before_a_second_crash_reuses_old_slots() {
    let base = seeded_disk();
    let reference = base.fork();
    let mut store = reopen(&reference).unwrap();
    reference.arm(usize::MAX, false);
    store.apply(one_update(), false).unwrap();
    let rename = reference
        .0
        .borrow()
        .trace
        .iter()
        .position(|event| *event == "rename_root")
        .unwrap()
        + 1;
    drop(store);

    let disk = base.fork();
    let mut store = reopen(&disk).unwrap();
    disk.arm(rename, true);
    assert!(store.apply(one_update(), false).is_err());
    drop(store); // Process loss preserves the unsynced, visible new root.
    disk.disarm();
    disk.arm(usize::MAX, false);
    let mut store = reopen(&disk).unwrap();
    let trace = disk.0.borrow().trace.clone();
    let barrier = trace
        .iter()
        .position(|event| *event == "sync_accepted_root")
        .unwrap();
    assert_eq!(trace[barrier + 1], "sync_directory");
    assert!(trace[barrier + 2..].contains(&"remove_temporary"));
    assert_eq!(store.record(0).unwrap(), Some(changed_object(1, 10)));
    let accepted_root = disk.0.borrow().names[&NodeName::Root];
    assert_eq!(
        disk.0.borrow().durable_names[&NodeName::Root],
        accepted_root
    );

    let old_leaf_slot = 1 - store.read_branch(0).unwrap()[0].slot;
    let prior_slot_inode = disk.0.borrow().names[&NodeName::Leaf(0, old_leaf_slot)];
    // Determine the first child rename without changing this store.
    let next_disk = disk.0.borrow().clone();
    let mut trial_state = next_disk;
    trial_state.leased = false;
    let trial = MemoryDisk(Rc::new(RefCell::new(trial_state)));
    let mut trial_store = reopen(&trial).unwrap();
    trial.arm(usize::MAX, false);
    trial_store
        .apply(
            vec![Change {
                absence: None,
                position: 1,
                expected_serial: None,
                record: Some(object(2, 12)),
            }],
            false,
        )
        .unwrap();
    let child_rename = trial
        .0
        .borrow()
        .trace
        .iter()
        .position(|event| *event == "rename_leaf")
        .unwrap()
        + 1;
    drop(trial_store);
    disk.arm(child_rename, true);
    assert!(store
        .apply(
            vec![Change {
                absence: None,
                position: 1,
                expected_serial: None,
                record: Some(object(2, 12))
            }],
            false
        )
        .is_err());
    assert_eq!(disk.0.borrow().trace.last(), Some(&"rename_leaf"));
    assert_ne!(
        disk.0.borrow().names[&NodeName::Leaf(0, old_leaf_slot)],
        prior_slot_inode
    );
    disk.persist_one_name(NodeName::Leaf(0, old_leaf_slot));
    drop(store);
    disk.power_loss();
    let store = reopen(&disk).unwrap();
    assert_eq!(store.record(0).unwrap(), Some(changed_object(1, 10)));
    assert!(store.record(1).unwrap().is_none());
}

#[test]
fn reopen_barrier_failure_never_reclaims_or_overwrites_children() {
    let base = seeded_disk();
    let reference = base.fork();
    reference.arm(usize::MAX, false);
    drop(reopen(&reference).unwrap());
    let trace = reference.0.borrow().trace.clone();
    let barrier = trace
        .iter()
        .position(|event| *event == "sync_accepted_root")
        .unwrap()
        + 1;
    for cut in [barrier, barrier + 1] {
        for after in [false, true] {
            let disk = base.fork();
            disk.arm(cut, after);
            assert!(reopen(&disk).is_err());
            assert!(!disk.0.borrow().trace.contains(&"remove_temporary"));
            assert!(!disk.0.borrow().trace.contains(&"write_temporary"));
            disk.power_loss();
            let store = reopen(&disk).unwrap();
            assert_eq!(store.record(0).unwrap(), Some(object(1, 10)));
        }
    }
}

#[test]
fn sole_current_root_never_falls_back_when_torn_or_missing() {
    let base = seeded_disk();
    let length = {
        let state = base.0.borrow();
        state.inodes[&state.names[&NodeName::Root]].bytes.len()
    };
    for length in 0..length {
        let disk = base.fork();
        {
            let mut state = disk.0.borrow_mut();
            let root = state.names[&NodeName::Root];
            state.inodes.get_mut(&root).unwrap().bytes.truncate(length);
        }
        assert!(reopen(&disk).is_err());
    }
    let disk = base.fork();
    disk.0.borrow_mut().names.remove(&NodeName::Root);
    assert!(reopen(&disk).is_err());
}

#[test]
fn resource_report_includes_two_slots_staging_and_decode_allocations() {
    let bounds = resource_bounds(limits(), super::super::tests::proposed_format()).unwrap();
    assert_eq!(bounds.leaf_files, 3);
    assert_eq!(bounds.branch_files, 1);
    assert_eq!(bounds.file_count, 10);
    assert_eq!(
        bounds.content_bytes,
        2 * 3 * 65806 + 2 * 16384 + 20480 + 65806
    );
    assert_eq!(bounds.index_bytes, 1024 * 40);
    println!("small_fixture_resource_bounds {bounds:?}");
    println!(
        "native_pending_bytes leaf {} branch {} change {}",
        std::mem::size_of::<PendingLeaf>(),
        std::mem::size_of::<PendingBranch>(),
        std::mem::size_of::<Change>()
    );
}

fn covered_records() -> (InventoryRecord, InventoryRecord, InventoryRecord) {
    use crate::cleanup_inventory::{CoverageMember, CoverageRecord, RecordLink, TransactionFamily};
    let mut first = object(1, 10);
    let mut second = object(2, 11);
    for record in [&mut first, &mut second] {
        if let InventoryRecord::Object(object) = record {
            object.coverage = Some(RecordLink {
                position: 128,
                serial: 3,
            });
        }
    }
    let coverage = InventoryRecord::Coverage(CoverageRecord {
        serial: 3,
        inventory_generation: 1,
        family: TransactionFamily::Roster,
        store_incarnation: [6; 16],
        correlation: [8; 16],
        operation_generation: 1,
        request_fingerprint: [9; 32],
        settlement: None,
        members: vec![
            CoverageMember {
                object: RecordLink {
                    position: 0,
                    serial: 1,
                },
                absence: None,
            },
            CoverageMember {
                object: RecordLink {
                    position: 64,
                    serial: 2,
                },
                absence: None,
            },
        ],
    });
    (first, second, coverage)
}

fn covered_disk() -> MemoryDisk {
    let disk = MemoryDisk::default();
    let mut store = create(&disk);
    let (first, second, coverage) = covered_records();
    store
        .apply(
            vec![
                Change {
                    absence: None,
                    position: 0,
                    expected_serial: None,
                    record: Some(first),
                },
                Change {
                    absence: None,
                    position: 64,
                    expected_serial: None,
                    record: Some(second),
                },
                Change {
                    absence: None,
                    position: 128,
                    expected_serial: None,
                    record: Some(coverage),
                },
            ],
            false,
        )
        .unwrap();
    drop(store);
    disk
}

#[test]
fn an_unsettled_coverage_cannot_be_forgotten_by_clearing_backlinks() {
    let disk = covered_disk();
    let mut store = reopen(&disk).unwrap();
    assert!(store
        .apply(
            vec![
                Change {
                    absence: None,
                    position: 0,
                    expected_serial: Some(1),
                    record: Some(object(1, 10))
                },
                Change {
                    absence: None,
                    position: 64,
                    expected_serial: Some(2),
                    record: Some(object(2, 11))
                },
                Change {
                    absence: None,
                    position: 128,
                    expected_serial: Some(3),
                    record: None
                }
            ],
            false
        )
        .is_err());
    assert!(store.record(128).unwrap().is_some());
}

#[test]
fn an_owned_object_cannot_be_forgotten_without_absence_authority() {
    let disk = seeded_disk();
    let mut store = reopen(&disk).unwrap();
    assert!(store
        .apply(
            vec![Change {
                absence: None,
                position: 0,
                expected_serial: Some(1),
                record: None
            }],
            false
        )
        .is_err());
    assert_eq!(store.record(0).unwrap(), Some(object(1, 10)));
}

fn retire_first() -> Vec<Change> {
    let (_, _, mut coverage) = covered_records();
    if let InventoryRecord::Coverage(coverage) = &mut coverage {
        coverage.members[0].absence = Some([10; 32]);
    }
    vec![
        Change {
            absence: Some([10; 32]),
            position: 0,
            expected_serial: Some(1),
            record: None,
        },
        Change {
            absence: None,
            position: 128,
            expected_serial: Some(3),
            record: Some(coverage),
        },
    ]
}

#[test]
fn multi_leaf_retirement_persists_coverage_witness_atomically_at_every_cut() {
    let base = covered_disk();
    let reference = base.fork();
    let mut store = reopen(&reference).unwrap();
    reference.arm(usize::MAX, false);
    store.apply(retire_first(), false).unwrap();
    let steps = reference.0.borrow().trace.len();
    drop(store);
    for cut in 1..=steps {
        for after in [false, true] {
            for power_loss in [false, true] {
                let disk = base.fork();
                let mut store = reopen(&disk).unwrap();
                disk.arm(cut, after);
                assert!(store.apply(retire_first(), false).is_err());
                drop(store);
                disk.disarm();
                if power_loss {
                    disk.power_loss();
                }
                let store = reopen(&disk).unwrap();
                let Some(InventoryRecord::Coverage(coverage)) = store.record(128).unwrap() else {
                    panic!("coverage disappeared before journal settlement")
                };
                assert_eq!(coverage.store_incarnation, [6; 16]);
                assert_eq!(
                    coverage.members[0].absence.is_some(),
                    store.record(0).unwrap().is_none()
                );
                assert!(coverage.members[1].absence.is_none());
                assert_eq!(store.record(64).unwrap(), Some(covered_records().1));
            }
        }
    }
    println!(
        "multi_leaf_retirement_fault_cases {} io_steps {steps}",
        steps * 4
    );
}

#[test]
fn retired_positions_reuse_new_serials_while_old_coverage_keeps_authority() {
    let disk = covered_disk();
    let mut store = reopen(&disk).unwrap();
    store.apply(retire_first(), false).unwrap();
    assert!(store
        .apply(
            vec![Change {
                absence: None,
                position: 0,
                expected_serial: None,
                record: Some(object(1, 12))
            }],
            false
        )
        .is_err());
    store
        .apply(
            vec![Change {
                absence: None,
                position: 0,
                expected_serial: None,
                record: Some(object(4, 12)),
            }],
            false,
        )
        .unwrap();
    let Some(InventoryRecord::Coverage(mut coverage)) = store.record(128).unwrap() else {
        panic!("coverage missing")
    };
    assert_eq!(coverage.members[0].object.serial, 1);
    assert_eq!(coverage.members[0].absence, Some([10; 32]));
    coverage.settlement = Some([11; 32]);
    store
        .apply(
            vec![Change {
                absence: None,
                position: 128,
                expected_serial: Some(3),
                record: Some(InventoryRecord::Coverage(coverage)),
            }],
            false,
        )
        .unwrap();
    store
        .apply(
            vec![
                Change {
                    absence: None,
                    position: 64,
                    expected_serial: Some(2),
                    record: Some(object(2, 11)),
                },
                Change {
                    absence: None,
                    position: 128,
                    expected_serial: Some(3),
                    record: None,
                },
            ],
            false,
        )
        .unwrap();
    drop(store);
    let store = reopen(&disk).unwrap();
    assert_eq!(store.record(0).unwrap(), Some(object(4, 12)));
    assert_eq!(store.record(64).unwrap(), Some(object(2, 11)));
    assert!(store.record(128).unwrap().is_none());
}

#[test]
fn lifetime_duplicates_wrong_store_and_broken_backlinks_are_refused_before_writes() {
    let disk = covered_disk();
    let mut store = reopen(&disk).unwrap();
    for changes in [
        vec![Change {
            absence: None,
            position: 1,
            expected_serial: None,
            record: Some(object(4, 10)),
        }],
        vec![Change {
            absence: None,
            position: 0,
            expected_serial: Some(1),
            record: Some(object(1, 10)),
        }],
    ] {
        disk.arm(usize::MAX, false);
        assert!(store.apply(changes, false).is_err());
        assert!(!disk.0.borrow().trace.contains(&"write_temporary"));
    }
    drop(store);
    for expected_stores in [[None; 3], [None, None, Some([12; 16])]] {
        disk.arm(usize::MAX, false);
        assert!(SnapshotStore::reopen(
            disk.acquire().unwrap(),
            InventoryKey::new([7; 32]),
            binding(),
            limits(),
            expected_stores,
            super::super::tests::proposed_format()
        )
        .is_err());
        assert!(!disk.0.borrow().trace.contains(&"sync_accepted_root"));
        assert!(!disk.0.borrow().trace.contains(&"write_temporary"));
    }
}

#[test]
fn admitted_same_leaf_batch_keeps_actual_path_allocations_inside_its_budget() {
    let disk = MemoryDisk::default();
    let format = super::super::tests::proposed_format();
    let mut configured = InventoryLimits {
        objects: 64,
        images: 128,
        coverage: 0,
        batch_records: 64,
        ..limits()
    };
    configured.working_bytes = resource_bounds(configured, format).unwrap().working_bytes;
    let mut store = SnapshotStore::create(
        disk.acquire().unwrap(),
        InventoryKey::new([7; 32]),
        binding(),
        RootPage {
            completion: [0; 4096],
            next_serial: 1,
            limits: configured,
            stores: stores(),
            children: [ChildReference::EMPTY; 256],
        },
        format,
    )
    .unwrap();
    let changes = (0..64_u32)
        .map(|position| Change {
            absence: None,
            position,
            expected_serial: None,
            record: Some(object(
                u64::from(position) + 1,
                u16::try_from(position).unwrap() + 10,
            )),
        })
        .collect();
    store.apply(changes, false).unwrap();
    let actual = u64::try_from(store.path_vector_allocation_bytes).unwrap();
    println!(
        "same_leaf_admitted_working_budget {} actual_path_vector_allocation {actual}",
        configured.working_bytes
    );
    assert!(
        actual <= configured.working_bytes,
        "path vectors alone exceed the admitted whole working budget"
    );
}

#[test]
fn replacing_coverage_cannot_drop_a_retired_member_and_its_absence_witness() {
    let disk = covered_disk();
    let mut store = reopen(&disk).unwrap();
    store.apply(retire_first(), false).unwrap();
    let Some(InventoryRecord::Coverage(mut coverage)) = store.record(128).unwrap() else {
        panic!("coverage missing")
    };
    coverage.members.remove(0);
    assert!(store
        .apply(
            vec![Change {
                absence: None,
                position: 128,
                expected_serial: Some(3),
                record: Some(InventoryRecord::Coverage(coverage))
            }],
            false
        )
        .is_err());
}

#[test]
fn replacing_coverage_cannot_remove_a_live_member_by_clearing_its_backlink() {
    let disk = covered_disk();
    let mut store = reopen(&disk).unwrap();
    let Some(InventoryRecord::Coverage(mut coverage)) = store.record(128).unwrap() else {
        panic!("coverage missing")
    };
    coverage.members.remove(0);
    assert!(store
        .apply(
            vec![
                Change {
                    absence: None,
                    position: 0,
                    expected_serial: Some(1),
                    record: Some(object(1, 10))
                },
                Change {
                    absence: None,
                    position: 128,
                    expected_serial: Some(3),
                    record: Some(InventoryRecord::Coverage(coverage))
                }
            ],
            false
        )
        .is_err());
}

#[test]
fn replacing_records_cannot_rewrite_creator_or_candidate_identity() {
    for change_creator in [false, true] {
        let disk = covered_disk();
        let mut store = reopen(&disk).unwrap();
        let (position, expected_serial, record) = if change_creator {
            let Some(InventoryRecord::Coverage(mut coverage)) = store.record(128).unwrap() else {
                panic!("coverage missing")
            };
            coverage.correlation = [15; 16];
            coverage.operation_generation += 1;
            coverage.request_fingerprint = [16; 32];
            (128, 3, InventoryRecord::Coverage(coverage))
        } else {
            let Some(InventoryRecord::Object(mut object)) = store.record(0).unwrap() else {
                panic!("object missing")
            };
            object.candidates[0].pre_effect_absence = [17; 32];
            if let super::super::CleanupImage::Policy(policy) = &mut object.candidates[0].image {
                policy.priority += 1;
            }
            (0, 1, InventoryRecord::Object(object))
        };
        assert!(store
            .apply(
                vec![Change {
                    absence: None,
                    position,
                    expected_serial: Some(expected_serial),
                    record: Some(record)
                }],
                false
            )
            .is_err());
    }
}

#[test]
fn prior_member_and_settlement_witnesses_are_monotonic_and_roster_order_is_fixed() {
    for mutation in 0..7 {
        let disk = covered_disk();
        let mut store = reopen(&disk).unwrap();
        store.apply(retire_first(), false).unwrap();
        let Some(InventoryRecord::Coverage(mut coverage)) = store.record(128).unwrap() else {
            panic!("coverage missing")
        };
        coverage.settlement = Some([20; 32]);
        store
            .apply(
                vec![Change {
                    absence: None,
                    position: 128,
                    expected_serial: Some(3),
                    record: Some(InventoryRecord::Coverage(coverage.clone())),
                }],
                false,
            )
            .unwrap();
        match mutation {
            0 => coverage.members[0].absence = None,
            1 => coverage.members[0].absence = Some([21; 32]),
            2 => coverage.settlement = None,
            3 => coverage.settlement = Some([21; 32]),
            4 => coverage.members.swap(0, 1),
            5 => coverage.members[0].object.serial = 2,
            _ => coverage.inventory_generation += 1,
        }
        disk.arm(usize::MAX, false);
        assert!(store
            .apply(
                vec![Change {
                    absence: None,
                    position: 128,
                    expected_serial: Some(3),
                    record: Some(InventoryRecord::Coverage(coverage))
                }],
                false
            )
            .is_err());
        assert!(!disk.0.borrow().trace.contains(&"write_temporary"));
    }
}
