use super::*;
use crate::consensus::native::{
    prefix::{PrefixIdentity, VerifiedAppendOwner},
    roster::frame,
};
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::FileExt as _;

const BLOCK: usize = 64 * 1024;

pub(super) struct FileFixture {
    _directory: tempfile::TempDir,
    file: File,
    owner: VerifiedAppendOwner,
    offset: u64,
    length: u32,
}

impl FileFixture {
    pub(super) fn corrupt_prefix(&self) {
        self.file.write_at(&[1], 0).unwrap();
        self.file.sync_all().unwrap();
    }

    fn bytes(bytes: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("roster.native");
        let offset = BLOCK - 17;
        let mut image = vec![0; (offset + bytes.len()).div_ceil(BLOCK) * BLOCK];
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&image).unwrap();
        file.sync_all().unwrap();
        let identity = PrefixIdentity {
            binding: [7; 32],
            file_epoch: 3,
            checkpoint_epoch: 11,
            operation_sequence: 18,
            frontiers: [8; 32],
            length: image.len() as u64,
            block_bytes: BLOCK,
            digest: Sha256::digest(&image).into(),
        };
        let owner = VerifiedAppendOwner::open(
            &path,
            identity,
            2 * image.len() as u64,
            || Ok(()),
            |reader| {
                // Byte admission alone deliberately gives malformed frames no
                // semantic authority; the selected reader must authenticate them.
                let mut actual = Vec::new();
                reader.read_to_end(&mut actual)?;
                if actual != image {
                    return Err(invalid("roster fixture prefix differs"));
                }
                Ok(())
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            file,
            owner,
            offset: offset as u64,
            length: bytes.len() as u32,
        }
    }

    fn row(
        row: &Row,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
    ) -> Self {
        let mut bytes = Vec::new();
        assert_eq!(
            frame::write_row_detached(&mut bytes, row, root, scope, &|| Ok(())).unwrap() as usize,
            bytes.len()
        );
        Self::bytes(&bytes)
    }

    fn selected(
        &self,
        row: &Row,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
    ) -> Row {
        row.selected(
            self.owner.current(),
            self.offset,
            self.length,
            root,
            scope,
            &|| Ok(()),
        )
        .unwrap()
    }
}

pub(super) fn select_all(store: &mut Store<'_, '_>) -> Vec<(RequestBindingKey, FileFixture)> {
    let rows: Vec<_> = store
        .ledger
        .rows
        .iter()
        .map(|(binding, row)| (*binding, row.clone()))
        .collect();
    let mut files = Vec::new();
    for (binding, before) in rows {
        let file = FileFixture::row(&before, store.root.unwrap(), &store.scope);
        let row = file.selected(&before, store.root.unwrap(), &store.scope);
        assert!(row.is_cold() && row.canonical.is_empty());
        assert!(
            row.canonical().is_err() && row.hydrate(store.root.unwrap(), &store.scope).is_err()
        );
        let relocated = before.relocated(row);
        assert!(relocated.ptr_eq(&before));
        store.ledger.rows.insert(binding, relocated);
        files.push((binding, file));
    }
    files
}

#[test]
fn native_roster_selected_v2_q1_q2_replay_and_complete_ledger_match_sql() {
    run_v2_sql_ledger(true);
}

#[test]
fn native_roster_selected_signed_v1_and_mixed_retirement_match_sql() {
    run_signed_v1_sql_ledger(true);
}

#[test]
fn native_roster_selected_rows_reject_wrong_extent_authority_projection_and_changed_source() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let state = predecessor(&signed, None);
    let delta = state.prepare(&[]).unwrap();
    let check = || Ok(());
    let mut store = Store::new_detached(&delta, &Ledger::empty(), &signed.root, &check).unwrap();
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    let binding = signed.admission.binding_key(1).unwrap();
    roster_engine::admit_v2(
        &mut store,
        signed.identity,
        signed.identity,
        1,
        now,
        &command(&signed),
    )
    .unwrap_or_else(|_| panic!("signed selected predecessor"));
    let original = store.ledger.rows[&binding].clone();
    let file = FileFixture::row(&original, store.root.unwrap(), &store.scope);
    let cold = Row::from_selected_range(
        file.owner.current(),
        file.offset,
        file.length,
        store.root.unwrap(),
        &store.scope,
        &check,
    )
    .unwrap();
    assert!(cold.is_cold() && cold.canonical().is_err());
    assert_eq!(
        cold.hydrate_detached(store.root.unwrap(), &store.scope, &check)
            .unwrap()
            .canonical(),
        original.canonical().unwrap()
    );
    assert!(cold
        .hydrate_detached(store.root.unwrap(), &store.scope, &|| Err(
            io::Error::other("cancelled roster read")
        ))
        .is_err());
    assert!(!file.owner.current().is_failed());
    for (offset, length) in [
        (file.offset, 0),
        (file.offset, file.length - 1),
        (file.offset, file.length + 1),
        (file.offset, frame::MAX_ROW as u32 + 1),
        (u64::MAX, file.length),
        (file.owner.current().identity().length, file.length),
    ] {
        assert!(Row::from_selected_range(
            file.owner.current(),
            offset,
            length,
            store.root.unwrap(),
            &store.scope,
            &check
        )
        .is_err());
    }
    let wrong_root =
        RosterAttestationTrustRootV1::new([0xF1; 32], signed.root.compressed_public_key()).unwrap();
    assert!(cold
        .hydrate_detached(&wrong_root, &store.scope, &check)
        .is_err());
    let mut wrong_scope = store.scope.clone();
    wrong_scope.current_identity = SessionConsensusIdentity::new(
        signed.identity.cluster_id(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([0xF2; 32]),
        signed.identity.configuration_epoch(),
    );
    assert!(cold
        .hydrate_detached(store.root.unwrap(), &wrong_scope, &check)
        .is_err());
    for case in 0..4 {
        let mut changed = file.selected(&original, store.root.unwrap(), &store.scope);
        match case {
            0 => changed.projection.stable_slot[31] ^= 1,
            1 => changed.facts.state = State::Tombstone,
            2 => changed.facts.terminal_sequence = Some(99),
            3 => changed.canonical.push(1),
            _ => unreachable!(),
        }
        assert!(
            changed
                .hydrate_detached(store.root.unwrap(), &store.scope, &check)
                .is_err(),
            "changed scalar {case}"
        );
    }
    let mut bytes = Vec::new();
    frame::write_row(&mut bytes, &original).unwrap();
    for at in [0, 135, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        let malformed = FileFixture::bytes(&changed);
        assert!(Row::from_selected_range(
            malformed.owner.current(),
            malformed.offset,
            malformed.length,
            store.root.unwrap(),
            &store.scope,
            &check
        )
        .is_err());
    }
    // A separately valid signed successor cannot be installed as a mere
    // relocation of the captured Q1 revision, even under the same trust root.
    roster_engine::terminal_v2(
        &mut store,
        signed.identity,
        signed.identity,
        2,
        2,
        now,
        &signed.terminal_command,
    )
    .unwrap_or_else(|_| panic!("signed selected successor"));
    let successor = FileFixture::row(
        &store.ledger.rows[&binding],
        store.root.unwrap(),
        &store.scope,
    );
    assert!(original
        .selected(
            successor.owner.current(),
            successor.offset,
            successor.length,
            store.root.unwrap(),
            &store.scope,
            &check
        )
        .is_err());
    let files = select_all(&mut store);
    assert!(
        Ledger::admit_detached(
            store.root.unwrap(),
            &store.scope,
            1,
            Some(1),
            store.ledger.rows.values().cloned(),
            store
                .ledger
                .partitions
                .iter()
                .map(|(key, row)| (*key, (**row).clone())),
            store.ledger.witness,
            |key| Ok(store.key(key).record),
            &check
        )
        .is_err(),
        "selected row cannot exceed its applied horizon"
    );
    assert_eq!(files.len(), 1);
    file.file.write_all_at(&[1], 0).unwrap();
    file.file.sync_all().unwrap();
    assert!(cold
        .hydrate_detached(store.root.unwrap(), &store.scope, &check)
        .is_err());
    assert!(file.owner.current().is_failed());
}

#[test]
fn native_roster_selected_late_maintenance_failure_discards_the_complete_savepoint() {
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let state = predecessor(&first, None);
    let delta = state.prepare(&[]).unwrap();
    let check = || Ok(());
    let mut store = Store::new_detached(&delta, &Ledger::empty(), &first.root, &check).unwrap();
    let now = first.authority.acquired_at().add_seconds(1).unwrap();
    for (epoch, signed) in [(1, &first), (3, &second)] {
        roster_engine::admit_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch,
            now,
            &command(signed),
        )
        .unwrap_or_else(|_| panic!("selected maintenance Q1"));
        roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch + 1,
            epoch + 1,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("selected maintenance Q2"));
    }
    let files = select_all(&mut store);
    let first_binding = first.admission.binding_key(1).unwrap();
    let second_binding = second.admission.binding_key(3).unwrap();
    assert_eq!(
        store
            .ledger
            .index
            .reclaim_prefix(i128::MAX)
            .iter()
            .map(|(_, binding)| *binding)
            .collect::<Vec<_>>(),
        [first_binding, second_binding]
    );
    let before = store.ledger.clone();
    let first_canonical = store
        .hydrate_row(first_binding)
        .unwrap()
        .unwrap()
        .canonical()
        .to_vec();
    let file = &files
        .iter()
        .find(|(binding, _)| *binding == second_binding)
        .unwrap()
        .1;
    file.file.write_all_at(&[1], 0).unwrap();
    file.file.sync_all().unwrap();
    assert!(store
        .maintain_due(now.add_seconds(24 * 60 * 60).unwrap())
        .is_err());
    assert!(file.owner.current().is_failed());
    assert!(
        store.ledger.witness == before.witness
            && store.ledger.partitions.ptr_eq(&before.partitions)
    );
    for (binding, row) in &before.rows {
        assert!(store.ledger.rows[binding].ptr_eq(row));
        assert!(store.ledger.rows[binding].facts.state == State::Retained);
    }
    assert_eq!(
        store
            .hydrate_row(first_binding)
            .unwrap()
            .unwrap()
            .canonical(),
        first_canonical
    );
    assert!(!store.key(first.authority.key()).reserved);
    assert!(store.key(first.authority.key()).record.is_none());
}
