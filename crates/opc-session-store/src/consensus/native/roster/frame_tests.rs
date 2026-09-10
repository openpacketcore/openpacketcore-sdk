use super::*;
use crate::consensus::native::roster::frame;
use std::io::{Cursor, Read};

/// Exercise the actual signed V1/V2 Q1, Q2, replay and mixed retention
/// fixtures at their existing semantic checkpoints. The reconstructed ledger
/// must re-prove business reservations, partition bounds and global charge.
pub(super) fn assert_ledger_frames(store: &Store<'_, '_>, sequence: u64) {
    store.changes.require_current(&store.ledger).unwrap();
    store
        .changes
        .validate_detached(store.root.unwrap(), &store.scope, &|| Ok(()))
        .unwrap();
    let mut rows = Vec::new();
    for row in store.ledger.rows.values() {
        let mut encoded = Vec::new();
        let length = frame::write_row_detached(
            &mut encoded,
            row,
            store.root.unwrap(),
            &store.scope,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(length as usize, encoded.len());
        let mut input = Cursor::new(&encoded);
        let hydrated =
            frame::read_row(&mut input, length, store.root.unwrap(), &store.scope).unwrap();
        assert_eq!(input.position(), u64::from(length));
        assert!(row.matches_canonical(hydrated.canonical()));
        assert!(hydrated.projection == row.projection && hydrated.facts == row.facts);
        assert_eq!(hydrated.reserved_key(), row.reserved_key());
        let rebuilt = Row::from_hydration(&hydrated).unwrap();
        let mut exact = Vec::new();
        assert_eq!(frame::write_row(&mut exact, &rebuilt).unwrap(), length);
        assert_eq!(exact, encoded);
        rows.push(SharedRow::new(rebuilt));
    }
    let mut partitions = Vec::new();
    for (key, partition) in &store.ledger.partitions {
        let mut encoded = Vec::new();
        let length = frame::write_partition(&mut encoded, *key, partition).unwrap();
        assert_eq!(length as usize, encoded.len());
        let mut input = Cursor::new(&encoded);
        let (decoded_key, decoded) = frame::read_partition(&mut input, length).unwrap();
        assert_eq!(input.position(), u64::from(length));
        assert_eq!(decoded_key, *key);
        assert!(decoded == **partition);
        partitions.push((decoded_key, decoded));
    }
    let rebuilt = Ledger::admit(
        store.root.unwrap(),
        &store.scope,
        sequence,
        Some(sequence),
        rows,
        partitions,
        store.ledger.witness,
        |key| Ok(store.key(key).record),
    )
    .unwrap();
    assert_eq!(rebuilt.rows.len(), store.ledger.rows.len());
    assert_eq!(rebuilt.index.len(), store.ledger.index.len());
    assert!(rebuilt.witness == store.ledger.witness);
}

#[test]
fn native_roster_frames_reject_wrong_extent_projection_authority_and_carrier() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let state = predecessor(&signed, None);
    let delta = state.prepare(&[]).unwrap();
    let mut store = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    roster_engine::admit_v2(
        &mut store,
        signed.identity,
        signed.identity,
        1,
        now,
        &command(&signed),
    )
    .unwrap_or_else(|_| panic!("signed frame predecessor"));
    let binding = signed.admission.binding_key(1).unwrap();
    let row = &store.ledger.rows[&binding];
    let mut encoded = Vec::new();
    let length = frame::write_row(&mut encoded, row).unwrap();
    let projection_len = usize::from(u16::from_be_bytes([encoded[128], encoded[129]]));
    for end in [0, 7, 127, 133, 134 + projection_len, encoded.len() - 1] {
        assert!(
            frame::read_row(
                &mut Cursor::new(&encoded[..end]),
                length,
                &signed.root,
                &store.scope
            )
            .is_err(),
            "truncated at {end}"
        );
    }
    for extent in [0, length - 1, length + 1, u32::MAX] {
        assert!(
            frame::read_row(
                &mut Cursor::new(&encoded),
                extent,
                &signed.root,
                &store.scope
            )
            .is_err(),
            "wrong extent {extent}"
        );
    }
    // Format, valid foreign epoch, valid changed stable-slot projection and
    // damaged canonical body all fail before a semantic row can escape.
    for offset in [0, 15, 135, encoded.len() - 1] {
        let mut changed = encoded.clone();
        changed[offset] ^= 2;
        assert!(
            frame::read_row(
                &mut Cursor::new(changed),
                length,
                &signed.root,
                &store.scope
            )
            .is_err(),
            "changed offset {offset}"
        );
    }
    let foreign_root =
        RosterAttestationTrustRootV1::new([0xF1; 32], signed.root.compressed_public_key()).unwrap();
    assert!(frame::read_row(
        &mut Cursor::new(&encoded),
        length,
        &foreign_root,
        &store.scope
    )
    .is_err());
    let mut scope = store.scope.clone();
    scope.current_identity = SessionConsensusIdentity::new(
        signed.identity.cluster_id(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([0xF2; 32]),
        signed.identity.configuration_epoch(),
    );
    assert!(frame::read_row(&mut Cursor::new(&encoded), length, &signed.root, &scope).is_err());

    // Oversized component claims are rejected from the fixed header. Even
    // asking the input for projection/body bytes would fail this assertion.
    struct HeaderOnly {
        input: Cursor<Vec<u8>>,
        body_requested: bool,
    }
    impl Read for HeaderOnly {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.input.position() == 134 {
                self.body_requested = true;
                return Err(io::Error::other("body read before bound check"));
            }
            self.input.read(out)
        }
    }
    for projection in [true, false] {
        let mut header = encoded[..134].to_vec();
        if projection {
            header[128..130].copy_from_slice(&513u16.to_be_bytes());
        } else {
            header[130..134]
                .copy_from_slice(&((carrier::MAX_CANONICAL_BYTES + 1) as u32).to_be_bytes());
        }
        let mut input = HeaderOnly {
            input: Cursor::new(header),
            body_requested: false,
        };
        assert!(frame::read_row(
            &mut input,
            frame::MAX_ROW as u32,
            &signed.root,
            &store.scope
        )
        .is_err());
        assert!(!input.body_requested);
    }
    // A redundant varint form decodes to the same Profile value in Postcard,
    // but the envelope must reject it as a different canonical projection.
    let mut noncanonical = encoded.clone();
    noncanonical[134] |= 0x80;
    noncanonical.insert(135, 0);
    noncanonical[128..130].copy_from_slice(&((projection_len + 1) as u16).to_be_bytes());
    assert!(frame::read_row(
        &mut Cursor::new(noncanonical),
        length + 1,
        &signed.root,
        &store.scope
    )
    .is_err());
}

#[test]
fn native_roster_partition_frames_bind_cursor_floor_and_exact_extent() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let binding = signed.admission.binding_key(1).unwrap();
    let floor = IrreversibleHistoryFloor::initial(binding).unwrap();
    let key = ProductionFloorKey::from_floor(floor).unwrap();
    // Use the original cursor codec and validate the complete floor relation.
    // This is deterministic retirement metadata, never attestation authority.
    let cursor = ProductionRetirementCursor::from_canonical_bytes(
        &postcard::to_allocvec(&(key, 1u64, Some(binding))).unwrap(),
    )
    .unwrap();
    for cursor in [None, Some(cursor)] {
        let partition = Partition { floor, cursor };
        let mut encoded = Vec::new();
        let length = frame::write_partition(&mut encoded, key, &partition).unwrap();
        let (actual_key, actual) =
            frame::read_partition(&mut Cursor::new(&encoded), length).unwrap();
        assert_eq!(actual_key, key);
        assert!(actual == partition);
        for extent in [0, length - 1, length + 1, u32::MAX] {
            assert!(frame::read_partition(&mut Cursor::new(&encoded), extent).is_err());
        }
        assert!(
            frame::read_partition(&mut Cursor::new(&encoded[..encoded.len() - 1]), length).is_err()
        );
        for offset in [0, 8] {
            let mut changed = encoded.clone();
            changed[offset] ^= 2;
            assert!(
                frame::read_partition(&mut Cursor::new(changed), length).is_err(),
                "changed partition offset {offset}"
            );
        }
        let floor_len = usize::from(u16::from_be_bytes([encoded[72], encoded[73]]));
        let mut changed = encoded.clone();
        if partition.cursor.is_some() {
            // Original cursor layout: bounded 64-byte key, then target epoch.
            // Epoch zero is invalid; a different valid last-deleted binding
            // needs the ledger's range proof, not a new envelope signature.
            changed[76 + floor_len + 65] = 0;
        } else {
            changed[76 + floor_len - 1] ^= 2;
        }
        assert!(frame::read_partition(&mut Cursor::new(changed), length).is_err());
        let mut foreign = *key.as_bytes();
        foreign[0] ^= 2;
        assert!(frame::write_partition(
            &mut Vec::new(),
            ProductionFloorKey::from_bytes(foreign).unwrap(),
            &partition
        )
        .is_err());
        for (start, value) in [(72, 129u16), (74, 257u16)] {
            let mut header = encoded[..76].to_vec();
            header[start..start + 2].copy_from_slice(&value.to_be_bytes());
            let mut input = Cursor::new(header);
            assert!(frame::read_partition(&mut input, frame::MAX_PARTITION as u32).is_err());
            assert_eq!(input.position(), 76);
        }
    }
}
