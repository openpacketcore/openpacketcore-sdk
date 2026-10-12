use super::*;

#[test]
fn native_preflight_rejects_wrong_base_identity() {
    let (storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    preflight(&files.bytes(), catalog.identity(), CUT).unwrap();
    let mut expected = catalog.identity();
    expected.binding[0] ^= 1;
    assert_eq!(
        preflight(&files.bytes(), expected, CUT)
            .unwrap_err()
            .to_string(),
        "native generation base differs from selected identity"
    );
}

#[test]
fn native_preflight_rejects_wrong_final_cut() {
    let (storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    preflight(&files.bytes(), catalog.identity(), CUT).unwrap();
    let mut cut = CUT;
    cut[0] ^= 1;
    assert_eq!(
        preflight(&files.bytes(), catalog.identity(), cut)
            .unwrap_err()
            .to_string(),
        "native generation selected final extent or cut differs"
    );
}

#[test]
fn native_preflight_rejects_wrong_delta_predecessor() {
    let (mut storage, _, _) = fixture();
    let (files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let prepared = files.prepare(&mut storage, 19);
    let mut delta = Vec::new();
    prepared.write_payload(&mut delta, &|| Ok(())).unwrap();
    let mut wire = Wire::<Header>::read(&delta);
    let identity = PrefixIdentity {
        checkpoint_epoch: wire.header.checkpoint_epoch,
        operation_sequence: wire.header.operation_sequence,
        ..files.owner.current().identity()
    };
    let positive = wire.encode(MAGIC, files.bytes());
    preflight(
        &positive,
        rebound(&positive, identity, &wire.header.after),
        wire.header.cut_binding,
    )
    .unwrap();
    wire.header.previous.operation_sequence ^= 1;
    let forged = wire.encode(MAGIC, files.bytes());
    assert_eq!(
        preflight(
            &forged,
            rebound(&forged, identity, &wire.header.after),
            wire.header.cut_binding
        )
        .unwrap_err()
        .to_string(),
        "native generation checkpoint predecessor differs"
    );
}

#[test]
fn native_preflight_rejects_oversize_count() {
    let (storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    preflight(&files.bytes(), catalog.identity(), CUT).unwrap();
    let mut wire = Wire::<BaseHeader>::read(&files.bytes());
    wire.header.context.log.count = validation::MAX_ITEMS + 1;
    let forged = wire.encode(base::MAGIC, Vec::new());
    assert_eq!(
        preflight(
            &forged,
            rebound(&forged, catalog.identity(), &wire.header.context),
            CUT
        )
        .unwrap_err()
        .to_string(),
        "native generation changed count exceeds original bound"
    );
}

#[test]
fn native_preflight_rejects_oversize_row_extent() {
    let (storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    preflight(&files.bytes(), catalog.identity(), CUT).unwrap();
    let mut wire = Wire::<BaseHeader>::read(&files.bytes());
    assert_eq!(
        &wire.body[..2],
        &[0, 0],
        "base begins with a key frame and no predecessor"
    );
    wire.body[2..6].copy_from_slice(&u32::try_from(MAX_ITEM + 1).unwrap().to_le_bytes());
    let forged = wire.encode(base::MAGIC, Vec::new());
    assert_eq!(
        preflight(
            &forged,
            rebound(&forged, catalog.identity(), &wire.header.context),
            CUT
        )
        .unwrap_err()
        .to_string(),
        "native generation input extent exceeds bound"
    );
}

#[test]
fn native_generation_magic_separates_vocabulary_from_voter_profile() {
    for (base_frame, fixed, slots) in [
        (true, base::MAGIC, base::SLOT_MAGIC),
        (false, MAGIC, SLOT_MAGIC),
    ] {
        assert_eq!(&fixed[..7], &slots[..7]);
        assert_eq!((fixed[6], fixed[7], slots[7]), (6, 0, 1));
        let fixed_format = Format::read(&mut &fixed[..], base_frame).unwrap();
        let slot_format = Format::read(&mut &slots[..], base_frame).unwrap();
        assert!(!fixed_format.has_voter_slots());
        assert!(slot_format.has_voter_slots());
        // Profiles are checked against their contexts, never ranked. A future
        // level may follow either profile; no pair of release markers is needed.
        for previous in [fixed_format, slot_format] {
            for profile in [VoterProfile::Fixed, VoterProfile::Slots] {
                previous
                    .validate_successor(Format {
                        vocabulary: 6,
                        profile,
                    })
                    .unwrap();
                previous
                    .validate_successor(Format {
                        vocabulary: 7,
                        profile,
                    })
                    .unwrap();
                assert_eq!(
                    previous
                        .validate_successor(Format {
                            vocabulary: 5,
                            profile
                        })
                        .unwrap_err()
                        .to_string(),
                    "native generation delta format regressed"
                );
            }
        }
        for original in [fixed, slots] {
            let mut future = *original;
            future[6] = 7;
            assert_eq!(
                Format::read(&mut &future[..], base_frame)
                    .err()
                    .unwrap()
                    .to_string(),
                "native generation discriminator differs"
            );
        }
        let mut unknown_profile = *fixed;
        unknown_profile[7] = 2;
        assert_eq!(
            Format::read(&mut &unknown_profile[..], base_frame)
                .err()
                .unwrap()
                .to_string(),
            "native generation voter profile differs"
        );
    }
}

fn preflight(bytes: &[u8], identity: PrefixIdentity, cut: [u8; 32]) -> io::Result<()> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("selected.native");
    std::fs::write(&path, bytes).unwrap();
    let result = preflight_format(&path, identity, MAXIMUM, cut, &|| Ok(()));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    result.map(|_| ())
}

#[test]
fn native_format_preflight_refuses_old_and_unknown_base_discriminators_without_writes() {
    let (storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    preflight(&original, catalog.identity(), CUT).unwrap();
    for magic in [
        base::LEGACY_MAGIC,
        base::V3_MAGIC,
        base::V4_MAGIC,
        base::V5_MAGIC,
        b"OPCNJB\x07\x00",
        b"OPCNAT01",
        b"OPCNAT02",
    ] {
        let mut bytes = original.clone();
        bytes[..8].copy_from_slice(magic);
        assert_eq!(
            preflight(
                &bytes,
                rebound(&bytes, catalog.identity(), &catalog.rows.context),
                CUT
            )
            .unwrap_err()
            .to_string(),
            "native generation discriminator differs"
        );
    }
    // The explicit historical reader remains testable, but its result cannot
    // satisfy a current native root's vocabulary boundary.
    let mut legacy = original.clone();
    legacy[..8].copy_from_slice(base::V4_MAGIC);
    let path = files._directory.path().join("historical.native");
    std::fs::write(&path, &legacy).unwrap();
    let (_, legacy) = Catalog::open(
        &path,
        rebound(&legacy, catalog.identity(), &catalog.rows.context),
        MAXIMUM,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: None,
        },
        CUT,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(
        legacy.require_reclamation_format().unwrap_err().to_string(),
        "native generation discriminator differs"
    );
    catalog.require_reclamation_format().unwrap();
}

#[test]
fn native_format_preflight_reads_delta_discriminators_and_preserves_format_order() {
    let (mut storage, _, _) = fixture();
    let (files, _) = Files::new(&storage);
    storage.begin_changes().unwrap();
    let prepared = files.prepare(&mut storage, 19);
    let mut delta = Vec::new();
    prepared.write_payload(&mut delta, &|| Ok(())).unwrap();
    let wire = Wire::<Header>::read(&delta);
    let identity = PrefixIdentity {
        checkpoint_epoch: wire.header.checkpoint_epoch,
        operation_sequence: wire.header.operation_sequence,
        ..files.owner.current().identity()
    };
    let positive = wire.encode(MAGIC, files.bytes());
    preflight(
        &positive,
        rebound(&positive, identity, &wire.header.after),
        wire.header.cut_binding,
    )
    .unwrap();
    for (magic, message) in [
        (b"OPCNJD\x07\x00", "native generation discriminator differs"),
        (V4_MAGIC, "native generation delta format regressed"),
    ] {
        let bytes = wire.encode(magic, files.bytes());
        assert_eq!(
            preflight(
                &bytes,
                rebound(&bytes, identity, &wire.header.after),
                wire.header.cut_binding
            )
            .unwrap_err()
            .to_string(),
            message
        );
    }
}

#[test]
fn native_format_preflight_refuses_unknown_context_fields_in_base_and_delta() {
    let (mut storage, _, _) = fixture();
    let (files, catalog) = Files::new(&storage);
    let original = files.bytes();
    let base = Wire::<BaseHeader>::read(&original);
    let mut header = serde_json::to_value(&base.header).unwrap();
    header["context"]["business"]["frontiers"]["future_retirement_frontier"] = serde_json::json!(1);
    let mut bytes = base::MAGIC.to_vec();
    write_bytes(
        &mut bytes,
        &serde_json::to_vec(&header).unwrap(),
        MAX_HEADER,
    )
    .unwrap();
    bytes.extend_from_slice(&base.body);
    bytes.resize(bytes.len().div_ceil(BLOCK) * BLOCK, 0);
    assert_eq!(
        preflight(
            &bytes,
            rebound(&bytes, catalog.identity(), &base.header.context),
            CUT
        )
        .unwrap_err()
        .to_string(),
        "native generation cold header invalid"
    );
    preflight(&original, catalog.identity(), CUT).unwrap();

    storage.begin_changes().unwrap();
    let prepared = files.prepare(&mut storage, 19);
    let mut delta = Vec::new();
    prepared.write_payload(&mut delta, &|| Ok(())).unwrap();
    let wire = Wire::<Header>::read(&delta);
    let identity = PrefixIdentity {
        checkpoint_epoch: wire.header.checkpoint_epoch,
        operation_sequence: wire.header.operation_sequence,
        ..catalog.identity()
    };
    let positive = wire.encode(MAGIC, original.clone());
    preflight(
        &positive,
        rebound(&positive, identity, &wire.header.after),
        wire.header.cut_binding,
    )
    .unwrap();
    for context in ["before", "after"] {
        let mut header = serde_json::to_value(&wire.header).unwrap();
        header[context]["business"]["frontiers"]["future_retirement_frontier"] =
            serde_json::json!(1);
        let mut bytes = original.clone();
        bytes.extend_from_slice(MAGIC);
        write_bytes(
            &mut bytes,
            &serde_json::to_vec(&header).unwrap(),
            MAX_HEADER,
        )
        .unwrap();
        bytes.extend_from_slice(&wire.body);
        bytes.resize(bytes.len().div_ceil(BLOCK) * BLOCK, 0);
        assert_eq!(
            preflight(
                &bytes,
                rebound(&bytes, identity, &wire.header.after),
                wire.header.cut_binding
            )
            .unwrap_err()
            .to_string(),
            "native generation cold header invalid"
        );
    }
}
