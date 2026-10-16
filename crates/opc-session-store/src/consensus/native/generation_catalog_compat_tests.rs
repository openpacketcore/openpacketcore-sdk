use super::*;

fn admit_exact(bytes: &[u8], identity: PrefixIdentity, storage: &NativeStorage, cut: [u8; 32]) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("compat.opc");
    std::fs::write(&path, bytes).unwrap();
    let (_, catalog) = Catalog::open(
        &path,
        identity,
        MAXIMUM,
        CatalogScope {
            identity: storage.business.identity,
            members: &storage.business.members,
            roster_root: storage.business.roster_root.clone(),
        },
        cut,
        &|| Ok(()),
    )
    .unwrap();
    exact(&catalog, storage);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn native_catalog_rowless_unchanged_context_accepts_the_same_operation_sequence() {
    let (mut storage, _, _) = fixture();
    let (mut files, _) = Files::new(&storage);
    let before = files.owner.current().identity();
    assert!(before.checkpoint_epoch > before.file_epoch + 1);
    storage.begin_changes().unwrap();
    let prepared = files.prepare(&mut storage, before.operation_sequence);
    assert!(prepared.header.before == prepared.header.after);
    assert_eq!(prepared.header.changed, [0; 5]);
    assert_eq!(prepared.header.roster_changed, Some([0; 2]));
    prepared.append(&mut files.owner, &|| Ok(())).unwrap();
    let after = files.owner.current().identity();
    assert_eq!(after.operation_sequence, before.operation_sequence);
    assert_eq!(after.checkpoint_epoch, before.checkpoint_epoch + 1);
    assert_eq!(after.file_epoch, before.file_epoch);
    assert_eq!(after.frontiers, before.frontiers);
    admit_exact(&files.bytes(), after, &storage, prepared.header.cut_binding);
}

#[test]
fn native_catalog_compares_only_the_final_cut_binding() {
    let (mut storage, _, _) = fixture();
    let (files, _) = Files::new(&storage);
    let original = files.owner.current().identity();
    storage.begin_changes().unwrap();
    let prepared = files.prepare(&mut storage, original.operation_sequence);
    let mut payload = Vec::new();
    prepared.write_payload(&mut payload, &|| Ok(())).unwrap();

    // Rebuild a valid physical chain with historical bindings that are not
    // the binding of this file's final selector. Only the final one is current.
    let mut base = Wire::<BaseHeader>::read(&files.bytes());
    base.header.cut_binding = [0xA1; 32];
    let base_bytes = base.encode(base::MAGIC, Vec::new());
    let base_identity = rebound(&base_bytes, original, &base.header.context);
    let mut middle = Wire::<Header>::read(&payload);
    middle.header.previous = base_identity.into();
    middle.header.cut_binding = [0xA2; 32];
    let middle_bytes = middle.encode(MAGIC, base_bytes);
    let middle_identity = rebound(
        &middle_bytes,
        PrefixIdentity {
            checkpoint_epoch: original.checkpoint_epoch + 1,
            ..original
        },
        &middle.header.after,
    );
    let mut final_frame = Wire::<Header>::read(&payload);
    final_frame.header.previous = middle_identity.into();
    final_frame.header.checkpoint_epoch = middle_identity.checkpoint_epoch + 1;
    final_frame.header.cut_binding = [0xA3; 32];
    let bytes = final_frame.encode(MAGIC, middle_bytes.clone());
    let final_identity = rebound(
        &bytes,
        PrefixIdentity {
            checkpoint_epoch: middle_identity.checkpoint_epoch + 1,
            ..middle_identity
        },
        &final_frame.header.after,
    );
    admit_exact(&bytes, final_identity, &storage, [0xA3; 32]);
    for historical in [[0xA1; 32], [0xA2; 32]] {
        assert_eq!(
            reject(&bytes, final_identity, &storage, historical),
            "native generation selected final extent or cut differs"
        );
    }
    final_frame.header.cut_binding[0] ^= 1;
    let forged = final_frame.encode(MAGIC, middle_bytes);
    assert_eq!(
        reject(
            &forged,
            rebound(&forged, final_identity, &final_frame.header.after),
            &storage,
            [0xA3; 32]
        ),
        "native generation selected final extent or cut differs"
    );
}
