use super::*;
use crate::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
use std::str::FromStr;

#[tokio::test]
async fn inventory_overflow_stays_invalid_after_owner_cleanup() {
    let observation = Arc::new(BufferObservation::new(|_, _| {}));
    let originals: Vec<_> = (0..=MAX_BUFFER_ROWS).map(|_| vec![1_u8; 17]).collect();
    let saturated = scope(Arc::clone(&observation), 1, async {
        let guards: Vec<_> = originals
            .iter()
            .map(|original| BufferBorrow::new(BufferKind::Ciphertext, original))
            .collect();
        let saturated = observation
            .capture(|snapshot| snapshot.overflowed && snapshot.allocations() == MAX_BUFFER_ROWS);
        drop(guards);
        saturated
    })
    .await;
    drop(originals);
    assert!(saturated);
    observation.capture(|snapshot| {
        assert!(snapshot.overflowed);
        assert_eq!(snapshot.allocations(), 0);
    });
}

#[tokio::test]
async fn typed_metadata_reports_original_spare_capacities_without_copying() {
    let observation = Arc::new(BufferObservation::new(|_, _| {}));
    let mut principal = String::with_capacity(8000);
    principal.push_str("synthetic");
    let mut store_kind = String::with_capacity(16000);
    store_kind.push_str("running");
    let mut key_id = String::with_capacity(32000);
    key_id.push_str("test-key");
    let originals = [
        (
            BufferKind::AadPrincipal,
            AllocationIdentity::of(principal.as_bytes()),
            principal.len(),
            principal.capacity(),
        ),
        (
            BufferKind::AadStoreKind,
            AllocationIdentity::of(store_kind.as_bytes()),
            store_kind.len(),
            store_kind.capacity(),
        ),
        (
            BufferKind::ProviderKeyId,
            AllocationIdentity::of(key_id.as_bytes()),
            key_id.len(),
            key_id.capacity(),
        ),
    ];
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        ConfigAad::new(
            TxId::new(),
            None,
            Timestamp::from_str("2026-09-01T00:00:00Z").unwrap(),
            principal,
            SchemaDigest::from_bytes([0x11; 32]),
            store_kind,
        )
        .unwrap(),
    );
    let handle = KeyHandle::new(
        KeyId::new(key_id).unwrap(),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0x22; 32]),
    );
    let exact = scope(Arc::clone(&observation), 1, async {
        let _aad = borrow_config_aad(&aad);
        let _handle = borrow_key_handle(&handle);
        observation.capture(|snapshot| {
            originals
                .into_iter()
                .all(|(kind, identity, length, capacity)| {
                    snapshot.buffers.iter().flatten().any(|row| {
                        row.kind == kind
                            && row.identity == identity
                            && row.length == length
                            && row.capacity == capacity
                    })
                })
        })
    })
    .await;
    drop(aad);
    drop(handle);
    assert!(
        exact,
        "typed metadata comes from the actual originals, not len-based copies"
    );
    assert_eq!(observation.capture(|snapshot| snapshot.allocations()), 0);
    assert_eq!(
        format!("{:?}", originals[0].1),
        "AllocationIdentity(<redacted>)"
    );
}

#[tokio::test]
async fn physical_union_deduplicates_cross_operation_borrows_and_rejects_conflicts() {
    let observation = Arc::new(BufferObservation::new(|_, _| {}));
    let mut original = Vec::with_capacity(1024);
    original.extend_from_slice(b"same original");
    let identity = AllocationIdentity::of(&original);
    let physical_union = scope(Arc::clone(&observation), 1, async {
        let _first = BufferBorrow::new(BufferKind::Ciphertext, &original);
        scope(Arc::clone(&observation), 2, async {
            let _second = BufferBorrow::new(BufferKind::RecordBlob, &original);
            observation.capture(|snapshot| {
                snapshot.buffers.iter().flatten().count() == 2
                    && snapshot.allocations() == 1
                    && snapshot.data_capacity() == original.capacity()
                    && snapshot
                        .buffers
                        .iter()
                        .flatten()
                        .all(|row| row.identity == identity)
                    && !snapshot.overflowed
            })
        })
        .await
    })
    .await;
    scope(Arc::clone(&observation), 3, async {
        let _original = BufferBorrow::new(BufferKind::Ciphertext, &original);
        // Deliberately inconsistent test-only receipt. It must poison evidence,
        // not create a smaller physical union which could pass a capacity gate.
        let _conflict =
            BufferBorrow::storage(BufferKind::RecordBlob, &original[..1], original.capacity());
    })
    .await;
    drop(original);
    assert!(physical_union);
    observation.capture(|snapshot| {
        assert!(snapshot.overflowed);
        assert_eq!(snapshot.allocations(), 0);
    });
}

#[tokio::test]
async fn final_arc_destruction_waits_for_synchronous_capture() {
    let observation = Arc::new(BufferObservation::new(|_, _| {}));
    let original = scope(Arc::clone(&observation), 1, async {
        ObservedArc::from(vec![3_u8; 4096])
    })
    .await;
    // Move the sole real owner into a dropping thread. Only callback metadata
    // is cloned; no strong or weak payload alias extends its allocation life.
    let dropping_observation = Arc::clone(&observation);
    let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let (thread, held) = observation.capture(|snapshot| {
        let thread = std::thread::spawn(move || {
            let capture_lock_held = dropping_observation.state.try_lock().is_err();
            attempted_tx.send(capture_lock_held).unwrap();
            drop(original);
            finished_tx.send(()).unwrap();
        });
        let capture_lock_held = attempted_rx.recv().unwrap();
        let held =
            snapshot.allocations() == 1 && capture_lock_held && finished_rx.try_recv().is_err();
        (thread, held)
    });
    finished_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    thread.join().unwrap();
    assert!(held);
    assert_eq!(observation.capture(|snapshot| snapshot.allocations()), 0);
}
