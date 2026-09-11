//! Allocation ownership diagnostics. These are single-threaded native model
//! measurements, not RSS or public throughput qualification.

use super::*;
use crate::sqlite::consensus::wal::Operation;
use allocation_counter::{measure, opt_out};
use changes::tests::{command, fixture, request, time};

fn populated(count: u64) -> NativeStorage {
    let (mut storage, _, mut outcome) = fixture();
    for index in 2..=count {
        let next = request(index, Some(&outcome));
        let entry = command(index, &next, time(1), false);
        storage
            .log
            .project(
                &Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]),
                &storage.business,
                None,
            )
            .unwrap();
        storage
            .log
            .project(
                &Operation::Committed(Some(entry.log_id)),
                &storage.business,
                None,
            )
            .unwrap();
        let applied = storage.business.apply(&[entry]).unwrap();
        let Ok(SessionMutationOutcome::FencedTransition(next)) = &applied.responses[0].result
        else {
            panic!("memory fixture successor failed");
        };
        outcome = next.clone();
    }
    storage.validate_image().unwrap();
    storage
}

fn report_owners(label: &str, mut storage: NativeStorage) {
    // Each root is uniquely owned here. Releasing a root counts its actual
    // allocations, including child payloads; shared prefix storage is counted
    // only when its final owner drops, so the disjoint releases add exactly.
    let keys = measure(|| drop(std::mem::take(&mut storage.business.keys)));
    let receipts = measure(|| drop(std::mem::take(&mut storage.business.receipts)));
    let notifications = measure(|| drop(std::mem::take(&mut storage.business.notifications)));
    let generic = measure(|| drop(std::mem::take(&mut storage.business.generic_receipts)));
    let proof = measure(|| drop(storage.business.proof.take()));
    let logs = measure(|| drop(std::mem::take(&mut storage.log.entries)));
    let remaining = measure(|| drop(storage));
    opt_out(|| {
        eprintln!(
            "native_heap_owners representation={label} keys={} receipts={} notifications={} generic={} proof={} logs={} remaining={}",
            -keys.bytes_current, -receipts.bytes_current, -notifications.bytes_current,
            -generic.bytes_current, -proof.bytes_current, -logs.bytes_current,
            -remaining.bytes_current,
        );
        eprintln!(
            "native_heap_owner_allocations representation={label} keys={} receipts={} notifications={} generic={} proof={} logs={} remaining={}",
            -keys.count_current, -receipts.count_current, -notifications.count_current,
            -generic.count_current, -proof.count_current, -logs.count_current,
            -remaining.count_current,
        );
    });
    if label == "selected" {
        // The full retained profile allows 2 GiB for three voters. Receipt
        // rows need headroom for watch history, keys, logs, captures and the
        // runtime. Keep this one owner below 360 bytes per fixture receipt;
        // retaining the duplicate response time exceeds this bound even
        // after selecting the payload and removing the identity allocation.
        assert!(
            -receipts.bytes_current <= 4096 * 360,
            "selected receipt owner retains {} bytes for 4096 rows",
            -receipts.bytes_current,
        );
        assert!(
            -proof.bytes_current <= 4096 * 70,
            "selected proof owner retains {} bytes for 4096 rows",
            -proof.bytes_current,
        );
        // The persistent vector already shares immutable history chunks.
        // Selected notification metadata needs no separate value and body
        // allocations per row; keep the measured owner below 110 bytes/row.
        assert!(
            -notifications.bytes_current <= 4096 * 110,
            "selected notification owner retains {} bytes for 4096 rows",
            -notifications.bytes_current,
        );
    }
}

#[test]
fn native_memory_ownership_profiles_resident_selected_and_captured_rows() {
    const ROWS: u64 = 4096;
    let whole = measure(|| {
        let mut hot = None;
        let resident = measure(|| hot = Some(populated(ROWS)));
        let hot = hot.unwrap();
        let mut capture = None;
        let captured = measure(|| capture = Some(hot.capture_snapshot().unwrap()));
        assert_eq!(
            capture.as_ref().unwrap().storage.business.receipt_count(),
            ROWS as usize
        );
        let shared_release = measure(|| drop(capture.take()));
        assert_eq!(captured.bytes_current, -shared_release.bytes_current);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner-measurement.opc");
        let mut file = std::fs::File::create_new(&path).unwrap();
        let prepared = generation::PreparedBase::prepare(
            &hot,
            crate::consensus::native::generation::BaseParameters {
                binding: [0xD9; 32],
                file_epoch: 1,
                checkpoint_epoch: 1,
                operation_sequence: ROWS,
                cut_binding: [0xD8; 32],
                block_bytes: 64 * 1024,
                maximum: 128 * 1024 * 1024,
            },
            &|| Ok(()),
        )
        .unwrap();
        let identity = prepared.write_to(&mut file, &|| Ok(())).unwrap();
        file.sync_all().unwrap();
        drop(prepared);
        let mut cold = None;
        let mut selected_peak = 0;
        let selected = measure(|| {
            let mut admitted = None;
            let admission = measure(|| {
                admitted = Some(
                    generation::Catalog::open(
                        &path,
                        identity,
                        128 * 1024 * 1024,
                        crate::consensus::native::generation::CatalogScope {
                            identity: hot.business.identity,
                            members: &hot.business.members,
                            roster_root: None,
                        },
                        [0xD8; 32],
                        &|| Ok(()),
                    )
                    .unwrap(),
                );
            });
            let (owner, catalog) = admitted.unwrap();
            let catalog_bound = catalog.resident_index_allocation_bound().unwrap();
            let conversion = measure(|| {
                cold = Some(catalog.into_storage(&|| Ok(())).unwrap());
                drop(owner);
            });
            // allocation-counter sums nested maxima when it merges a child.
            // These phases are sequential: conversion starts with the live
            // admitted catalog, not with its already released scratch peak.
            selected_peak = admission.bytes_max.max(
                u64::try_from(admission.bytes_current)
                    .unwrap()
                    .checked_add(conversion.bytes_max)
                    .unwrap(),
            );
            opt_out(|| {
                eprintln!(
                    "native_catalog_allocation rows={ROWS} admission_live={} admission_peak={} admission_allocations={} catalog_container_bound={} conversion_extra_peak={} conversion_net={} conversion_allocations={}",
                    admission.bytes_current, admission.bytes_max, admission.count_current,
                    catalog_bound, conversion.bytes_max, conversion.bytes_current,
                    conversion.count_total,
                );
            });
        });
        let cold = cold.unwrap();
        assert_eq!(cold.business.receipt_count(), ROWS as usize);
        assert_eq!(cold.business.notifications.len(), ROWS as usize);
        assert_eq!(cold.log.entries.len(), ROWS as usize + 1);
        let full_validation = measure(|| cold.validate_image().unwrap());
        assert_eq!(full_validation.bytes_current, 0);
        assert_eq!(full_validation.count_current, 0);
        opt_out(|| {
            eprintln!(
            "native_heap_profile rows={ROWS} resident_live={} resident_peak={} selected_live={} selected_peak={} capture_live={}",
            resident.bytes_current, resident.bytes_max, selected.bytes_current,
            selected_peak, captured.bytes_current,
        );
            eprintln!(
                "native_full_validation_allocation rows={ROWS} peak={} total={} allocations={}",
                full_validation.bytes_max, full_validation.bytes_total, full_validation.count_total,
            );
        });
        assert!(
            full_validation.bytes_max <= 64 * 1024,
            "full validation duplicated retained receipt storage: {} bytes for {ROWS} rows",
            full_validation.bytes_max,
        );
        report_owners("resident", hot);
        report_owners("selected", cold);
        // This temporary-owner bound leaves headroom above the selected live
        // roots, but catches the prospective catalog and verification scratch
        // peak as well as overlap while constructing the persistent index.
        // It is component evidence; the original three-voter RSS limit stays.
        assert!(
            selected_peak <= 4096 * 1100,
            "selected catalog peak {selected_peak} bytes exceeds the component bound",
        );
    });
    assert_eq!(
        whole.bytes_current, 0,
        "all model and capture owners released"
    );
    assert_eq!(
        whole.count_current, 0,
        "all model and capture owners released"
    );
}
