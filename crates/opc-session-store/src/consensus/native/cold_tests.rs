use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};

use super::super::changes::tests::{apply, clock, command, fixture, time};
use super::super::prefix::{PrefixIdentity, VerifiedAppendOwner};
use super::*;
use sha2::{Digest as _, Sha256};

const BLOCK: usize = 64 * 1024;

struct FileFixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    file: File,
    owner: VerifiedAppendOwner,
    range: ReceiptRange,
}

impl FileFixture {
    fn bytes(bytes: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.native");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        // Deliberately cross a proof-block boundary. The containing blocks,
        // not just the row body, must be verified before decoding the receipt.
        let offset = BLOCK - 17;
        let mut image = vec![0; (offset + bytes.len()).div_ceil(BLOCK) * BLOCK];
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
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
            4 * BLOCK as u64,
            || Ok(()),
            |reader| {
                // This fixture deliberately admits exact bytes without granting
                // row semantics, so malformed-row tests reach the cold decoder.
                let mut actual = Vec::new();
                reader.read_to_end(&mut actual)?;
                if actual != image {
                    return Err(invalid("fixture prefix differs"));
                }
                Ok(())
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            path,
            file,
            owner,
            range: ReceiptRange::new(offset as u64, bytes.len() as u32).unwrap(),
        }
    }

    fn row(state: &NativeState, id: FencedTransitionV2RequestId) -> Self {
        let mut bytes = Vec::new();
        assert_eq!(
            write_receipt(&mut bytes, id, state.receipts.get(&id).unwrap(), &|| Ok(())).unwrap(),
            bytes.len()
        );
        Self::bytes(&bytes)
    }

    fn ticket(&self, state: &NativeState, id: FencedTransitionV2RequestId) -> ReceiptReadTicket {
        ReceiptReadTicket::capture(state, id, self.owner.current(), self.range).unwrap()
    }
}

fn assert_complete(left: &NativeReceipt, right: &NativeReceipt) {
    assert_eq!(
        serde_json::to_vec(left).unwrap(),
        serde_json::to_vec(right).unwrap()
    );
}

#[test]
fn native_cold_receipt_selected_metadata_preserves_exact_response_time_at_range_boundaries() {
    use crate::fenced_transition::{
        FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS,
        FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS,
    };
    let (storage, request, _) = fixture();
    let id = request.request_id();
    for seconds in [
        FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS,
        -1,
        0,
        1,
        FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS
            - i64::try_from(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs()).unwrap(),
    ] {
        for nanos in [0, 1, 999_999_999] {
            let now = Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(seconds)
                    .unwrap()
                    .replace_nanosecond(nanos)
                    .unwrap(),
            );
            let mut row = (**storage.business.receipts.get(&id).unwrap()).clone();
            row.retained_until = retention_deadline(now).unwrap();
            let response = Arc::make_mut(row.response.as_mut().unwrap());
            response.result = Err(StoreError::CasConflict);
            response.logical_time = Some(now);
            let mut frontiers = storage.business.frontiers.clone();
            frontiers.logical_time = Some(now);
            let mut bytes = Vec::new();
            write_receipt(&mut bytes, id, &row, &|| Ok(())).unwrap();
            // The existing complete independent decoder and receipt
            // predicates admit the original wire response before selection.
            let facts = inspect_generation_bytes(
                &bytes,
                id,
                storage.business.identity,
                &frontiers,
                &|| Ok(()),
            )
            .unwrap();
            let file = FileFixture::bytes(&bytes);
            let selected = NativeReceipt::from_admitted_range(
                id,
                facts,
                file.owner.current(),
                file.range.offset,
                file.range.length,
            )
            .unwrap();
            let actual = selected.response_facts().unwrap().unwrap();
            let expected = facts.facts.response.unwrap();
            assert_eq!(actual.logical_time, now);
            assert_eq!(actual.sequence, expected.sequence);
            assert_eq!(actual.raft_index, expected.raft_index);
            let mut readback = vec![0; bytes.len()];
            let (source, range) = selected.cold_range().unwrap();
            source.read_exact_at(range.offset, &mut readback).unwrap();
            assert_eq!(readback, bytes);
            let (decoded_id, decoded) = decode(&readback).unwrap();
            assert_eq!(decoded_id, id);
            assert!(selected.matches_decoded(id, &decoded).unwrap());
            assert_complete(&decoded, &row);
            validation::validate_receipt(
                storage.business.identity,
                &id,
                &selected,
                &frontiers,
                frontiers.history.unwrap(),
            )
            .unwrap();

            // Alter only the alleged original response time by one
            // nanosecond. Selection cannot infer away a mismatch with the
            // exact retained-until timestamp admitted from the full row.
            let mut changed = facts;
            changed.facts.response.as_mut().unwrap().logical_time = Timestamp::from_offset_datetime(
                now.as_offset_datetime()
                    .checked_add(time::Duration::nanoseconds(1))
                    .unwrap(),
            );
            assert!(NativeReceipt::from_admitted_range(
                id,
                changed,
                file.owner.current(),
                file.range.offset,
                file.range.length,
            )
            .is_err());
        }
    }
}

#[test]
fn native_cold_receipt_round_trip_and_expiry_keep_full_id_tombstone_and_response() {
    let (mut state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let value = file
        .ticket(&state.business, id)
        .resolve(&|| Ok(()))
        .unwrap();
    assert_complete(
        &value.copy_current(&state.business).unwrap(),
        state.business.receipts.get(&id).unwrap(),
    );
    let expiry = state.business.receipts.get(&id).unwrap().retained_until;
    apply(
        &mut state,
        &[command(2, &request, expiry, false), clock(3, expiry)],
    );
    assert!(state.business.receipts.get(&id).unwrap().response.is_none());
    assert_eq!(
        state.business.receipts.len(),
        1,
        "expiry retains the exact request binding"
    );
    assert!(value.copy_current(&state.business).is_err());
    let expired = FileFixture::row(&state.business, id);
    assert_eq!(
        expired.range.length as usize, HEADER_BYTES,
        "explicit absent-response tombstone"
    );
    let row = expired
        .ticket(&state.business, id)
        .resolve(&|| Ok(()))
        .unwrap()
        .copy_current(&state.business)
        .unwrap();
    assert_complete(&row, state.business.receipts.get(&id).unwrap());
    assert!(row.response.is_none());
    state.validate_image().unwrap();
}

#[test]
fn native_cold_receipt_complete_capture_comparison_rejects_every_changed_field() {
    let (state, request, _) = fixture();
    let id = request.request_id();
    let original = &**state.business.receipts.get(&id).unwrap();
    for case in 0..10 {
        let mut row = original.clone();
        let mut encoded_id = id;
        match case {
            0 => row.ordinal += 1,
            1 => row.payload_digest[31] ^= 1,
            2 => row.retained_until = row.retained_until.add_seconds(1).unwrap(),
            3 => row.response = None,
            4 => Arc::make_mut(row.response.as_mut().unwrap()).sequence += 1,
            5 => {
                Arc::make_mut(row.response.as_mut().unwrap()).digest =
                    Some(SessionConsensusEntryDigest::from_bytes([9; 32]))
            }
            6 => Arc::make_mut(row.response.as_mut().unwrap()).raft_log_index += 1,
            7 => Arc::make_mut(row.response.as_mut().unwrap()).result = Err(StoreError::LeaseHeld),
            8 => {
                let mut commitment = *id.body_commitment();
                commitment[31] ^= 1;
                encoded_id =
                    FencedTransitionV2RequestId::from_parts(id.epoch(), id.nonce(), commitment);
                assert_eq!(&encoded_id.to_bytes()[..24], &id.to_bytes()[..24]);
            }
            9 => {
                Arc::make_mut(row.response.as_mut().unwrap()).logical_time = original
                    .response
                    .as_ref()
                    .unwrap()
                    .logical_time
                    .map(|time| time.add_seconds(1).unwrap())
            }
            _ => unreachable!(),
        }
        let mut bytes = Vec::new();
        write_receipt(&mut bytes, encoded_id, &row, &|| Ok(())).unwrap();
        let file = FileFixture::bytes(&bytes);
        assert!(
            file.ticket(&state.business, id)
                .resolve(&|| Ok(()))
                .is_err(),
            "changed field {case}"
        );
    }
    state.validate_image().unwrap();
}

#[test]
fn native_cold_receipt_malformed_fields_and_exact_extents_reject_before_use() {
    let (state, request, _) = fixture();
    let id = request.request_id();
    let mut original = Vec::new();
    write_receipt(
        &mut original,
        id,
        state.business.receipts.get(&id).unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    for case in 0..9 {
        let mut bytes = original.clone();
        match case {
            0 => bytes[0] ^= 1,
            1 => bytes[8..16].fill(0),
            2 => bytes[112..116].copy_from_slice(&1_000_000_000u32.to_le_bytes()),
            3 => bytes[116..120].copy_from_slice(&u32::MAX.to_le_bytes()),
            4 => {
                bytes.pop();
            }
            5 => bytes.push(0),
            6 => bytes[HEADER_BYTES] ^= 1,
            7 => bytes[116..120].fill(0),
            8 => {
                bytes[104..112].copy_from_slice(&i64::MAX.to_le_bytes());
            }
            _ => unreachable!(),
        }
        let file = FileFixture::bytes(&bytes);
        assert!(
            file.ticket(&state.business, id)
                .resolve(&|| Ok(()))
                .is_err(),
            "malformed field {case}"
        );
    }
    assert!(ReceiptRange::new(u64::MAX, HEADER_BYTES as u32).is_err());
    assert!(ReceiptRange::new(0, (HEADER_BYTES - 1) as u32).is_err());
    assert!(ReceiptRange::new(0, (MAX_BYTES + 1) as u32).is_err());
    let file = FileFixture::bytes(&original);
    let beyond = ReceiptRange::new(
        file.owner.current().identity().length,
        original.len() as u32,
    )
    .unwrap();
    assert!(ReceiptReadTicket::capture(&state.business, id, file.owner.current(), beyond).is_err());
}

#[test]
fn native_cold_receipt_delayed_worker_releases_owner_and_rejects_changed_business_version() {
    let (state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let owner = Arc::new(Mutex::new(state));
    let ticket = {
        let state = owner.lock().unwrap();
        file.ticket(&state.business, id)
    };
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let first = Cell::new(true);
        ticket.resolve(&|| {
            if first.replace(false) {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
            }
            Ok(())
        })
    });
    entered_rx.recv().unwrap();
    {
        let mut state = owner.try_lock().expect("no disk/decoder wait owns State");
        apply(&mut state, &[clock(2, time(2))]);
    }
    resume_tx.send(()).unwrap();
    let resolved = worker.join().unwrap().unwrap();
    let state = owner.lock().unwrap();
    assert_complete(&resolved.row, state.business.receipts.get(&id).unwrap());
    assert!(
        resolved.copy_current(&state.business).is_err(),
        "equal row bytes do not authorize an old business context"
    );
    state.validate_image().unwrap();
}

#[test]
fn native_cold_receipt_equal_value_new_row_and_dropped_owner_cannot_supply_currentness() {
    let (mut state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let ticket = file.ticket(&state.business, id);
    let original = state.business.receipts.get(&id).unwrap().clone();
    state
        .business
        .receipts
        .insert(id, SharedRow::new((*original).clone()).unwrap());
    // Deliberately keep the old summary to exercise the independent exact
    // row check, even before full re-admission issues a new business proof.
    let loaded = ticket.resolve(&|| Ok(())).unwrap();
    assert!(loaded.copy_current(&state.business).is_err());
    state.business.admit_business().unwrap();
    let detached = file.ticket(&state.business, id);
    drop(state);
    drop(file.owner);
    let retained = detached.resolve(&|| Ok(())).unwrap();
    assert_complete(&retained.row, &original);
    // A byte/semantic read can complete after owner destruction; no public
    // result/current authority is produced without a live owner comparison.
    assert_eq!(retained.ticket.source.identity().checkpoint_epoch, 11);
}

#[test]
fn native_cold_receipt_budget_precancel_and_decoded_lifetime_cover_all_exits() {
    let (state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let counter: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let reserve = |bytes| VerificationMemory::reserve_for_test(counter, bytes, READ_BYTES);
    let loaded = file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), reserve)
        .unwrap();
    assert_eq!(
        counter.load(Ordering::Acquire),
        READ_BYTES,
        "decoded value retains the reservation"
    );
    assert!(file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), reserve)
        .is_err());
    fn consumer_failure(_output: NativeReceipt) -> io::Result<()> {
        Err(invalid("consumer failure"))
    }
    assert!(consumer_failure(loaded.copy_current(&state.business).unwrap()).is_err());
    assert_eq!(counter.load(Ordering::Acquire), READ_BYTES);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _owned = loaded;
        panic!("consumer unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(counter.load(Ordering::Acquire), 0);
    for step in 0..3 {
        let calls = Cell::new(0);
        assert!(file
            .ticket(&state.business, id)
            .resolve_with(
                &|| {
                    let current = calls.get();
                    calls.set(current + 1);
                    if current == step {
                        Err(invalid("cancelled"))
                    } else {
                        Ok(())
                    }
                },
                reserve
            )
            .is_err());
        assert_eq!(counter.load(Ordering::Acquire), 0, "cancel step {step}");
    }
    for step in 0..3 {
        let calls = Cell::new(0);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = file.ticket(&state.business, id).resolve_with(
                &|| {
                    let current = calls.get();
                    calls.set(current + 1);
                    assert_ne!(current, step, "decoder boundary panic");
                    Ok(())
                },
                reserve,
            );
        }));
        assert!(unwind.is_err());
        assert_eq!(counter.load(Ordering::Acquire), 0, "panic step {step}");
    }
    let source = file.owner.current();
    file.file.set_len(0).unwrap();
    assert!(file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), |_| Err(invalid("budget denied")))
        .is_err());
    assert!(!source.is_failed(), "denial preceded file I/O");
    assert!(file
        .ticket(&state.business, id)
        .resolve_with(&|| Err(invalid("pre-cancel")), reserve)
        .is_err());
    assert!(!source.is_failed(), "pre-cancel preceded file I/O");
    assert!(file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), reserve)
        .is_err());
    assert!(source.is_failed(), "the actual read sees truncation");
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

#[test]
fn native_cold_receipt_output_clones_and_thread_transfer_own_independent_backing() {
    fn outcome(response: &SessionConsensusResponse) -> &FencedTransitionOutcome {
        match &response.result {
            Ok(SessionMutationOutcome::FencedTransition(value)) => value,
            _ => panic!("expected fixture success"),
        }
    }
    let (state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let counter: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let reserve = |bytes| VerificationMemory::reserve_for_test(counter, bytes, READ_BYTES);
    let loaded = file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), reserve)
        .unwrap();
    let output = loaded.copy_current(&state.business).unwrap();
    assert_complete(&output, &loaded.row);
    let decoded = outcome(loaded.row.response.as_ref().unwrap());
    let copied = outcome(output.response.as_ref().unwrap());
    assert_ne!(
        decoded.lease().key().stable_id.as_bytes().as_ptr(),
        copied.lease().key().stable_id.as_bytes().as_ptr(),
        "both live allocations must be independent"
    );
    let response_clone = output.response.as_ref().unwrap().clone();
    let outcome_clone = copied.clone();
    assert_eq!(
        outcome(&response_clone)
            .lease()
            .key()
            .stable_id
            .as_bytes()
            .as_ptr(),
        outcome_clone.lease().key().stable_id.as_bytes().as_ptr(),
        "exercise real shared Bytes clones of the public output"
    );
    let expected_response = serde_json::to_vec(output.response.as_ref().unwrap()).unwrap();
    let expected_outcome = serde_json::to_vec(copied).unwrap();
    let (resume_tx, resume_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        resume_rx.recv().unwrap();
        assert_eq!(
            serde_json::to_vec(&response_clone).unwrap(),
            expected_response
        );
        assert_eq!(
            serde_json::to_vec(&outcome_clone).unwrap(),
            expected_outcome
        );
        (response_clone, outcome_clone)
    });
    drop(output);
    assert_eq!(counter.load(Ordering::Acquire), READ_BYTES);
    drop(loaded);
    assert_eq!(
        counter.load(Ordering::Acquire),
        0,
        "all decoder allocations are gone while output clones survive"
    );
    // The full read reservation can be reused while those independent output
    // owners remain alive on the other thread.
    let next = file
        .ticket(&state.business, id)
        .resolve_with(&|| Ok(()), reserve)
        .unwrap();
    assert_eq!(counter.load(Ordering::Acquire), READ_BYTES);
    resume_tx.send(()).unwrap();
    let (response, outcome_copy) = worker.join().unwrap();
    assert_eq!(
        response,
        state
            .business
            .receipts
            .get(&id)
            .unwrap()
            .response
            .as_ref()
            .unwrap()
            .clone()
    );
    assert!(outcome_copy.matches_v2_request(&request));
    drop(next);
    assert_eq!(counter.load(Ordering::Acquire), 0);
    assert!(outcome(&response).matches_v2_request(&request));
}

#[test]
fn native_cold_receipt_pinned_descriptor_and_modified_block_never_change_returned_row() {
    let (state, request, _) = fixture();
    let id = request.request_id();
    let file = FileFixture::row(&state.business, id);
    let saved = file.path.with_extension("retained");
    std::fs::rename(&file.path, &saved).unwrap();
    std::fs::write(&file.path, vec![0xff; 2 * BLOCK]).unwrap();
    let old = file
        .ticket(&state.business, id)
        .resolve(&|| Ok(()))
        .unwrap();
    assert_complete(&old.row, state.business.receipts.get(&id).unwrap());
    file.file
        .write_all_at(&[0xff], file.range.offset + HEADER_BYTES as u64)
        .unwrap();
    file.file.sync_all().unwrap();
    assert!(file
        .ticket(&state.business, id)
        .resolve(&|| Ok(()))
        .is_err());
    assert_complete(&old.row, state.business.receipts.get(&id).unwrap());
}
