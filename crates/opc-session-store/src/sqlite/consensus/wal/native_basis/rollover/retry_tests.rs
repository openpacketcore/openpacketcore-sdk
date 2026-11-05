//! Real I/O adapters must preserve typed cancellation without retrying it.

use super::*;
use crate::consensus::native::prefix::{AppendTransaction, CompareWriter, Created};
use std::cell::Cell;
use std::io::Write;

fn identity() -> PrefixIdentity {
    PrefixIdentity {
        binding: [1; 32],
        file_epoch: 2,
        checkpoint_epoch: 3,
        operation_sequence: 4,
        frontiers: [2; 32],
        length: 65536,
        block_bytes: 65536,
        digest: [3; 32],
    }
}

fn cancellation_once(signal: &Coordinator, calls: &Cell<usize>) -> io::Result<()> {
    calls.set(calls.get() + 1);
    if calls.get() == 1 {
        signal.cancel();
        Err(cancelled())
    } else {
        // Finite RED escape: the old Interrupted retry is observed by the
        // second call instead of leaving the test harness spinning forever.
        Err(io::Error::other(
            "cancellation was retried inside an I/O adapter",
        ))
    }
}

#[test]
fn native_rollover_cancellation_inside_base_block_write_is_not_retried() {
    let mut failures = Vec::new();
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let file = tempfile::NamedTempFile::new().unwrap();
        let signal = Coordinator::new();
        let calls = Cell::new(0);
        let result = Created::encode(
            file.reopen().unwrap(),
            identity(),
            maximum(mode, 65536).unwrap(),
            &|| cancellation_once(&signal, &calls),
            |writer| writer.write_all(&vec![0x51; 2 * 65536]),
        );
        let error = result.err().expect("cancelled base write must fail");
        if !is_cancelled(&error) || calls.get() != 1 {
            failures.push(format!("{mode:?}: calls={}, error={error}", calls.get()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn native_rollover_cancellation_inside_extent_compare_is_not_retried() {
    let mut failures = Vec::new();
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        for exact_read in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("candidate.preparing");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let created = Created::encode(
                file,
                identity(),
                maximum(mode, 65536).unwrap(),
                &|| Ok(()),
                |writer| writer.write_all(&vec![0x51; 65536]),
            )
            .unwrap();
            created.file().sync_all().unwrap();
            let mut owner = created.admit(&path, &|| Ok(())).unwrap();
            let signal = Coordinator::new();
            let calls = Cell::new(0);
            let comparing = Cell::new(false);
            let before = owner.current();
            let result = owner.append(
                &before,
                AppendTransaction {
                    checkpoint_epoch: 4,
                    operation_sequence: 4,
                    frontiers: [4; 32],
                    payload_bytes: 65536,
                },
                || {
                    if comparing.get() {
                        cancellation_once(&signal, &calls)
                    } else {
                        Ok(())
                    }
                },
                |writer| writer.write_all(&vec![0x52; 65536]),
                |reader| {
                    comparing.set(true);
                    if exact_read {
                        reader.read_exact(&mut vec![0; 65536])
                    } else {
                        CompareWriter::new(reader).write_all(&vec![0x52; 65536])
                    }
                },
            );
            let error = result.err().expect("cancelled comparison must fail");
            if !is_cancelled(&error) || calls.get() != 1 {
                failures.push(format!(
                    "{mode:?}, exact={exact_read}: calls={}, error={error}",
                    calls.get()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}
