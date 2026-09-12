//! Bounded full hashing of already decoded and validated ordinary Unit,
//! Lease and successful CAS receipts. SQL queries, their original response
//! decoder, cancellation and ordered output stay on the caller. Workers only
//! borrow its receipts; decoded owners are allocated and freed on the caller.

use super::*;

const ROWS: usize = 64;
const BYTES: usize = 4 * 1024 * 1024;
const PARALLEL_MIN: usize = 16;
const WORKERS: usize = 8;
const STACK: usize = 2 * 1024 * 1024;

struct Resources<'a> {
    reserve: &'a dyn Fn(usize) -> io::Result<VerificationMemory>,
    available: usize,
}

struct Staged {
    id: SessionConsensusRequestId,
    receipt: NativeGenericReceipt,
    content: Option<io::Result<[u8; 32]>>,
    // The caller drops the complete receipt before refunding its original
    // row charge, including a Lease guard's key and owner. Only the closed
    // result family below, with borrowing serializers, can be staged.
    _memory: VerificationMemory,
}

fn hash_chunk(rows: &mut [Staged]) {
    for row in rows {
        row.content = Some(row.receipt.row_fingerprint(2, &row.id));
    }
}

fn hash_batch(rows: &mut [Staged], resources: &Resources<'_>) -> io::Result<()> {
    let workers = WORKERS.min(resources.available.max(1)).min(rows.len());
    if rows.len() < PARALLEL_MIN || workers <= 1 {
        hash_chunk(rows);
        return Ok(());
    }
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(workers)
            .map_err(|_| invalid("native SQL ordinary worker allocation failed"))?;
        let mut failure = None;
        let chunk_size = rows.len().div_ceil(workers);
        for (worker, chunk) in rows.chunks_mut(chunk_size).enumerate() {
            let memory = match (resources.reserve)(STACK) {
                Ok(memory) => memory,
                Err(_) => {
                    hash_chunk(chunk);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                failure = Some(invalid("native SQL ordinary worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native SQL ordinary worker failure");
                    }
                    hash_chunk(chunk);
                }) {
                Ok(handle) => {
                    handles.push((handle, memory));
                    #[cfg(test)]
                    OBSERVED.with(|value| value.borrow_mut().started += 1);
                }
                Err(error) => {
                    failure = Some(io::Error::other(error));
                    break;
                }
            }
        }
        for (handle, memory) in handles {
            if handle.join().is_err() && failure.is_none() {
                failure = Some(invalid("native SQL ordinary worker failed"));
            }
            #[cfg(test)]
            OBSERVED.with(|value| value.borrow_mut().joined += 1);
            drop(memory);
        }
        failure.map_or(Ok(()), Err)
    })
}

fn emit(
    id: SessionConsensusRequestId,
    receipt: &NativeGenericReceipt,
    content: [u8; 32],
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
) -> io::Result<()> {
    account(
        &mut context.business.counts[2],
        &mut context.business.content[2],
        content,
        validation::MAX_ITEMS,
    )?;
    writer.write_all(&[2])?;
    write_before(writer, None)?;
    binary.write(writer, &(id, Some(receipt)))
}

struct Batch {
    rows: Vec<Staged>,
    bytes: usize,
    // Row descriptors and temporary join handles are charged in addition to
    // the original per-row reservations and each admitted worker stack.
    _memory: VerificationMemory,
}

impl Batch {
    fn new(resources: &Resources<'_>) -> io::Result<Self> {
        let bytes = ROWS * std::mem::size_of::<Staged>()
            + WORKERS
                * std::mem::size_of::<(
                    std::thread::ScopedJoinHandle<'static, ()>,
                    VerificationMemory,
                )>();
        let memory = (resources.reserve)(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(ROWS)
            .map_err(|_| invalid("native SQL ordinary batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn flush(
        &mut self,
        writer: &mut dyn Write,
        binary: &mut SqliteBinaryRows,
        context: &mut Context,
        check: &impl Fn() -> io::Result<()>,
        resources: &Resources<'_>,
    ) -> io::Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        check()?;
        #[cfg(test)]
        OBSERVED.with(|value| {
            let mut value = value.borrow_mut();
            value.max_rows = value.max_rows.max(self.rows.len());
            value.max_bytes = value.max_bytes.max(self.bytes);
        });
        let mut failure = hash_batch(&mut self.rows, resources).err();
        // All workers have joined. Source order determines errors and output,
        // and every staged receipt remains caller-owned through its emission.
        for row in self.rows.drain(..) {
            let content = row.content.ok_or_else(|| {
                failure
                    .take()
                    .unwrap_or_else(|| invalid("native SQL ordinary hash result absent"))
            })??;
            check()?;
            emit(row.id, &row.receipt, content, writer, binary, context)?;
        }
        self.bytes = 0;
        if let Some(error) = failure {
            return Err(error);
        }
        check()
    }
}

pub(super) fn write(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    write_with_resources(
        tx,
        writer,
        binary,
        context,
        check,
        &Resources {
            reserve: &VerificationMemory::reserve,
            available: std::thread::available_parallelism().map_or(1, usize::from),
        },
    )
}

fn write_with_resources(
    tx: &Transaction<'_>,
    writer: &mut dyn Write,
    binary: &mut SqliteBinaryRows,
    context: &mut Context,
    check: &impl Fn() -> io::Result<()>,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let mut statement = tx.prepare("SELECT request_id,COALESCE(length(response_json),0) FROM consensus_request_outcomes ORDER BY request_id").map_err(db)?;
    let mut rows = statement.query([]).map_err(db)?;
    let mut batch = if resources.available <= 1 {
        None
    } else {
        Batch::new(resources).ok()
    };
    loop {
        let row = match rows.next().map_err(db) {
            Ok(Some(row)) => row,
            next => {
                if let Some(batch) = &mut batch {
                    batch.flush(writer, binary, context, check, resources)?;
                }
                return next.map(|_| ());
            }
        };
        check()?;
        let shape = (|| {
            let id = SessionConsensusRequestId::from_bytes(scalar(row, 0)?);
            let length: usize = row.get(1).map_err(db)?;
            if length > MAX_ITEM {
                return Err(invalid(
                    "native SQL generic response exceeds original bound",
                ));
            }
            Ok((id, row_memory_bytes(length)?))
        })();
        let (id, charged_bytes) = match shape {
            Ok(shape) => shape,
            Err(error) => {
                if let Some(batch) = &mut batch {
                    batch.flush(writer, binary, context, check, resources)?;
                }
                return Err(error);
            }
        };
        if let Some(batch) = &mut batch {
            if batch.rows.len() == ROWS || charged_bytes > BYTES - batch.bytes {
                batch.flush(writer, binary, context, check, resources)?;
            }
        }
        if charged_bytes > BYTES {
            batch = None;
        }
        let memory = match (resources.reserve)(charged_bytes) {
            Ok(memory) => memory,
            Err(error) => {
                let Some(pending) = &mut batch else {
                    return Err(error);
                };
                // Drop all staging before retrying original row admission.
                // No SQL read, decode, cancellation or I/O is retried here.
                pending.flush(writer, binary, context, check, resources)?;
                batch = None;
                (resources.reserve)(charged_bytes)?
            }
        };
        let decoded = (|| {
            // Keep the exact original BLOB-bound per-ID query, column reads,
            // complete response decode and record checks. In particular the
            // outer cursor is not a substitute for this original SQL reader.
            let (payload_digest, response) = source::ordinary(tx, context.business.identity, id)?;
            let receipt = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
                payload_digest,
                response: Box::new(response),
            });
            validation::validate_generic(&id, &receipt, &context.business.frontiers)?;
            Ok(receipt)
        })();
        let receipt = match decoded {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Some(batch) = &mut batch {
                    batch.flush(writer, binary, context, check, resources)?;
                }
                return Err(error);
            }
        };
        if let Some(batch) = &mut batch {
            if matches!(&receipt, NativeGenericReceipt::Ordinary(row)
                if matches!(row.response.result,
                    Ok(SessionMutationOutcome::Unit
                        | SessionMutationOutcome::Lease(_)
                        | SessionMutationOutcome::CompareAndSet(
                            crate::backend::CompareAndSetResult::Success))))
            {
                batch.rows.push(Staged {
                    id,
                    receipt,
                    content: None,
                    _memory: memory,
                });
                batch.bytes += charged_bytes;
                continue;
            }
            batch.flush(writer, binary, context, check, resources)?;
        }
        emit(
            id,
            &receipt,
            receipt.row_fingerprint(2, &id)?,
            writer,
            binary,
            context,
        )?;
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct Faults {
    spawn: Option<usize>,
    panic: Option<usize>,
}

#[cfg(test)]
#[derive(Default)]
struct Observation {
    started: usize,
    joined: usize,
    max_rows: usize,
    max_bytes: usize,
}

#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::Cell<Faults> = const { std::cell::Cell::new(Faults { spawn: None, panic: None }) };
    static OBSERVED: std::cell::RefCell<Observation> = std::cell::RefCell::new(Observation::default());
}

#[cfg(test)]
#[path = "generation_sqlite_ordinary_tests.rs"]
mod tests;
