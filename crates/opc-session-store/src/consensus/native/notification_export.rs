//! Bounded complete selected notification decoding outside State. The caller
//! retains authenticated reads, cancellation, sequence order and SQL output.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use generation::decode::{
    notification_encoding_bytes, ExportNotification, NotificationInput, NotificationPreparation,
    PreparedNotification,
};

const ROWS: usize = 64;
const BYTES: usize = 4 * 1024 * 1024;
const INPUT: usize = 64 * 1024;
const PARALLEL_MIN: usize = 16;
const WORKERS: usize = 8;
const STACK: usize = 2 * 1024 * 1024;

struct Resources<'a> {
    reserve: &'a dyn Fn(usize) -> io::Result<VerificationMemory>,
    available: usize,
}

struct Staged {
    input: Option<PreparedNotification>,
    result: Option<io::Result<ExportNotification>>,
}

fn decode_chunk(rows: &mut [Staged], frontiers: &NativeFrontiers) {
    for row in rows {
        row.result = Some(
            row.input
                .take()
                .ok_or_else(|| invalid("native notification export input consumed"))
                .and_then(|input| input.decode(frontiers)),
        );
    }
}

fn decode_batch(
    rows: &mut [Staged],
    frontiers: &NativeFrontiers,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let workers = WORKERS.min(resources.available.max(1)).min(rows.len());
    if rows.len() < PARALLEL_MIN || workers == 1 {
        decode_chunk(rows, frontiers);
        return Ok(());
    }
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(workers)
            .map_err(|_| invalid("native notification export worker allocation failed"))?;
        let mut failure = None;
        let chunk_size = rows.len().div_ceil(workers);
        for (worker, chunk) in rows.chunks_mut(chunk_size).enumerate() {
            let memory = match (resources.reserve)(STACK) {
                Ok(memory) => memory,
                Err(_) => {
                    decode_chunk(chunk, frontiers);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                failure = Some(invalid("native notification export worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native notification export worker failure");
                    }
                    decode_chunk(chunk, frontiers);
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
                failure = Some(invalid("native notification export worker failed"));
            }
            #[cfg(test)]
            OBSERVED.with(|value| value.borrow_mut().joined += 1);
            drop(memory);
        }
        failure.map_or(Ok(()), Err)
    })
}

struct Batch {
    rows: Vec<Staged>,
    bytes: usize,
    // Inputs and decoded rows drop before descriptor/handle capacity refund.
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
            .map_err(|_| invalid("native notification export batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn finish(
        &mut self,
        frontiers: &NativeFrontiers,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(&ReplicationEntry) -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let mut failure = decode_batch(&mut self.rows, frontiers, resources).err();
        for staged in self.rows.drain(..) {
            check()?;
            let owned = staged.result.ok_or_else(|| {
                failure
                    .take()
                    .unwrap_or_else(|| invalid("native notification export result absent"))
            })??;
            emit(owned.entry())?;
        }
        self.bytes = 0;
        if let Some(error) = failure {
            return Err(error);
        }
        check()
    }
}

fn emit_serial(
    entry: &NativeNotification,
    frontiers: &NativeFrontiers,
    check: &impl Fn() -> io::Result<()>,
    emit: &mut impl FnMut(&ReplicationEntry) -> io::Result<()>,
) -> io::Result<()> {
    let resolved = entry.read(frontiers, check)?;
    let _encoding_memory =
        VerificationMemory::reserve(notification_encoding_bytes(resolved.entry())?)?;
    emit(resolved.entry())
}

impl NativeNotification {
    pub(in crate::consensus::native) fn visit_export<'a>(
        rows: impl IntoIterator<Item = &'a NotificationRow>,
        frontiers: &NativeFrontiers,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(&ReplicationEntry) -> io::Result<()>,
    ) -> io::Result<()> {
        let rows = rows.into_iter();
        let available = if rows.size_hint().1.is_some_and(|count| count < PARALLEL_MIN) {
            1
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        Self::visit_export_with(
            rows,
            frontiers,
            &Resources {
                reserve: &VerificationMemory::reserve,
                available,
            },
            check,
            emit,
        )
    }

    fn visit_export_with<'a>(
        rows: impl IntoIterator<Item = &'a NotificationRow>,
        frontiers: &NativeFrontiers,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(&ReplicationEntry) -> io::Result<()>,
    ) -> io::Result<()> {
        let rows = rows.into_iter();
        let mut batch = if resources.available <= 1
            || rows.size_hint().1.is_some_and(|count| count < PARALLEL_MIN)
        {
            None
        } else {
            Batch::new(resources).ok()
        };
        for entry in rows {
            check()?;
            let Some(current) = &mut batch else {
                emit_serial(entry, frontiers, check, emit)?;
                continue;
            };
            let Body::Selected(selected) = &entry.body else {
                current.finish(frontiers, resources, check, emit)?;
                batch = None;
                emit_serial(entry, frontiers, check, emit)?;
                continue;
            };
            if selected.range.length() > INPUT {
                current.finish(frontiers, resources, check, emit)?;
                batch = None;
                emit_serial(entry, frontiers, check, emit)?;
                continue;
            }
            if current.rows.len() == ROWS || current.bytes + selected.range.length() > BYTES {
                current.finish(frontiers, resources, check, emit)?;
            }
            let reserved = match selected
                .range
                .reserve_read_with(&|bytes| (resources.reserve)(bytes))
            {
                Ok(reserved) => reserved,
                Err(_) => {
                    current.finish(frontiers, resources, check, emit)?;
                    batch = None;
                    emit_serial(entry, frontiers, check, emit)?;
                    continue;
                }
            };
            // Retry allocation admission only, never authenticated reads,
            // malformed input, authority/cancellation or output failures.
            let input = match reserved
                .read(check)
                .and_then(|bytes| NotificationInput::new(bytes, selected.row, check))
            {
                Ok(input) => input,
                Err(error) => {
                    current.finish(frontiers, resources, check, emit)?;
                    return Err(error);
                }
            };
            let bytes = input.charged_bytes()?;
            if current.bytes + bytes > BYTES {
                current.finish(frontiers, resources, check, emit)?;
            }
            if bytes > BYTES {
                batch = None;
                let owned = input.decode_serial(frontiers, check)?;
                emit(owned.entry())?;
                continue;
            }
            let prepared = match input.reserve_small(&|bytes| (resources.reserve)(bytes), check) {
                Ok(prepared) => prepared,
                Err(error) => {
                    current.finish(frontiers, resources, check, emit)?;
                    return Err(error);
                }
            };
            let input = match prepared {
                NotificationPreparation::Ready(input) => input,
                NotificationPreparation::Serial(input) => {
                    current.finish(frontiers, resources, check, emit)?;
                    batch = None;
                    let owned = input.decode_serial(frontiers, check)?;
                    emit(owned.entry())?;
                    continue;
                }
            };
            current.bytes += bytes;
            current.rows.push(Staged {
                input: Some(input),
                result: None,
            });
            #[cfg(test)]
            OBSERVED.with(|value| {
                let mut value = value.borrow_mut();
                value.rows = value.rows.max(current.rows.len());
                value.bytes = value.bytes.max(current.bytes);
            });
        }
        if let Some(batch) = &mut batch {
            batch.finish(frontiers, resources, check, emit)?;
        }
        check()
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
struct Observed {
    rows: usize,
    bytes: usize,
    started: usize,
    joined: usize,
}

#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::Cell<Faults> = const { std::cell::Cell::new(Faults { spawn: None, panic: None }) };
    static OBSERVED: std::cell::RefCell<Observed> = std::cell::RefCell::new(Observed::default());
}

#[cfg(test)]
#[path = "notification_export_tests.rs"]
mod tests;
