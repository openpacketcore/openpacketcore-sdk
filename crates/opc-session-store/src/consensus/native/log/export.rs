//! Complete selected-log inspection outside State. The caller retains source
//! order, authenticated reads, cancellation and every SQL write.

use super::*;
use crate::consensus::native::generation::decode::{LogInput, LogPreparation, PreparedLog};
use crate::consensus::verified_snapshot::VerificationMemory;

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
    input: PreparedLog,
    result: Option<io::Result<()>>,
}

fn inspect_chunk(
    rows: &mut [Staged],
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) {
    for row in rows {
        row.result = Some(row.input.inspect(identity, members));
    }
}

fn inspect_batch(
    rows: &mut [Staged],
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let workers = WORKERS.min(resources.available.max(1)).min(rows.len());
    if rows.len() < PARALLEL_MIN || workers == 1 {
        inspect_chunk(rows, identity, members);
        return Ok(());
    }
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(workers)
            .map_err(|_| invalid("native log export worker allocation failed"))?;
        let mut failure = None;
        let chunk_size = rows.len().div_ceil(workers);
        for (worker, chunk) in rows.chunks_mut(chunk_size).enumerate() {
            let memory = match (resources.reserve)(STACK) {
                Ok(memory) => memory,
                Err(_) => {
                    inspect_chunk(chunk, identity, members);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                failure = Some(invalid("native log export worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native log export worker failure");
                    }
                    inspect_chunk(chunk, identity, members);
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
                failure = Some(invalid("native log export worker failed"));
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
    // Inputs and decoder owners drop before descriptor/handle capacity refund.
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
            .map_err(|_| invalid("native log export batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn finish(
        &mut self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(LogId<SessionConsensusNodeId>, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let mut failure = inspect_batch(&mut self.rows, identity, members, resources).err();
        for staged in self.rows.drain(..) {
            check()?;
            staged.result.ok_or_else(|| {
                failure
                    .take()
                    .unwrap_or_else(|| invalid("native log export inspection result absent"))
            })??;
            emit(staged.input.id(), staged.input.bytes())?;
        }
        self.bytes = 0;
        if let Some(error) = failure {
            return Err(error);
        }
        check()
    }
}

impl NativeLogEntry {
    pub(in crate::consensus::native) fn visit_export(
        rows: &[&SharedRow<Self>],
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(LogId<SessionConsensusNodeId>, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let available = if rows.len() < PARALLEL_MIN {
            1
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        Self::visit_export_with(
            rows,
            identity,
            members,
            &Resources {
                reserve: &VerificationMemory::reserve,
                available,
            },
            check,
            emit,
        )
    }

    fn visit_export_with(
        rows: &[&SharedRow<Self>],
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
        emit: &mut impl FnMut(LogId<SessionConsensusNodeId>, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut batch = if resources.available <= 1 || rows.len() < PARALLEL_MIN {
            None
        } else {
            Batch::new(resources).ok()
        };
        for entry in rows {
            check()?;
            let Some(current) = &mut batch else {
                let bytes = entry.read_bytes(identity, members, check)?;
                emit(entry.id(), bytes.bytes())?;
                continue;
            };
            let Body::Selected(selected) = &entry.body else {
                current.finish(identity, members, resources, check, emit)?;
                let bytes = entry.read_bytes(identity, members, check)?;
                emit(entry.id(), bytes.bytes())?;
                continue;
            };
            if let Err(error) = entry.validate_context(entry.id().index, identity, members) {
                current.finish(identity, members, resources, check, emit)?;
                return Err(error);
            }
            if selected.range.length() > INPUT {
                current.finish(identity, members, resources, check, emit)?;
                batch = None;
                let bytes = entry.read_bytes(identity, members, check)?;
                emit(entry.id(), bytes.bytes())?;
                continue;
            }
            // Leave room for the exact input plus the original JSON preflight
            // temporary before parsing; full decoder scratch is known afterward.
            let read_charge = LogInput::read_charge(selected.range.length())?;
            if current.rows.len() == ROWS || current.bytes + read_charge > BYTES {
                current.finish(identity, members, resources, check, emit)?;
            }
            let reserved = match selected
                .range
                .reserve_read_with(&|bytes| (resources.reserve)(bytes))
            {
                Ok(reserved) => reserved,
                Err(_) => {
                    current.finish(identity, members, resources, check, emit)?;
                    batch = None;
                    let bytes = entry.read_bytes(identity, members, check)?;
                    emit(entry.id(), bytes.bytes())?;
                    continue;
                }
            };
            let input = match reserved.read(check).and_then(|bytes| {
                LogInput::new(
                    bytes,
                    selected.row,
                    &|bytes| (resources.reserve)(bytes),
                    check,
                )
            }) {
                Ok(input) => input,
                Err(error) => {
                    current.finish(identity, members, resources, check, emit)?;
                    return Err(error);
                }
            };
            let Some(bytes) = input.charged_bytes()? else {
                current.finish(identity, members, resources, check, emit)?;
                batch = None;
                #[cfg(test)]
                OBSERVED.with(|value| value.borrow_mut().preflight_serial += 1);
                let input = input.inspect_serial(identity, members, check)?;
                check()?;
                emit(entry.id(), input.bytes())?;
                continue;
            };
            if current.bytes + bytes > BYTES {
                current.finish(identity, members, resources, check, emit)?;
            }
            if bytes > BYTES {
                // A small encoded batch may still have a large decoded shape.
                // Drop all staging before its original large-log gate/admission.
                batch = None;
                let input = input.inspect_serial(identity, members, check)?;
                check()?;
                emit(entry.id(), input.bytes())?;
                continue;
            }
            let prepared = match input.reserve_small(&|bytes| (resources.reserve)(bytes), check) {
                Ok(prepared) => prepared,
                Err(error) => {
                    current.finish(identity, members, resources, check, emit)?;
                    return Err(error);
                }
            };
            let input = match prepared {
                LogPreparation::Ready(input) => input,
                LogPreparation::Serial(input) => {
                    current.finish(identity, members, resources, check, emit)?;
                    batch = None;
                    let input = input.inspect_serial(identity, members, check)?;
                    check()?;
                    emit(entry.id(), input.bytes())?;
                    continue;
                }
            };
            current.bytes += bytes;
            current.rows.push(Staged {
                input,
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
            batch.finish(identity, members, resources, check, emit)?;
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
    preflight_serial: usize,
}

#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::Cell<Faults> = const { std::cell::Cell::new(Faults { spawn: None, panic: None }) };
    static OBSERVED: std::cell::RefCell<Observed> = std::cell::RefCell::new(Observed::default());
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
