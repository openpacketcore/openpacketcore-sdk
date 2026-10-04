//! Bounded pure decoding for already selected generic receipt ranges. Reads,
//! cancellation, revisions and resident-map mutation remain on the caller.

use super::*;
use generation::decode::{GenericInput, GenericPreparation, OwnedGeneric, PreparedGeneric};

const ROWS: usize = 64;
const BYTES: usize = 4 * 1024 * 1024;
const INPUT: usize = 64 * 1024;
const PARALLEL_MIN: usize = 16;
const WORKERS: usize = 8;
const STACK: usize = 2 * 1024 * 1024;

/// One complete catalog identity, row binding and authenticated selected range.
pub(in crate::consensus::native) struct GenericSelection {
    pub(in crate::consensus::native) id: SessionConsensusRequestId,
    pub(in crate::consensus::native) row: generation::facts::Row<generation::facts::Request>,
    pub(in crate::consensus::native) range: resident::SelectedRange,
}

struct Resources<'a> {
    reserve: &'a dyn Fn(usize) -> io::Result<VerificationMemory>,
    available: usize,
}

struct Staged {
    id: SessionConsensusRequestId,
    input: Option<PreparedGeneric>,
    result: Option<io::Result<OwnedGeneric>>,
}

fn decode_chunk(rows: &mut [Staged], frontiers: &NativeFrontiers) {
    for row in rows {
        row.result = Some(
            row.input
                .take()
                .ok_or_else(|| invalid("native selected generic input consumed"))
                .and_then(|input| input.decode(frontiers)),
        );
    }
}

#[derive(Default)]
struct Observation {
    #[cfg(test)]
    fingerprints: u64,
}

fn decode_worker(rows: &mut [Staged], frontiers: &NativeFrontiers) -> Observation {
    #[cfg(test)]
    let before = generic_fingerprint_calls();
    decode_chunk(rows, frontiers);
    Observation {
        #[cfg(test)]
        fingerprints: generic_fingerprint_calls() - before,
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
            .map_err(|_| invalid("native selected generic worker allocation failed"))?;
        let mut error = None;
        let chunk_size = rows.len().div_ceil(workers);
        for (worker, rows) in rows.chunks_mut(chunk_size).enumerate() {
            let memory = match (resources.reserve)(STACK) {
                Ok(memory) => memory,
                Err(_) => {
                    decode_chunk(rows, frontiers);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                error = Some(invalid("native selected generic worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native selected generic worker failure");
                    }
                    decode_worker(rows, frontiers)
                }) {
                Ok(handle) => {
                    handles.push((handle, memory));
                    #[cfg(test)]
                    OBSERVED.with(|value| value.borrow_mut().started += 1);
                }
                Err(failure) => {
                    error = Some(io::Error::other(failure));
                    break;
                }
            }
        }
        for (handle, memory) in handles {
            match handle.join() {
                Ok(observation) => {
                    #[cfg(test)]
                    GENERIC_FINGERPRINT_CALLS
                        .set(GENERIC_FINGERPRINT_CALLS.get() + observation.fingerprints);
                    #[cfg(not(test))]
                    let _ = observation;
                }
                Err(_) if error.is_none() => {
                    error = Some(invalid("native selected generic worker failed"));
                }
                Err(_) => {}
            }
            #[cfg(test)]
            OBSERVED.with(|value| value.borrow_mut().joined += 1);
            drop(memory);
        }
        error.map_or(Ok(()), Err)
    })
}

struct Batch {
    rows: Vec<Staged>,
    bytes: usize,
    // Input/decoded guards drop before descriptor and handle capacity refunds.
    _memory: VerificationMemory,
}

impl Batch {
    fn new(resources: &Resources<'_>) -> io::Result<Self> {
        let bytes = ROWS * size_of::<Staged>()
            + WORKERS
                * size_of::<(
                    std::thread::ScopedJoinHandle<'static, Observation>,
                    VerificationMemory,
                )>();
        let memory = (resources.reserve)(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(ROWS)
            .map_err(|_| invalid("native selected generic batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn finish(
        &mut self,
        destination: &mut SelectedGenericRows,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let mut failure = decode_batch(&mut self.rows, &destination.frontiers, resources).err();
        for mut staged in self.rows.drain(..) {
            check()?;
            if destination.rows.contains_key(&staged.id) {
                return Err(invalid(
                    "native resident request conversion repeats an identity",
                ));
            }
            let owned = staged.result.take().ok_or_else(|| {
                failure
                    .take()
                    .unwrap_or_else(|| invalid("native selected generic result absent"))
            })??;
            let (row, content) = owned.into_resident();
            destination.insert_owned(staged.id, row, content)?;
        }
        self.bytes = 0;
        if let Some(error) = failure {
            return Err(error);
        }
        check()
    }
}

impl SelectedGenericRows {
    pub(in crate::consensus::native) fn insert_selected(
        &mut self,
        rows: impl IntoIterator<Item = io::Result<GenericSelection>>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let rows = rows.into_iter();
        let available = if rows.size_hint().1.is_some_and(|count| count < PARALLEL_MIN) {
            1
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        self.insert_selected_with(
            rows,
            &Resources {
                reserve: &VerificationMemory::reserve,
                available,
            },
            check,
        )
    }

    fn insert_selected_with(
        &mut self,
        rows: impl IntoIterator<Item = io::Result<GenericSelection>>,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let rows = rows.into_iter();
        // An iterator's hint selects only an optimization, never an admission
        // count. Small and single-CPU conversions retain the original lane.
        let mut batch = if resources.available <= 1
            || rows.size_hint().1.is_some_and(|count| count < PARALLEL_MIN)
        {
            None
        } else {
            Batch::new(resources).ok()
        };
        for selection in rows {
            let selection = match selection {
                Ok(selection) => selection,
                Err(error) => {
                    if let Some(batch) = &mut batch {
                        batch.finish(self, resources, check)?;
                    }
                    return Err(error);
                }
            };
            check()?;
            if selection.range.length() > INPUT {
                if let Some(batch) = &mut batch {
                    batch.finish(self, resources, check)?;
                }
                batch = None;
            }
            let Some(current) = &mut batch else {
                self.insert_serial(&selection, check)?;
                continue;
            };
            if current.rows.len() == ROWS || current.bytes + selection.range.length() > BYTES {
                current.finish(self, resources, check)?;
            }
            // Only memory admission is retried. Authenticated reads and shape
            // failures remain failures, after any earlier source-row error.
            let reserved = match selection.range.reserve_read() {
                Ok(reserved) => reserved,
                Err(_) => {
                    current.finish(self, resources, check)?;
                    batch = None;
                    self.insert_serial(&selection, check)?;
                    continue;
                }
            };
            let input = match reserved.read(check) {
                Ok(input) => input,
                Err(error) => {
                    current.finish(self, resources, check)?;
                    return Err(error);
                }
            };
            if self.rows.contains_key(&selection.id)
                || current.rows.iter().any(|row| row.id == selection.id)
            {
                current.finish(self, resources, check)?;
                return Err(invalid(
                    "native resident request conversion repeats an identity",
                ));
            }
            let input = match GenericInput::new(input, selection.id, selection.row) {
                Ok(input) => input,
                Err(error) => {
                    current.finish(self, resources, check)?;
                    return Err(error);
                }
            };
            let bytes = input.charged_bytes()?;
            if current.bytes + bytes > BYTES {
                current.finish(self, resources, check)?;
            }
            let input = match input.reserve(&|bytes| (resources.reserve)(bytes)) {
                GenericPreparation::Ready(input) => input,
                GenericPreparation::Serial(input) => {
                    current.finish(self, resources, check)?;
                    batch = None;
                    self.insert(input.bytes(), selection.id, selection.row, check)?;
                    continue;
                }
            };
            current.bytes += bytes;
            current.rows.push(Staged {
                id: selection.id,
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
            batch.finish(self, resources, check)?;
        }
        check()
    }

    fn insert_serial(
        &mut self,
        selection: &GenericSelection,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let input = selection.range.read(check)?;
        self.insert(input.bytes(), selection.id, selection.row, check)
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
#[path = "changes_selected_generic_tests.rs"]
mod tests;
