//! Bounded complete row inspection during independent catalog admission.
//! The cursor, prefix hash, predecessor rules and catalog stay on the caller.

use super::*;
use decode::{CatalogInput, CatalogKind, CatalogPreparation, CatalogRow, PreparedCatalogRow};

const ROWS: usize = 64;
const BYTES: usize = 4 * 1024 * 1024;
const INPUT: usize = 64 * 1024;
const PARALLEL_MIN: usize = 16;
const WORKERS: usize = 8;
const STACK: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Table {
    Generic,
    Notification,
}

impl Table {
    fn index(self) -> usize {
        match self {
            Self::Generic => 2,
            Self::Notification => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum Header {
    Generic(Option<[u8; 32]>),
    Notification(u64),
}

impl Header {
    fn kind(self, format: Format) -> CatalogKind {
        match self {
            Self::Generic(_) => CatalogKind::Generic(format),
            Self::Notification(sequence) => CatalogKind::Notification(sequence),
        }
    }
}

// Consume only the original length prefix before memory admission. The frame
// keeps the exact cursor and range bound together, so pressure can release
// earlier scratch before reading this body. I/O errors are never retried.
struct Frame<'a, 'r> {
    reader: &'a mut Cursor<'r>,
    range: Range,
}

impl<'r> Frame<'_, 'r> {
    fn reserve(
        &mut self,
        reserve: &dyn Fn(usize) -> io::Result<VerificationMemory>,
    ) -> io::Result<ReservedFrame<'_, 'r>> {
        let memory = reserve(self.range.length as usize)?;
        Ok(ReservedFrame {
            reader: self.reader,
            range: self.range,
            memory,
        })
    }
}

struct ReservedFrame<'a, 'r> {
    reader: &'a mut Cursor<'r>,
    range: Range,
    memory: VerificationMemory,
}

impl ReservedFrame<'_, '_> {
    fn read(self) -> io::Result<(Range, Input)> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(self.range.length as usize)
            .map_err(|_| invalid("native generation input allocation failed"))?;
        bytes.resize(self.range.length as usize, 0);
        self.reader.read_exact(&mut bytes)?;
        if self.range.offset.checked_add(u64::from(self.range.length)) != Some(self.reader.position)
        {
            return Err(invalid("native catalog row extent differs"));
        }
        Ok((
            self.range,
            Input {
                bytes,
                _memory: self.memory,
            },
        ))
    }
}

fn frame<'a, 'r>(
    reader: &'a mut Cursor<'r>,
    table: Table,
    notifications: usize,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(Header, Frame<'a, 'r>)> {
    check()?;
    expect(reader, &[table.index() as u8])?;
    let header = match table {
        Table::Generic => Header::Generic(reader.before()?),
        Table::Notification => {
            if notifications >= validation::MAX_ITEMS {
                return Err(invalid("native catalog watch count exceeds original bound"));
            }
            Header::Notification(notifications as u64 + 1)
        }
    };
    let offset = reader
        .position
        .checked_add(4)
        .ok_or_else(|| invalid("native catalog row offset overflow"))?;
    let length = u32::from_le_bytes(reader.scalar()?);
    if length == 0 || length as usize > MAX_ITEM {
        return Err(invalid("native generation row length invalid"));
    }
    Ok((
        header,
        Frame {
            reader,
            range: Range { offset, length },
        },
    ))
}

struct Resources<'a> {
    reserve: &'a dyn Fn(usize) -> io::Result<VerificationMemory>,
    available: usize,
}

struct Staged {
    header: Header,
    range: Range,
    input: Option<PreparedCatalogRow>,
    result: Option<io::Result<CatalogRow>>,
}

fn inspect_chunk(rows: &mut [Staged], frontiers: &NativeFrontiers) {
    for row in rows {
        row.result = Some(
            row.input
                .take()
                .ok_or_else(|| invalid("native catalog inspection input consumed"))
                .and_then(|input| input.inspect(frontiers)),
        );
    }
}

#[derive(Default)]
struct Observation {
    #[cfg(test)]
    fingerprints: u64,
}

fn inspect_worker(rows: &mut [Staged], frontiers: &NativeFrontiers) -> Observation {
    #[cfg(test)]
    let before = changes::generic_fingerprint_calls();
    inspect_chunk(rows, frontiers);
    Observation {
        #[cfg(test)]
        fingerprints: changes::generic_fingerprint_calls() - before,
    }
}

fn inspect_batch(
    rows: &mut [Staged],
    frontiers: &NativeFrontiers,
    resources: &Resources<'_>,
) -> io::Result<()> {
    let workers = WORKERS.min(resources.available.max(1)).min(rows.len());
    if rows.len() < PARALLEL_MIN || workers == 1 {
        inspect_chunk(rows, frontiers);
        return Ok(());
    }
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(workers)
            .map_err(|_| invalid("native catalog worker allocation failed"))?;
        let mut error = None;
        let chunk_size = rows.len().div_ceil(workers);
        for (worker, rows) in rows.chunks_mut(chunk_size).enumerate() {
            let memory = match (resources.reserve)(STACK) {
                Ok(memory) => memory,
                Err(_) => {
                    inspect_chunk(rows, frontiers);
                    continue;
                }
            };
            #[cfg(not(test))]
            let _ = worker;
            #[cfg(test)]
            if FAULTS.with(|faults| faults.get().spawn == Some(worker)) {
                error = Some(invalid("native catalog worker spawn failed"));
                break;
            }
            #[cfg(test)]
            let panic_worker = FAULTS.with(|faults| faults.get().panic == Some(worker));
            match std::thread::Builder::new()
                .stack_size(STACK)
                .spawn_scoped(scope, move || {
                    #[cfg(test)]
                    if panic_worker {
                        panic!("injected native catalog worker failure");
                    }
                    inspect_worker(rows, frontiers)
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
                    changes::record_joined_generic_fingerprint_calls(observation.fingerprints);
                    #[cfg(not(test))]
                    let _ = observation;
                }
                Err(_) if error.is_none() => {
                    error = Some(invalid("native catalog worker failed"));
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
            .map_err(|_| invalid("native catalog batch allocation failed"))?;
        Ok(Self {
            rows,
            bytes: 0,
            _memory: memory,
        })
    }

    fn finish(
        &mut self,
        destination: &mut Rows,
        after: &Context,
        section: RowSection,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let mut failure = inspect_batch(&mut self.rows, &after.business.frontiers, resources).err();
        for mut staged in self.rows.drain(..) {
            check()?;
            let row = staged.result.take().ok_or_else(|| {
                failure
                    .take()
                    .unwrap_or_else(|| invalid("native catalog inspection result absent"))
            })??;
            destination.accept_inspected(staged.header, staged.range, row, section)?;
        }
        self.bytes = 0;
        if let Some(error) = failure {
            return Err(error);
        }
        check()
    }
}

impl Rows {
    pub(super) fn read_catalog_table(
        &mut self,
        reader: &mut Cursor<'_>,
        after: &Context,
        section: RowSection,
        table: Table,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let available = if section.counts[table.index()] < PARALLEL_MIN {
            1
        } else {
            std::thread::available_parallelism().map_or(1, usize::from)
        };
        self.read_catalog_table_with(
            reader,
            after,
            section,
            table,
            &Resources {
                reserve: &VerificationMemory::reserve,
                available,
            },
            check,
        )
    }

    fn read_catalog_table_with(
        &mut self,
        reader: &mut Cursor<'_>,
        after: &Context,
        section: RowSection,
        table: Table,
        resources: &Resources<'_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let mut batch = if section.counts[table.index()] < PARALLEL_MIN || resources.available <= 1
        {
            None
        } else {
            Batch::new(resources).ok()
        };
        for _ in 0..section.counts[table.index()] {
            let pending = batch.as_ref().map_or(0, |batch| batch.rows.len());
            let (header, mut frame) =
                match frame(reader, table, self.notifications.len() + pending, check) {
                    Ok(frame) => frame,
                    Err(error) => {
                        if let Some(batch) = &mut batch {
                            batch.finish(self, after, section, resources, check)?;
                        }
                        return Err(error);
                    }
                };
            if frame.range.length as usize > INPUT {
                if let Some(batch) = &mut batch {
                    batch.finish(self, after, section, resources, check)?;
                }
                batch = None;
            }
            let Some(current) = &mut batch else {
                let (range, input) = frame.reserve(&VerificationMemory::reserve)?.read()?;
                let row = decode::inspect_catalog(
                    input.bytes(),
                    header.kind(section.format),
                    &after.business.frontiers,
                    check,
                )?;
                self.accept_inspected(header, range, row, section)?;
                continue;
            };
            if current.rows.len() == ROWS || current.bytes + frame.range.length as usize > BYTES {
                current.finish(self, after, section, resources, check)?;
            }
            let reserved = match frame.reserve(resources.reserve) {
                Ok(reserved) => reserved,
                Err(_) => {
                    current.finish(self, after, section, resources, check)?;
                    batch = None;
                    let (range, input) = frame.reserve(&VerificationMemory::reserve)?.read()?;
                    let row = decode::inspect_catalog(
                        input.bytes(),
                        header.kind(section.format),
                        &after.business.frontiers,
                        check,
                    )?;
                    self.accept_inspected(header, range, row, section)?;
                    continue;
                }
            };
            let (range, input) = match reserved.read() {
                Ok(input) => input,
                Err(error) => {
                    current.finish(self, after, section, resources, check)?;
                    return Err(error);
                }
            };
            let input = match CatalogInput::new(input, header.kind(section.format)) {
                Ok(input) => input,
                Err(error) => {
                    current.finish(self, after, section, resources, check)?;
                    return Err(error);
                }
            };
            let bytes = match input.charged_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    current.finish(self, after, section, resources, check)?;
                    return Err(error);
                }
            };
            if current.bytes + bytes > BYTES {
                current.finish(self, after, section, resources, check)?;
            }
            if bytes > BYTES {
                batch = None;
                let row = input.inspect_serial(&after.business.frontiers, check)?;
                self.accept_inspected(header, range, row, section)?;
                continue;
            }
            let input = match input.reserve(&|bytes| (resources.reserve)(bytes)) {
                CatalogPreparation::Ready(input) => input,
                CatalogPreparation::Serial(input) => {
                    current.finish(self, after, section, resources, check)?;
                    batch = None;
                    let row = input.inspect_serial(&after.business.frontiers, check)?;
                    self.accept_inspected(header, range, row, section)?;
                    continue;
                }
            };
            current.bytes += bytes;
            current.rows.push(Staged {
                header,
                range,
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
            batch.finish(self, after, section, resources, check)?;
        }
        check()
    }

    fn accept_inspected(
        &mut self,
        header: Header,
        range: Range,
        row: CatalogRow,
        section: RowSection,
    ) -> io::Result<()> {
        let RowSection {
            checkpoint, base, ..
        } = section;
        match (header, row) {
            (Header::Generic(before), CatalogRow::Generic(id, row)) => {
                predecessor(self.generic.get(&id), before, checkpoint, base)?;
                let row = row.ok_or_else(|| {
                    invalid("native generation generic removal lacks its lifecycle codec")
                })?;
                if let Some(before) = self.generic.get(&id) {
                    row.facts.validate_replacement(
                        before.row.facts,
                        before.row.content != row.content,
                    )?;
                } else if row.facts.retained_until.is_some() {
                    self.v1_count += 1;
                    if self.v1_count
                        > crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES
                    {
                        return Err(invalid(
                            "native catalog V1 count exceeds original lifetime bound",
                        ));
                    }
                }
                self.summary[2].replace(before, Some(row.content))?;
                put(
                    &mut self.generic,
                    id,
                    Indexed {
                        range,
                        row,
                        checkpoint,
                    },
                    validation::MAX_ITEMS,
                )?;
            }
            (Header::Notification(sequence), CatalogRow::Notification(row)) => {
                if sequence != self.notifications.len() as u64 + 1 || row.facts.sequence != sequence
                {
                    return Err(invalid(
                        "native catalog inspected notification order differs",
                    ));
                }
                self.summary[3].replace(None, Some(row.content))?;
                self.notifications
                    .try_reserve(1)
                    .map_err(|_| invalid("native resident watch catalog allocation failed"))?;
                self.notifications.push(Indexed {
                    range,
                    row,
                    checkpoint,
                });
            }
            _ => return Err(invalid("native catalog inspection kind differs")),
        }
        Ok(())
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
#[path = "generation_catalog_batch_tests.rs"]
mod tests;
