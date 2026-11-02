//! Bounded relocation from a completely authenticated expected base. Only the
//! immutable capture supplied to the fresh streaming-base verifier may enter here.
//! Each call scans at most one owner work unit and retains at most that many
//! replacements, independently of the number of rows in the complete file.

use super::*;
use crate::fenced_mutation_roster::RequestBindingKey;
use crate::fenced_mutation_roster_storage::ProductionFloorKey;

pub(super) struct RelocationStream {
    capture: capture::SnapshotCapture,
    source: Arc<VerifiedPrefix>,
    offset: u64,
    notification: usize,
}

impl RelocationStream {
    pub(super) fn new(
        capture: capture::SnapshotCapture,
        source: Arc<VerifiedPrefix>,
    ) -> io::Result<Self> {
        if Version::capture(&capture.storage)?.context_digest()? != source.identity().frontiers {
            return Err(invalid("native base relocation capture differs"));
        }
        let mut value = Self {
            capture,
            source,
            offset: 0,
            notification: 0,
        };
        let magic = value.read::<8>()?;
        if &magic != base::MAGIC && &magic != base::SLOT_MAGIC {
            return Err(invalid("native base relocation format differs"));
        }
        value.extent(MAX_HEADER)?;
        Ok(value)
    }

    fn read<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut bytes = [0; N];
        self.source.read_exact_at(self.offset, &mut bytes)?;
        self.offset = self
            .offset
            .checked_add(N as u64)
            .ok_or_else(|| invalid("native base relocation position overflow"))?;
        Ok(bytes)
    }

    fn expect<const N: usize>(&mut self, expected: [u8; N]) -> io::Result<()> {
        if self.read::<N>()? != expected {
            return Err(invalid("native base relocation frame differs"));
        }
        Ok(())
    }

    fn extent(&mut self, maximum: usize) -> io::Result<(u64, u32)> {
        let length = u32::from_le_bytes(self.read()?);
        if length == 0 || length as usize > maximum {
            return Err(invalid("native base relocation extent invalid"));
        }
        let offset = self.offset;
        self.offset = offset
            .checked_add(u64::from(length))
            .filter(|end| *end <= self.source.identity().length)
            .ok_or_else(|| invalid("native base relocation extent exceeds source"))?;
        Ok((offset, length))
    }

    pub(super) fn next(
        &mut self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(Relocations, bool)> {
        let mut rows = RelocationBuilder::new(relocation::RELOCATION_STEP_ROWS)?;
        let mut finished = false;
        for _ in 0..relocation::RELOCATION_STEP_ROWS {
            check()?;
            match self.read::<1>()?[0] {
                0 | 2 => {
                    self.expect([0])?; // A complete base has no predecessor row.
                    self.extent(MAX_ITEM)?;
                }
                1 => {
                    self.expect([0])?;
                    let id = cold::receipt_id(self.read()?)?;
                    self.expect([1])?;
                    let (offset, length) = self.extent(MAX_ITEM)?;
                    let row = self
                        .capture
                        .storage
                        .business
                        .receipts
                        .get(&id)
                        .ok_or_else(|| invalid("native base relocation receipt missing"))?;
                    rows.receipt(id, row, offset, length)?;
                }
                3 => {
                    let (offset, length) = self.extent(MAX_ITEM)?;
                    let row = self
                        .capture
                        .storage
                        .business
                        .notifications
                        .get(self.notification)
                        .ok_or_else(|| invalid("native base relocation notification missing"))?;
                    rows.notification(row, offset, length)?;
                    self.notification = self
                        .notification
                        .checked_add(1)
                        .ok_or_else(|| invalid("native base relocation notification overflow"))?;
                }
                4 => {
                    let index = u64::from_le_bytes(self.read()?);
                    self.expect([0])?;
                    self.expect([1])?;
                    let (offset, length) = self.extent(MAX_ITEM)?;
                    let row = self
                        .capture
                        .storage
                        .log
                        .entries
                        .get(&index)
                        .ok_or_else(|| invalid("native base relocation log missing"))?;
                    rows.log(index, row, offset, length)?;
                }
                tag @ (5 | 6) => {
                    // Roster sections keep their original lifecycle framing.
                    // The key widths are fixed by the complete base vocabulary.
                    self.expect([0])?;
                    let binding = if tag == 5 {
                        let key = ProductionFloorKey::from_bytes(self.read()?)
                            .map_err(|_| invalid("native base relocation partition key invalid"))?;
                        if !self
                            .capture
                            .storage
                            .business
                            .roster
                            .partitions
                            .contains_key(&key)
                        {
                            return Err(invalid("native base relocation partition missing"));
                        }
                        None
                    } else {
                        Some(
                            RequestBindingKey::from_bytes(self.read()?).map_err(|_| {
                                invalid("native base relocation roster key invalid")
                            })?,
                        )
                    };
                    self.expect(1_u64.to_le_bytes())?;
                    self.expect(0_u64.to_le_bytes())?;
                    self.expect([0])?;
                    self.expect([1])?;
                    let (offset, length) = self.extent(MAX_ITEM)?;
                    if let Some(binding) = binding {
                        let row = self
                            .capture
                            .storage
                            .business
                            .roster
                            .rows
                            .get(&binding)
                            .ok_or_else(|| invalid("native base relocation roster row missing"))?;
                        rows.roster(row, offset, length)?;
                    }
                }
                b'O' => {
                    self.expect(*b"PCNJEND")?;
                    if self.notification != self.capture.storage.business.notifications.len() {
                        return Err(invalid("native base relocation notification count differs"));
                    }
                    finished = true;
                    break;
                }
                _ => return Err(invalid("native base relocation row tag invalid")),
            }
        }
        let native = &self.capture.storage;
        let replacements = rows.prepare(
            Arc::clone(&self.source),
            native.business.identity,
            native.business.applied(),
            &native.business.members,
            native.business.roster_root.clone(),
            check,
        )?;
        Ok((replacements, finished))
    }
}
