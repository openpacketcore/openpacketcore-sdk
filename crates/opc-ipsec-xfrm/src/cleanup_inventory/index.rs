use super::InventoryError;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocatorKind {
    Object,
    Coverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Location {
    pub(super) position: u32,
    pub(super) kind: LocatorKind,
}

#[derive(Clone, Copy)]
struct IndexSlot {
    digest: [u8; 32],
    position: u32,
    kind: u8,
    state: u8,
}

impl Zeroize for IndexSlot {
    fn zeroize(&mut self) {
        self.digest.zeroize();
        self.position.zeroize();
        self.kind.zeroize();
        self.state.zeroize();
    }
}

impl IndexSlot {
    const EMPTY: Self = Self {
        digest: [0; 32],
        position: 0,
        kind: 0,
        state: 0,
    };

    fn location(&self) -> Location {
        Location {
            position: self.position,
            kind: if self.kind == 0 {
                LocatorKind::Object
            } else {
                LocatorKind::Coverage
            },
        }
    }
}

// A hit is a locator, never authority: callers must authenticate the pointed-to
// record and compare its complete identity, kind and lifecycle serial.
pub(super) struct LocatorIndex {
    slots: Zeroizing<Vec<IndexSlot>>,
    maximum_entries: usize,
    entries: usize,
}

impl LocatorIndex {
    pub(super) fn required_allocation(
        maximum_entries: usize,
    ) -> Result<(usize, usize), InventoryError> {
        let capacity = maximum_entries
            .checked_mul(2)
            .and_then(|count| count.max(2).checked_next_power_of_two())
            .ok_or(InventoryError::Capacity)?;
        let bytes = capacity
            .checked_mul(std::mem::size_of::<IndexSlot>())
            .ok_or(InventoryError::Capacity)?;
        Ok((capacity, bytes))
    }

    pub(super) fn new(maximum_entries: usize) -> Result<Self, InventoryError> {
        let (capacity, _) = Self::required_allocation(maximum_entries)?;
        let mut slots = Zeroizing::new(Vec::new());
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| InventoryError::Allocation)?;
        if slots.capacity() != capacity {
            return Err(InventoryError::Allocation);
        }
        slots.resize(capacity, IndexSlot::EMPTY);
        Ok(Self {
            slots,
            maximum_entries,
            entries: 0,
        })
    }

    fn starting_slot(&self, digest: &[u8; 32]) -> usize {
        let hash = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        (hash as usize) & (self.slots.len() - 1)
    }

    pub(super) fn insert(
        &mut self,
        digest: [u8; 32],
        location: Location,
    ) -> Result<(), InventoryError> {
        let start = self.starting_slot(&digest);
        let mut available = None;
        for probe in 0..self.slots.len() {
            let index = (start + probe) & (self.slots.len() - 1);
            let slot = &self.slots[index];
            if slot.state == 1 && bool::from(slot.digest.ct_eq(&digest)) {
                return if slot.location() == location {
                    Ok(())
                } else {
                    Err(InventoryError::Duplicate)
                };
            }
            if slot.state != 1 && available.is_none() {
                available = Some(index);
            }
            if slot.state == 0 {
                break;
            }
        }
        if self.entries >= self.maximum_entries {
            return Err(InventoryError::Capacity);
        }
        let index = available.ok_or(InventoryError::Capacity)?;
        self.slots[index] = IndexSlot {
            digest,
            position: location.position,
            kind: u8::from(location.kind == LocatorKind::Coverage),
            state: 1,
        };
        self.entries += 1;
        Ok(())
    }

    pub(super) fn lookup(&self, digest: &[u8; 32]) -> (Option<Location>, usize) {
        let start = self.starting_slot(digest);
        for probe in 0..self.slots.len() {
            let slot = &self.slots[(start + probe) & (self.slots.len() - 1)];
            if slot.state == 0 {
                return (None, probe + 1);
            }
            if slot.state == 1 && bool::from(slot.digest.ct_eq(digest)) {
                return (Some(slot.location()), probe + 1);
            }
        }
        (None, self.slots.len())
    }

    pub(super) fn remove(
        &mut self,
        digest: &[u8; 32],
        location: Location,
    ) -> Result<(), InventoryError> {
        let start = self.starting_slot(digest);
        let capacity = self.slots.len();
        for probe in 0..capacity {
            let slot = &mut self.slots[(start + probe) & (capacity - 1)];
            if slot.state == 0 {
                break;
            }
            if slot.state == 1 && bool::from(slot.digest.ct_eq(digest)) {
                if slot.location() != location {
                    return Err(InventoryError::WrongBinding);
                }
                slot.zeroize();
                slot.state = 2;
                self.entries -= 1;
                return Ok(());
            }
        }
        Err(InventoryError::WrongBinding)
    }

    pub(super) fn allocation(&self) -> (usize, usize, usize) {
        let slot_bytes = std::mem::size_of::<IndexSlot>();
        (
            self.slots.len(),
            slot_bytes,
            self.slots.capacity() * slot_bytes,
        )
    }
}
