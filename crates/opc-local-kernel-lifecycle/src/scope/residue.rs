//! Retry-stable diagnostics. These observations never grant deletion authority.
use opc_linux_gtpu_sys::tc::ArtifactInventory;
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct Residue {
    programs: BTreeSet<u32>,
    maps: BTreeSet<u32>,
    count: usize,
}
impl Residue {
    pub(super) fn capture(&mut self, inventory: &ArtifactInventory) {
        self.programs.extend(inventory.observed_program_ids());
        for identity in inventory.map_identities() {
            self.maps.insert(identity.id);
        }
    }
    pub(super) fn observed(mut self) -> Self {
        self.observe();
        self
    }
    pub(super) fn observe(&mut self) {
        // A pinless predecessor's map graph is unavailable without node-global
        // ID reopen. Keep only observed IDs as a fixed lower bound, never an
        // assertion that zero proves every old kernel object was reclaimed.
        self.count = self.programs.len() + self.maps.len();
    }
    pub(super) fn count(&self) -> usize {
        self.count
    }
}
