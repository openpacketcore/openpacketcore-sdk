//! Destructive, test-control-only observation of a fully closed native owner.
//! The caller supplies its allocator observer; production storage selects no
//! allocator and never exposes native rows or payloads through this interface.

use super::*;

impl NativeStorage {
    pub(crate) fn release_roots_for_test(
        mut self,
        mut observe: impl FnMut(&'static str, &mut dyn FnMut()),
    ) -> serde_json::Value {
        let counts = serde_json::json!({
            "keys": self.business.keys.len(),
            "receipts": self.business.receipts.len(),
            "selected_receipts": self.business.receipts.iter().filter(|(_, row)| row.cold.is_some()).count(),
            "notifications": self.business.notifications.len(),
            "selected_notifications": self.business.notifications.iter().filter(|row| row.is_selected_for_test()).count(),
            "generic_receipts": self.business.generic_receipts.len(),
            "logs": self.log.entries.len(),
            "selected_logs": self.log.entries.values().filter(|row| row.is_cold()).count(),
            "proof_strong_references": self.business.proof.as_ref().map(Arc::strong_count),
        });
        observe("changes", &mut || drop(self.business.changes.take()));
        observe("keys", &mut || {
            drop(std::mem::take(&mut self.business.keys))
        });
        observe("receipts", &mut || {
            drop(std::mem::take(&mut self.business.receipts))
        });
        observe("notifications", &mut || {
            drop(std::mem::take(&mut self.business.notifications))
        });
        observe("generic_receipts", &mut || {
            drop(std::mem::take(&mut self.business.generic_receipts))
        });
        observe("proof", &mut || drop(self.business.proof.take()));
        observe("logs", &mut || drop(std::mem::take(&mut self.log.entries)));
        let mut remaining = Some(self);
        observe("remaining", &mut || drop(remaining.take()));
        counts
    }
}
