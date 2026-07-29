//! Pure root-cgroup inventory transition checks used by the Linux installer.

use std::collections::BTreeSet;

use opc_linux_gtpu_sys::BpfCgroupProgramQuery;

const CGROUP_BPF_PROGRAM_CAPACITY: usize = 64;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RootInventory {
    revision: u64,
    attach_flags: u32,
    program_ids: Vec<u32>,
    program_attach_flags: Vec<u32>,
}

impl RootInventory {
    pub(crate) fn from_query(query: &BpfCgroupProgramQuery) -> Result<Self, InventoryError> {
        let program_ids = query
            .attachments()
            .iter()
            .map(|attachment| attachment.program_id())
            .collect::<Vec<_>>();
        let program_attach_flags = query
            .attachments()
            .iter()
            .map(|attachment| attachment.program_attach_flags())
            .collect::<Vec<_>>();
        let expected_flags = if program_ids.is_empty() {
            0
        } else {
            BPF_F_ALLOW_MULTI
        };
        let unique_program_ids = program_ids.iter().copied().collect::<BTreeSet<_>>();
        if program_ids.len() > CGROUP_BPF_PROGRAM_CAPACITY
            || program_ids.contains(&0)
            || unique_program_ids.len() != program_ids.len()
            || query.attach_flags() != expected_flags
            || program_attach_flags
                .iter()
                .any(|flags| *flags != expected_flags)
        {
            return Err(InventoryError::Invalid);
        }
        Ok(Self {
            revision: query.revision(),
            attach_flags: query.attach_flags(),
            program_ids,
            program_attach_flags,
        })
    }

    #[cfg(test)]
    pub(crate) fn fixture(revision: u64, program_ids: Vec<u32>) -> Self {
        let program_attach_flags = vec![BPF_F_ALLOW_MULTI; program_ids.len()];
        Self {
            revision,
            attach_flags: if program_ids.is_empty() {
                0
            } else {
                BPF_F_ALLOW_MULTI
            },
            program_ids,
            program_attach_flags,
        }
    }

    #[cfg(test)]
    fn fixture_with_flags(
        revision: u64,
        attach_flags: u32,
        program_ids: Vec<u32>,
        program_attach_flags: Vec<u32>,
    ) -> Self {
        Self {
            revision,
            attach_flags,
            program_ids,
            program_attach_flags,
        }
    }

    /// Plan the only accepted first installation transition.
    ///
    /// The pre-query must contain no program at all. This rejects a foreign
    /// direct attachment, a BPF-link attachment (which is indistinguishable in
    /// this query ABI), and any ambiguous pre-existing ordering. Revision zero
    /// is valid and intentionally retained: the kernel treats a zero expected
    /// revision as "no compare-and-swap", so the staged program must already
    /// be closed and [`DirectAttachPlan::validate_post`] becomes the mandatory
    /// authority check before any userspace activation can occur.
    pub(crate) fn plan_closed_direct_attach(
        &self,
        staged_program_id: u32,
    ) -> Result<DirectAttachPlan, InventoryError> {
        if !self.program_ids.is_empty() {
            return Err(InventoryError::ForeignAttachment);
        }
        if staged_program_id == 0 || self.revision == u64::MAX {
            return Err(InventoryError::CapacityOrRevision);
        }
        let expected_post_revision = self
            .revision
            .checked_add(1)
            .ok_or(InventoryError::CapacityOrRevision)?;
        Ok(DirectAttachPlan {
            before: self.clone(),
            staged_program_id,
            expected_post_revision,
        })
    }

    pub(crate) fn exact_match(&self, other: &Self) -> bool {
        self == other
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn attach_flags(&self) -> u32 {
        self.attach_flags
    }

    pub(crate) fn program_ids(&self) -> &[u32] {
        &self.program_ids
    }

    pub(crate) fn program_attach_flags(&self) -> &[u32] {
        &self.program_attach_flags
    }

    /// Prove one exact persisted direct-attachment inventory during adoption.
    pub(crate) fn matches_trusted_direct_attachment(
        &self,
        expected_revision: u64,
        expected_program_id: u32,
    ) -> bool {
        expected_program_id != 0
            && self.revision == expected_revision
            && self.attach_flags == BPF_F_ALLOW_MULTI
            && self.program_ids.as_slice() == [expected_program_id]
            && self.program_attach_flags.as_slice() == [BPF_F_ALLOW_MULTI]
    }
}

impl std::fmt::Debug for RootInventory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootInventory")
            .field("program_count", &self.program_ids.len())
            .field("revision_verified", &true)
            .finish()
    }
}

pub(crate) struct DirectAttachPlan {
    before: RootInventory,
    staged_program_id: u32,
    expected_post_revision: u64,
}

impl DirectAttachPlan {
    pub(crate) const fn expected_pre_revision(&self) -> u64 {
        self.before.revision
    }

    pub(crate) const fn expected_post_revision(&self) -> u64 {
        self.expected_post_revision
    }

    pub(crate) fn validate_post(&self, after: &RootInventory) -> Result<(), InventoryError> {
        if after.revision != self.expected_post_revision
            || after.attach_flags != BPF_F_ALLOW_MULTI
            || after.program_ids.as_slice() != [self.staged_program_id]
            || after.program_attach_flags.as_slice() != [BPF_F_ALLOW_MULTI]
        {
            return Err(InventoryError::ConcurrentMutation);
        }
        Ok(())
    }
}

impl std::fmt::Debug for DirectAttachPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DirectAttachPlan(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryError {
    Invalid,
    ForeignAttachment,
    CapacityOrRevision,
    ConcurrentMutation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pristine_revision_zero_is_valid_but_requires_exact_closed_first_readback() {
        let before = RootInventory::fixture(0, vec![]);
        let plan = before
            .plan_closed_direct_attach(11)
            .expect("pristine zero-revision plan");
        assert_eq!(plan.expected_pre_revision(), 0);
        assert_eq!(plan.expected_post_revision(), 1);
        assert!(plan
            .validate_post(&RootInventory::fixture(1, vec![11]))
            .is_ok());

        for raced in [
            RootInventory::fixture(0, vec![11]),
            RootInventory::fixture(2, vec![11]),
            RootInventory::fixture(1, vec![]),
            RootInventory::fixture(1, vec![13]),
            RootInventory::fixture(1, vec![11, 13]),
            RootInventory::fixture_with_flags(1, 0, vec![11], vec![BPF_F_ALLOW_MULTI]),
            RootInventory::fixture_with_flags(1, BPF_F_ALLOW_MULTI, vec![11], vec![0]),
        ] {
            assert_eq!(
                plan.validate_post(&raced),
                Err(InventoryError::ConcurrentMutation)
            );
        }
    }

    #[test]
    fn every_foreign_pre_attachment_is_rejected_before_mutation() {
        for foreign in [
            RootInventory::fixture(1, vec![3]),
            RootInventory::fixture(41, vec![3, 5, 7]),
            RootInventory::fixture_with_flags(1, 0, vec![3], vec![0]),
        ] {
            assert_eq!(
                foreign
                    .plan_closed_direct_attach(11)
                    .expect_err("foreign attachment"),
                InventoryError::ForeignAttachment
            );
        }
    }

    #[test]
    fn revision_wrap_and_zero_program_fail_before_mutation() {
        let full = RootInventory::fixture(u64::MAX, vec![]);
        assert_eq!(
            full.plan_closed_direct_attach(1)
                .expect_err("revision wrap"),
            InventoryError::CapacityOrRevision
        );
        let pristine = RootInventory::fixture(0, vec![]);
        assert_eq!(
            pristine
                .plan_closed_direct_attach(0)
                .expect_err("zero program"),
            InventoryError::CapacityOrRevision
        );
    }

    #[test]
    fn previously_mutated_but_empty_root_uses_kernel_revision_cas() {
        let before = RootInventory::fixture(41, vec![]);
        let plan = before
            .plan_closed_direct_attach(11)
            .expect("empty root plan");
        assert_eq!(plan.expected_pre_revision(), 41);
        assert_eq!(plan.expected_post_revision(), 42);
        assert!(plan
            .validate_post(&RootInventory::fixture(42, vec![11]))
            .is_ok());

        for mutated in [
            RootInventory::fixture(41, vec![11]),
            RootInventory::fixture(43, vec![11]),
            RootInventory::fixture(42, vec![13]),
            RootInventory::fixture(42, vec![]),
            RootInventory::fixture(42, vec![11, 13]),
        ] {
            assert_eq!(
                plan.validate_post(&mutated),
                Err(InventoryError::ConcurrentMutation)
            );
        }
    }

    #[test]
    fn trusted_adoption_requires_exact_revision_program_and_flags() {
        let committed = RootInventory::fixture(12, vec![19]);
        assert!(committed.matches_trusted_direct_attachment(12, 19));
        assert!(committed.exact_match(&committed));
        for changed in [
            RootInventory::fixture(13, vec![19]),
            RootInventory::fixture(12, vec![23]),
            RootInventory::fixture(12, vec![]),
            RootInventory::fixture(12, vec![19, 23]),
            RootInventory::fixture_with_flags(12, 0, vec![19], vec![0]),
        ] {
            assert!(!committed.exact_match(&changed));
            assert!(!changed.matches_trusted_direct_attachment(12, 19));
        }
        assert!(!committed.matches_trusted_direct_attachment(12, 0));
    }

    #[test]
    fn inventory_debug_never_exposes_ids_or_revision() {
        let inventory =
            RootInventory::fixture(0x0102_0304_0506_0708, vec![0x1112_1314, 0x2122_2324]);
        let debug = format!("{inventory:?}");
        for fragment in ["72623859790382856", "286397204", "555885348"] {
            assert!(!debug.contains(fragment));
        }
        assert!(debug.contains("program_count: 2"));
    }
}
