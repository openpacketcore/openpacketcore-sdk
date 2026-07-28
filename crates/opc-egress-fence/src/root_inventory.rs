//! Pure root-cgroup inventory transition checks used by the Linux installer.

use std::num::NonZeroU64;

use opc_linux_gtpu_sys::BpfCgroupProgramQuery;

const CGROUP_BPF_PROGRAM_CAPACITY: usize = 64;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RootInventory {
    revision: NonZeroU64,
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
        if program_ids.len() > CGROUP_BPF_PROGRAM_CAPACITY
            || program_ids.contains(&0)
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
            revision: NonZeroU64::new(revision).expect("fixture revision is nonzero"),
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
            revision: NonZeroU64::new(revision).expect("fixture revision is nonzero"),
            attach_flags,
            program_ids,
            program_attach_flags,
        }
    }

    pub(crate) fn plan_direct_attach(
        &self,
        staged_program_id: u32,
    ) -> Result<DirectAttachPlan, InventoryError> {
        if staged_program_id == 0
            || self.program_ids.len() >= CGROUP_BPF_PROGRAM_CAPACITY
            || self.revision.get() == u64::MAX
        {
            return Err(InventoryError::CapacityOrRevision);
        }
        let expected_post_revision =
            NonZeroU64::new(self.revision.get() + 1).ok_or(InventoryError::CapacityOrRevision)?;
        Ok(DirectAttachPlan {
            before: self.clone(),
            staged_program_id,
            expected_post_revision,
        })
    }

    pub(crate) fn exact_match(&self, other: &Self) -> bool {
        self == other
    }

    pub(crate) const fn revision(&self) -> NonZeroU64 {
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
}

impl std::fmt::Debug for RootInventory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootInventory")
            .field("program_count", &self.program_ids.len())
            .field("revision_verified_nonzero", &true)
            .finish()
    }
}

pub(crate) struct DirectAttachPlan {
    before: RootInventory,
    staged_program_id: u32,
    expected_post_revision: NonZeroU64,
}

impl DirectAttachPlan {
    pub(crate) const fn expected_pre_revision(&self) -> NonZeroU64 {
        self.before.revision
    }

    pub(crate) const fn expected_post_revision(&self) -> NonZeroU64 {
        self.expected_post_revision
    }

    pub(crate) fn validate_post(&self, after: &RootInventory) -> Result<(), InventoryError> {
        if after.revision != self.expected_post_revision
            || after.attach_flags != BPF_F_ALLOW_MULTI
            || after.program_ids.len() != self.before.program_ids.len() + 1
            || after.program_attach_flags.len() != after.program_ids.len()
            || after.program_ids[..self.before.program_ids.len()] != self.before.program_ids
            || after.program_attach_flags[..self.before.program_attach_flags.len()]
                != self.before.program_attach_flags
            || after.program_ids.last().copied() != Some(self.staged_program_id)
            || after.program_attach_flags.last().copied() != Some(BPF_F_ALLOW_MULTI)
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
    CapacityOrRevision,
    ConcurrentMutation,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(count: usize) -> Vec<u32> {
        (1..=u32::try_from(count).expect("small fixture")).collect()
    }

    #[test]
    fn attach_capacity_boundaries_accept_post_count_64_only() {
        for pre_count in [62, 63] {
            let before = RootInventory::fixture(7, ids(pre_count));
            let staged = 10_001 + u32::try_from(pre_count).expect("small fixture");
            let plan = before
                .plan_direct_attach(staged)
                .expect("pre-count below 64");
            let mut after_ids = before.program_ids().to_vec();
            after_ids.push(staged);
            let after = RootInventory::fixture(8, after_ids);
            assert!(plan.validate_post(&after).is_ok());
        }

        let full = RootInventory::fixture(7, ids(64));
        assert_eq!(
            full.plan_direct_attach(10_064).expect_err("pre-count 64"),
            InventoryError::CapacityOrRevision
        );
        let over_cap = RootInventory::fixture(7, ids(65));
        assert_eq!(
            over_cap
                .plan_direct_attach(10_065)
                .expect_err("over-cap inventory"),
            InventoryError::CapacityOrRevision
        );
    }

    #[test]
    fn attach_requires_exact_revision_and_fifo_tail_insertion_readback() {
        let before = RootInventory::fixture(41, vec![3, 5, 7]);
        let plan = before.plan_direct_attach(11).expect("attach plan");
        assert_eq!(plan.expected_pre_revision().get(), 41);
        assert_eq!(plan.expected_post_revision().get(), 42);
        assert!(plan
            .validate_post(&RootInventory::fixture(42, vec![3, 5, 7, 11]))
            .is_ok());

        for mutated in [
            RootInventory::fixture(41, vec![3, 5, 7, 11]),
            RootInventory::fixture(43, vec![3, 5, 7, 11]),
            RootInventory::fixture(42, vec![11, 3, 5, 7]),
            RootInventory::fixture(42, vec![3, 5, 7]),
            RootInventory::fixture(42, vec![3, 5, 13, 11]),
            RootInventory::fixture(42, vec![3, 5, 7, 11, 13]),
        ] {
            assert_eq!(
                plan.validate_post(&mutated),
                Err(InventoryError::ConcurrentMutation)
            );
        }
    }

    #[test]
    fn attach_rejects_shared_or_per_program_flag_drift() {
        let before = RootInventory::fixture(41, vec![3, 5, 7]);
        let plan = before.plan_direct_attach(11).expect("attach plan");

        for mutated in [
            RootInventory::fixture_with_flags(42, 0, vec![3, 5, 7, 11], vec![BPF_F_ALLOW_MULTI; 4]),
            RootInventory::fixture_with_flags(
                42,
                BPF_F_ALLOW_MULTI,
                vec![3, 5, 7, 11],
                vec![BPF_F_ALLOW_MULTI, 0, BPF_F_ALLOW_MULTI, BPF_F_ALLOW_MULTI],
            ),
            RootInventory::fixture_with_flags(
                42,
                BPF_F_ALLOW_MULTI,
                vec![3, 5, 7, 11],
                vec![BPF_F_ALLOW_MULTI; 3],
            ),
            RootInventory::fixture_with_flags(
                42,
                BPF_F_ALLOW_MULTI,
                vec![3, 5, 7, 11],
                vec![BPF_F_ALLOW_MULTI; 5],
            ),
        ] {
            assert_eq!(
                plan.validate_post(&mutated),
                Err(InventoryError::ConcurrentMutation)
            );
        }
    }

    #[test]
    fn revision_wrap_and_zero_program_fail_before_mutation() {
        let before = RootInventory::fixture(u64::MAX, vec![]);
        assert_eq!(
            before.plan_direct_attach(1).expect_err("revision wrap"),
            InventoryError::CapacityOrRevision
        );
        let before = RootInventory::fixture(1, vec![]);
        assert_eq!(
            before.plan_direct_attach(0).expect_err("zero program"),
            InventoryError::CapacityOrRevision
        );
    }

    #[test]
    fn later_root_change_invalidates_health_projection() {
        let committed = RootInventory::fixture(12, vec![3, 5, 7, 19]);
        assert!(committed.exact_match(&committed));
        for changed in [
            RootInventory::fixture(13, vec![3, 5, 7, 19, 23]),
            RootInventory::fixture(13, vec![3, 5, 7]),
            RootInventory::fixture(13, vec![29, 3, 5, 7]),
            RootInventory::fixture(12, vec![19, 3, 7, 5]),
        ] {
            assert!(!committed.exact_match(&changed));
        }
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
