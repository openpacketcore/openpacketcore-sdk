//! Linux `BPF_PROG_RUN` adapter for the frozen egress-fence control ABI.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aya::programs::{SchedClassifier, TestRun, TestRunOptions};
use opc_egress_fence_common::{
    ControlCommand, ControlOperation, CurrentFenceToken, FenceCookieValue, FenceEntryState,
    FenceInspection, CONTROL_RESULT_APPLIED, EGRESS_FENCE_CONTROL_COMMAND_LEN,
    EGRESS_FENCE_INSPECT_BUFFER_LEN,
};

use crate::lifecycle::{
    AttachmentIdentity, BootClock, KernelControl, KernelCurrentFence, KernelCurrentPhase,
    KernelEntryState, KernelFailure, KernelFenceEntry, KernelInspection,
};

/// Integrity proof rerun before and after every admission or mutation.
///
/// Implementations retain the true-root descriptor and verify the exact
/// direct attachment, pinned programs, map schemas/IDs, immutable manifest,
/// and frozen endpoint configuration. A check may be expensive: ambiguity is
/// intentionally resolved before a protected send rather than cached.
pub(crate) trait InstallationIntegrity: Send + Sync {
    fn verify(&self, expected: AttachmentIdentity) -> Result<(), KernelFailure>;

    /// Enumerate the bounded canonical entries strictly superseded by the
    /// supplied exact live lifecycle token.
    fn superseded_entries(
        &self,
        expected: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<Vec<KernelFenceEntry>, KernelFailure>;
}

/// Suspend-aware Linux clock with a fallible syscall boundary.
#[derive(Debug, Default)]
pub(crate) struct LinuxBootClock;

#[async_trait]
impl BootClock for LinuxBootClock {
    fn now_boot_ns(&self) -> Result<u64, KernelFailure> {
        opc_linux_gtpu_sys::clock_gettime_boottime_ns().map_err(|_| KernelFailure::Clock)
    }

    async fn wait_poll(&self, duration: Duration) -> Result<(), KernelFailure> {
        let timer =
            opc_linux_gtpu_sys::BootTimeTimer::new(duration).map_err(|_| KernelFailure::Clock)?;
        let timer = tokio::io::unix::AsyncFd::new(timer).map_err(|_| KernelFailure::Clock)?;
        loop {
            let mut readiness = timer.readable().await.map_err(|_| KernelFailure::Clock)?;
            match readiness.try_io(|inner| inner.get_ref().consume_expirations()) {
                Ok(Ok(expirations)) if expirations != 0 => return Ok(()),
                Ok(_) => return Err(KernelFailure::Clock),
                Err(_would_block) => {}
            }
        }
    }
}

/// Exact adapter for the unattached mutation and synchronized-view programs.
pub(crate) struct LinuxKernelControl {
    mutation: Mutex<Option<SchedClassifier>>,
    view: Mutex<Option<SchedClassifier>>,
    integrity: Arc<dyn InstallationIntegrity>,
    root_cgroup_id: u64,
}

impl LinuxKernelControl {
    pub(crate) fn new(
        mutation: SchedClassifier,
        view: SchedClassifier,
        integrity: Arc<dyn InstallationIntegrity>,
        root_cgroup_id: u64,
    ) -> Result<Self, KernelFailure> {
        if root_cgroup_id == 0 {
            return Err(KernelFailure::Readback);
        }
        Ok(Self {
            mutation: Mutex::new(Some(mutation)),
            view: Mutex::new(Some(view)),
            integrity,
            root_cgroup_id,
        })
    }

    fn command(
        &self,
        operation: ControlOperation,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<ControlCommand, KernelFailure> {
        ControlCommand::new(
            operation,
            self.root_cgroup_id,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            expected_epoch,
        )
        .ok_or(KernelFailure::Mutation)
    }

    fn mutate(
        &self,
        identity: AttachmentIdentity,
        command: ControlCommand,
    ) -> Result<(), KernelFailure> {
        self.integrity.verify(identity)?;
        self.verify_private_program_fds(KernelFailure::Mutation)?;
        let input = command.encode();
        let mut output = [0_u8; EGRESS_FENCE_CONTROL_COMMAND_LEN];
        let mutation = self.mutation.lock().map_err(|_| KernelFailure::Mutation)?;
        let result = mutation
            .as_ref()
            .ok_or(KernelFailure::Mutation)?
            .test_run(TestRunOptions {
                data_in: Some(&input),
                data_out: Some(&mut output),
                repeat: 1,
                ..TestRunOptions::default()
            })
            .map_err(|_| KernelFailure::Mutation)?;
        drop(mutation);
        if result.return_value != CONTROL_RESULT_APPLIED
            || result.data_size_out != EGRESS_FENCE_CONTROL_COMMAND_LEN as u32
            || result.ctx_size_out != 0
            || output != input
        {
            return Err(KernelFailure::Mutation);
        }
        self.verify_private_program_fds(KernelFailure::Mutation)?;
        self.integrity.verify(identity)
    }

    fn exact_entry(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        self.inspect(identity, Some((socket_cookie, lifecycle_token)))?
            .entry
            .ok_or(KernelFailure::Readback)
    }

    fn exact_current(
        &self,
        identity: AttachmentIdentity,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        Ok(self.inspect(identity, None)?.current)
    }

    fn verify_private_program_fds(&self, failure: KernelFailure) -> Result<(), KernelFailure> {
        {
            let mutation = self.mutation.lock().map_err(|_| failure)?;
            if mutation.is_none() {
                return Err(failure);
            }
        }
        {
            let view = self.view.lock().map_err(|_| failure)?;
            if view.is_none() {
                return Err(failure);
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for LinuxKernelControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LinuxKernelControl(<redacted>)")
    }
}

impl KernelControl for LinuxKernelControl {
    #[cfg(test)]
    fn test_drop_private_mutation_program_fd(&self) -> Result<(), KernelFailure> {
        let mut mutation = self.mutation.lock().map_err(|_| KernelFailure::Mutation)?;
        let Some(program) = mutation.take() else {
            return Err(KernelFailure::Readback);
        };
        drop(program);
        Ok(())
    }

    #[cfg(test)]
    fn test_drop_private_view_program_fd(&self) -> Result<(), KernelFailure> {
        let mut view = self.view.lock().map_err(|_| KernelFailure::Readback)?;
        let Some(program) = view.take() else {
            return Err(KernelFailure::Readback);
        };
        drop(program);
        Ok(())
    }

    fn inspect(
        &self,
        identity: AttachmentIdentity,
        entry_key: Option<(u64, u64)>,
    ) -> Result<KernelInspection, KernelFailure> {
        self.integrity.verify(identity)?;
        self.verify_private_program_fds(KernelFailure::Readback)?;
        let (socket_cookie, lifecycle_token) = entry_key.unwrap_or((0, 0));
        let command = self.command(
            ControlOperation::Inspect,
            socket_cookie,
            lifecycle_token,
            0,
            0,
        )?;
        let input = command
            .encode_inspect_request()
            .ok_or(KernelFailure::Readback)?;
        let mut output = [0_u8; EGRESS_FENCE_INSPECT_BUFFER_LEN];
        let view = self.view.lock().map_err(|_| KernelFailure::Readback)?;
        let result = view
            .as_ref()
            .ok_or(KernelFailure::Readback)?
            .test_run(TestRunOptions {
                data_in: Some(&input),
                data_out: Some(&mut output),
                repeat: 1,
                ..TestRunOptions::default()
            })
            .map_err(|_| KernelFailure::Readback)?;
        drop(view);
        if result.return_value != CONTROL_RESULT_APPLIED
            || result.data_size_out != EGRESS_FENCE_INSPECT_BUFFER_LEN as u32
            || result.ctx_size_out != 0
        {
            return Err(KernelFailure::Readback);
        }
        let inspection = FenceInspection::decode(&output).ok_or(KernelFailure::Readback)?;
        if inspection.mutation().in_flight_claim() != 0 {
            return Err(KernelFailure::Readback);
        }
        let current = decode_current(inspection.current())?;
        let entry = match (entry_key, inspection.entry()) {
            (None, None) => None,
            (Some(expected), Some(value)) => Some(decode_entry(value, expected)?),
            // A keyed inspection must represent canonical absence so a
            // successful reclaim can be proved by exact post-delete readback.
            (Some(_), None) => None,
            // An unrequested entry is never a canonical current-only view.
            (None, Some(_)) => return Err(KernelFailure::Readback),
        };
        self.verify_private_program_fds(KernelFailure::Readback)?;
        self.integrity.verify(identity)?;
        Ok(KernelInspection { current, entry })
    }

    fn publish_lifecycle(
        &self,
        identity: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        let command = self.command(ControlOperation::PublishLifecycle, 0, lifecycle_token, 0, 0)?;
        self.mutate(identity, command)?;
        self.exact_current(identity)
    }

    fn cleanup_superseded(
        &self,
        identity: AttachmentIdentity,
        lifecycle_token: u64,
    ) -> Result<(), KernelFailure> {
        let current = self.exact_current(identity)?;
        if current.phase != KernelCurrentPhase::LifecycleOpen
            || current.lifecycle_token != lifecycle_token
            || current.registered_socket_cookie != 0
        {
            return Err(KernelFailure::Readback);
        }
        for entry in self
            .integrity
            .superseded_entries(identity, lifecycle_token)?
        {
            if entry.socket_cookie == 0
                || entry.lifecycle_token == 0
                || entry.lifecycle_token >= lifecycle_token
                || entry.control_epoch == 0
            {
                return Err(KernelFailure::Readback);
            }
            let command = self.command(
                ControlOperation::Reclaim,
                entry.socket_cookie,
                entry.lifecycle_token,
                0,
                entry.control_epoch,
            )?;
            self.mutate(identity, command)?;
            if self
                .inspect(identity, Some((entry.socket_cookie, entry.lifecycle_token)))?
                .entry
                .is_some()
            {
                return Err(KernelFailure::Readback);
            }
        }
        let after = self.exact_current(identity)?;
        if after != current {
            return Err(KernelFailure::Readback);
        }
        Ok(())
    }

    fn publish_retirement(
        &self,
        identity: AttachmentIdentity,
        retirement_lifecycle_token: u64,
    ) -> Result<KernelCurrentFence, KernelFailure> {
        let command = self.command(
            ControlOperation::PublishRetirement,
            0,
            retirement_lifecycle_token,
            0,
            0,
        )?;
        self.mutate(identity, command)?;
        self.exact_current(identity)
    }

    fn register_closed(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        let command = self.command(
            ControlOperation::Register,
            socket_cookie,
            lifecycle_token,
            0,
            0,
        )?;
        self.mutate(identity, command)?;
        self.exact_entry(identity, socket_cookie, lifecycle_token)
    }

    fn activate(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        let command = self.command(
            ControlOperation::Activate,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            expected_epoch,
        )?;
        self.mutate(identity, command)?;
        self.exact_entry(identity, socket_cookie, lifecycle_token)
    }

    fn refresh(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        deadline_boot_ns: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        let command = self.command(
            ControlOperation::Refresh,
            socket_cookie,
            lifecycle_token,
            deadline_boot_ns,
            expected_epoch,
        )?;
        self.mutate(identity, command)?;
        self.exact_entry(identity, socket_cookie, lifecycle_token)
    }

    fn close(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<KernelFenceEntry, KernelFailure> {
        let command = self.command(
            ControlOperation::Close,
            socket_cookie,
            lifecycle_token,
            0,
            expected_epoch,
        )?;
        self.mutate(identity, command)?;
        self.exact_entry(identity, socket_cookie, lifecycle_token)
    }

    fn reclaim(
        &self,
        identity: AttachmentIdentity,
        socket_cookie: u64,
        lifecycle_token: u64,
        expected_epoch: u64,
    ) -> Result<(), KernelFailure> {
        let command = self.command(
            ControlOperation::Reclaim,
            socket_cookie,
            lifecycle_token,
            0,
            expected_epoch,
        )?;
        self.mutate(identity, command)?;
        let inspection = self.inspect(identity, Some((socket_cookie, lifecycle_token)))?;
        if inspection.entry.is_some() {
            return Err(KernelFailure::Readback);
        }
        Ok(())
    }
}

fn decode_current(current: CurrentFenceToken) -> Result<KernelCurrentFence, KernelFailure> {
    let lifecycle_token = current.durable_fence_token();
    let registered_socket_cookie = current.registered_socket_cookie();
    let phase = if lifecycle_token == 0 {
        if registered_socket_cookie != 0 {
            return Err(KernelFailure::Readback);
        }
        KernelCurrentPhase::Uninitialized
    } else if current.is_lifecycle_open() {
        KernelCurrentPhase::LifecycleOpen
    } else if current.is_retirement_closed() {
        KernelCurrentPhase::RetirementClosed
    } else {
        return Err(KernelFailure::Readback);
    };
    Ok(KernelCurrentFence {
        phase,
        lifecycle_token,
        registered_socket_cookie,
    })
}

fn decode_entry(
    value: FenceCookieValue,
    expected: (u64, u64),
) -> Result<KernelFenceEntry, KernelFailure> {
    let key = value.key();
    if (key.socket_cookie(), key.durable_fence_token()) != expected {
        return Err(KernelFailure::Readback);
    }
    let entry = value.entry();
    let state = match entry.state() {
        FenceEntryState::InitialClosed => KernelEntryState::InitialClosed,
        FenceEntryState::Active => KernelEntryState::Active,
        FenceEntryState::TerminalClosed => KernelEntryState::TerminalClosed,
        FenceEntryState::Reclaiming => KernelEntryState::Reclaiming,
    };
    Ok(KernelFenceEntry {
        state,
        socket_cookie: key.socket_cookie(),
        lifecycle_token: key.durable_fence_token(),
        deadline_boot_ns: entry.deadline_boot_ns(),
        control_epoch: entry.control_epoch(),
    })
}
