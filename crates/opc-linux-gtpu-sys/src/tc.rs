//! Complete tc inventories. Classifier summaries never authorize deletion.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod artifact;
mod artifact_batch;
mod containment;
pub use artifact::{
    retire_artifacts, retire_artifacts_checked, ArtifactInventory, ArtifactMap, ArtifactProgram,
    ArtifactSpec, InstalledArtifact, LocalEffectsRetired, RetiredArtifact,
};
mod scope;
#[cfg(test)]
mod tests;
mod topology;
mod wire;
pub use scope::{
    ContainedScope, ContainmentBank, ContainmentInspection, LocalHookSpec, LocalKernelScope,
    LocalScopeSpec, PinDirectory, PinnedIdentity, PinnedObject, ScopeError, TcScopeInspection,
};
#[cfg(test)]
mod scope_tests;

/// One direction of a device's clsact qdisc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcHook {
    /// Frames entering the device.
    Ingress,
    /// Frames leaving the device.
    Egress,
}

impl TcHook {
    const fn parent(self) -> u32 {
        match self {
            Self::Ingress => crate::TC_H_CLSACT_INGRESS,
            Self::Egress => crate::TC_H_CLSACT_EGRESS,
        }
    }
}

/// Exact filter coordinates, including the Ethernet protocol in host order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcSlot {
    ifindex: u32,
    hook: TcHook,
    chain: u32,
    protocol: u16,
    priority: u16,
    handle: u32,
}

impl TcSlot {
    /// Validate the coordinates of a single filter, never a wildcard deletion.
    pub fn new(
        ifindex: u32,
        hook: TcHook,
        chain: u32,
        protocol: u16,
        priority: u16,
        handle: u32,
    ) -> io::Result<Self> {
        if ifindex == 0
            || ifindex > i32::MAX as u32
            || protocol == 0
            || priority == 0
            || handle == 0
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tc_exact_slot"));
        }
        Ok(Self {
            ifindex,
            hook,
            chain,
            protocol,
            priority,
            handle,
        })
    }
    /// Device index in the client's network namespace.
    pub const fn ifindex(self) -> u32 {
        self.ifindex
    }
    /// Direction within clsact.
    pub const fn hook(self) -> TcHook {
        self.hook
    }
    /// Classifier chain.
    pub const fn chain(self) -> u32 {
        self.chain
    }
    /// Ethernet protocol in host byte order.
    pub const fn protocol(self) -> u16 {
        self.protocol
    }
    /// Classifier priority.
    pub const fn priority(self) -> u16 {
        self.priority
    }
    /// Exact filter handle; zero only for a kernel classifier summary.
    pub const fn handle(self) -> u32 {
        self.handle
    }
}

/// Complete direct-action BPF metadata from one classifier.
///
/// This identifies the attachment, not the origin or ownership of its program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcBpfIdentity {
    program_id: u32,
    name: Vec<u8>,
    tag: [u8; 8],
    classifier_flags: u32,
}

impl TcBpfIdentity {
    /// Program ID observed at this exact tc attachment. Fresh readiness also
    /// retains the load descriptor; crash retirement requires writer exclusion
    /// and a fresh comparison of the complete attachment before deletion.
    pub const fn program_id(&self) -> u32 {
        self.program_id
    }
    /// Full tc name, without its terminating NUL.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Kernel program tag.
    pub const fn tag(&self) -> &[u8; 8] {
        &self.tag
    }
    /// General classifier flags, including hardware/software disposition.
    pub const fn classifier_flags(&self) -> u32 {
        self.classifier_flags
    }
}

/// Terminal action used by one containment filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcVerdict {
    /// Accept the frame without consulting later filters.
    Pass,
    /// Drop the frame without consulting later filters.
    Drop,
}

/// One software-only matchall filter with a single terminal gact action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcGactIdentity {
    cookie: [u8; 16],
    verdict: TcVerdict,
    action_index: u32,
}

impl TcGactIdentity {
    /// Exact configured ownership cookie.
    pub const fn cookie(&self) -> &[u8; 16] {
        &self.cookie
    }
    /// Terminal verdict.
    pub const fn verdict(&self) -> TcVerdict {
        self.verdict
    }
    /// Kernel-assigned action index.
    pub const fn action_index(&self) -> u32 {
        self.action_index
    }
}

/// An immutable filter observation from a complete, authenticated kernel dump.
///
/// Fields cannot be supplied by callers. A handle-zero classifier summary is
/// retained for inventory and never accepted by [`TcClient::delete_exact`].
#[derive(Debug, Clone)]
pub struct TcFilterIdentity {
    entry: wire::Entry,
    origin: Arc<()>,
}

impl TcFilterIdentity {
    /// Exact observed coordinates.
    pub const fn slot(&self) -> TcSlot {
        self.entry.slot
    }
    /// Classifier kind, without its terminating NUL.
    pub fn kind(&self) -> &[u8] {
        &self.entry.kind
    }
    /// Whether this record describes a classifier rather than a filter.
    pub const fn is_summary(&self) -> bool {
        self.entry.slot.handle == 0
    }
    /// Known pure direct-action BPF shape, if all configuration is understood.
    pub fn bpf(&self) -> Option<&TcBpfIdentity> {
        self.entry.bpf.as_ref()
    }
    /// Known isolated, software-only terminal gact shape, if fully understood.
    pub fn gact(&self) -> Option<&TcGactIdentity> {
        self.entry.gact.as_ref()
    }
}

/// A bounded inventory finalized only by an uninterrupted multipart completion.
#[derive(Debug)]
pub struct TcFilterDump {
    entries: Vec<TcFilterIdentity>,
}

impl TcFilterDump {
    /// All classifier summaries and attached filters, including foreign kinds.
    pub fn entries(&self) -> &[TcFilterIdentity] {
        &self.entries
    }
    /// Look up one exact filter position in this complete inventory.
    pub fn find(&self, slot: TcSlot) -> Option<&TcFilterIdentity> {
        self.entries.iter().find(|entry| entry.slot() == slot)
    }
}

/// Serial tc client bound to the network namespace in which it was opened.
///
/// Each exchange has a one-second deadline. Deletion rechecks the entire
/// inventory, deletes one nonzero handle, and proves its absence afterward.
/// Callers must exclude concurrent writers across this sequence; rtnetlink has
/// no atomic compare-and-delete primitive. This layer grants no ownership.
/// A failed exchange discards its socket and queued replies. The next attempt
/// opens a fresh socket in the same network namespace.
pub struct TcClient {
    transport: Option<Box<dyn Transport>>,
    open_transport: OpenTransport,
    sequence: u32,
    origin: Arc<()>,
    attempt_deadline: Option<Instant>,
}

impl std::fmt::Debug for TcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TcClient")
    }
}

impl TcClient {
    /// Exclusively attach one retained classifier FD with direct action and
    /// software execution, then compare its fresh exact ID/tag/name readback.
    /// This never replaces an occupant or creates an auto-detaching link.
    pub fn create_classifier(
        &mut self,
        slot: TcSlot,
        program: &crate::bpf::ProgramHandle,
        name: &str,
    ) -> io::Result<TcFilterIdentity> {
        self.exchange(|client| client.create_classifier_inner(slot, program, name))
    }

    fn create_classifier_inner(
        &mut self,
        slot: TcSlot,
        program: &crate::bpf::ProgramHandle,
        name: &str,
    ) -> io::Result<TcFilterIdentity> {
        program.recheck().map_err(|_| wire::conflict())?;
        let identity = program.identity();
        if identity.program_type != 3
            || identity.ifindex != 0
            || self.dump(slot.ifindex, slot.hook)?.find(slot).is_some()
        {
            return Err(wire::conflict());
        }
        let sequence = self.next_sequence()?;
        let request = wire::classifier_request(
            slot,
            program.raw_fd(),
            name,
            sequence,
            self.transport()?.port_id(),
        )?;
        let deadline = self.exchange_deadline()?;
        program.recheck().map_err(|_| wire::conflict())?;
        self.transport()?.send(&request)?;
        let mut buffer = vec![0; 65_536];
        let length = self.transport()?.receive(&mut buffer, deadline)?;
        wire::ack(&buffer[..length], &request)?;
        let dump = self.dump(slot.ifindex, slot.hook)?;
        let actual = dump.find(slot).ok_or_else(wire::conflict)?;
        if actual.bpf().is_none_or(|observed| {
            observed.program_id != identity.id
                || observed.tag != identity.tag
                || observed.name != name.as_bytes()
                || !containment::software_only(actual)
        }) {
            return Err(wire::conflict());
        }
        program.recheck().map_err(|_| wire::conflict())?;
        Ok(actual.clone())
    }
    /// Open a serial, authenticated route-netlink client in the current netns.
    pub fn new() -> io::Result<Self> {
        // Retaining the namespace descriptor also prevents inode reuse. A
        // retry must not silently follow a caller that moved to another netns.
        #[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
        let namespace = std::fs::File::open("/proc/thread-self/ns/net")?;
        let mut open_transport: OpenTransport = Box::new(move || {
            #[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
            {
                use std::os::unix::fs::MetadataExt;
                let held = namespace.metadata()?;
                let current = std::fs::metadata("/proc/thread-self/ns/net")?;
                if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "tc_namespace"));
                }
            }
            Ok(Box::new(crate::open_route_netlink_socket()?))
        });
        Ok(Self {
            transport: Some(open_transport()?),
            open_transport,
            sequence: 0,
            origin: Arc::new(()),
            attempt_deadline: None,
        })
    }

    fn exchange<T>(&mut self, operation: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T> {
        if self.transport.is_none() {
            self.transport = Some((self.open_transport)()?);
            self.sequence = 0;
        }
        let result = operation(self);
        if result.is_err() {
            // Closing is unconditional, including malformed multipart data
            // and uncertain ACKs. Reopening may fail without retaining the
            // poisoned socket; a later attempt can try opening again.
            self.transport = None;
        }
        result
    }

    fn transport(&mut self) -> io::Result<&mut (dyn Transport + '_)> {
        match self.transport.as_mut() {
            Some(transport) => Ok(transport.as_mut()),
            None => Err(wire::invalid()),
        }
    }

    fn next_sequence(&mut self) -> io::Result<u32> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(wire::invalid)?;
        Ok(self.sequence)
    }

    fn exchange_deadline(&self) -> io::Result<Instant> {
        let now = Instant::now();
        let deadline = self
            .attempt_deadline
            .map_or(now + Duration::from_secs(1), |attempt| {
                attempt.min(now + Duration::from_secs(1))
            });
        if now >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "tc_attempt"));
        }
        Ok(deadline)
    }

    /// Return a complete inventory across every protocol, priority and chain.
    pub fn dump(&mut self, ifindex: u32, hook: TcHook) -> io::Result<TcFilterDump> {
        self.exchange(|client| client.dump_inner(ifindex, hook))
    }

    fn dump_inner(&mut self, ifindex: u32, hook: TcHook) -> io::Result<TcFilterDump> {
        let sequence = self.next_sequence()?;
        let port = self.transport()?.port_id();
        let request = wire::dump_request(ifindex, hook, sequence, port)?;
        let deadline = self.exchange_deadline()?;
        self.transport()?.send(&request)?;
        let mut parser = wire::Dump::new(ifindex, hook, sequence, port);
        let mut buffer = vec![0; 65_536];
        while !parser.is_done() {
            let length = self.transport()?.receive(&mut buffer, deadline)?;
            parser.consume(&buffer[..length])?;
        }
        Ok(TcFilterDump {
            entries: parser
                .finish()?
                .into_iter()
                .map(|entry| TcFilterIdentity {
                    entry,
                    origin: Arc::clone(&self.origin),
                })
                .collect(),
        })
    }

    /// Recheck, delete, and read back the absence of one exact filter.
    ///
    /// A changed occupant, incomplete inspection, summary, or identity from a
    /// different client refuses before deletion. An uncertain ACK returns an
    /// error; it never proves removal. The exclusive writer guard must remain
    /// held until the caller has reconciled that uncertainty.
    pub fn delete_exact(&mut self, expected: &TcFilterIdentity) -> io::Result<()> {
        self.exchange(|client| client.delete_exact_inner(expected))
    }

    fn delete_exact_inner(&mut self, expected: &TcFilterIdentity) -> io::Result<()> {
        if !Arc::ptr_eq(&self.origin, &expected.origin) || expected.is_summary() {
            return Err(wire::conflict());
        }
        let slot = expected.slot();
        let current = self.dump(slot.ifindex, slot.hook)?;
        if current.find(slot).map(|item| &item.entry) != Some(&expected.entry) {
            return Err(wire::conflict());
        }
        let sequence = self.next_sequence()?;
        let request =
            wire::delete_request(slot, expected.kind(), sequence, self.transport()?.port_id())?;
        let deadline = self.exchange_deadline()?;
        self.transport()?.send(&request)?;
        let mut buffer = vec![0; 65_536];
        let length = self.transport()?.receive(&mut buffer, deadline)?;
        wire::ack(&buffer[..length], &request)?;
        if self.dump(slot.ifindex, slot.hook)?.find(slot).is_some() {
            return Err(wire::conflict());
        }
        Ok(())
    }

    /// Exclusively create and read back one software-only terminal gact filter.
    ///
    /// This never replaces an existing filter or binds an existing action. The
    /// caller must hold its writer exclusion guard and prove hook coverage;
    /// this primitive alone is not evidence of packet containment.
    pub fn create_gact(
        &mut self,
        slot: TcSlot,
        cookie: [u8; 16],
        verdict: TcVerdict,
    ) -> io::Result<TcFilterIdentity> {
        self.exchange(|client| client.create_gact_inner(slot, cookie, verdict))
    }

    fn create_gact_inner(
        &mut self,
        slot: TcSlot,
        cookie: [u8; 16],
        verdict: TcVerdict,
    ) -> io::Result<TcFilterIdentity> {
        let sequence = self.next_sequence()?;
        let request =
            wire::gact_request(slot, cookie, verdict, sequence, self.transport()?.port_id())?;
        let deadline = self.exchange_deadline()?;
        self.transport()?.send(&request)?;
        let mut buffer = vec![0; 65_536];
        let length = self.transport()?.receive(&mut buffer, deadline)?;
        wire::ack(&buffer[..length], &request)?;
        let dump = self.dump(slot.ifindex, slot.hook)?;
        let actual = dump.find(slot).ok_or_else(wire::conflict)?;
        match actual.gact() {
            Some(value) if value.cookie == cookie && value.verdict == verdict => Ok(actual.clone()),
            _ => Err(wire::conflict()),
        }
    }
}

type OpenTransport = Box<dyn FnMut() -> io::Result<Box<dyn Transport>> + Send>;

trait Transport: Send {
    fn port_id(&self) -> u32;
    fn send(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn receive(&mut self, buffer: &mut [u8], deadline: Instant) -> io::Result<usize>;
}

impl Transport for crate::NetlinkSocket {
    fn port_id(&self) -> u32 {
        self.port_id()
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if crate::send_message(self, bytes)? != bytes.len() {
            return Err(wire::invalid());
        }
        Ok(())
    }
    fn receive(&mut self, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "tc_exchange"));
            }
            match crate::receive_kernel_message(self, buffer) {
                Ok(0) => return Err(wire::invalid()),
                Ok(length) => return Ok(length),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => return Err(error),
            }
        }
    }
}
