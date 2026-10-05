//! Backend-owned IPv4 control socket, serialized with attachment mutation.

use std::sync::Weak;

use super::*;
use crate::control_port::{
    GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlSendPlan,
};

/// One of the two backend-owned queues that tc hands authorized G-PDUs to
/// instead of decapsulating them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum HandOffQueue {
    /// Over-MTU Don't Fragment packets; see
    /// [`opc_gtpu_ebpf_common::GTPU_PACKET_TOO_BIG_QUEUE_PORT`].
    #[default]
    PacketTooBig,
    /// Inner fragments; see
    /// [`opc_gtpu_ebpf_common::GTPU_INNER_FRAGMENT_QUEUE_PORT`].
    InnerFragment,
}

impl HandOffQueue {
    const fn other(self) -> Self {
        match self {
            Self::PacketTooBig => Self::InnerFragment,
            Self::InnerFragment => Self::PacketTooBig,
        }
    }
}

/// Receive at most one datagram from the two hand-off queues, taking them in
/// turn.
///
/// `next` is the queue tried first. The queue that answers, with a datagram
/// or with an error, gives the next turn to the other one. A backlog or a
/// persistent failure in one hand-off queue therefore cannot keep the
/// consumer from the other: each is served at least every second time while
/// it has a datagram.
pub(super) fn receive_hand_off<T, E>(
    next: &mut HandOffQueue,
    mut receive: impl FnMut(HandOffQueue) -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    let first = *next;
    for queue in [first, first.other()] {
        match receive(queue) {
            Ok(None) => {}
            answered => {
                *next = queue.other();
                return answered;
            }
        }
    }
    Ok(None)
}

/// Datagrams the shared queue may be served in a row before the hand-off
/// queues get one turn.
///
/// The shared queue carries Echo, so it keeps priority: a backlog of
/// hand-offs delays it by at most one hand-off datagram per run. The run is
/// bounded because tc passes Echo and unknown-TEID G-PDUs to the shared
/// queue from any source. With absolute priority, sustained input there
/// would keep the consumer from both hand-off queues, and the inner
/// fragments and over-MTU packets waiting in them would overflow.
pub(super) const SHARED_QUEUE_RUN: u8 = 8;

/// The order in which one attachment's three backend-owned queues are
/// served: the shared queue first, for at most [`SHARED_QUEUE_RUN`]
/// datagrams in a row, then one turn for the two hand-off queues, which
/// alternate between themselves.
#[derive(Debug, Default)]
pub(super) struct DownlinkServiceOrder {
    /// The hand-off queue that the next hand-off turn tries first.
    next_hand_off: HandOffQueue,
    /// Answers taken from the shared queue since the hand-off queues last had
    /// a turn.
    shared_run: u8,
}

impl DownlinkServiceOrder {
    /// Receive at most one datagram. Returns it with whether a hand-off
    /// queue delivered it, or `None` when all three queues are empty.
    ///
    /// The hand-off queues get a turn when the shared queue is empty, and
    /// after every full run of the shared queue. A hand-off queue that holds
    /// a datagram is therefore served at least once in every
    /// `2 * (SHARED_QUEUE_RUN + 1)` calls, whatever arrives on the shared
    /// queue. A turn that finds both hand-off queues empty costs the shared
    /// queue nothing: it is served in the same call. An error from the
    /// shared queue counts toward its run, so a queue that keeps failing
    /// cannot keep the consumer from the hand-offs either.
    pub(super) fn receive<T, E>(
        &mut self,
        mut shared: impl FnMut() -> Result<Option<T>, E>,
        mut hand_off: impl FnMut(HandOffQueue) -> Result<Option<T>, E>,
    ) -> Result<Option<(T, bool)>, E> {
        if self.shared_run >= SHARED_QUEUE_RUN {
            self.shared_run = 0;
            if let Some(datagram) = receive_hand_off(&mut self.next_hand_off, &mut hand_off)? {
                return Ok(Some((datagram, true)));
            }
        }
        match shared() {
            Ok(Some(datagram)) => {
                self.shared_run = self.shared_run.saturating_add(1);
                Ok(Some((datagram, false)))
            }
            Ok(None) => {
                self.shared_run = 0;
                let datagram = receive_hand_off(&mut self.next_hand_off, &mut hand_off)?;
                Ok(datagram.map(|datagram| (datagram, true)))
            }
            Err(error) => {
                self.shared_run = self.shared_run.saturating_add(1);
                Err(error)
            }
        }
    }
}

#[derive(Default)]
pub(super) struct ControlSocketState {
    socket: Option<crate::GtpuReassemblySocket>,
    /// Dedicated queue for tc-steered over-MTU G-PDUs; see
    /// [`opc_gtpu_ebpf_common::GTPU_PACKET_TOO_BIG_QUEUE_PORT`].
    too_big_socket: Option<crate::GtpuReassemblySocket>,
    /// Dedicated queue for tc-steered inner-fragment G-PDUs; see
    /// [`opc_gtpu_ebpf_common::GTPU_INNER_FRAGMENT_QUEUE_PORT`].
    inner_fragment_socket: Option<crate::GtpuReassemblySocket>,
    /// Service order of the three queues above.
    service_order: DownlinkServiceOrder,
    retired: bool,
    /// Value-free counters of this registration's downlink consumer.
    downlink_counters: crate::GtpuDownlinkCounters,
    /// Per-registration in-tunnel Packet Too Big rate limit.
    too_big_limiter: crate::reassembly::PacketTooBigLimiter,
    /// Per-destination inner fragmentation budgets and Identification
    /// sequences of this registration.
    inner_fragment_budget: crate::reassembly::InnerFragmentBudget,
}

impl ControlSocketState {
    #[cfg(test)]
    pub(super) fn is_unopened(&self) -> bool {
        self.socket.is_none()
    }

    #[cfg(test)]
    pub(super) fn with_inner_fragment_limit(limit: crate::GtpuInnerFragmentRateLimit) -> Self {
        Self {
            inner_fragment_budget: crate::reassembly::InnerFragmentBudget::new(limit),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn downlink_counters(&self) -> crate::GtpuDownlinkCounters {
        self.downlink_counters
    }

    pub(super) fn retire(&mut self) {
        self.retired = true;
        self.socket = None;
        self.too_big_socket = None;
        self.inner_fragment_socket = None;
    }
}

type SocketSlot = Mutex<ControlSocketState>;

struct BackendControlPort {
    backend: Weak<EbpfGtpuDataplaneBackendInner>,
    socket: Weak<SocketSlot>,
    ifindex: u32,
}

impl fmt::Debug for BackendControlPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EbpfGtpuControlPort(<redacted>)")
    }
}

impl BackendControlPort {
    fn with_socket<T>(
        &self,
        operation: impl FnOnce(&crate::GtpuReassemblySocket) -> Result<T, GtpuControlPortError>,
    ) -> Result<T, GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            let socket = state
                .socket
                .as_ref()
                .ok_or(GtpuControlPortError::Unavailable)?;
            operation(socket)
        })
    }

    /// Run one operation under this attachment's exclusion with the exact live
    /// socket state and the attachment's authority scope.
    ///
    /// Exclusion is per attachment: the registration's socket slot. PDP
    /// installs and removals on this or any other attachment never block the
    /// shared queue, because every authorization reads the commit-last graph
    /// exactly like tc. Device removal holds this slot across its hook change
    /// and retires it, and a replaced or fenced registration is detected under
    /// the slot before anything is received or sent.
    fn with_attachment<T>(
        &self,
        operation: impl FnOnce(
            &EbpfGtpuDataplaneBackend,
            &mut ControlSocketState,
            super::reassembled_downlink::DownlinkAuthorityScope,
        ) -> Result<T, GtpuControlPortError>,
    ) -> Result<T, GtpuControlPortError> {
        let unavailable = || GtpuControlPortError::Unavailable;
        let inner = self.backend.upgrade().ok_or_else(unavailable)?;
        let backend = EbpfGtpuDataplaneBackend { inner };
        let slot = self.socket.upgrade().ok_or_else(unavailable)?;
        let registration = self.current_registration(&backend, &slot);
        let Some((name, scope)) = registration else {
            // Lock order is slot before device registry; never hold both here.
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        };
        if backend.inner.runtime.ifindex_by_name(&name).ok() != Some(self.ifindex)
            || !backend
                .inner
                .runtime
                .pdp_readback_datapath_usable(self.ifindex)
        {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        let mut state = slot.lock().map_err(|_| unavailable())?;
        if state.retired || state.socket.is_none() {
            return Err(unavailable());
        }
        // Revalidate under the slot: removal retires it while holding it, so
        // an operation that passes here linearizes before any removal effect.
        if self.current_registration(&backend, &slot).is_none() {
            state.retire();
            return Err(unavailable());
        }
        operation(&backend, &mut state, scope)
    }

    /// Return the exact live registration for this port, or `None` when the
    /// attachment was removed, replaced, fenced or is otherwise unusable.
    fn current_registration(
        &self,
        backend: &EbpfGtpuDataplaneBackend,
        slot: &Arc<SocketSlot>,
    ) -> Option<(String, super::reassembled_downlink::DownlinkAuthorityScope)> {
        let devices = backend.devices().ok()?;
        let managed = devices.get(&self.ifindex)?;
        if !Arc::ptr_eq(slot, &managed.control_socket)
            || managed.cleanup_only
            || managed.successor_pending
        {
            return None;
        }
        let scope = super::reassembled_downlink::DownlinkAuthorityScope {
            ifindex: self.ifindex,
            ordinary_local_ipv4: managed.local_ip,
            grouped_config: managed.grouped.and_then(|grouped| {
                grouped_device_config(grouped.device_id, self.ifindex, grouped.local_endpoints)
            }),
        };
        if managed.grouped.is_some() && scope.grouped_config.is_none() {
            return None;
        }
        Some((managed.name.clone(), scope))
    }
}

impl GtpuControlPort for BackendControlPort {
    fn try_receive_datagram(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<GtpuControlDatagram>, GtpuControlPortError> {
        self.with_socket(|socket| socket.try_receive_datagram(maximum_bytes))
    }

    fn send_control_response(
        &self,
        plan: GtpuControlSendPlan,
    ) -> Result<usize, GtpuControlPortError> {
        self.with_socket(|socket| socket.send_control_response(plan))
    }

    fn try_receive_downlink(
        &self,
        maximum_bytes: usize,
    ) -> Result<Option<crate::GtpuDownlinkEvent>, GtpuControlPortError> {
        self.with_attachment(|backend, state, scope| {
            let socket = state
                .socket
                .as_ref()
                .ok_or(GtpuControlPortError::Unavailable)?;
            // The shared queue (Echo, reassembled G-PDUs) is served first;
            // tc-steered G-PDUs wait in their own queues and can never crowd
            // it out. Its priority holds for a bounded run, after which the
            // hand-off queues get one turn, so sustained input on the shared
            // queue cannot starve them. The two hand-off queues take their
            // turns alternately, so a backlog of inner fragments cannot keep
            // the consumer from an over-MTU packet, or the reverse.
            let (too_big, inner_fragment) = (
                state.too_big_socket.as_ref(),
                state.inner_fragment_socket.as_ref(),
            );
            let received = state.service_order.receive(
                || socket.try_receive_datagram(maximum_bytes),
                |queue| {
                    let queue = match queue {
                        HandOffQueue::PacketTooBig => too_big,
                        HandOffQueue::InnerFragment => inner_fragment,
                    };
                    queue.map_or(Ok(None), |queue| queue.try_receive_datagram(maximum_bytes))
                },
            )?;
            let Some((datagram, steered)) = received else {
                return Ok(None);
            };
            let processed = super::reassembled_downlink::process_downlink_datagram(
                backend.inner.runtime.as_ref(),
                scope,
                datagram,
                &mut state.downlink_counters,
            );
            let plan = match processed {
                super::reassembled_downlink::ProcessedDownlink::PacketTooBig(plan) => plan,
                super::reassembled_downlink::ProcessedDownlink::FragmentInner(plan) => {
                    return Ok(Some(fragment_inner(state, &plan)));
                }
                super::reassembled_downlink::ProcessedDownlink::Event(event) => {
                    // A steered datagram only ever carries an authorized
                    // over-MTU packet or inner fragment. If authority changed
                    // since tc steered it, never expose it as a control or
                    // unknown-tunnel event bound to the wrong socket.
                    return Ok(Some(match event {
                        crate::GtpuDownlinkEvent::Control(_)
                        | crate::GtpuDownlinkEvent::UnknownTunnel(_)
                            if steered =>
                        {
                            state
                                .downlink_counters
                                .record_drop(crate::GtpuDownlinkDrop::StateUnavailable);
                            crate::GtpuDownlinkEvent::Dropped(
                                crate::GtpuDownlinkDrop::StateUnavailable,
                            )
                        }
                        event => event,
                    }));
                }
            };
            // At most one error per offending packet. The never-answer rules
            // run before a token is taken, so suppressed packets cannot drain
            // a session's budget. The error is always carried in the UE's
            // default-bearer uplink G-PDU; nothing is ever sent unencapsulated.
            let signal = match plan.build_uplink_gpdu() {
                None => crate::GtpuPacketTooBigSignal::Unsendable,
                Some(_)
                    if !state
                        .too_big_limiter
                        .admit(plan.session(), std::time::Instant::now()) =>
                {
                    crate::GtpuPacketTooBigSignal::RateLimited
                }
                Some((gpdu, local, peer)) => {
                    match socket.send_in_tunnel_error(local, peer, &gpdu) {
                        Ok(_) => crate::GtpuPacketTooBigSignal::Sent,
                        Err(_) => crate::GtpuPacketTooBigSignal::Unsendable,
                    }
                }
            };
            let counters = &mut state.downlink_counters;
            let slot = match signal {
                crate::GtpuPacketTooBigSignal::Sent => &mut counters.packet_too_big_signalled,
                crate::GtpuPacketTooBigSignal::RateLimited => {
                    &mut counters.packet_too_big_rate_limited
                }
                crate::GtpuPacketTooBigSignal::Unsendable => {
                    &mut counters.packet_too_big_unsendable
                }
            };
            *slot = slot.saturating_add(1);
            Ok(Some(crate::GtpuDownlinkEvent::PacketTooBig(
                crate::GtpuDownlinkPacketTooBig::new(
                    crate::GtpAddressFamily::Ipv4,
                    plan.mtu(),
                    signal,
                ),
            )))
        })
    }

    fn set_packet_too_big_rate_limit(
        &self,
        limit: crate::GtpuPacketTooBigRateLimit,
    ) -> Result<(), GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            state.too_big_limiter = crate::reassembly::PacketTooBigLimiter::new(limit);
            Ok(())
        })
    }

    fn set_inner_fragment_rate_limit(
        &self,
        limit: crate::GtpuInnerFragmentRateLimit,
    ) -> Result<(), GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            state.inner_fragment_budget.set_limit(limit);
            Ok(())
        })
    }

    fn downlink_counters(&self) -> Result<crate::GtpuDownlinkCounters, GtpuControlPortError> {
        self.with_attachment(|_, state, _| {
            let mut counters = state.downlink_counters;
            counters.shared_queue_drops = state
                .socket
                .as_ref()
                .map_or(0, |socket| u64::from(socket.queue_drops()));
            counters.packet_too_big_queue_drops = state
                .too_big_socket
                .as_ref()
                .map_or(0, |socket| u64::from(socket.queue_drops()));
            counters.inner_fragment_queue_drops = state
                .inner_fragment_socket
                .as_ref()
                .map_or(0, |socket| u64::from(socket.queue_drops()));
            Ok(counters)
        })
    }
}

/// Fragment one authorized over-MTU packet under the default policy, recording
/// exactly one outcome counter.
///
/// The header is validated first, so a malformed or option-bearing packet
/// takes no token; the destination's budget is taken next, and only then is
/// an Identification assigned from its sequence (atomic datagrams only).
pub(super) fn fragment_inner(
    state: &mut ControlSocketState,
    plan: &super::reassembled_downlink::InnerFragmentPlan,
) -> crate::GtpuDownlinkEvent {
    let drop = |state: &mut ControlSocketState, reason| {
        state.downlink_counters.record_drop(reason);
        crate::GtpuDownlinkEvent::Dropped(reason)
    };
    let source = match crate::inner_fragment::Ipv4FragmentSource::parse(plan.inner_packet()) {
        Ok(source) => source,
        Err(crate::inner_fragment::InnerFragmentRefusal::Options) => {
            return drop(state, crate::GtpuDownlinkDrop::InnerUnfragmentable);
        }
        Err(crate::inner_fragment::InnerFragmentRefusal::Malformed) => {
            return drop(state, crate::GtpuDownlinkDrop::Malformed);
        }
    };
    let Some(assigned) = state.inner_fragment_budget.admit(
        plan.destination(),
        std::time::Instant::now(),
        source.is_atomic(),
    ) else {
        return drop(state, crate::GtpuDownlinkDrop::InnerFragmentRateLimited);
    };
    let identification = assigned.unwrap_or_else(|| source.identification());
    let Some(fragments) = source.fragment(plan.mtu(), identification) else {
        return drop(state, crate::GtpuDownlinkDrop::Malformed);
    };
    let counters = &mut state.downlink_counters;
    counters.inner_fragmented = counters.inner_fragmented.saturating_add(1);
    counters.inner_fragments = counters
        .inner_fragments
        .saturating_add(u64::try_from(fragments.len()).unwrap_or(u64::MAX));
    crate::GtpuDownlinkEvent::Fragmented(crate::GtpuFragmentedDownlink::new(
        fragments,
        plan.bearer_mark(),
        plan.mtu(),
    ))
}

impl EbpfGtpuDataplaneBackend {
    /// Caller holds the attachment mutation guard and the exact namespace
    /// effect lease through all pre/post checks and this nonblocking send.
    pub(super) fn send_retired_n3_end_marker_under_guard(
        &self,
        device: &GtpDevice,
        local: Ipv4Addr,
        peer: Ipv4Addr,
        teid: crate::Teid,
        current: impl Fn() -> bool,
    ) -> Result<(), GtpuError> {
        let unavailable = || state_indeterminate("ebpf_n3_end_marker_socket");
        let devices = self.devices()?;
        let managed = devices.get(&device.ifindex).ok_or_else(unavailable)?;
        if managed.name != device.name
            || managed.cleanup_only
            || managed.successor_pending
            || managed
                .grouped
                .and_then(|grouped| grouped.local_endpoints.ipv4())
                != Some(local)
        {
            return Err(unavailable());
        }
        let slot = Arc::clone(&managed.control_socket);
        drop(devices);
        if self.inner.runtime.ifindex_by_name(&device.name)? != device.ifindex
            || !self
                .inner
                .runtime
                .pdp_readback_datapath_usable(device.ifindex)
        {
            slot.lock().map_err(|_| unavailable())?.retire();
            return Err(unavailable());
        }
        let mut state = slot.lock().map_err(|_| unavailable())?;
        if state.retired {
            return Err(unavailable());
        }
        if state.socket.is_none() {
            // This socket is bound on UDP/2152 of the attachment's interface,
            // where tc then finds it as the consumer of hand-offs. Like the
            // control port, it is not opened on an interface that was
            // enslaved since the attachment was made.
            self.inner
                .runtime
                .require_ip_receive_interface(device.ifindex)?;
            state.socket = Some(
                crate::GtpuReassemblySocket::bind(local, &device.name)
                    .map_err(|_| unavailable())?,
            );
        }
        let socket = state.socket.as_ref().ok_or_else(unavailable)?;
        if !current() {
            return Err(unavailable());
        }
        socket
            .send_retired_n3_end_marker(local, peer, teid)
            .map_err(|_| unavailable())?;
        if !current() {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn open_control_port_sync(
        &self,
        device: GtpDevice,
    ) -> Result<Arc<dyn GtpuControlPort>, GtpuError> {
        let _operation = self.operation_guard()?;
        let unavailable = || GtpuError::StateIndeterminate {
            operation: "ebpf_control_port_attachment",
        };
        let devices = self.devices()?;
        let managed = devices.get(&device.ifindex).ok_or(GtpuError::NotFound)?;
        if managed.name != device.name {
            return Err(GtpuError::NotFound);
        }
        if managed.cleanup_only || managed.successor_pending {
            return Err(unavailable());
        }
        let local_ip = managed
            .local_ip
            .or_else(|| {
                managed
                    .grouped
                    .and_then(|grouped| grouped.local_endpoints.ipv4())
            })
            .ok_or(GtpuError::UnsupportedFeature {
                feature: "gtpu_control_port_ipv6",
            })?;
        let slot = Arc::clone(&managed.control_socket);
        drop(devices);
        if self.inner.runtime.ifindex_by_name(&device.name)? != device.ifindex
            || !self
                .inner
                .runtime
                .pdp_readback_datapath_usable(device.ifindex)
        {
            slot.lock()
                .map_err(|_| GtpuError::io("ebpf_control_port_state", poisoned_lock()))?
                .retire();
            return Err(unavailable());
        }
        // The port is the consumer of this attachment's hand-offs. tc looks
        // for it on the attachment's interface, so IP input must receive
        // there: an interface that was enslaved since the attachment was made
        // is refused, and the attachment is left as it is.
        self.inner
            .runtime
            .require_ip_receive_interface(device.ifindex)?;
        let mut socket = slot
            .lock()
            .map_err(|_| GtpuError::io("ebpf_control_port_state", poisoned_lock()))?;
        if socket.retired {
            return Err(unavailable());
        }
        if socket.socket.is_none() {
            // This is the sole backend-owned queue. An existing external
            // listener produces a normal bind error, never SO_REUSEPORT.
            socket.socket = Some(
                crate::GtpuReassemblySocket::bind(local_ip, &device.name)
                    .map_err(|error| GtpuError::io("ebpf_control_port_bind", error))?,
            );
        }
        if socket.too_big_socket.is_none() {
            // Without this queue tc would drop every over-MTU G-PDU for
            // want of a consumer; refuse instead.
            socket.too_big_socket = Some(
                crate::GtpuReassemblySocket::bind_packet_too_big_queue(local_ip, &device.name)
                    .map_err(|error| {
                        GtpuError::io("ebpf_control_port_packet_too_big_bind", error)
                    })?,
            );
        }
        if socket.inner_fragment_socket.is_none() {
            // Likewise for tc-steered inner fragments: no port is published
            // unless their queue is bound too.
            socket.inner_fragment_socket = Some(
                crate::GtpuReassemblySocket::bind_inner_fragment_queue(local_ip, &device.name)
                    .map_err(|error| {
                        GtpuError::io("ebpf_control_port_inner_fragment_bind", error)
                    })?,
            );
        }
        Ok(Arc::new(BackendControlPort {
            backend: Arc::downgrade(&self.inner),
            socket: Arc::downgrade(&slot),
            ifindex: device.ifindex,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flood of inner fragments keeps its queue non-empty for as long as it
    /// lasts. The over-MTU queue must still be served every second time, and
    /// the reverse; an empty or failing queue never costs the other a turn.
    #[test]
    fn hand_off_queues_are_served_in_turn() {
        use std::collections::VecDeque;
        use HandOffQueue::{InnerFragment, PacketTooBig};

        struct Queues {
            too_big: VecDeque<Result<u32, &'static str>>,
            fragments: VecDeque<Result<u32, &'static str>>,
            next: HandOffQueue,
        }
        impl Queues {
            fn receive(&mut self) -> Result<Option<u32>, &'static str> {
                let (too_big, fragments) = (&mut self.too_big, &mut self.fragments);
                receive_hand_off(&mut self.next, |queue| {
                    match queue {
                        PacketTooBig => too_big.pop_front(),
                        InnerFragment => fragments.pop_front(),
                    }
                    .transpose()
                })
            }
        }
        let datagrams = |range: std::ops::Range<u32>| range.map(Ok).collect::<VecDeque<_>>();

        // Both queues empty: nothing is received and the turn does not move.
        let mut queues = Queues {
            too_big: VecDeque::new(),
            fragments: VecDeque::new(),
            next: HandOffQueue::default(),
        };
        assert_eq!(queues.next, PacketTooBig);
        assert_eq!(queues.receive(), Ok(None));
        assert_eq!(queues.next, PacketTooBig);

        // A fragment flood (100..) against three over-MTU packets (1..=3):
        // strict alternation while both have datagrams, starting with the
        // queue whose turn it is.
        queues.too_big = datagrams(1..4);
        queues.fragments = datagrams(100..200);
        let served: Vec<u32> = (0..8).map(|_| queues.receive().unwrap().unwrap()).collect();
        assert_eq!(served, [1, 100, 2, 101, 3, 102, 103, 104]);
        // The emptied queue keeps the first turn, so a late over-MTU packet
        // waits for no fragment at all.
        assert_eq!(queues.next, PacketTooBig);
        queues.too_big.push_back(Ok(4));
        assert_eq!(queues.receive(), Ok(Some(4)));
        assert_eq!(queues.receive(), Ok(Some(105)));

        // The mirror image: an over-MTU flood cannot starve fragments.
        queues.too_big = datagrams(10..110);
        queues.fragments = datagrams(500..502);
        queues.next = PacketTooBig;
        let served: Vec<u32> = (0..5).map(|_| queues.receive().unwrap().unwrap()).collect();
        assert_eq!(served, [10, 500, 11, 501, 12]);

        // A failing queue uses its own turn: the other one is served next,
        // however often the failure repeats.
        queues.too_big = VecDeque::from([Err("lost binding"), Err("lost binding"), Ok(20)]);
        queues.fragments = datagrams(600..603);
        queues.next = PacketTooBig;
        assert_eq!(queues.receive(), Err("lost binding"));
        assert_eq!(queues.receive(), Ok(Some(600)));
        assert_eq!(queues.receive(), Err("lost binding"));
        assert_eq!(queues.receive(), Ok(Some(601)));
        assert_eq!(queues.receive(), Ok(Some(20)));
        assert_eq!(queues.receive(), Ok(Some(602)));
        assert_eq!(queues.receive(), Ok(None));
    }

    /// The three queues of one attachment as scripted answers: `S` values
    /// come from the shared queue, the others from the two hand-off queues.
    struct ThreeQueues {
        shared: std::collections::VecDeque<Result<u32, &'static str>>,
        too_big: std::collections::VecDeque<Result<u32, &'static str>>,
        fragments: std::collections::VecDeque<Result<u32, &'static str>>,
        order: DownlinkServiceOrder,
    }

    impl ThreeQueues {
        fn new(shared: u32, too_big: u32, fragments: u32) -> Self {
            Self {
                shared: (0..shared).map(Ok).collect(),
                too_big: (1_000..1_000 + too_big).map(Ok).collect(),
                fragments: (2_000..2_000 + fragments).map(Ok).collect(),
                order: DownlinkServiceOrder::default(),
            }
        }

        fn receive(&mut self) -> Result<Option<(u32, bool)>, &'static str> {
            let (shared, too_big, fragments) =
                (&mut self.shared, &mut self.too_big, &mut self.fragments);
            self.order.receive(
                || shared.pop_front().transpose(),
                |queue| {
                    match queue {
                        HandOffQueue::PacketTooBig => too_big.pop_front(),
                        HandOffQueue::InnerFragment => fragments.pop_front(),
                    }
                    .transpose()
                },
            )
        }

        fn drain(&mut self, calls: usize) -> Vec<(u32, bool)> {
            (0..calls)
                .map(|_| self.receive().unwrap().unwrap())
                .collect()
        }
    }

    /// Sustained input on the shared queue (Echo and unknown-TEID G-PDUs
    /// arrive from any source) must not keep the consumer from the hand-off
    /// queues. The shared queue is served first for a run of eight, then the
    /// hand-off queues get one turn, alternating between themselves.
    #[test]
    fn shared_queue_priority_is_bounded_by_its_run() {
        assert_eq!(SHARED_QUEUE_RUN, 8);
        let run = usize::from(SHARED_QUEUE_RUN);
        // An endless shared flood against a backlog in both hand-off queues.
        let mut queues = ThreeQueues::new(1_000, 10, 10);
        let served = queues.drain(4 * (run + 1));
        let mut expected = Vec::new();
        let mut shared = 0;
        for hand_off in [1_000, 2_000, 1_001, 2_001] {
            for _ in 0..run {
                expected.push((shared, false));
                shared += 1;
            }
            expected.push((hand_off, true));
        }
        assert_eq!(
            served, expected,
            "eight from the shared queue, then one hand-off turn, alternating"
        );
        // Each hand-off queue is served once in every 2 * (run + 1) calls.
        for window in served.windows(2 * (run + 1)) {
            assert!(window.contains(&(1_000, true)) || window.contains(&(1_001, true)));
            assert!(window.contains(&(2_000, true)) || window.contains(&(2_001, true)));
        }
    }

    /// The bound costs the shared queue nothing while it matters most: a
    /// short burst is served ahead of any hand-off backlog, and a hand-off
    /// turn that finds both queues empty serves the shared queue in the same
    /// call.
    #[test]
    fn shared_queue_keeps_priority_within_a_run_and_loses_no_turn() {
        let run = u32::from(SHARED_QUEUE_RUN);
        // A burst within one run is served first, whatever waits elsewhere.
        let mut queues = ThreeQueues::new(run, 5, 5);
        let served = queues.drain(usize::from(SHARED_QUEUE_RUN) + 4);
        let shared_first: Vec<(u32, bool)> = (0..run).map(|value| (value, false)).collect();
        assert_eq!(&served[..usize::from(SHARED_QUEUE_RUN)], &shared_first[..]);
        assert_eq!(
            &served[usize::from(SHARED_QUEUE_RUN)..],
            &[(1_000, true), (2_000, true), (1_001, true), (2_001, true)],
            "then the hand-off queues alternate"
        );

        // No hand-off waiting: every call returns a shared datagram, in
        // order, across several runs.
        let mut queues = ThreeQueues::new(3 * run + 1, 0, 0);
        let served = queues.drain(usize::try_from(3 * run + 1).unwrap());
        let all_shared: Vec<(u32, bool)> = (0..3 * run + 1).map(|value| (value, false)).collect();
        assert_eq!(served, all_shared);
        assert_eq!(queues.receive(), Ok(None));

        // All three queues empty: nothing, and nothing changes.
        let mut queues = ThreeQueues::new(0, 0, 0);
        assert_eq!(queues.receive(), Ok(None));
        assert_eq!(queues.receive(), Ok(None));

        // A hand-off that arrives during a shared flood waits for at most
        // one run.
        let mut queues = ThreeQueues::new(1_000, 0, 0);
        let _ = queues.drain(3);
        queues.fragments.push_back(Ok(2_000));
        let served = queues.drain(usize::from(SHARED_QUEUE_RUN));
        assert_eq!(
            served
                .iter()
                .position(|served| *served == (2_000, true))
                .unwrap(),
            usize::from(SHARED_QUEUE_RUN) - 3,
            "served as soon as the current run is complete"
        );
    }

    /// An error from the shared queue counts toward its run, and an error
    /// from a hand-off queue uses that queue's turn: neither can pin the
    /// service order.
    #[test]
    fn failing_queues_cannot_pin_the_service_order() {
        let run = usize::from(SHARED_QUEUE_RUN);
        let mut queues = ThreeQueues::new(0, 2, 2);
        queues.shared = std::iter::repeat_n(Err("lost binding"), 3 * run).collect();
        for _ in 0..run {
            assert_eq!(queues.receive(), Err("lost binding"));
        }
        assert_eq!(queues.receive(), Ok(Some((1_000, true))));
        for _ in 0..run {
            assert_eq!(queues.receive(), Err("lost binding"));
        }
        assert_eq!(queues.receive(), Ok(Some((2_000, true))));

        // A failing hand-off queue: its error is returned at its turn, and
        // the shared queue is served by the next call.
        let mut queues = ThreeQueues::new(1_000, 0, 0);
        queues.too_big.push_back(Err("truncated"));
        let served = queues.drain(run);
        assert!(served.iter().all(|(_, steered)| !steered));
        assert_eq!(queues.receive(), Err("truncated"));
        assert_eq!(queues.receive(), Ok(Some((8, false))));
    }

    /// PDP churn holds the backend-wide operation lock almost continuously
    /// after a mass re-attach. The shared queue (Echo, reassembled G-PDUs)
    /// must neither wait for nor yield to that lock: its exclusion is the
    /// attachment's own socket slot.
    #[test]
    fn control_port_does_not_wait_for_or_yield_to_backend_mutation() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let guard = backend.operation_guard().unwrap();
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable,
            "an unregistered port is unavailable, never Busy behind another mutation"
        );
        drop(guard);
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        drop(backend);
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
    }

    #[test]
    fn downlink_consumer_does_not_yield_to_backend_mutation() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let guard = backend.operation_guard().unwrap();
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert_eq!(
            port.downlink_counters().unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        drop(guard);
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        drop(backend);
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
    }

    #[test]
    fn poisoned_backend_cannot_receive_or_publish_a_port() {
        let backend = EbpfGtpuDataplaneBackend::new();
        let port = BackendControlPort {
            backend: Arc::downgrade(&backend.inner),
            socket: Weak::new(),
            ifindex: 731,
        };
        let inner = Arc::clone(&backend.inner);
        assert!(std::thread::spawn(move || {
            let _guard = inner.operation_lock.lock().unwrap();
            panic!("synthetic writer failure");
        })
        .join()
        .is_err());
        assert_eq!(
            port.try_receive_datagram(8).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert!(backend
            .open_control_port_sync(GtpDevice {
                name: "sentinel".into(),
                ifindex: 731
            })
            .is_err());
    }
}
