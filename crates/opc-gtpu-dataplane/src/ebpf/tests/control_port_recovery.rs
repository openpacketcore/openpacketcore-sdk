//! The real backend slot and real loopback UDP queues, with only kernel
//! attachment readback supplied by the fake runtime. No fake port or opener.

use super::*;
use crate::control_port::{
    GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlResponseBudget,
};
use std::net::UdpSocket;
use std::time::Duration;

const ECHO: [u8; 12] = [0x32, 1, 0, 4, 0, 0, 0, 0, 0x91, 0x73, 0, 0];
const RESPONSE: [u8; 14] = [0x32, 2, 0, 6, 0, 0, 0, 0, 0x91, 0x73, 0, 0, 14, 0];
const PEER: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
static NEXT_ADDRESS: AtomicUsize = AtomicUsize::new(1);

struct Fixture {
    backend: EbpfGtpuDataplaneBackend,
    runtime: Arc<FakeRuntime>,
    device: GtpDevice,
    local: Ipv4Addr,
    peer: UdpSocket,
}

impl Fixture {
    async fn new(grouped: bool) -> Self {
        let local = Ipv4Addr::new(
            127,
            36,
            1,
            u8::try_from(NEXT_ADDRESS.fetch_add(1, Ordering::Relaxed)).unwrap(),
        );
        let mut runtime = FakeRuntime::new();
        runtime
            .ifindexes
            .insert("lo".into(), nix::net::if_::if_nametoindex("lo").unwrap());
        let runtime = Arc::new(runtime);
        let backend = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        let mut request = CreateGtpDeviceRequest::new("lo");
        request.bind_address = IpAddr::V4(local);
        let device = if grouped {
            backend
                .create_device_with_endpoints(grouped_device_request(
                    "lo",
                    grouped_device_id(0x36),
                    GtpuLocalEndpointSet::new(IpAddr::V4(local), None).unwrap(),
                ))
                .await
                .unwrap()
        } else {
            backend.create_device(request).await.unwrap()
        };
        let peer = UdpSocket::bind((PEER, 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        Self {
            backend,
            runtime,
            device,
            local,
            peer,
        }
    }

    async fn open(&self) -> Arc<dyn GtpuControlPort> {
        self.backend
            .open_gtpu_control_port(&self.device)
            .await
            .unwrap()
    }

    fn echo(&self, port: &dyn GtpuControlPort) -> GtpuControlDatagram {
        self.peer
            .send_to(&ECHO, (self.local, crate::GTPU_PORT))
            .unwrap();
        receive(|| port.try_receive_datagram(2048))
    }

    fn assert_echo(&self, port: &dyn GtpuControlPort) {
        let event = self.echo(port);
        assert_eq!(event.bytes(), ECHO);
        assert_eq!(event.provenance().ingress_ifindex(), self.device.ifindex);
        let plan = event
            .echo_response(GtpuControlResponseBudget::new(14, 2).unwrap())
            .unwrap();
        assert_eq!(port.send_control_response(plan).unwrap(), RESPONSE.len());
        let mut bytes = [0; 64];
        let (length, source) = self.peer.recv_from(&mut bytes).unwrap();
        assert_eq!(source, (self.local, crate::GTPU_PORT).into());
        assert_eq!(&bytes[..length], RESPONSE);
    }

    fn assert_queues_closed(&self) {
        // All three old queues must release their kernel bindings on failure.
        for port in [2152, 2153, 2154] {
            drop(UdpSocket::bind((self.local, port)).unwrap());
        }
    }

    async fn install_downlink(&self) {
        let mut context = context();
        context.link_ifindex = self.device.ifindex;
        context.peer_address = IpAddr::V4(PEER);
        context.downlink_inner_mtu = Some(crate::GtpuDownlinkInnerMtu::new(576).unwrap());
        self.backend.install_pdp_context(context).await.unwrap();
        let mut state = self.runtime.state();
        state
            .traffic_observation_gate
            .insert(self.device.ifindex, 3);
        state.grouped_map_ready.insert(self.device.ifindex);
    }

    fn assert_oversized_downlink(&self, port: &dyn GtpuControlPort) -> u16 {
        // Independent IPv4/UDP fixture: 700 octets, DF set, UE 10.45.0.2.
        let mut inner = vec![
            0x45, 0, 0x02, 0xbc, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 8, 8, 8, 8, 10, 45, 0, 2,
        ];
        let checksum = opc_gtpu_ebpf_common::internet_checksum(&inner);
        inner[10..12].copy_from_slice(&checksum.to_be_bytes());
        inner.extend_from_slice(&[0, 53, 0x13, 0xc4, 0x02, 0xa8, 0, 0]);
        inner.resize(700, 0x5a);
        let mut gpdu = vec![0x30, 0xff, 0x02, 0xbc, 0x10, 0, 0, 1];
        gpdu.extend_from_slice(&inner);
        self.peer.send_to(&gpdu, (self.local, 2153)).unwrap();
        let crate::GtpuDownlinkEvent::Fragmented(packet) =
            receive(|| port.try_receive_downlink(2048))
        else {
            panic!("the recovered hand-off queue must fragment the authorized packet");
        };
        assert_eq!(packet.mtu(), 576);
        assert_eq!(packet.fragments().len(), 2);
        assert_eq!(packet.fragments()[0].len(), 572);
        assert_eq!(packet.fragments()[1].len(), 148);
        assert_eq!(&packet.fragments()[0][20..], &inner[20..572]);
        assert_eq!(&packet.fragments()[1][20..], &inner[572..]);
        assert!(port.try_receive_downlink(2048).unwrap().is_none());
        u16::from_be_bytes([packet.fragments()[0][4], packet.fragments()[0][5]])
    }
}

fn receive<T>(mut poll: impl FnMut() -> Result<Option<T>, GtpuControlPortError>) -> T {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(event) = poll().unwrap() {
            return event;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "control queue receive deadline"
        );
        std::thread::yield_now();
    }
}

#[tokio::test]
async fn rate_budget_retention_control_port_replacement_restarts_each_burst() {
    let fixture = Fixture::new(false).await;
    let mut context = context();
    context.link_ifindex = fixture.device.ifindex;
    context.peer_address = IpAddr::V4(PEER);
    context.downlink_inner_mtu =
        Some(crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(576).unwrap());
    fixture.backend.install_pdp_context(context).await.unwrap();
    {
        let mut state = fixture.runtime.state();
        state
            .traffic_observation_gate
            .insert(fixture.device.ifindex, 3);
        state.grouped_map_ready.insert(fixture.device.ifindex);
    }
    let port = fixture.open().await;
    let limit = crate::GtpuPacketTooBigRateLimit::new(1, Duration::from_secs(3_600)).unwrap();
    port.set_packet_too_big_rate_limit(limit).unwrap();

    let mut inner = vec![
        0x45, 0, 0x02, 0xbc, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 8, 8, 8, 8, 10, 45, 0, 2,
    ];
    let checksum = opc_gtpu_ebpf_common::internet_checksum(&inner);
    inner[10..12].copy_from_slice(&checksum.to_be_bytes());
    inner.extend_from_slice(&[0, 53, 0x13, 0xc4, 0x02, 0xa8, 0, 0]);
    inner.resize(700, 0x5a);
    let mut gpdu = vec![0x30, 0xff, 0x02, 0xbc, 0x10, 0, 0, 1];
    gpdu.extend_from_slice(&inner);
    let signal = || {
        fixture.peer.send_to(&gpdu, (fixture.local, 2153)).unwrap();
        let crate::GtpuDownlinkEvent::PacketTooBig(event) =
            receive(|| port.try_receive_downlink(2048))
        else {
            panic!("the authorized oversized datagram must use the PTB policy");
        };
        event.signal()
    };
    assert_eq!(signal(), crate::GtpuPacketTooBigSignal::Sent);
    assert_eq!(signal(), crate::GtpuPacketTooBigSignal::RateLimited);
    for replacement in [
        limit,
        crate::GtpuPacketTooBigRateLimit::new(16, Duration::from_secs(3_600)).unwrap(),
    ] {
        port.set_packet_too_big_rate_limit(replacement).unwrap();
        for _ in 0..replacement.burst() {
            assert_eq!(signal(), crate::GtpuPacketTooBigSignal::Sent);
        }
        assert_eq!(signal(), crate::GtpuPacketTooBigSignal::RateLimited);
    }
    let counters = port.downlink_counters().unwrap();
    assert_eq!(counters.packet_too_big_signalled, 18);
    assert_eq!(counters.packet_too_big_rate_limited, 3);
    assert_eq!(counters.packet_too_big_capacity_exhausted, 0);
}

fn readiness_is_readable(source: &impl std::os::fd::AsFd) -> bool {
    use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};

    let poller = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC).unwrap();
    poller
        .add(source, EpollEvent::new(EpollFlags::EPOLLIN, 0))
        .unwrap();
    let mut events = [EpollEvent::empty(); 1];
    poller.wait(&mut events, 0_u8).unwrap() == 1
}

#[tokio::test]
async fn control_port_readiness_wakes_async_consumer_for_every_queue() {
    for grouped in [false, true] {
        let fixture = Fixture::new(grouped).await;
        let port = fixture.open().await;
        let source = port.downlink_readiness().unwrap();
        let sibling = fixture.open().await.downlink_readiness().unwrap();
        assert!(!readiness_is_readable(&source));
        assert!(!readiness_is_readable(&sibling));
        assert_eq!(format!("{source:?}"), "GtpuControlReadiness(<redacted>)");
        let reactor = source.register_tokio().unwrap();

        for queue in [2152, 2153, 2154, 2152] {
            // Arm the consumer before the datagram exists. No timer or
            // polling loop is responsible for making receive progress.
            let notified = reactor.readable();
            tokio::pin!(notified);
            assert!(futures_util::poll!(notified.as_mut()).is_pending());
            fixture.peer.send_to(&ECHO, (fixture.local, queue)).unwrap();
            let mut ready = tokio::time::timeout(Duration::from_secs(2), notified)
                .await
                .expect("a queued datagram must wake the reactor")
                .unwrap();
            assert!(readiness_is_readable(&sibling));
            let outcome = port.try_receive_downlink(2048).unwrap().unwrap();
            if queue == 2152 {
                let crate::GtpuDownlinkEvent::Control(event) = outcome else {
                    panic!("shared-queue Echo must remain a control event");
                };
                assert_eq!(event.bytes(), ECHO);
            } else {
                // A control sent directly to a hand-off queue is consumed,
                // but cannot acquire the shared socket's response authority.
                assert!(matches!(
                    outcome,
                    crate::GtpuDownlinkEvent::Dropped(crate::GtpuDownlinkDrop::StateUnavailable)
                ));
            }
            assert!(port.try_receive_downlink(2048).unwrap().is_none());
            assert!(!readiness_is_readable(&sibling));
            ready.clear_ready();
        }
    }
}

#[tokio::test]
async fn control_port_readiness_preserves_queued_input_and_shared_priority() {
    let fixture = Fixture::new(false).await;
    let port = fixture.open().await;
    for queue in [2154, 2153, 2152] {
        fixture.peer.send_to(&ECHO, (fixture.local, queue)).unwrap();
    }
    // Registration after arrival must observe every already-queued packet.
    let source = port.downlink_readiness().unwrap();
    assert!(readiness_is_readable(&source));
    let crate::GtpuDownlinkEvent::Control(event) =
        port.try_receive_downlink(2048).unwrap().unwrap()
    else {
        panic!("the shared queue must still be served first");
    };
    assert_eq!(event.bytes(), ECHO);
    assert!(port.try_receive_datagram(2048).unwrap().is_none());
    assert!(readiness_is_readable(&source));
    for _ in 0..2 {
        assert!(matches!(
            port.try_receive_downlink(2048).unwrap(),
            Some(crate::GtpuDownlinkEvent::Dropped(
                crate::GtpuDownlinkDrop::StateUnavailable
            ))
        ));
    }
    assert!(port.try_receive_downlink(2048).unwrap().is_none());
    assert!(!readiness_is_readable(&source));
}

#[tokio::test]
async fn control_port_readiness_retires_without_retaining_udp_sockets() {
    for grouped in [false, true] {
        let fixture = Fixture::new(grouped).await;
        let port = fixture.open().await;
        let source = port.downlink_readiness().unwrap();
        assert!(!readiness_is_readable(&source));
        fixture
            .backend
            .remove_device(&fixture.device)
            .await
            .unwrap();
        assert!(readiness_is_readable(&source));
        assert_eq!(
            port.downlink_readiness().unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert_eq!(
            port.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        fixture.assert_queues_closed();
        // Reading readiness never consumes the retirement notification.
        assert!(readiness_is_readable(&source));
    }
}

#[tokio::test]
async fn control_port_readiness_backend_loss_wakes_and_releases_all_bindings() {
    let fixture = Fixture::new(false).await;
    let port = fixture.open().await;
    let source = port.downlink_readiness().unwrap();
    let reactor = source.register_tokio().unwrap();
    let notified = reactor.readable();
    tokio::pin!(notified);
    assert!(futures_util::poll!(notified.as_mut()).is_pending());
    let local = fixture.local;
    drop(fixture);
    let _ready = tokio::time::timeout(Duration::from_secs(2), notified)
        .await
        .expect("backend loss must wake an idle consumer")
        .unwrap();
    assert_eq!(
        port.try_receive_downlink(2048).unwrap_err(),
        GtpuControlPortError::Unavailable
    );
    for queue in [2152, 2153, 2154] {
        drop(UdpSocket::bind((local, queue)).unwrap());
    }
}

#[tokio::test]
async fn control_port_readiness_readback_recovery_never_revives_old_generation() {
    for fault in Fault::EACH {
        let fixture = Fixture::new(false).await;
        let old = fixture.open().await;
        let old_source = old.downlink_readiness().unwrap();
        assert!(!readiness_is_readable(&old_source));
        fault.set(&fixture, true);
        assert_eq!(
            old.try_receive_downlink(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        assert!(readiness_is_readable(&old_source));
        fixture.assert_queues_closed();
        fault.set(&fixture, false);
        let fresh = fixture.open().await;
        let fresh_source = fresh.downlink_readiness().unwrap();
        assert!(!readiness_is_readable(&fresh_source));
        assert_eq!(
            old.downlink_readiness().unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        fixture.assert_echo(fresh.as_ref());
        assert!(readiness_is_readable(&old_source));
        assert!(!readiness_is_readable(&fresh_source));
    }
}

#[test]
fn standalone_control_socket_does_not_advertise_downlink_readiness() {
    let socket = crate::GtpuReassemblySocket::bind(Ipv4Addr::new(127, 36, 3, 1), "lo").unwrap();
    assert_eq!(
        socket.downlink_readiness().unwrap_err(),
        GtpuControlPortError::Unsupported
    );
    assert_eq!(
        socket.try_receive_downlink(2048).unwrap_err(),
        GtpuControlPortError::Unsupported
    );
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    InterfaceReadback,
    DatapathReadback,
}

impl Fault {
    const EACH: [Self; 2] = [Self::InterfaceReadback, Self::DatapathReadback];

    fn set(self, fixture: &Fixture, failed: bool) {
        let mut state = fixture.runtime.state();
        match (self, failed) {
            (Self::InterfaceReadback, true) => {
                state.interface_readback_unavailable.insert("lo".into());
            }
            (Self::InterfaceReadback, false) => {
                state.interface_readback_unavailable.remove("lo");
            }
            (Self::DatapathReadback, true) => {
                state.pin_identity_invalid.insert(fixture.device.ifindex);
            }
            (Self::DatapathReadback, false) => {
                state.pin_identity_invalid.remove(&fixture.device.ifindex);
            }
        }
    }
}

#[tokio::test]
async fn retired_sdk_control_port_recovers_or_escalates_after_transient_readback() {
    for fault in Fault::EACH {
        for downlink_poll in [false, true] {
            let fixture = Fixture::new(false).await;
            fixture.install_downlink().await;
            let old = fixture.open().await;
            let sibling = fixture.open().await;
            fixture.assert_echo(old.as_ref());
            let identification = fixture.assert_oversized_downlink(old.as_ref());
            let counters = old.downlink_counters().unwrap();
            let budget = GtpuControlResponseBudget::new(14, 2).unwrap();
            let old_plan = fixture.echo(old.as_ref()).echo_response(budget).unwrap();
            fault.set(&fixture, true);
            let failure = if downlink_poll {
                old.try_receive_downlink(2048).unwrap_err()
            } else {
                old.try_receive_datagram(2048).unwrap_err()
            };
            assert_eq!(failure, GtpuControlPortError::Unavailable, "{fault:?}");
            fixture.assert_queues_closed();
            assert!(fixture
                .backend
                .open_gtpu_control_port(&fixture.device)
                .await
                .is_err());
            fault.set(&fixture, false);

            let recovered = fixture.open().await;
            assert_eq!(
                old.try_receive_datagram(2048).unwrap_err(),
                GtpuControlPortError::Unavailable
            );
            assert_eq!(
                sibling.try_receive_downlink(2048).unwrap_err(),
                GtpuControlPortError::Unavailable
            );
            assert_eq!(
                recovered.send_control_response(old_plan).unwrap_err(),
                GtpuControlPortError::SocketMismatch
            );
            assert_eq!(recovered.downlink_counters().unwrap(), counters);
            // A stale handle's delayed failed readback cannot close the
            // replacement queues. No additional open is allowed here.
            fault.set(&fixture, true);
            assert_eq!(
                old.try_receive_datagram(2048).unwrap_err(),
                GtpuControlPortError::Unavailable
            );
            fault.set(&fixture, false);
            fixture.assert_echo(recovered.as_ref());
            assert_eq!(
                fixture.assert_oversized_downlink(recovered.as_ref()),
                identification.wrapping_add(1).max(1),
                "reopening preserves the per-destination Identification sequence"
            );
        }
    }
}

#[tokio::test]
async fn control_port_open_readback_failure_can_recover_without_replacing_attachment() {
    for fault in Fault::EACH {
        let fixture = Fixture::new(false).await;
        let old = fixture.open().await;
        fault.set(&fixture, true);
        assert!(fixture
            .backend
            .open_gtpu_control_port(&fixture.device)
            .await
            .is_err());
        fixture.assert_queues_closed();
        fault.set(&fixture, false);
        let recovered = fixture.open().await;
        assert_eq!(
            old.try_receive_datagram(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        fixture.assert_echo(recovered.as_ref());
    }
}

#[tokio::test]
async fn end_marker_readback_failure_does_not_permanently_disable_control_port() {
    for fault in Fault::EACH {
        let fixture = Fixture::new(true).await;
        let old = fixture.open().await;
        fault.set(&fixture, true);
        {
            let _guard = fixture.backend.operation_guard().unwrap();
            assert!(fixture
                .backend
                .send_retired_n3_end_marker_under_guard(
                    &fixture.device,
                    fixture.local,
                    PEER,
                    teid(0x2000_0001).into(),
                    || true,
                )
                .is_err());
        }
        fixture.assert_queues_closed();
        fault.set(&fixture, false);
        let recovered = fixture.open().await;
        assert_eq!(
            old.try_receive_datagram(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        fixture.assert_echo(recovered.as_ref());
    }
}

#[tokio::test]
async fn control_port_recovery_does_not_revive_removed_or_fenced_registrations() {
    for successor_pending in [false, true] {
        let fixture = Fixture::new(false).await;
        let old = fixture.open().await;
        Fault::DatapathReadback.set(&fixture, true);
        assert_eq!(
            old.try_receive_datagram(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        Fault::DatapathReadback.set(&fixture, false);
        {
            let mut devices = fixture.backend.devices().unwrap();
            let managed = devices.get_mut(&fixture.device.ifindex).unwrap();
            managed.cleanup_only = !successor_pending;
            managed.successor_pending = successor_pending;
        }
        assert!(fixture
            .backend
            .open_gtpu_control_port(&fixture.device)
            .await
            .is_err());
        assert_eq!(
            old.try_receive_datagram(2048).unwrap_err(),
            GtpuControlPortError::Unavailable
        );
        fixture.assert_queues_closed();
    }
    let fixture = Fixture::new(false).await;
    let old = fixture.open().await;
    fixture
        .backend
        .remove_device(&fixture.device)
        .await
        .unwrap();
    assert!(fixture
        .backend
        .open_gtpu_control_port(&fixture.device)
        .await
        .is_err());
    let mut request = CreateGtpDeviceRequest::new("lo");
    request.bind_address = IpAddr::V4(fixture.local);
    let replacement = fixture.backend.create_device(request).await.unwrap();
    assert_eq!(replacement, fixture.device);
    let fresh = fixture.open().await;
    assert_eq!(
        old.try_receive_datagram(2048).unwrap_err(),
        GtpuControlPortError::Unavailable
    );
    fixture.assert_echo(fresh.as_ref());
}
