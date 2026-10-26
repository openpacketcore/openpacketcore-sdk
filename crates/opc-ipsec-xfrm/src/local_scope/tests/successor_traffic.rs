//! Independently authenticated ESP packets for native successor traffic checks.

use crate::local_scope_quorum::{child_key, Quorum, TestAuthority};
use crate::*;
use hmac::{Hmac, KeyInit, Mac};
use nix::sys::socket::{setsockopt, sockopt};
use nix::{libc, setsockopt_impl, sockopt_impl};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

const UDP_ENCAP_OPTION: libc::c_int = 100;
sockopt_impl!(
    UdpEncapsulation,
    SetOnly,
    libc::SOL_UDP,
    UDP_ENCAP_OPTION,
    libc::c_int
);

fn ip(last: u8) -> IpAddress {
    IpAddress::Ipv4([127, 0, 0, last])
}

pub(super) fn request(id: u8, direction: XfrmDirection) -> ScopedXfrmRequest {
    let (mut sa, mut policy) = crate::local_scope::request::fixture();
    sa.selector = XfrmSelector::new(ip(20), ip(21), 17);
    sa.selector.source_port = 32_000 + u16::from(id) * 2;
    sa.selector.destination_port = sa.selector.source_port + 1;
    sa.id.spi = 0x7100 + u32::from(id);
    sa.id.destination = ip(3);
    sa.source_address = ip(2);
    sa.if_id = None;
    sa.mark = Some(XfrmLookupMark::full(u32::from(id)));
    sa.aead = None;
    sa.auth = Some((
        AuthAlgorithm::hmac_sha256(128),
        KeyMaterial::new(vec![0x3b; 32]),
    ));
    sa.crypt = Some((Algorithm::null(), KeyMaterial::new(Vec::new())));
    sa.encap = Some(UdpEncap::esp_in_udp(
        4500 + u16::from(id),
        4500 + u16::from(id),
    ));
    sa.replay_state = Some(SaReplayState::legacy(91, 87, 0b1011));
    policy.selector = sa.selector.clone();
    policy.if_id = None;
    policy.mark = sa.mark;
    policy.direction = direction;
    policy.templates[0].id = XfrmId { spi: 0, ..sa.id };
    policy.templates[0].source_address = sa.source_address;
    ScopedXfrmRequest::new(sa, policy).unwrap()
}
pub(super) fn socket(address: u8, port: u16, mark: u8) -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, address), port)).unwrap();
    setsockopt(&socket, sockopt::Mark, &u32::from(mark)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    socket
}
pub(super) fn prepare_loopback() {
    let link = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()
        .unwrap();
    assert!(
        link.status.success(),
        "{}",
        String::from_utf8_lossy(&link.stderr)
    );
    // Linux creates loopback with both XFRM bypass switches set. Enable the
    // real SA and policy paths in this test's disposable network namespace.
    for name in ["disable_xfrm", "disable_policy"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/lo/{name}"), "0\n").unwrap();
    }
    // Tunnel input drops the outer route and routes the inner packet again.
    // Our synthetic peer also uses loopback addresses, so permit that local
    // source on reinjection; XFRM policy and authentication remain enabled.
    for name in ["route_localnet", "accept_local"] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/lo/{name}"), "1\n").unwrap();
    }
}
pub(super) fn received(socket: &UdpSocket, payload: &[u8]) {
    let mut bytes = [0; 4096];
    let length = socket.recv(&mut bytes).unwrap_or_else(|error| {
        diagnose_traffic();
        panic!("inner packet receive failed: {error}");
    });
    assert_eq!(&bytes[..length], payload);
}
pub(super) fn diagnose_traffic() {
    for path in ["/proc/net/xfrm_stat", "/proc/net/snmp", "/proc/net/netstat"] {
        eprintln!("{path}: {}", std::fs::read_to_string(path).unwrap());
    }
    for args in [
        vec!["-s", "xfrm", "state"],
        vec!["-s", "xfrm", "policy"],
        vec!["-s", "link", "show", "lo"],
    ] {
        let output = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
    }
}
pub(super) fn absent(socket: &UdpSocket) {
    let error = socket.recv(&mut [0; 4096]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}
// RFC 4303 sections 2.2, 2.5 and 2.6: an independently authenticated, unencrypted
// ESP tunnel packet. Kernel authentication and anti-replay decide delivery.
pub(super) fn packet(
    parameters: &SaParameters,
    spi: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = 28 + payload.len();
    let mut inner = vec![0; length];
    inner[0] = 0x45;
    inner[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    inner[8] = 64;
    inner[9] = 17;
    inner[12..16].copy_from_slice(&[127, 0, 0, 20]);
    inner[16..20].copy_from_slice(&[127, 0, 0, 21]);
    let mut sum: u32 = inner[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes(*pair)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    inner[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    inner[20..22].copy_from_slice(&parameters.selector.source_port.to_be_bytes());
    inner[22..24].copy_from_slice(&parameters.selector.destination_port.to_be_bytes());
    inner[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    inner[28..].copy_from_slice(payload);
    let mut esp = spi.to_be_bytes().to_vec();
    esp.extend(sequence.to_be_bytes());
    esp.extend(inner);
    let padding = (4 - (length + 2) % 4) % 4;
    esp.extend(1..=padding as u8);
    esp.extend([padding as u8, 4]);
    let mut authentication = Hmac::<sha2::Sha256>::new_from_slice(&[0x3b; 32]).unwrap();
    authentication.update(&esp);
    esp.extend(&authentication.finalize().into_bytes()[..16]);
    esp
}

pub(super) async fn install(
    backend: &NamespaceBoundLinuxXfrmBackend,
    profile: &LocalXfrmProfile,
    authority: &TestAuthority,
    quorum: &Quorum,
    id: u8,
    request: ScopedXfrmRequest,
) -> ScopedXfrmReceipt {
    let effect = authority
        .commit_activation(quorum.create_request(id).await, child_key(id))
        .await
        .unwrap();
    backend
        .install_scoped(profile, effect, request)
        .await
        .unwrap()
}

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
pub(super) struct Traffic {
    stop: Arc<AtomicBool>,
    barrier: mpsc::Sender<mpsc::Sender<u32>>,
    worker: Option<std::thread::JoinHandle<(usize, usize)>>,
}
impl Traffic {
    pub(super) fn start(
        first: &ScopedXfrmRequest,
        second: &ScopedXfrmRequest,
        inbound_spi: u32,
    ) -> Self {
        let first = first.clone();
        let second = second.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (barrier, barriers) = mpsc::channel::<mpsc::Sender<u32>>();
        let worker = std::thread::spawn(move || {
            let mark = first.sa.mark.unwrap().value() as u8;
            let encap = first.sa.encap.unwrap();
            let source_port = first.sa.selector.source_port;
            let destination_port = first.sa.selector.destination_port;
            let outer = socket(3, encap.destination_port, mark);
            let inner = socket(21, destination_port, mark);
            let inbound = first.policy.direction == XfrmDirection::In;
            let sender = if inbound {
                setsockopt(&outer, UdpEncapsulation, &2).unwrap();
                // The loopback routing setup must not bypass the inbound
                // protective policy: only independently authenticated ESP
                // may reach this inner receiver.
                let unprotected = socket(20, source_port, mark);
                unprotected
                    .send_to(
                        b"unprotected",
                        (Ipv4Addr::new(127, 0, 0, 21), destination_port),
                    )
                    .unwrap();
                absent(&inner);
                socket(2, encap.source_port, mark)
            } else {
                let sender = socket(20, source_port, mark);
                sender
                    .connect((Ipv4Addr::new(127, 0, 0, 21), destination_port))
                    .unwrap();
                sender
            };
            let mut packets = 0u32;
            let mut counts = (0usize, 0usize);
            let mut last_sequence = [0u32; 2];
            let inbound_floor = if inbound_spi == first.sa.id.spi {
                87
            } else {
                0
            };
            while !worker_stop.load(Ordering::Acquire) {
                let acknowledgements: Vec<_> = barriers.try_iter().collect();
                packets += 1;
                let payload = packets.to_be_bytes();
                let observed_spi = if inbound {
                    sender
                        .send_to(
                            &packet(&first.sa, inbound_spi, inbound_floor + packets, &payload),
                            (Ipv4Addr::new(127, 0, 0, 3), encap.destination_port),
                        )
                        .unwrap();
                    received(&inner, &payload);
                    inbound_spi
                } else {
                    sender.send(&payload).unwrap();
                    let mut bytes = [0u8; 4096];
                    let length = outer.recv(&mut bytes).unwrap_or_else(|error| {
                        diagnose_traffic();
                        panic!("protected packet receive failed: {error}");
                    });
                    assert!(length >= 8 + 28 + payload.len() + 2 + 16);
                    let spi = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                    let generation = if spi == first.sa.id.spi {
                        0
                    } else {
                        assert_eq!(spi, second.sa.id.spi);
                        1
                    };
                    let sequence = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                    assert!(sequence > last_sequence[generation]);
                    last_sequence[generation] = sequence;
                    assert_eq!(&bytes[36..40], &payload);
                    spi
                };
                if observed_spi == first.sa.id.spi {
                    counts.0 += 1;
                } else {
                    counts.1 += 1;
                }
                for acknowledgement in acknowledgements {
                    acknowledgement.send(observed_spi).unwrap();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if !inbound {
                absent(&inner);
            }
            counts
        });
        Self {
            stop,
            barrier,
            worker: Some(worker),
        }
    }
    // The acknowledged packet is sent after this request, including when called
    // after a policy change or predecessor deletion has returned.
    pub(super) fn checkpoint(&self, expected_spi: u32) {
        let (reply, observed) = mpsc::channel();
        self.barrier.send(reply).unwrap();
        assert_eq!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            expected_spi
        );
    }
    pub(super) fn finish(mut self) -> (usize, usize) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Traffic {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
