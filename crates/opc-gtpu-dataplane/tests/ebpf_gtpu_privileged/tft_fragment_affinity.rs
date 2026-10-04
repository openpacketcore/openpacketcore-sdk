//! Real tc uplink fragment-affinity proofs using synthetic IPv4 ESP packets.

use super::*;
use opc_gtpu_ebpf_common::{
    TftClassifierKey, TftClassifierMeta, TftClassifierOwnerId, TftFragmentKey,
    COUNTER_TFT_CLASSIFIER_INVALID_STATE, COUNTER_TFT_CLASSIFIER_MALFORMED, TFT_FRAGMENT_BUCKETS,
    TFT_FRAGMENT_BUCKET_VALUE_LEN, TFT_FRAGMENT_LIFETIME_NS, TFT_FRAGMENT_MAX_RANGES,
    TFT_FRAGMENT_WAYS,
};

const SPI: u32 = 0x1020_3040;
const SPI_B: u32 = 0x5060_7080;
const MORE: u16 = 0x2000;
const LIFETIME: Duration = Duration::from_nanos(TFT_FRAGMENT_LIFETIME_NS);
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn esp_classifier(ifindex: u32) -> TftUplinkClassifier {
    classifier_for(ifindex, UE_PAA, &[(MARK_A, SPI)])
}

fn classifier_for(ifindex: u32, paa: Ipv4Addr, selectors: &[(u32, u32)]) -> TftUplinkClassifier {
    let mut bearers = vec![TftUplinkBearer::default_bearer()];
    for (rank, &(mark, spi)) in selectors.iter().enumerate() {
        let filter = PacketFilter::new(
            PacketFilterIdentifier::new(0).unwrap(),
            PacketFilterDirection::UplinkOnly,
            10 + u8::try_from(rank).unwrap(),
            vec![
                PacketFilterComponent::Ipv4LocalAddress {
                    address: paa,
                    mask: Ipv4Addr::BROADCAST,
                },
                PacketFilterComponent::Ipv4RemoteAddress {
                    address: REMOTE_HOST,
                    mask: Ipv4Addr::BROADCAST,
                },
                PacketFilterComponent::ProtocolIdentifierNextHeader(IPPROTO_ESP),
                PacketFilterComponent::SecurityParameterIndex(spi),
            ],
        )
        .unwrap();
        bearers.push(TftUplinkBearer::dedicated(
            GtpBearerMark::new(mark).unwrap(),
            TrafficFlowTemplate::create_new(vec![filter], vec![]).unwrap(),
        ));
    }
    TftUplinkClassifier::new(ifindex, IpAddr::V4(paa), bearers).unwrap()
}

fn esp_fragment(id: u16, fragment: u16) -> Vec<u8> {
    let mut packet = vec![0xa5; 44];
    packet[..20].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 64;
    packet[9] = IPPROTO_ESP;
    packet[12..16].copy_from_slice(&UE_PAA.octets());
    packet[16..20].copy_from_slice(&REMOTE_HOST.octets());
    packet[20..24].copy_from_slice(&SPI.to_be_bytes());
    packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
    checksum(&mut packet);
    packet
}

fn checksum(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let mut header = [0; 20];
    header.copy_from_slice(&packet[..20]);
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
}

fn with_spi(mut packet: Vec<u8>, spi: u32) -> Vec<u8> {
    packet[20..24].copy_from_slice(&spi.to_be_bytes());
    packet
}

fn with_paa(mut packet: Vec<u8>, paa: Ipv4Addr) -> Vec<u8> {
    packet[12..16].copy_from_slice(&paa.octets());
    checksum(&mut packet);
    packet
}

fn tft_count(pin_dir: &Path, counter: u32) -> u64 {
    pinned_per_cpu_u64_values(
        pin_dir,
        MAP_TFT_CLASSIFIER_COUNTERS,
        TFT_CLASSIFIER_COUNTER_SLOTS,
    )[counter as usize]
        .iter()
        .sum()
}

fn malformed_count(pin_dir: &Path) -> u64 {
    tft_count(pin_dir, COUNTER_TFT_CLASSIFIER_MALFORMED)
}

/// One attachment with an exact default and two independently owned dedicated
/// bearers. Every receipt checks the complete inner packet and the peer TEID.
struct Fixture {
    net: TestNet,
    backend: EbpfGtpuDataplaneBackend,
    device: GtpDevice,
    socket: UdpSocket,
    pin_dir: PathBuf,
}

impl Fixture {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let nohz_full = tft_nohz_full::require_requested_profile();
        let net = TestNet::provision();
        let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        });
        let mut request = CreateGtpDeviceRequest::new("s2bu");
        request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
        let device = backend.create_device(request).await?;
        if nohz_full {
            tft_nohz_full::require_aya_available(&backend);
        }
        backend
            .install_pdp_context(session_context(device.ifindex))
            .await?;
        for (mark, local, peer) in [
            (MARK_A, LOCAL_TEID_A, PEER_TEID_A),
            (MARK_B, LOCAL_TEID_B, PEER_TEID_B),
        ] {
            backend
                .install_pdp_context(dedicated_session_context(device.ifindex, mark, local, peer))
                .await?;
        }
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(esp_classifier(device.ifindex))
                .await?,
            TftUplinkClassifierReconcileOutcome::Installed
        );
        let socket = in_netns(&net.pgw_ns, || {
            UdpSocket::bind((PGW_IP, GTPU_PORT)).unwrap()
        });
        let pin_dir = net.pin_root.join("s2bu");
        let fixture = Self {
            net,
            backend,
            device,
            socket,
            pin_dir,
        };
        // Warm the neighbour and prove the exact selector before any lifetime
        // starts. A later timeout cannot be mistaken for initial ARP latency.
        fixture.forward(&esp_fragment(0x7000, 0), PEER_TEID_A);
        Ok(fixture)
    }

    fn forward(&self, packet: &[u8], expected_teid: u32) {
        send_wireguard_ipv4_packet(&self.net.ue_ns, packet);
        receive_fragment(&self.socket, packet, EPDG_S2BU_IP, expected_teid);
    }

    fn forward_many(&self, packets: &[Vec<u8>], expected_teid: u32) {
        send_fragments(&self.net.ue_ns, packets);
        for packet in packets {
            receive_fragment(&self.socket, packet, EPDG_S2BU_IP, expected_teid);
        }
    }

    fn reject_many(&self, packets: &[Vec<u8>], counter: DropCounter) {
        reject_fragments(
            &self.net.ue_ns,
            &self.socket,
            &self.pin_dir,
            packets,
            counter,
        );
    }

    fn first(&self, id: u16) -> Instant {
        let started = Instant::now();
        self.forward(&esp_fragment(id, MORE), PEER_TEID_A);
        started
    }

    fn reject(&self, packet: &[u8], counter: DropCounter) {
        reject_fragment(
            &self.net.ue_ns,
            &self.socket,
            &self.pin_dir,
            packet,
            counter,
        );
    }

    async fn finish(self) -> TestResult {
        self.backend.remove_device(&self.device).await?;
        Ok(())
    }
}

fn receive_fragment(
    socket: &UdpSocket,
    packet: &[u8],
    expected_source: Ipv4Addr,
    expected_teid: u32,
) {
    let mut expected = packet.to_vec();
    // The namespace router decrements the inner IPv4 TTL once.
    expected[8] -= 1;
    checksum(&mut expected);
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut received = [0; 2048];
    let (length, source) = socket.recv_from(&mut received).unwrap_or_else(|error| {
        panic!("fragment must encapsulate on its exact peer TEID: {error}")
    });
    assert_eq!(source, SocketAddr::from((expected_source, GTPU_PORT)));
    assert_exact_gpdu(&received[..length], expected_teid, &expected);
}

fn socket_is_empty(socket: &UdpSocket) {
    socket.set_nonblocking(true).unwrap();
    let mut received = [0; 2048];
    let result = socket.recv_from(&mut received);
    socket.set_nonblocking(false).unwrap();
    assert!(
        matches!(result, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock),
        "rejected fragment must not reach any default or dedicated TEID: {result:?}"
    );
}

#[derive(Clone, Copy)]
enum DropCounter {
    Invalid,
    Malformed,
    Authority,
}

fn reject_fragment(
    namespace: &str,
    socket: &UdpSocket,
    pin_dir: &Path,
    packet: &[u8],
    counter: DropCounter,
) {
    reject_fragments(namespace, socket, pin_dir, &[packet.to_vec()], counter);
}

fn reject_fragments(
    namespace: &str,
    socket: &UdpSocket,
    pin_dir: &Path,
    packets: &[Vec<u8>],
    counter: DropCounter,
) {
    assert!(!packets.is_empty());
    let before = [
        tft_count(pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE),
        malformed_count(pin_dir),
        pinned_counter(pin_dir, COUNTER_UL_FAR_MISS),
    ];
    let encapsulated = pinned_counter(pin_dir, COUNTER_UL_ENCAP);
    let index = match counter {
        DropCounter::Invalid => 0,
        DropCounter::Malformed => 1,
        DropCounter::Authority => 2,
    };
    let mut expected = before;
    expected[index] += u64::try_from(packets.len()).unwrap();
    send_fragments(namespace, packets);
    let deadline = Instant::now() + Duration::from_millis(500);
    let after = loop {
        let observed = [
            tft_count(pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE),
            malformed_count(pin_dir),
            pinned_counter(pin_dir, COUNTER_UL_FAR_MISS),
        ];
        if observed[index] >= expected[index] || Instant::now() >= deadline {
            break observed;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(
        after, expected,
        "every packet in the batch must reach its exact drop boundary"
    );
    assert_eq!(
        pinned_counter(pin_dir, COUNTER_UL_ENCAP),
        encapsulated,
        "a rejected fragment must never encapsulate"
    );
    socket_is_empty(socket);
}

fn assert_live(started: Instant) {
    assert!(
        started.elapsed() < LIFETIME,
        "live-entry proof exceeded its fixed deadline"
    );
}

fn expire(started: Instant) {
    if let Some(remaining) = (LIFETIME + Duration::from_millis(100)).checked_sub(started.elapsed())
    {
        std::thread::sleep(remaining);
    }
}

fn meta_map(
    pin_dir: &Path,
) -> BpfHashMap<MapData, [u8; TFT_CLASSIFIER_KEY_LEN], [u8; TFT_CLASSIFIER_META_VALUE_LEN]> {
    let map = Map::from_map_data(MapData::from_pin(pin_dir.join(MAP_TFT_CLASSIFIER_META)).unwrap())
        .unwrap();
    BpfHashMap::try_from(map).unwrap()
}

fn fragment_key(ifindex: u32, id: u16) -> TftFragmentKey {
    TftFragmentKey::new(
        TftClassifierKey::new(ifindex, UE_PAA.octets()).unwrap(),
        UE_PAA.octets(),
        REMOTE_HOST.octets(),
        IPPROTO_ESP,
        id,
    )
}

fn bucket_bytes(pin_dir: &Path, bucket: u32) -> [u8; TFT_FRAGMENT_BUCKET_VALUE_LEN] {
    let map =
        Map::from_map_data(MapData::from_pin(pin_dir.join(MAP_TFT_FRAGMENT_AFFINITY)).unwrap())
            .unwrap();
    Array::<_, [u8; TFT_FRAGMENT_BUCKET_VALUE_LEN]>::try_from(map)
        .unwrap()
        .get(&bucket, 4) // BPF_F_LOCK: inspect one coherent bucket.
        .unwrap()
}

/// Batch injection avoids process-start latency consuming the live proofs'
/// fixed two-second lifetime. Packet bytes remain on stdin, as in the harness.
fn send_fragments(namespace: &str, packets: &[Vec<u8>]) {
    const PYTHON_SENDER: &str = r#"
import socket
import struct
import sys

sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
stream = sys.stdin.buffer
while True:
    encoded = stream.read(4)
    if not encoded:
        break
    if len(encoded) != 4:
        raise SystemExit(1)
    length = struct.unpack("!I", encoded)[0]
    packet = stream.read(length)
    if len(packet) != length:
        raise SystemExit(1)
    if sender.sendto(packet, (socket.inet_ntoa(packet[16:20]), 0)) != length:
        raise SystemExit(1)
"#;
    let mut child = Command::new("ip")
        .args(["netns", "exec", namespace, "python3", "-c", PYTHON_SENDER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for packet in packets {
        stdin
            .write_all(&u32::try_from(packet.len()).unwrap().to_be_bytes())
            .unwrap();
        stdin.write_all(packet).unwrap();
    }
    drop(stdin);
    assert!(
        child.wait().unwrap().success(),
        "fragment batch sender failed"
    );
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_pair() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let malformed_before = malformed_count(&fixture.pin_dir);
    let encapsulated = pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP);
    let started = Instant::now();
    fixture.forward_many(
        &[esp_fragment(0x7121, MORE), esp_fragment(0x7121, 3)],
        PEER_TEID_A,
    );
    assert_live(started);
    assert_eq!(malformed_count(&fixture.pin_dir), malformed_before);
    assert_eq!(
        pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP),
        encapsulated + 2
    );
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_exact_key() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let alternate_paa = Ipv4Addr::new(10, 45, 0, 3);
    for (mark, local, peer) in [
        (None, 0x1100_0001, 0x2100_0001),
        (Some(MARK_B), 0x1100_0002, 0x2100_0002),
    ] {
        let mut context = session_context(fixture.device.ifindex);
        context.ms_address = IpAddr::V4(alternate_paa);
        context.local_teid = Teid::new(local).unwrap();
        context.peer_teid = Teid::new(peer).unwrap();
        context.bearer_mark = mark.map(|mark| GtpBearerMark::new(mark).unwrap());
        fixture.backend.install_pdp_context(context).await?;
    }
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(classifier_for(
                fixture.device.ifindex,
                alternate_paa,
                &[(MARK_B, SPI)]
            ))
            .await?,
        TftUplinkClassifierReconcileOutcome::Installed
    );
    run("ip", &["route", "add", "8.8.4.4/32", "via", "192.0.2.10"]);
    // The alternate key has a real default and dedicated classifier. An absent
    // classifier's intentional fallback cannot accidentally satisfy this test.
    fixture.forward(
        &with_paa(esp_fragment(0x7200, 0), alternate_paa),
        0x2100_0002,
    );
    fixture.reject(&esp_fragment(0x7201, 3), DropCounter::Invalid);
    let mut changed_destination = esp_fragment(0x7202, 3);
    changed_destination[16..20].copy_from_slice(&[8, 8, 4, 4]);
    checksum(&mut changed_destination);
    let mut changed_protocol = esp_fragment(0x7202, 3);
    changed_protocol[9] = 51;
    checksum(&mut changed_protocol);
    let started = fixture.first(0x7202);
    fixture.reject_many(
        &[
            esp_fragment(0x7203, 3),
            with_paa(esp_fragment(0x7202, 3), alternate_paa),
            changed_destination,
            changed_protocol,
        ],
        DropCounter::Invalid,
    );
    fixture.forward(&esp_fragment(0x7202, 3), PEER_TEID_A);
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_conflicting_first() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(classifier_for(
                fixture.device.ifindex,
                UE_PAA,
                &[(MARK_A, SPI), (MARK_B, SPI_B)]
            ))
            .await?,
        TftUplinkClassifierReconcileOutcome::Replaced
    );
    // A changed first fragment cannot move a live datagram to another
    // dedicated bearer, to default, or between different SPIs on default.
    for (id, original, replacement, peer) in [
        (0x7301, SPI, SPI_B, PEER_TEID_A),
        (0x7302, SPI, 0x9090_9090, PEER_TEID_A),
        (0x7303, 0x9090_9090, 0x9191_9191, PEER_TEID),
    ] {
        let started = Instant::now();
        let first = with_spi(esp_fragment(id, MORE), original);
        // Identical first duplicates are allowed.
        fixture.forward_many(&[first.clone(), first.clone()], peer);
        fixture.reject_many(
            &[
                with_spi(esp_fragment(id, MORE), replacement),
                esp_fragment(id, 3),
                first,
            ],
            DropCounter::Invalid,
        );
        assert_live(started);
    }
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_overlap_and_range_bound() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let started = fixture.first(0x7401);
    // Bytes 16..40 overlap the accepted first interval 0..24.
    fixture.reject_many(
        &[
            esp_fragment(0x7401, MORE | 2),
            esp_fragment(0x7401, 3),
            esp_fragment(0x7401, MORE),
        ],
        DropCounter::Invalid,
    );
    assert_live(started);

    let started = fixture.first(0x7402);
    fixture.forward(&esp_fragment(0x7402, MORE | 3), PEER_TEID_A);
    // Unlike a duplicate first, a duplicate later interval is ambiguous.
    fixture.reject_many(
        &[esp_fragment(0x7402, MORE | 3), esp_fragment(0x7402, 6)],
        DropCounter::Invalid,
    );
    assert_live(started);

    let started = fixture.first(0x7403);
    fixture.forward(&esp_fragment(0x7403, 6), PEER_TEID_A);
    // A distinct second final interval conflicts with the retained final end.
    fixture.reject(&esp_fragment(0x7403, 3), DropCounter::Invalid);
    assert_live(started);

    // A valid envelope with an incomplete first TCP header cannot establish
    // even a default decision. The corresponding tail remains an orphan.
    let mut incomplete = esp_fragment(0x7404, MORE);
    incomplete.truncate(28);
    incomplete[2..4].copy_from_slice(&28_u16.to_be_bytes());
    incomplete[9] = 6;
    checksum(&mut incomplete);
    fixture.reject(&incomplete, DropCounter::Malformed);
    let mut orphan = esp_fragment(0x7404, 1);
    orphan[9] = 6;
    checksum(&mut orphan);
    fixture.reject(&orphan, DropCounter::Invalid);

    let packets = (0..TFT_FRAGMENT_MAX_RANGES)
        .map(|index| esp_fragment(0x7405, MORE | u16::try_from(index * 3).unwrap()))
        .collect::<Vec<_>>();
    let started = Instant::now();
    let encapsulated = pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP);
    let malformed = malformed_count(&fixture.pin_dir);
    send_fragments(&fixture.net.ue_ns, &packets);
    for packet in &packets {
        receive_fragment(&fixture.socket, packet, EPDG_S2BU_IP, PEER_TEID_A);
    }
    assert_eq!(
        pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP),
        encapsulated + u64::try_from(TFT_FRAGMENT_MAX_RANGES).unwrap()
    );
    assert_eq!(malformed_count(&fixture.pin_dir), malformed);
    fixture.reject_many(
        &[
            esp_fragment(0x7405, u16::try_from(TFT_FRAGMENT_MAX_RANGES * 3).unwrap()),
            esp_fragment(0x7405, MORE),
        ],
        DropCounter::Invalid,
    );
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_classifier_identity() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let key = TftClassifierKey::new(fixture.device.ifindex, UE_PAA.octets())
        .unwrap()
        .encode();
    let mut metadata = meta_map(&fixture.pin_dir);
    let original = metadata.get(&key, 0).unwrap();
    let meta = TftClassifierMeta::decode(original).unwrap();
    let mut other_owner = meta.owner().unwrap().into_bytes();
    other_owner[0] ^= 0x80;
    let mut other_fingerprint = meta.classifier_fingerprint();
    other_fingerprint[0] ^= 0x80;
    for (index, owner, owner_generation, snapshot_generation, fingerprint) in [
        (
            0,
            TftClassifierOwnerId::new(other_owner).unwrap(),
            meta.owner_generation(),
            meta.snapshot_generation(),
            meta.classifier_fingerprint(),
        ),
        (
            1,
            meta.owner().unwrap(),
            meta.owner_generation().checked_add(1).unwrap(),
            meta.snapshot_generation(),
            meta.classifier_fingerprint(),
        ),
        (
            2,
            meta.owner().unwrap(),
            meta.owner_generation(),
            meta.snapshot_generation().checked_add(1).unwrap(),
            meta.classifier_fingerprint(),
        ),
        (
            3,
            meta.owner().unwrap(),
            meta.owner_generation(),
            meta.snapshot_generation(),
            other_fingerprint,
        ),
    ] {
        let id = 0x7500 + index;
        let started = fixture.first(id);
        // Canonical metadata changes one identity field only. A tail does not
        // read filter rows, so this isolates affinity identity validation.
        let replacement = TftClassifierMeta::new(
            meta.active_bank(),
            meta.has_default(),
            owner,
            owner_generation,
            snapshot_generation,
            meta.filter_count(),
            fingerprint,
        )
        .unwrap();
        metadata.insert(key, replacement.encode(), 0).unwrap();
        fixture.reject(&esp_fragment(id, 3), DropCounter::Invalid);
        metadata.insert(key, original, 0).unwrap();
        // Restoring the old authority cannot resurrect a poisoned live key.
        fixture.reject_many(
            &[esp_fragment(id, 3), esp_fragment(id, MORE)],
            DropCounter::Invalid,
        );
        assert_live(started);
    }
    let started = fixture.first(0x7510);
    fixture.forward(&esp_fragment(0x7510, 3), PEER_TEID_A);
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_lifecycle() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let classifier = esp_classifier(fixture.device.ifindex);
    let key = TftClassifierKey::new(fixture.device.ifindex, UE_PAA.octets())
        .unwrap()
        .encode();
    let old_meta = meta_map(&fixture.pin_dir).get(&key, 0).unwrap();
    let started = Instant::now();
    // Leave the second live entry untouched throughout removal. Its first
    // post-removal packet arrives only after an identical reinstall.
    fixture.forward_many(
        &[esp_fragment(0x7601, MORE), esp_fragment(0x7606, MORE)],
        PEER_TEID_A,
    );
    assert_eq!(
        fixture
            .backend
            .remove_tft_uplink_classifier_exact(classifier.clone())
            .await?,
        TftUplinkClassifierRemovalOutcome::Removed
    );
    assert_eq!(
        fixture
            .backend
            .read_tft_uplink_classifier(fixture.device.ifindex, IpAddr::V4(UE_PAA))
            .await?,
        TftUplinkClassifierReadback::Absent
    );
    fixture.reject_many(
        &[esp_fragment(0x7601, 3), esp_fragment(0x7601, MORE)],
        DropCounter::Invalid,
    );
    // No live key and no classifier retains the pre-existing default path.
    fixture.forward_many(
        &[esp_fragment(0x7602, 0), esp_fragment(0x7603, 3)],
        PEER_TEID,
    );
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(classifier)
            .await?,
        TftUplinkClassifierReconcileOutcome::Installed
    );
    let reinstalled = meta_map(&fixture.pin_dir).get(&key, 0).unwrap();
    assert_ne!(
        old_meta, reinstalled,
        "identical remove/reinstall must change publication identity"
    );
    fixture.reject_many(
        &[esp_fragment(0x7606, 3), esp_fragment(0x7606, MORE)],
        DropCounter::Invalid,
    );
    assert_live(started);

    let started = fixture.first(0x7604);
    let established = Instant::now();
    let replacement = classifier_for(fixture.device.ifindex, UE_PAA, &[(MARK_B, SPI)]);
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(replacement)
            .await?,
        TftUplinkClassifierReconcileOutcome::Replaced
    );
    fixture.reject_many(
        &[esp_fragment(0x7604, 3), esp_fragment(0x7604, MORE)],
        DropCounter::Invalid,
    );
    fixture.forward_many(
        &[esp_fragment(0x7605, MORE), esp_fragment(0x7605, 3)],
        PEER_TEID_B,
    );
    assert_live(started);
    expire(established);
    // Reusing the poisoned old ID is safe only after the immutable deadline,
    // and must take the replacement's exact dedicated peer TEID.
    fixture.forward_many(
        &[esp_fragment(0x7604, MORE), esp_fragment(0x7604, 3)],
        PEER_TEID_B,
    );
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_malformed_retained() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    // Keep authority installed: the valid tail must depend on the malformed
    // packet poisoning this key, not on an absent-classifier rejection.
    let started = fixture.first(0x7b00);
    fixture.reject(
        &esp_fragment(0x7b00, 0x4000 | MORE | 3),
        DropCounter::Malformed,
    );
    fixture.reject(&esp_fragment(0x7b00, 3), DropCounter::Invalid);
    assert_live(started);
    let started = fixture.first(0x7b01);
    assert_eq!(
        fixture
            .backend
            .remove_tft_uplink_classifier_exact(esp_classifier(fixture.device.ifindex))
            .await?,
        TftUplinkClassifierRemovalOutcome::Removed
    );
    // Version 4 with DF+MF reaches tc's fragment classifier. Its malformed
    // envelope must find the retained key before an absent classifier could
    // permit default-bearer fallback.
    fixture.reject(
        &esp_fragment(0x7b01, 0x4000 | MORE | 3),
        DropCounter::Malformed,
    );
    fixture.reject(&esp_fragment(0x7b01, 3), DropCounter::Invalid);
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_expiry() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    fixture.first(0x7701);
    let established = Instant::now();
    let bucket = fragment_key(fixture.device.ifindex, 0x7701).bucket();
    let original = bucket_bytes(&fixture.pin_dir, bucket);
    std::thread::sleep(Duration::from_millis(800));
    fixture.forward(&esp_fragment(0x7701, MORE), PEER_TEID_A);
    assert_eq!(
        bucket_bytes(&fixture.pin_dir, bucket),
        original,
        "identical first duplicate must not refresh the deadline or add a range"
    );
    assert_live(established);
    expire(established);
    fixture.reject(&esp_fragment(0x7701, 3), DropCounter::Invalid);
    let started = fixture.first(0x7701);
    fixture.forward(&esp_fragment(0x7701, 3), PEER_TEID_A);
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_authority_revocation() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let started = fixture.first(0x7801);
    let key = TftClassifierKey::new(fixture.device.ifindex, UE_PAA.octets())
        .unwrap()
        .encode();
    let original_meta = meta_map(&fixture.pin_dir).get(&key, 0).unwrap();
    let bearer =
        dedicated_session_context(fixture.device.ifindex, MARK_A, LOCAL_TEID_A, PEER_TEID_A);
    assert_eq!(
        fixture
            .backend
            .remove_pdp_context_exact(bearer.clone())
            .await?,
        PdpContextRemovalOutcome::Removed
    );
    assert_eq!(
        meta_map(&fixture.pin_dir).get(&key, 0).unwrap(),
        original_meta
    );
    // Classifier identity still matches. Only the existing exact marked
    // forwarding authority rejects; TFT counters must remain unchanged.
    fixture.reject(&esp_fragment(0x7801, 3), DropCounter::Authority);
    assert_live(started);
    fixture.forward(&with_spi(esp_fragment(0x7802, 0), SPI_B), PEER_TEID);
    fixture.backend.install_pdp_context(bearer).await?;
    let started = fixture.first(0x7803);
    fixture.forward(&esp_fragment(0x7803, 3), PEER_TEID_A);
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_capacity() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let (_, key_size, value_size, max_entries) =
        pinned_map_abi(&fixture.pin_dir, MAP_TFT_FRAGMENT_AFFINITY).unwrap();
    assert_eq!(
        (key_size, value_size, max_entries),
        (
            4,
            u32::try_from(TFT_FRAGMENT_BUCKET_VALUE_LEN).unwrap(),
            TFT_FRAGMENT_BUCKETS
        )
    );
    let mut by_bucket = vec![Vec::new(); TFT_FRAGMENT_BUCKETS as usize];
    let collisions = (1..=u16::MAX)
        .find_map(|id| {
            let bucket = fragment_key(fixture.device.ifindex, id).bucket() as usize;
            by_bucket[bucket].push(id);
            (by_bucket[bucket].len() == TFT_FRAGMENT_WAYS + 1).then(|| by_bucket[bucket].clone())
        })
        .expect("five synthetic IPv4 IDs collide in one bounded bucket");
    let bucket = fragment_key(fixture.device.ifindex, collisions[0]).bucket();
    let started = Instant::now();
    fixture.forward_many(
        &collisions[..TFT_FRAGMENT_WAYS]
            .iter()
            .map(|id| esp_fragment(*id, MORE))
            .collect::<Vec<_>>(),
        PEER_TEID_A,
    );
    assert!(
        bucket_bytes(&fixture.pin_dir, (bucket + 1) % TFT_FRAGMENT_BUCKETS)[4..]
            .iter()
            .all(|byte| *byte == 0),
        "capacity refusal must occur while another bucket is entirely free"
    );
    let admitted = bucket_bytes(&fixture.pin_dir, bucket);
    fixture.reject(
        &esp_fragment(collisions[TFT_FRAGMENT_WAYS], MORE),
        DropCounter::Invalid,
    );
    assert_eq!(
        bucket_bytes(&fixture.pin_dir, bucket),
        admitted,
        "a full bucket must not evict or alter any live entry"
    );
    fixture.forward_many(
        &collisions[..TFT_FRAGMENT_WAYS]
            .iter()
            .map(|id| esp_fragment(*id, 3))
            .collect::<Vec<_>>(),
        PEER_TEID_A,
    );
    fixture.reject(
        &esp_fragment(collisions[TFT_FRAGMENT_WAYS], 3),
        DropCounter::Invalid,
    );
    assert_live(started);
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_cross_attachment() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    // Reuse the already owned UE-side veth as a second real attachment. Its
    // independent classifier and peer socket make wrong-interface reuse visible.
    let second_local = Ipv4Addr::new(10, 45, 0, 1);
    let mut request = CreateGtpDeviceRequest::new("ue0");
    request.bind_address = IpAddr::V4(second_local);
    let second = fixture.backend.create_device(request).await?;
    assert_ne!(fixture.device.ifindex, second.ifindex);
    for (mark, local, peer) in [
        (None, 0x1200_0001, 0x2200_0001),
        (Some(MARK_B), 0x1200_0002, 0x2200_0002),
    ] {
        let mut context = session_context(second.ifindex);
        context.local_teid = Teid::new(local).unwrap();
        context.peer_teid = Teid::new(peer).unwrap();
        context.peer_address = IpAddr::V4(UE_PAA);
        context.bearer_mark = mark.map(|mark| GtpBearerMark::new(mark).unwrap());
        fixture.backend.install_pdp_context(context).await?;
    }
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(classifier_for(
                second.ifindex,
                UE_PAA,
                &[(MARK_B, SPI)]
            ))
            .await?,
        TftUplinkClassifierReconcileOutcome::Installed
    );
    let second_socket = in_netns(&fixture.net.ue_ns, || {
        UdpSocket::bind((UE_PAA, GTPU_PORT)).unwrap()
    });
    let second_pin_dir = fixture.net.pin_root.join("ue0");
    let started = fixture.first(0x7901);
    run(
        "ip",
        &[
            "route",
            "replace",
            "8.8.8.8/32",
            "via",
            "10.45.0.2",
            "dev",
            "ue0",
        ],
    );
    reject_fragment(
        &fixture.net.ue_ns,
        &second_socket,
        &second_pin_dir,
        &esp_fragment(0x7901, 3),
        DropCounter::Invalid,
    );
    socket_is_empty(&fixture.socket);
    send_wireguard_ipv4_packet(&fixture.net.ue_ns, &esp_fragment(0x7901, MORE));
    receive_fragment(
        &second_socket,
        &esp_fragment(0x7901, MORE),
        second_local,
        0x2200_0002,
    );
    send_wireguard_ipv4_packet(&fixture.net.ue_ns, &esp_fragment(0x7901, 3));
    receive_fragment(
        &second_socket,
        &esp_fragment(0x7901, 3),
        second_local,
        0x2200_0002,
    );
    run(
        "ip",
        &[
            "route",
            "replace",
            "8.8.8.8/32",
            "via",
            "192.0.2.10",
            "dev",
            "s2bu",
        ],
    );
    fixture.forward(&esp_fragment(0x7901, 3), PEER_TEID_A);
    socket_is_empty(&second_socket);
    assert_live(started);
    fixture.backend.remove_device(&second).await?;
    fixture.finish().await
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_port_only_control() -> TestResult {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new().await?;
    let filter = PacketFilter::new(
        PacketFilterIdentifier::new(0).unwrap(),
        PacketFilterDirection::UplinkOnly,
        10,
        vec![
            PacketFilterComponent::SingleLocalPort(0x1020),
            PacketFilterComponent::SingleRemotePort(0x3040),
        ],
    )
    .unwrap();
    let classifier = TftUplinkClassifier::new(
        fixture.device.ifindex,
        IpAddr::V4(UE_PAA),
        vec![
            TftUplinkBearer::default_bearer(),
            TftUplinkBearer::dedicated(
                GtpBearerMark::new(MARK_A).unwrap(),
                TrafficFlowTemplate::create_new(vec![filter], vec![]).unwrap(),
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        fixture
            .backend
            .reconcile_tft_uplink_classifier(classifier)
            .await?,
        TftUplinkClassifierReconcileOutcome::Replaced
    );
    let malformed = malformed_count(&fixture.pin_dir);
    let encapsulated = pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP);
    // ESP SPI bytes deliberately equal the port tuple. Protected payload must
    // never be reinterpreted as a transport header.
    fixture.forward(&esp_fragment(0x7a01, 0), PEER_TEID);
    assert_eq!(malformed_count(&fixture.pin_dir), malformed);
    assert_eq!(
        pinned_counter(&fixture.pin_dir, COUNTER_UL_ENCAP),
        encapsulated + 1
    );
    socket_is_empty(&fixture.socket);
    fixture.finish().await
}
