//! Default-bearer uplink continuity across exact TFT classifier removal
//! (#1030).
//!
//! TS 24.302 §7.4.6.4.3: the ePDG forwards an uplink packet received on an
//! S2b bearer's SA using that bearer. With the shared-SA default model
//! (TS 23.402 §4.10.5.1), unmarked packets that match no dedicated filter use
//! the default bearer before, during, and after a dedicated bearer's filters
//! are removed. Exact removal first converts the published selector into its
//! durable removal fence. These proofs pin the tc behaviour for that state:
//! a fence whose classifier has a default bearer forwards unmarked packets
//! exactly as its absent successor does, including after rows below the
//! durable cursor are gone; a fence without a default bearer still drops.
//!
//! Synthetic documentation/private addresses and payloads only.

use super::*;
use opc_gtpu_ebpf_common::{
    TftClassifierFilterKey, TftClassifierMeta, COUNTER_TFT_CLASSIFIER_INVALID_STATE,
};
use std::sync::atomic::{AtomicBool, AtomicU64};

const VOICE_PORT: u16 = 5010;
const VOICE_CONTROL_PORT: u16 = 5011;
const DEFAULT_PORT: u16 = 5099;
const REMOTE_PORT: u16 = 5499;
const PROBE_TAG: [u8; 8] = *b"tftfence";
const PROBE_INTERVAL: Duration = Duration::from_micros(50);
const CONTROL_WINDOW: Duration = Duration::from_millis(200);
const REMOVAL_CYCLES: usize = 12;
const CYCLE_SETTLE: Duration = Duration::from_millis(20);
const DRAIN_IDLE: Duration = Duration::from_millis(200);
const PGW_RECEIVE_BUFFER: usize = 16 << 20;

/// One dedicated voice bearer with two UDP local-port filters, optionally
/// beside the unfiltered default bearer.
fn voice_classifier(link_ifindex: u32, with_default: bool) -> TftUplinkClassifier {
    let filter = |identifier: u8, precedence: u8, port: u16| {
        PacketFilter::new(
            PacketFilterIdentifier::new(identifier).expect("TFT identifier is four-bit"),
            PacketFilterDirection::UplinkOnly,
            precedence,
            vec![
                PacketFilterComponent::ProtocolIdentifierNextHeader(IPPROTO_UDP),
                PacketFilterComponent::SingleLocalPort(port),
            ],
        )
        .expect("TFT packet filter is canonical")
    };
    let voice = TrafficFlowTemplate::create_new(
        vec![filter(0, 10, VOICE_PORT), filter(1, 11, VOICE_CONTROL_PORT)],
        Vec::new(),
    )
    .expect("TFT snapshot is canonical");
    let mut bearers = vec![TftUplinkBearer::dedicated(
        GtpBearerMark::new(MARK_A).expect("nonzero dedicated mark"),
        voice,
    )];
    if with_default {
        bearers.insert(0, TftUplinkBearer::default_bearer());
    }
    TftUplinkClassifier::new(link_ifindex, IpAddr::V4(UE_PAA), bearers)
        .expect("canonical shared-PAA TFT classifier")
}

/// Create the S2b-U device with the default bearer and one marked dedicated
/// bearer sharing the UE PAA.
async fn provision_shared_paa(
) -> Result<(TestNet, EbpfGtpuDataplaneBackend, GtpDevice), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    backend
        .install_pdp_context(session_context(device.ifindex))
        .await?;
    backend
        .install_pdp_context(dedicated_session_context(
            device.ifindex,
            MARK_A,
            LOCAL_TEID_A,
            PEER_TEID_A,
        ))
        .await?;
    Ok((net, backend, device))
}

fn send_uplink_probe(net: &TestNet, source_port: u16, sentinel: &[u8]) {
    let packet = build_inner_udp(UE_PAA, REMOTE_HOST, source_port, REMOTE_PORT, sentinel);
    send_wireguard_ipv4_packet(&net.ue_ns, &packet);
}

fn tft_drop_count(pin_dir: &Path, slot: u32) -> u64 {
    pinned_per_cpu_u64_values(
        pin_dir,
        MAP_TFT_CLASSIFIER_COUNTERS,
        TFT_CLASSIFIER_COUNTER_SLOTS,
    )[usize::try_from(slot).expect("counter index fits usize")]
    .iter()
    .sum()
}

fn pinned_tft_meta(
    pin_dir: &Path,
) -> BpfHashMap<MapData, [u8; TFT_CLASSIFIER_KEY_LEN], [u8; TFT_CLASSIFIER_META_VALUE_LEN]> {
    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_TFT_CLASSIFIER_META)).expect("open pinned TFT metadata"),
    )
    .expect("identify pinned TFT metadata");
    BpfHashMap::try_from(map).expect("typed pinned TFT metadata")
}

fn only_tft_meta_entry(
    meta: &BpfHashMap<MapData, [u8; TFT_CLASSIFIER_KEY_LEN], [u8; TFT_CLASSIFIER_META_VALUE_LEN]>,
) -> (
    [u8; TFT_CLASSIFIER_KEY_LEN],
    [u8; TFT_CLASSIFIER_META_VALUE_LEN],
) {
    let entries = meta
        .iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("read pinned TFT metadata");
    assert_eq!(entries.len(), 1, "exactly one classifier is published");
    entries[0]
}

/// Leave the durable state of an exact removal interrupted right after its
/// first step: the published selector converted in place into its removal
/// fence, every filter row intact.
fn fence_published_classifier(pin_dir: &Path) -> TftClassifierMeta {
    let mut meta = pinned_tft_meta(pin_dir);
    let (key, raw) = only_tft_meta_entry(&meta);
    let fence = TftClassifierMeta::decode(raw)
        .and_then(TftClassifierMeta::removing)
        .expect("the published selector converts to its removal fence");
    meta.insert(key, fence.encode(), 0)
        .expect("publish the removal fence");
    fence
}

/// Continue the interrupted removal by one rank, in the backend's order:
/// durably advance the cursor over rank zero, then delete that active row.
fn delete_first_fenced_rank(pin_dir: &Path, fence: TftClassifierMeta) {
    let advanced = fence
        .advance_removal_progress()
        .expect("the fence authorizes deleting rank zero");
    let mut meta = pinned_tft_meta(pin_dir);
    let (key, raw) = only_tft_meta_entry(&meta);
    assert_eq!(raw, fence.encode(), "the fence is still published");
    meta.insert(key, advanced.encode(), 0)
        .expect("publish the advanced removal cursor");

    let map = Map::from_map_data(
        MapData::from_pin(pin_dir.join(MAP_TFT_CLASSIFIER_FILTERS))
            .expect("open pinned TFT filters"),
    )
    .expect("identify pinned TFT filters");
    let mut filters = BpfHashMap::<
        _,
        [u8; TFT_CLASSIFIER_FILTER_KEY_LEN],
        [u8; TFT_CLASSIFIER_FILTER_VALUE_LEN],
    >::try_from(map)
    .expect("typed pinned TFT filters");
    let keys = filters
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .expect("read pinned TFT filter keys");
    assert_eq!(
        keys.len(),
        usize::from(fence.filter_count()),
        "every active row is present before the first deletion"
    );
    let first = keys
        .into_iter()
        .find(|raw_key| {
            TftClassifierFilterKey::decode(*raw_key).is_some_and(|filter_key| {
                filter_key.bank() == fence.active_bank() && filter_key.filter_index() == 0
            })
        })
        .expect("the active bank has a rank-zero row");
    filters.remove(&first).expect("delete the rank-zero row");
}

// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_fence() -> Result<(), Box<dyn std::error::Error>> {
    let nohz_full = tft_nohz_full::require_requested_profile();
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (net, backend, device) = provision_shared_paa().await?;
    if nohz_full {
        tft_nohz_full::require_aya_available(&backend);
    }
    let pin_dir = net.pin_root.join("s2bu");
    let pgw_socket = in_netns(&net.pgw_ns, || {
        UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW TFT GTP-U socket")
    });

    let with_default = voice_classifier(device.ifindex, true);
    assert_eq!(
        backend
            .reconcile_tft_uplink_classifier(with_default.clone())
            .await?,
        TftUplinkClassifierReconcileOutcome::Installed
    );
    send_uplink_probe(&net, VOICE_PORT, b"fence-baseline-voice");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID_A, b"fence-baseline-voice");
    send_uplink_probe(&net, DEFAULT_PORT, b"fence-baseline-default");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-baseline-default");

    let invalid_before = tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE);
    let fence = fence_published_classifier(&pin_dir);
    // Default-bearer traffic is forwarded exactly as by the absent successor.
    send_uplink_probe(&net, DEFAULT_PORT, b"fence-default");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-default");
    // So is the flow whose filters are being removed: it takes the default
    // bearer now, as it will once the classifier is absent.
    send_uplink_probe(&net, VOICE_PORT, b"fence-voice");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-voice");
    // Rows below the durable cursor may already be gone; tc must not read
    // them.
    delete_first_fenced_rank(&pin_dir, fence);
    send_uplink_probe(&net, DEFAULT_PORT, b"fence-partial-default");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-partial-default");
    send_uplink_probe(&net, VOICE_CONTROL_PORT, b"fence-partial-voice");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-partial-voice");
    assert_eq!(
        tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE),
        invalid_before,
        "a removal fence with a default bearer must not drop as invalid state"
    );

    // Exact removal resumes from the durable fence and cursor.
    assert_eq!(
        backend
            .remove_tft_uplink_classifier_exact(with_default)
            .await?,
        TftUplinkClassifierRemovalOutcome::Removed
    );
    assert_eq!(
        backend
            .read_tft_uplink_classifier(device.ifindex, IpAddr::V4(UE_PAA))
            .await?,
        TftUplinkClassifierReadback::Absent
    );
    send_uplink_probe(&net, VOICE_PORT, b"fence-removed-voice");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"fence-removed-voice");

    // Without a default bearer, unmatched traffic has no bearer while the
    // classifier exists, and its fence keeps failing closed.
    let without_default = voice_classifier(device.ifindex, false);
    assert_eq!(
        backend
            .reconcile_tft_uplink_classifier(without_default.clone())
            .await?,
        TftUplinkClassifierReconcileOutcome::Installed
    );
    send_uplink_probe(&net, VOICE_PORT, b"no-default-voice");
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID_A, b"no-default-voice");
    fence_published_classifier(&pin_dir);
    let invalid_before = tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE);
    send_uplink_probe(&net, DEFAULT_PORT, b"no-default-fence-unmatched");
    expect_no_datagram(&pgw_socket);
    send_uplink_probe(&net, VOICE_PORT, b"no-default-fence-voice");
    expect_no_datagram(&pgw_socket);
    assert_eq!(
        tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE),
        invalid_before + 2,
        "a removal fence without a default bearer must drop as invalid state"
    );
    assert_eq!(
        backend
            .remove_tft_uplink_classifier_exact(without_default)
            .await?,
        TftUplinkClassifierRemovalOutcome::Removed
    );
    let maps = current_map_contents(&pin_dir);
    assert!(maps.tft_meta.is_empty());
    assert!(maps.tft_filters.is_empty());

    drop(pgw_socket);
    backend.remove_device(&device).await?;
    eprintln!(
        "OPC_GTPU_TFT_REMOVAL_FENCE_DEFAULT_PROVEN: fence and partly deleted fence forward on the default bearer; no-default fence drops"
    );
    Ok(())
}

/// Send tagged default-bearer probes at a fixed pace until `stop`, publishing
/// the count sent so far. A late sender resumes the pace without a burst.
fn send_probes(socket: &UdpSocket, stop: &AtomicBool, sent: &AtomicU64) -> u64 {
    let mut payload = [0_u8; 16];
    payload[..8].copy_from_slice(&PROBE_TAG);
    let mut sequence = 0_u64;
    let mut deadline = Instant::now();
    while !stop.load(Ordering::Acquire) {
        payload[8..].copy_from_slice(&sequence.to_be_bytes());
        socket
            .send(&payload)
            .expect("send a default-bearer uplink probe");
        sequence += 1;
        sent.store(sequence, Ordering::Release);
        deadline += PROBE_INTERVAL;
        let now = Instant::now();
        if deadline <= now {
            deadline = now;
        } else {
            while Instant::now() < deadline {
                std::hint::spin_loop();
            }
        }
    }
    sequence
}

/// Return the probe sequence number and TEID of one received G-PDU.
fn parse_probe(datagram: &[u8]) -> Option<(u64, u32)> {
    if datagram.len() < GTPU_MANDATORY_HDR_LEN + IPV4_MIN_HDR_LEN + UDP_HDR_LEN + 16
        || datagram[0] != 0x30
        || datagram[1] != 0xff
    {
        return None;
    }
    let teid = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    let (tag, sequence) = datagram[datagram.len() - 16..].split_at(8);
    (tag == PROBE_TAG).then(|| {
        (
            u64::from_be_bytes(sequence.try_into().expect("eight-byte sequence")),
            teid,
        )
    })
}

/// Receive G-PDUs until `stop` is set and the path has been idle for
/// `DRAIN_IDLE`. Returns every parsed probe and the count of other datagrams.
fn receive_probes(socket: &UdpSocket, stop: &AtomicBool) -> (Vec<(u64, u32)>, usize) {
    socket
        .set_read_timeout(Some(DRAIN_IDLE))
        .expect("set probe receive timeout");
    let mut buffer = vec![0_u8; 2048];
    let mut probes = Vec::new();
    let mut other = 0_usize;
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => match parse_probe(&buffer[..length]) {
                Some(probe) => probes.push(probe),
                None => other += 1,
            },
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Ordering::Acquire) {
                    return (probes, other);
                }
            }
            Err(error) => panic!("probe receive failed: {error}"),
        }
    }
}

// The serial guard is deliberately held for the entire test body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify_continuity() -> Result<(), Box<dyn std::error::Error>> {
    let nohz_full = tft_nohz_full::require_requested_profile();
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (net, backend, device) = provision_shared_paa().await?;
    if nohz_full {
        tft_nohz_full::require_aya_available(&backend);
    }
    let pin_dir = net.pin_root.join("s2bu");
    let pgw_socket = in_netns(&net.pgw_ns, || {
        let socket = UdpSocket::bind((PGW_IP, GTPU_PORT)).expect("bind PGW TFT GTP-U socket");
        nix::sys::socket::setsockopt(
            &socket,
            nix::sys::socket::sockopt::RcvBufForce,
            &PGW_RECEIVE_BUFFER,
        )
        .expect("size the PGW receive buffer");
        socket
    });
    let ue_socket = in_netns(&net.ue_ns, || {
        let socket =
            UdpSocket::bind((UE_PAA, DEFAULT_PORT)).expect("bind the UE default-bearer socket");
        socket
            .connect((REMOTE_HOST, REMOTE_PORT))
            .expect("connect the UE default-bearer socket");
        socket
    });
    // Resolve every neighbour on the path before the measured stream starts.
    ue_socket.send(b"continuity-warmup")?;
    receive_tft_uplink_teid(&pgw_socket, PEER_TEID, b"continuity-warmup");

    let classifier = voice_classifier(device.ifindex, true);
    let invalid_before = tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE);
    let stop = Arc::new(AtomicBool::new(false));
    let sent_so_far = Arc::new(AtomicU64::new(0));
    let receiver = {
        let socket = pgw_socket.try_clone()?;
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || receive_probes(&socket, &stop))
    };
    let sender = {
        let stop = Arc::clone(&stop);
        let sent_so_far = Arc::clone(&sent_so_far);
        std::thread::spawn(move || send_probes(&ue_socket, &stop, &sent_so_far))
    };

    std::thread::sleep(CONTROL_WINDOW);
    let control_end = sent_so_far.load(Ordering::Acquire);
    let mut removal_windows = Vec::with_capacity(REMOVAL_CYCLES);
    for cycle in 0..REMOVAL_CYCLES {
        assert_eq!(
            backend
                .reconcile_tft_uplink_classifier(classifier.clone())
                .await?,
            TftUplinkClassifierReconcileOutcome::Installed,
            "cycle {cycle} installs the classifier"
        );
        std::thread::sleep(CYCLE_SETTLE);
        let start = sent_so_far.load(Ordering::Acquire);
        assert_eq!(
            backend
                .remove_tft_uplink_classifier_exact(classifier.clone())
                .await?,
            TftUplinkClassifierRemovalOutcome::Removed,
            "cycle {cycle} removes the classifier"
        );
        removal_windows.push(start..sent_so_far.load(Ordering::Acquire));
        std::thread::sleep(CYCLE_SETTLE);
    }
    stop.store(true, Ordering::Release);
    let sent = sender.join().expect("probe sender thread");
    let (probes, other) = receiver.join().expect("probe receiver thread");
    let invalid_state_drops =
        tft_drop_count(&pin_dir, COUNTER_TFT_CLASSIFIER_INVALID_STATE) - invalid_before;

    let mut seen = vec![false; usize::try_from(sent)?];
    let mut wrong_bearer = 0_usize;
    let mut duplicate = 0_usize;
    let mut unknown = 0_usize;
    for (sequence, teid) in probes {
        let Some(slot) = usize::try_from(sequence)
            .ok()
            .and_then(|index| seen.get_mut(index))
        else {
            unknown += 1;
            continue;
        };
        if *slot {
            duplicate += 1;
        }
        *slot = true;
        if teid != PEER_TEID {
            wrong_bearer += 1;
        }
    }
    let missing = (0..sent)
        .filter(|sequence| !seen[usize::try_from(*sequence).expect("sequence fits usize")])
        .collect::<Vec<_>>();
    let missing_in_control = missing
        .iter()
        .filter(|sequence| **sequence < control_end)
        .count();
    let missing_in_removals = missing
        .iter()
        .filter(|sequence| {
            removal_windows
                .iter()
                .any(|window| window.contains(*sequence))
        })
        .count();
    let probes_in_removals = removal_windows
        .iter()
        .map(|window| window.end - window.start)
        .sum::<u64>();
    eprintln!(
        "TFT removal continuity: sent={sent} control={control_end} sent_during_removals={probes_in_removals} missing={} (control={missing_in_control}, sent during a removal={missing_in_removals}) wrong_bearer={wrong_bearer} duplicate={duplicate} unknown={unknown} other={other} tft_invalid_state_drops={invalid_state_drops}",
        missing.len()
    );
    assert!(
        probes_in_removals > 0,
        "no probe was sent during any classifier removal; the proof would be vacuous"
    );
    assert_eq!(
        missing_in_control, 0,
        "the probe path must be lossless without classifier mutation"
    );
    assert!(
        missing.is_empty()
            && wrong_bearer == 0
            && duplicate == 0
            && unknown == 0
            && other == 0
            && invalid_state_drops == 0,
        "default-bearer uplink must be continuous across {REMOVAL_CYCLES} exact classifier removals"
    );

    drop(pgw_socket);
    backend.remove_device(&device).await?;
    eprintln!(
        "OPC_GTPU_TFT_REMOVAL_CONTINUITY_PROVEN: {sent} default-bearer probes across {REMOVAL_CYCLES} exact classifier removals, none lost"
    );
    Ok(())
}
