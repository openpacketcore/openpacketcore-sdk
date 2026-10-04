//! Synthetic stateful host proofs for the shared inner-uplink fragment contract.
//! Packet-only classifiers remain strict; affinity supplies only a bearer mark.

use std::net::{IpAddr, Ipv4Addr};

use opc_gtpu_dataplane::{
    GtpBearerMark, TftUplinkBearer, TftUplinkClassification, TftUplinkClassifier,
    TftUplinkDropReason, TftUplinkFragmentSnapshot, TftUplinkFragmentTable,
};
use opc_gtpu_ebpf_common::{
    internet_checksum, TftClassifierIpv4Packet, TftClassifierKey, TftFragmentKey,
    TFT_FRAGMENT_BUCKETS, TFT_FRAGMENT_LIFETIME_NS, TFT_FRAGMENT_MAX_RANGES, TFT_FRAGMENT_WAYS,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TrafficFlowTemplate,
};

const IFINDEX: u32 = 7;
const PAA: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const MARK_A: u32 = 11;
const MARK_B: u32 = 12;
// These SPI bytes deliberately resemble local/remote ports.
const SPI: u32 = (40_000_u32 << 16) | 5060;
const SPI_B: u32 = 0x1122_3344;
const MORE: u16 = 0x2000;
const FIRST_TIME: u64 = 100;
const DEADLINE: u64 = FIRST_TIME + TFT_FRAGMENT_LIFETIME_NS;

type Classification = Option<TftUplinkClassification>;

fn selected(mark: u32) -> Classification {
    Some(TftUplinkClassification::Selected(GtpBearerMark::new(mark)))
}

fn dropped(reason: TftUplinkDropReason) -> Classification {
    Some(TftUplinkClassification::Drop(reason))
}

fn invalid() -> Classification {
    dropped(TftUplinkDropReason::InvalidState)
}

fn checksum(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let value = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&value.to_be_bytes());
    assert_eq!(internet_checksum(&packet[..20]), 0);
}

fn ipv4(id: u16, fragment: u16, protocol: u8, payload_length: usize) -> Vec<u8> {
    let mut packet = vec![0xa5; 20 + payload_length];
    packet[..20].fill(0);
    packet[0] = 0x45;
    let total_length = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&fragment.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&PAA.octets());
    packet[16..20].copy_from_slice(&REMOTE.octets());
    checksum(&mut packet);
    packet
}

fn esp(id: u16, fragment: u16, spi: u32) -> Vec<u8> {
    let mut packet = ipv4(id, fragment, 50, 24);
    packet[20..24].copy_from_slice(&spi.to_be_bytes());
    packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
    packet
}

fn bearer(mark: u32, precedence: u8, components: Vec<PacketFilterComponent>) -> TftUplinkBearer {
    let filter = PacketFilter::new(
        PacketFilterIdentifier::new(1).unwrap(),
        PacketFilterDirection::UplinkOnly,
        precedence,
        components,
    )
    .unwrap();
    TftUplinkBearer::dedicated(
        GtpBearerMark::new(mark).unwrap(),
        TrafficFlowTemplate::create_new(vec![filter], vec![]).unwrap(),
    )
}

fn classifier_for(ifindex: u32, paa: Ipv4Addr, selectors: &[(u32, u32)]) -> TftUplinkClassifier {
    let mut bearers = vec![TftUplinkBearer::default_bearer()];
    for (index, &(mark, spi)) in selectors.iter().enumerate() {
        bearers.push(bearer(
            mark,
            10 + u8::try_from(index).unwrap(),
            vec![
                PacketFilterComponent::Ipv4LocalAddress {
                    address: paa,
                    mask: Ipv4Addr::BROADCAST,
                },
                PacketFilterComponent::Ipv4RemoteAddress {
                    address: REMOTE,
                    mask: Ipv4Addr::BROADCAST,
                },
                PacketFilterComponent::ProtocolIdentifierNextHeader(50),
                PacketFilterComponent::SecurityParameterIndex(spi),
            ],
        ));
    }
    TftUplinkClassifier::new(ifindex, IpAddr::V4(paa), bearers).unwrap()
}

fn classifier() -> TftUplinkClassifier {
    classifier_for(IFINDEX, PAA, &[(MARK_A, SPI), (MARK_B, SPI_B)])
}

fn published(classifier: &TftUplinkClassifier) -> TftUplinkFragmentSnapshot {
    TftUplinkFragmentSnapshot::new(classifier, [1; 16], 1, 1).unwrap()
}

fn table() -> TftUplinkFragmentTable {
    TftUplinkFragmentTable::new(IFINDEX).unwrap()
}

fn classify(
    table: &mut TftUplinkFragmentTable,
    current: Option<&TftUplinkFragmentSnapshot>,
    packet: &[u8],
    now: u64,
) -> Classification {
    table.classify(PAA, current, packet, now)
}

#[test]
fn stateful_esp_pair_selects_one_exact_mark() {
    let classifier = classifier();
    let snapshot = published(&classifier);
    let mut table = table();
    for (packet, now) in [
        (esp(1, 0, SPI), FIRST_TIME - 1),
        (esp(1, MORE, SPI), FIRST_TIME),
        (esp(1, 3, SPI), FIRST_TIME + 1),
    ] {
        let result = classify(&mut table, Some(&snapshot), &packet, now);
        assert_eq!(result, selected(MARK_A));
    }
}

#[test]
fn stateless_entry_points_remain_strict_for_first_and_later_fragments() {
    let classifier = classifier();
    for flags in [MORE, 3] {
        let packet = esp(1, flags, SPI);
        assert_eq!(
            classifier.classify(&packet),
            TftUplinkClassification::Drop(TftUplinkDropReason::MalformedOrUnsupportedPacket)
        );
        assert!(TftClassifierIpv4Packet::parse(&packet).is_none());
    }
    assert!(TftClassifierIpv4Packet::parse_first_fragment(&esp(1, MORE, SPI)).is_some());
    assert!(TftClassifierIpv4Packet::parse_first_fragment(&esp(1, 3, SPI)).is_none());
}

#[test]
fn port_only_filters_never_read_esp_ports_and_fragment_pair_keeps_default() {
    let classifier = TftUplinkClassifier::new(
        IFINDEX,
        IpAddr::V4(PAA),
        vec![
            TftUplinkBearer::default_bearer(),
            bearer(
                MARK_A,
                10,
                vec![
                    PacketFilterComponent::SingleLocalPort(40_000),
                    PacketFilterComponent::SingleRemotePort(5060),
                ],
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        classifier.classify(&esp(1, 0, SPI)),
        TftUplinkClassification::Selected(None)
    );
    let snapshot = published(&classifier);
    let mut table = table();
    for (time, flags) in [(100, 0), (101, MORE), (102, 3)] {
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, flags, SPI), time),
            selected(0)
        );
    }
}

#[test]
fn orphan_later_fragment_drops_but_absent_classifier_without_a_key_preserves_fallback() {
    let snapshot = published(&classifier());
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), 100),
        invalid()
    );
    assert_eq!(classify(&mut table, None, &esp(1, 3, SPI), 101), None);
    assert_eq!(classify(&mut table, None, &esp(2, MORE, SPI), 102), None);
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(2, 3, SPI), 103),
        invalid()
    );
}

#[test]
fn changed_first_decision_or_spi_poisons_the_live_key_until_its_original_deadline() {
    let snapshot = published(&classifier());
    for (original_spi, conflicting_spi, original_mark) in [
        (SPI, SPI_B, MARK_A),
        (SPI, 0x9090_9090, MARK_A),
        (0x9090_9090, 0x9191_9191, 0),
    ] {
        let mut table = table();
        let first = esp(1, MORE, original_spi);
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, FIRST_TIME),
            selected(original_mark)
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, FIRST_TIME + 1),
            selected(original_mark)
        );
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(1, MORE, conflicting_spi),
                FIRST_TIME + 2
            ),
            invalid()
        );
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(1, 3, original_spi),
                FIRST_TIME + 3
            ),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, DEADLINE - 1),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, DEADLINE),
            selected(original_mark)
        );
    }
}

#[test]
fn every_packet_key_field_and_attachment_is_isolated() {
    let snapshot = published(&classifier());
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 100),
        selected(MARK_A)
    );
    let mut wrong_source = esp(1, 3, SPI);
    wrong_source[15] ^= 1;
    checksum(&mut wrong_source);
    assert_eq!(
        classify(&mut table, Some(&snapshot), &wrong_source, 101),
        dropped(TftUplinkDropReason::PaaMismatch)
    );
    for (index, mask) in [(19, 1), (9, 1), (5, 1)] {
        let mut foreign_key = esp(1, 3, SPI);
        foreign_key[index] ^= mask;
        checksum(&mut foreign_key);
        assert_eq!(
            classify(&mut table, Some(&snapshot), &foreign_key, 102),
            invalid()
        );
    }
    let other_paa = Ipv4Addr::new(192, 0, 2, 11);
    let other_snapshot = snapshot_for_other_paa(other_paa);
    assert_eq!(
        table.classify(other_paa, Some(&other_snapshot), &wrong_source, 103),
        invalid()
    );
    assert_eq!(
        table.classify(other_paa, Some(&snapshot), &wrong_source, 104),
        invalid()
    );
    let other_interface = published(&classifier_for(IFINDEX + 1, PAA, &[(MARK_B, SPI)]));
    assert_eq!(
        classify(&mut table, Some(&other_interface), &esp(1, 3, SPI), 105),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), 106),
        selected(MARK_A)
    );
}

#[test]
fn failed_first_classification_without_default_poisons_an_existing_key() {
    let classifier = TftUplinkClassifier::new(
        IFINDEX,
        IpAddr::V4(PAA),
        vec![bearer(
            MARK_A,
            10,
            vec![
                PacketFilterComponent::ProtocolIdentifierNextHeader(50),
                PacketFilterComponent::SecurityParameterIndex(SPI),
            ],
        )],
    )
    .unwrap();
    let snapshot = published(&classifier);
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 100),
        selected(MARK_A)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI_B), 101),
        dropped(TftUplinkDropReason::NoMatch)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), 102),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(2, MORE, SPI_B), 103),
        dropped(TftUplinkDropReason::NoMatch)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(2, 3, SPI_B), 104),
        invalid()
    );
}

fn snapshot_for_other_paa(paa: Ipv4Addr) -> TftUplinkFragmentSnapshot {
    published(&classifier_for(IFINDEX, paa, &[(MARK_B, SPI)]))
}

#[test]
fn owner_generations_and_canonical_fingerprint_changes_reject_live_affinity() {
    let classifier = classifier();
    let original = published(&classifier);
    let changed_filters = classifier_for(IFINDEX, PAA, &[(MARK_B, SPI), (MARK_A, SPI_B)]);
    for replacement in [
        TftUplinkFragmentSnapshot::new(&classifier, [2; 16], 1, 1).unwrap(),
        TftUplinkFragmentSnapshot::new(&classifier, [1; 16], 2, 1).unwrap(),
        TftUplinkFragmentSnapshot::new(&classifier, [1; 16], 1, 2).unwrap(),
        // Even a faulty publisher reusing its generation cannot reuse a key
        // under different canonical filters/fingerprint. No raw metadata is
        // paired with a host classifier by this API.
        TftUplinkFragmentSnapshot::new(&changed_filters, [1; 16], 1, 1).unwrap(),
    ] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&original), &esp(1, MORE, SPI), 100),
            selected(MARK_A)
        );
        assert_eq!(
            classify(&mut table, Some(&replacement), &esp(1, 3, SPI), 101),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&original), &esp(1, 3, SPI), 102),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&original), &esp(1, MORE, SPI), 103),
            invalid()
        );
    }
}

#[test]
fn removal_reinstall_and_replacement_retain_stale_keys_until_expiry() {
    let original = published(&classifier());
    let replacement = TftUplinkFragmentSnapshot::new(
        &classifier_for(IFINDEX, PAA, &[(MARK_B, SPI)]),
        [1; 16],
        1,
        2,
    )
    .unwrap();
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&original), &esp(1, MORE, SPI), FIRST_TIME),
        selected(MARK_A)
    );
    assert_eq!(
        classify(&mut table, None, &esp(1, 3, SPI), FIRST_TIME + 1),
        invalid()
    );
    assert_eq!(
        classify(&mut table, None, &esp(1, MORE, SPI), FIRST_TIME + 2),
        invalid()
    );
    assert_eq!(
        classify(&mut table, None, &esp(2, 3, SPI), FIRST_TIME + 3),
        None
    );
    assert_eq!(
        classify(&mut table, None, &esp(1, 0, SPI), FIRST_TIME + 4),
        None
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&replacement),
            &esp(1, MORE, SPI),
            FIRST_TIME + 5
        ),
        invalid()
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&replacement),
            &esp(1, 3, SPI),
            FIRST_TIME + 6
        ),
        invalid()
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&replacement),
            &esp(2, MORE, SPI),
            FIRST_TIME + 7
        ),
        selected(MARK_B)
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&replacement),
            &esp(2, 3, SPI),
            FIRST_TIME + 8
        ),
        selected(MARK_B)
    );
    assert_eq!(
        classify(&mut table, Some(&replacement), &esp(1, MORE, SPI), DEADLINE),
        selected(MARK_B)
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&replacement),
            &esp(1, 3, SPI),
            DEADLINE + 1
        ),
        selected(MARK_B)
    );
}

#[test]
fn identical_reinstall_rejects_tail_without_needing_a_packet_during_removal() {
    let classifier = classifier();
    let original = published(&classifier);
    let reinstalled = TftUplinkFragmentSnapshot::new(&classifier, [1; 16], 1, 2).unwrap();
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&original), &esp(1, MORE, SPI), 100),
        selected(MARK_A)
    );
    assert_eq!(
        classify(&mut table, Some(&reinstalled), &esp(1, 3, SPI), 101),
        invalid()
    );
}

#[test]
fn identical_first_duplicates_and_completion_never_extend_expiry() {
    let snapshot = published(&classifier());
    for completed in [false, true] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), FIRST_TIME),
            selected(MARK_A)
        );
        if completed {
            assert_eq!(
                classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), FIRST_TIME + 1),
                selected(MARK_A)
            );
        }
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(1, MORE, SPI),
                DEADLINE - 1
            ),
            selected(MARK_A)
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), DEADLINE),
            invalid()
        );
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(1, MORE, SPI_B),
                DEADLINE + 1
            ),
            selected(MARK_B)
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, 3, SPI_B), DEADLINE + 2),
            selected(MARK_B)
        );
    }
}

#[test]
fn overlaps_duplicate_tails_and_conflicting_final_intervals_poison_the_key() {
    let snapshot = published(&classifier());
    for (accepted, conflict) in [(None, MORE | 2), (Some(MORE | 3), MORE | 3), (Some(6), 3)] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 100),
            selected(MARK_A)
        );
        if let Some(flags) = accepted {
            assert_eq!(
                classify(&mut table, Some(&snapshot), &esp(1, flags, SPI), 101),
                selected(MARK_A)
            );
        }
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, conflict, SPI), 102),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, 9, SPI), 103),
            invalid()
        );
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 104),
            invalid()
        );
    }
}

#[test]
fn non_overlapping_tails_can_fill_gaps_after_the_first_and_final_fragments() {
    let snapshot = published(&classifier());
    let mut table = table();
    for (time, flags) in [(100, MORE), (101, 9), (102, MORE | 6), (103, MORE | 3)] {
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, flags, SPI), time),
            selected(MARK_A)
        );
    }
}

#[test]
fn range_bound_accepts_64_intervals_then_poisons_without_refresh() {
    let snapshot = published(&classifier());
    let mut table = table();
    for index in 0..TFT_FRAGMENT_MAX_RANGES {
        let flags = MORE | u16::try_from(index * 3).unwrap();
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(1, flags, SPI),
                FIRST_TIME + index as u64
            ),
            selected(MARK_A)
        );
    }
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(1, (TFT_FRAGMENT_MAX_RANGES * 3) as u16, SPI),
            FIRST_TIME + TFT_FRAGMENT_MAX_RANGES as u64
        ),
        invalid()
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(1, MORE, SPI),
            DEADLINE - 1
        ),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), DEADLINE),
        selected(MARK_A)
    );
}

fn fragment_bucket(id: u16) -> u32 {
    TftFragmentKey::new(
        TftClassifierKey::new(IFINDEX, PAA.octets()).unwrap(),
        PAA.octets(),
        REMOTE.octets(),
        50,
        id,
    )
    .bucket()
}

fn colliding_ids() -> Vec<u16> {
    let mut buckets = vec![Vec::new(); TFT_FRAGMENT_BUCKETS as usize];
    for id in 0..=u16::MAX {
        let bucket = &mut buckets[fragment_bucket(id) as usize];
        bucket.push(id);
        if bucket.len() == TFT_FRAGMENT_WAYS + 1 {
            return bucket.clone();
        }
    }
    panic!("the synthetic key space must contain a full bucket and one collision");
}

#[test]
fn full_bucket_refuses_new_ids_and_never_evicts_live_or_completed_entries() {
    let snapshot = published(&classifier());
    let mut table = table();
    let ids = colliding_ids();
    for &id in &ids[..TFT_FRAGMENT_WAYS] {
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(id, MORE, SPI), FIRST_TIME),
            selected(MARK_A)
        );
    }
    let refused = ids[TFT_FRAGMENT_WAYS];
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(refused, MORE, SPI),
            FIRST_TIME + 1
        ),
        invalid()
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(refused, 3, SPI),
            FIRST_TIME + 2
        ),
        invalid()
    );
    for &id in &ids[..TFT_FRAGMENT_WAYS] {
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &esp(id, 3, SPI),
                FIRST_TIME + 3
            ),
            selected(MARK_A)
        );
    }
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(refused, MORE, SPI),
            FIRST_TIME + 4
        ),
        invalid()
    );
    let other = (0..=u16::MAX)
        .find(|id| fragment_bucket(*id) != fragment_bucket(refused))
        .unwrap();
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(other, MORE, SPI),
            FIRST_TIME + 5
        ),
        selected(MARK_A)
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(refused, MORE, SPI),
            DEADLINE
        ),
        selected(MARK_A)
    );
    assert_eq!(
        classify(
            &mut table,
            Some(&snapshot),
            &esp(refused, 3, SPI),
            DEADLINE + 1
        ),
        selected(MARK_A)
    );
}

#[test]
fn backwards_clock_drops_across_absence_and_publication_changes() {
    let classifier = classifier();
    let original = published(&classifier);
    let replacement = TftUplinkFragmentSnapshot::new(&classifier, [2; 16], 2, 2).unwrap();
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&original), &esp(1, MORE, SPI), 100),
        selected(MARK_A)
    );
    assert_eq!(classify(&mut table, None, &esp(2, 0, SPI), 200), None);
    assert_eq!(
        classify(&mut table, Some(&replacement), &esp(2, MORE, SPI), 150),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&replacement), &esp(2, 3, SPI), 201),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&replacement), &esp(2, MORE, SPI), 202),
        selected(MARK_A)
    );
    assert_eq!(
        classify(&mut table, Some(&original), &esp(2, 3, SPI), 201),
        invalid()
    );
    assert_eq!(classify(&mut table, None, &esp(2, 3, SPI), 201), invalid());
    assert_eq!(
        classify(&mut table, Some(&replacement), &esp(2, 3, SPI), 203),
        selected(MARK_A)
    );
}

#[test]
fn non_ipv4_version_bypasses_affinity_without_poisoning_a_live_key() {
    let snapshot = published(&classifier());
    for current in [Some(&snapshot), None] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 100),
            selected(MARK_A)
        );
        let mut unrelated = esp(1, 3, SPI);
        unrelated[0] = 0x65;
        checksum(&mut unrelated);
        assert_eq!(classify(&mut table, current, &unrelated, 101), None);
        assert_eq!(
            classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), 102),
            selected(MARK_A)
        );
    }
}

#[test]
fn malformed_ipv4_still_finds_and_poisons_a_retained_key_after_removal() {
    let snapshot = published(&classifier());
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, MORE, SPI), 100),
        selected(MARK_A)
    );
    // Unlike a non-IPv4 version nibble, DF+MF reaches the real tc classifier.
    let mut malformed = esp(1, 0x4000 | MORE | 3, SPI);
    assert_eq!(
        classify(&mut table, None, &malformed, 101),
        dropped(TftUplinkDropReason::MalformedOrUnsupportedPacket)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(1, 3, SPI), 102),
        invalid()
    );
    malformed[5] = 2;
    checksum(&mut malformed);
    assert_eq!(classify(&mut table, None, &malformed, 103), None);
}

#[test]
fn incomplete_tcp_header_or_invalid_udp_length_cannot_establish_default_affinity() {
    let snapshot = published(&classifier());
    let mut tcp_short = ipv4(1, MORE, 6, 16);
    tcp_short[32] = 0x50;
    let mut tcp_options_short = ipv4(2, MORE, 6, 24);
    tcp_options_short[32] = 0xf0;
    let mut udp_short = ipv4(3, MORE, 17, 8);
    udp_short[24..26].copy_from_slice(&8_u16.to_be_bytes());
    for first in [tcp_short, tcp_options_short, udp_short] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, 100),
            dropped(TftUplinkDropReason::MalformedOrUnsupportedPacket)
        );
        let tail = ipv4(u16::from_be_bytes([first[4], first[5]]), 3, first[9], 24);
        assert_eq!(classify(&mut table, Some(&snapshot), &tail, 101), invalid());
    }
}

#[test]
fn esp_first_rejects_unaligned_payload_and_accepts_the_minimal_header() {
    let snapshot = published(&classifier());
    let mut table = table();
    // Four ESP bytes with MF fail IPv4's eight-byte fragment alignment rule.
    assert_eq!(
        classify(&mut table, Some(&snapshot), &ipv4(4, MORE, 50, 4), 100),
        dropped(TftUplinkDropReason::MalformedOrUnsupportedPacket)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(4, 1, SPI), 101),
        invalid()
    );
    let mut first = ipv4(5, MORE, 50, 8);
    first[20..24].copy_from_slice(&SPI.to_be_bytes());
    assert_eq!(
        classify(&mut table, Some(&snapshot), &first, 102),
        selected(MARK_A)
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &esp(5, 1, SPI), 103),
        selected(MARK_A)
    );
}

#[test]
fn udp_declared_length_fences_final_length_and_duplicate_first() {
    let classifier = TftUplinkClassifier::new(
        IFINDEX,
        IpAddr::V4(PAA),
        vec![
            TftUplinkBearer::default_bearer(),
            bearer(
                MARK_A,
                10,
                vec![
                    PacketFilterComponent::ProtocolIdentifierNextHeader(17),
                    PacketFilterComponent::SingleLocalPort(40_000),
                    PacketFilterComponent::SingleRemotePort(5060),
                ],
            ),
        ],
    )
    .unwrap();
    let snapshot = published(&classifier);
    let mut first = ipv4(1, MORE, 17, 24);
    first[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    first[22..24].copy_from_slice(&5060_u16.to_be_bytes());
    first[24..26].copy_from_slice(&48_u16.to_be_bytes());
    for (flags, payload, expected) in [
        (3, 24, selected(MARK_A)),
        (3, 8, invalid()),
        (3, 32, invalid()),
        (MORE | 3, 24, invalid()),
    ] {
        let mut table = table();
        assert_eq!(
            classify(&mut table, Some(&snapshot), &first, 100),
            selected(MARK_A)
        );
        assert_eq!(
            classify(
                &mut table,
                Some(&snapshot),
                &ipv4(1, flags, 17, payload),
                101
            ),
            expected
        );
    }
    let mut table = table();
    assert_eq!(
        classify(&mut table, Some(&snapshot), &first, 100),
        selected(MARK_A)
    );
    first[24..26].copy_from_slice(&56_u16.to_be_bytes());
    assert_eq!(
        classify(&mut table, Some(&snapshot), &first, 101),
        invalid()
    );
    assert_eq!(
        classify(&mut table, Some(&snapshot), &ipv4(1, 3, 17, 24), 102),
        invalid()
    );
}

#[test]
fn snapshot_requires_nonzero_authority_and_diagnostics_stay_redacted() {
    let classifier = classifier();
    assert!(TftUplinkFragmentTable::new(0).is_err());
    for (owner, owner_generation, snapshot_generation) in
        [([0; 16], 1, 1), ([1; 16], 0, 1), ([1; 16], 1, 0)]
    {
        assert!(matches!(
            TftUplinkFragmentSnapshot::new(
                &classifier,
                owner,
                owner_generation,
                snapshot_generation
            ),
            Err(opc_gtpu_dataplane::GtpuError::InvalidConfig { .. })
        ));
    }
    let snapshot = published(&classifier);
    assert_eq!(
        format!("{snapshot:?}"),
        "TftUplinkFragmentSnapshot(<redacted>)"
    );
    assert_eq!(
        format!("{:?}", table()),
        "TftUplinkFragmentTable(<redacted>)"
    );
}
