use super::*;
use bytes::Bytes;
use opc_gtpu_ebpf_common::internet_checksum;

#[derive(Default)]
struct RecordingSender {
    packets: Vec<(Vec<u8>, Option<GtpBearerMark>)>,
    fail_after: Option<usize>,
    short_after: Option<usize>,
}

impl Ipv4Sender for RecordingSender {
    fn send(&mut self, packet: &[u8], mark: Option<GtpBearerMark>) -> std::io::Result<usize> {
        if self.fail_after == Some(self.packets.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "sensitive socket diagnostic must not escape",
            ));
        }
        if self.short_after == Some(self.packets.len()) {
            return Ok(packet.len() - 1);
        }
        self.packets.push((packet.to_vec(), mark));
        Ok(packet.len())
    }
}

fn injector() -> Injector<RecordingSender> {
    Injector {
        sender: RecordingSender::default(),
        contract: InjectionContract::RawIpv4,
        counters: GtpuDownlinkInjectionCounters::default(),
    }
}

pub(super) fn packet(id: u16, flags: u16, data: &[u8]) -> Bytes {
    // Independently authored synthetic IPv4 header, including a source
    // which need not be assigned to the injector's host.
    let mut bytes = vec![
        0x45, 0x28, 0, 0, 0, 0, 0, 0, 61, 17, 0, 0, 198, 51, 100, 7, 203, 0, 113, 7,
    ];
    bytes.extend_from_slice(data);
    let length = u16::try_from(bytes.len()).unwrap();
    bytes[2..4].copy_from_slice(&length.to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags.to_be_bytes());
    let checksum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes.into()
}

fn decapsulated(bytes: Bytes, mark: Option<GtpBearerMark>) -> GtpuDecapsulatedDownlink {
    GtpuDecapsulatedDownlink::new(bytes, mark, GtpAddressFamily::Ipv4)
}

#[test]
fn exact_packet_and_mark_survive_bearer_switches() {
    let mut injector = injector();
    let original = packet(89, 0x4000, b"synthetic");
    for mark in [GtpBearerMark::new(37), None, GtpBearerMark::new(41)] {
        let event = decapsulated(original.clone(), mark);
        assert_eq!(injector.inject((&event).into()), Ok(1));
        assert_eq!(
            injector.sender.packets.last().unwrap(),
            &(original.to_vec(), mark)
        );
    }
    assert_eq!(injector.counters.packets_accepted, 3);
}

#[test]
fn decapsulated_zero_id_fragments_are_refused_before_sending_and_counted() {
    let mut injector = injector();
    for flags in [0x2000, 0x2001, 0x0001] {
        let event = decapsulated(packet(0, flags, &[0x53; 8]), None);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::ZeroIdentificationFragment)
        );
    }
    assert!(injector.sender.packets.is_empty());
    assert_eq!(injector.counters.zero_identification_refusals, 3);
    // DF suppresses the Linux rewrite. An unfragmented zero-ID packet does
    // not have sibling fragments with which Linux could disagree.
    for flags in [0, 0x4000, 0x6000, 0x4001] {
        let event = decapsulated(packet(0, flags, &[0x53; 8]), None);
        assert_eq!(injector.inject((&event).into()), Ok(1));
    }
    assert_eq!(injector.counters.zero_identification_refusals, 3);
}

#[test]
fn zero_id_fragment_batches_are_refused_without_sending_or_mutation() {
    let mut injector = injector();
    for start in [0, 7] {
        // A real zero-ID batch re-fragments one origin fragment and retains
        // MF on its final piece; siblings are separate receive outcomes.
        let original = vec![
            packet(0, 0x2000 | start, &[0x11; 16]),
            packet(0, 0x2000 | (start + 2), &[0x22; 8]),
        ];
        let event = GtpuFragmentedDownlink::new(original.clone(), GtpBearerMark::new(37), 576);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::ZeroIdentificationFragment)
        );
        assert_eq!(event.fragments(), original);
    }
    assert!(injector.sender.packets.is_empty());
    assert_eq!(injector.counters.zero_identification_refusals, 2);
    assert_eq!(injector.counters.packets_accepted, 0);
}

#[test]
fn numbered_fragments_are_sent_byte_exactly_in_offset_order() {
    let mut injector = injector();
    let original = vec![packet(712, 0x2000, &[0x11; 8]), packet(712, 1, &[0x22; 7])];
    let event = GtpuFragmentedDownlink::new(original.clone(), None, 576);
    assert_eq!(injector.inject((&event).into()), Ok(2));
    assert_eq!(
        injector.sender.packets,
        original
            .iter()
            .map(|p| (p.to_vec(), None))
            .collect::<Vec<_>>()
    );
}

#[test]
fn whole_batch_is_validated_before_its_first_send() {
    let mut injector = injector();
    let good = packet(8, 0x2000, &[0x11; 8]);
    let tail = packet(8, 1, &[0x22; 7]);
    let mut bad_checksum = tail.to_vec();
    bad_checksum[10] ^= 1;
    for fragments in [
        vec![],
        vec![good.clone(), Bytes::from(bad_checksum)],
        vec![tail.clone(), good.clone()],
        vec![good.clone(), packet(9, 1, &[0x22; 7])],
        vec![good.clone(), packet(8, 2, &[0x22; 7])],
    ] {
        let event = GtpuFragmentedDownlink::new(fragments, None, 576);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::MalformedIpv4)
        );
    }
    assert!(injector.sender.packets.is_empty());
}

#[test]
fn invalid_and_ipv6_inputs_never_reach_the_sender() {
    let mut injector = injector();
    let mut trailing = packet(1, 0x4000, b"data").to_vec();
    trailing.push(0);
    for bytes in [Bytes::new(), Bytes::from(trailing)] {
        let event = decapsulated(bytes, None);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::MalformedIpv4)
        );
    }
    let ipv6 =
        GtpuDecapsulatedDownlink::new(Bytes::from(vec![0x60; 40]), None, GtpAddressFamily::Ipv6);
    assert_eq!(
        injector.inject((&ipv6).into()),
        Err(GtpuDownlinkInjectionError::UnsupportedFamily)
    );
    assert!(injector.sender.packets.is_empty());
}

#[test]
fn unspecified_source_is_refused_instead_of_replaced_by_the_kernel() {
    let mut injector = injector();
    for (id, flags) in [(1, 0x4000), (0, 0x2000)] {
        let mut bytes = packet(id, flags, &[0; 8]).to_vec();
        bytes[12..16].fill(0);
        bytes[10..12].fill(0);
        let checksum = internet_checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        let event = decapsulated(bytes.into(), None);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::UnspecifiedSource)
        );
    }
    assert_eq!(injector.counters.zero_identification_refusals, 0);
    assert!(injector.sender.packets.is_empty());
}

#[test]
fn options_and_numbered_refragmented_portions_remain_unchanged() {
    let mut injector = injector();
    let mut with_options = packet(2, 0x4000, b"data").to_vec();
    // A router-alert option with the copy bit set. The raw sender neither
    // interprets it nor removes it while selecting its source and mark.
    with_options.splice(20..20, [0x94, 4, 0, 0]);
    with_options[0] = 0x46;
    let length = u16::try_from(with_options.len()).unwrap();
    with_options[2..4].copy_from_slice(&length.to_be_bytes());
    with_options[10..12].fill(0);
    let checksum = internet_checksum(&with_options[..24]);
    with_options[10..12].copy_from_slice(&checksum.to_be_bytes());
    let event = decapsulated(with_options.clone().into(), None);
    assert_eq!(injector.inject((&event).into()), Ok(1));
    assert_eq!(injector.sender.packets[0].0, with_options);

    // A Fragmented outcome need not start at offset zero or contain the
    // original datagram's last fragment: it may split an existing fragment.
    let parts = vec![
        packet(81, 0x2002, &[0x11; 8]),
        packet(81, 0x2003, &[0x22; 8]),
    ];
    let event = GtpuFragmentedDownlink::new(parts.clone(), None, 576);
    assert_eq!(injector.inject((&event).into()), Ok(2));
    for ((sent, _), expected) in injector.sender.packets[1..].iter().zip(parts) {
        assert_eq!(sent.as_slice(), expected.as_ref());
    }
}

#[test]
fn a_partial_send_stops_in_order_and_reports_only_static_classes_and_counts() {
    let mut injector = injector();
    injector.sender.fail_after = Some(1);
    let event = GtpuFragmentedDownlink::new(
        vec![packet(2, 0x2000, &[0; 8]), packet(2, 1, &[0; 7])],
        None,
        576,
    );
    let error = injector.inject((&event).into()).unwrap_err();
    assert_eq!(
        error,
        GtpuDownlinkInjectionError::Send {
            class: GtpuDownlinkSendFailure::WouldBlock,
            packets_sent: 1
        }
    );
    assert_eq!(injector.sender.packets.len(), 1);
    assert_eq!(injector.counters.packets_accepted, 1);
    assert_eq!(injector.counters.send_failures, 1);
    assert_eq!(
        format!("{error:?}"),
        "Send { class: WouldBlock, packets_sent: 1 }"
    );
    assert!(!error.to_string().contains("sensitive"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn batch_address_protocol_df_and_alignment_mismatches_send_nothing() {
    let mut injector = injector();
    let first = packet(9, 0x2000, &[0x11; 8]);
    let tail = packet(9, 1, &[0x22; 8]);
    for byte in [12, 16, 9, 6] {
        let mut mismatch = tail.to_vec();
        mismatch[byte] ^= if byte == 6 { 0x40 } else { 1 };
        mismatch[10..12].fill(0);
        let checksum = internet_checksum(&mismatch[..20]);
        mismatch[10..12].copy_from_slice(&checksum.to_be_bytes());
        let event = GtpuFragmentedDownlink::new(vec![first.clone(), mismatch.into()], None, 576);
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::MalformedIpv4)
        );
    }
    let unaligned =
        GtpuFragmentedDownlink::new(vec![packet(9, 0x2000, &[0x11; 7]), tail], None, 576);
    assert_eq!(
        injector.inject((&unaligned).into()),
        Err(GtpuDownlinkInjectionError::MalformedIpv4)
    );
    assert!(injector.sender.packets.is_empty());
}

#[test]
fn fragment_extent_accepts_65535_and_refuses_65536_octets() {
    let mut injector = injector();
    let last = decapsulated(packet(9, 8189, &[0x11; 3]), None);
    assert_eq!(injector.inject((&last).into()), Ok(1));
    let oversized = decapsulated(packet(9, 8189, &[0x11; 4]), None);
    assert_eq!(
        injector.inject((&oversized).into()),
        Err(GtpuDownlinkInjectionError::MalformedIpv4)
    );
    assert_eq!(injector.sender.packets.len(), 1);
}

#[test]
fn short_write_stops_the_batch_and_reports_only_complete_packets() {
    let mut injector = injector();
    injector.sender.short_after = Some(1);
    let event = GtpuFragmentedDownlink::new(
        vec![
            packet(9, 0x2000, &[0x11; 8]),
            packet(9, 0x2001, &[0x22; 8]),
            packet(9, 2, &[0x33; 7]),
        ],
        None,
        576,
    );
    assert_eq!(
        injector.inject((&event).into()),
        Err(GtpuDownlinkInjectionError::Send {
            class: GtpuDownlinkSendFailure::ShortWrite,
            packets_sent: 1,
        })
    );
    assert_eq!(injector.sender.packets.len(), 1);
    assert_eq!(injector.counters.packets_accepted, 1);
    assert_eq!(injector.counters.send_failures, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn send_failure_classes_distinguish_kernel_limits_and_containment() {
    use nix::libc;
    for (errno, expected) in [
        (libc::EAGAIN, GtpuDownlinkSendFailure::WouldBlock),
        (libc::EMSGSIZE, GtpuDownlinkSendFailure::MessageTooLarge),
        (libc::ENOBUFS, GtpuDownlinkSendFailure::NoBufferSpace),
        (libc::EPERM, GtpuDownlinkSendFailure::PolicyOrFilterRefused),
        (libc::EACCES, GtpuDownlinkSendFailure::AccessDenied),
        (libc::ENXIO, GtpuDownlinkSendFailure::InterfaceUnavailable),
        (libc::ENODEV, GtpuDownlinkSendFailure::InterfaceUnavailable),
        (libc::ENETDOWN, GtpuDownlinkSendFailure::InterfaceDown),
        (libc::EBADF, GtpuDownlinkSendFailure::Other),
    ] {
        assert_eq!(
            classify_send_error(&io::Error::from_raw_os_error(errno)),
            expected
        );
    }
}

#[test]
fn event_debug_has_no_packet_or_bearer_values() {
    let event = decapsulated(packet(23, 0x4000, b"synthetic"), GtpBearerMark::new(37));
    let request = GtpuDownlinkInjection::from(&event);
    let debug = format!("{request:?}");
    for private in ["198.51.100.7", "203.0.113.7", "synthetic", "37", "23"] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn interface_contract_preserves_zero_ids_across_separate_outcomes_and_batches() {
    let mut injector = injector();
    injector.contract = InjectionContract::XfrmInterfaceIpv4;
    for mark in [GtpBearerMark::new(37), None, GtpBearerMark::new(41)] {
        let siblings = vec![packet(0, 0x2000, &[0x11; 8]), packet(0, 1, &[0x22; 7])];
        let start = injector.sender.packets.len();
        for bytes in &siblings {
            let event = decapsulated(bytes.clone(), mark);
            assert_eq!(injector.inject((&event).into()), Ok(1));
        }
        let batch = GtpuFragmentedDownlink::new(siblings.clone(), mark, 576);
        assert_eq!(injector.inject((&batch).into()), Ok(2));
        for ((sent, actual_mark), expected) in injector.sender.packets[start..]
            .iter()
            .zip(siblings.iter().cycle())
        {
            assert_eq!(sent.as_slice(), expected.as_ref());
            assert_eq!(actual_mark, &mark);
        }
    }
    assert_eq!(injector.counters.packets_accepted, 12);
    assert_eq!(injector.counters.zero_identification_refusals, 0);
}

#[test]
fn interface_contract_stops_a_zero_id_batch_on_partial_acceptance() {
    let mut injector = injector();
    injector.contract = InjectionContract::XfrmInterfaceIpv4;
    injector.sender.fail_after = Some(1);
    let first = packet(0, 0x2000, &[0x11; 8]);
    let event =
        GtpuFragmentedDownlink::new(vec![first.clone(), packet(0, 1, &[0x22; 7])], None, 576);
    assert_eq!(
        injector.inject((&event).into()),
        Err(GtpuDownlinkInjectionError::Send {
            class: GtpuDownlinkSendFailure::WouldBlock,
            packets_sent: 1,
        })
    );
    assert_eq!(injector.sender.packets, vec![(first.to_vec(), None)]);
    assert_eq!(injector.counters.zero_identification_refusals, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn interface_constructor_rejects_invalid_identity_without_opening_a_socket() {
    for (index, id) in [(0, 19), (1, 0), (u32::MAX, 19)] {
        assert!(matches!(
            GtpuDownlinkInjector::xfrm_interface_ipv4(index, id),
            Err(GtpuDownlinkInjectionError::InvalidInterface)
        ));
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn interface_constructor_refuses_unsupported_platforms() {
    assert!(matches!(
        GtpuDownlinkInjector::xfrm_interface_ipv4(7, 19),
        Err(GtpuDownlinkInjectionError::UnsupportedPlatform)
    ));
}
