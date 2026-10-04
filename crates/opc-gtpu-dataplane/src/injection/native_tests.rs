//! Real-kernel proof with an independent Python ESP peer and wire observer.

use super::*;
use opc_gtpu_ebpf_common::internet_checksum;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Peer {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    configuration: serde_json::Value,
}

impl Peer {
    fn start() -> Self {
        Self::start_with_mode("raw")
    }

    fn start_with_mode(mode: &str) -> Self {
        let mut child = Command::new("python3")
            .args([
                "-u",
                "-c",
                include_str!("../../tests/fixtures/downlink_injection.py"),
                mode,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start independent injection peer");
        let input = Some(child.stdin.take().unwrap());
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut peer = Self {
            child,
            input,
            output,
            configuration: serde_json::Value::Null,
        };
        peer.configuration = peer.read();
        assert_eq!(peer.configuration["ready"], true);
        peer
    }

    fn read(&mut self) -> serde_json::Value {
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "independent peer stopped"
        );
        serde_json::from_str(&line).expect("independent peer response")
    }

    fn call(&mut self, operation: &str) -> serde_json::Value {
        writeln!(self.input.as_mut().unwrap(), "{{\"op\":\"{operation}\"}}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
        self.read()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // EOF makes the fixture reap its peer and remove its namespace-local
        // objects, including when an assertion unwinds the test.
        drop(self.input.take());
        let _ = self.child.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode(bytes: &serde_json::Value) -> Vec<u8> {
    let hex = bytes.as_str().unwrap().as_bytes();
    hex.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn udp(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x7d, 0x00, 0x7d, 0x01, 0, 0, 0, 0];
    bytes[4..6].copy_from_slice(&u16::try_from(payload.len() + 8).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn expect_encrypted(observation: &serde_json::Value, spi: u32, inner: &[&[u8]], payload: &[u8]) {
    let wire = observation["wire"].as_array().unwrap();
    assert_eq!(
        wire.len(),
        inner.len(),
        "one encrypted wire packet per injected packet"
    );
    let mut last_sequence = None;
    for packet in wire {
        let packet = decode(packet);
        assert_eq!(packet[9], 50, "plaintext escaped the sender");
        let header = usize::from(packet[0] & 0x0f) * 4;
        assert_eq!(
            u32::from_be_bytes(packet[header..header + 4].try_into().unwrap()),
            spi
        );
        let sequence = u32::from_be_bytes(packet[header + 4..header + 8].try_into().unwrap());
        if let Some(last) = last_sequence {
            assert_eq!(sequence, last + 1, "fragments left out of order");
        }
        last_sequence = Some(sequence);
    }
    let received = observation["inner"].as_array().unwrap();
    assert_eq!(received.len(), inner.len());
    for (received, expected) in received.iter().zip(inner) {
        assert_eq!(decode(received), *expected, "decrypted packet differs");
    }
    assert_eq!(observation["payloads"], serde_json::json!([hex(payload)]));
}

fn expect_no_wire(peer: &mut Peer) {
    let observation = peer.call("observe");
    assert!(observation["wire"].as_array().unwrap().is_empty());
    assert!(observation["payloads"].as_array().unwrap().is_empty());
    for entry in observation["trace"].as_array().unwrap() {
        if entry["protocol"] == 0x800 {
            assert_ne!(
                decode(&entry["packet"])[9],
                1,
                "unexpected ICMP on a namespace device"
            );
        }
    }
}

#[test]
#[ignore = "requires root in a fresh network namespace, iproute2, nftables and Python 3"]
fn raw_ipv4_injection_preserves_bearer_source_fragments_and_containment() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "private network namespace required"
    );
    let mut peer = Peer::start();
    let mut injector = GtpuDownlinkInjector::raw_ipv4().unwrap();
    assert_eq!(
        format!("{injector:?}"),
        "GtpuDownlinkInjector { contract: RawIpv4 }"
    );
    let payload: Vec<u8> = (0..240).map(|n| u8::try_from(n).unwrap()).collect();
    let data = udp(&payload);

    // Raw HDRINCL output returns a local error for both device MTU and
    // tunnel path-MTU failures. A return route to the source and the all-
    // device trace make an unexpected network ICMP error observable.
    for size in [1470, 1600] {
        let event = GtpuDecapsulatedDownlink::new(
            tests::packet(70, 0x4000, &udp(&vec![0x61; size])),
            None,
            GtpAddressFamily::Ipv4,
        );
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::Send {
                class: GtpuDownlinkSendFailure::MessageTooLarge,
                packets_sent: 0,
            })
        );
        expect_no_wire(&mut peer);
    }

    // Same socket: dedicated -> default -> dedicated. The selectors constrain
    // a source which is not assigned in the sender namespace. A missing
    // IP_PKTINFO source or a stale SO_MARK therefore cannot pass these legs.
    for (mark, spi) in [
        (GtpBearerMark::new(37), 0x101),
        (None, 0x100),
        (GtpBearerMark::new(37), 0x101),
    ] {
        let bytes = tests::packet(71, 0x4000, &data);
        let event = GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
        assert_eq!(injector.inject((&event).into()), Ok(1));
        expect_encrypted(&peer.call("observe"), spi, &[&bytes], &payload);
    }

    for (mark, spi) in [(None, 0x100), (GtpBearerMark::new(37), 0x101)] {
        let numbered = vec![
            tests::packet(91, 0x2000, &data[..128]),
            tests::packet(91, 16, &data[128..]),
        ];
        let event = GtpuFragmentedDownlink::new(numbered.clone(), mark, 576);
        assert_eq!(injector.inject((&event).into()), Ok(2));
        expect_encrypted(
            &peer.call("observe"),
            spi,
            &[&numbered[0], &numbered[1]],
            &payload,
        );
        let zero = GtpuFragmentedDownlink::new(
            vec![
                tests::packet(0, 0x2000, &data[..128]),
                tests::packet(0, 0x2010, &data[128..]),
            ],
            mark,
            576,
        );
        assert_eq!(
            injector.inject((&zero).into()),
            Err(GtpuDownlinkInjectionError::ZeroIdentificationFragment)
        );
        expect_no_wire(&mut peer);
        // Ordinary Decapsulated siblings are separate calls, with no cache.
        for bytes in [
            tests::packet(93, 0x2000, &data[..128]),
            tests::packet(93, 16, &data[128..]),
        ] {
            let event = GtpuDecapsulatedDownlink::new(bytes, mark, GtpAddressFamily::Ipv4);
            assert_eq!(injector.inject((&event).into()), Ok(1));
        }
        let first = tests::packet(93, 0x2000, &data[..128]);
        let last = tests::packet(93, 16, &data[128..]);
        expect_encrypted(&peer.call("observe"), spi, &[&first, &last], &payload);
        for bytes in [
            tests::packet(0, 0x2000, &data[..128]),
            tests::packet(0, 16, &data[128..]),
        ] {
            let event = GtpuDecapsulatedDownlink::new(bytes, mark, GtpAddressFamily::Ipv4);
            assert_eq!(
                injector.inject((&event).into()),
                Err(GtpuDownlinkInjectionError::ZeroIdentificationFragment)
            );
        }
        expect_no_wire(&mut peer);
    }
    assert_eq!(injector.counters().zero_identification_refusals, 6);

    // NODEFRAG bypasses gathering, not conntrack's invalid classification
    // of non-initial fragments. A common invalid-drop output rule refuses
    // one such fragment, even with a matching policy and SA still installed.
    let invalid_before = peer.call("invalid_count")["invalid"].as_u64().unwrap();
    assert_eq!(peer.call("drop_invalid")["done"], true);
    let tail = GtpuDecapsulatedDownlink::new(
        tests::packet(97, 16, &data[128..]),
        None,
        GtpAddressFamily::Ipv4,
    );
    assert_eq!(
        injector.inject((&tail).into()),
        Err(GtpuDownlinkInjectionError::Send {
            class: GtpuDownlinkSendFailure::PolicyOrFilterRefused,
            packets_sent: 0,
        })
    );
    expect_no_wire(&mut peer);
    assert_eq!(
        peer.call("invalid_count")["invalid"].as_u64(),
        Some(invalid_before + 1)
    );
    assert_eq!(peer.call("allow_invalid")["done"], true);

    assert_eq!(peer.call("remove_bearers")["block_present"], true);
    for mark in [None, GtpBearerMark::new(37)] {
        let bytes = tests::packet(94, 0x4000, &data);
        let event = GtpuDecapsulatedDownlink::new(bytes, mark, GtpAddressFamily::Ipv4);
        assert!(matches!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::Send {
                class: GtpuDownlinkSendFailure::PolicyOrFilterRefused,
                packets_sent: 0,
            })
        ));
        expect_no_wire(&mut peer);
    }
    // Keeping disable_policy=0 does not prevent either egress-device or
    // namespace-wide disable_xfrm from bypassing the installed pool block.
    for operation in ["bypass_device", "bypass_all"] {
        let configured = peer.call(operation);
        assert_eq!(configured["done"], true);
        assert_eq!(configured["disable_policy"], 0);
        assert_eq!(peer.call("query_block")["block_present"], true);
        for mark in [None, GtpBearerMark::new(37)] {
            let bytes = tests::packet(98, 0x4000, &data);
            let event = GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
            assert_eq!(injector.inject((&event).into()), Ok(1));
            assert_eq!(
                peer.call("observe")["wire"],
                serde_json::json!([hex(&bytes)])
            );
        }
        assert_eq!(peer.call("enable_xfrm")["done"], true);
    }
    // Negative control: a successful read-only diagnostic is not a lease.
    assert_eq!(peer.call("query_block")["block_present"], true);
    assert_eq!(peer.call("remove_block")["done"], true);
    for mark in [None, GtpBearerMark::new(37)] {
        let bytes = tests::packet(95, 0x4000, &data);
        let event = GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
        assert_eq!(injector.inject((&event).into()), Ok(1));
        let observation = peer.call("observe");
        assert_eq!(
            observation["wire"],
            serde_json::json!([hex(&bytes)]),
            "missing containment must expose the negative control"
        );
    }
    // A namespace default block survives deletion of every ordinary OUT
    // policy. It must be explicitly changed to allow unrelated plaintext.
    assert_eq!(peer.call("default_block")["done"], true);
    for mark in [None, GtpBearerMark::new(37)] {
        let event = GtpuDecapsulatedDownlink::new(
            tests::packet(99, 0x4000, &data),
            mark,
            GtpAddressFamily::Ipv4,
        );
        assert_eq!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::Send {
                class: GtpuDownlinkSendFailure::PolicyOrFilterRefused,
                packets_sent: 0,
            })
        );
        expect_no_wire(&mut peer);
    }
    // A deliberate explicit allow overrides the namespace default and is
    // therefore still excluded by the consumer's no-bypass obligation.
    assert_eq!(peer.call("allow_plaintext")["done"], true);
    let bytes = tests::packet(100, 0x4000, &data);
    let event = GtpuDecapsulatedDownlink::new(bytes.clone(), None, GtpAddressFamily::Ipv4);
    assert_eq!(injector.inject((&event).into()), Ok(1));
    assert_eq!(
        peer.call("observe")["wire"],
        serde_json::json!([hex(&bytes)])
    );
    assert_eq!(peer.call("remove_plaintext_allow")["done"], true);
    assert_eq!(peer.call("restore")["done"], true);
    let bytes = tests::packet(96, 0x4000, &data);
    let event = GtpuDecapsulatedDownlink::new(bytes.clone(), None, GtpAddressFamily::Ipv4);
    assert_eq!(injector.inject((&event).into()), Ok(1));
    expect_encrypted(&peer.call("observe"), 0x100, &[&bytes], &payload);
    assert_eq!(peer.call("default_accept")["done"], true);
    println!("OPC_GTPU_RAW_INJECTION_PROVEN: marks, source selectors, ordered fragments, zero-ID refusal, retained/default block containment, disable_xfrm and query/send negative controls, NODEFRAG invalid-filter refusal; no ICMP on any device for block/default-block or device/tunnel MTU refusal with source return route");
}

fn expect_local_acceptance(injector: &mut GtpuDownlinkInjector, event: &GtpuDecapsulatedDownlink) {
    // xfrmi_xmit consumes failed transforms and returns NETDEV_TX_OK. Neither
    // missing transforms nor generated ICMP are reported by this return value.
    assert_eq!(injector.inject(event.into()), Ok(1));
}

fn settled_interface(index: u32) -> GtpuDownlinkInjector {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match GtpuDownlinkInjector::xfrm_interface_ipv4(index, 19) {
            Ok(injector) => return injector,
            Err(GtpuDownlinkInjectionError::InterfaceIdentityMismatch)
                if std::time::Instant::now() < deadline =>
            {
                // Deferred NEWLINK after bringing a device up must still
                // refuse the attempt. Retry with a new monitor and socket.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("interface construction did not settle: {error}"),
        }
    }
}

fn expect_icmp_quote(peer: &mut Peer, original: &[u8], code: u8) {
    let observation = peer.call("observe");
    let wire = observation["wire"].as_array().unwrap();
    assert_eq!(
        wire.len(),
        1,
        "one ICMP error must escape without the guard"
    );
    let packet = decode(&wire[0]);
    assert_eq!(packet[9], 1);
    assert_eq!(&packet[16..20], &original[12..16]);
    let header = usize::from(packet[0] & 15) * 4;
    assert_eq!(&packet[header..header + 2], &[3, code]);
    if code == 4 {
        let mtu = u16::from_be_bytes(packet[header + 6..header + 8].try_into().unwrap());
        assert!(usize::from(mtu) < original.len() && mtu >= 68);
    }
    let quote = &packet[header + 8..];
    assert!(quote.len() >= 28 && packet.len() <= 576);
    assert_eq!(
        quote,
        &original[..quote.len()],
        "ICMP carries original bytes"
    );
    assert!(observation["payloads"].as_array().unwrap().is_empty());
    println!(
        "ICMP observation: type=3 code={code} bytes={} quoted_bytes={} trace={}",
        packet.len(),
        quote.len(),
        observation["trace"]
    );
}

fn expect_guarded_drop(peer: &mut Peer, injector: &mut GtpuDownlinkInjector, bytes: Bytes) {
    for mark in [None, GtpBearerMark::new(37)] {
        let before = peer.call("hooks")["icmp_quote_drop"].as_u64().unwrap();
        let event = GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(injector, &event);
        expect_no_wire(peer);
        assert_eq!(
            peer.call("hooks")["icmp_quote_drop"].as_u64(),
            Some(before + 1)
        );
    }
}

#[test]
#[ignore = "requires root in a fresh network namespace, iproute2, nftables and Python 3"]
fn xfrm_interface_injection_preserves_packets_and_containment() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "private network namespace required"
    );
    let mut peer = Peer::start_with_mode("interface");
    let index = u32::try_from(peer.configuration["interface_index"].as_u64().unwrap()).unwrap();
    let physical = u32::try_from(peer.configuration["physical_index"].as_u64().unwrap()).unwrap();
    let unknown = peer.call("unknown_kind");
    assert_eq!(unknown["unsupported"], true);
    println!("unknown link kind: {}", unknown["diagnostic"]);
    assert!(matches!(
        GtpuDownlinkInjector::xfrm_interface_ipv4(physical, 19),
        Err(GtpuDownlinkInjectionError::UnsupportedInterface)
    ));
    if peer.configuration["interface_supported"] == false {
        // This is an executed production-constructor refusal, not a skipped
        // datapath assertion. The CI runner separately requires the supported
        // proof on kernels whose configuration provides XFRM interfaces.
        assert!(matches!(
            GtpuDownlinkInjector::xfrm_interface_ipv4(index, 19),
            Err(GtpuDownlinkInjectionError::UnsupportedInterface)
        ));
        expect_no_wire(&mut peer);
        println!("OPC_GTPU_XFRM_INTERFACE_UNSUPPORTED_PROVEN: kernel refused interface creation; constructor refused substitute device");
        return;
    }
    assert!(matches!(
        GtpuDownlinkInjector::xfrm_interface_ipv4(index, 20),
        Err(GtpuDownlinkInjectionError::InterfaceIdentityMismatch)
    ));
    let mut injector = settled_interface(index);
    assert_eq!(
        format!("{injector:?}"),
        "GtpuDownlinkInjector { contract: XfrmInterfaceIpv4 }"
    );
    let payload: Vec<u8> = (0..240).map(|n| u8::try_from(n).unwrap()).collect();
    let data = udp(&payload);

    for (mark, spi) in [
        (GtpBearerMark::new(37), 0x101),
        (None, 0x100),
        (GtpBearerMark::new(37), 0x101),
    ] {
        // Even an unfragmented zero-ID non-DF packet stays byte exact.
        let bytes = tests::packet(0, 0, &data);
        let event = GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
        assert_eq!(injector.inject((&event).into()), Ok(1));
        expect_encrypted(&peer.call("observe"), spi, &[&bytes], &payload);
    }

    for (mark, spi) in [(None, 0x100), (GtpBearerMark::new(37), 0x101)] {
        for id in [91, 0] {
            let siblings = vec![
                tests::packet(id, 0x2000, &data[..128]),
                tests::packet(id, 16, &data[128..]),
            ];
            let batch = GtpuFragmentedDownlink::new(siblings.clone(), mark, 576);
            assert_eq!(injector.inject((&batch).into()), Ok(2));
            expect_encrypted(
                &peer.call("observe"),
                spi,
                &[&siblings[0], &siblings[1]],
                &payload,
            );
            for bytes in &siblings {
                let event =
                    GtpuDecapsulatedDownlink::new(bytes.clone(), mark, GtpAddressFamily::Ipv4);
                assert_eq!(injector.inject((&event).into()), Ok(1));
            }
            expect_encrypted(
                &peer.call("observe"),
                spi,
                &[&siblings[0], &siblings[1]],
                &payload,
            );
        }
    }
    assert_eq!(injector.counters().zero_identification_refusals, 0);

    let mut options = tests::packet(0, 0, &data).to_vec();
    options.splice(20..20, [0x94, 4, 0, 0]);
    options[0] = 0x46;
    let length = u16::try_from(options.len()).unwrap();
    options[2..4].copy_from_slice(&length.to_be_bytes());
    options[10..12].fill(0);
    let checksum = internet_checksum(&options[..24]);
    options[10..12].copy_from_slice(&checksum.to_be_bytes());
    let event = GtpuDecapsulatedDownlink::new(options.clone().into(), None, GtpAddressFamily::Ipv4);
    assert_eq!(injector.inject((&event).into()), Ok(1));
    expect_encrypted(&peer.call("observe"), 0x100, &[&options], &payload);
    let hooks = peer.call("hooks");
    assert_eq!(hooks["inner_output"], 0, "inner LOCAL_OUT must be bypassed");
    assert_eq!(
        hooks["inner_postrouting"].as_u64(),
        Some(injector.counters().packets_accepted),
        "plaintext POST_ROUTING remains before the transform"
    );
    assert_eq!(
        hooks["inner_invalid"], hooks["inner_postrouting"],
        "all injected inner packets reach POST_ROUTING without conntrack entries"
    );

    assert_eq!(peer.call("drop_invalid_post")["done"], true);
    let invalid_before = hooks["inner_invalid"].as_u64().unwrap();
    for bytes in [
        tests::packet(90, 0x4000, &data),
        tests::packet(90, 0x2000, &data[..128]),
        tests::packet(90, 16, &data[128..]),
    ] {
        let event = GtpuDecapsulatedDownlink::new(bytes, None, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_no_wire(&mut peer);
    }
    assert_eq!(
        peer.call("hooks")["inner_invalid"].as_u64(),
        Some(invalid_before + 3)
    );
    assert_eq!(peer.call("allow_invalid")["done"], true);

    // Decrypted inbound packets are visible on xfrm0 and delivered to a UDP
    // consumer, but must never be retained by the injection socket.
    assert_eq!(peer.call("inbound")["received"], 8);
    let received = peer.call("observe");
    let inbound = received["trace"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["device"] == "xfrm0"
                && entry["protocol"] == 0x800
                && entry["packet_type"] == 0
                && decode(&entry["packet"])[9] == 17
        })
        .count();
    assert_eq!(
        inbound, 8,
        "the independent trace must observe actual inbound traffic"
    );
    let InjectionSocket::XfrmInterface(socket) = &injector.inner.sender else {
        panic!("wrong injection contract");
    };
    socket.assert_receive_queue_empty();

    // A DF packet fitting the interface but exceeding the ESP path MTU
    // generates an ordinary-routed ICMP error containing plaintext bytes.
    let oversized = tests::packet(93, 0x4000, &udp(&vec![0x61; 1470]));
    for mark in [None, GtpBearerMark::new(37)] {
        let event = GtpuDecapsulatedDownlink::new(oversized.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_icmp_quote(&mut peer, &oversized, 4);
    }
    assert_eq!(peer.call("suppress_icmp")["done"], true);
    expect_guarded_drop(&mut peer, &mut injector, oversized);
    assert_eq!(peer.call("allow_icmp")["done"], true);

    assert_eq!(peer.call("remove_bearers")["done"], true);
    let missing = tests::packet(94, 0x4000, &udp(&[0x72; 800]));
    for mark in [None, GtpBearerMark::new(37)] {
        let event = GtpuDecapsulatedDownlink::new(missing.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_icmp_quote(&mut peer, &missing, 1);
        let first = tests::packet(94, 0x2000, &data[..128]);
        let event = GtpuDecapsulatedDownlink::new(first.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_icmp_quote(&mut peer, &first, 1);
        let tail = GtpuDecapsulatedDownlink::new(
            tests::packet(94, 16, &data[128..]),
            mark,
            GtpAddressFamily::Ipv4,
        );
        expect_local_acceptance(&mut injector, &tail);
        expect_no_wire(&mut peer);
    }
    assert_eq!(peer.call("suppress_icmp")["done"], true);
    expect_guarded_drop(&mut peer, &mut injector, missing.clone());
    expect_guarded_drop(
        &mut peer,
        &mut injector,
        tests::packet(94, 0x2000, &data[..128]),
    );
    assert_eq!(peer.call("replace_route")["done"], true);
    for mark in [None, GtpBearerMark::new(37)] {
        let event = GtpuDecapsulatedDownlink::new(missing.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_no_wire(&mut peer);
    }
    assert_eq!(peer.call("restore")["done"], true);
    assert_eq!(peer.call("remove_states")["done"], true);
    assert_eq!(peer.call("allow_icmp")["done"], true);
    for mark in [None, GtpBearerMark::new(37)] {
        let event = GtpuDecapsulatedDownlink::new(missing.clone(), mark, GtpAddressFamily::Ipv4);
        expect_local_acceptance(&mut injector, &event);
        expect_icmp_quote(&mut peer, &missing, 1);
    }
    assert_eq!(peer.call("suppress_icmp")["done"], true);
    expect_guarded_drop(&mut peer, &mut injector, missing);
    assert_eq!(peer.call("restore_states")["done"], true);
    let bytes = tests::packet(97, 0x4000, &data);
    let event = GtpuDecapsulatedDownlink::new(bytes.clone(), None, GtpAddressFamily::Ipv4);
    assert_eq!(injector.inject((&event).into()), Ok(1));
    expect_encrypted(&peer.call("observe"), 0x100, &[&bytes], &payload);

    assert_eq!(peer.call("interface_down")["done"], true);
    assert_eq!(
        injector.inject((&event).into()),
        Err(GtpuDownlinkInjectionError::Send {
            class: GtpuDownlinkSendFailure::InterfaceDown,
            packets_sent: 0,
        })
    );
    expect_no_wire(&mut peer);
    assert_eq!(peer.call("interface_up")["done"], true);
    // NETDEV_DOWN also queues sk_err. The next allocation may report that
    // pending error even after UP; no bytes were sent, so a new explicit
    // attempt is safe. This is not a retry after partial acceptance.
    let resumed = injector.inject((&event).into());
    if resumed != Ok(1) {
        assert_eq!(
            resumed,
            Err(GtpuDownlinkInjectionError::Send {
                class: GtpuDownlinkSendFailure::InterfaceDown,
                packets_sent: 0,
            })
        );
        expect_no_wire(&mut peer);
        assert_eq!(injector.inject((&event).into()), Ok(1));
    }
    expect_encrypted(&peer.call("observe"), 0x100, &[&bytes], &payload);

    for operation in [
        "delete_interface",
        "replace_interface_dummy",
        "replace_interface_xfrm",
    ] {
        assert_eq!(peer.call(operation)["done"], true);
        if operation == "delete_interface" {
            assert!(matches!(
                GtpuDownlinkInjector::xfrm_interface_ipv4(index, 19),
                Err(GtpuDownlinkInjectionError::InterfaceUnavailable)
            ));
        }
        assert!(matches!(
            injector.inject((&event).into()),
            Err(GtpuDownlinkInjectionError::Send {
                packets_sent: 0,
                class: GtpuDownlinkSendFailure::InterfaceUnavailable,
            })
        ));
        expect_no_wire(&mut peer);
    }
    // Identical attributes cannot hide a delete/create between the initial
    // GETLINK receipt and bind. The notification monitor must refuse it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let mut replaced = false;
        let raced = xfrm_interface::XfrmInterfaceSocket::open_checked(index, 19, || {
            assert_eq!(peer.call("replace_interface_xfrm")["done"], true);
            replaced = true;
        });
        assert!(matches!(
            raced,
            Err(GtpuDownlinkInjectionError::InterfaceIdentityMismatch)
        ));
        if replaced {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "race hook was never reached"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    expect_no_wire(&mut peer);
    let mut replacement = settled_interface(index);
    assert_eq!(replacement.inject((&event).into()), Ok(1));
    expect_encrypted(&peer.call("observe"), 0x100, &[&bytes], &payload);
    println!("OPC_GTPU_XFRM_INTERFACE_INJECTION_PROVEN: exact zero/nonzero-ID packets, both bearers, source/protocol selectors, ordered reassembly with conntrack, inner POST_ROUTING invalid-state drops, inbound receive queue empty, ICMP host-unreachable and fragmentation-needed quotes with positive controls and consumer output suppression, route replacement, interface retirement/reuse and construction race");
}
