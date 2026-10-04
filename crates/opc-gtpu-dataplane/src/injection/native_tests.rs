//! Real-kernel proof with an independent Python ESP peer and wire observer.

use super::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

struct Peer {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}

impl Peer {
    fn start() -> Self {
        let mut child = Command::new("python3")
            .args([
                "-u",
                "-c",
                include_str!("../../tests/fixtures/downlink_injection.py"),
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
        };
        assert_eq!(peer.read()["ready"], true);
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
