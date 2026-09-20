use opc_proto_ikev2::nwu::mobike::Notify;

#[test]
fn independent_mobike_notify_shapes() {
    assert_eq!(
        Notify::decode_body(&[0, 0, 0x40, 0x10]).unwrap(),
        Some(Notify::UpdateSaAddresses)
    );
    assert_eq!(
        Notify::UpdateSaAddresses.encode_body().unwrap(),
        [0, 0, 0x40, 0x10]
    );
    for length in 0..=65 {
        let mut bytes = vec![0, 0, 0x40, 0x11];
        bytes.extend(vec![0x5a; length]);
        assert_eq!(
            Notify::decode_body(&bytes).is_ok(),
            (8..=64).contains(&length)
        );
    }
}

use aes_gcm::{
    aead::{Aead, Key, KeyInit, Nonce, Payload},
    Aes128Gcm,
};
use opc_proto_ikev2::{
    derive_ike_sa_init_key_material,
    nwu::mobike::{
        Error, NatState, Outbound, Path, ProbeOutcome, Request, RequestStatus, Responder,
    },
    nwu::{
        Address, AddressFamilies, ConfigurationReply, ConfigurationRequest, Limits, NasEndpoint,
    },
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2InitiatorMessageIdWindow, Ikev2PrfAlgorithm,
    Ikev2ProtectedPayloadDirection, Ikev2ResponderMessageIdWindow, Ikev2SaInitCryptoProfile,
    Ikev2SaInitKeyMaterial, Ikev2SaInitProtectedPayloadProvider, PayloadType,
};
use sha1::{Digest, Sha1};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
};
mod support;

const SPIS: [u64; 2] = [0x0102030405060708, 0x1112131415161718];
const UPDATE: &[u8] = &[0, 0, 0x40, 0x10];

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .unwrap()
}
fn keys() -> Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        profile(),
        SPIS[0].to_be_bytes(),
        SPIS[1].to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        None,
    )
    .unwrap()
}
fn config(families: AddressFamilies, supported: bool) -> ConfigurationReply {
    let v4 = Address::new("192.0.2.10".parse().unwrap());
    let v6 = Address::new("2001:db8::10".parse().unwrap());
    ConfigurationReply::new(
        ConfigurationRequest {
            families,
            mobike_supported: supported,
        },
        families.ipv4().then_some(v4),
        families.ipv6().then_some((v6, 64)),
        NasEndpoint::new(
            families.ipv4().then_some(v4),
            families.ipv6().then_some(v6),
            20000,
        )
        .unwrap(),
    )
    .unwrap()
}
fn receiver(keys: &Ikev2SaInitKeyMaterial, supported: bool, encapsulated: bool) -> Responder<'_> {
    Responder::new(
        SPIS,
        config(AddressFamilies::Ipv4, true),
        Ikev2SaInitProtectedPayloadProvider::new(
            profile(),
            keys,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ),
        NatState::new(supported, encapsulated).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn path(source: &str, dest: &str) -> Path {
    Path::new(source.parse().unwrap(), dest.parse().unwrap()).unwrap()
}
fn v4path(nat: bool) -> Path {
    path(
        "192.0.2.20:45123",
        if nat {
            "198.51.100.1:4500"
        } else {
            "198.51.100.1:500"
        },
    )
}
fn window() -> Ikev2ResponderMessageIdWindow {
    Ikev2ResponderMessageIdWindow::with_highest_processed(2)
}

// Independent RFC 7296 generic headers and RFC 5282 AES-GCM packet construction.
// This oracle does not call the SDK Notify builder, packet encoder or sealer.
fn chain(bodies: &[&[u8]]) -> (PayloadType, Vec<u8>) {
    let mut out = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        out.extend([if i + 1 == bodies.len() { 0 } else { 41 }, 0]);
        out.extend(((4 + b.len()) as u16).to_be_bytes());
        out.extend_from_slice(b);
    }
    (
        if bodies.is_empty() {
            PayloadType::NoNext
        } else {
            PayloadType::Notify
        },
        out,
    )
}
fn encrypted(
    keys: &Ikev2SaInitKeyMaterial,
    id: u32,
    response: bool,
    natt: bool,
    first: PayloadType,
    cleartext: &[u8],
) -> Vec<u8> {
    static IV: AtomicU64 = AtomicU64::new(1);
    let iv = IV.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    let mut plaintext = cleartext.to_vec();
    plaintext.push(0); // zero IKE padding
    let body_len = 8 + plaintext.len() + 16;
    let mut prefix = Vec::new();
    prefix.extend(SPIS[0].to_be_bytes());
    prefix.extend(SPIS[1].to_be_bytes());
    prefix.extend([46, 0x20, 37, if response { 0x28 } else { 0x08 }]);
    prefix.extend(id.to_be_bytes());
    prefix.extend(((32 + body_len) as u32).to_be_bytes());
    prefix.extend([first.as_u8(), 0]);
    prefix.extend(((4 + body_len) as u16).to_be_bytes());
    let material = keys.sk_ei();
    let (key, salt) = material.split_at(16);
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(&iv);
    let cipher = Aes128Gcm::new(<&Key<Aes128Gcm>>::try_from(key).unwrap());
    let ciphertext = cipher
        .encrypt(
            <&Nonce<Aes128Gcm>>::try_from(nonce.as_slice()).unwrap(),
            Payload {
                msg: &plaintext,
                aad: &prefix,
            },
        )
        .unwrap();
    let mut out = if natt { vec![0; 4] } else { vec![] };
    out.extend(prefix);
    out.extend(iv);
    out.extend(ciphertext);
    out
}
fn packet(
    keys: &Ikev2SaInitKeyMaterial,
    id: u32,
    response: bool,
    natt: bool,
    bodies: &[&[u8]],
) -> Vec<u8> {
    let (first, bytes) = chain(bodies);
    encrypted(keys, id, response, natt, first, &bytes)
}
fn hash(endpoint: SocketAddr) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(SPIS[0].to_be_bytes());
    h.update(SPIS[1].to_be_bytes());
    match endpoint.ip() {
        std::net::IpAddr::V4(v) => h.update(v.octets()),
        std::net::IpAddr::V6(v) => h.update(v.octets()),
    };
    h.update(endpoint.port().to_be_bytes());
    h.finalize().into()
}
fn nat_bodies(p: Path, source_nat: bool, dest_nat: bool) -> (Vec<u8>, Vec<u8>) {
    let mut source = hash(p.source());
    let mut dest = hash(p.destination());
    if source_nat {
        source[0] ^= 1;
    }
    if dest_nat {
        dest[0] ^= 1;
    }
    let mut a = vec![0, 0, 0x40, 4];
    a.extend(source);
    let mut b = vec![0, 0, 0x40, 5];
    b.extend(dest);
    (a, b)
}
fn probe_response(keys: &Ikev2SaInitKeyMaterial, probe: &Outbound, natt: bool) -> Vec<u8> {
    let cookie = &probe.payloads()[0].body;
    assert_eq!(&cookie[..4], &[0, 0, 0x40, 0x11]);
    packet(keys, probe.message_id(), true, natt, &[cookie])
}

#[test]
fn independently_encrypted_update_requires_cookie2_before_migration() {
    let k = keys();
    let p = v4path(true);
    let mut r = receiver(&k, true, false);
    let mut w = window();
    let cookie = [0, 0, 0x40, 0x11, 1, 2, 3, 4, 5, 6, 7, 8];
    let (nat_s, nat_d) = nat_bodies(p, true, false);
    let update = packet(&k, 3, false, true, &[&nat_d, &cookie, UPDATE, &nat_s]);
    let accepted = r
        .receive_request(&update, p, &mut w, |observed| observed == p)
        .unwrap();
    assert_eq!(accepted.status(), RequestStatus::Accepted);
    assert_eq!(accepted.ike_path(), Some(p));
    assert_eq!(accepted.reply().path(), p.reversed());
    assert_eq!(accepted.reply().message_id(), 3);
    assert!(accepted.reply().is_response());
    assert_eq!(accepted.reply().payloads()[0].body, cookie);
    assert_eq!(
        &accepted.reply().payloads()[1].body[4..],
        hash(p.destination())
    );
    assert_eq!(&accepted.reply().payloads()[2].body[4..], hash(p.source()));
    assert!(r.has_pending_update());
    assert!(!r.nat_state().esp_udp_encapsulation());
    let mut outbound = Ikev2InitiatorMessageIdWindow::with_next_message_id(9);
    let probe = r.begin_return_routability(&mut outbound).unwrap();
    assert_eq!(probe.path(), p.reversed());
    assert!(!probe.is_response());
    assert_eq!(probe.message_id(), 9);
    assert_eq!(probe.payloads()[0].body.len(), 36);
    let header = probe.header(57).unwrap();
    assert!(!header.flags.initiator());
    assert!(!header.flags.response());
    assert_eq!(header.length, 89);
    assert!(r.begin_return_routability(&mut outbound).is_err());
    let reply = probe_response(&k, &probe, true);
    let ProbeOutcome::Verified(migration) =
        r.receive_probe_response(&reply, p, &mut outbound).unwrap()
    else {
        panic!("proof expected")
    };
    assert_eq!(migration.path(), p);
    assert!(migration.esp_udp_encapsulation());
    assert!(r.nat_state().esp_udp_encapsulation());
    assert!(!r.has_pending_update());
    assert_eq!(outbound.next_message_id(), 10);
    assert!(outbound.outstanding().is_none());
    assert!(matches!(
        r.receive_probe_response(&reply, p, &mut outbound),
        Err(Error::State)
    ));
    assert!(matches!(
        r.receive_request(&update, p, &mut w, |_| panic!("replay policy call")),
        Err(Error::Replay)
    ));
}

#[test]
fn every_packet_region_tamper_and_policy_rejection_preserve_state() {
    let k = keys();
    let p = v4path(true);
    let update = packet(&k, 3, false, true, &[UPDATE]);
    let mut r = receiver(&k, true, false);
    let mut w = window();
    for index in 0..update.len() {
        let mut bad = update.clone();
        bad[index] ^= 1;
        assert!(
            r.receive_request(&bad, p, &mut w, |_| panic!("unauthenticated policy call"))
                .is_err(),
            "octet {index}"
        );
        assert_eq!(w.highest_processed(), Some(2));
        assert!(!r.has_pending_update());
    }
    let denied = r.receive_request(&update, p, &mut w, |_| false).unwrap();
    assert_eq!(denied.status(), RequestStatus::UnacceptableAddresses);
    assert_eq!(denied.reply().payloads()[0].body, [0, 0, 0, 40]);
    assert_eq!(denied.ike_path(), None);
    assert_eq!(w.highest_processed(), Some(2));
    assert!(!r.has_pending_update());
    r.receive_request(&update, p, &mut w, |_| true).unwrap();
    assert_eq!(w.highest_processed(), Some(3));
}

#[test]
fn source_cookie_and_response_correlation_checks_are_not_interchangeable() {
    let k = keys();
    let p = v4path(true);
    let mut r = receiver(&k, true, false);
    let mut w = window();
    r.receive_request(&packet(&k, 3, false, true, &[UPDATE]), p, &mut w, |_| true)
        .unwrap();
    let mut outbound = Ikev2InitiatorMessageIdWindow::with_next_message_id(9);
    let probe = r.begin_return_routability(&mut outbound).unwrap();
    let response = probe_response(&k, &probe, true);
    let wrong_source = path("192.0.2.21:45123", "198.51.100.1:4500");
    assert!(matches!(
        r.receive_probe_response(&response, wrong_source, &mut outbound),
        Err(Error::Source)
    ));
    let wrong_id = packet(&k, 10, true, true, &[&probe.payloads()[0].body]);
    assert!(matches!(
        r.receive_probe_response(&wrong_id, p, &mut outbound),
        Err(Error::Correlation)
    ));
    assert_eq!(outbound.outstanding().unwrap().message_id, 9);
    let mut cookie = probe.payloads()[0].body.clone();
    cookie[4] ^= 1;
    let bad = packet(&k, 9, true, true, &[&cookie]);
    assert!(matches!(
        r.receive_probe_response(&bad, p, &mut outbound).unwrap(),
        ProbeOutcome::DiscardIkeAndAllChildren
    ));
    assert!(matches!(
        r.receive_request(&packet(&k, 4, false, true, &[UPDATE]), p, &mut w, |_| true),
        Err(Error::Closed)
    ));
    assert!(outbound.outstanding().is_none());
    assert!(!r.has_pending_update());
}

#[test]
fn wire_lengths_conflicting_lists_and_resource_limits() {
    let additional = [0, 0, 0x40, 0x0d, 192, 0, 2, 30];
    let no_additional = [0, 0, 0x40, 0x0f];
    let (first, bytes) = chain(&[&additional, UPDATE]);
    let parsed = Request::decode(first, &bytes, Limits::default()).unwrap();
    assert!(parsed.updates_addresses());
    assert_eq!(
        parsed.additional_addresses().unwrap(),
        [Address::new("192.0.2.30".parse().unwrap())]
    );
    for bodies in [
        &[additional.as_slice(), additional.as_slice()][..],
        &[additional.as_slice(), no_additional.as_slice()][..],
        &[UPDATE, UPDATE][..],
    ] {
        let (first, bytes) = chain(bodies);
        assert!(Request::decode(first, &bytes, Limits::default()).is_err());
    }
    for len in 0..bytes.len() {
        assert!(Request::decode(first, &bytes[..len], Limits::default()).is_err());
    }
    assert!(Request::decode(
        first,
        &bytes,
        Limits {
            bytes: bytes.len() - 1,
            entries: 2
        }
    )
    .is_err());
    assert!(Request::decode(
        first,
        &bytes,
        Limits {
            bytes: bytes.len(),
            entries: 1
        }
    )
    .is_err());
    assert!(Request::decode(
        first,
        &bytes,
        Limits {
            bytes: bytes.len(),
            entries: 2
        }
    )
    .is_ok());
    let (first, bytes) = chain(&[UPDATE, &[0, 0, 0xff, 0xff]]);
    assert!(Request::decode(
        first,
        &bytes,
        Limits {
            bytes: 1024,
            entries: 1
        }
    )
    .is_err());
    assert!(Request::decode(
        first,
        &bytes,
        Limits {
            bytes: 1024,
            entries: 2
        }
    )
    .is_ok());
    assert!(Request::decode(
        PayloadType::Unknown(250),
        &[0, 0x80, 0, 4],
        Limits::default()
    )
    .is_err());
    assert!(Request::decode(PayloadType::Unknown(250), &[0, 0, 0, 4], Limits::default()).is_ok());
    for t in [0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12] {
        assert!(Notify::decode_body(&[0, 1, 0x40, t, 1]).is_err());
    }
    assert_eq!(
        Notify::decode_body(&[255, 0, 0x40, 0x10]).unwrap(),
        Some(Notify::UpdateSaAddresses)
    );
    assert!(Notify::Cookie2(&[0; 65]).encode_body().is_err());
    assert!(Notify::NatSource(&[0; 19]).encode_body().is_err());
    assert!(Notify::NatDestination(&[0; 21]).encode_body().is_err());
    let v4 = [
        0, 0, 0x40, 0x12, 192, 0, 2, 20, 198, 51, 100, 1, 0xb0, 0x43, 1, 0xf4,
    ];
    let p = v4path(false);
    assert_eq!(
        Notify::decode_body(&v4).unwrap(),
        Some(Notify::NoNatsAllowed(p))
    );
    assert_eq!(Notify::NoNatsAllowed(p).encode_body().unwrap(), v4);
    let published = include_str!(
        "../../opc-n3iwf-fixtures/fixtures/nwu-ike/wire/mobility-additional-addresses.hex"
    );
    let bytes = published
        .split_whitespace()
        .map(|v| u8::from_str_radix(v, 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        Request::decode(PayloadType::Notify, &bytes, Limits::default())
            .unwrap()
            .additional_addresses()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn nat_detection_matrix_changes_encapsulation_only_after_latest_proof() {
    let k = keys();
    let p = v4path(true);
    for source_nat in [false, true] {
        for dest_nat in [false, true] {
            let mut r = receiver(&k, true, !(source_nat || dest_nat));
            let mut w = window();
            let (source, dest) = nat_bodies(p, source_nat, dest_nat);
            let initial = r.nat_state();
            r.receive_request(
                &packet(&k, 3, false, true, &[UPDATE, &source, &dest]),
                p,
                &mut w,
                |_| true,
            )
            .unwrap();
            assert_eq!(r.nat_state(), initial);
            let mut out = Ikev2InitiatorMessageIdWindow::new();
            let probe = r.begin_return_routability(&mut out).unwrap();
            let reply = probe_response(&k, &probe, true);
            let ProbeOutcome::Verified(m) = r.receive_probe_response(&reply, p, &mut out).unwrap()
            else {
                panic!("proof expected")
            };
            assert_eq!(m.esp_udp_encapsulation(), source_nat || dest_nat);
            assert_eq!(
                r.nat_state().esp_udp_encapsulation(),
                source_nat || dest_nat
            );
        }
    }
    let mut r = receiver(&k, true, false);
    let mut w = window();
    let (source, dest) = nat_bodies(p, true, true);
    let probe_only = r
        .receive_request(
            &packet(&k, 3, false, true, &[&source, &dest]),
            p,
            &mut w,
            |_| panic!("DPD address policy"),
        )
        .unwrap();
    assert_eq!(probe_only.ike_path(), None);
    assert_eq!(probe_only.reply().payloads().len(), 2);
    assert!(!r.has_pending_update());
    assert!(!r.nat_state().esp_udp_encapsulation());
    let mut out = Ikev2InitiatorMessageIdWindow::new();
    assert!(matches!(
        r.begin_return_routability(&mut out),
        Err(Error::State)
    ));
    for bodies in [
        &[source.as_slice()][..],
        &[dest.as_slice()][..],
        &[source.as_slice(), dest.as_slice(), dest.as_slice()][..],
    ] {
        let data = packet(&k, 4, false, true, bodies);
        assert!(r.receive_request(&data, p, &mut w, |_| true).is_err());
        assert_eq!(w.highest_processed(), Some(3));
    }
    // Multiple source hashes are OR alternatives, with exactly one destination.
    let (match_source, _) = nat_bodies(p, false, false);
    r.receive_request(
        &packet(&k, 4, false, true, &[UPDATE, &source, &match_source, &dest]),
        p,
        &mut w,
        |_| true,
    )
    .unwrap();
}

#[test]
fn nat_prohibition_binds_both_addresses_and_ports_for_ipv4_and_ipv6() {
    let k = keys();
    for p in [
        v4path(false),
        path("[2001:db8::20]:500", "[2001:db8:1::1]:500"),
    ] {
        let mut r = receiver(&k, false, false);
        let mut w = window();
        let no_nat = Notify::NoNatsAllowed(p).encode_body().unwrap();
        assert!(r
            .receive_request(&packet(&k, 3, false, false, &[UPDATE]), p, &mut w, |_| true)
            .is_err());
        let width = if p.source().is_ipv4() { 4 } else { 16 };
        for index in [4, 4 + width, no_nat.len() - 3, no_nat.len() - 1] {
            let mut changed = no_nat.clone();
            changed[index] ^= 1;
            let reply = r
                .receive_request(
                    &packet(&k, 3, false, false, &[UPDATE, &changed]),
                    p,
                    &mut w,
                    |_| panic!("NAT mismatch policy"),
                )
                .unwrap();
            assert_eq!(reply.status(), RequestStatus::UnexpectedNatDetected);
            assert_eq!(reply.reply().payloads()[0].body, [0, 0, 0, 41]);
            assert_eq!(reply.reply().path(), p.reversed());
            assert!(!r.has_pending_update());
            assert_eq!(w.highest_processed(), Some(2));
        }
        r.receive_request(
            &packet(&k, 3, false, false, &[UPDATE, &no_nat]),
            p,
            &mut w,
            |_| true,
        )
        .unwrap();
        let mut out = Ikev2InitiatorMessageIdWindow::new();
        let probe = r.begin_return_routability(&mut out).unwrap();
        let reply = probe_response(&k, &probe, false);
        let ProbeOutcome::Verified(m) = r.receive_probe_response(&reply, p, &mut out).unwrap()
        else {
            panic!("proof expected")
        };
        assert_eq!(m.path(), p);
        assert!(!m.esp_udp_encapsulation());
    }
}

#[test]
fn superseded_probe_cannot_apply_old_candidate_and_missing_cookie_closes() {
    let k = keys();
    let p = v4path(true);
    let second = path("192.0.2.21:46000", "198.51.100.1:4500");
    let mut r = receiver(&k, true, false);
    let mut w = window();
    r.receive_request(&packet(&k, 3, false, true, &[UPDATE]), p, &mut w, |_| true)
        .unwrap();
    let mut out = Ikev2InitiatorMessageIdWindow::with_next_message_id(20);
    let first_probe = r.begin_return_routability(&mut out).unwrap();
    r.receive_request(
        &packet(&k, 4, false, true, &[UPDATE]),
        second,
        &mut w,
        |_| true,
    )
    .unwrap();
    assert!(matches!(
        r.receive_probe_response(&probe_response(&k, &first_probe, true), p, &mut out)
            .unwrap(),
        ProbeOutcome::Superseded
    ));
    assert!(r.has_pending_update());
    assert_eq!(out.next_message_id(), 21);
    let new_probe = r.begin_return_routability(&mut out).unwrap();
    assert_eq!(new_probe.path(), second.reversed());
    assert_ne!(first_probe.payloads()[0].body, new_probe.payloads()[0].body);
    let ProbeOutcome::Verified(m) = r
        .receive_probe_response(&probe_response(&k, &new_probe, true), second, &mut out)
        .unwrap()
    else {
        panic!("latest proof")
    };
    assert_eq!(m.path(), second);
    r.receive_request(&packet(&k, 5, false, true, &[UPDATE]), p, &mut w, |_| true)
        .unwrap();
    let probe = r.begin_return_routability(&mut out).unwrap();
    let missing = packet(&k, probe.message_id(), true, true, &[]);
    assert!(matches!(
        r.receive_probe_response(&missing, p, &mut out).unwrap(),
        ProbeOutcome::DiscardIkeAndAllChildren
    ));
}

#[test]
fn announcements_dpd_windows_transport_and_redaction_remain_separate() {
    let k = keys();
    let p = v4path(true);
    let mut r = receiver(&k, true, true);
    let mut w = window();
    let additional = [0, 0, 0x40, 0x0d, 192, 0, 2, 30];
    let received = r
        .receive_request(
            &packet(&k, 3, false, true, &[&additional]),
            p,
            &mut w,
            |_| true,
        )
        .unwrap();
    assert_eq!(
        received.peer_addresses().unwrap(),
        [
            Address::new(p.source().ip()),
            Address::new("192.0.2.30".parse().unwrap())
        ]
    );
    assert_eq!(received.ike_path(), None);
    assert!(!r.has_pending_update());
    let no_additional = [0, 0, 0x40, 0x0f];
    let replaced = r
        .receive_request(
            &packet(&k, 4, false, true, &[&no_additional]),
            p,
            &mut w,
            |_| true,
        )
        .unwrap();
    assert_eq!(
        replaced.peer_addresses().unwrap(),
        [Address::new(p.source().ip())]
    );
    for garbage in [
        &[0xff][..],
        &[1, 2, 3, 4, 0, 0, 0, 1][..],
        &[0, 0, 0, 0][..],
    ] {
        assert!(matches!(
            r.receive_request(garbage, p, &mut w, |_| panic!("non-IKE policy")),
            Err(Error::Transport)
        ));
    }
    assert!(matches!(
        r.receive_request(&packet(&k, 5, false, false, &[UPDATE]), p, &mut w, |_| true),
        Err(Error::Transport)
    ));
    assert!(matches!(
        r.receive_request(
            &packet(&k, 5, false, false, &[UPDATE]),
            v4path(false),
            &mut w,
            |_| true
        ),
        Err(Error::Transport)
    ));
    let fresh = packet(&k, 5, false, true, &[UPDATE]);
    assert!(matches!(
        r.receive_request(&fresh, p, &mut Ikev2ResponderMessageIdWindow::new(), |_| {
            true
        }),
        Err(Error::Window)
    ));
    assert_eq!(w.highest_processed(), Some(4));
    r.receive_request(&fresh, p, &mut w, |_| true).unwrap();
    // Even a mistakenly replaced shared receive window cannot replay an update
    // already accepted by this receiver.
    assert!(matches!(
        r.receive_request(&fresh, p, &mut window(), |_| true),
        Err(Error::Replay)
    ));
    let mut out = Ikev2InitiatorMessageIdWindow::with_next_message_id(u32::MAX);
    assert!(matches!(
        r.begin_return_routability(&mut out),
        Err(Error::Window)
    ));
    let mut out = Ikev2InitiatorMessageIdWindow::new();
    let probe = r.begin_return_routability(&mut out).unwrap();
    let debug = format!(
        "{r:?} {p:?} {probe:?} {received:?} {:?}",
        Notify::Cookie2(&[0x7f; 32])
    );
    for secret in [
        "192.0.2.20",
        "198.51.100.1",
        "45123",
        "127, 127",
        "72623859790382856",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(
        r.probe_timeout(),
        opc_proto_ikev2::nwu::DeleteOutcome::DiscardIkeAndAllChildren
    );
}

#[test]
fn conditional_capability_and_crypto_direction_bind_the_established_sa() {
    let k = keys();
    for families in [
        AddressFamilies::Ipv4,
        AddressFamilies::Ipv6,
        AddressFamilies::Dual,
    ] {
        for supported in [false, true] {
            let result = Responder::new(
                SPIS,
                config(families, supported),
                Ikev2SaInitProtectedPayloadProvider::new(
                    profile(),
                    &k,
                    Ikev2ProtectedPayloadDirection::InitiatorToResponder,
                ),
                NatState::new(true, false).unwrap(),
                Limits::default(),
            );
            assert_eq!(result.is_ok(), families.ipv4() && supported);
        }
    }
    assert!(Responder::new(
        SPIS,
        config(AddressFamilies::Ipv4, true),
        Ikev2SaInitProtectedPayloadProvider::new(
            profile(),
            &k,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator
        ),
        NatState::new(true, false).unwrap(),
        Limits::default()
    )
    .is_err());
    assert!(NatState::new(false, true).is_err());
    for (a, b) in [
        ("0.0.0.0:500", "192.0.2.1:500"),
        ("224.0.0.1:500", "192.0.2.1:500"),
        ("192.0.2.1:0", "192.0.2.2:500"),
        ("192.0.2.1:500", "[2001:db8::1]:500"),
    ] {
        assert!(Path::new(a.parse().unwrap(), b.parse().unwrap()).is_err());
    }
}

#[test]
fn complete_datagram_bounds_precede_probe_entropy_and_window_allocation() {
    let k = keys();
    let p = v4path(true);
    let update = packet(&k, 3, false, true, &[UPDATE]);
    for cap in [update.len() - 1, update.len(), 100, 101] {
        let mut r = Responder::new(
            SPIS,
            config(AddressFamilies::Ipv4, true),
            Ikev2SaInitProtectedPayloadProvider::new(
                profile(),
                &k,
                Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            ),
            NatState::new(true, false).unwrap(),
            Limits {
                bytes: cap,
                entries: 1,
            },
        )
        .unwrap();
        let mut w = window();
        let admitted = r.receive_request(&update, p, &mut w, |_| true);
        assert_eq!(admitted.is_ok(), cap >= update.len());
        let mut out = Ikev2InitiatorMessageIdWindow::new();
        let probe = r.begin_return_routability(&mut out);
        assert_eq!(probe.is_ok(), cap >= 101);
        if let Ok(probe) = probe {
            assert!(probe.header(65).is_ok());
            assert!(probe.header(66).is_err());
            assert_eq!(probe.cleartext().unwrap().1.len(), 40);
        } else {
            assert!(out.outstanding().is_none());
            assert_eq!(out.next_message_id(), 0);
        }
    }
}

fn verified_migration(
    keys: &Ikev2SaInitKeyMaterial,
    responder: &mut Responder<'_>,
    receive: &mut Ikev2ResponderMessageIdWindow,
    send: &mut Ikev2InitiatorMessageIdWindow,
    id: u32,
    observed: Path,
) -> opc_proto_ikev2::nwu::mobike::Migration {
    responder
        .receive_request(
            &packet(keys, id, false, true, &[UPDATE]),
            observed,
            receive,
            |_| true,
        )
        .unwrap();
    let probe = responder.begin_return_routability(send).unwrap();
    let ProbeOutcome::Verified(migration) = responder
        .receive_probe_response(&probe_response(keys, &probe, true), observed, send)
        .unwrap()
    else {
        panic!("authenticated proof required")
    };
    migration
}

#[test]
fn migration_permit_requires_exact_live_association_and_accepted_event_freshness() {
    let keys = keys();
    let observed = v4path(true);
    let mut responder = receiver(&keys, true, true);
    let foreign = receiver(&keys, true, true);
    let association = responder.migration_association();
    let mut receive = window();
    let mut send = Ikev2InitiatorMessageIdWindow::with_next_message_id(20);
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 3, observed);
    let permit = migration.authorize(&association).unwrap();
    assert_eq!(permit.path(), observed);
    assert!(permit.esp_udp_encapsulation());
    assert_eq!(permit.validate(&association), Ok(()));
    assert_eq!(
        permit.validate(&foreign.migration_association()),
        Err(Error::Correlation)
    );
    assert_eq!(format!("{permit:?}"), "MigrationPermit(<redacted>)");
    assert_eq!(
        format!("{association:?}"),
        "MigrationAssociation(<redacted>)"
    );

    let mut corrupted = packet(&keys, 4, false, true, &[UPDATE]);
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(matches!(
        responder.receive_request(&corrupted, observed, &mut receive, |_| true),
        Err(Error::Authentication)
    ));
    assert_eq!(permit.validate(&association), Ok(()));
    assert!(matches!(
        responder.receive_request(
            &packet(&keys, 3, false, true, &[UPDATE]),
            observed,
            &mut receive,
            |_| true
        ),
        Err(Error::Replay)
    ));
    assert_eq!(permit.validate(&association), Ok(()));
    let rejected = responder
        .receive_request(
            &packet(&keys, 4, false, true, &[UPDATE]),
            observed,
            &mut receive,
            |_| false,
        )
        .unwrap();
    assert_eq!(rejected.status(), RequestStatus::UnacceptableAddresses);
    assert_eq!(permit.validate(&association), Ok(()));

    // Even a successfully admitted liveness request is a later SA event.
    responder
        .receive_request(
            &packet(&keys, 4, false, true, &[]),
            observed,
            &mut receive,
            |_| true,
        )
        .unwrap();
    assert_eq!(permit.validate(&association), Err(Error::Replay));
}

#[test]
fn stale_migration_cannot_be_authorized_and_external_events_or_drop_revoke_permits() {
    let keys = keys();
    let observed = v4path(true);
    let mut responder = receiver(&keys, true, true);
    let association = responder.migration_association();
    let mut receive = window();
    let mut send = Ikev2InitiatorMessageIdWindow::with_next_message_id(20);
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 3, observed);
    responder.invalidate_migration_authority().unwrap();
    assert!(matches!(
        migration.authorize(&association),
        Err(Error::Replay)
    ));
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 4, observed);
    let permit = migration.authorize(&association).unwrap();
    responder.invalidate_migration_authority().unwrap();
    assert_eq!(permit.validate(&association), Err(Error::Replay));
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 5, observed);
    let permit = migration.authorize(&association).unwrap();
    drop(responder);
    assert_eq!(permit.validate(&association), Err(Error::Closed));
    assert_eq!(permit.validate(&association.clone()), Err(Error::Closed));
}

#[test]
fn cross_association_authorization_and_cookie_failure_cannot_create_live_permits() {
    let keys = keys();
    let observed = v4path(true);
    let mut responder = receiver(&keys, true, true);
    let foreign = receiver(&keys, true, true);
    let association = responder.migration_association();
    let mut receive = window();
    let mut send = Ikev2InitiatorMessageIdWindow::with_next_message_id(20);
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 3, observed);
    assert!(matches!(
        migration.authorize(&foreign.migration_association()),
        Err(Error::Correlation)
    ));
    let migration = verified_migration(&keys, &mut responder, &mut receive, &mut send, 4, observed);
    let permit = migration.authorize(&association).unwrap();
    responder
        .receive_request(
            &packet(&keys, 5, false, true, &[UPDATE]),
            observed,
            &mut receive,
            |_| true,
        )
        .unwrap();
    let probe = responder.begin_return_routability(&mut send).unwrap();
    let reply = packet(&keys, probe.message_id(), true, true, &[]);
    assert!(matches!(
        responder
            .receive_probe_response(&reply, observed, &mut send)
            .unwrap(),
        ProbeOutcome::DiscardIkeAndAllChildren
    ));
    assert_eq!(permit.validate(&association), Err(Error::Closed));
}
