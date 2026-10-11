use super::*;

// These fixtures encode the Linux UAPI independently of the production encoder.
// Native-endian integer fields surround the network-order EtherType in tcm_info.
pub(super) fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(((data.len() + 4) as u16).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(data);
    out.resize((out.len() + 3) & !3, 0);
    out
}

pub(super) fn message(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(((body.len() + 16) as u32).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(flags.to_ne_bytes());
    out.extend(9_u32.to_ne_bytes());
    out.extend(77_u32.to_ne_bytes());
    out.extend(body);
    out
}

pub(super) fn filter(handle: u32, protocol: u16, chain: u32) -> Vec<u8> {
    let mut body = vec![0; 4];
    body.extend(7_u32.to_ne_bytes());
    body.extend(handle.to_ne_bytes());
    body.extend(0xffff_fff3_u32.to_ne_bytes());
    body.extend(((60_u32 << 16) | u32::from(protocol.to_be())).to_ne_bytes());
    body.extend(attr(1, b"bpf\0"));
    body.extend(attr(11, &chain.to_ne_bytes()));
    if handle != 0 {
        let options = [
            attr(7, b"opc_fixture\0"),
            attr(8, &1_u32.to_ne_bytes()),
            attr(9, &8_u32.to_ne_bytes()),
            attr(10, &[11; 8]),
            attr(11, &42_u32.to_ne_bytes()),
        ]
        .concat();
        body.extend(attr(2, &options));
    }
    message(44, 2, &body)
}

pub(super) fn done() -> Vec<u8> {
    message(3, 2, &0_i32.to_ne_bytes())
}
fn dump() -> wire::Dump {
    wire::Dump::new(7, TcHook::Egress, 9, 77)
}

#[test]
fn complete_inventory_preserves_all_coordinates_and_summaries() {
    let mut parser = dump();
    for bytes in [
        filter(0, 3, 0),
        filter(1, 3, 0),
        filter(2, 3, 0),
        filter(1, 0x800, 0),
        filter(1, 3, 4),
        done(),
    ] {
        parser.consume(&bytes).unwrap();
    }
    let entries = parser.finish().unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].slot.handle, 0);
    assert_eq!(entries[2].slot.handle, 2);
    assert_eq!(entries[3].slot.protocol, 0x800);
    assert_eq!(entries[4].slot.chain, 4);
}

#[test]
fn missing_completion_never_proves_even_empty_inventory() {
    assert!(dump().finish().is_err());
    let mut parser = dump();
    parser.consume(&filter(1, 3, 0)).unwrap();
    assert!(parser.finish().is_err());
}

#[test]
fn wrong_sequence_port_hook_device_and_interrupted_dumps_refuse() {
    for offset in [0, 6, 8, 12, 16, 20, 28] {
        let mut bytes = filter(1, 3, 0);
        bytes[offset] ^= if offset == 6 { 16 } else { 1 };
        assert!(dump().consume(&bytes).is_err(), "offset {offset}");
    }
    for bytes in [
        message(4, 2, &[]),
        message(3, 2, &(-4_i32).to_ne_bytes()),
        message(3, 0, &0_i32.to_ne_bytes()),
    ] {
        assert!(dump().consume(&bytes).is_err());
    }
    let mut parser = dump();
    parser.consume(&done()).unwrap();
    assert!(parser.consume(&filter(1, 3, 0)).is_err());
}

#[test]
fn malformed_attributes_duplicate_entries_and_false_summaries_refuse() {
    let base = filter(1, 3, 0);
    for end in 0..base.len() {
        assert!(dump().consume(&base[..end]).is_err(), "truncated at {end}");
    }
    for attribute in [attr(1, b"bpf\0"), attr(11, &[0, 0]), vec![3, 0, 21, 0]] {
        let mut bytes = base.clone();
        bytes.extend(attribute);
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        assert!(dump().consume(&bytes).is_err());
    }
    let mut parser = dump();
    parser.consume(&base).unwrap();
    assert!(parser.consume(&base).is_err());
    let mut summary = base;
    summary[24..28].copy_from_slice(&0_u32.to_ne_bytes());
    assert!(dump().consume(&summary).is_err());
}

#[test]
fn delete_request_addresses_only_one_exact_filter() {
    let slot = TcSlot::new(7, TcHook::Egress, 4, 0x800, 60, 19).unwrap();
    let bytes = wire::delete_request(slot, b"bpf", 9, 77).unwrap();
    assert_eq!(&bytes[4..6], &45_u16.to_ne_bytes());
    assert_eq!(&bytes[6..8], &5_u16.to_ne_bytes());
    assert_eq!(&bytes[24..28], &19_u32.to_ne_bytes());
    assert_eq!(&bytes[28..32], &0xffff_fff3_u32.to_ne_bytes());
    assert_eq!(
        &bytes[32..36],
        &((60_u32 << 16) | u32::from(0x800_u16.to_be())).to_ne_bytes()
    );
    assert!(bytes[36..]
        .windows(8)
        .any(|value| value == attr(11, &4_u32.to_ne_bytes())));
    let summary = TcSlot { handle: 0, ..slot };
    assert!(wire::delete_request(summary, b"bpf", 9, 77).is_err());
}

#[test]
fn wildcard_coordinates_never_construct_a_deletable_slot() {
    for (ifindex, protocol, priority, handle) in [
        (0, 3, 60, 1),
        (u32::MAX, 3, 60, 1),
        (7, 0, 60, 1),
        (7, 3, 0, 1),
        (7, 3, 60, 0),
    ] {
        assert!(TcSlot::new(ifindex, TcHook::Egress, 0, protocol, priority, handle).is_err());
    }
}

#[test]
fn classifier_creation_is_exclusive_direct_action_and_skips_hardware() {
    let slot = TcSlot::new(7, TcHook::Egress, 0, 3, 60, 1).unwrap();
    let request = wire::classifier_request(slot, 123, "program", 9, 77).unwrap();
    assert_eq!(&request[4..6], &44_u16.to_ne_bytes());
    assert_eq!(&request[6..8], &0x605_u16.to_ne_bytes());
    for expected in [
        attr(6, &123_i32.to_ne_bytes()),
        attr(7, b"program\0"),
        attr(8, &1_u32.to_ne_bytes()),
        attr(9, &1_u32.to_ne_bytes()),
    ] {
        assert!(request.windows(expected.len()).any(|part| part == expected));
    }
    assert!(wire::classifier_request(slot, -1, "program", 9, 77).is_err());
    assert!(wire::classifier_request(slot, 123, "bad\0name", 9, 77).is_err());
}

pub(super) fn gact_filter(
    verdict: u32,
    counter: u64,
    extra: Option<(u16, Vec<u8>)>,
    hardware: u32,
    bind_count: u32,
) -> Vec<u8> {
    let mut parameters = Vec::new();
    for word in [17_u32, 0, verdict, 1, bind_count] {
        parameters.extend(word.to_ne_bytes());
    }
    let mut options = attr(2, &parameters);
    options.extend(attr(1, &[counter.to_ne_bytes(); 4].concat()));
    if let Some((key, value)) = extra {
        options.extend(attr(key, &value));
    }
    let action = [
        attr(1, b"gact\0"),
        attr(2, &options),
        attr(6, &[0x55; 16]),
        attr(7, &[2_u32.to_ne_bytes(), 2_u32.to_ne_bytes()].concat()),
        attr(10, &0_u32.to_ne_bytes()),
    ]
    .concat();
    let mut body = filter(0, 3, 0)[16..36].to_vec();
    body[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    body.extend(attr(1, b"matchall\0"));
    body.extend(attr(11, &0_u32.to_ne_bytes()));
    body.extend(attr(
        2,
        &[
            attr(2, &attr(1, &action)),
            attr(3, &hardware.to_ne_bytes()),
            attr(4, &counter.to_ne_bytes()),
        ]
        .concat(),
    ));
    message(44, 2, &body)
}

fn parsed(bytes: &[u8]) -> Vec<wire::Entry> {
    let mut parser = dump();
    parser.consume(bytes).unwrap();
    parser.consume(&done()).unwrap();
    parser.finish().unwrap()
}

#[test]
fn matchall_gact_requires_cookie_terminal_action_and_software_execution() {
    for (verdict, expected) in [(0, TcVerdict::Pass), (2, TcVerdict::Drop)] {
        let items = parsed(&gact_filter(verdict, 1, None, 9, 1));
        let identity = items[0].gact.as_ref().expect("one understood gact action");
        assert_eq!(identity.verdict(), expected);
        assert_eq!(identity.cookie(), &[0x55; 16]);
        assert_eq!(identity.action_index(), 17);
    }
    for bytes in [
        gact_filter(3, 1, None, 9, 1),
        gact_filter(2, 1, Some((3, vec![0; 8])), 9, 1),
        gact_filter(2, 1, None, 10, 1),
        gact_filter(2, 1, None, 5, 1),
        gact_filter(2, 1, None, 9, 2),
    ] {
        assert!(parsed(&bytes)[0].gact.is_none());
    }
}

#[test]
fn runtime_counters_do_not_change_gact_identity_but_action_configuration_does() {
    let first = parsed(&gact_filter(2, 1, None, 9, 1));
    let later = parsed(&gact_filter(2, 90, None, 9, 1));
    assert_eq!(first, later);
    let different = parsed(&gact_filter(0, 90, None, 9, 1));
    assert_ne!(later, different);
}

#[test]
fn gact_create_is_exclusive_software_only_and_never_reuses_an_action_index() {
    let slot = TcSlot::new(7, TcHook::Egress, 0, 3, 5, 1).unwrap();
    let bytes = wire::gact_request(slot, [0x55; 16], TcVerdict::Drop, 9, 77).unwrap();
    assert_eq!(&bytes[4..6], &44_u16.to_ne_bytes());
    assert_eq!(&bytes[6..8], &0x605_u16.to_ne_bytes());
    assert!(bytes
        .windows(8)
        .any(|value| value == attr(3, &1_u32.to_ne_bytes())));
    let parameters = attr(
        2,
        &[
            0_u32.to_ne_bytes(),
            0_u32.to_ne_bytes(),
            2_u32.to_ne_bytes(),
            0_u32.to_ne_bytes(),
            0_u32.to_ne_bytes(),
        ]
        .concat(),
    );
    assert!(bytes
        .windows(parameters.len())
        .any(|value| value == parameters));
    let cookie = attr(6, &[0x55; 16]);
    assert!(bytes.windows(cookie.len()).any(|value| value == cookie));
}

#[derive(Debug)]
enum Reply {
    Dump(Vec<Vec<u8>>),
    Ack,
    Lost,
    ReceiveError(io::ErrorKind),
    SendError,
    WrongSequence,
}

type Sent = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;
struct FakeNetlink {
    replies: Arc<std::sync::Mutex<std::collections::VecDeque<Reply>>>,
    pending: std::collections::VecDeque<Vec<u8>>,
    receive_error: Option<io::ErrorKind>,
    sent: Sent,
}
impl Transport for FakeNetlink {
    fn port_id(&self) -> u32 {
        77
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.sent.lock().unwrap().push(bytes.to_vec());
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected kernel request");
        let send_error = matches!(reply, Reply::SendError);
        let wrong_sequence = matches!(reply, Reply::WrongSequence);
        let mut replies = match reply {
            Reply::Dump(messages) => messages,
            Reply::Ack => vec![message(
                2,
                0,
                &[0_i32.to_ne_bytes().as_slice(), &bytes[..16]].concat(),
            )],
            Reply::Lost => Vec::new(),
            Reply::ReceiveError(error) => {
                self.receive_error = Some(error);
                vec![done()]
            }
            Reply::SendError => vec![done()],
            Reply::WrongSequence => vec![done(), done()],
        };
        for message in &mut replies {
            message[8..16].copy_from_slice(&bytes[8..16]);
        }
        if wrong_sequence {
            replies[0][8] ^= 1;
        }
        self.pending.extend(replies);
        if send_error {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
    fn receive(&mut self, buffer: &mut [u8], _deadline: Instant) -> io::Result<usize> {
        if let Some(error) = self.receive_error.take() {
            return Err(error.into());
        }
        let Some(bytes) = self.pending.pop_front() else {
            return Err(io::ErrorKind::TimedOut.into());
        };
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

fn client(replies: Vec<Reply>) -> (TcClient, Sent) {
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let replies = Arc::new(std::sync::Mutex::new(replies.into()));
    let requests = Arc::clone(&sent);
    let mut open_transport: OpenTransport = Box::new(move || {
        Ok(Box::new(FakeNetlink {
            replies: Arc::clone(&replies),
            pending: Default::default(),
            receive_error: None,
            sent: Arc::clone(&requests),
        }))
    });
    (
        TcClient {
            transport: Some(open_transport().unwrap()),
            open_transport,
            sequence: 0,
            attempt_deadline: None,
            origin: Arc::new(()),
        },
        sent,
    )
}
fn inventory(mut messages: Vec<Vec<u8>>) -> Reply {
    messages.push(done());
    Reply::Dump(messages)
}

#[test]
fn failed_exchange_discards_queued_stale_replies_before_retry() {
    for fault in [
        Reply::ReceiveError(io::ErrorKind::TimedOut),
        Reply::ReceiveError(io::ErrorKind::ConnectionReset),
        Reply::SendError,
        Reply::WrongSequence,
        Reply::Dump(vec![message(99, 2, &[]), done()]),
    ] {
        let (mut tc, sent) = client(vec![fault, inventory(vec![filter(1, 3, 0)])]);
        assert!(tc.dump(7, TcHook::Egress).is_err());
        let fresh = tc
            .dump(7, TcHook::Egress)
            .expect("retry must use a fresh socket");
        assert_eq!(fresh.entries().len(), 1);
        assert_eq!(sent.lock().unwrap().len(), 2);
    }
}

#[test]
fn failed_topology_exchange_does_not_poison_filter_dump() {
    for operation in 0..3 {
        let (mut tc, _) = client(vec![
            Reply::ReceiveError(io::ErrorKind::TimedOut),
            inventory(vec![]),
        ]);
        let failed = match operation {
            0 => topology::inspect_link(&mut tc, 7).map(|_| ()),
            1 => topology::inspect_qdisc(&mut tc, 7).map(|_| ()),
            _ => topology::ensure_clsact(&mut tc, 7),
        };
        assert!(failed.is_err());
        assert!(tc.dump(7, TcHook::Egress).unwrap().entries().is_empty());
    }
}

#[test]
fn reopening_can_fail_and_retry_without_losing_same_client_identity() {
    let ours = filter(1, 3, 0);
    let (mut tc, _) = client(vec![
        inventory(vec![ours.clone()]),
        Reply::ReceiveError(io::ErrorKind::TimedOut),
        inventory(vec![ours]),
        Reply::Ack,
        inventory(vec![]),
    ]);
    let original = tc.dump(7, TcHook::Egress).unwrap();
    assert!(tc.dump(7, TcHook::Egress).is_err());
    let mut reopen = std::mem::replace(&mut tc.open_transport, Box::new(|| unreachable!()));
    let mut failed = false;
    tc.open_transport = Box::new(move || {
        if !failed {
            failed = true;
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            reopen()
        }
    });
    assert_eq!(
        tc.dump(7, TcHook::Egress).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    // The receipt still belongs to this client after recovery, and deletion
    // must obtain a complete fresh inventory before using it.
    tc.delete_exact(&original.entries()[0]).unwrap();
}

#[test]
fn lost_filter_ack_reopens_before_reconciliation() {
    let (mut tc, _) = client(vec![
        Reply::ReceiveError(io::ErrorKind::TimedOut),
        inventory(vec![gact_filter(2, 0, None, 9, 1)]),
    ]);
    let slot = TcSlot::new(7, TcHook::Egress, 0, 3, 60, 1).unwrap();
    assert!(tc.create_gact(slot, [0x55; 16], TcVerdict::Drop).is_err());
    let current = tc.dump(7, TcHook::Egress).unwrap();
    assert_eq!(
        current.find(slot).unwrap().gact().unwrap().verdict(),
        TcVerdict::Drop
    );
}

#[test]
fn legacy_ingress_on_an_unhooked_interface_does_not_refuse_our_qdisc() {
    // Review regression probe: the qdisc dump covers the whole namespace,
    // but only the requested interface belongs to this observation.
    let qdisc = |index: u32, kind: &[u8]| {
        let mut body = vec![0; 20];
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&0xffff0000_u32.to_ne_bytes());
        body[12..16].copy_from_slice(&0xfffffff1_u32.to_ne_bytes());
        body.extend(attr(1, kind));
        message(36, 2, &body)
    };
    let (mut tc, _) = client(vec![inventory(vec![
        qdisc(8, b"ingress\0"),
        qdisc(7, b"clsact\0"),
    ])]);
    assert_eq!(
        topology::inspect_qdisc(&mut tc, 7).unwrap(),
        (true, false, false)
    );
}

#[test]
fn qdisc_inventory_scopes_namespace_wide_dumps_to_the_requested_device() {
    let qdisc = |index: u32, extra: Vec<u8>| {
        let mut body = vec![0; 20];
        body[4..8].copy_from_slice(&index.to_ne_bytes());
        body[8..12].copy_from_slice(&0xffff0000_u32.to_ne_bytes());
        body[12..16].copy_from_slice(&0xfffffff1_u32.to_ne_bytes());
        body.extend(attr(1, b"clsact\0"));
        body.extend(extra);
        message(36, 2, &body)
    };
    let (mut tc, _) = client(vec![inventory(vec![
        qdisc(8, [attr(13, &1_u32.to_ne_bytes()), attr(12, &[1])].concat()),
        qdisc(7, vec![]),
    ])]);
    assert_eq!(
        super::topology::inspect_qdisc(&mut tc, 7).unwrap(),
        (true, false, false)
    );
}

#[test]
fn real_driver_rechecks_deletes_one_handle_and_confirms_absence() {
    let ours = filter(1, 3, 0);
    let neighbor = filter(2, 3, 0);
    let (mut tc, sent) = client(vec![
        inventory(vec![ours.clone(), neighbor.clone()]),
        inventory(vec![ours, neighbor.clone()]),
        Reply::Ack,
        inventory(vec![neighbor]),
    ]);
    let original = tc.dump(7, TcHook::Egress).unwrap();
    tc.delete_exact(&original.entries()[0]).unwrap();
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 4);
    assert_eq!(&sent[2][4..6], &45_u16.to_ne_bytes());
    assert_eq!(&sent[2][24..28], &1_u32.to_ne_bytes());
    // Dump requests cannot silently restrict to one priority or one chain.
    for request in [&sent[0], &sent[1], &sent[3]] {
        assert_eq!(request.len(), 36);
        assert_eq!(&request[32..36], &[0; 4]);
    }
}

#[test]
fn changed_occupant_or_incomplete_recheck_causes_no_deletion() {
    let old = filter(1, 3, 0);
    let mut replacement = old.clone();
    let index = replacement
        .windows(8)
        .position(|v| v == attr(11, &42_u32.to_ne_bytes()))
        .unwrap();
    replacement[index + 4..index + 8].copy_from_slice(&43_u32.to_ne_bytes());
    for recheck in [inventory(vec![replacement]), Reply::Dump(vec![old.clone()])] {
        let (mut tc, sent) = client(vec![inventory(vec![old.clone()]), recheck]);
        let original = tc.dump(7, TcHook::Egress).unwrap();
        assert!(tc.delete_exact(&original.entries()[0]).is_err());
        assert_eq!(sent.lock().unwrap().len(), 2);
    }
}

#[test]
fn lost_ack_or_surviving_occupant_cannot_prove_deletion() {
    for (ack, post, requests) in [
        (Reply::Lost, None, 3),
        (Reply::Ack, Some(inventory(vec![filter(1, 3, 0)])), 4),
    ] {
        let mut replies = vec![
            inventory(vec![filter(1, 3, 0)]),
            inventory(vec![filter(1, 3, 0)]),
            ack,
        ];
        replies.extend(post);
        let (mut tc, sent) = client(replies);
        let original = tc.dump(7, TcHook::Egress).unwrap();
        assert!(tc.delete_exact(&original.entries()[0]).is_err());
        assert_eq!(sent.lock().unwrap().len(), requests);
    }
}

#[test]
fn identities_cannot_cross_clients_and_summaries_cannot_delete() {
    let (mut tc, sent) = client(vec![inventory(vec![filter(0, 3, 0), filter(1, 3, 0)])]);
    let original = tc.dump(7, TcHook::Egress).unwrap();
    assert!(tc.delete_exact(&original.entries()[0]).is_err());
    assert_eq!(sent.lock().unwrap().len(), 1);
    let (mut other, other_sent) = client(Vec::new());
    assert!(other.delete_exact(&original.entries()[1]).is_err());
    assert!(other_sent.lock().unwrap().is_empty());
}

#[test]
fn ack_requires_exact_request_correlation_and_no_extra_messages() {
    let request = wire::delete_request(
        TcSlot::new(7, TcHook::Egress, 0, 3, 60, 1).unwrap(),
        b"bpf",
        9,
        77,
    )
    .unwrap();
    let valid = message(
        2,
        0,
        &[0_i32.to_ne_bytes().as_slice(), &request[..16]].concat(),
    );
    wire::ack(&valid, &request).unwrap();
    for offset in [0, 4, 6, 8, 12, 16, 20, 24, 28, 32] {
        let mut bytes = valid.clone();
        bytes[offset] ^= 1;
        assert!(wire::ack(&bytes, &request).is_err(), "offset {offset}");
    }
    assert!(wire::ack(&[valid.clone(), valid].concat(), &request).is_err());
}

#[test]
fn failed_dump_is_poisoned_and_bounded() {
    let mut parser = dump();
    let mut wrong = done();
    wrong[8] ^= 1;
    assert!(parser.consume(&wrong).is_err());
    assert!(parser.consume(&done()).is_err());
    assert!(parser.finish().is_err());
    let mut parser = dump();
    for handle in 1..=4096 {
        parser.consume(&filter(handle, 3, 0)).unwrap();
    }
    assert!(parser.consume(&filter(4097, 3, 0)).is_err());
    assert!(parser.finish().is_err());
}

#[test]
fn create_driver_requires_full_cookie_and_action_readback() {
    let slot = TcSlot::new(7, TcHook::Egress, 0, 3, 60, 1).unwrap();
    let actual = gact_filter(2, 0, None, 9, 1);
    let (mut tc, _) = client(vec![Reply::Ack, inventory(vec![actual.clone()])]);
    let installed = tc.create_gact(slot, [0x55; 16], TcVerdict::Drop).unwrap();
    assert_eq!(installed.gact().unwrap().action_index(), 17);
    for (cookie, verdict) in [([0x56; 16], TcVerdict::Drop), ([0x55; 16], TcVerdict::Pass)] {
        let (mut tc, _) = client(vec![Reply::Ack, inventory(vec![actual.clone()])]);
        assert!(tc.create_gact(slot, cookie, verdict).is_err());
    }
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
#[test]
#[ignore = "requires explicit private-netns root qualification"]
fn private_netns_gact_round_trip_preserves_foreign_filter() {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
        std::fs::metadata("/proc/1/ns/net").unwrap().ino()
    );
    assert!(std::process::Command::new("tc")
        .args(["qdisc", "add", "dev", "lo", "clsact"])
        .status()
        .unwrap()
        .success());
    let mut tc = TcClient::new().unwrap();
    assert!(tc.dump(1, TcHook::Egress).unwrap().entries().is_empty());
    let slot = TcSlot::new(1, TcHook::Egress, 0, 3, 7, 1).unwrap();
    let neighbor_slot = TcSlot::new(1, TcHook::Egress, 0, 3, 8, 1).unwrap();
    let neighbor = tc
        .create_gact(neighbor_slot, [0x66; 16], TcVerdict::Pass)
        .unwrap();
    let exact = tc.create_gact(slot, [0x55; 16], TcVerdict::Drop).unwrap();
    tc.delete_exact(&exact).unwrap();
    let after = tc.dump(1, TcHook::Egress).unwrap();
    assert!(after.find(slot).is_none());
    assert_eq!(after.find(neighbor_slot).unwrap().gact(), neighbor.gact());
    tc.delete_exact(&neighbor).unwrap();
    assert!(tc.dump(1, TcHook::Egress).unwrap().entries().is_empty());
}

#[test]
fn expired_attempt_admits_no_new_netlink_request() {
    let (mut tc, sent) = client(Vec::new());
    tc.attempt_deadline = Some(Instant::now());
    let error = tc.dump(7, TcHook::Egress).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn abandoned_multipart_reply_does_not_poison_later_exchanges() {
    // Regression probe: an early parse error leaves DONE queued on the old
    // transport. Reopening discards that queue before the next request.
    let (mut tc, _) = client(vec![
        Reply::Dump(vec![filter(1, 3, 0), done()]),
        inventory(vec![]),
        inventory(vec![]),
    ]);
    assert!(tc.dump(8, TcHook::Egress).is_err());
    assert!(tc.dump(7, TcHook::Egress).is_ok());
    assert!(tc.dump(7, TcHook::Egress).is_ok());
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
#[test]
fn late_kernel_reply_causes_one_refusal_then_scope_client_recovers() {
    // Native regression probe, requiring no privilege: deliberately abandon a
    // loopback dump after sending it. A mismatch refuses this exchange and
    // discards the socket; the same client must recover for all later work.
    let mut tc = TcClient::new().unwrap();
    tc.dump(1, TcHook::Egress).unwrap();
    let sequence = tc.next_sequence().unwrap();
    let transport = tc.transport.as_mut().unwrap();
    let port = transport.port_id();
    transport
        .send(&wire::dump_request(1, TcHook::Egress, sequence, port).unwrap())
        .unwrap();
    assert_eq!(
        tc.dump(1, TcHook::Egress).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(tc.transport.is_none());
    for exchange in 0..50 {
        tc.dump(1, TcHook::Egress)
            .unwrap_or_else(|error| panic!("exchange {exchange}: {error}"));
    }
    for _ in 0..2 {
        super::topology::inspect_link(&mut tc, 1).unwrap();
    }
}
