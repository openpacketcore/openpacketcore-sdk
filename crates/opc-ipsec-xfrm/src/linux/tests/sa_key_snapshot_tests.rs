//! Key-scoped SA snapshots: `XFRM_MSG_GETSA` dump encoding, multipart
//! parsing, interrupted-dump retry, key filtering, and exact removal.

use super::*;

const SEQUENCE: u32 = 7;
const KEY_SPI: u32 = 0x1234_5678;
const AF_INET_WIRE: u16 = 2;
const AF_INET6_WIRE: u16 = 10;
const LINUX_EPERM: i32 = 1;

fn dump_config() -> LinuxXfrmBackendConfig {
    LinuxXfrmBackendConfig {
        receive_attempts: 2,
        receive_buffer_len: 16 * 1024,
        retry_delay: Duration::ZERO,
    }
}

/// The marked SA a consumer owns at the key.
fn marked_sa() -> SaParameters {
    let mut parameters = relocation_parameters();
    parameters.id.spi = KEY_SPI;
    parameters.mark = Some(XfrmLookupMark::full(0x42));
    parameters
}

/// An unmarked SA at the same key, which answers every lookup mark.
fn unmarked_sa() -> SaParameters {
    let mut parameters = marked_sa();
    parameters.mark = None;
    parameters.request_id = XfrmRequestId::new(0x0909);
    parameters
}

/// A marked SA at the same key whose full-mask value is disjoint.
fn disjoint_sa() -> SaParameters {
    let mut parameters = marked_sa();
    parameters.mark = Some(XfrmLookupMark::full(0x43));
    parameters
}

fn key() -> SaLookupKey {
    SaLookupKey::from(marked_sa().id)
}

fn identity(parameters: &SaParameters) -> SaRelocationIdentity {
    test_sa_relocation_readback(parameters).unwrap().1
}

fn sa_body(parameters: &SaParameters) -> Vec<u8> {
    encode_sa_info(parameters).unwrap().to_vec()
}

/// One netlink message, zero-padded to the 4-byte boundary as the kernel
/// places messages in a datagram. The length field stays unpadded.
fn message(message_type: u16, flags: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut message = encode_netlink_message(message_type, flags, sequence, body)
        .unwrap()
        .to_vec();
    message.resize(align_to_netlink(message.len()).unwrap(), 0);
    message
}

fn member(sequence: u32, body: &[u8]) -> Vec<u8> {
    message(XFRM_MSG_NEWSA, NLM_F_MULTI, sequence, body)
}

fn done(sequence: u32, status: i32) -> Vec<u8> {
    message(NLMSG_DONE, NLM_F_MULTI, sequence, &status.to_ne_bytes())
}

fn datagram(messages: &[Vec<u8>]) -> Vec<u8> {
    messages.concat()
}

/// A message whose sequence the scripted transport fills in at dump time.
#[derive(Debug, Clone)]
struct Scripted {
    message_type: u16,
    flags: u16,
    sequence: Option<u32>,
    body: Vec<u8>,
}

impl Scripted {
    fn member(body: Vec<u8>) -> Self {
        Self {
            message_type: XFRM_MSG_NEWSA,
            flags: NLM_F_MULTI,
            sequence: None,
            body,
        }
    }

    fn done() -> Self {
        Self {
            message_type: NLMSG_DONE,
            flags: NLM_F_MULTI,
            sequence: None,
            body: 0_i32.to_ne_bytes().to_vec(),
        }
    }

    fn interrupted(mut self) -> Self {
        self.flags |= NLM_F_DUMP_INTR;
        self
    }

    fn render(&self, sequence: u32) -> Vec<u8> {
        message(
            self.message_type,
            self.flags,
            self.sequence.unwrap_or(sequence),
            &self.body,
        )
    }
}

type ScriptedDump = Vec<Vec<Scripted>>;
/// A dump request and the sequence it was sent with.
type DumpRequest = (Vec<u8>, u32);
/// A non-dump request and its operation label.
type Transaction = (&'static str, Vec<u8>);

/// Transport that answers each dump request with the next scripted dump and
/// records every request.
#[derive(Debug, Clone, Default)]
struct DumpTransport {
    dumps: Arc<Mutex<VecDeque<ScriptedDump>>>,
    dump_requests: Arc<Mutex<Vec<DumpRequest>>>,
    transactions: Arc<Mutex<Vec<Transaction>>>,
}

impl DumpTransport {
    fn new(dumps: Vec<ScriptedDump>) -> Self {
        Self {
            dumps: Arc::new(Mutex::new(dumps.into())),
            ..Self::default()
        }
    }

    fn dump_requests(&self) -> Vec<DumpRequest> {
        self.dump_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn transactions(&self) -> Vec<Transaction> {
        self.transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl LinuxXfrmTransport for DumpTransport {
    fn transact(
        &self,
        operation: &'static str,
        _operation_class: NetlinkOperationClass,
        request: &[u8],
        _expected_sequence: u32,
        _config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        self.transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((operation, request.to_vec()));
        Ok(None)
    }

    fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
        XfrmProbe::unsupported()
    }

    fn dump(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        reply_message_type: u16,
        _config: LinuxXfrmBackendConfig,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), XfrmError>,
    ) -> Result<NetlinkDumpCompletion, XfrmError> {
        self.dump_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((request.to_vec(), expected_sequence));
        let script = self
            .dumps
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or_default();
        let mut datagrams: VecDeque<Vec<u8>> = script
            .iter()
            .map(|messages| {
                messages
                    .iter()
                    .flat_map(|message| message.render(expected_sequence))
                    .collect()
            })
            .collect();
        receive_netlink_dump(
            operation,
            expected_sequence,
            reply_message_type,
            dump_config(),
            |buffer| deliver(&mut datagrams, buffer),
            visit,
        )
    }
}

fn deliver(
    datagrams: &mut VecDeque<Vec<u8>>,
    buffer: &mut [u8],
) -> io::Result<ReceiveMessageOutcome> {
    let Some(datagram) = datagrams.pop_front() else {
        return Err(io::Error::from(io::ErrorKind::WouldBlock));
    };
    if datagram.len() > buffer.len() {
        return Ok(ReceiveMessageOutcome::ConsumedOversize {
            buffer_bytes: buffer.len(),
            datagram_bytes: datagram.len(),
        });
    }
    buffer[..datagram.len()].copy_from_slice(&datagram);
    Ok(ReceiveMessageOutcome::Complete {
        bytes_received: datagram.len(),
    })
}

/// Run the dump parser over raw datagrams and collect the visited bodies.
fn run_dump(datagrams: Vec<Vec<u8>>) -> (Result<NetlinkDumpCompletion, XfrmError>, Vec<Vec<u8>>) {
    let mut datagrams: VecDeque<_> = datagrams.into();
    let mut visited = Vec::new();
    let result = receive_netlink_dump(
        SA_KEY_SNAPSHOT,
        SEQUENCE,
        XFRM_MSG_NEWSA,
        dump_config(),
        |buffer| deliver(&mut datagrams, buffer),
        &mut |body| {
            visited.push(body.to_vec());
            Ok(())
        },
    );
    (result, visited)
}

fn assert_malformed(result: Result<NetlinkDumpCompletion, XfrmError>) {
    assert!(
        matches!(
            result,
            Err(XfrmError::Io {
                operation: SA_KEY_SNAPSHOT,
                kind: io::ErrorKind::InvalidData,
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn key_dump_request_is_an_attribute_only_getsa_dump_with_kernel_filters() {
    for (destination, family, prefix_len, address) in [
        (
            IpAddress::Ipv4([192, 0, 2, 20]),
            AF_INET_WIRE,
            32_u8,
            [&[192, 0, 2, 20][..], &[0; 12][..]].concat(),
        ),
        (
            IpAddress::Ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
            ]),
            AF_INET6_WIRE,
            128_u8,
            vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
            ],
        ),
    ] {
        let transport = DumpTransport::new(vec![vec![vec![Scripted::done()]]]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        let snapshot = backend
            .query_sa_key_snapshot(SaLookupKey::new(destination, 50, KEY_SPI))
            .await
            .unwrap();
        assert!(snapshot.is_empty());

        let requests = transport.dump_requests();
        assert_eq!(requests.len(), 1);
        let (request, sequence) = &requests[0];
        assert_eq!(netlink_message_type(request), XFRM_MSG_GETSA);
        // A dump never asks for an ACK: Linux sends none for a started dump.
        assert_eq!(
            u16::from_ne_bytes([request[6], request[7]]),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(
            u32::from_ne_bytes(request[8..12].try_into().unwrap()),
            *sequence
        );
        assert_eq!(
            netlink_operation_class(netlink_message_type(request)),
            NetlinkOperationClass::ReadOnly
        );

        // The body is attributes only: `xfrm_dump_sa` parses from offset 0.
        let body = netlink_body(request);
        let filter = route_attr_payload_from(body, 0, XFRMA_ADDRESS_FILTER).unwrap();
        assert_eq!(filter.len(), XFRM_ADDRESS_FILTER_LEN);
        assert_eq!(
            filter.len(),
            size_of::<opc_linux_xfrm_sys::XfrmAddressFilter>()
        );
        assert_eq!(&filter[..16], &[0; 16], "any outer source");
        assert_eq!(&filter[16..32], address.as_slice());
        assert_eq!(u16::from_ne_bytes([filter[32], filter[33]]), family);
        assert_eq!(filter[34], 0, "zero source prefix length");
        assert_eq!(filter[35], prefix_len, "exact destination");
        assert_eq!(
            route_attr_payload_from(body, 0, XFRMA_PROTO),
            Some(&[50][..])
        );
        assert_eq!(body.len(), 40 + 8);
    }
}

#[test]
fn dump_reads_multipart_datagrams_until_done() {
    let (marked, unmarked, disjoint) = (
        sa_body(&marked_sa()),
        sa_body(&unmarked_sa()),
        sa_body(&disjoint_sa()),
    );
    let (result, visited) = run_dump(vec![
        datagram(&[member(SEQUENCE, &marked), member(SEQUENCE, &unmarked)]),
        datagram(&[member(SEQUENCE, &disjoint)]),
        datagram(&[done(SEQUENCE, 0)]),
    ]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Complete);
    assert_eq!(visited, vec![marked, unmarked, disjoint]);

    // The completion may share the final member datagram.
    let body = sa_body(&marked_sa());
    let (result, visited) = run_dump(vec![datagram(&[
        member(SEQUENCE, &body),
        done(SEQUENCE, 0),
    ])]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Complete);
    assert_eq!(visited, vec![body]);

    // An empty dump is only a completion.
    let (result, visited) = run_dump(vec![done(SEQUENCE, 0)]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Complete);
    assert!(visited.is_empty());
}

#[test]
fn dump_ignores_noop_messages_and_non_kernel_datagrams() {
    let body = sa_body(&marked_sa());
    let mut datagrams: VecDeque<Result<ReceiveMessageOutcome, Vec<u8>>> = VecDeque::from([
        Ok(ReceiveMessageOutcome::RejectedNonKernel),
        Err(datagram(&[
            message(NLMSG_NOOP, NLM_F_MULTI, SEQUENCE, &[]),
            member(SEQUENCE, &body),
        ])),
        Ok(ReceiveMessageOutcome::RejectedNonKernel),
        Err(done(SEQUENCE, 0)),
    ]);
    let mut visited = 0;
    let result = receive_netlink_dump(
        SA_KEY_SNAPSHOT,
        SEQUENCE,
        XFRM_MSG_NEWSA,
        dump_config(),
        |buffer| match datagrams.pop_front() {
            Some(Ok(outcome)) => Ok(outcome),
            Some(Err(bytes)) => deliver(&mut VecDeque::from([bytes]), buffer),
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        },
        &mut |_| {
            visited += 1;
            Ok(())
        },
    );
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Complete);
    assert_eq!(visited, 1);
}

#[test]
fn dump_without_done_is_never_complete() {
    let body = sa_body(&marked_sa());
    let (result, visited) = run_dump(vec![member(SEQUENCE, &body)]);
    assert!(
        matches!(
            result,
            Err(XfrmError::StateIndeterminate {
                operation: SA_KEY_SNAPSHOT
            })
        ),
        "{result:?}"
    );
    // The visitor saw the member, but the caller gets no snapshot.
    assert_eq!(visited.len(), 1);
}

#[test]
fn dump_intr_or_overrun_interrupts_the_whole_dump() {
    let body = sa_body(&marked_sa());
    let mut interrupted_member = member(SEQUENCE, &body);
    interrupted_member[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());
    let mut interrupted_done = done(SEQUENCE, 0);
    interrupted_done[6..8].copy_from_slice(&(NLM_F_MULTI | NLM_F_DUMP_INTR).to_ne_bytes());

    // The flagged member is not visited, nor is anything after it.
    let (result, visited) = run_dump(vec![
        datagram(&[interrupted_member.clone(), member(SEQUENCE, &body)]),
        done(SEQUENCE, 0),
    ]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Interrupted);
    assert!(visited.is_empty());

    // A flag on a later batch interrupts a dump whose first batch was clean.
    let (result, visited) = run_dump(vec![
        member(SEQUENCE, &body),
        datagram(&[interrupted_member]),
        done(SEQUENCE, 0),
    ]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Interrupted);
    assert_eq!(visited.len(), 1);

    // The flag on the completion itself is enough.
    let (result, _) = run_dump(vec![datagram(&[member(SEQUENCE, &body), interrupted_done])]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Interrupted);

    let (result, _) = run_dump(vec![
        datagram(&[
            member(SEQUENCE, &body),
            message(NLMSG_OVERRUN, NLM_F_MULTI, SEQUENCE, &[]),
        ]),
        done(SEQUENCE, 0),
    ]);
    assert_eq!(result.unwrap(), NetlinkDumpCompletion::Interrupted);
}

#[test]
fn dump_error_reply_and_failed_completion_are_typed_errors() {
    // A dump the kernel refuses to start, for example without CAP_NET_ADMIN.
    let (result, _) = run_dump(vec![message(
        NLMSG_ERROR,
        0,
        SEQUENCE,
        &[(-LINUX_EPERM).to_ne_bytes().as_slice(), &[0; 16]].concat(),
    )]);
    assert!(
        matches!(
            result,
            Err(XfrmError::Io {
                operation: SA_KEY_SNAPSHOT,
                kind: io::ErrorKind::PermissionDenied,
                raw_os_error: Some(LINUX_EPERM),
            })
        ),
        "{result:?}"
    );

    // A dump callback that fails reports its errno in the completion.
    let (result, _) = run_dump(vec![
        member(SEQUENCE, &sa_body(&marked_sa())),
        done(SEQUENCE, -LINUX_EINVAL),
    ]);
    assert!(
        matches!(
            result,
            Err(XfrmError::Io {
                operation: SA_KEY_SNAPSHOT,
                raw_os_error: Some(LINUX_EINVAL),
                ..
            })
        ),
        "{result:?}"
    );

    // A bare acknowledgement and a positive status are not dump replies.
    assert_malformed(run_dump(vec![message(NLMSG_ERROR, 0, SEQUENCE, &[0; 20])]).0);
    assert_malformed(run_dump(vec![done(SEQUENCE, 1)]).0);
    assert_malformed(run_dump(vec![message(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, &[0; 2])]).0);
}

#[test]
fn dump_rejects_malformed_and_foreign_messages() {
    let body = sa_body(&marked_sa());
    // Another request's reply.
    assert_malformed(run_dump(vec![member(SEQUENCE + 1, &body)]).0);
    // A member or completion outside a multipart reply.
    assert_malformed(run_dump(vec![message(XFRM_MSG_NEWSA, 0, SEQUENCE, &body)]).0);
    assert_malformed(run_dump(vec![message(NLMSG_DONE, 0, SEQUENCE, &0_i32.to_ne_bytes())]).0);
    // Another message type.
    assert_malformed(
        run_dump(vec![message(
            XFRM_MSG_NEWPOLICY,
            NLM_F_MULTI,
            SEQUENCE,
            &body,
        )])
        .0,
    );
    // A message after the completion in the same datagram.
    assert_malformed(
        run_dump(vec![datagram(&[
            done(SEQUENCE, 0),
            member(SEQUENCE, &body),
        ])])
        .0,
    );
    // A length that overruns the datagram, or undercuts the header.
    let mut overrun = member(SEQUENCE, &body);
    let length = u32::try_from(overrun.len() + 4).unwrap();
    overrun[..4].copy_from_slice(&length.to_ne_bytes());
    assert_malformed(run_dump(vec![overrun]).0);
    let mut undercut = member(SEQUENCE, &body);
    undercut[..4].copy_from_slice(&8_u32.to_ne_bytes());
    assert_malformed(run_dump(vec![undercut]).0);
    assert_malformed(run_dump(vec![vec![0; 8]]).0);
    // Nonzero padding between two messages.
    let mut short = message(NLMSG_NOOP, NLM_F_MULTI, SEQUENCE, &[0; 2]);
    assert_eq!(short.len(), 20);
    short[19] = 1;
    assert_malformed(run_dump(vec![datagram(&[short, done(SEQUENCE, 0)])]).0);
}

#[test]
fn oversized_dump_datagram_is_a_typed_read_error() {
    let mut datagrams = VecDeque::from([vec![0; 64]]);
    let result = receive_netlink_dump(
        SA_KEY_SNAPSHOT,
        SEQUENCE,
        XFRM_MSG_NEWSA,
        LinuxXfrmBackendConfig {
            receive_attempts: 2,
            receive_buffer_len: 32,
            retry_delay: Duration::ZERO,
        },
        |buffer| deliver(&mut datagrams, buffer),
        &mut |_| Ok(()),
    );
    assert!(
        matches!(
            result,
            Err(XfrmError::ResponseTooLarge {
                operation: SA_KEY_SNAPSHOT,
                buffer_bytes: 32,
                datagram_bytes: 64,
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn key_snapshot_keeps_exactly_the_states_lookup_compares_with_the_key() {
    let mut other_spi = marked_sa();
    other_spi.id.spi += 1;
    // A kernel that ignored XFRMA_ADDRESS_FILTER or XFRMA_PROTO.
    let mut other_destination = marked_sa();
    other_destination.id.destination = IpAddress::Ipv4([192, 0, 2, 21]);
    let mut other_protocol = sa_body(&marked_sa());
    other_protocol[XFRM_SPI_OFFSET_IN_SA_INFO + 4] = 51;
    // An IPv6 state whose destination begins with the IPv4 key's octets.
    let mut other_family = marked_sa();
    other_family.selector =
        XfrmSelector::new(IpAddress::Ipv6([0xfd; 16]), IpAddress::Ipv6([0xfe; 16]), 0);
    other_family.source_address = IpAddress::Ipv6([0xfd; 16]);
    let mut destination = [0_u8; 16];
    destination[..4].copy_from_slice(&[192, 0, 2, 20]);
    other_family.id.destination = IpAddress::Ipv6(destination);
    // `xfrm_addr_equal` compares four bytes for IPv4, so a state whose unused
    // address words are not zero is still at the key.
    let mut upper_words = sa_body(&unmarked_sa());
    upper_words[60..72].copy_from_slice(&[0xaa; 12]);

    let transport = DumpTransport::new(vec![vec![
        vec![
            Scripted::member(sa_body(&other_spi)),
            Scripted::member(sa_body(&marked_sa())),
            Scripted::member(sa_body(&other_destination)),
        ],
        vec![
            Scripted::member(other_protocol),
            Scripted::member(sa_body(&other_family)),
            Scripted::member(upper_words),
            Scripted::member(sa_body(&disjoint_sa())),
        ],
        vec![Scripted::done()],
    ]]);
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let snapshot = backend.query_sa_key_snapshot(key()).await.unwrap();

    assert_eq!(snapshot.key(), key());
    assert_eq!(
        snapshot.states(),
        &[
            identity(&marked_sa()),
            identity(&unmarked_sa()),
            identity(&disjoint_sa())
        ]
    );
    assert_eq!(transport.dump_requests().len(), 1);
    assert!(transport.transactions().is_empty());
}

#[tokio::test]
async fn key_snapshot_skips_unrepresentable_states_elsewhere_but_not_at_the_key() {
    let mut other_spi = marked_sa();
    other_spi.id.spi += 1;
    let mut broken_elsewhere = sa_body(&other_spi);
    broken_elsewhere.extend_from_slice(&[0xff; 3]);
    let transport = DumpTransport::new(vec![vec![vec![
        Scripted::member(broken_elsewhere),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]]]);
    let snapshot = LinuxXfrmBackend::with_transport(transport)
        .query_sa_key_snapshot(key())
        .await
        .unwrap();
    assert_eq!(snapshot.states(), &[identity(&marked_sa())]);

    // A state at the key with an unaddressable lookup mark fails the read
    // rather than vanishing from it.
    let mut noncanonical = sa_body(&unmarked_sa());
    append_attr(
        &mut noncanonical,
        XFRMA_MARK,
        &[0x11_u32.to_ne_bytes(), 0xf0_u32.to_ne_bytes()].concat(),
    )
    .unwrap();
    // So does a truncated member at any key.
    let short = sa_body(&marked_sa())[..XFRM_USER_SA_INFO_LEN - 1].to_vec();
    for body in [noncanonical, short] {
        let transport = DumpTransport::new(vec![vec![vec![
            Scripted::member(sa_body(&marked_sa())),
            Scripted::member(body),
            Scripted::done(),
        ]]]);
        let error = LinuxXfrmBackend::with_transport(transport)
            .query_sa_key_snapshot(key())
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                XfrmError::Io {
                    operation: SA_KEY_SNAPSHOT,
                    kind: io::ErrorKind::InvalidData,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn interrupted_dump_is_discarded_and_repeated_with_a_fresh_sequence() {
    let transport = DumpTransport::new(vec![
        vec![
            vec![Scripted::member(sa_body(&marked_sa()))],
            vec![Scripted::member(sa_body(&disjoint_sa())).interrupted()],
            vec![Scripted::done()],
        ],
        vec![vec![
            Scripted::member(sa_body(&unmarked_sa())),
            Scripted::done(),
        ]],
    ]);
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let snapshot = backend.query_sa_key_snapshot(key()).await.unwrap();

    // Nothing from the interrupted attempt survives.
    assert_eq!(snapshot.states(), &[identity(&unmarked_sa())]);
    let requests = transport.dump_requests();
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[0].1, requests[1].1);
    assert_eq!(netlink_body(&requests[0].0), netlink_body(&requests[1].0));
}

#[tokio::test]
async fn persistently_interrupted_dump_fails_closed_after_bounded_attempts() {
    let interrupted = || {
        vec![vec![
            Scripted::member(sa_body(&marked_sa())).interrupted(),
            Scripted::done(),
        ]]
    };
    let transport = DumpTransport::new(
        (0..SA_KEY_SNAPSHOT_DUMP_ATTEMPTS + 1)
            .map(|_| interrupted())
            .collect(),
    );
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .query_sa_key_snapshot(key())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: SA_KEY_SNAPSHOT
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        transport.dump_requests().len(),
        SA_KEY_SNAPSHOT_DUMP_ATTEMPTS
    );
}

#[tokio::test]
async fn key_snapshot_rejects_invalid_keys_before_any_request() {
    let transport = DumpTransport::new(Vec::new());
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let destination = marked_sa().id.destination;
    for (key, field) in [
        (SaLookupKey::new(destination, 50, 0), "sa_key.spi"),
        (
            SaLookupKey::new(destination, 17, KEY_SPI),
            "sa_key.protocol",
        ),
    ] {
        let error = backend.query_sa_key_snapshot(key).await.unwrap_err();
        assert!(
            matches!(error, XfrmError::InvalidConfig { field: observed, .. } if observed == field),
            "{error:?}"
        );
    }
    assert!(transport.dump_requests().is_empty());
}

#[tokio::test]
async fn exact_removal_refuses_marked_and_unmarked_overlap_without_delsa() {
    let transport = DumpTransport::new(vec![vec![vec![
        Scripted::member(sa_body(&unmarked_sa())),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]]]);
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: "remove_sa_exact_preflight"
            }
        ),
        "{error:?}"
    );
    assert_eq!(transport.dump_requests().len(), 1);
    assert!(transport.transactions().is_empty(), "no DELSA was sent");
}

#[tokio::test]
async fn exact_removal_deletes_the_sole_candidate_with_its_lookup_mark() {
    // The disjoint full-mask state is at the key but cannot answer the
    // marked lookup.
    let transport = DumpTransport::new(vec![vec![vec![
        Scripted::member(sa_body(&disjoint_sa())),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]]]);
    LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap();

    let transactions = transport.transactions();
    assert_eq!(transactions.len(), 1);
    let (operation, request) = &transactions[0];
    assert_eq!(*operation, "remove_sa_exact");
    assert_eq!(netlink_message_type(request), XFRM_MSG_DELSA);
    let sa = marked_sa();
    assert_eq!(
        netlink_body(request),
        encode_sa_id(sa.id.destination, sa.id.protocol, sa.id.spi, sa.mark)
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        route_attr_payload_from(netlink_body(request), XFRM_USER_SA_ID_LEN, XFRMA_MARK),
        Some(&[0x42_u32.to_ne_bytes(), u32::MAX.to_ne_bytes()].concat()[..])
    );
}

#[tokio::test]
async fn exact_removal_reports_absent_or_changed_states_without_delsa() {
    let mut changed = marked_sa();
    changed.request_id = XfrmRequestId::new(0x0a0a);
    for (states, expected) in [
        (Vec::new(), "not_found"),
        (vec![Scripted::member(sa_body(&changed))], "mismatch"),
        (vec![Scripted::member(sa_body(&unmarked_sa()))], "mismatch"),
    ] {
        let mut dump = states;
        dump.push(Scripted::done());
        let transport = DumpTransport::new(vec![vec![dump]]);
        let error = LinuxXfrmBackend::with_transport(transport.clone())
            .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
            .await
            .unwrap_err();
        match expected {
            "not_found" => assert!(matches!(error, XfrmError::NotFound), "{error:?}"),
            _ => assert!(
                matches!(
                    error,
                    XfrmError::StateMismatch {
                        operation: "remove_sa_exact_preflight"
                    }
                ),
                "{error:?}"
            ),
        }
        assert!(transport.transactions().is_empty(), "no DELSA was sent");
    }
}

#[tokio::test]
async fn exact_removal_without_a_complete_snapshot_sends_no_delsa() {
    let transport = DumpTransport::new(
        (0..SA_KEY_SNAPSHOT_DUMP_ATTEMPTS)
            .map(|_| vec![vec![Scripted::member(sa_body(&marked_sa())).interrupted()]])
            .collect(),
    );
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: "remove_sa_exact_preflight"
            }
        ),
        "{error:?}"
    );
    assert!(transport.transactions().is_empty());

    // A transport without dump support fails closed the same way.
    let transport = CapturingTransport::default();
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "sa_key_snapshot"
            }
        ),
        "{error:?}"
    );
    assert!(transport.requests().is_empty());
}
