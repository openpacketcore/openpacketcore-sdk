//! Key-scoped SA snapshots: the counted read (SAD count, unfiltered
//! `XFRM_MSG_GETSA` dump, SAD count) on one socket, multipart parsing,
//! interrupted and short dumps, key filtering, and exact removal.

use std::sync::atomic::AtomicUsize;

use super::*;

const SEQUENCE: u32 = 7;
const KEY_SPI: u32 = 0x1234_5678;
const LINUX_EPERM: i32 = 1;
/// `enum xfrm_sadattr_type_t` in `include/uapi/linux/xfrm.h`.
const XFRMA_SAD_HINFO: u16 = 2;

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

/// A non-dump request and its operation label.
type Transaction = (&'static str, Vec<u8>);

/// One counted read as the scripted kernel answers it.
#[derive(Debug, Clone, Default)]
struct ScriptedRead {
    /// SAD count before the dump; `None` reports the scripted members.
    count_before: Option<u32>,
    /// Dump datagrams, each a list of messages.
    dump: Vec<Vec<Scripted>>,
    /// SAD count after the dump; `None` reports the scripted members.
    count_after: Option<u32>,
}

impl ScriptedRead {
    /// A dump whose counts agree with it, as on a quiet kernel.
    fn dump(dump: Vec<Vec<Scripted>>) -> Self {
        Self {
            dump,
            ..Self::default()
        }
    }

    /// The same dump between explicit SAD counts.
    fn counted(mut self, before: u32, after: u32) -> Self {
        self.count_before = Some(before);
        self.count_after = Some(after);
        self
    }

    fn members(&self) -> u32 {
        let members = self
            .dump
            .iter()
            .flatten()
            .filter(|message| message.message_type == XFRM_MSG_NEWSA)
            .count();
        u32::try_from(members).unwrap()
    }
}

/// A request one session received.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionRequest {
    session: usize,
    message_type: u16,
    flags: u16,
    sequence: u32,
    body: Vec<u8>,
}

/// Transport whose sessions answer like the kernel: each session plays the
/// next scripted read. It records every session request and every
/// single-request transaction.
#[derive(Debug, Clone, Default)]
struct KernelTransport {
    reads: Arc<Mutex<VecDeque<ScriptedRead>>>,
    sessions: Arc<AtomicUsize>,
    session_requests: Arc<Mutex<Vec<SessionRequest>>>,
    transactions: Arc<Mutex<Vec<Transaction>>>,
}

impl KernelTransport {
    fn new(reads: Vec<ScriptedRead>) -> Self {
        Self {
            reads: Arc::new(Mutex::new(reads.into())),
            ..Self::default()
        }
    }

    fn sessions(&self) -> usize {
        self.sessions.load(Ordering::Acquire)
    }

    fn session_requests(&self) -> Vec<SessionRequest> {
        self.session_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn dump_requests(&self) -> Vec<SessionRequest> {
        self.session_requests()
            .into_iter()
            .filter(|request| request.message_type == XFRM_MSG_GETSA)
            .collect()
    }

    fn transactions(&self) -> Vec<Transaction> {
        self.transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl LinuxXfrmTransport for KernelTransport {
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

    fn open_session(
        &self,
        _operation: &'static str,
    ) -> Result<Box<dyn LinuxXfrmSession>, XfrmError> {
        let read = self
            .reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or_else(|| ScriptedRead::dump(vec![vec![Scripted::done()]]));
        Ok(Box::new(ScriptedSession {
            index: self.sessions.fetch_add(1, Ordering::AcqRel),
            read,
            counts_sent: 0,
            pending: VecDeque::new(),
            requests: Arc::clone(&self.session_requests),
        }))
    }
}

struct ScriptedSession {
    index: usize,
    read: ScriptedRead,
    counts_sent: usize,
    pending: VecDeque<Vec<u8>>,
    requests: Arc<Mutex<Vec<SessionRequest>>>,
}

impl LinuxXfrmSession for ScriptedSession {
    fn send(&mut self, request: &[u8]) -> Result<(), XfrmError> {
        let message_type = netlink_message_type(request);
        let sequence = u32::from_ne_bytes(request[8..12].try_into().unwrap());
        self.requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(SessionRequest {
                session: self.index,
                message_type,
                flags: u16::from_ne_bytes([request[6], request[7]]),
                sequence,
                body: netlink_body(request).to_vec(),
            });
        match message_type {
            XFRM_MSG_GETSADINFO => {
                let count = if self.counts_sent == 0 {
                    self.read.count_before
                } else {
                    self.read.count_after
                }
                .unwrap_or_else(|| self.read.members());
                self.counts_sent += 1;
                self.pending.push_back(sad_info_reply(sequence, count));
            }
            XFRM_MSG_GETSA => {
                for datagram in &self.read.dump {
                    self.pending.push_back(
                        datagram
                            .iter()
                            .flat_map(|message| message.render(sequence))
                            .collect(),
                    );
                }
            }
            other => panic!("unexpected session request type {other}"),
        }
        Ok(())
    }

    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<ReceiveMessageOutcome> {
        deliver(&mut self.pending, buffer)
    }
}

/// The kernel's `XFRM_MSG_NEWSADINFO` reply (`build_sadinfo`).
fn sad_info_reply(sequence: u32, count: u32) -> Vec<u8> {
    let mut body = 0_u32.to_ne_bytes().to_vec();
    append_attr(&mut body, XFRMA_SAD_CNT, &count.to_ne_bytes()).unwrap();
    append_attr(&mut body, XFRMA_SAD_HINFO, &[0; 8]).unwrap();
    message(XFRM_MSG_NEWSADINFO, 0, sequence, &body)
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
async fn key_read_dumps_every_state_between_two_sad_counts_on_one_socket() {
    let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![vec![Scripted::done()]])]);
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let snapshot = backend.query_sa_key_snapshot(key()).await.unwrap();
    assert!(snapshot.is_empty());
    assert_eq!(transport.sessions(), 1);

    let requests = transport.session_requests();
    let kinds: Vec<_> = requests
        .iter()
        .map(|request| (request.session, request.message_type, request.flags))
        .collect();
    // One socket carries the three requests, so the count reply received with
    // the configured buffer also sizes the dump's batches. Neither request
    // asks for an acknowledgement, which would arrive as a stray datagram.
    assert_eq!(
        kinds,
        vec![
            (0, XFRM_MSG_GETSADINFO, NLM_F_REQUEST),
            (0, XFRM_MSG_GETSA, NLM_F_REQUEST | NLM_F_DUMP),
            (0, XFRM_MSG_GETSADINFO, NLM_F_REQUEST),
        ]
    );
    assert!(requests[0].sequence < requests[1].sequence);
    assert!(requests[1].sequence < requests[2].sequence);
    // GETSADINFO carries its `__u32` flags word. The dump carries no
    // `XFRMA_ADDRESS_FILTER` or `XFRMA_PROTO`: the SAD count covers the
    // whole namespace, so the dump must too.
    assert_eq!(requests[0].body, 0_u32.to_ne_bytes());
    assert!(requests[1].body.is_empty());
    assert_eq!(requests[2].body, 0_u32.to_ne_bytes());
    for message_type in [XFRM_MSG_GETSA, XFRM_MSG_GETSADINFO] {
        assert_eq!(
            netlink_operation_class(message_type),
            NetlinkOperationClass::ReadOnly
        );
    }
    assert!(transport.transactions().is_empty());
}

#[tokio::test]
async fn a_dump_shorter_than_the_sad_count_is_never_complete() {
    // Linux ends a dump with DONE(0) when a state does not fit an empty
    // batch, dropping it and every older state. Here the kernel counts four
    // states but the dump delivers two, on every attempt.
    let short = || {
        ScriptedRead::dump(vec![vec![
            Scripted::member(sa_body(&disjoint_sa())),
            Scripted::member(sa_body(&marked_sa())),
            Scripted::done(),
        ]])
        .counted(4, 4)
    };
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS + 1)
            .map(|_| short())
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
    assert_eq!(transport.sessions(), SA_KEY_SNAPSHOT_READ_ATTEMPTS);

    // Exact removal refuses before trying this same incomplete dump, even
    // though its reported marked state would look like the sole candidate.
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS)
            .map(|_| short())
            .collect(),
    );
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            }
        ),
        "{error:?}"
    );
    assert_eq!(transport.sessions(), 0);
    assert!(transport.session_requests().is_empty());
    assert!(transport.transactions().is_empty(), "no DELSA was sent");
}

/// A larval state as the dump reports it: the protocol's transform
/// attributes are absent. Kernel ACQUIRE states (`xfrm_state_find`) and SPI
/// allocations (`__find_acq_core`) never carry one.
fn larval_body(parameters: &SaParameters, spi: u32) -> Vec<u8> {
    let mut body = sa_body(parameters)[..XFRM_USER_SA_INFO_LEN].to_vec();
    body[XFRM_SPI_OFFSET_IN_SA_INFO..XFRM_SPI_OFFSET_IN_SA_INFO + 4]
        .copy_from_slice(&spi.to_be_bytes());
    body
}

#[tokio::test]
async fn an_acquire_state_standing_in_for_an_omitted_state_is_never_complete() {
    // The review counterexample: the namespace holds a small state E and an
    // oversized state U at the key, so the first count is 2. A kernel
    // ACQUIRE state A is inserted before the dump starts; the dump returns A
    // and E and ends silently at U; E expires before the second count. All
    // three numbers are 2, yet U is missing.
    let mut elsewhere = disjoint_sa();
    elsewhere.id.spi += 7;
    let acquire = larval_body(&unmarked_sa(), 0);
    let counterexample = || {
        ScriptedRead::dump(vec![vec![
            Scripted::member(acquire.clone()),
            Scripted::member(sa_body(&elsewhere)),
            Scripted::done(),
        ]])
        .counted(2, 2)
    };
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS)
            .map(|_| counterexample())
            .collect(),
    );
    let read = LinuxXfrmBackend::with_transport(transport.clone())
        .query_sa_key_snapshot(key())
        .await;
    assert!(
        matches!(
            read,
            Err(XfrmError::StateIndeterminate {
                operation: SA_KEY_SNAPSHOT
            })
        ),
        "{read:?}"
    );
    assert_eq!(transport.sessions(), SA_KEY_SNAPSHOT_READ_ATTEMPTS);

    // Exact removal refuses before reading and cannot report U absent.
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS)
            .map(|_| counterexample())
            .collect(),
    );
    let removal = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await;
    assert!(
        matches!(
            removal,
            Err(XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            })
        ),
        "{removal:?}"
    );
    assert_eq!(transport.sessions(), 0);
    assert!(transport.session_requests().is_empty());
    assert!(transport.transactions().is_empty(), "no DELSA was sent");
}

#[tokio::test]
async fn any_larval_or_unclassifiable_state_makes_the_read_indeterminate() {
    // A larval state anywhere, including at the key itself with the key's
    // SPI (an SPI allocation, or an ACQUIRE for a template naming that SPI),
    // or a state of a protocol whose larval and established forms look alike.
    let mut ipip = sa_body(&disjoint_sa());
    ipip[XFRM_SPI_OFFSET_IN_SA_INFO + 4] = 4;
    let at_key = larval_body(&unmarked_sa(), unmarked_sa().id.spi);
    for extra in [larval_body(&disjoint_sa(), 0x0bad_0001), at_key, ipip] {
        let transport = KernelTransport::new(
            (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS)
                .map(|_| {
                    ScriptedRead::dump(vec![vec![
                        Scripted::member(sa_body(&marked_sa())),
                        Scripted::member(extra.clone()),
                        Scripted::done(),
                    ]])
                })
                .collect(),
        );
        let read = LinuxXfrmBackend::with_transport(transport.clone())
            .query_sa_key_snapshot(key())
            .await;
        assert!(
            matches!(
                read,
                Err(XfrmError::StateIndeterminate {
                    operation: SA_KEY_SNAPSHOT
                })
            ),
            "{read:?}"
        );
        assert_eq!(transport.sessions(), SA_KEY_SNAPSHOT_READ_ATTEMPTS);
    }

    // Once the larval state is gone, the next attempt completes.
    let transport = KernelTransport::new(vec![
        ScriptedRead::dump(vec![vec![
            Scripted::member(larval_body(&unmarked_sa(), 0)),
            Scripted::member(sa_body(&marked_sa())),
            Scripted::done(),
        ]]),
        ScriptedRead::dump(vec![vec![
            Scripted::member(sa_body(&marked_sa())),
            Scripted::done(),
        ]]),
    ]);
    let snapshot = LinuxXfrmBackend::with_transport(transport.clone())
        .query_sa_key_snapshot(key())
        .await
        .unwrap();
    assert_eq!(snapshot.states(), &[identity(&marked_sa())]);
    assert_eq!(transport.sessions(), 2);
}

#[tokio::test]
async fn a_read_whose_counts_disagree_is_repeated_whole() {
    let states = || {
        vec![vec![
            Scripted::member(sa_body(&unmarked_sa())),
            Scripted::member(sa_body(&marked_sa())),
            Scripted::done(),
        ]]
    };
    for first in [
        // A state added while the dump ran.
        ScriptedRead::dump(states()).counted(2, 3),
        // A state removed while the dump ran.
        ScriptedRead::dump(states()).counted(2, 1),
        // A state added before the dump started, then removed after it.
        ScriptedRead::dump(states()).counted(1, 1),
    ] {
        let transport = KernelTransport::new(vec![first, ScriptedRead::dump(states())]);
        let snapshot = LinuxXfrmBackend::with_transport(transport.clone())
            .query_sa_key_snapshot(key())
            .await
            .unwrap();
        assert_eq!(
            snapshot.states(),
            &[identity(&unmarked_sa()), identity(&marked_sa())]
        );
        assert_eq!(transport.sessions(), 2);
    }
}

#[test]
fn sad_state_count_reply_parsing_is_strict() {
    let parse = |datagram: &[u8]| parse_sad_state_count_reply(SA_KEY_SNAPSHOT, datagram, SEQUENCE);
    assert_eq!(parse(&sad_info_reply(SEQUENCE, 77)).unwrap(), 77);
    assert_eq!(parse(&sad_info_reply(SEQUENCE, 0)).unwrap(), 0);

    let malformed = |result: Result<u32, XfrmError>| {
        matches!(
            result,
            Err(XfrmError::Io {
                operation: SA_KEY_SNAPSHOT,
                kind: io::ErrorKind::InvalidData,
                ..
            })
        )
    };
    let reply = |message_type: u16, body: &[u8]| message(message_type, 0, SEQUENCE, body);
    let flags = 0_u32.to_ne_bytes();
    let with_attrs = |attrs: &[(u16, &[u8])]| {
        let mut body = flags.to_vec();
        for (attr_type, payload) in attrs {
            append_attr(&mut body, *attr_type, payload).unwrap();
        }
        body
    };
    // Another request's reply, another message type, or a second message.
    assert!(malformed(parse(&sad_info_reply(SEQUENCE + 1, 1))));
    assert!(malformed(parse(&reply(
        XFRM_MSG_NEWSA,
        &with_attrs(&[(XFRMA_SAD_CNT, &1_u32.to_ne_bytes())])
    ))));
    assert!(malformed(parse(
        &[sad_info_reply(SEQUENCE, 1), sad_info_reply(SEQUENCE, 1)].concat()
    )));
    // No flags word, no count, a short count, or two counts.
    assert!(malformed(parse(&reply(XFRM_MSG_NEWSADINFO, &[0; 2]))));
    assert!(malformed(parse(&reply(
        XFRM_MSG_NEWSADINFO,
        &with_attrs(&[(XFRMA_SAD_HINFO, &[0; 8])])
    ))));
    assert!(malformed(parse(&reply(
        XFRM_MSG_NEWSADINFO,
        &with_attrs(&[(XFRMA_SAD_CNT, &[1, 0])])
    ))));
    assert!(malformed(parse(&reply(
        XFRM_MSG_NEWSADINFO,
        &with_attrs(&[
            (XFRMA_SAD_CNT, &1_u32.to_ne_bytes()),
            (XFRMA_SAD_CNT, &1_u32.to_ne_bytes())
        ])
    ))));
    // Truncated or overlong framing.
    assert!(malformed(parse(&[0; 8])));
    let mut overlong = sad_info_reply(SEQUENCE, 1);
    let length = u32::try_from(overlong.len() + 4).unwrap();
    overlong[..4].copy_from_slice(&length.to_ne_bytes());
    assert!(malformed(parse(&overlong)));
    // An acknowledgement is not an answer; an error carries its errno.
    assert!(malformed(parse(&reply(NLMSG_ERROR, &[0; 20]))));
    assert!(matches!(
        parse(&reply(
            NLMSG_ERROR,
            &[(-LINUX_EPERM).to_ne_bytes().as_slice(), &[0; 16]].concat()
        )),
        Err(XfrmError::Io {
            operation: SA_KEY_SNAPSHOT,
            kind: io::ErrorKind::PermissionDenied,
            raw_os_error: Some(LINUX_EPERM),
        })
    ));
}

#[test]
fn sad_state_count_receive_is_bounded() {
    let config = LinuxXfrmBackendConfig {
        receive_attempts: 2,
        receive_buffer_len: 16,
        retry_delay: Duration::ZERO,
    };
    let mut datagrams = VecDeque::from([sad_info_reply(SEQUENCE, 1)]);
    assert!(matches!(
        receive_sad_state_count(SA_KEY_SNAPSHOT, SEQUENCE, config, |buffer| {
            deliver(&mut datagrams, buffer)
        }),
        Err(XfrmError::ResponseTooLarge {
            operation: SA_KEY_SNAPSHOT,
            buffer_bytes: 16,
            ..
        })
    ));
    let mut empty = VecDeque::new();
    assert!(matches!(
        receive_sad_state_count(SA_KEY_SNAPSHOT, SEQUENCE, dump_config(), |buffer| {
            deliver(&mut empty, buffer)
        }),
        Err(XfrmError::StateIndeterminate {
            operation: SA_KEY_SNAPSHOT
        })
    ));
    let mut outcomes = VecDeque::from([
        Ok(ReceiveMessageOutcome::RejectedNonKernel),
        Err(sad_info_reply(SEQUENCE, 9)),
    ]);
    assert_eq!(
        receive_sad_state_count(SA_KEY_SNAPSHOT, SEQUENCE, dump_config(), |buffer| {
            match outcomes.pop_front() {
                Some(Ok(outcome)) => Ok(outcome),
                Some(Err(bytes)) => deliver(&mut VecDeque::from([bytes]), buffer),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        })
        .unwrap(),
        9
    );
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
    // The dump is unfiltered, so every other state arrives too.
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

    let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![
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
    ])]);
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
    assert_eq!(transport.sessions(), 1);
    assert!(transport.transactions().is_empty());
}

#[tokio::test]
async fn key_snapshot_skips_unrepresentable_states_elsewhere_but_not_at_the_key() {
    // A well-formed established state at another key is classified and
    // counted but not decoded, so a mark the SDK cannot represent there does
    // not fail the read.
    let mut other_spi = marked_sa();
    other_spi.id.spi += 1;
    let mut noncanonical_elsewhere = sa_body(&other_spi);
    append_attr(
        &mut noncanonical_elsewhere,
        XFRMA_MARK,
        &[0x11_u32.to_ne_bytes(), 0xf0_u32.to_ne_bytes()].concat(),
    )
    .unwrap();
    let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![vec![
        Scripted::member(noncanonical_elsewhere),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]])]);
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
    // So do a truncated member and a malformed attribute stream at any key,
    // because every state must be classified as established or larval.
    let short = sa_body(&marked_sa())[..XFRM_USER_SA_INFO_LEN - 1].to_vec();
    let mut malformed_elsewhere = sa_body(&other_spi);
    malformed_elsewhere.extend_from_slice(&[0xff; 3]);
    for body in [noncanonical, short, malformed_elsewhere] {
        let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![vec![
            Scripted::member(sa_body(&marked_sa())),
            Scripted::member(body),
            Scripted::done(),
        ]])]);
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

#[test]
fn dumped_states_are_classified_by_their_required_transform() {
    let classify = |body: &[u8]| dumped_state_kind(body, SA_KEY_SNAPSHOT).unwrap();
    let with_protocol = |body: &[u8], protocol: u8| {
        let mut body = body.to_vec();
        body[XFRM_SPI_OFFSET_IN_SA_INFO + 4] = protocol;
        body
    };
    let bare = larval_body(&marked_sa(), 0);
    let with_attr = |attr_type: u16, payload: &[u8]| {
        let mut body = bare.clone();
        append_attr(&mut body, attr_type, payload).unwrap();
        body
    };
    // ESP needs AEAD or CRYPT; AUTH alone is not enough.
    assert_eq!(
        classify(&sa_body(&marked_sa())),
        DumpedStateKind::Established
    );
    assert_eq!(
        classify(&with_attr(XFRMA_ALG_AEAD, &[0; 72])),
        DumpedStateKind::Established
    );
    assert_eq!(
        classify(&with_attr(XFRMA_ALG_AUTH_TRUNC, &[0; 72])),
        DumpedStateKind::Larval
    );
    assert_eq!(classify(&bare), DumpedStateKind::Larval);
    // AH needs AUTH or AUTH_TRUNC, and IPComp needs COMP.
    for (attr_type, protocol, kind) in [
        (XFRMA_ALG_AUTH, IPPROTO_AH, DumpedStateKind::Established),
        (
            XFRMA_ALG_AUTH_TRUNC,
            IPPROTO_AH,
            DumpedStateKind::Established,
        ),
        (XFRMA_ALG_CRYPT, IPPROTO_AH, DumpedStateKind::Larval),
        (XFRMA_ALG_COMP, IPPROTO_COMP, DumpedStateKind::Established),
        (XFRMA_ALG_AUTH, IPPROTO_COMP, DumpedStateKind::Larval),
    ] {
        assert_eq!(
            classify(&with_protocol(&with_attr(attr_type, &[0; 68]), protocol)),
            kind
        );
    }
    assert_eq!(
        classify(&with_protocol(&bare, IPPROTO_AH)),
        DumpedStateKind::Larval
    );
    assert_eq!(
        classify(&with_protocol(&bare, IPPROTO_COMP)),
        DumpedStateKind::Larval
    );
    // IPIP and every other protocol cannot be told apart.
    for protocol in [0, 4, 41, 43, 60] {
        assert_eq!(
            classify(&with_protocol(&sa_body(&marked_sa()), protocol)),
            DumpedStateKind::Unclassified
        );
    }
    // A malformed attribute stream or a short member is an error.
    let mut malformed = sa_body(&marked_sa());
    malformed.extend_from_slice(&[0xff; 3]);
    assert!(dumped_state_kind(&malformed, SA_KEY_SNAPSHOT).is_err());
    assert!(dumped_state_kind(&bare[..XFRM_USER_SA_INFO_LEN - 1], SA_KEY_SNAPSHOT).is_err());
}

#[tokio::test]
async fn interrupted_dump_is_discarded_and_repeated_with_a_fresh_sequence() {
    let transport = KernelTransport::new(vec![
        ScriptedRead::dump(vec![
            vec![Scripted::member(sa_body(&marked_sa()))],
            vec![Scripted::member(sa_body(&disjoint_sa())).interrupted()],
            vec![Scripted::done()],
        ]),
        ScriptedRead::dump(vec![vec![
            Scripted::member(sa_body(&unmarked_sa())),
            Scripted::done(),
        ]]),
    ]);
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let snapshot = backend.query_sa_key_snapshot(key()).await.unwrap();

    // Nothing from the interrupted attempt survives.
    assert_eq!(snapshot.states(), &[identity(&unmarked_sa())]);
    let requests = transport.dump_requests();
    assert_eq!(requests.len(), 2);
    assert_ne!(requests[0].session, requests[1].session);
    assert_ne!(requests[0].sequence, requests[1].sequence);
    assert_eq!(requests[0].body, requests[1].body);
}

#[tokio::test]
async fn persistently_interrupted_dump_fails_closed_after_bounded_attempts() {
    let interrupted = || {
        vec![vec![
            Scripted::member(sa_body(&marked_sa())).interrupted(),
            Scripted::done(),
        ]]
    };
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS + 1)
            .map(|_| ScriptedRead::dump(interrupted()))
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
        SA_KEY_SNAPSHOT_READ_ATTEMPTS
    );
}

#[tokio::test]
async fn key_snapshot_rejects_invalid_keys_before_any_request() {
    let transport = KernelTransport::new(Vec::new());
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
    assert_eq!(transport.sessions(), 0);
}

#[tokio::test]
async fn unfenced_exact_removal_linux_refuses_before_opening_any_netlink_session() {
    let mut changed = marked_sa();
    changed.request_id = XfrmRequestId::new(0x0a0a);
    for states in [
        vec![disjoint_sa(), marked_sa()],
        vec![marked_sa()],
        vec![unmarked_sa(), marked_sa()],
        vec![changed],
        Vec::new(),
    ] {
        let mut dump: Vec<_> = states
            .iter()
            .map(|state| Scripted::member(sa_body(state)))
            .collect();
        dump.push(Scripted::done());
        let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![dump])]);
        let result = LinuxXfrmBackend::with_transport(transport.clone())
            .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
            .await;

        assert_eq!(transport.sessions(), 0, "no snapshot session may be opened");
        assert!(
            transport.session_requests().is_empty(),
            "no read may be sent"
        );
        assert!(
            transport.transactions().is_empty(),
            "no deletion may be sent"
        );
        assert_eq!(transport.reads.lock().unwrap().len(), 1);
        assert!(
            matches!(
                result,
                Err(XfrmError::UnsupportedFeature {
                    feature: "exact_sa_removal"
                })
            ),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn unfenced_exact_removal_linux_validates_before_refusing() {
    let transport = KernelTransport::new(Vec::new());
    let backend = LinuxXfrmBackend::with_transport(transport.clone());
    let mut zero_spi = identity(&marked_sa());
    zero_spi.id.spi = 0;
    let mut wrong_protocol = identity(&marked_sa());
    wrong_protocol.id.protocol = 17;
    let mut zero_if_id = identity(&marked_sa());
    zero_if_id.if_id = Some(0);
    for (expected, field) in [
        (zero_spi, "sa_key.spi"),
        (wrong_protocol, "sa_key.protocol"),
        (zero_if_id, "sa.if_id"),
    ] {
        let result = backend
            .remove_sa_exact(ExactRemoveSaRequest::new(expected))
            .await;
        assert!(
            matches!(result, Err(XfrmError::InvalidConfig { field: actual, .. }) if actual == field),
            "{result:?}"
        );
        assert_eq!(transport.sessions(), 0);
        assert!(transport.session_requests().is_empty());
        assert!(transport.transactions().is_empty());
    }
}

#[tokio::test]
async fn exact_removal_refuses_marked_and_unmarked_overlap_without_any_request() {
    let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![vec![
        Scripted::member(sa_body(&unmarked_sa())),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]])]);
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            }
        ),
        "{error:?}"
    );
    assert_eq!(transport.sessions(), 0);
    assert!(transport.session_requests().is_empty());
    assert!(transport.transactions().is_empty(), "no DELSA was sent");
}

#[tokio::test]
async fn exact_removal_refuses_a_sole_candidate_before_any_request() {
    // The disjoint full-mask state is at the key but cannot answer the
    // marked lookup.
    let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![vec![
        Scripted::member(sa_body(&disjoint_sa())),
        Scripted::member(sa_body(&marked_sa())),
        Scripted::done(),
    ]])]);
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            }
        ),
        "{error:?}"
    );
    assert_eq!(transport.sessions(), 0);
    assert!(transport.session_requests().is_empty());
    assert!(transport.transactions().is_empty(), "no DELSA was sent");
}

#[tokio::test]
async fn exact_removal_refuses_absent_or_changed_states_without_reading() {
    let mut changed = marked_sa();
    changed.request_id = XfrmRequestId::new(0x0a0a);
    for states in [
        Vec::new(),
        vec![Scripted::member(sa_body(&changed))],
        vec![Scripted::member(sa_body(&unmarked_sa()))],
    ] {
        let mut dump = states;
        dump.push(Scripted::done());
        let transport = KernelTransport::new(vec![ScriptedRead::dump(vec![dump])]);
        let error = LinuxXfrmBackend::with_transport(transport.clone())
            .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                XfrmError::UnsupportedFeature {
                    feature: "exact_sa_removal"
                }
            ),
            "{error:?}"
        );
        assert_eq!(transport.sessions(), 0);
        assert!(transport.session_requests().is_empty());
        assert!(transport.transactions().is_empty(), "no DELSA was sent");
    }
}

#[tokio::test]
async fn exact_removal_does_not_attempt_a_snapshot_even_when_it_would_fail() {
    let transport = KernelTransport::new(
        (0..SA_KEY_SNAPSHOT_READ_ATTEMPTS)
            .map(|_| {
                ScriptedRead::dump(vec![vec![
                    Scripted::member(sa_body(&marked_sa())).interrupted()
                ]])
            })
            .collect(),
    );
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            }
        ),
        "{error:?}"
    );
    assert_eq!(transport.sessions(), 0);
    assert!(transport.session_requests().is_empty());
    assert!(transport.transactions().is_empty());

    // A transport without sessions fails closed the same way.
    let transport = CapturingTransport::default();
    let error = LinuxXfrmBackend::with_transport(transport.clone())
        .remove_sa_exact(ExactRemoveSaRequest::new(identity(&marked_sa())))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "exact_sa_removal"
            }
        ),
        "{error:?}"
    );
    assert!(transport.requests().is_empty());
}
