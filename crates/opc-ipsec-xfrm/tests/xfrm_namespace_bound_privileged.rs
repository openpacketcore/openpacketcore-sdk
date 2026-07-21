//! Privileged proof that two namespace-bound actors isolate identical XFRM SAs.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, EspCounterProofRequirement, EspCounterResumeApplyRequest,
    EspCounterResumeBinding, EspCounterResumeProofSet, InstallPolicyRequest, InstallSaRequest,
    InstalledOutboundSaBinding, IpAddress, KeyMaterial, LifetimeConfig, LinuxXfrmBackend,
    NamespaceBoundLinuxXfrmBackend, PolicyParameters, QuerySaRequest, RemovePolicyRequest,
    RemoveSaRequest, SaParameters, XfrmAction, XfrmBackend, XfrmCompositeInstallRequest,
    XfrmDirection, XfrmId, XfrmMode, XfrmRequestId, XfrmSelector, XfrmStagedInstall, XfrmTemplate,
};

const IPPROTO_ESP: u8 = 50;
const SHARED_SPI: u32 = 0x7333_0001;
const CAPTURE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_PACKET_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_NAMESPACE_SET: AtomicU64 = AtomicU64::new(1);

fn command(program: &str, args: &[&str]) -> io::Result<Output> {
    Command::new(program).args(args).output()
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let output = command(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other("privileged namespace command failed"))
    }
}

fn capture_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn join_capture_thread<T>(handle: JoinHandle<io::Result<T>>) -> io::Result<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("packet capture worker failed"))?
}

fn wait_for_capture_exit(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for one outbound ESP packet",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct EspPacketCapture {
    child: Option<Child>,
    bytes: Option<JoinHandle<io::Result<Vec<u8>>>>,
    diagnostics: Option<JoinHandle<io::Result<()>>>,
}

impl EspPacketCapture {
    fn start(namespace: &str) -> io::Result<Self> {
        let mut child = Command::new("ip")
            .args([
                "netns", "exec", namespace, "tcpdump", "-n", "-i", "opcxfrm0", "-c", "1", "-U",
                "-s", "96", "-y", "EN10MB", "-w", "-", "ip", "proto", "50",
            ])
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("packet capture stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("packet capture diagnostics unavailable"))?;

        let bytes = thread::spawn(move || {
            let mut bytes = Vec::new();
            BufReader::new(stdout).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let diagnostics = thread::spawn(move || {
            let mut signalled = false;
            for line in BufReader::new(stderr).lines() {
                let line = line?;
                if !signalled && line.contains("listening on") {
                    let _ = ready_tx.send(());
                    signalled = true;
                }
            }
            if signalled {
                Ok(())
            } else {
                Err(io::Error::other("packet capture did not become ready"))
            }
        });
        let capture = Self {
            child: Some(child),
            bytes: Some(bytes),
            diagnostics: Some(diagnostics),
        };
        ready_rx
            .recv_timeout(CAPTURE_READY_TIMEOUT)
            .map_err(|_| io::Error::other("packet capture readiness timed out"))?;
        Ok(capture)
    }

    fn finish(mut self) -> io::Result<Vec<u8>> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("packet capture process unavailable"))?;
        let status = wait_for_capture_exit(child, CAPTURE_PACKET_TIMEOUT)?;
        self.child.take();
        let bytes = join_capture_thread(
            self.bytes
                .take()
                .ok_or_else(|| io::Error::other("packet capture reader unavailable"))?,
        )?;
        join_capture_thread(
            self.diagnostics
                .take()
                .ok_or_else(|| io::Error::other("packet capture monitor unavailable"))?,
        )?;
        if !status.success() {
            return Err(io::Error::other("packet capture command failed"));
        }
        Ok(bytes)
    }
}

impl Drop for EspPacketCapture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(bytes) = self.bytes.take() {
            let _ = bytes.join();
        }
        if let Some(diagnostics) = self.diagnostics.take() {
            let _ = diagnostics.join();
        }
    }
}

#[derive(Clone, Copy)]
enum PcapByteOrder {
    Big,
    Little,
}

fn pcap_u32(bytes: &[u8], order: PcapByteOrder) -> io::Result<u32> {
    let octets: [u8; 4] = bytes
        .try_into()
        .map_err(|_| capture_error("truncated packet capture integer"))?;
    Ok(match order {
        PcapByteOrder::Big => u32::from_be_bytes(octets),
        PcapByteOrder::Little => u32::from_le_bytes(octets),
    })
}

fn parse_captured_esp_header(capture: &[u8]) -> io::Result<(u32, u32)> {
    const GLOBAL_HEADER_LEN: usize = 24;
    const RECORD_HEADER_LEN: usize = 16;
    const ETHERNET_HEADER_LEN: usize = 14;
    const DLT_EN10MB: u32 = 1;

    if capture.len() < GLOBAL_HEADER_LEN + RECORD_HEADER_LEN {
        return Err(capture_error("truncated packet capture"));
    }
    let order = match capture[..4] {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => PcapByteOrder::Big,
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => PcapByteOrder::Little,
        _ => return Err(capture_error("unsupported packet capture encoding")),
    };
    if pcap_u32(&capture[20..24], order)? != DLT_EN10MB {
        return Err(capture_error("unexpected packet capture link type"));
    }
    let captured_len = pcap_u32(&capture[32..36], order)? as usize;
    let packet_start = GLOBAL_HEADER_LEN + RECORD_HEADER_LEN;
    let packet_end = packet_start
        .checked_add(captured_len)
        .filter(|end| *end <= capture.len())
        .ok_or_else(|| capture_error("truncated captured packet"))?;
    let packet = &capture[packet_start..packet_end];
    if packet.len() < ETHERNET_HEADER_LEN + 20 || packet[12..14] != [0x08, 0x00] {
        return Err(capture_error("captured packet is not Ethernet IPv4"));
    }
    let ipv4 = &packet[ETHERNET_HEADER_LEN..];
    if ipv4[0] >> 4 != 4 || ipv4[9] != IPPROTO_ESP {
        return Err(capture_error("captured packet is not native ESP"));
    }
    let header_len = usize::from(ipv4[0] & 0x0f) * 4;
    if header_len < 20 || ipv4.len() < header_len + 8 {
        return Err(capture_error("captured ESP header is truncated"));
    }
    let esp = &ipv4[header_len..];
    let spi = u32::from_be_bytes(
        esp[..4]
            .try_into()
            .map_err(|_| capture_error("captured ESP SPI is truncated"))?,
    );
    let sequence = u32::from_be_bytes(
        esp[4..8]
            .try_into()
            .map_err(|_| capture_error("captured ESP sequence is truncated"))?,
    );
    Ok((spi, sequence))
}

struct TestNamespaces {
    names: Vec<String>,
}

impl TestNamespaces {
    fn provision() -> io::Result<Self> {
        let pid = std::process::id();
        let set = NEXT_NAMESPACE_SET.fetch_add(1, Ordering::Relaxed);
        let mut namespaces = Self {
            names: Vec::with_capacity(2),
        };
        for suffix in ["a", "b"] {
            let name = format!("opcx{pid}{set}{suffix}");
            let _ = command("ip", &["netns", "del", &name]);
            run("ip", &["netns", "add", &name])?;
            namespaces.names.push(name);
        }
        Ok(namespaces)
    }
}

impl Drop for TestNamespaces {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = command("ip", &["netns", "del", name]);
        }
    }
}

fn ip(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn shared_sa() -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(ip([10, 33, 0, 1]), ip([10, 33, 0, 2]), 17),
        id: XfrmId {
            destination: ip([192, 0, 2, 2]),
            spi: SHARED_SPI,
            protocol: IPPROTO_ESP,
        },
        source_address: ip([192, 0, 2, 1]),
        request_id: None,
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x33; 32]),
        )),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn outbound_binding_request() -> XfrmCompositeInstallRequest {
    let mut sa = shared_sa();
    sa.selector = XfrmSelector::new(ip([10, 33, 0, 1]), ip([10, 33, 0, 2]), 1);
    sa.request_id = XfrmRequestId::new(333);
    sa.replay_window = 64;
    let policy = PolicyParameters {
        selector: sa.selector.clone(),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![XfrmTemplate {
            id: sa.id,
            source_address: sa.source_address,
            request_id: sa.request_id,
            mode: sa.mode,
        }],
        mark: sa.mark,
        if_id: sa.if_id,
    };
    XfrmCompositeInstallRequest {
        sa: InstallSaRequest { parameters: sa },
        policy: InstallPolicyRequest { parameters: policy },
    }
}

fn configure_packet_path(namespace: &str) -> io::Result<()> {
    run(
        "ip",
        &["netns", "exec", namespace, "ip", "link", "set", "lo", "up"],
    )?;
    run(
        "ip",
        &[
            "netns", "exec", namespace, "ip", "link", "add", "opcxfrm0", "type", "dummy",
        ],
    )?;
    run(
        "ip",
        &[
            "netns", "exec", namespace, "ip", "link", "set", "opcxfrm0", "up",
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "ip",
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            "opcxfrm0",
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "ip",
            "address",
            "add",
            "10.33.0.1/32",
            "dev",
            "lo",
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "ip",
            "route",
            "add",
            "10.33.0.2/32",
            "dev",
            "opcxfrm0",
            "src",
            "10.33.0.1",
        ],
    )?;
    run(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "ip",
            "neighbor",
            "replace",
            "192.0.2.2",
            "lladdr",
            "02:00:00:00:00:02",
            "nud",
            "permanent",
            "dev",
            "opcxfrm0",
        ],
    )
}

fn install_in_namespace(
    namespace: String,
) -> Result<NamespaceBoundLinuxXfrmBackend, Box<dyn std::error::Error + Send + Sync>> {
    std::thread::spawn(move || {
        let file = fs::File::open(format!("/run/netns/{namespace}"))?;
        nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET)?;
        let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(backend.install_sa(InstallSaRequest {
            parameters: shared_sa(),
        }))?;
        Ok(backend)
    })
    .join()
    .map_err(|_| io::Error::other("namespace installer thread failed"))?
}

type BindingInstall = (
    Arc<NamespaceBoundLinuxXfrmBackend>,
    InstalledOutboundSaBinding,
    XfrmCompositeInstallRequest,
);

fn install_binding_in_namespace(
    namespace: String,
) -> Result<BindingInstall, Box<dyn std::error::Error + Send + Sync>> {
    std::thread::spawn(move || {
        let file = fs::File::open(format!("/run/netns/{namespace}"))?;
        nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET)?;
        let backend = Arc::new(LinuxXfrmBackend::new().bind_current_network_namespace()?);
        let request = outbound_binding_request();
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let binding = runtime.block_on(
            XfrmStagedInstall::new(request.clone())
                .run_and_commit_outbound_sa_policy(Arc::clone(&backend)),
        )?;
        Ok((backend, binding, request))
    })
    .join()
    .map_err(|_| io::Error::other("namespace binding installer thread failed"))?
}

#[tokio::test]
#[ignore = "requires root, CAP_NET_ADMIN, Linux XFRM, iproute2, and named netns support"]
async fn identical_sas_remain_isolated_between_namespace_bound_actors(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if env::var("OPC_XFRM_RUN_NAMESPACE_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_NAMESPACE_PRIVILEGED=1 on a privileged Linux host");
        return Ok(());
    }

    let namespaces = TestNamespaces::provision()?;
    let backend_a = install_in_namespace(namespaces.names[0].clone())?;
    let backend_b = install_in_namespace(namespaces.names[1].clone())?;
    let query = QuerySaRequest::new(ip([192, 0, 2, 2]), IPPROTO_ESP, SHARED_SPI);

    let state_a = backend_a.query_sa(query).await?;
    let state_b = backend_b.query_sa(query).await?;
    assert_eq!(state_a.id, state_b.id);
    assert_eq!(state_a.selector, state_b.selector);

    let remove = RemoveSaRequest::new(ip([192, 0, 2, 2]), IPPROTO_ESP, SHARED_SPI);
    backend_a.remove_sa(remove).await?;
    // Removing namespace A's identical tuple must not remove namespace B's SA.
    let still_present_b = backend_b.query_sa(query).await?;
    assert_eq!(still_present_b.id, state_b.id);
    backend_b.remove_sa(remove).await?;

    drop(backend_a);
    drop(backend_b);
    drop(namespaces);
    Ok(())
}

#[tokio::test]
#[ignore = "requires root, CAP_NET_ADMIN, Linux XFRM, iproute2, and named netns support"]
async fn counter_receipt_from_identical_other_namespace_is_rejected(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if env::var("OPC_XFRM_RUN_NAMESPACE_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_NAMESPACE_PRIVILEGED=1 on a privileged Linux host");
        return Ok(());
    }

    let namespaces = TestNamespaces::provision()?;
    let (backend_a, authority_a, request_a) =
        install_binding_in_namespace(namespaces.names[0].clone())?;
    let (backend_b, authority_b, request_b) =
        install_binding_in_namespace(namespaces.names[1].clone())?;
    assert_eq!(
        authority_a.id(),
        authority_b.id(),
        "durable correlation must remain stable across identical namespace state"
    );

    let target_a = authority_a.outbound_esp_counter_target();
    let target_b = authority_b.outbound_esp_counter_target();
    let binding = EspCounterResumeBinding::new(33, 34, authority_b.id(), 17)?;
    let receipt = backend_b
        .apply_and_read_back_outbound_esp_counter(
            &authority_b,
            authority_b.id(),
            EspCounterResumeApplyRequest::new(binding, request_b.sa.parameters.clone()),
        )
        .await?;
    let proofs = EspCounterResumeProofSet::single(receipt);
    proofs
        .validate_counter_proof(
            &target_b,
            binding,
            EspCounterProofRequirement::BeforeOwnershipCommit,
        )
        .await?;
    let error = proofs
        .validate_counter_proof(
            &target_a,
            binding,
            EspCounterProofRequirement::BeforeOwnershipCommit,
        )
        .await
        .expect_err("a valid receipt from namespace B must not authorize namespace A");
    assert_eq!(error.code(), "esp_counter_receipt_target_mismatch");

    for (backend, request) in [(&backend_a, &request_a), (&backend_b, &request_b)] {
        backend
            .remove_policy(RemovePolicyRequest::new(
                request.policy.parameters.selector.clone(),
                request.policy.parameters.direction,
            ))
            .await?;
        backend
            .remove_sa(RemoveSaRequest::new(
                request.sa.parameters.id.destination,
                request.sa.parameters.id.protocol,
                request.sa.parameters.id.spi,
            ))
            .await?;
    }
    drop(backend_a);
    drop(backend_b);
    drop(namespaces);
    Ok(())
}

#[tokio::test]
#[ignore = "requires root, CAP_NET_ADMIN/CAP_NET_RAW, Linux XFRM, iproute2, ping, tcpdump, and named netns support"]
async fn outbound_binding_installs_recovers_and_transforms_first_packet(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if env::var("OPC_XFRM_RUN_NAMESPACE_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_NAMESPACE_PRIVILEGED=1 on a privileged Linux host");
        return Ok(());
    }

    let namespaces = TestNamespaces::provision()?;
    let namespace = &namespaces.names[0];
    configure_packet_path(namespace)?;
    let (backend, installed, request) = install_binding_in_namespace(namespace.clone())?;
    let recovered = match backend
        .recover_installed_outbound_sa_binding(request.clone())
        .await
    {
        Ok(binding) => binding,
        Err(error) => {
            eprintln!(
                "binding recovery failed: code={}, source={:?}",
                error.code(),
                std::error::Error::source(&error)
            );
            return Err(error.into());
        }
    };
    assert_eq!(installed.id(), recovered.id());

    const RESUMED_SEND_NEXT: u64 = (1_u64 << 32) + 17;
    let counter_target = recovered.outbound_esp_counter_target();
    let counter_binding = EspCounterResumeBinding::new(1, 1, recovered.id(), RESUMED_SEND_NEXT)?;
    let receipt = backend
        .apply_and_read_back_outbound_esp_counter(
            &recovered,
            recovered.id(),
            EspCounterResumeApplyRequest::new(counter_binding, request.sa.parameters.clone()),
        )
        .await?;
    EspCounterResumeProofSet::single(receipt)
        .validate_counter_proof(
            &counter_target,
            counter_binding,
            EspCounterProofRequirement::BeforeFirstPublication,
        )
        .await?;

    // Capture exactly one outbound ESP packet in memory. The capture is never
    // logged or persisted and only its public ESP header is inspected.
    let capture = EspPacketCapture::start(namespace)?;
    // A response is not expected because the dummy link has no peer. The
    // outbound packet must nevertheless cross policy lookup and ESP output.
    let _ = command(
        "ip",
        &[
            "netns",
            "exec",
            namespace,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            "10.33.0.1",
            "10.33.0.2",
        ],
    )?;
    let (wire_spi, wire_sequence) = parse_captured_esp_header(&capture.finish()?)?;
    assert_eq!(wire_spi, request.sa.parameters.id.spi);
    assert_eq!(wire_sequence, RESUMED_SEND_NEXT as u32);

    let query = QuerySaRequest::new(
        request.sa.parameters.id.destination,
        request.sa.parameters.id.protocol,
        request.sa.parameters.id.spi,
    );
    let state = backend.query_sa(query).await?;
    assert_eq!(
        state.lifetime_current.packets, 1,
        "exactly one first packet must traverse the outbound ESP SA"
    );
    let emitted_sequence = (u64::from(state.replay_state.outbound_sequence_hi) << 32)
        | u64::from(state.replay_state.outbound_sequence);
    assert_eq!(
        emitted_sequence, RESUMED_SEND_NEXT,
        "Linux stores last assigned oseq, so one packet must advance next - 1 to next"
    );

    backend
        .remove_policy(RemovePolicyRequest::new(
            request.policy.parameters.selector,
            request.policy.parameters.direction,
        ))
        .await?;
    backend
        .remove_sa(RemoveSaRequest::new(
            request.sa.parameters.id.destination,
            request.sa.parameters.id.protocol,
            request.sa.parameters.id.spi,
        ))
        .await?;
    drop(backend);
    drop(namespaces);
    Ok(())
}
