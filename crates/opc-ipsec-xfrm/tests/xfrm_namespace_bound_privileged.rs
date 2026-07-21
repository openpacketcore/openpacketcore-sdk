//! Privileged proof that two namespace-bound actors isolate identical XFRM SAs.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io;
use std::process::{Command, Output};
use std::sync::Arc;

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

struct TestNamespaces {
    names: Vec<String>,
}

impl TestNamespaces {
    fn provision() -> io::Result<Self> {
        let pid = std::process::id();
        let mut namespaces = Self {
            names: Vec::with_capacity(2),
        };
        for suffix in ["a", "b"] {
            let name = format!("opcx{pid}{suffix}");
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
#[ignore = "requires root, CAP_NET_ADMIN, Linux XFRM, iproute2, ping, and named netns support"]
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
            counter_binding,
            EspCounterProofRequirement::BeforeFirstPublication,
        )
        .await?;

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
