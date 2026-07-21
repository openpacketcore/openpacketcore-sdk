//! Privileged proof that two namespace-bound actors isolate identical XFRM SAs.

#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io;
use std::process::{Command, Output};

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend, QuerySaRequest, RemoveSaRequest,
    SaParameters, XfrmBackend, XfrmId, XfrmMode, XfrmSelector,
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
