//! Real-kernel startup reset after SIGKILL, with independent iproute2 dumps.
//! Every active test creates its own network namespace; the parent fixture also
//! holds sentinels in a separate private namespace. No host XFRM table is used.

#![cfg(target_os = "linux")]

#[path = "support/readiness.rs"]
mod readiness;

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sched::{unshare, CloneFlags};
use opc_ipsec_xfrm::{
    Algorithm, AllocateSpiRequest, AuthAlgorithm, ExclusiveNamespaceResetAcknowledgement,
    InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
    LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend, PolicyParameters, SaParameters, XfrmAction,
    XfrmBackend, XfrmDirection, XfrmError, XfrmId, XfrmMode, XfrmObjectInstallRecoveryStore,
    XfrmObjectInstallRequest, XfrmObjectRecoveryProofKey, XfrmObjectRosterGroupId,
    XfrmObjectRosterMemberRequest, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterRecoveryStore, XfrmObjectRosterRequest,
    XfrmRequestId, XfrmSaRelocationRecoveryProofKey, XfrmSaRelocationRecoveryStore, XfrmSelector,
    XfrmTemplate,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Bound = (
    NamespaceBoundLinuxXfrmBackend,
    XfrmObjectInstallRecoveryStore,
    XfrmSaRelocationRecoveryStore,
    XfrmObjectRosterRecoveryStore,
);

const ENABLE: &str = "OPC_XFRM_RUN_EXCLUSIVE_RESET_PRIVILEGED";
const SEED_ROOT: &str = "OPC_XFRM_RESET_SEED_ROOT";
const SEED_READY: &str = "OPC_XFRM_RESET_SEED_READY";
const FORCE_NO_SUB_POLICY: &str = "OPC_XFRM_RESET_TEST_FORCE_NO_SUB_POLICY";
const KEY: &str = "0x0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10";

fn enabled() -> bool {
    if std::env::var(ENABLE).as_deref() == Ok("1") {
        true
    } else {
        eprintln!("skipping: exclusive namespace reset requires explicit privileged enablement");
        false
    }
}

fn ack() -> ExclusiveNamespaceResetAcknowledgement {
    ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state()
}

fn ip(args: &[&str]) -> TestResult<Vec<u8>> {
    let output = Command::new("ip").args(args).output()?;
    if !output.status.success() {
        // ip may echo sensitive request fields in stderr. Keep failures value-free.
        return Err(io::Error::other("independent iproute2 fixture command failed").into());
    }
    Ok(output.stdout)
}

enum SubPolicyCoverage {
    Exercised,
    KernelRefused,
    SimulatedRefusal,
}

impl SubPolicyCoverage {
    fn marker(self) -> &'static str {
        match self {
            Self::Exercised => "XFRM_EXCLUSIVE_NAMESPACE_RESET_SUB_POLICY=exercised",
            Self::KernelRefused => "XFRM_EXCLUSIVE_NAMESPACE_RESET_SUB_POLICY=kernel-refused",
            Self::SimulatedRefusal => "XFRM_EXCLUSIVE_NAMESPACE_RESET_SUB_POLICY=simulated-refusal",
        }
    }
}

fn sub_policy_add_supported(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> TestResult<bool> {
    if code == Some(0) {
        return Ok(true);
    }
    // With LC_ALL=C, this is the kernel's extack for a fixed, valid SUB add
    // when CONFIG_XFRM_SUB_POLICY is disabled. No other failure is optional.
    if code == Some(2) && stdout.is_empty() && stderr == b"Error: Invalid policy type.\n" {
        return Ok(false);
    }
    // Never copy fixture output into errors: it can contain object values.
    Err(io::Error::other("independent iproute2 sub-policy fixture command failed").into())
}

fn add_sub_policy(args: &[&str]) -> TestResult<SubPolicyCoverage> {
    if std::env::var(FORCE_NO_SUB_POLICY).as_deref() == Ok("1") {
        // Test-only simulation of the refused add, without changing the host
        // kernel. It exercises the same classifier and all remaining fixture
        // commands, but is never reported as real kernel-refusal evidence.
        assert!(!sub_policy_add_supported(
            Some(2),
            b"",
            b"Error: Invalid policy type.\n"
        )?);
        return Ok(SubPolicyCoverage::SimulatedRefusal);
    }
    let output = Command::new("ip").env("LC_ALL", "C").args(args).output()?;
    if sub_policy_add_supported(output.status.code(), &output.stdout, &output.stderr)? {
        Ok(SubPolicyCoverage::Exercised)
    } else {
        Ok(SubPolicyCoverage::KernelRefused)
    }
}

fn parameters() -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(
            IpAddress::Ipv4([10, 90, 0, 1]),
            IpAddress::Ipv4([10, 90, 0, 2]),
            17,
        ),
        id: XfrmId {
            destination: IpAddress::Ipv4([192, 0, 2, 2]),
            spi: 0x901,
            protocol: 50,
        },
        source_address: IpAddress::Ipv4([192, 0, 2, 1]),
        request_id: XfrmRequestId::new(90),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x31; 32]),
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

fn policy() -> InstallPolicyRequest {
    let sa = parameters();
    InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: sa.selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 90,
            templates: vec![XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
            }],
            mark: None,
            if_id: None,
        },
    }
}

fn roster() -> TestResult<XfrmObjectRosterRequest> {
    Ok(XfrmObjectRosterRequest::new(vec![
        XfrmObjectRosterMemberRequest::new(XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: parameters(),
        })),
        XfrmObjectRosterMemberRequest::new(XfrmObjectInstallRequest::Policy(policy())),
    ])?)
}

fn bind(root: &Path) -> TestResult<Bound> {
    Ok(LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
            root.join("objects"),
            XfrmObjectRecoveryProofKey::new([0x41; 32])?,
            root.join("relocations"),
            XfrmSaRelocationRecoveryProofKey::new([0x42; 32])?,
            root.join("rosters"),
            XfrmObjectRosterRecoveryProofKey::new([0x43; 32])?,
        )?)
}

struct Root(PathBuf);
impl Root {
    fn new() -> TestResult<Self> {
        let id = XfrmObjectRosterGroupId::generate()?.to_bytes();
        let suffix: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("opc-xfrm-exclusive-reset-{suffix}"));
        DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Seed(Child);
impl Drop for Seed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn seed_and_kill(root: &Path) -> TestResult {
    let ready = root.join("ready");
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "exclusive_namespace_reset_seed",
            "--nocapture",
        ])
        .env(SEED_ROOT, root)
        .env(SEED_READY, &ready)
        .stdin(Stdio::null())
        .spawn()?;
    let mut child = Seed(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready.exists() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(io::Error::other("reset predecessor did not become ready").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill()?;
    let status = child.0.wait()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    Ok(())
}

fn add_foreign_objects() -> TestResult<SubPolicyCoverage> {
    ip(&[
        "xfrm",
        "state",
        "add",
        "src",
        "192.0.2.3",
        "dst",
        "192.0.2.4",
        "proto",
        "ah",
        "spi",
        "0x902",
        "mode",
        "transport",
        "auth-trunc",
        "hmac(sha256)",
        KEY,
        "128",
    ])?;
    ip(&[
        "xfrm",
        "state",
        "add",
        "src",
        "192.0.2.5",
        "dst",
        "192.0.2.6",
        "proto",
        "comp",
        "spi",
        "0x903",
        "mode",
        "transport",
        "comp",
        "deflate",
    ])?;
    let block_policy = |policy_type: &'static str| {
        [
            "xfrm",
            "policy",
            "add",
            "src",
            "198.51.100.1/32",
            "dst",
            "198.51.100.2/32",
            "dir",
            "in",
            "ptype",
            policy_type,
            "action",
            "block",
            "priority",
            "100",
        ]
    };
    ip(&block_policy("main"))?;
    add_sub_policy(&block_policy("sub"))
}

fn assert_empty() -> TestResult {
    assert!(
        ip(&["xfrm", "state", "list"])?.is_empty(),
        "SAD retained an object"
    );
    assert!(
        ip(&["xfrm", "policy", "list"])?.is_empty(),
        "SPD retained an object"
    );
    Ok(())
}

#[test]
fn sub_policy_refusal_requires_the_exact_kernel_response() {
    assert!(sub_policy_add_supported(Some(0), b"", b"").unwrap());
    assert!(!sub_policy_add_supported(Some(2), b"", b"Error: Invalid policy type.\n").unwrap());

    let other_failures: &[(Option<i32>, &[u8], &[u8])] = &[
        (Some(1), b"", b"Error: Invalid policy type.\n"),
        (None, b"", b"Error: Invalid policy type.\n"),
        (
            Some(2),
            b"",
            b"RTNETLINK answers: Operation not permitted\n",
        ),
        (Some(2), b"", b"Error: Invalid argument.\n"),
        (Some(2), b"", b"Error: Invalid policy type.\nfixture values"),
        (Some(2), b"fixture values", b"Error: Invalid policy type.\n"),
        (Some(2), b"", b""),
    ];
    for (code, stdout, stderr) in other_failures {
        let error = sub_policy_add_supported(*code, stdout, stderr).unwrap_err();
        assert_eq!(
            error.to_string(),
            "independent iproute2 sub-policy fixture command failed"
        );
    }
}

#[test]
#[ignore = "requires root, iproute2, AH and IPComp; covers SUB policies when supported or their kernel refusal"]
fn exclusive_namespace_reset_after_process_loss() -> TestResult {
    if !enabled() {
        return Ok(());
    }
    // Even direct invocation without an outer `unshare` cannot touch host XFRM.
    unshare(CloneFlags::CLONE_NEWNET)?;
    add_foreign_objects()?;
    let outer_sad = ip(&["xfrm", "state", "list"])?;
    let outer_spd = ip(&["xfrm", "policy", "list"])?;
    let worker = std::thread::spawn(|| -> TestResult {
        unshare(CloneFlags::CLONE_NEWNET)?;
        ip(&["link", "set", "lo", "up"])?;
        ip(&["link", "add", "reset-proof", "type", "dummy"])?;
        ip(&["route", "add", "blackhole", "203.0.113.0/24"])?;
        ip(&[
            "xfrm",
            "policy",
            "setdefault",
            "in",
            "block",
            "out",
            "block",
            "fwd",
            "block",
        ])?;
        let devices = ip(&["-j", "link", "show"])?;
        let routes = ip(&["-j", "route", "show", "table", "all"])?;
        let defaults = ip(&["xfrm", "policy", "getdefault"])?;
        let root = Root::new()?;
        seed_and_kill(&root.0)?;
        assert!(!ip(&["xfrm", "state", "list"])?.is_empty());
        assert!(!ip(&["xfrm", "policy", "list"])?.is_empty());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            // Independent kernel refusal and an unresolved roster gate are
            // both present before the successor can reset anything.
            assert!(matches!(
                LinuxXfrmBackend::new()
                    .install_sa(InstallSaRequest {
                        parameters: parameters()
                    })
                    .await,
                Err(XfrmError::AlreadyExists)
            ));
            let bound = bind(&root.0)?;
            assert!(bound.0.install_policy(policy()).await.is_err());
            assert!(bound
                .0
                .reset_exclusively_owned_namespace(ack())
                .await
                .is_err());
            drop(bound);
            // The detached actor drains before releasing its store leases.
            let deadline = Instant::now() + Duration::from_secs(5);
            let bound = loop {
                match bind(&root.0) {
                    Ok(bound) => break bound,
                    Err(_) if Instant::now() < deadline => std::thread::yield_now(),
                    Err(error) => return Err(error),
                }
            };
            assert_eq!(
                bound
                    .0
                    .reset_exclusively_owned_namespace(ack())
                    .await?
                    .stores_reset,
                3
            );
            assert_empty()?;
            // Every store is logically empty, including the roster journal;
            // fresh preparation in every family is additionally covered by
            // the deterministic store phase matrix.
            for family in ["objects", "relocations"] {
                assert_eq!(fs::read_dir(root.0.join(family))?.count(), 2);
            }
            assert_eq!(fs::metadata(root.0.join("rosters/journal"))?.len(), 80);
            assert_eq!(
                bound
                    .0
                    .reset_exclusively_owned_namespace(ack())
                    .await?
                    .stores_reset,
                3
            );
            let request = roster()?;
            let authority = bound
                .0
                .prepare_durable_object_roster(
                    &bound.3,
                    XfrmObjectRosterGroupId::from_bytes([1; 16])?,
                    XfrmObjectRosterOperationGeneration::new(1)
                        .ok_or_else(|| io::Error::other("generation"))?,
                    request,
                )
                .await?;
            bound.0.run_durable_object_roster(authority).await?;
            let before = ip(&["xfrm", "state", "list"])?;
            assert!(!before.is_empty());
            assert!(bound
                .0
                .reset_exclusively_owned_namespace(ack())
                .await
                .is_err());
            assert!(before == ip(&["xfrm", "state", "list"])?);
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })?;
        assert!(devices == ip(&["-j", "link", "show"])?);
        assert!(routes == ip(&["-j", "route", "show", "table", "all"])?);
        assert!(defaults == ip(&["xfrm", "policy", "getdefault"])?);
        Ok(())
    });
    worker
        .join()
        .map_err(|_| io::Error::other("reset namespace worker failed"))??;
    assert!(outer_sad == ip(&["xfrm", "state", "list"])?);
    assert!(outer_spd == ip(&["xfrm", "policy", "list"])?);
    println!("XFRM_EXCLUSIVE_NAMESPACE_RESET_PROOF_OK");
    Ok(())
}

#[test]
#[ignore = "private predecessor process for the privileged reset proof"]
fn exclusive_namespace_reset_seed() -> TestResult {
    let Some(root) = std::env::var_os(SEED_ROOT) else {
        return Ok(());
    };
    if !enabled() {
        return Ok(());
    }
    let ready =
        std::env::var_os(SEED_READY).ok_or_else(|| io::Error::other("missing readiness"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let bound = bind(Path::new(&root))?;
        // Allocate a larval ESP SA before retaining unresolved roster authority.
        bound
            .0
            .allocate_spi(AllocateSpiRequest {
                destination: IpAddress::Ipv4([192, 0, 2, 8]),
                protocol: 50,
                min_spi: 0x908,
                max_spi: 0x908,
            })
            .await?;
        let request = roster()?;
        let authority = bound
            .0
            .prepare_durable_object_roster(
                &bound.3,
                XfrmObjectRosterGroupId::from_bytes([1; 16])?,
                XfrmObjectRosterOperationGeneration::new(1)
                    .ok_or_else(|| io::Error::other("generation"))?,
                request,
            )
            .await?;
        bound
            .0
            .detector_cut_roster_issuing_at_member(authority, 1, true)
            .await?;
        let sub_policy = add_foreign_objects()?;
        println!("{}", sub_policy.marker());
        readiness::publish(Path::new(&ready), b"ready")?;
        // Keep the actor and all its leases alive until the parent SIGKILLs us.
        std::thread::sleep(Duration::from_secs(30));
        drop(bound);
        Err::<(), Box<dyn std::error::Error + Send + Sync>>(
            io::Error::other("predecessor was not killed").into(),
        )
    })
}

#[test]
#[ignore = "requires root and iproute2"]
fn exclusive_namespace_reset_empty_namespace() -> TestResult {
    if !enabled() {
        return Ok(());
    }
    unshare(CloneFlags::CLONE_NEWNET)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
        assert_eq!(
            backend
                .reset_exclusively_owned_namespace(ack())
                .await?
                .stores_reset,
            0
        );
        assert_eq!(
            backend
                .reset_exclusively_owned_namespace(ack())
                .await?
                .stores_reset,
            0
        );
        assert_empty()?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })?;
    println!("XFRM_EXCLUSIVE_NAMESPACE_RESET_EMPTY_OK");
    Ok(())
}

#[test]
#[ignore = "requires root, Python and iproute2"]
fn exclusive_namespace_reset_preserves_socket_policy() -> TestResult {
    use std::io::{BufRead, BufReader};
    if !enabled() {
        return Ok(());
    }
    unshare(CloneFlags::CLONE_NEWNET)?;
    // Safe Python socket API supplies a per-socket XFRM policy independently
    // of the SDK. The holder stays alive across flush and readback.
    let mut holder = Seed(
        Command::new("python3")
            .args([
                "-c",
                r#"
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p = bytearray(168)
struct.pack_into('=H', p, 40, socket.AF_INET)
struct.pack_into('=4Q', p, 56, *([2**64-1] * 4))
p[160] = 1  # OUT, stored by Linux at socket direction 4
p[161] = 1  # BLOCK
s.setsockopt(socket.IPPROTO_IP, 17, p)  # IP_XFRM_POLICY
print('ready', flush=True)
sys.stdin.buffer.read(1)
"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut line = String::new();
    BufReader::new(
        holder
            .0
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing holder output"))?,
    )
    .read_line(&mut line)?;
    assert_eq!(line.trim(), "ready");
    let before = ip(&["xfrm", "policy", "list"])?;
    assert!(
        !before.is_empty(),
        "socket policy must be visible to the independent dump"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;
        backend.reset_exclusively_owned_namespace(ack()).await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })?;
    assert!(before == ip(&["xfrm", "policy", "list"])?);
    println!("XFRM_EXCLUSIVE_NAMESPACE_RESET_SOCKET_OK");
    Ok(())
}
