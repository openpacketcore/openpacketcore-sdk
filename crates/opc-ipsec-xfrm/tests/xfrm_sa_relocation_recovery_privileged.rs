//! Privileged, real-process detectors for durable SA relocation recovery.
//!
//! Each detector spawns a child inside a token-derived named network
//! namespace, drives one durable relocation to the requested crash cut, kills
//! it with SIGKILL, and rebinds the retained store from the parent to
//! reconcile against the live kernel through the exact public recovery API.

#![cfg(target_os = "linux")]

use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, ExactRemovePolicyRequest, InstallPolicyRequest, InstallSaRequest,
    IpAddress, KeyMaterial, LifetimeConfig, LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend,
    PolicyParameters, QuerySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest,
    SaParameters, SaRelocationDirection, SaRelocationEncap, SaRelocationIdentity, UdpEncap,
    XfrmAction, XfrmBackend, XfrmCapability, XfrmDirection, XfrmError, XfrmId, XfrmMode,
    XfrmObjectRecoveryBindError, XfrmRequestId, XfrmSaRelocationDurableError,
    XfrmSaRelocationOperationGeneration, XfrmSaRelocationOperationId,
    XfrmSaRelocationRecoveryProofKey, XfrmSaRelocationRecoveryStore,
    XfrmSaRelocationRestartOutcome, XfrmSelector, XfrmTemplate,
};
use sha2::{Digest, Sha256};

const RUN_PRIVILEGED_ENV: &str = "OPC_XFRM_RUN_SA_RELOCATION_RECOVERY_PRIVILEGED";
const CHILD_ROLE_ENV: &str = "OPC_XFRM_SA_RELOCATION_RECOVERY_CHILD_ROLE";
const CHILD_ROOT_ENV: &str = "OPC_XFRM_SA_RELOCATION_RECOVERY_CHILD_ROOT";
const CHILD_TOKEN_ENV: &str = "OPC_XFRM_SA_RELOCATION_RECOVERY_CHILD_TOKEN";
const CHILD_TEST_NAME: &str = "xfrm_sa_relocation_recovery_privileged_child";
const RESOURCE_PREFIX: &str = "opc-xfrm-629-";
const PROVISION_ATTEMPTS: usize = 32;
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_FAILSAFE_TIMEOUT: Duration = Duration::from_secs(30);
const IPPROTO_ESP: u8 = 50;
const IPPROTO_UDP: u8 = 17;
const INBOUND_SPI: u32 = 0x6290_0101;
const OUTBOUND_SPI: u32 = 0x6290_0102;
const ENCAP_SPI: u32 = 0x6290_0103;
const BLOCK_POLICY_IF_ID: u32 = 62_901;
const FOREIGN_SOURCE: IpAddress = IpAddress::Ipv4([203, 0, 113, 7]);

const ROLE_PREPARED_CUT: &str = "sa-reloc-prepared-cut-629";
const ROLE_ISSUING_CUT_BEFORE_EFFECT: &str = "sa-reloc-issuing-cut-before-effect-629";
const ROLE_ISSUING_CUT_AFTER_EFFECT: &str = "sa-reloc-issuing-cut-after-effect-629";
const ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT: &str =
    "sa-reloc-outbound-issuing-cut-after-effect-629";
const ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT: &str = "sa-reloc-encap-only-before-effect-629";
const ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT: &str = "sa-reloc-encap-only-after-effect-629";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn privileged_enabled() -> bool {
    if env::var(RUN_PRIVILEGED_ENV).as_deref() == Ok("1") {
        true
    } else {
        eprintln!("skipping: set {RUN_PRIVILEGED_ENV}=1 on a privileged Linux host");
        false
    }
}

fn ipv4(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn old_destination() -> IpAddress {
    ipv4([192, 0, 2, 62])
}

fn new_destination() -> IpAddress {
    ipv4([198, 51, 100, 20])
}

fn old_source() -> IpAddress {
    ipv4([192, 0, 2, 61])
}

fn new_source() -> IpAddress {
    ipv4([198, 51, 100, 10])
}

fn native_encap() -> Option<UdpEncap> {
    None
}

fn current_natt_encap() -> Option<UdpEncap> {
    Some(UdpEncap::esp_in_udp(4500, 4500))
}

fn relocated_natt_encap() -> UdpEncap {
    UdpEncap::esp_in_udp(4500, 62_900)
}

/// The fixture SA for an address-changing relocation. Each role family uses a
/// distinct SPI so two detectors can never interpret each other's residue.
fn sa_parameters(spi: u32, encap: Option<UdpEncap>) -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(ipv4([10, 62, 9, 1]), ipv4([10, 62, 9, 2]), IPPROTO_UDP),
        id: XfrmId {
            destination: old_destination(),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: old_source(),
        request_id: XfrmRequestId::new(629),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x62; 32]),
        )),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap,
        mark: None,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn sa_install_request(spi: u32, encap: Option<UdpEncap>) -> InstallSaRequest {
    InstallSaRequest {
        parameters: sa_parameters(spi, encap),
    }
}

fn query_at(destination: IpAddress, spi: u32) -> QuerySaRequest {
    QuerySaRequest::new(destination, IPPROTO_ESP, spi)
}

fn removal_at(destination: IpAddress, spi: u32) -> RemoveSaRequest {
    RemoveSaRequest {
        destination,
        protocol: IPPROTO_ESP,
        spi,
        mark: None,
    }
}

fn role_spi(role: &str) -> TestResult<u32> {
    match role {
        ROLE_PREPARED_CUT | ROLE_ISSUING_CUT_BEFORE_EFFECT | ROLE_ISSUING_CUT_AFTER_EFFECT => {
            Ok(INBOUND_SPI)
        }
        ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT => Ok(OUTBOUND_SPI),
        ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT => Ok(ENCAP_SPI),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into()),
    }
}

fn role_encap(role: &str) -> TestResult<Option<UdpEncap>> {
    match role {
        ROLE_PREPARED_CUT
        | ROLE_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_ISSUING_CUT_AFTER_EFFECT
        | ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT => Ok(native_encap()),
        ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT => {
            Ok(current_natt_encap())
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into()),
    }
}

/// Build the role's relocation request against a freshly queried identity.
fn role_relocation_request(
    role: &str,
    current: SaRelocationIdentity,
) -> TestResult<RelocateSaRequest> {
    let direction = match role {
        ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT => {
            SaRelocationDirection::OutboundBlockPolicyInstalled
        }
        ROLE_PREPARED_CUT
        | ROLE_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_ISSUING_CUT_AFTER_EFFECT
        | ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT
        | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT => SaRelocationDirection::Inbound,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into()),
    };
    let same_identity = matches!(
        role,
        ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT
    );
    let (new_source_address, new_destination, encap) = if same_identity {
        // Encapsulation-only relocation at an unchanged XfrmId.
        (
            old_source(),
            old_destination(),
            SaRelocationEncap::Set(relocated_natt_encap()),
        )
    } else {
        (
            new_source(),
            new_destination(),
            SaRelocationEncap::Set(relocated_natt_encap()),
        )
    };
    Ok(RelocateSaRequest {
        current,
        new_source_address,
        new_destination,
        encap,
        direction,
    })
}

fn block_policy_request(spi: u32) -> InstallPolicyRequest {
    let sa = sa_parameters(spi, native_encap());
    InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: sa.selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Block,
            priority: 10,
            templates: vec![XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
            }],
            mark: None,
            if_id: Some(BLOCK_POLICY_IF_ID),
        },
    }
}

fn block_policy_removal(spi: u32) -> ExactRemovePolicyRequest {
    let policy = block_policy_request(spi);
    ExactRemovePolicyRequest::new(RemovePolicyRequest {
        selector: policy.parameters.selector,
        direction: policy.parameters.direction,
        mark: None,
    })
    .with_if_id(BLOCK_POLICY_IF_ID)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build privileged test runtime")
        .block_on(future)
}

fn derived_secret(token: &str, domain: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(token.as_bytes());
    digest.finalize().into()
}

fn proof_key(
    token: &str,
) -> Result<XfrmSaRelocationRecoveryProofKey, XfrmSaRelocationDurableError> {
    let mut bytes = derived_secret(token, b"opc-xfrm-629-proof-key\0");
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    XfrmSaRelocationRecoveryProofKey::new(bytes)
}

fn operation_id(token: &str) -> Result<XfrmSaRelocationOperationId, XfrmSaRelocationDurableError> {
    let digest = derived_secret(token, b"opc-xfrm-629-operation-id\0");
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    XfrmSaRelocationOperationId::from_bytes(bytes)
}

fn operation_generation() -> XfrmSaRelocationOperationGeneration {
    XfrmSaRelocationOperationGeneration::new(1).expect("nonzero test operation generation")
}

fn bind_namespace(namespace: &str) -> TestResult<Arc<NamespaceBoundLinuxXfrmBackend>> {
    let namespace = namespace.to_owned();
    thread::spawn(move || -> TestResult<Arc<NamespaceBoundLinuxXfrmBackend>> {
        let namespace_file = File::open(PathBuf::from("/run/netns").join(namespace))?;
        nix::sched::setns(namespace_file, nix::sched::CloneFlags::CLONE_NEWNET)?;
        Ok(Arc::new(
            LinuxXfrmBackend::new().bind_current_network_namespace()?,
        ))
    })
    .join()
    .map_err(|_| io::Error::other("namespace binding worker panicked"))?
}

fn try_bind_namespace_with_sa_recovery(
    namespace: &str,
    store_path: PathBuf,
    token: &str,
) -> TestResult<
    Result<
        (
            Arc<NamespaceBoundLinuxXfrmBackend>,
            XfrmSaRelocationRecoveryStore,
        ),
        XfrmObjectRecoveryBindError,
    >,
> {
    let namespace = namespace.to_owned();
    let token = token.to_owned();
    thread::spawn(move || -> TestResult<_> {
        let namespace_file = File::open(PathBuf::from("/run/netns").join(namespace))?;
        nix::sched::setns(namespace_file, nix::sched::CloneFlags::CLONE_NEWNET)?;
        Ok(LinuxXfrmBackend::new()
            .bind_current_network_namespace_with_sa_relocation_recovery(
                store_path,
                proof_key(&token)?,
            )
            .map(|(backend, store)| (Arc::new(backend), store)))
    })
    .join()
    .map_err(|_| io::Error::other("namespace recovery binding worker panicked"))?
}

fn bind_namespace_with_sa_recovery(
    namespace: &str,
    fixture: &PrivilegedFixture,
) -> TestResult<(
    Arc<NamespaceBoundLinuxXfrmBackend>,
    XfrmSaRelocationRecoveryStore,
)> {
    Ok(try_bind_namespace_with_sa_recovery(
        namespace,
        fixture.store_path(),
        &fixture.token,
    )??)
}

/// Assert the fixture SA is present with its exact pre-relocation identity.
fn assert_old_sa_intact(backend: &NamespaceBoundLinuxXfrmBackend, spi: u32) -> TestResult {
    let expected = sa_parameters(
        spi,
        if spi == ENCAP_SPI {
            current_natt_encap()
        } else {
            native_encap()
        },
    );
    match block_on(backend.query_sa_relocation_identity(query_at(old_destination(), spi))) {
        Ok(identity) => {
            let expected_identity = SaRelocationIdentity {
                selector: opc_ipsec_xfrm::SaRelocationSelector::from_selector(&expected.selector),
                id: expected.id,
                source_address: expected.source_address,
                request_id: expected.request_id,
                mode: expected.mode,
                encap: expected.encap,
                mark: None,
                if_id: None,
                output_mark: None,
            };
            if identity == expected_identity {
                Ok(())
            } else {
                Err(io::Error::other("old SA readback was not exact").into())
            }
        }
        Err(error) => Err(io::Error::other(format!("old SA was absent: {error}")).into()),
    }
}

fn assert_sa_absent(
    backend: &NamespaceBoundLinuxXfrmBackend,
    destination: IpAddress,
    spi: u32,
) -> TestResult {
    match block_on(backend.query_sa_relocation_identity(query_at(destination, spi))) {
        Err(XfrmError::NotFound) => Ok(()),
        Ok(_) => Err(io::Error::other("SA unexpectedly present").into()),
        Err(error) => Err(error.into()),
    }
}

/// Pre-recovery kernel truth for one detector role.
fn assert_pre_recovery_kernel_state(
    backend: &NamespaceBoundLinuxXfrmBackend,
    role: &str,
    spi: u32,
    old_present_before: bool,
    target_present_before: bool,
) -> TestResult {
    if role == ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT {
        // Same-XfrmId relocation: the residue sits at the shared identity
        // with the resulting encapsulation and new source.
        let observed =
            block_on(backend.query_sa_relocation_identity(query_at(old_destination(), spi)))
                .map_err(|error| {
                    io::Error::other(format!("encap-only residue was absent: {error}"))
                })?;
        if observed.encap != Some(relocated_natt_encap()) || observed.source_address != old_source()
        {
            return Err(io::Error::other("encap-only residue was not exact").into());
        }
        return Ok(());
    }
    if old_present_before {
        assert_old_sa_intact(backend, spi)?;
    } else {
        assert_sa_absent(backend, old_destination(), spi)?;
    }
    if target_present_before {
        let observed =
            block_on(backend.query_sa_relocation_identity(query_at(new_destination(), spi)))
                .map_err(|error| {
                    io::Error::other(format!("expected target residue was absent: {error}"))
                })?;
        if observed.source_address != new_source() {
            return Err(io::Error::other("target residue was not relocated").into());
        }
    } else if role != ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT {
        // The encap-only before-effect cut keeps its SA at the shared
        // identity; a distinct target identity must otherwise be absent.
        assert_sa_absent(backend, new_destination(), spi)?;
    }
    Ok(())
}

fn random_token() -> io::Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = String::with_capacity(random.len() * 2);
    for byte in random {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(token)
}

fn path_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn run_ip(args: &[&str]) -> io::Result<Output> {
    Command::new("ip")
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
}

fn command_error(operation: &'static str, output: &Output) -> io::Error {
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    io::Error::other(format!(
        "{operation} failed with status {}: {}",
        output.status,
        diagnostics.trim()
    ))
}

fn record_first_error(slot: &mut Option<io::Error>, error: io::Error) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn remove_owned_namespace(name: &str) -> io::Result<()> {
    let path = PathBuf::from("/run/netns").join(name);
    if !path_exists(&path)? {
        return Ok(());
    }
    let output = run_ip(&["netns", "del", name])?;
    if !output.status.success() && path_exists(&path)? {
        return Err(command_error("delete owned network namespace", &output));
    }
    if path_exists(&path)? {
        return Err(io::Error::other(
            "owned network namespace remained after deletion",
        ));
    }
    Ok(())
}

/// Count policies carrying the block-policy interface marker in a namespace.
fn block_policy_count(namespace: &str) -> TestResult<usize> {
    let output = run_ip(&[
        "netns", "exec", namespace, "ip", "-j", "xfrm", "policy", "list",
    ])?;
    if !output.status.success() {
        return Err(command_error("list namespace XFRM policies", &output).into());
    }
    let listing = String::from_utf8(output.stdout)?;
    // Some supported iproute2 builds ignore `-j` for `ip xfrm` and render
    // `if_id` as hexadecimal text. Normalizing punctuation makes both that
    // form and JSON's numeric/string forms use the same bounded token parser.
    let normalized: String = listing
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                ' '
            }
        })
        .collect();
    let mut count = 0_usize;
    let mut tokens = normalized.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        if token != "if_id" {
            continue;
        }
        let encoded = tokens
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "if_id value is missing"))?;
        let value = match encoded.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => encoded.parse(),
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "if_id value is malformed"))?;
        if value == BLOCK_POLICY_IF_ID {
            count += 1;
        }
    }
    Ok(count)
}

/// Inject a foreign SA at the target identity through raw iproute2: a
/// non-cooperating writer the durable gate deliberately cannot exclude.
fn inject_foreign_target_sa(namespace: &str, spi: u32) -> TestResult {
    let encoded_spi = format!("0x{spi:08x}");
    let output = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "state",
        "add",
        "dst",
        "198.51.100.20",
        "proto",
        "esp",
        "spi",
        &encoded_spi,
        "mode",
        "tunnel",
        "src",
        "203.0.113.7",
        "enc",
        "cbc(aes)",
        "0x000102030405060708090a0b0c0d0e0f",
    ])?;
    if !output.status.success() {
        return Err(command_error("inject foreign target SA", &output).into());
    }
    Ok(())
}

struct PrivilegedFixture {
    token: String,
    root: PathBuf,
    claim: PathBuf,
    namespaces: Vec<String>,
    cleaned: bool,
}

impl PrivilegedFixture {
    fn provision() -> io::Result<Self> {
        let temporary_root = env::temp_dir();
        for _ in 0..PROVISION_ATTEMPTS {
            let token = random_token()?;
            let stem = format!("{RESOURCE_PREFIX}{token}");
            let claim = temporary_root.join(format!(".{stem}.claim"));
            let mut claim_file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&claim)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            if let Err(error) = claim_file
                .write_all(std::process::id().to_string().as_bytes())
                .and_then(|()| claim_file.sync_all())
            {
                let _ = fs::remove_file(&claim);
                return Err(error);
            }

            let root = temporary_root.join(&stem);
            match DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&claim)?;
                    continue;
                }
                Err(error) => {
                    let _ = fs::remove_file(&claim);
                    return Err(error);
                }
            }
            let coordination = root.join("coordination");
            if let Err(error) = DirBuilder::new().mode(0o700).create(&coordination) {
                let _ = fs::remove_dir(&root);
                let _ = fs::remove_file(&claim);
                return Err(error);
            }

            let mut candidate = Self {
                token,
                root,
                claim,
                namespaces: Vec::with_capacity(2),
                cleaned: false,
            };
            let mut collision = false;
            for suffix in ["a", "b"] {
                let name = format!("opc629-{}-{suffix}", candidate.token);
                let namespace_path = PathBuf::from("/run/netns").join(&name);
                if path_exists(&namespace_path)? {
                    collision = true;
                    break;
                }
                let output = run_ip(&["netns", "add", &name])?;
                if output.status.success() {
                    candidate.namespaces.push(name);
                } else if path_exists(&namespace_path)? {
                    // Creation did not establish ownership. Leave the path
                    // untouched and retry with a fresh random identity.
                    collision = true;
                    break;
                } else {
                    return Err(command_error(
                        "create collision-free network namespace",
                        &output,
                    ));
                }
            }

            if collision {
                candidate.cleanup()?;
                continue;
            }

            return Ok(candidate);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not claim a collision-free privileged test identity",
        ))
    }

    fn namespace_a(&self) -> &str {
        &self.namespaces[0]
    }

    fn namespace_b(&self) -> &str {
        &self.namespaces[1]
    }

    fn store_path(&self) -> PathBuf {
        self.root.join("store")
    }

    fn ready_path(&self, role: &str) -> PathBuf {
        self.root.join("coordination").join(format!("{role}.ready"))
    }

    fn readiness_bytes(&self, role: &str, child_pid: u32) -> Vec<u8> {
        format!("{}:{role}:{child_pid}:ready\n", self.token).into_bytes()
    }

    fn child_command(&self, namespace: &str, role: &str) -> io::Result<Command> {
        let executable = env::current_exe()?;
        let mut command = Command::new("ip");
        command
            .arg("netns")
            .arg("exec")
            .arg(namespace)
            .arg(executable)
            .args([
                "--exact",
                CHILD_TEST_NAME,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ROLE_ENV, role)
            .env(CHILD_ROOT_ENV, &self.root)
            .env(CHILD_TOKEN_ENV, &self.token)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(command)
    }

    fn cleanup(mut self) -> io::Result<()> {
        let mut first_error = None;
        cleanup_owned_resources(
            &mut self.namespaces,
            &self.root,
            &self.claim,
            &mut first_error,
        );
        self.cleaned = first_error.is_none()
            && !path_exists(&self.root)?
            && !path_exists(&self.claim)?
            && self.namespaces.is_empty();
        if !self.cleaned && first_error.is_none() {
            first_error = Some(io::Error::other(
                "privileged fixture cleanup assertions failed",
            ));
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for PrivilegedFixture {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let mut first_error = None;
        cleanup_owned_resources(
            &mut self.namespaces,
            &self.root,
            &self.claim,
            &mut first_error,
        );
        self.cleaned = true;
    }
}

fn cleanup_owned_resources(
    namespaces: &mut Vec<String>,
    root: &Path,
    claim: &Path,
    first_error: &mut Option<io::Error>,
) {
    let owned_names = std::mem::take(namespaces);
    for name in owned_names.into_iter().rev() {
        if let Err(error) = remove_owned_namespace(&name) {
            namespaces.push(name);
            record_first_error(first_error, error);
        }
    }

    if let Err(error) = fs::remove_dir_all(root) {
        if error.kind() != io::ErrorKind::NotFound {
            record_first_error(first_error, error);
        }
    }
    let root_removed = match path_exists(root) {
        Ok(false) => true,
        Ok(true) => {
            record_first_error(
                first_error,
                io::Error::other("owned store root remained after cleanup"),
            );
            false
        }
        Err(error) => {
            record_first_error(first_error, error);
            false
        }
    };

    // Keep the exclusive claim if either namespace or the store root could
    // not be retired. A future random collision must never reinterpret those
    // leftovers as newly owned resources.
    if !namespaces.is_empty() || !root_removed {
        return;
    }

    if let Err(error) = fs::remove_file(claim) {
        if error.kind() != io::ErrorKind::NotFound {
            record_first_error(first_error, error);
        }
    }
    match path_exists(claim) {
        Ok(false) => {}
        Ok(true) => record_first_error(
            first_error,
            io::Error::other("owned resource claim remained after cleanup"),
        ),
        Err(error) => record_first_error(first_error, error),
    }
}

fn publish_readiness(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("readiness path has no parent"))?,
    )?
    .sync_all()
}

struct TestChild {
    child: Option<Child>,
}

impl TestChild {
    fn spawn(mut command: Command) -> io::Result<Self> {
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("child was already reaped"))?
            .try_wait()
    }

    fn id(&self) -> io::Result<u32> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::other("child was already reaped"))
    }

    fn wait_for_readiness(&mut self, path: &Path, expected: &[u8]) -> io::Result<()> {
        let deadline = Instant::now() + CHILD_READY_TIMEOUT;
        loop {
            match fs::read(path) {
                Ok(actual) if actual == expected => return Ok(()),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "child published malformed readiness evidence",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if let Some(status) = self.try_wait()? {
                return Err(io::Error::other(format!(
                    "child exited before readiness with status {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child readiness deadline elapsed",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn kill_and_reap(mut self) -> io::Result<Output> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| io::Error::other("child was already reaped"))?;
        child.kill()?;
        wait_for_exit(child, CHILD_EXIT_TIMEOUT)?;
        self.child
            .take()
            .ok_or_else(|| io::Error::other("child was already reaped"))?
            .wait_with_output()
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = wait_for_exit(&mut child, CHILD_EXIT_TIMEOUT);
            }
            let _ = child.wait();
        }
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child exit deadline elapsed",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_sigkill(output: &Output) -> io::Result<()> {
    if output.status.signal() == Some(nix::libc::SIGKILL) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "child did not terminate via SIGKILL: status {}",
            output.status
        )))
    }
}

fn child_wait_for_sigkill() -> ! {
    thread::sleep(CHILD_FAILSAFE_TIMEOUT);
    panic!("privileged recovery child was not killed by its parent")
}

fn child_context() -> io::Result<Option<(String, PathBuf, String)>> {
    let Some(role) = env::var_os(CHILD_ROLE_ENV) else {
        return Ok(None);
    };
    let role = role
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 child role"))?;
    let root = PathBuf::from(
        env::var_os(CHILD_ROOT_ENV)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing child root"))?,
    );
    let token = env::var(CHILD_TOKEN_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "missing child token"))?;
    Ok(Some((role, root, token)))
}

fn issuing_cut_admits_effect(role: &str) -> bool {
    matches!(
        role,
        ROLE_ISSUING_CUT_AFTER_EFFECT
            | ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT
            | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT
    )
}

fn run_sa_relocation_crash_child(role: &str, root: &Path, token: &str) -> TestResult {
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_sa_relocation_recovery(
            root.join("store"),
            proof_key(token)?,
        )?;
    let spi = role_spi(role)?;
    let encap = role_encap(role)?;
    block_on(backend.install_sa(sa_install_request(spi, encap)))?;

    // The outbound detector asserts the consumer-owned temporary block policy
    // survives recovery; the child installs it exactly as the product would.
    if role == ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT {
        block_on(backend.install_policy(block_policy_request(spi)))?;
    }

    let current = block_on(backend.query_sa_relocation_identity(query_at(old_destination(), spi)))?;
    let request = role_relocation_request(role, current)?;
    let target_query = query_at(request.new_destination, spi);

    if role == ROLE_PREPARED_CUT {
        let _authority = block_on(backend.prepare_sa_relocation(
            &store,
            operation_id(token)?,
            operation_generation(),
            request,
        ))?;
    } else {
        let admit_effect = issuing_cut_admits_effect(role);
        let authority = block_on(backend.prepare_sa_relocation(
            &store,
            operation_id(token)?,
            operation_generation(),
            request,
        ))?;
        block_on(backend.detector_cut_prepared_sa_relocation_issuing(authority, admit_effect))?;
        if admit_effect {
            // The cut seam intentionally ignores the effect result to model a
            // crash before terminal publication. A silently failed migration
            // would make the parent misread the crash window, so surface it
            // here instead of publishing readiness.
            if block_on(backend.query_sa_relocation_identity(target_query)).is_err() {
                return Err(io::Error::other("relocation effect did not reach the kernel").into());
            }
        }
    }

    let ready_path = root.join("coordination").join(format!("{role}.ready"));
    let evidence = format!("{token}:{role}:{}:ready\n", std::process::id());
    publish_readiness(&ready_path, evidence.as_bytes())?;
    child_wait_for_sigkill()
}

#[test]
#[ignore = "child role launched only by the privileged parent detector"]
fn xfrm_sa_relocation_recovery_privileged_child() -> TestResult {
    let Some((role, root, token)) = child_context()? else {
        return Ok(());
    };
    match role.as_str() {
        ROLE_PREPARED_CUT
        | ROLE_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_ISSUING_CUT_AFTER_EFFECT
        | ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT
        | ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT
        | ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT => run_sa_relocation_crash_child(&role, &root, &token),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into()),
    }
}

fn crash_sa_relocation_operation(
    fixture: &PrivilegedFixture,
    namespace: &str,
    role: &str,
) -> TestResult {
    let ready_path = fixture.ready_path(role);
    let mut child = TestChild::spawn(fixture.child_command(namespace, role)?)?;
    let ready_bytes = fixture.readiness_bytes(role, child.id()?);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;
    Ok(())
}

fn role_request_for_parent(
    role: &str,
    current: SaRelocationIdentity,
) -> TestResult<RelocateSaRequest> {
    role_relocation_request(role, current)
}

/// Rebuild the role's request on the parent from a fresh kernel readback of
/// the old identity (prepared/before-effect detectors) or from the bound
/// fixture identity (after-effect detectors where the old tuple is gone).
fn parent_request_from_old_identity(
    backend: &NamespaceBoundLinuxXfrmBackend,
    role: &str,
) -> TestResult<RelocateSaRequest> {
    let spi = role_spi(role)?;
    let current = block_on(backend.query_sa_relocation_identity(query_at(old_destination(), spi)))?;
    role_request_for_parent(role, current)
}

/// One real-process recovery detector: crash the child at the role's cut,
/// reconcile through the public API, and prove the kernel/gate contract.
fn sa_relocation_recovery_detector(
    role: &str,
    expected_outcome: &'static str,
    old_present_before: bool,
    target_present_before: bool,
) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    assert!(
        !path_exists(&fixture.store_path())?,
        "the durable API must exclusively create its own store"
    );
    let spi = role_spi(role)?;

    // After-effect detectors require the real exact single-SA migration UAPI.
    // Probe it inside the target namespace first and skip cleanly on kernels
    // without it, exactly like the capability-gated relocation proof.
    if issuing_cut_admits_effect(role) {
        let probe = bind_namespace(fixture.namespace_a())?;
        let capability = block_on(probe.sa_relocation_capability())?;
        drop(probe);
        if !matches!(capability, XfrmCapability::Available) {
            eprintln!("skipping {role}: kernel does not expose the exact single-SA migration UAPI");
            fixture.cleanup()?;
            return Ok(());
        }
    }

    // Keep an identical object in the foreign namespace so recovery in
    // namespace A is also crossed against the namespace boundary.
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    block_on(foreign_backend.install_sa(sa_install_request(spi, role_encap(role)?)))?;
    drop(foreign_backend);

    crash_sa_relocation_operation(&fixture, fixture.namespace_a(), role)?;

    let (backend, store) = bind_namespace_with_sa_recovery(fixture.namespace_a(), &fixture)?;
    assert_pre_recovery_kernel_state(
        &backend,
        role,
        spi,
        old_present_before,
        target_present_before,
    )?;

    // While the cut record stays unresolved, the writer gate must reject
    // every cooperating mutation before any kernel effect.
    let gated = block_on(backend.install_sa(sa_install_request(spi, role_encap(role)?)));
    assert!(
        matches!(gated, Err(XfrmError::Unavailable)),
        "unresolved relocation record must gate cooperating mutations"
    );
    assert_pre_recovery_kernel_state(
        &backend,
        role,
        spi,
        old_present_before,
        target_present_before,
    )?;

    let request = if role == ROLE_ISSUING_CUT_AFTER_EFFECT
        || role == ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT
        || role == ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT
    {
        // The old tuple is gone; rebuild the request from the fixture
        // identity the child bound.
        let current = {
            let parameters = sa_parameters(spi, role_encap(role)?);
            SaRelocationIdentity {
                selector: opc_ipsec_xfrm::SaRelocationSelector::from_selector(&parameters.selector),
                id: parameters.id,
                source_address: parameters.source_address,
                request_id: parameters.request_id,
                mode: parameters.mode,
                encap: parameters.encap,
                mark: None,
                if_id: None,
                output_mark: None,
            }
        };
        role_request_for_parent(role, current)?
    } else {
        parent_request_from_old_identity(&backend, role)?
    };

    let outcome = block_on(backend.recover_durable_sa_relocation(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        request.clone(),
    ))?;
    assert_eq!(outcome.as_str(), expected_outcome);

    // Post-recovery kernel state.
    match expected_outcome {
        "owned_residue_retired" => {
            assert_sa_absent(&backend, request.new_destination, spi)?;
            if request.new_destination != request.current.id.destination {
                assert_sa_absent(&backend, old_destination(), spi)?;
            }
        }
        "no_mutation" => {
            assert_old_sa_intact(&backend, spi)?;
        }
        "foreign_untouched" => {
            assert_old_sa_intact(&backend, spi)?;
        }
        _ => {
            return Err(io::Error::other("unexpected detector outcome").into());
        }
    }
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    assert_old_sa_intact(&foreign_backend, spi)?;
    drop(foreign_backend);

    // Repeat recovery is idempotent and performs no further kernel work.
    // (Asserted before the admission proof below: admitted mutations burn a
    // writer epoch, which prunes the retired record.)
    let repeated = block_on(backend.recover_durable_sa_relocation(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        request.clone(),
    ))?;
    assert!(matches!(
        repeated,
        XfrmSaRelocationRestartOutcome::Retired | XfrmSaRelocationRestartOutcome::NoMutation
    ));

    // Recovery retired the record, so the gate reopens. Prove admission with
    // clean same-identity mutations and leave the namespace clean.
    if role == ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT {
        // The consumer-owned block policy must have survived recovery; the
        // reopened gate now admits its exact removal.
        assert_eq!(block_policy_count(fixture.namespace_a())?, 1);
        block_on(backend.remove_policy_exact(block_policy_removal(spi)))?;
        assert_eq!(block_policy_count(fixture.namespace_a())?, 0);
    }
    if matches!(expected_outcome, "no_mutation" | "foreign_untouched") {
        // The recovery deliberately left the old SA alive; retire it through
        // the reopened gate before the clean admission proof below.
        block_on(backend.remove_sa(removal_at(old_destination(), spi)))?;
    }
    block_on(backend.install_sa(sa_install_request(spi, role_encap(role)?)))?;
    block_on(backend.remove_sa(removal_at(old_destination(), spi)))?;
    if matches!(expected_outcome, "foreign_untouched") && role != ROLE_PREPARED_CUT {
        // The injected/remaining foreign target state is removable through
        // the reopened gate with its exact identity.
        block_on(backend.remove_sa(removal_at(request.new_destination, spi)))?;
    }

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn prepared_sa_relocation_recovers_no_mutation() -> TestResult {
    sa_relocation_recovery_detector(ROLE_PREPARED_CUT, "no_mutation", true, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_before_effect_recovers_no_mutation() -> TestResult {
    sa_relocation_recovery_detector(ROLE_ISSUING_CUT_BEFORE_EFFECT, "no_mutation", true, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_after_effect_retires_owned_residue() -> TestResult {
    sa_relocation_recovery_detector(
        ROLE_ISSUING_CUT_AFTER_EFFECT,
        "owned_residue_retired",
        false,
        true,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn outbound_block_policy_survives_issuing_cut_recovery() -> TestResult {
    sa_relocation_recovery_detector(
        ROLE_OUTBOUND_ISSUING_CUT_AFTER_EFFECT,
        "owned_residue_retired",
        false,
        true,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn encap_only_issuing_cut_before_effect_recovers_no_mutation() -> TestResult {
    sa_relocation_recovery_detector(
        ROLE_ENCAP_ONLY_CUT_BEFORE_EFFECT,
        "no_mutation",
        true,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn encap_only_issuing_cut_after_effect_retires_owned_residue() -> TestResult {
    sa_relocation_recovery_detector(
        ROLE_ENCAP_ONLY_CUT_AFTER_EFFECT,
        "owned_residue_retired",
        true,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn foreign_replacement_at_target_is_left_untouched() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let role = ROLE_ISSUING_CUT_BEFORE_EFFECT;
    let spi = role_spi(role)?;
    crash_sa_relocation_operation(&fixture, fixture.namespace_a(), role)?;

    // After the crash, a non-cooperating writer occupies the target identity
    // with state that matches neither the bound current identity nor the
    // relocation expectation.
    inject_foreign_target_sa(fixture.namespace_a(), spi)?;

    let (backend, store) = bind_namespace_with_sa_recovery(fixture.namespace_a(), &fixture)?;
    assert_old_sa_intact(&backend, spi)?;
    let request = parent_request_from_old_identity(&backend, role)?;

    // The unresolved record still gates cooperating mutations.
    let gated = block_on(backend.install_sa(sa_install_request(spi, native_encap())));
    assert!(matches!(gated, Err(XfrmError::Unavailable)));

    let outcome = block_on(backend.recover_durable_sa_relocation(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        request.clone(),
    ))?;
    assert!(matches!(
        outcome,
        XfrmSaRelocationRestartOutcome::ForeignUntouched
    ));

    // Neither the intact old SA nor the foreign target state was deleted.
    assert_old_sa_intact(&backend, spi)?;
    let foreign_identity =
        block_on(backend.query_sa_relocation_identity(query_at(new_destination(), spi)))?;
    if foreign_identity.source_address != FOREIGN_SOURCE {
        return Err(io::Error::other("foreign target state was modified").into());
    }

    // Repeat recovery is idempotent (asserted before the cleanup mutations:
    // admitted mutations burn a writer epoch, which prunes retired records).
    let repeated = block_on(backend.recover_durable_sa_relocation(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        request,
    ))?;
    assert!(matches!(
        repeated,
        XfrmSaRelocationRestartOutcome::Retired | XfrmSaRelocationRestartOutcome::NoMutation
    ));

    // The reopened gate admits clean same-identity mutations; remove both
    // states through their exact identities.
    block_on(backend.remove_sa(removal_at(old_destination(), spi)))?;
    block_on(backend.remove_sa(removal_at(new_destination(), spi)))?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn wrong_namespace_store_binding_fails_closed() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let role = ROLE_ISSUING_CUT_BEFORE_EFFECT;
    let spi = role_spi(role)?;
    crash_sa_relocation_operation(&fixture, fixture.namespace_a(), role)?;

    // Binding the retained store from another namespace must fail closed
    // even though the object shape is identical there.
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    block_on(foreign_backend.install_sa(sa_install_request(spi, native_encap())))?;
    drop(foreign_backend);
    let wrong_binding = try_bind_namespace_with_sa_recovery(
        fixture.namespace_b(),
        fixture.store_path(),
        &fixture.token,
    )?
    .expect_err("store from another namespace must be rejected");
    assert!(matches!(
        wrong_binding,
        XfrmObjectRecoveryBindError::SaRelocationStore {
            source: XfrmSaRelocationDurableError::WrongBinding
        }
    ));

    let (backend, store) = bind_namespace_with_sa_recovery(fixture.namespace_a(), &fixture)?;
    assert_old_sa_intact(&backend, spi)?;
    let request = parent_request_from_old_identity(&backend, role)?;
    let outcome = block_on(backend.recover_durable_sa_relocation(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        request,
    ))?;
    assert!(matches!(
        outcome,
        XfrmSaRelocationRestartOutcome::NoMutation
    ));
    assert_old_sa_intact(&backend, spi)?;
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    assert_old_sa_intact(&foreign_backend, spi)?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}
