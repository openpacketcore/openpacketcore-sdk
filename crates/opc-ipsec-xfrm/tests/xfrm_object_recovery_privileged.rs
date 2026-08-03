//! Privileged, real-process detectors for durable single-object XFRM recovery.

#![cfg(target_os = "linux")]

use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, ExactRemovePolicyRequest, InstallPolicyRequest, InstallSaRequest,
    IpAddress, KeyMaterial, LifetimeConfig, LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend,
    PolicyParameters, QuerySaRequest, RemovePolicyRequest, RemoveSaRequest, SaParameters,
    XfrmAction, XfrmBackend, XfrmDirection, XfrmError, XfrmId, XfrmMode,
    XfrmObjectInstallDurableError, XfrmObjectInstallDurableOutcome, XfrmObjectInstallDurablePhase,
    XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
    XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRecoveryStore, XfrmObjectInstallRequest,
    XfrmObjectInstallRestartOutcome, XfrmObjectRecoveryBindError, XfrmObjectRecoveryProofKey,
    XfrmRequestId, XfrmSelector, XfrmTemplate, XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES,
};
use sha2::{Digest, Sha256};

const RUN_PRIVILEGED_ENV: &str = "OPC_XFRM_RUN_OBJECT_RECOVERY_PRIVILEGED";
const CHILD_ROLE_ENV: &str = "OPC_XFRM_OBJECT_RECOVERY_CHILD_ROLE";
const CHILD_ROOT_ENV: &str = "OPC_XFRM_OBJECT_RECOVERY_CHILD_ROOT";
const CHILD_TOKEN_ENV: &str = "OPC_XFRM_OBJECT_RECOVERY_CHILD_TOKEN";
const CHILD_TEST_NAME: &str = "xfrm_object_recovery_privileged_child";
const RESOURCE_PREFIX: &str = "opc-xfrm-616-";
const PROVISION_ATTEMPTS: usize = 32;
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_FAILSAFE_TIMEOUT: Duration = Duration::from_secs(30);
const IPPROTO_ESP: u8 = 50;
const IPPROTO_UDP: u8 = 17;
const TEST_SPI: u32 = 0x6160_0001;
const POLICY_IF_ID_OWNED: u32 = 61_601;
const POLICY_IF_ID_NEIGHBOR: u32 = 61_602;
const ROLE_HARNESS_SIGKILL: &str = "harness-sigkill";
const ROLE_SA_ACQUIRED: &str = "sa-acquired";
const ROLE_SA_NO_MUTATION: &str = "sa-no-mutation";
const ROLE_POLICY_ACQUIRED: &str = "policy-acquired";
const ROLE_SA_PREPARED_BEFORE_ADMISSION: &str = "sa-prepared-before-admission-621";
const ROLE_SA_PREPARED_POLL_ADMITTED: &str = "sa-prepared-poll-admitted-621";
const ROLE_POLICY_PREPARED_BEFORE_ADMISSION: &str = "policy-prepared-before-admission-621";
const ROLE_POLICY_PREPARED_POLL_ADMITTED: &str = "policy-prepared-poll-admitted-621";
const ROLE_SA_ISSUING_CUT_BEFORE_EFFECT: &str = "sa-issuing-cut-before-effect-628";
const ROLE_POLICY_ISSUING_CUT_BEFORE_EFFECT: &str = "policy-issuing-cut-before-effect-628";
const ROLE_SA_ISSUING_CUT_AFTER_EFFECT: &str = "sa-issuing-cut-after-effect-628";
const ROLE_POLICY_ISSUING_CUT_AFTER_EFFECT: &str = "policy-issuing-cut-after-effect-628";
const ROLE_SA_ISSUING_CUT_CONFLICT: &str = "sa-issuing-cut-conflict-628";
const ROLE_POLICY_ISSUING_CUT_CONFLICT: &str = "policy-issuing-cut-conflict-628";

const RECORD_BODY_BYTES: usize = 176;
const ACTOR_INCARNATION_RANGE: std::ops::Range<usize> = 64..80;
const RECORD_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-record-v1\0";

type HmacSha256 = Hmac<Sha256>;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn privileged_enabled() -> bool {
    if env::var(RUN_PRIVILEGED_ENV).as_deref() == Ok("1") {
        true
    } else {
        eprintln!("skipping: set {RUN_PRIVILEGED_ENV}=1 on a privileged Linux host");
        false
    }
}

fn ip(value: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(value)
}

fn sa_parameters() -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(ip([10, 61, 6, 1]), ip([10, 61, 6, 2]), IPPROTO_UDP),
        id: XfrmId {
            destination: ip([192, 0, 2, 62]),
            spi: TEST_SPI,
            protocol: IPPROTO_ESP,
        },
        source_address: ip([192, 0, 2, 61]),
        request_id: XfrmRequestId::new(616),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x61; 32]),
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

fn sa_install_request() -> InstallSaRequest {
    InstallSaRequest {
        parameters: sa_parameters(),
    }
}

fn sa_object_request() -> XfrmObjectInstallRequest {
    XfrmObjectInstallRequest::Sa(sa_install_request())
}

fn sa_query_request() -> QuerySaRequest {
    let id = sa_parameters().id;
    QuerySaRequest::new(id.destination, id.protocol, id.spi)
}

fn sa_remove_request() -> RemoveSaRequest {
    let id = sa_parameters().id;
    RemoveSaRequest {
        destination: id.destination,
        protocol: id.protocol,
        spi: id.spi,
        mark: None,
    }
}

fn policy_install_request(if_id: u32) -> InstallPolicyRequest {
    let sa = sa_parameters();
    InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: sa.selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 616,
            templates: vec![XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
            }],
            mark: None,
            if_id: Some(if_id),
        },
    }
}

fn policy_object_request(if_id: u32) -> XfrmObjectInstallRequest {
    XfrmObjectInstallRequest::Policy(policy_install_request(if_id))
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

fn proof_key_bytes(token: &str) -> [u8; 32] {
    let mut bytes = derived_secret(token, b"opc-xfrm-616-proof-key\0");
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    bytes
}

fn proof_key(token: &str) -> Result<XfrmObjectRecoveryProofKey, XfrmObjectInstallDurableError> {
    XfrmObjectRecoveryProofKey::new(proof_key_bytes(token))
}

fn operation_id(
    token: &str,
) -> Result<XfrmObjectInstallOperationId, XfrmObjectInstallDurableError> {
    let digest = derived_secret(token, b"opc-xfrm-616-operation-id\0");
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    XfrmObjectInstallOperationId::from_bytes(bytes)
}

fn operation_generation() -> XfrmObjectInstallOperationGeneration {
    XfrmObjectInstallOperationGeneration::new(1).expect("nonzero test operation generation")
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

fn try_bind_namespace_with_recovery(
    namespace: &str,
    store_path: PathBuf,
    token: &str,
) -> TestResult<
    Result<
        (
            Arc<NamespaceBoundLinuxXfrmBackend>,
            XfrmObjectInstallRecoveryStore,
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
            .bind_current_network_namespace_with_object_recovery(store_path, proof_key(&token)?)
            .map(|(backend, store)| (Arc::new(backend), store)))
    })
    .join()
    .map_err(|_| io::Error::other("namespace recovery binding worker panicked"))?
}

fn bind_namespace_with_recovery(
    namespace: &str,
    fixture: &PrivilegedFixture,
) -> TestResult<(
    Arc<NamespaceBoundLinuxXfrmBackend>,
    XfrmObjectInstallRecoveryStore,
)> {
    Ok(try_bind_namespace_with_recovery(
        namespace,
        fixture.store_path(),
        &fixture.token,
    )??)
}

fn assert_sa_presence(
    backend: &NamespaceBoundLinuxXfrmBackend,
    expected_present: bool,
) -> TestResult {
    match block_on(backend.query_sa(sa_query_request())) {
        Ok(state) => {
            if !expected_present {
                return Err(io::Error::other("unexpected matching SA remained").into());
            }
            let expected = sa_parameters();
            if state.id != expected.id
                || state.selector != expected.selector
                || state.source_address != expected.source_address
                || state.request_id != expected.request_id
                || state.mode != expected.mode
            {
                return Err(io::Error::other("matching SA readback was not exact").into());
            }
            Ok(())
        }
        Err(XfrmError::NotFound) if !expected_present => Ok(()),
        Err(XfrmError::NotFound) => Err(io::Error::other("expected matching SA was absent").into()),
        Err(error) => Err(error.into()),
    }
}

fn policy_if_id_count(namespace: &str, if_id: u32) -> TestResult<usize> {
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
        if value == if_id {
            count += 1;
        }
    }
    Ok(count)
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
                let name = format!("opc616-{}-{suffix}", candidate.token);
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

    fn handle_path(&self, role: &str) -> PathBuf {
        self.root
            .join("coordination")
            .join(format!("{role}.handle"))
    }

    fn poll_admitted_path(&self, role: &str) -> PathBuf {
        self.root
            .join("coordination")
            .join(format!("{role}.poll-admitted"))
    }

    fn readiness_bytes(&self, role: &str, child_pid: u32) -> Vec<u8> {
        format!("{}:{role}:{child_pid}:ready\n", self.token).into_bytes()
    }

    fn poll_admitted_bytes(&self, role: &str, child_pid: u32) -> Vec<u8> {
        format!("{}:{role}:{child_pid}:PollAdmitted\n", self.token).into_bytes()
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

fn read_recovery_handle(path: &Path) -> io::Result<XfrmObjectInstallRecoveryHandle> {
    let bytes = fs::read(path)?;
    let encoded: [u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid recovery handle size"))?;
    Ok(XfrmObjectInstallRecoveryHandle::from_bytes(encoded))
}

fn authenticated_wrong_incarnation_record(
    mut encoded: [u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES],
    key: &[u8; 32],
) -> TestResult<[u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES]> {
    let original = encoded[ACTOR_INCARNATION_RANGE].to_vec();
    encoded[ACTOR_INCARNATION_RANGE].fill(0x5a);
    if original == encoded[ACTOR_INCARNATION_RANGE] {
        encoded[ACTOR_INCARNATION_RANGE].fill(0xa5);
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::other("construct recovery-record authenticator"))?;
    mac.update(RECORD_AUTH_DOMAIN);
    mac.update(&encoded[..RECORD_BODY_BYTES]);
    encoded[RECORD_BODY_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(encoded)
}

fn poison_acquired_record_incarnation(store_root: &Path, key: &[u8; 32]) -> TestResult {
    let mut acquired = Vec::new();
    for entry in fs::read_dir(store_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 store entry"))?;
        if name.starts_with("acquired-") {
            acquired.push(entry.path());
        }
    }
    if acquired.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected exactly one acquired durable record",
        )
        .into());
    }
    let record_path = acquired
        .pop()
        .ok_or_else(|| io::Error::other("acquired durable record disappeared"))?;
    let path_metadata = fs::symlink_metadata(&record_path)?;
    if !path_metadata.file_type().is_file()
        || path_metadata.mode() & 0o7777 != 0o600
        || path_metadata.nlink() != 1
        || path_metadata.len() != XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "acquired durable record metadata is invalid",
        )
        .into());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(&record_path)?;
    let descriptor_metadata = file.metadata()?;
    if descriptor_metadata.dev() != path_metadata.dev()
        || descriptor_metadata.ino() != path_metadata.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "acquired durable record identity changed while opening",
        )
        .into());
    }
    let mut encoded = [0_u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES];
    file.read_exact(&mut encoded)?;
    let poisoned = authenticated_wrong_incarnation_record(encoded, key)?;
    file.rewind()?;
    file.write_all(&poisoned)?;
    file.sync_all()?;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(store_root)?;
    directory.sync_all()?;
    let final_metadata = file.metadata()?;
    if !final_metadata.file_type().is_file()
        || final_metadata.mode() & 0o7777 != 0o600
        || final_metadata.nlink() != 1
        || final_metadata.len() != XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "poisoned durable record metadata changed",
        )
        .into());
    }
    Ok(())
}

fn durable_child_request(role: &str) -> TestResult<XfrmObjectInstallRequest> {
    match role {
        ROLE_SA_ACQUIRED
        | ROLE_SA_NO_MUTATION
        | ROLE_SA_PREPARED_BEFORE_ADMISSION
        | ROLE_SA_PREPARED_POLL_ADMITTED
        | ROLE_SA_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_SA_ISSUING_CUT_AFTER_EFFECT
        | ROLE_SA_ISSUING_CUT_CONFLICT => Ok(sa_object_request()),
        ROLE_POLICY_ACQUIRED
        | ROLE_POLICY_PREPARED_BEFORE_ADMISSION
        | ROLE_POLICY_PREPARED_POLL_ADMITTED
        | ROLE_POLICY_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_POLICY_ISSUING_CUT_AFTER_EFFECT
        | ROLE_POLICY_ISSUING_CUT_CONFLICT => Ok(policy_object_request(POLICY_IF_ID_OWNED)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown durable child role").into()),
    }
}

/// Whether the issuing-cut child installs the object before cutting, so the
/// readback witnesses a conflict. Used for the foreign-untouched detectors.
fn issuing_cut_preinstalls_conflict(role: &str) -> bool {
    matches!(
        role,
        ROLE_SA_ISSUING_CUT_CONFLICT | ROLE_POLICY_ISSUING_CUT_CONFLICT
    )
}

/// Whether the issuing-cut child admits the backend effect after the durable
/// `Issuing` publication, modelling a crash after kernel creation.
fn issuing_cut_admits_effect(role: &str) -> bool {
    matches!(
        role,
        ROLE_SA_ISSUING_CUT_AFTER_EFFECT | ROLE_POLICY_ISSUING_CUT_AFTER_EFFECT
    )
}

fn run_issuing_cut_crash_child(role: &str, root: &Path, token: &str) -> TestResult {
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_object_recovery(
            root.join("store"),
            proof_key(token)?,
        )?;
    let request = durable_child_request(role)?;

    // For the conflict detectors the exact identity already exists, so the
    // pre-effect readback witnesses `Conflict` and the install cannot create it.
    if issuing_cut_preinstalls_conflict(role) {
        match &request {
            XfrmObjectInstallRequest::Sa(request) => block_on(backend.install_sa(request.clone()))?,
            XfrmObjectInstallRequest::Policy(request) => {
                block_on(backend.install_policy(request.clone()))?
            }
        }
    }

    let authority = block_on(backend.prepare_durable_object_install(
        &store,
        operation_id(token)?,
        operation_generation(),
        request,
    ))?;
    block_on(backend.detector_cut_prepared_issuing(authority, issuing_cut_admits_effect(role)))?;

    let ready_path = root.join("coordination").join(format!("{role}.ready"));
    let evidence = format!("{token}:{role}:{}:ready\n", std::process::id());
    publish_readiness(&ready_path, evidence.as_bytes())?;
    child_wait_for_sigkill()
}

fn run_durable_crash_child(role: &str, root: &Path, token: &str) -> TestResult {
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_object_recovery(
            root.join("store"),
            proof_key(token)?,
        )?;
    let authority = block_on(backend.prepare_durable_object_install(
        &store,
        operation_id(token)?,
        operation_generation(),
        durable_child_request(role)?,
    ))?;
    let outcome = block_on(backend.run_durable_object_install(authority))?;
    let expected = match role {
        ROLE_SA_ACQUIRED | ROLE_POLICY_ACQUIRED => {
            matches!(&outcome, XfrmObjectInstallDurableOutcome::Acquired(_))
        }
        ROLE_SA_NO_MUTATION => {
            matches!(&outcome, XfrmObjectInstallDurableOutcome::NoMutation(_))
        }
        _ => false,
    };
    if !expected {
        return Err(io::Error::other("durable child observed an unexpected outcome").into());
    }

    let handle_path = root.join("coordination").join(format!("{role}.handle"));
    publish_readiness(&handle_path, &outcome.handle().to_bytes())?;
    let ready_path = root.join("coordination").join(format!("{role}.ready"));
    let evidence = format!("{token}:{role}:{}:ready\n", std::process::id());
    publish_readiness(&ready_path, evidence.as_bytes())?;
    child_wait_for_sigkill()
}

fn prepared_role_has_poll_admission(role: &str) -> TestResult<bool> {
    match role {
        ROLE_SA_PREPARED_BEFORE_ADMISSION | ROLE_POLICY_PREPARED_BEFORE_ADMISSION => Ok(false),
        ROLE_SA_PREPARED_POLL_ADMITTED | ROLE_POLICY_PREPARED_POLL_ADMITTED => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown prepared child role").into()),
    }
}

fn run_prepared_crash_child(role: &str, root: &Path, token: &str) -> TestResult {
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_object_recovery(
            root.join("store"),
            proof_key(token)?,
        )?;
    let _authority = block_on(backend.prepare_durable_object_install(
        &store,
        operation_id(token)?,
        operation_generation(),
        durable_child_request(role)?,
    ))?;

    if prepared_role_has_poll_admission(role)? {
        let poll_admitted_path = root
            .join("coordination")
            .join(format!("{role}.poll-admitted"));
        let evidence = format!("{token}:{role}:{}:PollAdmitted\n", std::process::id());
        publish_readiness(&poll_admitted_path, evidence.as_bytes())?;
    }

    let ready_path = root.join("coordination").join(format!("{role}.ready"));
    let evidence = format!("{token}:{role}:{}:ready\n", std::process::id());
    publish_readiness(&ready_path, evidence.as_bytes())?;
    child_wait_for_sigkill()
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

fn crash_durable_operation(
    fixture: &PrivilegedFixture,
    namespace: &str,
    role: &str,
) -> TestResult<XfrmObjectInstallRecoveryHandle> {
    let ready_path = fixture.ready_path(role);
    let handle_path = fixture.handle_path(role);
    let mut child = TestChild::spawn(fixture.child_command(namespace, role)?)?;
    let ready_bytes = fixture.readiness_bytes(role, child.id()?);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;
    Ok(read_recovery_handle(&handle_path)?)
}

fn crash_issuing_cut_operation(
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

fn crash_prepared_operation(
    fixture: &PrivilegedFixture,
    namespace: &str,
    role: &str,
    expect_poll_admitted: bool,
) -> TestResult {
    let ready_path = fixture.ready_path(role);
    let poll_admitted_path = fixture.poll_admitted_path(role);
    if poll_admitted_path.starts_with(fixture.store_path()) {
        return Err(io::Error::other("consumer admission marker overlaps the SDK store").into());
    }
    if path_exists(&ready_path)? || path_exists(&poll_admitted_path)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "prepared-cut coordination evidence already exists",
        )
        .into());
    }

    let mut child = TestChild::spawn(fixture.child_command(namespace, role)?)?;
    let child_pid = child.id()?;
    let ready_bytes = fixture.readiness_bytes(role, child_pid);
    let poll_admitted_bytes = fixture.poll_admitted_bytes(role, child_pid);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    if expect_poll_admitted {
        if fs::read(&poll_admitted_path)? != poll_admitted_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "child published malformed consumer admission evidence",
            )
            .into());
        }
    } else if path_exists(&poll_admitted_path)? {
        return Err(io::Error::other(
            "consumer admission marker was published before the admission cut",
        )
        .into());
    }

    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;
    if expect_poll_admitted && fs::read(&poll_admitted_path)? != poll_admitted_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable consumer admission evidence did not survive SIGKILL",
        )
        .into());
    }
    Ok(())
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

fn child_wait_for_sigkill() -> ! {
    thread::sleep(CHILD_FAILSAFE_TIMEOUT);
    panic!("privileged recovery child was not killed by its parent")
}

#[test]
#[ignore = "child role launched only by the privileged parent detector"]
fn xfrm_object_recovery_privileged_child() -> TestResult {
    let Some((role, root, token)) = child_context()? else {
        return Ok(());
    };
    match role.as_str() {
        ROLE_HARNESS_SIGKILL => {
            let ready = root.join("coordination").join(format!("{role}.ready"));
            let evidence = format!("{token}:{role}:{}:ready\n", std::process::id());
            publish_readiness(&ready, evidence.as_bytes())?;
            child_wait_for_sigkill()
        }
        ROLE_SA_ACQUIRED | ROLE_SA_NO_MUTATION | ROLE_POLICY_ACQUIRED => {
            run_durable_crash_child(&role, &root, &token)
        }
        ROLE_SA_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_POLICY_ISSUING_CUT_BEFORE_EFFECT
        | ROLE_SA_ISSUING_CUT_AFTER_EFFECT
        | ROLE_POLICY_ISSUING_CUT_AFTER_EFFECT
        | ROLE_SA_ISSUING_CUT_CONFLICT
        | ROLE_POLICY_ISSUING_CUT_CONFLICT => run_issuing_cut_crash_child(&role, &root, &token),
        ROLE_SA_PREPARED_BEFORE_ADMISSION
        | ROLE_SA_PREPARED_POLL_ADMITTED
        | ROLE_POLICY_PREPARED_BEFORE_ADMISSION
        | ROLE_POLICY_PREPARED_POLL_ADMITTED => run_prepared_crash_child(&role, &root, &token),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into()),
    }
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn collision_safe_sigkill_harness_preserves_parent_owned_cleanup() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    assert_ne!(fixture.namespace_a(), fixture.namespace_b());
    assert!(
        !path_exists(&fixture.store_path())?,
        "the durable API must exclusively create its own store"
    );

    let backend_a = bind_namespace(fixture.namespace_a())?;
    let backend_b = bind_namespace(fixture.namespace_b())?;
    let XfrmObjectInstallRequest::Sa(sa) = sa_object_request() else {
        return Err(io::Error::other("SA fixture changed object kind").into());
    };
    block_on(backend_a.install_sa(sa))?;
    assert_sa_presence(&backend_a, true)?;
    assert_sa_presence(&backend_b, false)?;

    for if_id in [POLICY_IF_ID_OWNED, POLICY_IF_ID_NEIGHBOR] {
        let XfrmObjectInstallRequest::Policy(policy) = policy_object_request(if_id) else {
            return Err(io::Error::other("policy fixture changed object kind").into());
        };
        block_on(backend_a.install_policy(policy))?;
        assert_eq!(policy_if_id_count(fixture.namespace_a(), if_id)?, 1);
        assert_eq!(policy_if_id_count(fixture.namespace_b(), if_id)?, 0);
    }

    let role = ROLE_HARNESS_SIGKILL;
    let ready_path = fixture.ready_path(role);
    let mut child = TestChild::spawn(fixture.child_command(fixture.namespace_a(), role)?)?;
    let ready_bytes = fixture.readiness_bytes(role, child.id()?);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;

    drop(backend_a);
    drop(backend_b);
    fixture.cleanup()?;
    Ok(())
}

fn prepared_sa_cut_recovers_no_mutation(role: &str, poll_admitted: bool) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    assert!(
        !path_exists(&fixture.store_path())?,
        "the durable API must exclusively create its own store"
    );

    // Keep an identical object in the foreign namespace so the detector also
    // crosses the namespace-actor/backend boundary. Recovery in namespace A
    // must leave both the absent target and the namespace-B object unchanged.
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    block_on(foreign_backend.install_sa(sa_install_request()))?;
    assert_sa_presence(&foreign_backend, true)?;
    drop(foreign_backend);
    let before = bind_namespace(fixture.namespace_a())?;
    assert_sa_presence(&before, false)?;
    drop(before);

    crash_prepared_operation(&fixture, fixture.namespace_a(), role, poll_admitted)?;

    // The child has been killed and reaped with the requested object still
    // absent. If the opaque authority were bypassed and issue had started,
    // this assertion would turn the detector red before recovery could hide
    // the acquired residue. Install a same-identity non-cooperating object
    // after the cut so Prepared recovery must also prove zero deletion.
    let replacement = bind_namespace(fixture.namespace_a())?;
    assert_sa_presence(&replacement, false)?;
    block_on(replacement.install_sa(sa_install_request()))?;
    assert_sa_presence(&replacement, true)?;
    drop(replacement);

    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_sa_presence(&backend, true)?;
    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))?;
    assert!(matches!(
        outcome,
        XfrmObjectInstallRestartOutcome::NoMutation
    ));
    assert_sa_presence(&backend, true)?;
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    assert_sa_presence(&foreign_backend, true)?;

    drop(foreign_backend);
    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

fn prepared_policy_cut_recovers_no_mutation(role: &str, poll_admitted: bool) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    assert!(
        !path_exists(&fixture.store_path())?,
        "the durable API must exclusively create its own store"
    );

    // A same-shape neighbor in namespace A and an exact object in namespace B
    // make an accidental backend call observable without placing the requested
    // policy in namespace A before the Prepared cut.
    let neighbor_backend = bind_namespace(fixture.namespace_a())?;
    block_on(neighbor_backend.install_policy(policy_install_request(POLICY_IF_ID_NEIGHBOR)))?;
    drop(neighbor_backend);
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    block_on(foreign_backend.install_policy(policy_install_request(POLICY_IF_ID_OWNED)))?;
    drop(foreign_backend);
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        0
    );
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_NEIGHBOR)?,
        1
    );
    assert_eq!(
        policy_if_id_count(fixture.namespace_b(), POLICY_IF_ID_OWNED)?,
        1
    );

    crash_prepared_operation(&fixture, fixture.namespace_a(), role, poll_admitted)?;

    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        0
    );
    let replacement = bind_namespace(fixture.namespace_a())?;
    block_on(replacement.install_policy(policy_install_request(POLICY_IF_ID_OWNED)))?;
    drop(replacement);
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        1
    );

    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        policy_object_request(POLICY_IF_ID_OWNED),
    ))?;
    assert!(matches!(
        outcome,
        XfrmObjectInstallRestartOutcome::NoMutation
    ));
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        1
    );
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_NEIGHBOR)?,
        1
    );
    assert_eq!(
        policy_if_id_count(fixture.namespace_b(), POLICY_IF_ID_OWNED)?,
        1
    );

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn prepared_sa_before_consumer_admission_recovers_no_mutation() -> TestResult {
    prepared_sa_cut_recovers_no_mutation(ROLE_SA_PREPARED_BEFORE_ADMISSION, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn poll_admitted_prepared_sa_recovers_no_mutation_after_sigkill() -> TestResult {
    prepared_sa_cut_recovers_no_mutation(ROLE_SA_PREPARED_POLL_ADMITTED, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn prepared_policy_before_consumer_admission_recovers_no_mutation() -> TestResult {
    prepared_policy_cut_recovers_no_mutation(ROLE_POLICY_PREPARED_BEFORE_ADMISSION, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn poll_admitted_prepared_policy_recovers_no_mutation_after_sigkill() -> TestResult {
    prepared_policy_cut_recovers_no_mutation(ROLE_POLICY_PREPARED_POLL_ADMITTED, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn acquired_sa_is_recovered_after_real_process_loss() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let handle = crash_durable_operation(&fixture, fixture.namespace_a(), ROLE_SA_ACQUIRED)?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_sa_presence(&backend, true)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectInstallDurablePhase::Acquired
    );
    let blocked = block_on(backend.remove_sa(sa_remove_request()))
        .expect_err("atomic restart binding must activate the retained cleanup gate");
    assert!(matches!(blocked, XfrmError::Unavailable));
    assert_sa_presence(&backend, true)?;

    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))?;
    assert!(matches!(
        outcome,
        XfrmObjectInstallRestartOutcome::OwnedResidueRetired
    ));
    assert_sa_presence(&backend, false)?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn already_exists_crash_never_removes_preexisting_sa() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let preinstaller = bind_namespace(fixture.namespace_a())?;
    block_on(preinstaller.install_sa(sa_install_request()))?;
    assert_sa_presence(&preinstaller, true)?;
    drop(preinstaller);

    let handle = crash_durable_operation(&fixture, fixture.namespace_a(), ROLE_SA_NO_MUTATION)?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectInstallDurablePhase::NoMutation
    );

    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))?;
    assert!(matches!(
        outcome,
        XfrmObjectInstallRestartOutcome::NoMutation
    ));
    // A recovery implementation that substitutes matching readback for the
    // authenticated NoMutation result would delete this foreign SA.
    assert_sa_presence(&backend, true)?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum IssuingCutObject {
    Sa,
    Policy,
}

fn issuing_cut_request(kind: IssuingCutObject) -> XfrmObjectInstallRequest {
    match kind {
        IssuingCutObject::Sa => sa_object_request(),
        IssuingCutObject::Policy => policy_object_request(POLICY_IF_ID_OWNED),
    }
}

fn issuing_cut_object_present(
    backend: &NamespaceBoundLinuxXfrmBackend,
    namespace: &str,
    kind: IssuingCutObject,
) -> TestResult<bool> {
    match kind {
        IssuingCutObject::Sa => match block_on(backend.query_sa(sa_query_request())) {
            Ok(_) => Ok(true),
            Err(XfrmError::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        },
        IssuingCutObject::Policy => Ok(policy_if_id_count(namespace, POLICY_IF_ID_OWNED)? > 0),
    }
}

/// Real-process detector for one `Issuing` reconciliation verdict. The child
/// cuts the durable record at `Issuing` (optionally after admitting the kernel
/// effect), is SIGKILLed, and the parent rebinds and reconciles against the
/// live kernel.
fn issuing_cut_recovery_detector(
    role: &str,
    kind: IssuingCutObject,
    expected_outcome: &'static str,
    present_before: bool,
    present_after: bool,
) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    crash_issuing_cut_operation(&fixture, fixture.namespace_a(), role)?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        issuing_cut_object_present(&backend, fixture.namespace_a(), kind)?,
        present_before,
        "unexpected kernel state before reconciliation"
    );

    // While the cut record stays unresolved, the writer gate must reject
    // every cooperating mutation before any kernel effect.
    let gated = match kind {
        IssuingCutObject::Sa => block_on(backend.install_sa(sa_install_request())),
        IssuingCutObject::Policy => {
            block_on(backend.install_policy(policy_install_request(POLICY_IF_ID_OWNED)))
        }
    };
    assert!(
        matches!(gated, Err(XfrmError::Unavailable)),
        "unresolved Issuing record must gate cooperating mutations"
    );
    assert_eq!(
        issuing_cut_object_present(&backend, fixture.namespace_a(), kind)?,
        present_before,
        "the gated mutation must not reach the kernel"
    );

    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        issuing_cut_request(kind),
    ))?;
    assert_eq!(outcome.as_str(), expected_outcome);
    assert_eq!(
        issuing_cut_object_present(&backend, fixture.namespace_a(), kind)?,
        present_after,
        "reconciliation verdict did not leave the expected kernel state"
    );

    // Recovery retired the record, so the gate reopens for cooperating
    // mutations. Prove admission with an exact same-identity mutation: when
    // the verdict left the identity absent, install and remove it; when a
    // foreign conflict object remains, remove it. Both paths leave the
    // namespace clean.
    match kind {
        IssuingCutObject::Sa => {
            if !present_after {
                block_on(backend.install_sa(sa_install_request()))?;
            }
            block_on(backend.remove_sa(sa_remove_request()))?;
        }
        IssuingCutObject::Policy => {
            let install = policy_install_request(POLICY_IF_ID_OWNED);
            if !present_after {
                block_on(backend.install_policy(install.clone()))?;
            }
            let removal = RemovePolicyRequest {
                selector: install.parameters.selector,
                direction: install.parameters.direction,
                mark: None,
            };
            block_on(backend.remove_policy_exact(
                ExactRemovePolicyRequest::new(removal).with_if_id(POLICY_IF_ID_OWNED),
            ))?;
        }
    }

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_before_effect_recovers_sa_no_mutation() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_SA_ISSUING_CUT_BEFORE_EFFECT,
        IssuingCutObject::Sa,
        "no_mutation",
        false,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_before_effect_recovers_policy_no_mutation() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_POLICY_ISSUING_CUT_BEFORE_EFFECT,
        IssuingCutObject::Policy,
        "no_mutation",
        false,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_after_effect_retires_owned_sa_residue() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_SA_ISSUING_CUT_AFTER_EFFECT,
        IssuingCutObject::Sa,
        "owned_residue_retired",
        true,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_after_effect_retires_owned_policy_residue() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_POLICY_ISSUING_CUT_AFTER_EFFECT,
        IssuingCutObject::Policy,
        "owned_residue_retired",
        true,
        false,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_with_conflict_leaves_foreign_sa_untouched() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_SA_ISSUING_CUT_CONFLICT,
        IssuingCutObject::Sa,
        "foreign_untouched",
        true,
        true,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_with_conflict_leaves_foreign_policy_untouched() -> TestResult {
    issuing_cut_recovery_detector(
        ROLE_POLICY_ISSUING_CUT_CONFLICT,
        IssuingCutObject::Policy,
        "foreign_untouched",
        true,
        true,
    )
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn stale_receipt_cannot_remove_same_identity_replacement() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let handle = crash_durable_operation(&fixture, fixture.namespace_a(), ROLE_SA_ACQUIRED)?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectInstallDurablePhase::Acquired
    );

    let phase = block_on(backend.finalize_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))?;
    assert_eq!(phase, XfrmObjectInstallDurablePhase::Committed);
    assert_sa_presence(&backend, true)?;

    // Both ordinary mutations pass through the bound namespace actor. It
    // advances the durable writer epoch before deleting the old object and
    // before installing its exact same-identity replacement.
    block_on(backend.remove_sa(sa_remove_request()))?;
    assert_sa_presence(&backend, false)?;
    block_on(backend.install_sa(sa_install_request()))?;
    assert_sa_presence(&backend, true)?;

    let error = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))
    .expect_err("retired receipt must not recover a same-identity replacement");
    assert!(matches!(
        error,
        XfrmObjectInstallDurableError::NotFound | XfrmObjectInstallDurableError::Stale
    ));
    // Without current-phase/generation validation, matching readback would
    // make the replacement indistinguishable and this assertion would fail.
    assert_sa_presence(&backend, true)?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn wrong_namespace_and_durable_writer_incarnation_fail_closed() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    block_on(foreign_backend.install_sa(sa_install_request()))?;
    assert_sa_presence(&foreign_backend, true)?;
    drop(foreign_backend);

    let handle = crash_durable_operation(&fixture, fixture.namespace_a(), ROLE_SA_ACQUIRED)?;
    let wrong_binding = try_bind_namespace_with_recovery(
        fixture.namespace_b(),
        fixture.store_path(),
        &fixture.token,
    )?
    .expect_err("store from another namespace must be rejected");
    assert!(matches!(
        wrong_binding,
        XfrmObjectRecoveryBindError::Store {
            source: XfrmObjectInstallDurableError::WrongBinding
        }
    ));
    // The object is deliberately identical. Omitting namespace validation
    // would let matching readback authorize deletion in namespace B.
    let wrong_namespace = bind_namespace(fixture.namespace_b())?;
    assert_sa_presence(&wrong_namespace, true)?;
    drop(wrong_namespace);

    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectInstallDurablePhase::Acquired
    );
    poison_acquired_record_incarnation(&fixture.store_path(), &proof_key_bytes(&fixture.token))?;
    let wrong_incarnation = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        sa_object_request(),
    ))
    .expect_err("authenticated record from another writer incarnation must be rejected");
    assert_eq!(
        wrong_incarnation,
        XfrmObjectInstallDurableError::WrongIncarnation
    );
    // A correctly authenticated but wrong durable-writer incarnation must
    // still perform no backend operation.
    assert_sa_presence(&backend, true)?;
    let foreign_backend = bind_namespace(fixture.namespace_b())?;
    assert_sa_presence(&foreign_backend, true)?;

    drop(foreign_backend);
    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn scoped_policy_recovery_removes_only_the_owned_if_id() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let preinstaller = bind_namespace(fixture.namespace_a())?;
    block_on(preinstaller.install_policy(policy_install_request(POLICY_IF_ID_NEIGHBOR)))?;
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_NEIGHBOR)?,
        1
    );
    drop(preinstaller);

    let handle = crash_durable_operation(&fixture, fixture.namespace_a(), ROLE_POLICY_ACQUIRED)?;
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        1
    );
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_NEIGHBOR)?,
        1
    );

    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectInstallDurablePhase::Acquired
    );
    let outcome = block_on(backend.recover_durable_object_install(
        &store,
        operation_id(&fixture.token)?,
        operation_generation(),
        policy_object_request(POLICY_IF_ID_OWNED),
    ))?;
    assert!(matches!(
        outcome,
        XfrmObjectInstallRestartOutcome::OwnedResidueRetired
    ));
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_OWNED)?,
        0
    );
    // Dropping if_id from the fingerprint or delete request would either
    // leave the owned policy behind or target its identical neighbor.
    assert_eq!(
        policy_if_id_count(fixture.namespace_a(), POLICY_IF_ID_NEIGHBOR)?,
        1
    );

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}
