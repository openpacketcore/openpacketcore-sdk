//! Privileged, real-process detectors for durable grouped XFRM object roster
//! recovery.
//!
//! Each detector spawns a child inside a token-derived named network
//! namespace, drives one durable roster to the requested crash cut, kills it
//! with SIGKILL, and rebinds the retained store from the parent to reconcile
//! against the live kernel through the exact public recovery API. Every verdict
//! is checked twice: once against the store's own authenticated phase and
//! per-member dispositions, and once against `ip xfrm` output that never passes
//! through the SDK.
//!
//! # Exhaustiveness split
//!
//! Altitude A — the flow detectors in `durable_roster_flow.rs` — covers EVERY
//! member index and EVERY phase exhaustively against a scripted backend and a
//! real store on a temporary directory. This file is altitude C. It SAMPLES the
//! member indices `k` in `{0, 2, 4}` for real-kernel crash cuts, because a
//! real-process detector costs a namespace, a fork, and a SIGKILL per case, and
//! because member index is already an exhausted dimension one altitude down.
//! What altitude C adds is what a mock cannot state: that Linux itself holds,
//! keeps, or releases exactly the objects each durable verdict claims, that a
//! non-cooperating `ip xfrm` writer survives every recovery untouched, and that
//! the kernel's own selection relation behaves the way
//! `XfrmObjectRosterRequest::new` assumes it does.
//!
//! # The fixture roster
//!
//! Five members in one caller-declared apply order, expressed only as generic
//! SA and policy objects: an SA, a policy, a second policy, a second SA, and a
//! third policy. Every member carries a distinct exact identity — the SAs by
//! SPI, the policies by direction and interface identifier — so a per-member
//! kernel count is unambiguous evidence about that member alone.
//!
//! # Foreign-object planting
//!
//! The foreign-object detectors plant through raw `ip xfrm`, never through the
//! SDK, so the planted object is a genuinely non-cooperating writer that the
//! durable gate cannot exclude. Both member kinds are covered: a policy at
//! member two's exact identity through `ip xfrm policy add`, and an SA at
//! member three's exact identity through `ip xfrm state add`. Survival is
//! proved by comparing a complete `ip xfrm ... get` snapshot taken before the
//! roster ran with the same snapshot taken after recovery.

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
    PolicyParameters, RemovePolicyRequest, RemoveSaRequest, SaParameters, XfrmAction, XfrmBackend,
    XfrmDirection, XfrmError, XfrmId, XfrmLookupMark, XfrmMode, XfrmObjectInstallRequest,
    XfrmObjectRecoveryBindError, XfrmObjectRosterDurableError, XfrmObjectRosterDurableOutcome,
    XfrmObjectRosterDurablePhase, XfrmObjectRosterGroupId, XfrmObjectRosterMemberDispositions,
    XfrmObjectRosterMemberRequest, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRecoveryProofKey,
    XfrmObjectRosterRecoveryStore, XfrmObjectRosterRequest, XfrmObjectRosterRequestError,
    XfrmRequestId, XfrmSelector, XfrmTemplate, XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
};
use sha2::{Digest, Sha256};

const RUN_PRIVILEGED_ENV: &str = "OPC_XFRM_RUN_OBJECT_ROSTER_RECOVERY_PRIVILEGED";
const CHILD_ROLE_ENV: &str = "OPC_XFRM_OBJECT_ROSTER_RECOVERY_CHILD_ROLE";
const CHILD_ROOT_ENV: &str = "OPC_XFRM_OBJECT_ROSTER_RECOVERY_CHILD_ROOT";
const CHILD_TOKEN_ENV: &str = "OPC_XFRM_OBJECT_ROSTER_RECOVERY_CHILD_TOKEN";
const CHILD_ORDINAL_ENV: &str = "OPC_XFRM_OBJECT_ROSTER_RECOVERY_CHILD_ORDINAL";
const CHILD_EFFECT_ENV: &str = "OPC_XFRM_OBJECT_ROSTER_RECOVERY_CHILD_EFFECT";
const CHILD_TEST_NAME: &str = "xfrm_object_roster_recovery_privileged_child";
const RESOURCE_PREFIX: &str = "opc-xfrm-677-";
const PROVISION_ATTEMPTS: usize = 32;
const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(15);
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_FAILSAFE_TIMEOUT: Duration = Duration::from_secs(30);

const IPPROTO_ESP: u8 = 50;
const IPPROTO_UDP: u8 = 17;

/// Shared tunnel endpoints for every fixture object.
const SA_SOURCE: IpAddress = IpAddress::Ipv4([192, 0, 2, 61]);
const SA_DESTINATION: IpAddress = IpAddress::Ipv4([192, 0, 2, 62]);
/// The address a raw `ip xfrm` writer uses, so a foreign SA is distinguishable
/// from anything the roster could have installed.
const FOREIGN_SOURCE_TEXT: &str = "203.0.113.7";
const SA_SOURCE_TEXT: &str = "192.0.2.61";
const SA_DESTINATION_TEXT: &str = "192.0.2.62";
const POLICY_SOURCE_TEXT: &str = "10.67.7.1/32";
const POLICY_DESTINATION_TEXT: &str = "10.67.7.2/32";
const FOREIGN_ENCRYPTION_KEY: &str = "0x0f0e0d0c0b0a09080706050403020100";
const FOREIGN_POLICY_PRIORITY: &str = "4242";

const MEMBER_0_SPI: u32 = 0x6770_0001;
const MEMBER_3_SPI: u32 = 0x6770_0002;
const MEMBER_1_IF_ID: u32 = 67_701;
const MEMBER_2_IF_ID: u32 = 67_702;
const MEMBER_4_IF_ID: u32 = 67_703;
/// A same-shape object at a non-member identity. Every recovery verdict must
/// leave it exactly where it was found.
const NEIGHBOR_IF_ID: u32 = 67_709;
const NEIGHBOR_SPI: u32 = 0x6770_000f;
/// A non-member identity used only to probe the cooperating-writer gate. It is
/// absent whenever it is probed, so an open gate would install it and change
/// the kernel observably.
const GATE_PROBE_SPI: u32 = 0x6770_00f1;
/// The identity the unmarked/marked kernel-divergence detector uses. It never
/// participates in a roster transaction.
const MARK_DIVERGENCE_SPI: u32 = 0x6770_00f2;
const MARK_DIVERGENCE_MARK: u32 = 0x0067_7001;

const ROSTER_ARITY: usize = 5;
const POLICY_PRIORITY: u32 = 677;
const REQUEST_ID: u32 = 677;

const ROLE_HARNESS_SIGKILL: &str = "roster-harness-sigkill-677";
const ROLE_PREPARED_CUT: &str = "roster-prepared-cut-677";
const ROLE_ISSUING_CUT: &str = "roster-issuing-cut-677";
const ROLE_APPLIED_CUT: &str = "roster-applied-cut-677";
const ROLE_COMPENSATING_CUT: &str = "roster-compensating-cut-677";
const ROLE_CONFLICT_TERMINAL: &str = "roster-conflict-terminal-677";

/// Byte layout of one durable roster record, mirrored here so the poison
/// detector rewrites exactly the actor-incarnation field and nothing else.
const RECORD_BODY_BYTES: usize = 912;
const ACTOR_INCARNATION_RANGE: std::ops::Range<usize> = 64..80;
const RECORD_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-record-v1\0";
const JOURNAL_NAME: &str = "journal";
const JOURNAL_HEADER_BYTES: usize = 80;
const EPOCH_BODY_BYTES: usize = JOURNAL_HEADER_BYTES - 32;
const EPOCH_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-epoch-v1\0";

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

/// One fixture member, described only by the identity the kernel selects on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    Sa {
        spi: u32,
    },
    Policy {
        if_id: u32,
        direction: XfrmDirection,
    },
}

/// The caller-declared apply order. Ordinal zero is applied first and
/// compensated last.
const ROSTER_MEMBERS: [MemberKind; ROSTER_ARITY] = [
    MemberKind::Sa { spi: MEMBER_0_SPI },
    MemberKind::Policy {
        if_id: MEMBER_1_IF_ID,
        direction: XfrmDirection::In,
    },
    MemberKind::Policy {
        if_id: MEMBER_2_IF_ID,
        direction: XfrmDirection::Forward,
    },
    MemberKind::Sa { spi: MEMBER_3_SPI },
    MemberKind::Policy {
        if_id: MEMBER_4_IF_ID,
        direction: XfrmDirection::Out,
    },
];

fn policy_selector() -> XfrmSelector {
    XfrmSelector::new(
        IpAddress::Ipv4([10, 67, 7, 1]),
        IpAddress::Ipv4([10, 67, 7, 2]),
        IPPROTO_UDP,
    )
}

fn sa_parameters(spi: u32, mark: Option<XfrmLookupMark>) -> SaParameters {
    SaParameters {
        selector: policy_selector(),
        id: XfrmId {
            destination: SA_DESTINATION,
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: SA_SOURCE,
        request_id: XfrmRequestId::new(REQUEST_ID),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x67; 32]),
        )),
        crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 32,
        replay_state: None,
        encap: None,
        mark,
        output_mark: None,
        if_id: None,
        egress_dscp: None,
    }
}

fn sa_object_request(spi: u32, mark: Option<XfrmLookupMark>) -> XfrmObjectInstallRequest {
    XfrmObjectInstallRequest::Sa(InstallSaRequest {
        parameters: sa_parameters(spi, mark),
    })
}

fn policy_object_request(if_id: u32, direction: XfrmDirection) -> XfrmObjectInstallRequest {
    XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: policy_selector(),
            direction,
            action: XfrmAction::Allow,
            priority: POLICY_PRIORITY,
            templates: vec![XfrmTemplate {
                id: XfrmId {
                    destination: SA_DESTINATION,
                    spi: MEMBER_0_SPI,
                    protocol: IPPROTO_ESP,
                },
                source_address: SA_SOURCE,
                request_id: XfrmRequestId::new(REQUEST_ID),
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: Some(if_id),
        },
    })
}

fn member_install_request(ordinal: usize) -> TestResult<XfrmObjectInstallRequest> {
    match ROSTER_MEMBERS.get(ordinal) {
        Some(MemberKind::Sa { spi }) => Ok(sa_object_request(*spi, None)),
        Some(MemberKind::Policy { if_id, direction }) => {
            Ok(policy_object_request(*if_id, *direction))
        }
        None => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown member ordinal").into()),
    }
}

fn roster_request() -> TestResult<XfrmObjectRosterRequest> {
    let mut members = Vec::with_capacity(ROSTER_ARITY);
    for ordinal in 0..ROSTER_ARITY {
        members.push(XfrmObjectRosterMemberRequest::new(member_install_request(
            ordinal,
        )?));
    }
    Ok(XfrmObjectRosterRequest::new(members)?)
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
    let mut bytes = derived_secret(token, b"opc-xfrm-677-roster-proof-key\0");
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    bytes
}

fn proof_key(
    token: &str,
) -> Result<XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterDurableError> {
    XfrmObjectRosterRecoveryProofKey::new(proof_key_bytes(token))
}

/// Derive the group identity both the parent and its child agree on. The salt
/// lets one detector run a second, distinct roster in the same namespace.
fn group_id(
    token: &str,
    salt: u8,
) -> Result<XfrmObjectRosterGroupId, XfrmObjectRosterDurableError> {
    let digest = derived_secret(token, b"opc-xfrm-677-roster-group-id\0");
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[0] ^= salt;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = 1;
    }
    XfrmObjectRosterGroupId::from_bytes(bytes)
}

fn generation(value: u64) -> TestResult<XfrmObjectRosterOperationGeneration> {
    XfrmObjectRosterOperationGeneration::new(value)
        .ok_or_else(|| io::Error::other("roster generation must be nonzero").into())
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

#[allow(clippy::type_complexity)]
fn try_bind_namespace_with_recovery(
    namespace: &str,
    store_path: PathBuf,
    token: &str,
) -> TestResult<
    Result<
        (
            Arc<NamespaceBoundLinuxXfrmBackend>,
            XfrmObjectRosterRecoveryStore,
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
            .bind_current_network_namespace_with_object_roster_recovery(
                store_path,
                proof_key(&token)?,
            )
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
    XfrmObjectRosterRecoveryStore,
)> {
    Ok(try_bind_namespace_with_recovery(
        namespace,
        fixture.store_path(),
        &fixture.token,
    )??)
}

// ---------------------------------------------------------------------------
// Independent kernel evidence
//
// Everything below reads `ip xfrm` directly. None of it goes through the SDK,
// so a recovery implementation that lied about what it did to the kernel could
// not also make these assertions pass.
// ---------------------------------------------------------------------------

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

/// Reduce an `ip xfrm` rendering to whitespace-separated alphanumeric tokens.
///
/// Some supported iproute2 builds ignore `-j` for `ip xfrm` and render numeric
/// attributes as hexadecimal text. Normalizing punctuation makes that form and
/// JSON's numeric and string forms use the same bounded token parser.
fn normalize_listing(listing: &str) -> String {
    listing
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                ' '
            }
        })
        .collect()
}

fn count_attribute(listing: &str, attribute: &str, expected: u32) -> TestResult<usize> {
    let normalized = normalize_listing(listing);
    let mut count = 0_usize;
    let mut tokens = normalized.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        if token != attribute {
            continue;
        }
        let encoded = tokens.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "xfrm attribute value is missing",
            )
        })?;
        let value = match encoded.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16),
            None => encoded.parse(),
        }
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "xfrm attribute value is malformed",
            )
        })?;
        if value == expected {
            count += 1;
        }
    }
    Ok(count)
}

fn policy_if_id_count(namespace: &str, if_id: u32) -> TestResult<usize> {
    let output = run_ip(&[
        "netns", "exec", namespace, "ip", "-j", "xfrm", "policy", "list",
    ])?;
    if !output.status.success() {
        return Err(command_error("list namespace XFRM policies", &output).into());
    }
    count_attribute(&String::from_utf8(output.stdout)?, "if_id", if_id)
}

fn sa_spi_count(namespace: &str, spi: u32) -> TestResult<usize> {
    let output = run_ip(&[
        "netns", "exec", namespace, "ip", "-j", "xfrm", "state", "list",
    ])?;
    if !output.status.success() {
        return Err(command_error("list namespace XFRM states", &output).into());
    }
    count_attribute(&String::from_utf8(output.stdout)?, "spi", spi)
}

fn member_kernel_count(namespace: &str, ordinal: usize) -> TestResult<usize> {
    match ROSTER_MEMBERS.get(ordinal) {
        Some(MemberKind::Sa { spi }) => sa_spi_count(namespace, *spi),
        Some(MemberKind::Policy { if_id, .. }) => policy_if_id_count(namespace, *if_id),
        None => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown member ordinal").into()),
    }
}

/// Assert the exact per-member kernel population, member by member.
fn assert_member_presence(namespace: &str, expected: [bool; ROSTER_ARITY]) -> TestResult {
    for (ordinal, present) in expected.iter().enumerate() {
        let observed = member_kernel_count(namespace, ordinal)?;
        let wanted = usize::from(*present);
        if observed != wanted {
            return Err(io::Error::other(format!(
                "member {ordinal} kernel population was {observed}, expected {wanted}"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_no_roster_members(namespace: &str) -> TestResult {
    assert_member_presence(namespace, [false; ROSTER_ARITY])
}

/// Assert the two non-member neighbours planted by the caller are untouched.
fn assert_neighbors_untouched(namespace: &str) -> TestResult {
    if policy_if_id_count(namespace, NEIGHBOR_IF_ID)? != 1 {
        return Err(io::Error::other("the neighbouring policy did not survive").into());
    }
    if sa_spi_count(namespace, NEIGHBOR_SPI)? != 1 {
        return Err(io::Error::other("the neighbouring SA did not survive").into());
    }
    Ok(())
}

/// Plant two same-shape objects at identities no roster member declares.
fn plant_neighbors(namespace: &str) -> TestResult {
    let backend = bind_namespace(namespace)?;
    let XfrmObjectInstallRequest::Sa(sa) = sa_object_request(NEIGHBOR_SPI, None) else {
        return Err(io::Error::other("neighbour SA fixture changed object kind").into());
    };
    block_on(backend.install_sa(sa))?;
    let XfrmObjectInstallRequest::Policy(policy) =
        policy_object_request(NEIGHBOR_IF_ID, XfrmDirection::Out)
    else {
        return Err(io::Error::other("neighbour policy fixture changed object kind").into());
    };
    block_on(backend.install_policy(policy))?;
    drop(backend);
    assert_neighbors_untouched(namespace)
}

fn foreign_sa_snapshot(namespace: &str, spi: u32) -> TestResult<String> {
    let encoded_spi = format!("0x{spi:08x}");
    let output = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "state",
        "get",
        "src",
        FOREIGN_SOURCE_TEXT,
        "dst",
        SA_DESTINATION_TEXT,
        "proto",
        "esp",
        "spi",
        &encoded_spi,
    ])?;
    if !output.status.success() {
        return Err(command_error("read foreign XFRM state", &output).into());
    }
    Ok(normalize_listing(&String::from_utf8(output.stdout)?))
}

fn foreign_policy_snapshot(namespace: &str, if_id: u32) -> TestResult<String> {
    let encoded_if_id = format!("0x{if_id:x}");
    let output = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "policy",
        "get",
        "src",
        POLICY_SOURCE_TEXT,
        "dst",
        POLICY_DESTINATION_TEXT,
        "proto",
        "udp",
        "dir",
        "fwd",
        "if_id",
        &encoded_if_id,
    ])?;
    if !output.status.success() {
        return Err(command_error("read foreign XFRM policy", &output).into());
    }
    Ok(normalize_listing(&String::from_utf8(output.stdout)?))
}

/// Plant a foreign SA at member three's exact identity through raw iproute2.
///
/// The source address and encryption key differ from anything the roster could
/// install, so a snapshot comparison proves the surviving object is the planted
/// one rather than a replacement.
fn plant_foreign_member_sa(namespace: &str, spi: u32) -> TestResult {
    let encoded_spi = format!("0x{spi:08x}");
    let output = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "state",
        "add",
        "src",
        FOREIGN_SOURCE_TEXT,
        "dst",
        SA_DESTINATION_TEXT,
        "proto",
        "esp",
        "spi",
        &encoded_spi,
        "mode",
        "tunnel",
        "enc",
        "cbc(aes)",
        FOREIGN_ENCRYPTION_KEY,
    ])?;
    if !output.status.success() {
        return Err(command_error("plant foreign XFRM state", &output).into());
    }
    Ok(())
}

/// Plant a foreign policy at member two's exact identity through raw iproute2.
///
/// The action and priority differ from anything the roster could install.
fn plant_foreign_member_policy(namespace: &str, if_id: u32) -> TestResult {
    let encoded_if_id = format!("0x{if_id:x}");
    let output = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "policy",
        "add",
        "src",
        POLICY_SOURCE_TEXT,
        "dst",
        POLICY_DESTINATION_TEXT,
        "proto",
        "udp",
        "dir",
        "fwd",
        "if_id",
        &encoded_if_id,
        "priority",
        FOREIGN_POLICY_PRIORITY,
        "action",
        "block",
    ])?;
    if !output.status.success() {
        return Err(command_error("plant foreign XFRM policy", &output).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cooperating-writer helpers
// ---------------------------------------------------------------------------

fn install_member(
    backend: &NamespaceBoundLinuxXfrmBackend,
    ordinal: usize,
) -> TestResult<Result<(), XfrmError>> {
    Ok(match member_install_request(ordinal)? {
        XfrmObjectInstallRequest::Sa(request) => block_on(backend.install_sa(request)),
        XfrmObjectInstallRequest::Policy(request) => block_on(backend.install_policy(request)),
    })
}

fn remove_member(
    backend: &NamespaceBoundLinuxXfrmBackend,
    ordinal: usize,
) -> TestResult<Result<(), XfrmError>> {
    Ok(match ROSTER_MEMBERS.get(ordinal) {
        Some(MemberKind::Sa { spi }) => block_on(backend.remove_sa(RemoveSaRequest {
            destination: SA_DESTINATION,
            protocol: IPPROTO_ESP,
            spi: *spi,
            mark: None,
        })),
        Some(MemberKind::Policy { if_id, direction }) => block_on(
            backend.remove_policy_exact(
                ExactRemovePolicyRequest::new(RemovePolicyRequest {
                    selector: policy_selector(),
                    direction: *direction,
                    mark: None,
                })
                .with_if_id(*if_id),
            ),
        ),
        None => {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "unknown member ordinal").into(),
            )
        }
    })
}

fn gate_probe_install(backend: &NamespaceBoundLinuxXfrmBackend) -> Result<(), XfrmError> {
    let XfrmObjectInstallRequest::Sa(request) = sa_object_request(GATE_PROBE_SPI, None) else {
        return Err(XfrmError::Unavailable);
    };
    block_on(backend.install_sa(request))
}

fn gate_probe_remove(backend: &NamespaceBoundLinuxXfrmBackend) -> Result<(), XfrmError> {
    block_on(backend.remove_sa(RemoveSaRequest {
        destination: SA_DESTINATION,
        protocol: IPPROTO_ESP,
        spi: GATE_PROBE_SPI,
        mark: None,
    }))
}

/// Prove the cooperating-writer gate is closed and that the rejection happened
/// before any kernel effect.
fn assert_writer_gate_closed(
    backend: &NamespaceBoundLinuxXfrmBackend,
    namespace: &str,
) -> TestResult {
    let rejected = gate_probe_install(backend);
    if !matches!(rejected, Err(XfrmError::Unavailable)) {
        return Err(io::Error::other(
            "an unresolved roster must reject every cooperating mutation as unavailable",
        )
        .into());
    }
    if sa_spi_count(namespace, GATE_PROBE_SPI)? != 0 {
        return Err(io::Error::other("the gated mutation still reached the kernel").into());
    }
    Ok(())
}

/// Prove the gate reopened once the roster resolved, without leaving residue.
fn assert_writer_gate_reopened(
    backend: &NamespaceBoundLinuxXfrmBackend,
    namespace: &str,
) -> TestResult {
    gate_probe_install(backend)?;
    if sa_spi_count(namespace, GATE_PROBE_SPI)? != 1 {
        return Err(io::Error::other("the readmitted mutation did not reach the kernel").into());
    }
    gate_probe_remove(backend)?;
    if sa_spi_count(namespace, GATE_PROBE_SPI)? != 0 {
        return Err(io::Error::other("the gate probe left residue behind").into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

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
                let name = format!("opc677-{}-{suffix}", candidate.token);
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

    fn readiness_bytes(&self, role: &str, child_pid: u32) -> Vec<u8> {
        format!("{}:{role}:{child_pid}:ready\n", self.token).into_bytes()
    }

    fn child_command(&self, namespace: &str, cut: ChildCut) -> io::Result<Command> {
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
            .env(CHILD_ROLE_ENV, cut.role)
            .env(CHILD_ROOT_ENV, &self.root)
            .env(CHILD_TOKEN_ENV, &self.token)
            .env(CHILD_ORDINAL_ENV, cut.ordinal.to_string())
            .env(CHILD_EFFECT_ENV, if cut.admit_effect { "1" } else { "0" })
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

fn read_recovery_handle(path: &Path) -> io::Result<XfrmObjectRosterRecoveryHandle> {
    let bytes = fs::read(path)?;
    let encoded: [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid recovery handle size"))?;
    Ok(XfrmObjectRosterRecoveryHandle::from_bytes(encoded))
}

/// Authenticate one fixed-size durable roster frame with the real proof key.
fn authenticate_record_frame(
    encoded: &[u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES],
    key: &[u8; 32],
) -> TestResult {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::other("construct roster record authenticator"))?;
    mac.update(RECORD_AUTH_DOMAIN);
    mac.update(&encoded[..RECORD_BODY_BYTES]);
    mac.verify_slice(&encoded[RECORD_BODY_BYTES..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid roster record tag"))?;
    Ok(())
}

fn authenticate_journal_header(encoded: &[u8], key: &[u8; 32]) -> TestResult {
    if encoded.len() != JOURNAL_HEADER_BYTES
        || encoded[..8] != *b"OPCXRSE1"
        || encoded[8..10] != 1_u16.to_be_bytes()
        || encoded[10..16].iter().any(|byte| *byte != 0)
        || encoded[40..EPOCH_BODY_BYTES].iter().any(|byte| *byte != 0)
        || encoded[16..32].iter().all(|byte| *byte == 0)
        || encoded[32..40].iter().all(|byte| *byte == 0)
    {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "invalid roster journal header").into(),
        );
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::other("construct roster journal authenticator"))?;
    mac.update(EPOCH_AUTH_DOMAIN);
    mac.update(&encoded[..EPOCH_BODY_BYTES]);
    mac.verify_slice(&encoded[EPOCH_BODY_BYTES..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid roster journal tag"))?;
    Ok(())
}

/// Count authenticated durable roster frames, excluding only the store's
/// control and epoch witnesses. A journal header alone is not a frame; every
/// complete frame after it is retained durable state and makes a zero-residue
/// assertion fail.
fn retained_record_count(store_root: &Path, key: &[u8; 32]) -> TestResult<usize> {
    let mut count = 0_usize;
    for entry in fs::read_dir(store_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 store entry"))?;
        if name == "control" || name.starts_with("epoch-") {
            continue;
        }
        let path = entry.path();
        let path_metadata = fs::symlink_metadata(&path)?;
        if name != JOURNAL_NAME {
            // An unknown residual entry remains observable as residue even if
            // it is not a record frame the test can authenticate.
            if path_metadata.len() != XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES as u64 {
                count += 1;
                continue;
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&path)?;
            let descriptor_metadata = file.metadata()?;
            if descriptor_metadata.dev() != path_metadata.dev()
                || descriptor_metadata.ino() != path_metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable roster record identity changed while opening",
                )
                .into());
            }
            let mut encoded = [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES];
            file.read_exact(&mut encoded)?;
            authenticate_record_frame(&encoded, key)?;
            count += 1;
            continue;
        }
        if !path_metadata.file_type().is_file()
            || path_metadata.mode() & 0o7777 != 0o600
            || path_metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable roster journal metadata is invalid",
            )
            .into());
        }
        let length = usize::try_from(path_metadata.len())?;
        if length < JOURNAL_HEADER_BYTES
            || !(length - JOURNAL_HEADER_BYTES)
                .is_multiple_of(XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable roster journal frame layout is invalid",
            )
            .into());
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(&path)?;
        let descriptor_metadata = file.metadata()?;
        if descriptor_metadata.dev() != path_metadata.dev()
            || descriptor_metadata.ino() != path_metadata.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable roster journal identity changed while opening",
            )
            .into());
        }
        let mut bytes = vec![0_u8; length];
        file.read_exact(&mut bytes)?;
        authenticate_journal_header(&bytes[..JOURNAL_HEADER_BYTES], key)?;
        let (frames, remainder) =
            bytes[JOURNAL_HEADER_BYTES..].as_chunks::<XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES>();
        if !remainder.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid roster frame").into());
        }
        for frame in frames {
            authenticate_record_frame(frame, key)?;
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Poison-record rewrite
// ---------------------------------------------------------------------------

fn authenticated_wrong_incarnation_record(
    mut encoded: [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES],
    key: &[u8; 32],
) -> TestResult<[u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES]> {
    let original = encoded[ACTOR_INCARNATION_RANGE].to_vec();
    encoded[ACTOR_INCARNATION_RANGE].fill(0x5a);
    if original == encoded[ACTOR_INCARNATION_RANGE] {
        encoded[ACTOR_INCARNATION_RANGE].fill(0xa5);
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::other("construct roster record authenticator"))?;
    mac.update(RECORD_AUTH_DOMAIN);
    mac.update(&encoded[..RECORD_BODY_BYTES]);
    encoded[RECORD_BODY_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    Ok(encoded)
}

/// Rewrite the actor incarnation of the exact retained record named by
/// `handle`, then re-authenticate it with the real proof key.
///
/// The record may be a legacy phase-named file or a complete frame in the
/// append journal. The rewrite is MAC-valid on purpose: a tampering test only
/// proves the tag works, while this proves the binding checks see a real
/// current frame.
fn poison_record_incarnation(
    store_root: &Path,
    handle: &XfrmObjectRosterRecoveryHandle,
    key: &[u8; 32],
) -> TestResult {
    let mut matching = Vec::new();
    let target = handle.to_bytes();
    for entry in fs::read_dir(store_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 store entry"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            continue;
        }
        if name == JOURNAL_NAME {
            let length = usize::try_from(metadata.len())?;
            if length < JOURNAL_HEADER_BYTES
                || !(length - JOURNAL_HEADER_BYTES)
                    .is_multiple_of(XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable roster journal frame layout is invalid",
                )
                .into());
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&path)?;
            let descriptor_metadata = file.metadata()?;
            if descriptor_metadata.dev() != metadata.dev()
                || descriptor_metadata.ino() != metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable roster journal identity changed while opening",
                )
                .into());
            }
            let mut bytes = vec![0_u8; length];
            file.read_exact(&mut bytes)?;
            let (frames, remainder) = bytes[JOURNAL_HEADER_BYTES..]
                .as_chunks::<XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES>();
            if !remainder.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable roster journal frame layout is invalid",
                )
                .into());
            }
            for (index, frame) in frames.iter().enumerate() {
                if *frame == target {
                    matching.push((
                        path.clone(),
                        u64::try_from(
                            JOURNAL_HEADER_BYTES + index * XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
                        )?,
                        metadata.len(),
                    ));
                }
            }
        } else if metadata.len() == XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES as u64 {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .open(&path)?;
            let descriptor_metadata = file.metadata()?;
            if descriptor_metadata.dev() != metadata.dev()
                || descriptor_metadata.ino() != metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable roster record identity changed while opening",
                )
                .into());
            }
            let mut encoded = [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES];
            file.read_exact(&mut encoded)?;
            if encoded == target {
                matching.push((path, 0, metadata.len()));
            }
        }
    }
    if matching.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected exactly one retained durable roster frame",
        )
        .into());
    }
    let (record_path, offset, expected_length) = matching
        .pop()
        .ok_or_else(|| io::Error::other("durable roster frame disappeared"))?;
    let path_metadata = fs::symlink_metadata(&record_path)?;
    if !path_metadata.file_type().is_file()
        || path_metadata.mode() & 0o7777 != 0o600
        || path_metadata.nlink() != 1
        || path_metadata.len() != expected_length
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable roster record metadata is invalid",
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
            "durable roster record identity changed while opening",
        )
        .into());
    }
    let mut encoded = [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES];
    file.seek(io::SeekFrom::Start(offset))?;
    file.read_exact(&mut encoded)?;
    let poisoned = authenticated_wrong_incarnation_record(encoded, key)?;
    file.seek(io::SeekFrom::Start(offset))?;
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
        || final_metadata.len() != expected_length
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "poisoned durable roster record metadata changed",
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Child process
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct ChildCut {
    role: &'static str,
    ordinal: usize,
    admit_effect: bool,
}

impl ChildCut {
    const fn simple(role: &'static str) -> Self {
        Self {
            role,
            ordinal: 0,
            admit_effect: false,
        }
    }

    const fn at(role: &'static str, ordinal: usize, admit_effect: bool) -> Self {
        Self {
            role,
            ordinal,
            admit_effect,
        }
    }
}

struct ChildContext {
    role: String,
    root: PathBuf,
    token: String,
    ordinal: usize,
    admit_effect: bool,
}

fn child_context() -> io::Result<Option<ChildContext>> {
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
    let ordinal = env::var(CHILD_ORDINAL_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing child ordinal"))?;
    let admit_effect = env::var(CHILD_EFFECT_ENV).as_deref() == Ok("1");
    Ok(Some(ChildContext {
        role,
        root,
        token,
        ordinal,
        admit_effect,
    }))
}

fn child_wait_for_sigkill() -> ! {
    thread::sleep(CHILD_FAILSAFE_TIMEOUT);
    panic!("privileged roster recovery child was not killed by its parent")
}

fn child_publish_ready(context: &ChildContext) -> io::Result<()> {
    let ready = context
        .root
        .join("coordination")
        .join(format!("{}.ready", context.role));
    let evidence = format!(
        "{}:{}:{}:ready\n",
        context.token,
        context.role,
        std::process::id()
    );
    publish_readiness(&ready, evidence.as_bytes())
}

fn child_publish_handle(
    context: &ChildContext,
    handle: &XfrmObjectRosterRecoveryHandle,
) -> io::Result<()> {
    let path = context
        .root
        .join("coordination")
        .join(format!("{}.handle", context.role));
    publish_readiness(&path, &handle.to_bytes())
}

fn assert_child_phase(
    store: &XfrmObjectRosterRecoveryStore,
    handle: &XfrmObjectRosterRecoveryHandle,
    expected: XfrmObjectRosterDurablePhase,
) -> TestResult {
    let observed = store.inspect(handle)?;
    if observed != expected {
        return Err(io::Error::other(format!(
            "child cut left phase {} instead of {}",
            observed.as_str(),
            expected.as_str()
        ))
        .into());
    }
    Ok(())
}

fn run_child(context: ChildContext) -> TestResult {
    if context.role == ROLE_HARNESS_SIGKILL {
        child_publish_ready(&context)?;
        child_wait_for_sigkill();
    }

    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_object_roster_recovery(
            context.root.join("store"),
            proof_key(&context.token)?,
        )?;
    let roster = roster_request()?;
    let group = group_id(&context.token, 0)?;
    let generation = generation(1)?;

    if context.role == ROLE_PREPARED_CUT {
        // The prepared authority is deliberately never consumed. Dropping it
        // here would be a legal outcome too, so hold it across the cut.
        let _authority =
            block_on(backend.prepare_durable_object_roster(&store, group, generation, roster))?;
        child_publish_ready(&context)?;
        child_wait_for_sigkill();
    }

    let authority =
        block_on(backend.prepare_durable_object_roster(&store, group, generation, roster.clone()))?;

    let handle = match context.role.as_str() {
        ROLE_ISSUING_CUT => {
            let handle = block_on(backend.detector_cut_roster_issuing_at_member(
                authority,
                context.ordinal,
                context.admit_effect,
            ))?;
            assert_child_phase(&store, &handle, XfrmObjectRosterDurablePhase::Issuing)?;
            handle
        }
        ROLE_APPLIED_CUT => {
            let handle = block_on(backend.detector_cut_roster_applied(authority))?;
            assert_child_phase(&store, &handle, XfrmObjectRosterDurablePhase::Applied)?;
            handle
        }
        ROLE_COMPENSATING_CUT => {
            let applied = block_on(backend.detector_cut_roster_applied(authority))?;
            assert_child_phase(&store, &applied, XfrmObjectRosterDurablePhase::Applied)?;
            let handle = block_on(backend.detector_cut_roster_compensating_at_member(
                &store,
                group,
                generation,
                &roster,
                context.ordinal,
                context.admit_effect,
            ))?;
            assert_child_phase(&store, &handle, XfrmObjectRosterDurablePhase::Compensating)?;
            handle
        }
        ROLE_CONFLICT_TERMINAL => {
            let outcome = block_on(backend.run_durable_object_roster(authority))?;
            if !matches!(outcome, XfrmObjectRosterDurableOutcome::NoMutation { .. }) {
                return Err(io::Error::other(format!(
                    "conflict child observed {} instead of no_mutation",
                    outcome.as_str()
                ))
                .into());
            }
            if !outcome.members().has_conflict() {
                return Err(io::Error::other(
                    "the no-mutation verdict did not name a conflicting member",
                )
                .into());
            }
            let handle = outcome.handle().clone();
            assert_child_phase(&store, &handle, XfrmObjectRosterDurablePhase::NoMutation)?;
            handle
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown child role").into());
        }
    };

    child_publish_handle(&context, &handle)?;
    child_publish_ready(&context)?;
    child_wait_for_sigkill()
}

// ---------------------------------------------------------------------------
// Child supervision
// ---------------------------------------------------------------------------

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

/// Drive one child to its cut, SIGKILL it, and return the durable handle it
/// published before dying.
fn crash_roster_cut(
    fixture: &PrivilegedFixture,
    namespace: &str,
    cut: ChildCut,
) -> TestResult<XfrmObjectRosterRecoveryHandle> {
    let ready_path = fixture.ready_path(cut.role);
    let handle_path = fixture.handle_path(cut.role);
    let mut child = TestChild::spawn(fixture.child_command(namespace, cut)?)?;
    let ready_bytes = fixture.readiness_bytes(cut.role, child.id()?);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;
    Ok(read_recovery_handle(&handle_path)?)
}

/// Drive the prepared child, which publishes no handle because a prepared
/// roster has no cleanup authority to correlate.
fn crash_prepared_cut(fixture: &PrivilegedFixture, namespace: &str) -> TestResult {
    let cut = ChildCut::simple(ROLE_PREPARED_CUT);
    let ready_path = fixture.ready_path(cut.role);
    let mut child = TestChild::spawn(fixture.child_command(namespace, cut)?)?;
    let ready_bytes = fixture.readiness_bytes(cut.role, child.id()?);
    child.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = child.kill_and_reap()?;
    assert_sigkill(&output)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Durable disposition assertions
// ---------------------------------------------------------------------------

fn assert_dispositions(
    dispositions: &XfrmObjectRosterMemberDispositions,
    expected: [&str; ROSTER_ARITY],
) -> TestResult {
    if dispositions.arity() != ROSTER_ARITY {
        return Err(io::Error::other("durable dispositions lost a member slot").into());
    }
    for (ordinal, phase) in expected.iter().enumerate() {
        let member = dispositions
            .member(ordinal)
            .ok_or_else(|| io::Error::other("durable dispositions lost a member slot"))?;
        if member.ordinal() != ordinal {
            return Err(io::Error::other("durable dispositions reordered members").into());
        }
        if member.phase() != *phase {
            return Err(io::Error::other(format!(
                "member {ordinal} durable phase was {} instead of {phase}",
                member.phase()
            ))
            .into());
        }
    }
    Ok(())
}

/// Re-authenticate the retained handle and assert every member slot, which is
/// the durable half of each detector's evidence.
fn assert_member_phases(
    store: &XfrmObjectRosterRecoveryStore,
    handle: &XfrmObjectRosterRecoveryHandle,
    fixture: &PrivilegedFixture,
    expected: [&str; ROSTER_ARITY],
) -> TestResult {
    let roster = roster_request()?;
    let dispositions = store.inspect_dispositions(
        handle,
        group_id(&fixture.token, 0)?,
        generation(1)?,
        &roster,
    )?;
    assert_dispositions(&dispositions, expected)
}

// ---------------------------------------------------------------------------
// Role 1: harness self-test
// ---------------------------------------------------------------------------

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
    for ordinal in 0..ROSTER_ARITY {
        assert!(install_member(&backend_a, ordinal)?.is_ok());
    }
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_no_roster_members(fixture.namespace_b())?;

    let child = ChildCut::simple(ROLE_HARNESS_SIGKILL);
    let ready_path = fixture.ready_path(child.role);
    let mut process = TestChild::spawn(fixture.child_command(fixture.namespace_a(), child)?)?;
    let ready_bytes = fixture.readiness_bytes(child.role, process.id()?);
    process.wait_for_readiness(&ready_path, &ready_bytes)?;
    let output = process.kill_and_reap()?;
    assert_sigkill(&output)?;

    // The child ran inside namespace A and died there. Namespace ownership,
    // the store root, and the exclusive claim all belong to this process.
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_no_roster_members(fixture.namespace_b())?;
    assert!(
        !path_exists(&fixture.store_path())?,
        "the harness self-test must not create a durable store"
    );

    drop(backend_a);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role 2: prepared cut
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn prepared_roster_cut_recovers_no_mutation_without_any_backend_call() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    assert!(
        !path_exists(&fixture.store_path())?,
        "the durable API must exclusively create its own store"
    );
    plant_neighbors(fixture.namespace_a())?;
    // An identical group in the foreign namespace makes an accidental
    // cross-namespace backend call observable.
    let foreign = bind_namespace(fixture.namespace_b())?;
    for ordinal in 0..ROSTER_ARITY {
        assert!(install_member(&foreign, ordinal)?.is_ok());
    }
    drop(foreign);
    assert_member_presence(fixture.namespace_b(), [true; ROSTER_ARITY])?;
    assert_no_roster_members(fixture.namespace_a())?;

    crash_prepared_cut(&fixture, fixture.namespace_a())?;
    assert_no_roster_members(fixture.namespace_a())?;

    // Plant every member through a non-cooperating binding after the cut. A
    // prepared roster owns nothing, so recovery must delete none of them.
    let replacement = bind_namespace(fixture.namespace_a())?;
    for ordinal in 0..ROSTER_ARITY {
        assert!(install_member(&replacement, ordinal)?.is_ok());
    }
    drop(replacement);
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let outcome =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(outcome.as_str(), "no_mutation");
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_neighbors_untouched(fixture.namespace_a())?;
    assert_member_presence(fixture.namespace_b(), [true; ROSTER_ARITY])?;

    // Idempotent re-recovery reports the retired record and still deletes
    // nothing.
    let repeated =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(repeated.as_str(), "retired");
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Roles 3, 4 and 12: issuing cuts
// ---------------------------------------------------------------------------

/// The member slots an `Issuing` cut at `ordinal` must leave behind.
///
/// This deliberately takes no effect-admission argument. The cut member's
/// terminal slot publication is exactly what the crash window omits, so the
/// slot reads `Pending` whether or not the kernel effect was admitted — which
/// is precisely why recovery has to consult the live kernel rather than the
/// slot alone.
fn expected_issuing_phases(ordinal: usize) -> [&'static str; ROSTER_ARITY] {
    let mut phases = ["pending"; ROSTER_ARITY];
    for phase in phases.iter_mut().take(ordinal) {
        *phase = "acquired";
    }
    phases
}

fn expected_issuing_kernel(ordinal: usize, admit_effect: bool) -> [bool; ROSTER_ARITY] {
    let mut present = [false; ROSTER_ARITY];
    for slot in present.iter_mut().take(ordinal) {
        *slot = true;
    }
    if admit_effect {
        present[ordinal] = true;
    }
    present
}

/// Real-process detector for one `Issuing` reconciliation verdict.
fn issuing_cut_detector(ordinal: usize, admit_effect: bool) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::at(ROLE_ISSUING_CUT, ordinal, admit_effect),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;

    // Durable side of the evidence.
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Issuing
    );
    assert_member_phases(&store, &handle, &fixture, expected_issuing_phases(ordinal))?;

    // Kernel side of the evidence, read straight out of `ip xfrm`.
    assert_member_presence(
        fixture.namespace_a(),
        expected_issuing_kernel(ordinal, admit_effect),
    )?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    // Role 12: the unresolved roster fences cooperating writers before any
    // kernel effect, and it keeps fencing until the verdict is durable.
    assert_writer_gate_closed(&backend, fixture.namespace_a())?;
    assert_member_presence(
        fixture.namespace_a(),
        expected_issuing_kernel(ordinal, admit_effect),
    )?;

    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let outcome =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(outcome.as_str(), "rolled_back");
    // The cut member is classified from its own adjacent proof against a fresh
    // readback: retired when its effect was admitted, provably no-mutation when
    // it was not. Either way the acquired prefix below it is compensated
    // exactly and no member above it is ever touched.
    let mut recovered = ["pending"; ROSTER_ARITY];
    for phase in recovered.iter_mut().take(ordinal) {
        *phase = "retired";
    }
    recovered[ordinal] = if admit_effect {
        "retired"
    } else {
        "no_mutation"
    };
    assert_dispositions(outcome.members(), recovered)?;

    // Every member the roster could have owned is gone, and nothing else is.
    assert_no_roster_members(fixture.namespace_a())?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    let repeated =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(repeated.as_str(), "retired");
    assert_no_roster_members(fixture.namespace_a())?;

    assert_writer_gate_reopened(&backend, fixture.namespace_a())?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_first_member_with_admitted_effect_rolls_back() -> TestResult {
    issuing_cut_detector(0, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_middle_member_with_admitted_effect_rolls_back() -> TestResult {
    issuing_cut_detector(2, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_last_member_with_admitted_effect_rolls_back() -> TestResult {
    issuing_cut_detector(4, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_middle_member_without_effect_compensates_only_the_prefix() -> TestResult {
    issuing_cut_detector(2, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_first_member_without_effect_compensates_only_the_prefix() -> TestResult {
    issuing_cut_detector(0, false)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn issuing_cut_at_last_member_without_effect_compensates_only_the_prefix() -> TestResult {
    issuing_cut_detector(4, false)
}

// ---------------------------------------------------------------------------
// Role 5: applied-unfinalized then RECOVER
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn applied_unfinalized_roster_recovers_the_whole_group_as_owned_residue() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::simple(ROLE_APPLIED_CUT),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;

    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Applied
    );
    assert_member_phases(&store, &handle, &fixture, ["acquired"; ROSTER_ARITY])?;
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    assert_writer_gate_closed(&backend, fixture.namespace_a())?;
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let outcome =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(outcome.as_str(), "owned_residue_retired");
    assert_dispositions(outcome.members(), ["retired"; ROSTER_ARITY])?;
    assert_no_roster_members(fixture.namespace_a())?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    let repeated =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(repeated.as_str(), "retired");
    assert_no_roster_members(fixture.namespace_a())?;

    assert_writer_gate_reopened(&backend, fixture.namespace_a())?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role 6: applied-unfinalized then ADOPT
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn applied_unfinalized_roster_adopts_every_member_without_deleting_anything() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::simple(ROLE_APPLIED_CUT),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;

    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Applied
    );
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_writer_gate_closed(&backend, fixture.namespace_a())?;

    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let adopted =
        block_on(backend.adopt_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(adopted.as_str(), "adopted");
    // Per-member ownership survives adoption, so a crash immediately after it
    // still classifies every object exactly.
    assert_dispositions(adopted.members(), ["acquired"; ROSTER_ARITY])?;

    // Adoption is additive: all five objects Linux acknowledged are still
    // there, and the durable record now carries the product's commitment.
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_neighbors_untouched(fixture.namespace_a())?;
    assert_eq!(
        block_on(backend.finalize_durable_object_roster(&store, group, generation(1)?, &roster))?,
        XfrmObjectRosterDurablePhase::Committed
    );
    // Committed is not an unresolved phase, so recovery reports it and never
    // deletes the adopted group.
    assert_eq!(
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?
            .as_str(),
        "committed"
    );
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    // The committed record is terminal, so the writer gate is open and the
    // consumer owns the objects. Retiring them advances the writer epoch,
    // which prunes the terminal record: no retained entries survive success.
    for ordinal in (0..ROSTER_ARITY).rev() {
        remove_member(&backend, ordinal)??;
    }
    assert_no_roster_members(fixture.namespace_a())?;
    assert_eq!(
        retained_record_count(&fixture.store_path(), &proof_key_bytes(&fixture.token))?,
        0
    );

    // The namespace and the store are cleanly reusable afterwards.
    let reuse_group = group_id(&fixture.token, 0x5a)?;
    let authority = block_on(backend.prepare_durable_object_roster(
        &store,
        reuse_group,
        generation(2)?,
        roster.clone(),
    ))?;
    let outcome = block_on(backend.run_durable_object_roster(authority))?;
    assert_eq!(outcome.as_str(), "applied");
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_eq!(
        block_on(backend.finalize_durable_object_roster(
            &store,
            reuse_group,
            generation(2)?,
            &roster
        ))?,
        XfrmObjectRosterDurablePhase::Committed
    );
    assert_neighbors_untouched(fixture.namespace_a())?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role 7: compensating cuts
// ---------------------------------------------------------------------------

/// Real-process detector for a crash in the middle of reverse compensation.
fn compensating_cut_detector(ordinal: usize, admit_effect: bool) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::at(ROLE_COMPENSATING_CUT, ordinal, admit_effect),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;

    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Compensating
    );
    // Compensation is strictly descending: everything above the cut is retired
    // and the cut member's removal is durably admitted but not acknowledged.
    let mut expected_phases = ["acquired"; ROSTER_ARITY];
    for phase in expected_phases.iter_mut().skip(ordinal + 1) {
        *phase = "retired";
    }
    expected_phases[ordinal] = "removal_admitted";
    assert_member_phases(&store, &handle, &fixture, expected_phases)?;

    let mut expected_kernel = [true; ROSTER_ARITY];
    for slot in expected_kernel.iter_mut().skip(ordinal + 1) {
        *slot = false;
    }
    expected_kernel[ordinal] = !admit_effect;
    assert_member_presence(fixture.namespace_a(), expected_kernel)?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    assert_writer_gate_closed(&backend, fixture.namespace_a())?;
    assert_member_presence(fixture.namespace_a(), expected_kernel)?;

    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let outcome =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(outcome.as_str(), "rolled_back");
    // Resumed compensation is strictly descending and finishes the job: every
    // slot the applied group owned is retired.
    assert_dispositions(outcome.members(), ["retired"; ROSTER_ARITY])?;
    assert_no_roster_members(fixture.namespace_a())?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    let repeated =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(repeated.as_str(), "retired");
    assert_no_roster_members(fixture.namespace_a())?;

    assert_writer_gate_reopened(&backend, fixture.namespace_a())?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn compensating_cut_with_admitted_delete_resumes_to_rolled_back() -> TestResult {
    compensating_cut_detector(2, true)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn compensating_cut_without_delete_resumes_to_rolled_back() -> TestResult {
    compensating_cut_detector(2, false)
}

// ---------------------------------------------------------------------------
// Role 8: foreign-object safety
// ---------------------------------------------------------------------------

/// Real-process detector proving a non-cooperating object at a member identity
/// aborts the whole group before any effect and is never touched afterwards.
fn foreign_member_detector(ordinal: usize) -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    // Plant through raw iproute2, never through the SDK: this writer does not
    // cooperate with the durable gate and the gate cannot exclude it.
    let snapshot = match ROSTER_MEMBERS[ordinal] {
        MemberKind::Sa { spi } => {
            plant_foreign_member_sa(fixture.namespace_a(), spi)?;
            foreign_sa_snapshot(fixture.namespace_a(), spi)?
        }
        MemberKind::Policy { if_id, .. } => {
            plant_foreign_member_policy(fixture.namespace_a(), if_id)?;
            foreign_policy_snapshot(fixture.namespace_a(), if_id)?
        }
    };

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::simple(ROLE_CONFLICT_TERMINAL),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;

    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::NoMutation
    );
    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let dispositions = store.inspect_dispositions(&handle, group, generation(1)?, &roster)?;
    assert!(
        dispositions.has_conflict(),
        "the durable record must name the conflicting member"
    );
    let conflicted = dispositions
        .member(ordinal)
        .ok_or_else(|| io::Error::other("durable dispositions lost the conflicting member"))?;
    assert!(
        conflicted.is_conflicting(),
        "the conflicting ordinal must be the planted one"
    );
    assert_eq!(conflicted.sweep_proof(), Some("conflict"));

    // Zero effects: only the planted object exists at a member identity.
    let mut expected_kernel = [false; ROSTER_ARITY];
    expected_kernel[ordinal] = true;
    assert_member_presence(fixture.namespace_a(), expected_kernel)?;

    let outcome =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(outcome.as_str(), "foreign_untouched");
    // The named deletion invariant, restated over the verdict itself: a group
    // that aborted on a sweep conflict never owned a member, so no slot may
    // report acquisition or removal.
    for member in outcome.members().iter() {
        assert!(
            !matches!(member.phase(), "acquired" | "removal_admitted" | "retired"),
            "a zero-effect roster reported member ownership"
        );
    }

    // The planted object survives with the parameters it was planted with, so
    // it cannot have been deleted and reinstalled by the roster.
    let after = match ROSTER_MEMBERS[ordinal] {
        MemberKind::Sa { spi } => foreign_sa_snapshot(fixture.namespace_a(), spi)?,
        MemberKind::Policy { if_id, .. } => foreign_policy_snapshot(fixture.namespace_a(), if_id)?,
    };
    assert_eq!(after, snapshot, "the foreign object was not left as found");
    assert_member_presence(fixture.namespace_a(), expected_kernel)?;
    assert_neighbors_untouched(fixture.namespace_a())?;

    let repeated =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))?;
    assert_eq!(repeated.as_str(), "retired");
    assert_member_presence(fixture.namespace_a(), expected_kernel)?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn foreign_policy_at_a_member_identity_survives_the_whole_transaction() -> TestResult {
    foreign_member_detector(2)
}

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn foreign_sa_at_a_member_identity_survives_the_whole_transaction() -> TestResult {
    foreign_member_detector(3)
}

// ---------------------------------------------------------------------------
// Role 9: unmarked/marked kernel divergence
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn unmarked_and_marked_sa_pair_collides_in_the_kernel_and_is_rejected() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    let namespace = fixture.namespace_a();
    let encoded_spi = format!("0x{MARK_DIVERGENCE_SPI:08x}");
    let encoded_mark = format!("0x{MARK_DIVERGENCE_MARK:08x}");

    // An unmarked SA first.
    let unmarked = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "state",
        "add",
        "src",
        SA_SOURCE_TEXT,
        "dst",
        SA_DESTINATION_TEXT,
        "proto",
        "esp",
        "spi",
        &encoded_spi,
        "mode",
        "tunnel",
        "enc",
        "cbc(aes)",
        FOREIGN_ENCRYPTION_KEY,
    ])?;
    if !unmarked.status.success() {
        return Err(command_error("add the unmarked divergence SA", &unmarked).into());
    }
    assert_eq!(sa_spi_count(namespace, MARK_DIVERGENCE_SPI)?, 1);

    // A full-mask marked SA at the same destination, protocol, and SPI. Linux
    // matches a stored SA's mark mask against the incoming lookup value, so
    // the unmarked SA is already selected for every lookup value and the
    // kernel refuses the second insertion outright.
    let marked = run_ip(&[
        "netns",
        "exec",
        namespace,
        "ip",
        "xfrm",
        "state",
        "add",
        "src",
        SA_SOURCE_TEXT,
        "dst",
        SA_DESTINATION_TEXT,
        "proto",
        "esp",
        "spi",
        &encoded_spi,
        "mode",
        "tunnel",
        "mark",
        &encoded_mark,
        "mask",
        "0xffffffff",
        "enc",
        "cbc(aes)",
        FOREIGN_ENCRYPTION_KEY,
    ])?;
    assert!(
        !marked.status.success(),
        "the kernel accepted an unmarked/marked SA pair it must reject"
    );
    let diagnostics = String::from_utf8_lossy(&marked.stderr).to_ascii_lowercase();
    assert!(
        diagnostics.contains("file exists"),
        "the kernel rejected the marked SA for an unexpected reason"
    );
    // The rejection left the original untouched, so a roster that admitted the
    // pair would have installed one member and then failed the other.
    assert_eq!(sa_spi_count(namespace, MARK_DIVERGENCE_SPI)?, 1);

    // The constructor rejects the same pair before anything durable happens.
    // Only a real kernel can witness the collision above; the mock backend
    // keys on the whole request and would accept both members happily.
    let ambiguous = XfrmObjectRosterRequest::new(vec![
        XfrmObjectRosterMemberRequest::new(sa_object_request(MARK_DIVERGENCE_SPI, None)),
        XfrmObjectRosterMemberRequest::new(sa_object_request(
            MARK_DIVERGENCE_SPI,
            Some(XfrmLookupMark::full(MARK_DIVERGENCE_MARK)),
        )),
    ])
    .expect_err("the constructor must reject a kernel-ambiguous member pair");
    assert_eq!(
        ambiguous,
        XfrmObjectRosterRequestError::AmbiguousKernelSelection
    );

    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role 10: poisoned actor incarnation
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn poisoned_actor_incarnation_fails_closed_and_deletes_nothing() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    plant_neighbors(fixture.namespace_a())?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::simple(ROLE_APPLIED_CUT),
    )?;
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Applied
    );
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    poison_record_incarnation(
        &fixture.store_path(),
        &handle,
        &proof_key_bytes(&fixture.token),
    )?;

    let roster = roster_request()?;
    let group = group_id(&fixture.token, 0)?;
    let rejected =
        block_on(backend.recover_durable_object_roster(&store, group, generation(1)?, &roster))
            .expect_err("a record from another writer incarnation must be rejected");
    assert_eq!(rejected, XfrmObjectRosterDurableError::WrongIncarnation);

    // A correctly authenticated but wrong-incarnation record must not have
    // authorized a single deletion.
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;
    assert_neighbors_untouched(fixture.namespace_a())?;
    // Adoption is additive and must fail closed the same way.
    let refused =
        block_on(backend.adopt_durable_object_roster(&store, group, generation(1)?, &roster))
            .expect_err("adoption must reject a wrong-incarnation record too");
    assert_eq!(refused, XfrmObjectRosterDurableError::WrongIncarnation);
    assert_member_presence(fixture.namespace_a(), [true; ROSTER_ARITY])?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Role 11: wrong-namespace bind
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires root, CAP_SYS_ADMIN/CAP_NET_ADMIN, iproute2, and named netns support"]
fn roster_store_from_another_namespace_is_rejected_at_bind() -> TestResult {
    if !privileged_enabled() {
        return Ok(());
    }

    let fixture = PrivilegedFixture::provision()?;
    // Deliberately identical objects in namespace B. Without namespace
    // validation a matching readback would authorize deleting them.
    let foreign = bind_namespace(fixture.namespace_b())?;
    for ordinal in 0..ROSTER_ARITY {
        assert!(install_member(&foreign, ordinal)?.is_ok());
    }
    drop(foreign);
    assert_member_presence(fixture.namespace_b(), [true; ROSTER_ARITY])?;

    let handle = crash_roster_cut(
        &fixture,
        fixture.namespace_a(),
        ChildCut::simple(ROLE_APPLIED_CUT),
    )?;

    let wrong_binding = try_bind_namespace_with_recovery(
        fixture.namespace_b(),
        fixture.store_path(),
        &fixture.token,
    )?
    .expect_err("a roster store from another namespace must be rejected");
    assert!(matches!(
        wrong_binding,
        XfrmObjectRecoveryBindError::RosterStore {
            source: XfrmObjectRosterDurableError::WrongBinding
        }
    ));
    assert_member_presence(fixture.namespace_b(), [true; ROSTER_ARITY])?;

    // The correct namespace still recovers its own group, and only its own.
    let (backend, store) = bind_namespace_with_recovery(fixture.namespace_a(), &fixture)?;
    assert_eq!(
        store.inspect(&handle)?,
        XfrmObjectRosterDurablePhase::Applied
    );
    let roster = roster_request()?;
    let outcome = block_on(backend.recover_durable_object_roster(
        &store,
        group_id(&fixture.token, 0)?,
        generation(1)?,
        &roster,
    ))?;
    assert_eq!(outcome.as_str(), "owned_residue_retired");
    assert_no_roster_members(fixture.namespace_a())?;
    assert_member_presence(fixture.namespace_b(), [true; ROSTER_ARITY])?;

    drop(store);
    drop(backend);
    fixture.cleanup()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Child entry point
// ---------------------------------------------------------------------------

#[test]
#[ignore = "child role launched only by the privileged parent detector"]
fn xfrm_object_roster_recovery_privileged_child() -> TestResult {
    let Some(context) = child_context()? else {
        return Ok(());
    };
    run_child(context)
}
