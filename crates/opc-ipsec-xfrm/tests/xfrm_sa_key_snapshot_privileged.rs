//! Privileged Linux-kernel checks for key-scoped SA snapshots and unavailable
//! exact SA removal.
//!
//! Run this ignored test inside a fresh network namespace. It installs a
//! marked SA and then an unmarked SA at one destination/protocol/SPI key,
//! which Linux admits, and proves on the kernel that:
//!
//! - an `XFRM_MSG_GETSA` carrying the marked SA's own mark is answered by the
//!   unmarked SA, so a point query cannot identify the marked SA;
//! - the `NLM_F_DUMP` key snapshot reports both states;
//! - `remove_sa_exact` reports `UnsupportedFeature` for overlapping, sole,
//!   disjoint, absent and changed candidates and leaves the fixtures intact;
//! - an unmarked SA refuses a later marked install at its key;
//! - the key read stays exact when several hundred other states at the same
//!   destination make the kernel split the dump into many multipart batches;
//! - a state whose dump message does not fit an empty dump batch never makes
//!   the read a false complete. Linux ends such a dump with a successful
//!   `NLMSG_DONE`, silently dropping that state and every older one, so the
//!   read must either still be complete or fail with `StateIndeterminate`;
//! - a larval state from a kernel ACQUIRE makes the read and the exact
//!   removal fail closed. Linux inserts one when outbound traffic matches a
//!   policy template that no SA satisfies while a key manager listens; the
//!   test listens with `ip xfrm monitor acquire`. The test replays the review
//!   counterexample one kernel step at a time: an oversized target U and a
//!   newer state E with a short hard lifetime give a SAD count of 2, an
//!   ACQUIRE inserts a larval state A, a dump returns A and E and silently
//!   stops at U, and E expires, so the count is 2 again with U missing from
//!   the dump. It also covers an ordinary target beside a larval state, an
//!   ordinary target hidden by an unrelated oversized state, recovery once
//!   the larval states expire, and the larval state of an SPI allocation.
//!
//! The test prints `SA_KEY_SNAPSHOT_TRUNCATION_PROOF_OK`,
//! `SA_KEY_SNAPSHOT_ACQUIRE_PROOF_OK`, and `SA_KEY_SNAPSHOT_PROOF_OK` only
//! after every assertion.
//! Raw removals below only manage isolated test fixtures after refusal and
//! unchanged-state checks. They do not demonstrate exact cleanup support.

#![cfg(target_os = "linux")]

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use opc_ipsec_xfrm::{
    Algorithm, AllocateSpiRequest, AuthAlgorithm, ExactRemoveSaRequest, InstallSaRequest,
    IpAddress, KeyMaterial, LifetimeConfig, LinuxXfrmBackend, LinuxXfrmBackendConfig,
    QuerySaRequest, RemoveSaRequest, SaKeySnapshot, SaLookupKey, SaParameters,
    SaRelocationIdentity, XfrmBackend, XfrmError, XfrmId, XfrmLookupMark, XfrmMode, XfrmRequestId,
    XfrmSelector,
};

const IPPROTO_ESP: u8 = 50;
const KEY_SPI: u32 = 0x5150_0001;
const MULTIPART_KEY_SPI: u32 = 0x5150_0002;
const FILLER_SPI_BASE: u32 = 0x5151_0000;
/// Each dumped ESP state is a 224-byte `xfrm_usersa_info` plus its
/// attributes, so this many states exceed the kernel's 32 KiB dump batch
/// many times over and force a multipart reply.
const FILLER_STATES: u32 = 384;
const MARK: u32 = 0x42;
const DISJOINT_MARK: u32 = 0x43;
const LINUX_EMSGSIZE: i32 = nix::errno::Errno::EMSGSIZE as i32;
const TRUNCATION_TARGET_SPI: u32 = 0x5152_0001;
const TRUNCATION_OVERLAP_SPI: u32 = 0x5152_0002;
const TRUNCATION_KEY_SPI: u32 = 0x5152_0003;
const LARGE_STATE_SPI_BASE: u32 = 0x5153_0000;
/// An HMAC key this long makes a dumped state about 4.6 KiB, because Linux
/// reports the key in both `XFRMA_ALG_AUTH` and `XFRMA_ALG_AUTH_TRUNC`. That
/// exceeds the first dump batch of a fresh socket (`NLMSG_GOODSIZE`, about
/// 3.7 KiB with 4 KiB pages) but fits the 8 KiB batch that the default
/// receive buffer requests.
const LARGE_KEY_BYTES: usize = 2048;
/// About 12.6 KiB per dumped state: above the default 8 KiB batch, below the
/// kernel's 32 KiB dump-batch cap.
const BATCH_EXCEEDING_KEY_BYTES: usize = 6144;
/// About 33 KiB per dumped state: above the 32 KiB cap, so no dump batch
/// can hold it.
const UNDUMPABLE_KEY_BYTES: usize = 16384;
const ACQUIRE_OVERSIZED_SPI: u32 = 0x5154_0001;
const ACQUIRE_EXPIRING_SPI: u32 = 0x5154_0002;
const ACQUIRE_TARGET_SPI: u32 = 0x5154_0003;
const ACQUIRE_BLOCKER_SPI: u32 = 0x5154_0004;
const ALLOCATED_SPI_MIN: u32 = 0x5155_0000;
const ALLOCATED_SPI_MAX: u32 = 0x5155_ffff;
/// The hard lifetime of the expiring state E.
const EXPIRING_LIFETIME_SECONDS: u64 = 2;
/// `net.core.xfrm_acq_expires` during the ACQUIRE phase: long enough for a
/// larval state to outlive E, short enough to wait for.
const ACQUIRE_LIFETIME_SECONDS: u64 = 6;
const ACQ_EXPIRES_SYSCTL: &str = "/proc/sys/net/core/xfrm_acq_expires";
const DEFAULT_ACQ_EXPIRES: &str = "30\n";
const ACQUIRE_LINK: &str = "opcacq0";
const ACQUIRE_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const ACQUIRE_POLICY: [&str; 8] = [
    "src",
    "198.18.0.1/32",
    "dst",
    "198.18.0.0/16",
    "proto",
    "udp",
    "dir",
    "out",
];

fn ipv4(octets: [u8; 4]) -> IpAddress {
    IpAddress::Ipv4(octets)
}

fn sa(spi: u32, mark: Option<XfrmLookupMark>, request_id: u32) -> SaParameters {
    SaParameters {
        selector: XfrmSelector::new(ipv4([10, 51, 5, 1]), ipv4([10, 51, 5, 2]), 0),
        id: XfrmId {
            destination: ipv4([192, 0, 2, 51]),
            spi,
            protocol: IPPROTO_ESP,
        },
        source_address: ipv4([192, 0, 2, 50]),
        request_id: XfrmRequestId::new(request_id),
        auth: Some((
            AuthAlgorithm::hmac_sha256(128),
            KeyMaterial::new(vec![0x51; 32]),
        )),
        crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0x50; 16]))),
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

fn marked(spi: u32) -> SaParameters {
    sa(spi, Some(XfrmLookupMark::full(MARK)), 1)
}

fn unmarked(spi: u32) -> SaParameters {
    sa(spi, None, 2)
}

/// A valid unmarked ESP SA with an HMAC key of `key_bytes` bytes; HMAC
/// accepts any key length.
fn large_key_sa(spi: u32, key_bytes: usize) -> SaParameters {
    let mut parameters = sa(spi, None, 4);
    parameters.auth = Some((
        AuthAlgorithm::hmac_sha256(128),
        KeyMaterial::new(vec![0x5a; key_bytes]),
    ));
    parameters
}

fn key(spi: u32) -> SaLookupKey {
    SaLookupKey::new(ipv4([192, 0, 2, 51]), IPPROTO_ESP, spi)
}

async fn install(backend: &impl XfrmBackend, parameters: &SaParameters) -> Result<(), XfrmError> {
    backend
        .install_sa(InstallSaRequest {
            parameters: parameters.clone(),
        })
        .await
}

/// The kernel's own identity for the state a lookup carrying `mark` selects.
async fn lookup(
    backend: &impl XfrmBackend,
    spi: u32,
    mark: Option<XfrmLookupMark>,
) -> Result<SaRelocationIdentity, XfrmError> {
    let query = QuerySaRequest::new(ipv4([192, 0, 2, 51]), IPPROTO_ESP, spi);
    backend
        .query_sa_relocation_identity(match mark {
            Some(mark) => query.with_mark(mark),
            None => query,
        })
        .await
}

async fn snapshot(backend: &impl XfrmBackend, spi: u32) -> Result<SaKeySnapshot, XfrmError> {
    backend.query_sa_key_snapshot(key(spi)).await
}

fn marks(snapshot: &SaKeySnapshot) -> Vec<Option<XfrmLookupMark>> {
    snapshot.states().iter().map(|state| state.mark).collect()
}

fn read_failed_closed(read: &Result<SaKeySnapshot, XfrmError>) -> bool {
    matches!(
        read,
        Err(XfrmError::StateIndeterminate {
            operation: "query_sa_key_snapshot"
        })
    )
}

fn read_is_exactly(
    read: &Result<SaKeySnapshot, XfrmError>,
    expected: &[SaRelocationIdentity],
) -> bool {
    read.as_ref()
        .is_ok_and(|snapshot| snapshot.states() == expected)
}

/// Render a read for the proof log without addresses or keys.
fn describe(read: &Result<SaKeySnapshot, XfrmError>) -> String {
    match read {
        Ok(snapshot) => format!("complete with {} state(s)", snapshot.len()),
        Err(error) => format!("error: {error}"),
    }
}

async fn remove_unmarked(backend: &impl XfrmBackend, spi: u32) -> Result<(), XfrmError> {
    backend
        .remove_sa(RemoveSaRequest::new(
            ipv4([192, 0, 2, 51]),
            IPPROTO_ESP,
            spi,
        ))
        .await
}

async fn remove_marked(backend: &impl XfrmBackend, spi: u32) -> Result<(), XfrmError> {
    backend
        .remove_sa(
            RemoveSaRequest::new(ipv4([192, 0, 2, 51]), IPPROTO_ESP, spi)
                .with_mark(XfrmLookupMark::full(MARK)),
        )
        .await
}

fn refused_as_unsupported(result: Result<(), XfrmError>) -> bool {
    matches!(
        result,
        Err(XfrmError::UnsupportedFeature {
            feature: "exact_sa_removal"
        })
    )
}

/// Assert the capability refusal before any fixture teardown. Ordinary
/// fixtures must retain the same lookup identity (or remain absent). For an
/// oversized fixture, Linux GETSA finds the state but cannot encode it in
/// `NLMSG_DEFAULT_SIZE`, returning EMSGSIZE rather than ESRCH. Retaining that
/// result witnesses its presence; it is not a complete identity readback.
async fn assert_refused_without_changing_fixture_lookup(
    backend: &impl XfrmBackend,
    expected: &SaRelocationIdentity,
) {
    let before = lookup(backend, expected.id.spi, expected.mark).await;
    let removal = backend
        .remove_sa_exact(ExactRemoveSaRequest::new(expected.clone()))
        .await;
    assert!(refused_as_unsupported(removal.clone()), "{removal:?}");
    let after = lookup(backend, expected.id.spi, expected.mark).await;
    match (before, after) {
        (Ok(before), Ok(after)) => assert_eq!(after, before),
        (Err(XfrmError::NotFound), Err(XfrmError::NotFound)) => {}
        (
            Err(XfrmError::Io {
                raw_os_error: Some(LINUX_EMSGSIZE),
                ..
            }),
            Err(XfrmError::Io {
                raw_os_error: Some(LINUX_EMSGSIZE),
                ..
            }),
        ) => {}
        (before, after) => {
            panic!("fixture lookup changed across exact-removal refusal: {before:?} -> {after:?}")
        }
    }
}

fn ip(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("ip").args(args).env("LC_ALL", "C").output()?;
    if !output.status.success() {
        return Err(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// The kernel's SAD count (`XFRMA_SAD_CNT`), as `ip xfrm state count` prints
/// it.
fn sad_count() -> Result<u32, Box<dyn Error>> {
    let report = ip(&["xfrm", "state", "count"])?;
    let count = report
        .split_whitespace()
        .last()
        .ok_or("empty SAD count report")?;
    Ok(count.parse()?)
}

/// How many states one `XFRM_MSG_GETSA` dump returns; `ip -oneline` prints
/// one line per state.
fn dumped_state_count() -> Result<usize, Box<dyn Error>> {
    Ok(ip(&["-oneline", "xfrm", "state", "list"])?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

/// Whether a `NETLINK_XFRM` socket in this namespace has joined
/// `XFRMNLGRP_ACQUIRE`, group 1 and so bit 0 of the first group word.
fn acquire_listener_registered() -> io::Result<bool> {
    const NETLINK_XFRM: &str = "6";
    let table = fs::read_to_string("/proc/net/netlink")?;
    Ok(table.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() > 3
            && fields[1] == NETLINK_XFRM
            && u32::from_str_radix(fields[3], 16).is_ok_and(|groups| groups & 1 != 0)
    }))
}

/// A dummy link, an ACQUIRE listener, and an outbound policy whose template
/// no SA satisfies. Each datagram to a destination behind the link that no
/// earlier datagram used makes Linux insert one larval ACQUIRE state, which
/// expires after `ACQUIRE_LIFETIME_SECONDS`.
struct AcquireLab {
    listener: Option<Child>,
    socket: Option<UdpSocket>,
    link: bool,
    policy: bool,
    next_host: u32,
}

impl AcquireLab {
    fn start() -> Result<Self, Box<dyn Error>> {
        let mut lab = Self {
            listener: None,
            socket: None,
            link: false,
            policy: false,
            next_host: 2,
        };
        fs::write(ACQ_EXPIRES_SYSCTL, format!("{ACQUIRE_LIFETIME_SECONDS}\n"))?;
        ip(&["link", "add", ACQUIRE_LINK, "type", "dummy"])?;
        lab.link = true;
        ip(&["address", "add", "198.18.0.1/16", "dev", ACQUIRE_LINK])?;
        ip(&["link", "set", ACQUIRE_LINK, "up"])?;
        lab.listener = Some(
            Command::new("ip")
                .args(["xfrm", "monitor", "acquire"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !acquire_listener_registered()? {
            if Instant::now() >= deadline {
                return Err("the ACQUIRE listener never joined its group".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut policy = vec!["xfrm", "policy", "add"];
        policy.extend(ACQUIRE_POLICY);
        policy.extend([
            "tmpl",
            "proto",
            "esp",
            "mode",
            "transport",
            "reqid",
            "0x5154",
        ]);
        ip(&policy)?;
        lab.policy = true;
        lab.socket = Some(UdpSocket::bind(SocketAddrV4::new(ACQUIRE_SOURCE, 0))?);
        Ok(lab)
    }

    /// Make Linux insert one new larval state. The datagram itself is
    /// dropped.
    fn trigger(&mut self) -> io::Result<()> {
        let [_, _, high, low] = self.next_host.to_be_bytes();
        self.next_host += 1;
        self.socket
            .as_ref()
            .ok_or_else(|| io::Error::other("ACQUIRE socket unavailable"))?
            .send_to(
                b"acquire",
                SocketAddrV4::new(Ipv4Addr::new(198, 18, high, low), 9),
            )?;
        Ok(())
    }

    /// Stop further ACQUIREs. Larval states already inserted stay until they
    /// expire.
    fn remove_policy(&mut self) -> Result<(), Box<dyn Error>> {
        if self.policy {
            let mut policy = vec!["xfrm", "policy", "delete"];
            policy.extend(ACQUIRE_POLICY);
            ip(&policy)?;
            self.policy = false;
        }
        Ok(())
    }
}

impl Drop for AcquireLab {
    fn drop(&mut self) {
        if let Some(mut listener) = self.listener.take() {
            let _ = listener.kill();
            let _ = listener.wait();
        }
        let _ = self.remove_policy();
        if self.link {
            let _ = Command::new("ip")
                .args(["link", "del", ACQUIRE_LINK])
                .output();
        }
        let _ = fs::write(ACQ_EXPIRES_SYSCTL, DEFAULT_ACQ_EXPIRES);
    }
}

/// Record a failed snapshot refusal, then require the exact-removal
/// capability refusal and the same fixture lookup observation.
async fn expect_refused(
    backend: &impl XfrmBackend,
    identity: &SaRelocationIdentity,
    label: &str,
    failures: &mut Vec<String>,
) {
    let read = snapshot(backend, identity.id.spi).await;
    println!("{label}: read {}", describe(&read));
    if !read_failed_closed(&read) {
        failures.push(format!("{label}: read {}", describe(&read)));
    }
    assert_refused_without_changing_fixture_lookup(backend, identity).await;
}

/// Poll until `spi`'s unmarked state is gone, as after its hard expiry.
async fn wait_until_removed(
    backend: &impl XfrmBackend,
    spi: u32,
    within: Duration,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + within;
    loop {
        match lookup(backend, spi, None).await {
            Err(XfrmError::NotFound) => return Ok(()),
            Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Ok(_) => return Err("the expiring state outlived its hard lifetime".into()),
            Err(error) => return Err(error.into()),
        }
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, XFRM, and a fresh network namespace"]
async fn key_snapshot_proves_overlapping_lookup_candidates_on_the_kernel(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_XFRM_RUN_SA_KEY_SNAPSHOT_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping: set OPC_XFRM_RUN_SA_KEY_SNAPSHOT_PRIVILEGED=1 inside a fresh privileged netns"
        );
        return Ok(());
    }
    let backend = LinuxXfrmBackend::new().bind_current_network_namespace()?;

    // No state at the key: an empty snapshot, and nothing to remove.
    assert!(snapshot(&backend, KEY_SPI).await?.is_empty());
    let marked_sa = marked(KEY_SPI);
    let unmarked_sa = unmarked(KEY_SPI);
    install(&backend, &marked_sa).await?;
    let marked_identity = lookup(&backend, KEY_SPI, marked_sa.mark).await?;
    assert_eq!(marked_identity.mark, marked_sa.mark);

    // Linux admits an unmarked state next to the marked one...
    install(&backend, &unmarked_sa).await?;
    let unmarked_identity = lookup(&backend, KEY_SPI, None).await?;
    assert_eq!(unmarked_identity.mark, None);
    assert_ne!(unmarked_identity, marked_identity);
    // ...and the newer unmarked state, at the head of the SPI hash chain,
    // answers a GETSA that carries the marked state's own mark.
    assert_eq!(
        lookup(&backend, KEY_SPI, marked_sa.mark).await?,
        unmarked_identity
    );

    // The dump reports both states, newest first.
    let both = snapshot(&backend, KEY_SPI).await?;
    assert_eq!(
        both.states(),
        &[unmarked_identity.clone(), marked_identity.clone()]
    );
    assert_eq!(both.lookup_candidates(marked_sa.mark).count(), 2);
    assert_eq!(both.lookup_candidates(None).count(), 1);

    // Exact removal is unavailable, including when the key has overlapping
    // candidates. Neither fixture changes.
    assert_refused_without_changing_fixture_lookup(&backend, &marked_identity).await;
    assert_eq!(snapshot(&backend, KEY_SPI).await?.len(), 2);
    assert_eq!(snapshot(&backend, KEY_SPI).await?, both);

    // A sole candidate is still refused. Only after checking the unchanged
    // fixture do we explicitly tear down its unmarked state for the next case.
    assert_refused_without_changing_fixture_lookup(&backend, &unmarked_identity).await;
    assert_eq!(snapshot(&backend, KEY_SPI).await?, both);
    remove_unmarked(&backend, KEY_SPI).await?;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&marked_identity)
    );
    assert!(matches!(
        lookup(&backend, KEY_SPI, None).await,
        Err(XfrmError::NotFound)
    ));
    // A disjoint full-mask state at the key is never a candidate.
    let disjoint_sa = sa(KEY_SPI, Some(XfrmLookupMark::full(DISJOINT_MARK)), 3);
    install(&backend, &disjoint_sa).await?;
    let disjoint_identity = lookup(&backend, KEY_SPI, disjoint_sa.mark).await?;
    assert_eq!(disjoint_identity.mark, disjoint_sa.mark);
    let disjoint_pair = snapshot(&backend, KEY_SPI).await?;
    assert_refused_without_changing_fixture_lookup(&backend, &marked_identity).await;
    assert_eq!(snapshot(&backend, KEY_SPI).await?, disjoint_pair);
    // Isolated fixture teardown; exact removal above performed no cleanup.
    remove_marked(&backend, KEY_SPI).await?;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&disjoint_identity)
    );
    // Both an absent fixture and changed expected fields still receive the
    // same capability refusal, without changing the remaining disjoint state.
    assert_refused_without_changing_fixture_lookup(&backend, &marked_identity).await;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&disjoint_identity)
    );
    let mut changed = disjoint_identity.clone();
    changed.request_id = XfrmRequestId::new(99);
    assert_refused_without_changing_fixture_lookup(&backend, &changed).await;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&disjoint_identity)
    );
    assert_refused_without_changing_fixture_lookup(&backend, &disjoint_identity).await;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&disjoint_identity)
    );
    // Explicit teardown of the synthetic disjoint-mark fixture only.
    backend
        .remove_sa(
            RemoveSaRequest::new(ipv4([192, 0, 2, 51]), IPPROTO_ESP, KEY_SPI)
                .with_mark(XfrmLookupMark::full(DISJOINT_MARK)),
        )
        .await?;
    assert!(snapshot(&backend, KEY_SPI).await?.is_empty());

    // In the other order, the unmarked state answers the marked install's
    // own lookup, so Linux refuses it.
    install(&backend, &unmarked_sa).await?;
    assert!(matches!(
        install(&backend, &marked_sa).await,
        Err(XfrmError::AlreadyExists)
    ));
    assert_eq!(marks(&snapshot(&backend, KEY_SPI).await?), vec![None]);
    backend
        .remove_sa(RemoveSaRequest::new(
            ipv4([192, 0, 2, 51]),
            IPPROTO_ESP,
            KEY_SPI,
        ))
        .await?;

    // A dump far larger than one netlink batch: every filler shares the
    // key's destination and protocol, so the kernel filter passes all of
    // them and only the SPI check separates the key's two states.
    for index in 0..FILLER_STATES {
        install(&backend, &marked(FILLER_SPI_BASE + index)).await?;
    }
    install(&backend, &marked(MULTIPART_KEY_SPI)).await?;
    for index in 0..FILLER_STATES {
        install(&backend, &unmarked(FILLER_SPI_BASE + FILLER_STATES + index)).await?;
    }
    install(&backend, &unmarked(MULTIPART_KEY_SPI)).await?;
    let multipart = snapshot(&backend, MULTIPART_KEY_SPI).await?;
    assert_eq!(
        marks(&multipart),
        vec![None, Some(XfrmLookupMark::full(MARK))]
    );
    assert!(multipart
        .states()
        .iter()
        .all(|state| state.id.spi == MULTIPART_KEY_SPI));
    let multipart_marked = multipart.states()[1].clone();
    let multipart_unmarked = multipart.states()[0].clone();
    assert_refused_without_changing_fixture_lookup(&backend, &multipart_marked).await;
    assert_eq!(snapshot(&backend, MULTIPART_KEY_SPI).await?.len(), 2);
    assert_eq!(snapshot(&backend, MULTIPART_KEY_SPI).await?, multipart);
    assert_refused_without_changing_fixture_lookup(&backend, &multipart_unmarked).await;
    assert_eq!(snapshot(&backend, MULTIPART_KEY_SPI).await?, multipart);
    // Teardown after refusal arranges the sole-candidate fixture.
    remove_unmarked(&backend, MULTIPART_KEY_SPI).await?;
    assert_refused_without_changing_fixture_lookup(&backend, &multipart_marked).await;
    assert_eq!(
        snapshot(&backend, MULTIPART_KEY_SPI).await?.states(),
        std::slice::from_ref(&multipart_marked)
    );
    remove_marked(&backend, MULTIPART_KEY_SPI).await?;
    assert!(snapshot(&backend, MULTIPART_KEY_SPI).await?.is_empty());
    for index in 0..FILLER_STATES * 2 {
        let spi = FILLER_SPI_BASE + index;
        let removal = RemoveSaRequest::new(ipv4([192, 0, 2, 51]), IPPROTO_ESP, spi);
        let removal = if index < FILLER_STATES {
            removal.with_mark(XfrmLookupMark::full(MARK))
        } else {
            removal
        };
        backend.remove_sa(removal).await?;
    }
    assert!(snapshot(&backend, FILLER_SPI_BASE).await?.is_empty());

    // Oversized states. Each case records its outcome so that one run shows
    // every case; the assertion follows after the namespace is clean again.
    let mut failures = Vec::new();

    // 1. A newer large-key state at the target's destination and protocol,
    // but another SPI, is the first state the dump reaches.
    let target_sa = marked(TRUNCATION_TARGET_SPI);
    install(&backend, &target_sa).await?;
    let target = lookup(&backend, TRUNCATION_TARGET_SPI, target_sa.mark).await?;
    install(
        &backend,
        &large_key_sa(LARGE_STATE_SPI_BASE, LARGE_KEY_BYTES),
    )
    .await?;
    let read = snapshot(&backend, TRUNCATION_TARGET_SPI).await;
    println!("large state before an ordinary target: {}", describe(&read));
    if !read_is_exactly(&read, std::slice::from_ref(&target)) {
        failures.push(format!(
            "ordinary target behind a large state: {}",
            describe(&read)
        ));
    }
    assert_refused_without_changing_fixture_lookup(&backend, &target).await;
    assert_eq!(
        snapshot(&backend, TRUNCATION_TARGET_SPI).await?.states(),
        std::slice::from_ref(&target)
    );
    // Isolated fixture teardown follows the no-change assertion.
    remove_marked(&backend, TRUNCATION_TARGET_SPI).await?;
    remove_unmarked(&backend, LARGE_STATE_SPI_BASE).await?;

    // 2. The same large state in front of an overlapping pair.
    let overlap_marked = marked(TRUNCATION_OVERLAP_SPI);
    let overlap_unmarked = unmarked(TRUNCATION_OVERLAP_SPI);
    install(&backend, &overlap_marked).await?;
    let overlap_marked_identity =
        lookup(&backend, TRUNCATION_OVERLAP_SPI, overlap_marked.mark).await?;
    install(&backend, &overlap_unmarked).await?;
    let overlap_unmarked_identity = lookup(&backend, TRUNCATION_OVERLAP_SPI, None).await?;
    install(
        &backend,
        &large_key_sa(LARGE_STATE_SPI_BASE + 1, LARGE_KEY_BYTES),
    )
    .await?;
    let read = snapshot(&backend, TRUNCATION_OVERLAP_SPI).await;
    println!(
        "large state before an overlapping pair: {}",
        describe(&read)
    );
    if !read_is_exactly(
        &read,
        &[
            overlap_unmarked_identity.clone(),
            overlap_marked_identity.clone(),
        ],
    ) {
        failures.push(format!(
            "overlapping pair behind a large state: {}",
            describe(&read)
        ));
    }
    assert_refused_without_changing_fixture_lookup(&backend, &overlap_marked_identity).await;
    assert_eq!(
        snapshot(&backend, TRUNCATION_OVERLAP_SPI).await?.states(),
        &[overlap_unmarked_identity, overlap_marked_identity]
    );
    let _ = remove_unmarked(&backend, TRUNCATION_OVERLAP_SPI).await;
    let _ = remove_marked(&backend, TRUNCATION_OVERLAP_SPI).await;
    remove_unmarked(&backend, LARGE_STATE_SPI_BASE + 1).await?;

    // 3. A state larger than the default 8 KiB batch, but within the 32 KiB
    // cap: the default backend must fail closed, while a backend whose
    // receive buffer requests 32 KiB batches reads the key completely.
    let key_sa = marked(TRUNCATION_KEY_SPI);
    install(&backend, &key_sa).await?;
    let key_identity = lookup(&backend, TRUNCATION_KEY_SPI, key_sa.mark).await?;
    install(
        &backend,
        &large_key_sa(LARGE_STATE_SPI_BASE + 2, BATCH_EXCEEDING_KEY_BYTES),
    )
    .await?;
    let read = snapshot(&backend, TRUNCATION_KEY_SPI).await;
    println!("12.6 KiB state, 8 KiB batches: {}", describe(&read));
    if !read_failed_closed(&read) {
        failures.push(format!(
            "state above the default batch: {}",
            describe(&read)
        ));
    }
    let wide = LinuxXfrmBackend::with_config(LinuxXfrmBackendConfig {
        receive_buffer_len: 32 * 1024,
        ..LinuxXfrmBackendConfig::default()
    })
    .bind_current_network_namespace()?;
    let read = snapshot(&wide, TRUNCATION_KEY_SPI).await;
    println!("12.6 KiB state, 32 KiB batches: {}", describe(&read));
    if !read_is_exactly(&read, std::slice::from_ref(&key_identity)) {
        failures.push(format!("state within 32 KiB batches: {}", describe(&read)));
    }
    remove_unmarked(&backend, LARGE_STATE_SPI_BASE + 2).await?;

    // 4. A state no dump batch can hold: every read fails closed.
    install(
        &backend,
        &large_key_sa(LARGE_STATE_SPI_BASE + 3, UNDUMPABLE_KEY_BYTES),
    )
    .await?;
    for (label, read) in [
        ("8 KiB", snapshot(&backend, TRUNCATION_KEY_SPI).await),
        ("32 KiB", snapshot(&wide, TRUNCATION_KEY_SPI).await),
    ] {
        println!("33 KiB state, {label} batches: {}", describe(&read));
        if !read_failed_closed(&read) {
            failures.push(format!(
                "undumpable state, {label} batches: {}",
                describe(&read)
            ));
        }
    }
    assert_refused_without_changing_fixture_lookup(&backend, &key_identity).await;
    remove_unmarked(&backend, LARGE_STATE_SPI_BASE + 3).await?;
    let _ = remove_marked(&backend, TRUNCATION_KEY_SPI).await;

    for spi in [
        TRUNCATION_TARGET_SPI,
        TRUNCATION_OVERLAP_SPI,
        TRUNCATION_KEY_SPI,
    ] {
        assert!(snapshot(&backend, spi).await?.is_empty());
    }
    assert!(
        failures.is_empty(),
        "oversized states produced a false or missing proof: {failures:#?}"
    );
    println!("SA_KEY_SNAPSHOT_TRUNCATION_PROOF_OK");

    acquire_phase(&backend).await?;
    println!("SA_KEY_SNAPSHOT_ACQUIRE_PROOF_OK");

    println!("SA_KEY_SNAPSHOT_PROOF_OK");
    Ok(())
}

/// Kernel ACQUIRE. A larval state that a dump returns may have been inserted
/// after the read's first SAD count, and so may stand in for a state the dump
/// dropped. Every read whose dump returns one must fail closed.
async fn acquire_phase(backend: &impl XfrmBackend) -> Result<(), Box<dyn Error>> {
    assert_eq!(sad_count()?, 0, "earlier phases left states behind");
    let mut failures = Vec::new();
    let mut lab = AcquireLab::start()?;

    // 1. The review counterexample, one kernel step at a time. The oversized
    // target U is older than the small state E, which has a short hard
    // lifetime. Linux cannot answer a GETSA for U either, so U's identity
    // comes from a small twin with the same identity fields.
    install(backend, &sa(ACQUIRE_OVERSIZED_SPI, None, 4)).await?;
    let oversized = lookup(backend, ACQUIRE_OVERSIZED_SPI, None).await?;
    remove_unmarked(backend, ACQUIRE_OVERSIZED_SPI).await?;
    install(
        backend,
        &large_key_sa(ACQUIRE_OVERSIZED_SPI, UNDUMPABLE_KEY_BYTES),
    )
    .await?;
    let mut expiring = sa(ACQUIRE_EXPIRING_SPI, None, 5);
    expiring.lifetime.hard_add_expires_seconds = EXPIRING_LIFETIME_SECONDS;
    install(backend, &expiring).await?;
    let count_before = sad_count()?;
    // A kernel ACQUIRE inserts the larval state A...
    lab.trigger()?;
    let count_with_acquire = sad_count()?;
    // ...a dump returns A and E and then silently stops at U...
    let dumped = dumped_state_count()?;
    expect_refused(
        backend,
        &oversized,
        "oversized target, larval state, expiring state",
        &mut failures,
    )
    .await;
    // ...and E expires, so the count again equals the dump with U missing.
    wait_until_removed(
        backend,
        ACQUIRE_EXPIRING_SPI,
        Duration::from_secs(EXPIRING_LIFETIME_SECONDS + 8),
    )
    .await?;
    let count_after = sad_count()?;
    println!(
        "kernel steps: SAD count {count_before}, ACQUIRE, SAD count {count_with_acquire}, \
         dump of {dumped} state(s), expiry, SAD count {count_after}"
    );
    assert_eq!(
        (count_before, count_with_acquire, dumped, count_after),
        (2, 3, 2, 2),
        "the kernel did not reproduce the counterexample"
    );
    expect_refused(
        backend,
        &oversized,
        "oversized target and larval state after the expiry",
        &mut failures,
    )
    .await;
    // The unchanged oversized lookup was checked before this fixture teardown.
    remove_unmarked(backend, ACQUIRE_OVERSIZED_SPI).await?;

    // 2. An ordinary target that every dump returns, beside a fresh larval
    // state. The counts agree, yet the read must fail closed: the dump alone
    // cannot show whether the larval state was inserted after the first
    // count.
    let target_sa = marked(ACQUIRE_TARGET_SPI);
    install(backend, &target_sa).await?;
    let target = lookup(backend, ACQUIRE_TARGET_SPI, target_sa.mark).await?;
    lab.trigger()?;
    expect_refused(
        backend,
        &target,
        "ordinary target beside a larval state",
        &mut failures,
    )
    .await;
    let still_installed = lookup(backend, ACQUIRE_TARGET_SPI, target_sa.mark).await;
    if !still_installed
        .as_ref()
        .is_ok_and(|identity| *identity == target)
    {
        failures.push(format!(
            "ordinary target beside a larval state was deleted: {still_installed:?}"
        ));
        install(backend, &target_sa).await?;
    }

    // 3. An unrelated oversized state, newer than the ordinary target, hides
    // it from every dump: never a false absence.
    install(
        backend,
        &large_key_sa(ACQUIRE_BLOCKER_SPI, UNDUMPABLE_KEY_BYTES),
    )
    .await?;
    lab.trigger()?;
    let read = snapshot(backend, ACQUIRE_TARGET_SPI).await;
    println!(
        "ordinary target behind an oversized state: read {}",
        describe(&read)
    );
    if !(read_failed_closed(&read) || read_is_exactly(&read, std::slice::from_ref(&target))) {
        failures.push(format!(
            "ordinary target behind an oversized state: read {}",
            describe(&read)
        ));
    }
    assert_refused_without_changing_fixture_lookup(backend, &target).await;
    remove_unmarked(backend, ACQUIRE_BLOCKER_SPI).await?;

    // 4. With no new ACQUIREs, the read completes once the larval states
    // expire.
    lab.remove_policy()?;
    let deadline = Instant::now() + Duration::from_secs(ACQUIRE_LIFETIME_SECONDS + 8);
    let recovered = loop {
        let read = snapshot(backend, ACQUIRE_TARGET_SPI).await;
        if read_is_exactly(&read, std::slice::from_ref(&target)) {
            break true;
        }
        if !read_failed_closed(&read) {
            failures.push(format!(
                "while larval states expire: read {}",
                describe(&read)
            ));
            break false;
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(250));
    };
    println!("read after the larval states expired: complete {recovered}");
    if !recovered {
        failures.push("the read never completed after the larval states expired".into());
    }

    // 5. An SPI allocation leaves a larval state too, until it is removed.
    let allocation = backend
        .allocate_spi(AllocateSpiRequest {
            destination: ipv4([192, 0, 2, 51]),
            protocol: IPPROTO_ESP,
            min_spi: ALLOCATED_SPI_MIN,
            max_spi: ALLOCATED_SPI_MAX,
        })
        .await?;
    let read = snapshot(backend, ACQUIRE_TARGET_SPI).await;
    println!(
        "ordinary target beside a pending SPI allocation: read {}",
        describe(&read)
    );
    if !read_failed_closed(&read) {
        failures.push(format!(
            "ordinary target beside a pending SPI allocation: read {}",
            describe(&read)
        ));
    }
    remove_unmarked(backend, allocation.spi).await?;
    let read = snapshot(backend, ACQUIRE_TARGET_SPI).await;
    println!("after removing the allocation: read {}", describe(&read));
    if !read_is_exactly(&read, std::slice::from_ref(&target)) {
        failures.push(format!(
            "after removing the allocation: read {}",
            describe(&read)
        ));
    }

    assert_refused_without_changing_fixture_lookup(backend, &target).await;
    assert_eq!(
        snapshot(backend, ACQUIRE_TARGET_SPI).await?.states(),
        std::slice::from_ref(&target)
    );
    // Final isolated fixture teardown, after proving refusal retained it.
    remove_marked(backend, ACQUIRE_TARGET_SPI).await?;
    assert!(snapshot(backend, ACQUIRE_TARGET_SPI).await?.is_empty());
    drop(lab);
    assert!(
        failures.is_empty(),
        "kernel ACQUIRE activity produced a false or missing proof: {failures:#?}"
    );
    Ok(())
}
