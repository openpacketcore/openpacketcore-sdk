//! Privileged Linux-kernel evidence for key-scoped SA snapshots and exact SA
//! removal.
//!
//! Run this ignored test inside a fresh network namespace. It installs a
//! marked SA and then an unmarked SA at one destination/protocol/SPI key,
//! which Linux admits, and proves on the kernel that:
//!
//! - an `XFRM_MSG_GETSA` carrying the marked SA's own mark is answered by the
//!   unmarked SA, so a point query cannot identify the marked SA;
//! - the `NLM_F_DUMP` key snapshot reports both states;
//! - `remove_sa_exact` refuses the marked SA while the unmarked one is a
//!   lookup candidate and deletes neither, then removes each state once it is
//!   the only candidate for its own lookup mark;
//! - an unmarked SA refuses a later marked install at its key;
//! - the key read stays exact when several hundred other states at the same
//!   destination make the kernel split the dump into many multipart batches;
//! - a state whose dump message does not fit an empty dump batch never makes
//!   the read a false complete. Linux ends such a dump with a successful
//!   `NLMSG_DONE`, silently dropping that state and every older one, so the
//!   read must either still be complete or fail with `StateIndeterminate`.
//!
//! The test prints `SA_KEY_SNAPSHOT_TRUNCATION_PROOF_OK` and
//! `SA_KEY_SNAPSHOT_PROOF_OK` only after every assertion.

#![cfg(target_os = "linux")]

use std::env;

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, ExactRemoveSaRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, LinuxXfrmBackend, LinuxXfrmBackendConfig, QuerySaRequest, RemoveSaRequest,
    SaKeySnapshot, SaLookupKey, SaParameters, SaRelocationIdentity, XfrmBackend, XfrmError, XfrmId,
    XfrmLookupMark, XfrmMode, XfrmRequestId, XfrmSelector,
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

fn refused_as_ambiguous(result: Result<(), XfrmError>) -> bool {
    matches!(
        result,
        Err(XfrmError::StateIndeterminate {
            operation: "remove_sa_exact_preflight"
        })
    )
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

    // The marked SA is not the only candidate for its own lookup: refused,
    // and neither state is deleted.
    assert!(refused_as_ambiguous(
        backend
            .remove_sa_exact(ExactRemoveSaRequest::new(marked_identity.clone()))
            .await
    ));
    assert_eq!(snapshot(&backend, KEY_SPI).await?.len(), 2);

    // The unmarked lookup selects only the unmarked state, so it is removed;
    // the marked state is then the sole candidate for its own mark.
    backend
        .remove_sa_exact(ExactRemoveSaRequest::new(unmarked_identity.clone()))
        .await?;
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
    backend
        .remove_sa_exact(ExactRemoveSaRequest::new(marked_identity.clone()))
        .await?;
    assert_eq!(
        snapshot(&backend, KEY_SPI).await?.states(),
        std::slice::from_ref(&disjoint_identity)
    );
    // The removed state is absent, and a changed identity is refused.
    assert!(matches!(
        backend
            .remove_sa_exact(ExactRemoveSaRequest::new(marked_identity.clone()))
            .await,
        Err(XfrmError::NotFound)
    ));
    let mut changed = disjoint_identity.clone();
    changed.request_id = XfrmRequestId::new(99);
    assert!(matches!(
        backend
            .remove_sa_exact(ExactRemoveSaRequest::new(changed))
            .await,
        Err(XfrmError::StateMismatch {
            operation: "remove_sa_exact_preflight"
        })
    ));
    backend
        .remove_sa_exact(ExactRemoveSaRequest::new(disjoint_identity))
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
    assert!(refused_as_ambiguous(
        backend
            .remove_sa_exact(ExactRemoveSaRequest::new(multipart_marked.clone()))
            .await
    ));
    assert_eq!(snapshot(&backend, MULTIPART_KEY_SPI).await?.len(), 2);
    backend
        .remove_sa_exact(ExactRemoveSaRequest::new(multipart_unmarked))
        .await?;
    backend
        .remove_sa_exact(ExactRemoveSaRequest::new(multipart_marked))
        .await?;
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
    let removal = backend
        .remove_sa_exact(ExactRemoveSaRequest::new(target.clone()))
        .await;
    println!("exact removal of that target: {removal:?}");
    if removal.is_err() {
        failures.push(format!("exact removal behind a large state: {removal:?}"));
        let _ = remove_marked(&backend, TRUNCATION_TARGET_SPI).await;
    }
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
    let removal = backend
        .remove_sa_exact(ExactRemoveSaRequest::new(overlap_marked_identity))
        .await;
    println!("exact removal of the marked state of that pair: {removal:?}");
    if !refused_as_ambiguous(removal.clone()) {
        failures.push(format!(
            "exact removal of an ambiguous candidate behind a large state: {removal:?}"
        ));
    }
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
    let removal = backend
        .remove_sa_exact(ExactRemoveSaRequest::new(key_identity))
        .await;
    println!("exact removal behind an undumpable state: {removal:?}");
    if !matches!(
        removal,
        Err(XfrmError::StateIndeterminate {
            operation: "remove_sa_exact_preflight"
        })
    ) {
        failures.push(format!(
            "exact removal behind an undumpable state: {removal:?}"
        ));
    }
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

    println!("SA_KEY_SNAPSHOT_PROOF_OK");
    Ok(())
}
