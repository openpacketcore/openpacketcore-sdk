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
//!   destination make the kernel split the dump into many multipart batches.
//!
//! The test prints `SA_KEY_SNAPSHOT_PROOF_OK` only after every assertion.

#![cfg(target_os = "linux")]

use std::env;

use opc_ipsec_xfrm::{
    Algorithm, AuthAlgorithm, ExactRemoveSaRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, LinuxXfrmBackend, QuerySaRequest, RemoveSaRequest, SaKeySnapshot, SaLookupKey,
    SaParameters, SaRelocationIdentity, XfrmBackend, XfrmError, XfrmId, XfrmLookupMark, XfrmMode,
    XfrmRequestId, XfrmSelector,
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

    println!("SA_KEY_SNAPSHOT_PROOF_OK");
    Ok(())
}
