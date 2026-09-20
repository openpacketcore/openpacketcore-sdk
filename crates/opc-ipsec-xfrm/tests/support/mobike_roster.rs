//! Real native/NAT-T whole-roster moves through independently sealed IKE bytes.

use super::*;
use nix::sys::socket::{bind, sendto, MsgFlags, SockaddrIn};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf};

const NEW_LOCAL: [u8; 4] = [192, 0, 2, 11];
const NEW_PEER: [u8; 4] = [192, 0, 2, 12];

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let id = XfrmSaRelocationOperationId::generate().unwrap().to_bytes();
        let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("opc-childsa-mobike-{name}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn captured(fd: &OwnedFd, payload: &[u8], destination: [u8; 4], udp: bool) -> (u32, u32) {
    let mut bytes = [0u8; 65536];
    for _ in 0..128 {
        let (length, _) = recvfrom::<LinkAddr>(fd.as_raw_fd(), &mut bytes).unwrap();
        let f = &bytes[..length];
        if length < 42
            || f[12..14] != [8, 0]
            || f[30..34] != destination
            || f[23] != if udp { 17 } else { 50 }
        {
            continue;
        }
        let transport = 14 + usize::from(f[14] & 15) * 4;
        let esp = transport + if udp { 8 } else { 0 };
        if esp + 8 > length || !f.windows(payload.len()).any(|w| w == payload) {
            continue;
        }
        if udp {
            assert_eq!(&f[transport..transport + 4], &[0x11, 0x94, 0x11, 0x94]);
        }
        return (
            u32::from_be_bytes(f[esp..esp + 4].try_into().unwrap()),
            u32::from_be_bytes(f[esp + 4..esp + 8].try_into().unwrap()),
        );
    }
    panic!("expected independently captured ESP packet absent");
}

struct RawPeer {
    fd: OwnedFd,
    source: [u8; 4],
}

fn raw_peer(network: &Network, source: [u8; 4]) -> RawPeer {
    peer(&network.peer, move || {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::Raw,
        )
        .unwrap();
        bind(
            fd.as_raw_fd(),
            &SockaddrIn::from(std::net::SocketAddrV4::new(Ipv4Addr::from(source), 0)),
        )
        .unwrap();
        RawPeer { fd, source }
    })
}

fn send(packet: &[u8], destination: [u8; 4], udp: &Option<UdpSocket>, raw: &Option<RawPeer>) {
    if let Some(socket) = udp {
        socket
            .send_to(packet, (Ipv4Addr::from(destination), 4500))
            .unwrap();
    } else {
        let raw = raw.as_ref().unwrap();
        // IPPROTO_RAW includes our independent outer IPv4 header. Linux fills
        // its length/checksum; the ESP bytes and HMAC remain entirely unchanged.
        let mut datagram = vec![0u8; 20];
        datagram[0] = 0x45;
        datagram[8] = 64;
        datagram[9] = 50;
        datagram[12..16].copy_from_slice(&raw.source);
        datagram[16..20].copy_from_slice(&destination);
        datagram.extend_from_slice(packet);
        let address = SockaddrIn::from(std::net::SocketAddrV4::new(Ipv4Addr::from(destination), 0));
        assert_eq!(
            sendto(raw.fd.as_raw_fd(), &datagram, &address, MsgFlags::empty()).unwrap(),
            datagram.len()
        );
    }
}

async fn outbound(
    backend: &NamespaceBoundLinuxXfrmBackend,
    roster: &InstalledChildSaRoster,
    capture: &OwnedFd,
    destination: [u8; 4],
    udp: bool,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (flow, id, incarnation) in [
        (10, 1, 1),
        (11, 1, 1),
        (20, 2, 2),
        (21, 2, 2),
        (30, 3, 1),
        (31, 3, 1),
        (0, 3, 1),
    ] {
        let selection = if flow == 0 {
            ChildSaOutboundSelection::Default
        } else {
            ChildSaOutboundSelection::Class(class(flow))
        };
        let selected = backend.select_installed_child_sa(roster, selection).await?;
        assert_eq!(selected.pair().child(), child(id));
        assert_eq!(selected.pair().incarnation().get(), incarnation);
        let socket = UdpSocket::bind((Ipv4Addr::from(INNER_LOCAL), 0))?;
        setsockopt(&socket, sockopt::Mark, &(id as u32))?;
        let payload = format!("mobike-{udp}-{phase}-{flow}");
        socket.send_to(payload.as_bytes(), (Ipv4Addr::from(INNER_PEER), PORT))?;
        let (observed, sequence) = captured(capture, payload.as_bytes(), destination, udp);
        assert_eq!(observed, spi(id, incarnation, false));
        assert!(sequence > if phase == "after" { 2 } else { 0 });
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires CAP_NET_ADMIN, XFRM, and a fresh network namespace"]
async fn authenticated_complete_roster_moves_preserve_replay_and_flow_selection(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 in a fresh netns");
        return Ok(());
    }
    let mut supported = 0;
    for udp in [false, true] {
        let network = Network::new();
        command(&["addr", "add", "192.0.2.11/24", "dev", "n3c0"]);
        command(&[
            "-n",
            &network.peer,
            "addr",
            "add",
            "192.0.2.12/24",
            "dev",
            "n3cp",
        ]);
        let _local_old = udp.then(|| encapsulation(OUTER_LOCAL));
        let _local_new = udp.then(|| encapsulation(NEW_LOCAL));
        let peer_old = udp.then(|| peer(&network.peer, || encapsulation(OUTER_PEER)));
        let peer_new = udp.then(|| peer(&network.peer, || encapsulation(NEW_PEER)));
        let raw_old = (!udp).then(|| raw_peer(&network, OUTER_PEER));
        let raw_new = (!udp).then(|| raw_peer(&network, NEW_PEER));
        let receiver = receiver(INNER_LOCAL);
        let capture = capture();
        let directory = Directory::new();
        let (backend, store) = LinuxXfrmBackend::new()
            .bind_current_network_namespace_with_sa_relocation_recovery(
                directory.0.join("store"),
                XfrmSaRelocationRecoveryProofKey::new([0x97; 32])?,
            )?;
        let mut current = request(true);
        if !udp {
            for pair in &mut current.pairs {
                pair.inbound_sa.encap = None;
                pair.outbound_sa.encap = None;
            }
        }
        for (index, pair) in current.pairs.iter().enumerate() {
            for parameters in [&pair.inbound_sa, &pair.outbound_sa] {
                backend
                    .install_sa(InstallSaRequest {
                        parameters: parameters.clone(),
                    })
                    .await?;
            }
            if index == 0 {
                backend
                    .install_policy(InstallPolicyRequest {
                        parameters: pair.inbound_policy.clone(),
                    })
                    .await?;
            }
            if let Some(parameters) = &pair.outbound_policy {
                backend
                    .install_policy(InstallPolicyRequest {
                        parameters: parameters.clone(),
                    })
                    .await?;
            }
        }
        let roster = backend
            .publish_child_sa_roster(
                backend.begin_child_sa_roster_update().await?,
                current.clone(),
            )
            .await?;
        outbound(&backend, &roster, &capture, OUTER_PEER, udp, "before").await?;
        for (id, incarnation) in [(1, 1), (2, 1), (3, 1), (2, 2)] {
            let payload = format!("mobike-in-before-{id}-{incarnation}");
            send(
                &authenticated_packet(id, incarnation, 1, payload.as_bytes()),
                OUTER_LOCAL,
                &peer_old,
                &raw_old,
            );
            received(&receiver, payload.as_bytes(), INNER_PEER);
        }
        let mut before = Vec::new();
        for pair in &current.pairs {
            for identity in [pair.pair.inbound(), pair.pair.outbound()] {
                before.push(backend.query_sa(identity.query()).await?);
            }
        }
        let keys = mobike::keys();
        let mut responder = mobike::responder(&keys, udp);
        let association = backend
            .bind_child_sa_mobike(&roster, responder.migration_association())
            .await?;
        let path = opc_proto_ikev2::nwu::mobike::Path::new(
            (Ipv4Addr::from(NEW_PEER), 4500).into(),
            (Ipv4Addr::from(NEW_LOCAL), 4500).into(),
        )?;
        let permit = mobike::migration(&keys, &mut responder, path)
            .authorize(&responder.migration_association())?;
        let intent = ChildSaRelocationIntent {
            current: current.clone(),
            path,
            esp_udp: udp,
        };
        let operation = XfrmSaRelocationOperationId::generate()?;
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let prepared = backend
            .prepare_child_sa_relocation(
                &store,
                operation,
                generation,
                association,
                intent.clone(),
                permit,
            )
            .await;
        if backend.child_sa_relocation_capability().await? == XfrmCapability::Missing {
            assert!(
                matches!(
                    prepared,
                    Err(ChildSaRelocationError::Backend(
                        XfrmError::UnsupportedFeature { .. }
                    ))
                ),
                "unexpected prepare result: {prepared:?}"
            );
            backend
                .select_installed_child_sa(&roster, ChildSaOutboundSelection::Default)
                .await?;
            eprintln!("N3_CHILD_SA_MOBIKE_UNSUPPORTED udp={udp}");
            continue;
        }
        let receipt = backend.run_child_sa_relocation(prepared?).await?;
        assert!(backend
            .select_installed_child_sa(&roster, ChildSaOutboundSelection::Default)
            .await
            .is_err());
        for (index, original) in before.iter().enumerate() {
            let pair = &current.pairs[index / 2];
            let inbound = index % 2 == 0;
            let old = if inbound {
                pair.pair.inbound()
            } else {
                pair.pair.outbound()
            }
            .query();
            let query = QuerySaRequest {
                destination: ip(if inbound { NEW_LOCAL } else { NEW_PEER }),
                ..old
            };
            assert!(matches!(
                backend.query_sa(old).await,
                Err(XfrmError::NotFound)
            ));
            let state = backend.query_sa(query).await?;
            assert_eq!(state.selector, original.selector);
            assert!(state.replay_state == original.replay_state);
            assert_eq!(state.lifetime_current, original.lifetime_current);
            let identity = backend.query_sa_relocation_identity(query).await?;
            assert_eq!(
                identity.encap,
                udp.then(|| UdpEncap::esp_in_udp(4500, 4500))
            );
        }
        outbound(&backend, receipt.roster(), &capture, NEW_PEER, udp, "after").await?;
        for (id, incarnation) in [(1, 1), (2, 1), (3, 1), (2, 2)] {
            let payload = format!("mobike-in-after-{id}-{incarnation}");
            receiver.set_read_timeout(Some(Duration::from_millis(120)))?;
            send(
                &authenticated_packet(id, incarnation, 1, payload.as_bytes()),
                NEW_LOCAL,
                &peer_new,
                &raw_new,
            );
            assert!(
                receiver.recv(&mut [0u8; 256]).is_err(),
                "old replay bitmap was lost"
            );
            let mut bad = authenticated_packet(id, incarnation, 2, payload.as_bytes());
            *bad.last_mut().unwrap() ^= 1;
            send(&bad, NEW_LOCAL, &peer_new, &raw_new);
            assert!(
                receiver.recv(&mut [0u8; 256]).is_err(),
                "ICV verification was lost"
            );
            receiver.set_read_timeout(Some(Duration::from_secs(3)))?;
            send(
                &authenticated_packet(id, incarnation, 2, payload.as_bytes()),
                NEW_LOCAL,
                &peer_new,
                &raw_new,
            );
            received(&receiver, payload.as_bytes(), INNER_PEER);
        }
        assert_eq!(
            backend
                .recover_child_sa_relocation(&store, operation, generation, intent)
                .await?,
            ChildSaRelocationRecovery::Completed
        );
        supported += 1;
    }
    if supported == 2 {
        eprintln!("N3_CHILD_SA_MOBIKE_PROOF_OK profiles=2 pairs=4 flows=7");
    } else {
        assert_eq!(supported, 0, "kernel support must agree across profiles");
    }
    Ok(())
}

fn original(udp: bool) -> ChildSaInstalledRosterRequest {
    let mut current = request(true);
    if !udp {
        for pair in &mut current.pairs {
            pair.inbound_sa.encap = None;
            pair.outbound_sa.encap = None;
        }
    }
    current
}

fn target(udp: bool) -> ChildSaInstalledRosterRequest {
    let mut moved = original(udp);
    for pair in &mut moved.pairs {
        pair.inbound_sa.source_address = ip(NEW_PEER);
        pair.inbound_sa.id.destination = ip(NEW_LOCAL);
        pair.outbound_sa.source_address = ip(NEW_LOCAL);
        pair.outbound_sa.id.destination = ip(NEW_PEER);
        pair.inbound_policy.templates[0].source_address = ip(NEW_PEER);
        pair.inbound_policy.templates[0].id.destination = ip(NEW_LOCAL);
        if let Some(policy) = &mut pair.outbound_policy {
            policy.templates[0].source_address = ip(NEW_LOCAL);
            policy.templates[0].id.destination = ip(NEW_PEER);
        }
        pair.pair = ChildSaPair::new(
            pair.pair.child(),
            pair.pair.incarnation(),
            ChildSaTrafficIdentity::new(pair.inbound_sa.id, pair.inbound_sa.mark, None).unwrap(),
            ChildSaTrafficIdentity::new(pair.outbound_sa.id, pair.outbound_sa.mark, None).unwrap(),
            pair.pair.outbound_use(),
        );
    }
    moved.plan = ChildSaSelectionPlan::new(
        moved.pairs.iter().map(|p| p.pair.clone()).collect(),
        moved.plan.classes().to_vec(),
        moved.plan.default_child(),
        ChildSaSelectionLimits {
            max_pairs: 4,
            max_classes: 6,
        },
    )
    .unwrap();
    moved
}

fn relocation_intent(udp: bool) -> ChildSaRelocationIntent {
    ChildSaRelocationIntent {
        current: original(udp),
        path: opc_proto_ikev2::nwu::mobike::Path::new(
            (Ipv4Addr::from(NEW_PEER), 4500).into(),
            (Ipv4Addr::from(NEW_LOCAL), 4500).into(),
        )
        .unwrap(),
        esp_udp: udp,
    }
}

async fn install(
    backend: &NamespaceBoundLinuxXfrmBackend,
    request: &ChildSaInstalledRosterRequest,
) -> Result<(), XfrmError> {
    for (index, pair) in request.pairs.iter().enumerate() {
        for parameters in [&pair.inbound_sa, &pair.outbound_sa] {
            backend
                .install_sa(InstallSaRequest {
                    parameters: parameters.clone(),
                })
                .await?;
        }
        if index == 0 {
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: pair.inbound_policy.clone(),
                })
                .await?;
        }
        if let Some(parameters) = &pair.outbound_policy {
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: parameters.clone(),
                })
                .await?;
        }
    }
    Ok(())
}

const PROCESS_TEST: &str =
    "mobike_roster::whole_roster_process_loss_at_every_kernel_prefix_recovers_without_publication";
const CHILD_ROLE: &str = "OPC_XFRM_MOBIKE_DETECTOR_ROLE";

async fn process_stage(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    assert_ne!(
        fs::read_link("/proc/self/ns/net")?,
        fs::read_link("/proc/1/ns/net")?
    );
    let root = PathBuf::from(std::env::var("OPC_XFRM_MOBIKE_DETECTOR_ROOT")?);
    let udp = std::env::var("OPC_XFRM_MOBIKE_DETECTOR_UDP")? == "1";
    let cut: usize = std::env::var("OPC_XFRM_MOBIKE_DETECTOR_CUT")?.parse()?;
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_sa_relocation_recovery(
            root.join("store"),
            XfrmSaRelocationRecoveryProofKey::new([0x97; 32])?,
        )?;
    let intent = relocation_intent(udp);
    let operation = XfrmSaRelocationOperationId::from_bytes([0x79; 16])?;
    let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
    if role == "cut" {
        install(&backend, &intent.current).await?;
        let roster = backend
            .publish_child_sa_roster(
                backend.begin_child_sa_roster_update().await?,
                intent.current.clone(),
            )
            .await?;
        let keys = mobike::keys();
        let mut responder = mobike::responder(&keys, udp);
        let association = backend
            .bind_child_sa_mobike(&roster, responder.migration_association())
            .await?;
        let permit = mobike::migration(&keys, &mut responder, intent.path)
            .authorize(&responder.migration_association())?;
        let authority = backend
            .prepare_child_sa_relocation(&store, operation, generation, association, intent, permit)
            .await?;
        assert!(matches!(
            backend
                .detector_cut_child_sa_relocation(authority, cut)
                .await,
            Err(ChildSaRelocationError::Backend(
                XfrmError::StateIndeterminate {
                    operation: "child_sa_roster_detector_cut"
                }
            ))
        ));
        assert!(backend.begin_child_sa_roster_update().await.is_err());
        // Abrupt process loss drops no actor, store, receipt, or secret values.
        // The parent retains the namespace and verifies the next process's repair.
        eprintln!("N3_CHILD_SA_PROCESS_CUT udp={udp} cut={cut}");
        std::process::exit(86);
    }
    assert_eq!(role, "recover");
    assert!(backend.begin_child_sa_roster_update().await.is_err());
    assert!(backend
        .rekey_policy(RekeyPolicyRequest {
            parameters: intent.current.pairs[0].outbound_policy.clone().unwrap()
        })
        .await
        .is_err());
    // A wrong cold-member key must not authorize even the first repair effect.
    let mut foreign = intent.clone();
    foreign.current.pairs[1].inbound_sa.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x13; 32]);
    assert!(backend
        .recover_child_sa_relocation(&store, operation, generation, foreign)
        .await
        .is_err());
    assert!(backend.begin_child_sa_roster_update().await.is_err());
    assert_eq!(
        backend
            .recover_child_sa_relocation(&store, operation, generation, intent.clone())
            .await?,
        ChildSaRelocationRecovery::Completed
    );
    assert_eq!(
        backend
            .recover_child_sa_relocation(&store, operation, generation, intent)
            .await?,
        ChildSaRelocationRecovery::Completed
    );
    // Recovery itself returns no publication. Re-establishing ownership requires
    // the ordinary whole-roster key/policy readback and a new actor-issued ticket.
    let moved = target(udp);
    let publication = backend
        .publish_child_sa_roster(backend.begin_child_sa_roster_update().await?, moved.clone())
        .await?;
    for flow in [10, 11, 20, 21, 30, 31] {
        backend
            .select_installed_child_sa(&publication, ChildSaOutboundSelection::Class(class(flow)))
            .await?;
    }
    backend
        .select_installed_child_sa(&publication, ChildSaOutboundSelection::Default)
        .await?;
    for pair in original(udp).pairs {
        for identity in [pair.pair.inbound(), pair.pair.outbound()] {
            assert!(matches!(
                backend.query_sa(identity.query()).await,
                Err(XfrmError::NotFound)
            ));
        }
    }
    eprintln!("N3_CHILD_SA_PROCESS_RECOVERED udp={udp} cut={cut}");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires CAP_NET_ADMIN, XFRM, and a fresh network namespace"]
async fn whole_roster_process_loss_at_every_kernel_prefix_recovers_without_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 in a fresh netns");
        return Ok(());
    }
    if let Ok(role) = std::env::var(CHILD_ROLE) {
        return process_stage(&role).await;
    }
    assert_ne!(
        fs::read_link("/proc/self/ns/net")?,
        fs::read_link("/proc/1/ns/net")?
    );
    if LinuxXfrmBackend::new().sa_relocation_capability().await? == XfrmCapability::Missing {
        eprintln!("N3_CHILD_SA_MOBIKE_PROCESS_UNSUPPORTED");
        return Ok(());
    }
    for udp in [false, true] {
        // Three outgoing blocks, eight directional SAs, one shared inbound
        // policy, three outgoing allows: sixteen distinct cuts, including zero.
        for cut in 0..=15 {
            let _network = Network::new();
            let directory = Directory::new();
            for (role, expected) in [("cut", 86), ("recover", 0)] {
                let output = Command::new(std::env::current_exe()?)
                    .args([
                        "--ignored",
                        "--exact",
                        PROCESS_TEST,
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD_ROLE, role)
                    .env("OPC_XFRM_MOBIKE_DETECTOR_ROOT", &directory.0)
                    .env("OPC_XFRM_MOBIKE_DETECTOR_UDP", if udp { "1" } else { "0" })
                    .env("OPC_XFRM_MOBIKE_DETECTOR_CUT", cut.to_string())
                    .output()?;
                assert_eq!(
                    output.status.code(),
                    Some(expected),
                    "role={role} udp={udp} cut={cut}: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let marker = if role == "cut" {
                    "N3_CHILD_SA_PROCESS_CUT"
                } else {
                    "N3_CHILD_SA_PROCESS_RECOVERED"
                };
                assert!(String::from_utf8_lossy(&output.stderr).contains(marker));
            }
        }
    }
    eprintln!("N3_CHILD_SA_MOBIKE_PROCESS_PROOF_OK profiles=2 cuts=32 processes=64");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires CAP_NET_ADMIN, XFRM, and a fresh network namespace"]
async fn live_authority_mismatch_revocation_and_caller_cancellation_never_publish(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::future::Future;
    if std::env::var("OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_XFRM_RUN_CHILD_SA_ROSTER_PRIVILEGED=1 in a fresh netns");
        return Ok(());
    }
    let _network = Network::new();
    let directory = Directory::new();
    let (backend, store) = LinuxXfrmBackend::new()
        .bind_current_network_namespace_with_sa_relocation_recovery(
            directory.0.join("store"),
            XfrmSaRelocationRecoveryProofKey::new([0x97; 32])?,
        )?;
    let intent = relocation_intent(true);
    install(&backend, &intent.current).await?;
    let mut roster = backend
        .publish_child_sa_roster(
            backend.begin_child_sa_roster_update().await?,
            intent.current.clone(),
        )
        .await?;
    let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
    let keys = mobike::keys();
    for failure in ["scope", "stale", "path", "mode"] {
        let mut responder = mobike::responder(&keys, true);
        let association = backend
            .bind_child_sa_mobike(&roster, responder.migration_association())
            .await?;
        let mut foreign = mobike::responder(&keys, true);
        let provider = if failure == "scope" {
            &mut foreign
        } else {
            &mut responder
        };
        let permit = mobike::migration(&keys, provider, intent.path)
            .authorize(&provider.migration_association())?;
        if failure == "stale" {
            responder.invalidate_migration_authority()?;
        }
        let mut proposed = intent.clone();
        if failure == "mode" {
            proposed.esp_udp = false;
        }
        if failure == "path" {
            proposed.path = opc_proto_ikev2::nwu::mobike::Path::new(
                "192.0.2.13:4500".parse()?,
                intent.path.destination(),
            )?;
        }
        assert!(
            matches!(
                backend
                    .prepare_child_sa_relocation(
                        &store,
                        XfrmSaRelocationOperationId::generate()?,
                        generation,
                        association,
                        proposed,
                        permit
                    )
                    .await,
                Err(ChildSaRelocationError::Authentication)
            ),
            "{failure}"
        );
        backend
            .select_installed_child_sa(&roster, ChildSaOutboundSelection::Default)
            .await?;
    }
    if backend.child_sa_relocation_capability().await? == XfrmCapability::Missing {
        eprintln!("N3_CHILD_SA_MOBIKE_AUTH_PROOF_OK; N3_CHILD_SA_MOBIKE_CANCEL_UNSUPPORTED");
        return Ok(());
    }
    for failure in [
        "revoked-prepared",
        "wrong-actor",
        "dropped-prepared",
        "cancelled-run",
    ] {
        let mut responder = mobike::responder(&keys, true);
        let association = backend
            .bind_child_sa_mobike(&roster, responder.migration_association())
            .await?;
        let permit = mobike::migration(&keys, &mut responder, intent.path)
            .authorize(&responder.migration_association())?;
        let operation = XfrmSaRelocationOperationId::generate()?;
        let authority = backend
            .prepare_child_sa_relocation(
                &store,
                operation,
                generation,
                association,
                intent.clone(),
                permit,
            )
            .await?;
        match failure {
            "revoked-prepared" => {
                responder.invalidate_migration_authority()?;
                assert!(matches!(
                    backend.run_child_sa_relocation(authority).await,
                    Err(ChildSaRelocationError::Authentication)
                ));
            }
            "wrong-actor" => {
                let other = LinuxXfrmBackend::new().bind_current_network_namespace()?;
                assert!(matches!(
                    other.run_child_sa_relocation(authority).await,
                    Err(ChildSaRelocationError::Durable(
                        XfrmSaRelocationDurableError::WrongBinding
                    ))
                ));
            }
            "dropped-prepared" => drop(authority),
            "cancelled-run" => {
                let mut running = Box::pin(backend.run_child_sa_relocation(authority));
                std::future::poll_fn(|cx| {
                    assert!(
                        running.as_mut().poll(cx).is_pending(),
                        "detector must drop an admitted pending caller"
                    );
                    std::task::Poll::Ready(())
                })
                .await;
                drop(running);
            }
            _ => unreachable!(),
        }
        assert!(backend
            .select_installed_child_sa(&roster, ChildSaOutboundSelection::Default)
            .await
            .is_err());
        let expected = if failure == "cancelled-run" {
            ChildSaRelocationRecovery::Completed
        } else {
            ChildSaRelocationRecovery::NoMutation
        };
        assert_eq!(
            backend
                .recover_child_sa_relocation(&store, operation, generation, intent.clone())
                .await?,
            expected,
            "{failure}"
        );
        let requested = if failure == "cancelled-run" {
            target(true)
        } else {
            intent.current.clone()
        };
        roster = backend
            .publish_child_sa_roster(backend.begin_child_sa_roster_update().await?, requested)
            .await?;
        backend
            .select_installed_child_sa(&roster, ChildSaOutboundSelection::Default)
            .await?;
    }
    eprintln!("N3_CHILD_SA_MOBIKE_AUTH_PROOF_OK; N3_CHILD_SA_MOBIKE_CANCEL_PROOF_OK");
    Ok(())
}
