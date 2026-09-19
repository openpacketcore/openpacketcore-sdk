//! Real authenticated delivery through explicitly blocked SCTP peer paths.
use super::*;
use opc_sctp::{HeartbeatConfig, RtoConfig, SctpAssociation, SctpAuthenticationConfig};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};

fn require_private_namespace() {
    let current = std::fs::read_link("/proc/self/ns/net").expect("current netns");
    let initial = std::fs::read_link("/proc/1/ns/net").expect("initial netns");
    assert_ne!(
        current, initial,
        "requires an explicitly private network namespace"
    );
}

struct PathBlock {
    destination: &'static str,
}

impl PathBlock {
    fn destination(destination: &'static str) -> Self {
        require_private_namespace();
        let result = Command::new("nft")
            .args(["add", "table", "inet", "opc_n3_dtls_paths"])
            .output()
            .expect("nft table");
        assert!(result.status.success(), "private test table must be new");
        let block = Self { destination };
        block.replace(false);
        block
    }

    fn replace(&self, all: bool) {
        let addresses = if all {
            "127.0.0.1, 127.0.0.2, 127.0.0.3, 127.0.0.4"
        } else {
            self.destination
        };
        let script = format!(
            "flush table inet opc_n3_dtls_paths\n\
             add chain inet opc_n3_dtls_paths output {{ type filter hook output priority 0; policy accept; }}\n\
             add rule inet opc_n3_dtls_paths output meta l4proto sctp ip daddr {{ {addresses} }} counter drop\n"
        );
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("private path blocker");
        child
            .stdin
            .take()
            .expect("nft input")
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().expect("nft completion").success());
    }

    fn dropped(&self) -> u64 {
        let result = Command::new("nft")
            .args(["list", "table", "inet", "opc_n3_dtls_paths"])
            .output()
            .expect("private counter readback");
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).expect("counter text");
        let words: Vec<_> = text.split_whitespace().collect();
        let position = words
            .iter()
            .position(|word| *word == "packets")
            .expect("drop counter");
        words[position + 1].parse().expect("bounded counter")
    }
}

impl Drop for PathBlock {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "opc_n3_dtls_paths"])
            .output();
    }
}

async fn multihomed_pair(material: &TestMaterial, reverse_roles: bool) -> (Connection, Connection) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let auth = SctpAuthenticationConfig::data();
    let rto = RtoConfig {
        initial_ms: Some(200),
        min_ms: Some(100),
        max_ms: Some(400),
    };
    let heartbeat = HeartbeatConfig {
        interval_ms: Some(100),
        path_max_retrans: Some(1),
    };
    let mut server_config =
        opc_sctp::SctpEndpointConfig::one_to_one("127.0.0.3:0".parse().unwrap());
    server_config
        .local_addrs
        .push("127.0.0.4:0".parse().unwrap());
    server_config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    server_config.rto = rto;
    server_config.heartbeat = heartbeat;
    let endpoint = opc_sctp::SctpEndpoint::bind_with_authentication(server_config, auth).unwrap();
    let addresses = endpoint.local_addresses().unwrap();
    let port = addresses[0].port();
    let primary: SocketAddr = ("127.0.0.3".parse::<IpAddr>().unwrap(), port).into();
    let secondary: SocketAddr = ("127.0.0.4".parse::<IpAddr>().unwrap(), port).into();
    assert_eq!(addresses.len(), 2);
    assert!(addresses.contains(&primary) && addresses.contains(&secondary));
    let mut config = opc_sctp::SctpConnectConfig::new(primary);
    config.remote_addrs.push(secondary);
    config.local_addrs = ["127.0.0.1:0", "127.0.0.2:0"]
        .map(|v| v.parse().unwrap())
        .to_vec();
    config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    config.rto = rto;
    config.heartbeat = heartbeat;
    let client = tokio::time::timeout_at(
        deadline,
        SctpAssociation::connect_with_authentication(config, auth),
    )
    .await
    .unwrap()
    .unwrap();
    let server = tokio::time::timeout_at(deadline, endpoint.accept())
        .await
        .unwrap()
        .unwrap();
    for (association, wanted) in [(&client, "127.0.0.3"), (&server, "127.0.0.1")] {
        assert_eq!(association.local_addresses().unwrap().len(), 2);
        assert_eq!(association.peer_addresses().unwrap().len(), 2);
        let wanted = wanted.parse::<IpAddr>().unwrap();
        let peer = association
            .peer_addresses()
            .unwrap()
            .into_iter()
            .find(|v| v.ip() == wanted)
            .unwrap();
        association.set_primary_peer_path(peer).unwrap();
        assert_eq!(
            association
                .peer_path_health()
                .iter()
                .filter(|v| v.primary)
                .map(|v| v.peer_addr)
                .collect::<Vec<_>>(),
            [peer]
        );
        assert!(association.is_pristine_rfc6083_auth_state());
    }
    let policy =
        Policy::ordered_streams(PayloadProtocol::Ngap, MAX_DTLS_SCTP_MESSAGE_BYTES, 16, 64)
            .unwrap();
    let connector =
        Connector::new(material.client_controller.clone(), peer(SERVER_ID), policy).unwrap();
    let acceptor =
        Acceptor::new(material.server_controller.clone(), peer(CLIENT_ID), policy).unwrap();
    // DTLS roles are independent of which SCTP endpoint connected. Exercise
    // each role as the sender whose primary peer destination is blocked.
    let (client, server) = if reverse_roles {
        (server, client)
    } else {
        (client, server)
    };
    let (client, server) = tokio::join!(
        connector.connect(
            Transport::from_sctp(client, PayloadProtocol::Ngap, 64).unwrap(),
            deadline
        ),
        acceptor.accept(
            Transport::from_sctp(server, PayloadProtocol::Ngap, 64).unwrap(),
            deadline
        ),
    );
    (
        client.expect("multihomed protected client"),
        server.expect("multihomed protected server"),
    )
}

#[derive(PartialEq, Eq)]
struct ProtectionSnapshot {
    role: Role,
    protocol: PayloadProtocol,
    version: DtlsSctpVersion,
    cipher: DtlsSctpCipher,
    epoch: opc_tls::TlsMaterialEpoch,
    local_expiry: Timestamp,
    peer_expiry: Timestamp,
    expected_peer: ExpectedPeer,
    stream_count: u16,
    capacity: usize,
}

fn assert_protection(
    connection: &Connection,
    role: Role,
    material: &TestMaterial,
) -> ProtectionSnapshot {
    let evidence = connection.readback().expect("exact retained protection");
    assert_eq!(evidence.payload_protocol(), PayloadProtocol::Ngap);
    assert_eq!(evidence.version(), DtlsSctpVersion::Dtls12);
    assert_eq!(evidence.role(), role);
    assert_eq!(evidence.application_stream_count(), 16);
    let (controller, expected) = if role == Role::Connector {
        (&material.client_controller, SERVER_ID)
    } else {
        (&material.server_controller, CLIENT_ID)
    };
    assert_eq!(evidence.material_epoch(), controller.status().epoch());
    assert_eq!(evidence.expected_peer(), &peer(expected));
    assert_eq!(format!("{evidence:?}"), "Evidence([redacted])");
    assert!(evidence.crls().is_none(), "explicit profile without CRLs");
    ProtectionSnapshot {
        role: evidence.role(),
        protocol: evidence.payload_protocol(),
        version: evidence.version(),
        cipher: evidence.cipher(),
        epoch: evidence.material_epoch(),
        local_expiry: evidence.local_certificate_expires_at(),
        peer_expiry: evidence.peer_certificate_expires_at(),
        expected_peer: evidence.expected_peer().clone(),
        stream_count: evidence.application_stream_count(),
        capacity: evidence.pending_record_capacity(),
    }
}

async fn exchange(client: &mut Connection, server: &mut Connection) {
    for reverse in [false, true] {
        let (sender, receiver) = if reverse {
            (&mut *server, &mut *client)
        } else {
            (&mut *client, &mut *server)
        };
        for stream in [0, 1, 2, 15] {
            let bytes = [stream as u8, u8::from(reverse), 0xa7];
            let deadline = Instant::now() + Duration::from_secs(8);
            let (sent, received) = tokio::join!(
                sender.send_on_stream(stream, &bytes, deadline),
                receiver.receive(deadline)
            );
            sent.expect("protected path send");
            let received = received.expect("protected path delivery");
            assert_eq!(received.stream_id(), stream);
            assert_eq!(received.as_bytes(), bytes);
        }
    }
}

#[tokio::test]
#[ignore = "requires private Linux SCTP-AUTH netns and nftables"]
async fn generic_kernel_multihoming_preserves_protection_and_bounds_total_path_loss() {
    require_private_namespace();
    let material = dtls_material();
    for reverse_roles in [false, true] {
        let (mut client, mut server) = multihomed_pair(&material, reverse_roles).await;
        exchange(&mut client, &mut server).await;
        let client_before = assert_protection(&client, Role::Connector, &material);
        let server_before = assert_protection(&server, Role::Acceptor, &material);
        // SCTP may change its active destination during the handshake. Try
        // each of the two known peer destinations once, requiring actual
        // drops before accepting the path-failure phase. An unused address
        // cannot qualify it merely because application delivery succeeded.
        let mut selected = None;
        for destination in ["127.0.0.3", "127.0.0.4"] {
            let candidate = PathBlock::destination(destination);
            exchange(&mut client, &mut server).await;
            if candidate.dropped() > 0 {
                selected = Some(candidate);
                break;
            }
        }
        let block = selected.expect("must actually block an active peer path");
        assert!(assert_protection(&client, Role::Connector, &material) == client_before);
        assert!(assert_protection(&server, Role::Acceptor, &material) == server_before);
        eprintln!("protected active-path loss completed: reverse_roles={reverse_roles}");
        block.replace(true);
        let deadline = Instant::now() + Duration::from_secs(1);
        let _ = tokio::join!(
            client.send_on_stream(3, b"cannot cross any path", deadline),
            server.send_on_stream(3, b"nor the reverse path", deadline)
        );
        let received = tokio::join!(client.receive(deadline), server.receive(deadline));
        assert!(
            received.0.is_err() && received.1.is_err(),
            "no delivery through blocked paths"
        );
        assert!(
            client.readback().is_err() && server.readback().is_err(),
            "deadline must retire both roles"
        );
        assert!(block.dropped() > 0, "total path loss must reach the kernel");
        drop(block);
        assert!(client.readback().is_err() && server.readback().is_err());
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            client.send(b"cannot revive", deadline).await.err(),
            Some(Error::ConnectionClosed)
        );
        assert_eq!(
            server.receive(deadline).await.err(),
            Some(Error::ConnectionClosed)
        );
        drop(client);
        drop(server);
        let (mut client, mut server) = multihomed_pair(&material, reverse_roles).await;
        exchange(&mut client, &mut server).await;
        assert_protection(&client, Role::Connector, &material);
        assert_protection(&server, Role::Acceptor, &material);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (closed, peer_closed) = tokio::join!(client.close(deadline), server.receive(deadline));
        closed.expect("fresh association reciprocal close");
        assert_eq!(peer_closed.err(), Some(Error::PeerClosed));
    }
    eprintln!("native protected SCTP path assertions completed");
}
