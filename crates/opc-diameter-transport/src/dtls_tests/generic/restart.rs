//! Actual peer process death and fresh, mutually authenticated replacement.
use super::*;
use opc_sctp::{SctpAssociation, SctpAuthenticationConfig};
use std::io::{BufRead, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};

const TEST: &str = "dtls_tests::generic::restart::generic_kernel_process_restart_requires_fresh_mutual_authentication";
const CHILD_ROLE: &str = "OPC_RFC6083_TEST_CHILD_ROLE";
const CHILD_PHASE: &str = "OPC_RFC6083_TEST_CHILD_PHASE";
const MARKER: &str = "rfc6083-child:";

fn listener_address(child_role: Role) -> std::net::SocketAddr {
    // Independent role scenarios use distinct listeners so the first one's
    // graceful-close kernel state cannot affect the next scenario. All three
    // processes within one restart scenario rebind the exact same endpoint.
    match child_role {
        Role::Connector => "127.0.0.1:38770",
        Role::Acceptor => "127.0.0.1:38769",
    }
    .parse()
    .unwrap()
}

fn require_private_namespace() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").expect("current netns"),
        std::fs::read_link("/proc/1/ns/net").expect("initial netns"),
        "requires an explicitly private network namespace"
    );
}

fn policy() -> Policy {
    Policy::ordered_streams(PayloadProtocol::Ngap, MAX_DTLS_SCTP_MESSAGE_BYTES, 16, 64)
        .unwrap()
        .with_allowed_ciphers(&[DtlsSctpCipher::Aes128GcmSha256])
        .unwrap()
}

fn marker(value: &str) {
    println!("{MARKER}{value}");
    std::io::stdout().flush().expect("control marker flush");
}

struct ChildPeer {
    child: Child,
    markers: tokio::sync::mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl ChildPeer {
    fn start(role: Role, phase: &str, state: &IdentityState) -> Self {
        eprintln!("native process stage: {role:?} {phase}");
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--ignored",
                "--exact",
                TEST,
                "--test-threads=1",
                "--nocapture",
            ])
            .env(
                CHILD_ROLE,
                if role == Role::Connector {
                    "client"
                } else {
                    "server"
                },
            )
            .env(CHILD_PHASE, phase)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("fresh peer process");
        let (sender, markers) = tokio::sync::mpsc::channel(8);
        let mut peer = Self {
            child,
            markers,
            reader: None,
        };
        let stdout = peer.child.stdout.take().expect("private control pipe");
        peer.reader = Some(std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.expect("child control line");
                if let Some((_, value)) = line.split_once(MARKER) {
                    assert!(matches!(
                        value,
                        "ready" | "authenticated" | "queued" | "rejected" | "done"
                    ));
                    if sender.blocking_send(value.to_owned()).is_err() {
                        break;
                    }
                }
            }
        }));
        // Freshly generated synthetic test credentials cross only this private
        // pipe. No key files, environment values or diagnostic key bytes exist.
        let mut input = peer.child.stdin.take().expect("private credential pipe");
        assert_eq!(state.svid.cert_chain.len(), 2);
        for bytes in [
            state.svid.cert_chain[0].as_ref(),
            state.svid.cert_chain[1].as_ref(),
            state.svid.private_key.secret_der(),
        ] {
            assert!(bytes.len() <= 65_536);
            input
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            input.write_all(bytes).unwrap();
        }
        input.flush().unwrap();
        peer
    }

    async fn expect(&mut self, expected: &str) {
        let value = tokio::time::timeout(Duration::from_secs(10), self.markers.recv())
            .await
            .expect("bounded peer stage")
            .expect("peer stage exists");
        assert_eq!(value, expected, "exact peer control stage");
    }

    fn kill(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "peer alive at crash cut"
        );
        self.child.kill().expect("real peer SIGKILL");
        assert_eq!(
            self.child.wait().unwrap().signal(),
            Some(9),
            "actual process death"
        );
    }

    async fn finish(&mut self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = self.child.try_wait().expect("peer exit observation") {
                    assert!(
                        status.success(),
                        "replacement peer completes its assertions"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("bounded peer exit");
    }
}

impl Drop for ChildPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn child_material(local_id: &str) -> IdentityState {
    fn blob(input: &mut impl Read) -> Vec<u8> {
        let mut length = [0; 4];
        input
            .read_exact(&mut length)
            .expect("synthetic blob length");
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=65_536).contains(&length), "bounded synthetic blob");
        let mut value = vec![0; length];
        input
            .read_exact(&mut value)
            .expect("complete synthetic blob");
        value
    }
    let mut input = std::io::stdin().lock();
    let leaf = CertificateDer::from(blob(&mut input));
    let ca = CertificateDer::from(blob(&mut input));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(blob(&mut input)));
    let mut trust = TrustBundleSet::new();
    trust.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: vec![ca.clone()],
    });
    let state = build_identity_state(vec![leaf, ca], key, trust).expect("reloaded identity");
    assert!(
        state.identity.spiffe_id.as_str() == local_id,
        "exact reloaded identity"
    );
    state
}

async fn protect(
    association: SctpAssociation,
    controller: TlsMaterialController,
    role: Role,
) -> Result<Connection, Error> {
    assert!(
        association.is_pristine_rfc6083_auth_state(),
        "new AUTH key lifecycle"
    );
    let transport = Transport::from_sctp(association, PayloadProtocol::Ngap, 64).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    if role == Role::Connector {
        Connector::new(controller, peer(SERVER_ID), policy())
            .unwrap()
            .connect(transport, deadline)
            .await
    } else {
        Acceptor::new(controller, peer(CLIENT_ID), policy())
            .unwrap()
            .accept(transport, deadline)
            .await
    }
}

fn assert_readback(connection: &Connection, controller: &TlsMaterialController, role: Role) {
    let evidence = connection.readback().expect("fresh protection evidence");
    assert_eq!(evidence.role(), role);
    assert_eq!(evidence.payload_protocol(), PayloadProtocol::Ngap);
    assert_eq!(evidence.version(), DtlsSctpVersion::Dtls12);
    assert_eq!(evidence.cipher(), DtlsSctpCipher::Aes128GcmSha256);
    assert_eq!(evidence.material_epoch(), controller.status().epoch());
    assert_eq!(evidence.application_stream_count(), 16);
    assert_eq!(evidence.pending_record_capacity(), 64);
    assert_eq!(
        evidence.expected_peer(),
        &peer(if role == Role::Connector {
            SERVER_ID
        } else {
            CLIENT_ID
        })
    );
    assert!(evidence.local_certificate_expires_at() > Timestamp::now_utc());
    assert!(evidence.peer_certificate_expires_at() > Timestamp::now_utc());
    assert!(
        evidence.crls().is_none(),
        "explicit profile without required CRLs"
    );
    assert_eq!(format!("{evidence:?}"), "Evidence([redacted])");
}

async fn exchange(connection: &mut Connection, generation: u8, child: bool) {
    for stream in [0, 1, 2, 15] {
        let outbound = [generation, stream as u8, if child { 0xbb } else { 0xaa }];
        let expected = [generation, stream as u8, if child { 0xaa } else { 0xbb }];
        let deadline = Instant::now() + Duration::from_secs(5);
        if !child {
            connection
                .send_on_stream(stream, &outbound, deadline)
                .await
                .unwrap();
        }
        let message = connection
            .receive(deadline)
            .await
            .expect("protected process delivery");
        assert_eq!(message.stream_id(), stream);
        assert!(
            message.as_bytes() == expected,
            "exact fresh-generation payload"
        );
        assert_eq!(format!("{message:?}"), "ApplicationMessage([redacted])");
        if child {
            connection
                .send_on_stream(stream, &outbound, deadline)
                .await
                .unwrap();
        }
    }
}

async fn child(role: Role, phase: &str) {
    assert!(matches!(phase, "crash" | "identity-refusal" | "recovered"));
    let local_id = match (role, phase == "identity-refusal") {
        (Role::Connector, false) => CLIENT_ID,
        (Role::Connector, true) => OTHER_CLIENT_ID,
        (Role::Acceptor, false) => SERVER_ID,
        (Role::Acceptor, true) => OTHER_SERVER_ID,
    };
    let state = child_material(local_id);
    let (_source, rx) = watch::channel(Some(state));
    let controller = material_controller(&rx, local_id);
    let mut config = opc_sctp::SctpEndpointConfig::one_to_one(listener_address(role));
    config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    let endpoint =
        opc_sctp::SctpEndpoint::bind_with_authentication(config, SctpAuthenticationConfig::data())
            .expect("restarted SCTP listener");
    marker("ready");
    let association = tokio::time::timeout(Duration::from_secs(10), endpoint.accept())
        .await
        .expect("bounded child association")
        .expect("child association");
    let result = protect(association, controller.clone(), role).await;
    if phase == "identity-refusal" {
        assert!(
            result.is_err(),
            "wrong-identity process cannot acquire protection"
        );
        marker("rejected");
        return;
    }
    let mut connection = result.expect("fresh mutually authenticated child");
    assert_readback(&connection, &controller, role);
    exchange(&mut connection, u8::from(phase == "recovered"), true).await;
    marker("authenticated");
    if phase == "crash" {
        connection
            .send_on_stream(
                3,
                b"synthetic-queued-before-process-death",
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .expect("pre-crash queue");
        marker("queued");
        // The parent must terminate this live process with SIGKILL. There is
        // no graceful close, destructor execution, or exported DTLS state.
        tokio::time::sleep(Duration::from_secs(45)).await;
        panic!("parent did not execute the process crash cut");
    }
    assert_eq!(
        connection
            .receive(Instant::now() + Duration::from_secs(5))
            .await
            .err(),
        Some(Error::PeerClosed)
    );
    marker("done");
}

async fn connect(controller: TlsMaterialController, role: Role) -> Result<Connection, Error> {
    let child_role = if role == Role::Connector {
        Role::Acceptor
    } else {
        Role::Connector
    };
    let mut config = opc_sctp::SctpConnectConfig::new(listener_address(child_role));
    config.local_addrs.push("127.0.0.2:0".parse().unwrap());
    config.max_message_bytes = crate::MAX_DTLS_SCTP_RECORD_BYTES;
    let association = tokio::time::timeout(
        Duration::from_secs(5),
        SctpAssociation::connect_with_authentication(config, SctpAuthenticationConfig::data()),
    )
    .await
    .expect("bounded parent association")
    .expect("parent association");
    protect(association, controller, role).await
}

#[tokio::test]
#[ignore = "requires a private Linux SCTP-AUTH netns and real child processes"]
async fn generic_kernel_process_restart_requires_fresh_mutual_authentication() {
    require_private_namespace();
    if let Ok(role) = std::env::var(CHILD_ROLE) {
        let role = match role.as_str() {
            "client" => Role::Connector,
            "server" => Role::Acceptor,
            _ => panic!("invalid private child role"),
        };
        child(
            role,
            &std::env::var(CHILD_PHASE).expect("private child phase"),
        )
        .await;
        return;
    }
    let material = dtls_material();
    for role in [Role::Connector, Role::Acceptor] {
        let (controller, local_expiry, remote_role, remote_id, wrong_id) =
            if role == Role::Connector {
                (
                    &material.client_controller,
                    material
                        .client_source
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .identity
                        .expires_at,
                    Role::Acceptor,
                    SERVER_ID,
                    OTHER_SERVER_ID,
                )
            } else {
                (
                    &material.server_controller,
                    material
                        ._server_source
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .identity
                        .expires_at,
                    Role::Connector,
                    CLIENT_ID,
                    OTHER_CLIENT_ID,
                )
            };
        let initial_state = identity_state(remote_id, &material._ca);
        let mut initial = ChildPeer::start(remote_role, "crash", &initial_state);
        assert_ne!(
            initial.child.id(),
            std::process::id(),
            "actual separate process"
        );
        initial.expect("ready").await;
        let mut old = connect(controller.clone(), role)
            .await
            .expect("initial protection");
        exchange(&mut old, 0, false).await;
        initial.expect("authenticated").await;
        assert_readback(&old, controller, role);
        assert_eq!(
            old.readback().unwrap().local_certificate_expires_at(),
            local_expiry
        );
        assert_eq!(
            old.readback().unwrap().peer_certificate_expires_at(),
            initial_state.identity.expires_at
        );
        initial.expect("queued").await;
        initial.kill();
        tokio::time::timeout(Duration::from_secs(5), async {
            while old.readback().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded process-death observation without application reads");
        assert_eq!(old.readback().err(), Some(Error::ConnectionClosed));
        assert_eq!(
            old.receive(Instant::now() + Duration::from_secs(1))
                .await
                .err(),
            Some(Error::ConnectionClosed),
            "queued pre-crash plaintext is not authority"
        );

        let wrong_state = identity_state(wrong_id, &material._ca);
        let mut wrong = ChildPeer::start(remote_role, "identity-refusal", &wrong_state);
        assert_ne!(wrong.child.id(), initial.child.id());
        wrong.expect("ready").await;
        assert_eq!(
            connect(controller.clone(), role).await.err(),
            Some(Error::PeerIdentityMismatch),
            "a restarted process must be authenticated again"
        );
        wrong.expect("rejected").await;
        wrong.finish().await;

        let fresh_state = identity_state(remote_id, &material._ca);
        let mut fresh = ChildPeer::start(remote_role, "recovered", &fresh_state);
        assert_ne!(fresh.child.id(), initial.child.id());
        assert_ne!(fresh.child.id(), wrong.child.id());
        fresh.expect("ready").await;
        let mut replacement = connect(controller.clone(), role)
            .await
            .expect("fresh protection");
        exchange(&mut replacement, 1, false).await;
        fresh.expect("authenticated").await;
        assert_readback(&replacement, controller, role);
        assert_eq!(
            replacement
                .readback()
                .unwrap()
                .local_certificate_expires_at(),
            local_expiry
        );
        assert_eq!(
            replacement
                .readback()
                .unwrap()
                .peer_certificate_expires_at(),
            fresh_state.identity.expires_at
        );
        assert_eq!(old.readback().err(), Some(Error::ConnectionClosed));
        assert_eq!(
            old.send(b"cannot revive", Instant::now() + Duration::from_secs(1))
                .await
                .err(),
            Some(Error::ConnectionClosed)
        );
        replacement
            .close(Instant::now() + Duration::from_secs(5))
            .await
            .expect("fresh reciprocal close");
        fresh.expect("done").await;
        fresh.finish().await;
    }
    eprintln!("native protected SCTP process restart assertions completed");
}
