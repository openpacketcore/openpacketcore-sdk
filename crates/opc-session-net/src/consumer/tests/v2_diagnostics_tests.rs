use super::super::v2_response_matches_request;
use super::*;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Output, Stdio};
use std::time::Instant;

const CLIENT_PROBE: &str =
    "consumer::tests::v2_diagnostics_tests::client_errors_preserve_typed_results";
const TRANSPORT_PROBE: &str =
    "consumer::tests::v2_outcome_status_recovery_preserves_the_original_status_envelope";
const SERVICE_PROBE: &str =
    "consumer::tests::v2_diagnostics_tests::service_errors_preserve_exact_batch_results";

struct AmbiguousBatchConsumer(AtomicUsize);

#[async_trait::async_trait]
impl SessionQuorumConsumer for AmbiguousBatchConsumer {
    async fn execute(
        &self,
        _: &SessionConsumerAuthorization,
        _: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
    }

    async fn execute_v2(
        &self,
        _: &SessionConsumerAuthorization,
        request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        self.0.fetch_add(1, Ordering::SeqCst);
        // A service-origin ambiguity must carry the complete identity vector.
        // The server closes the lane for unbound singleton or per-item errors.
        let response = SessionConsumerV2Response::FencedTransitionV2Batch(Err(
            opc_session_store::consumer::SessionConsumerV2FencedTransitionBatchError::OutcomeUnknown {
                request_ids: v2_batch_request_ids(&request),
            },
        ));
        assert!(v2_response_matches_request(&request, &response));
        response
    }

    async fn watch(
        &self,
        _: &SessionConsumerAuthorization,
        _: SessionConsumerScope,
        _: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        Err(SessionConsumerRejection::Unavailable)
    }
}

#[tokio::test]
async fn service_errors_preserve_exact_batch_results() {
    let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
        .lock()
        .await;
    let client_identity = material_spiffe("v2-diagnostic-client");
    let server_identity = material_spiffe("v2-diagnostic-server");
    let material = RotatableClientMaterial::new(client_identity.as_str());
    let service = Arc::new(AmbiguousBatchConsumer(AtomicUsize::new(0)));
    let authorizer = SessionConsumerAuthorizer::from_authoritative_members(
        scope(),
        [client_identity],
        std::iter::empty(),
    )
    .expect("diagnostic probe authorizer");
    let (server, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        material.trusted_server_config(server_identity.as_str()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().expect("loopback address"))
    .await
    .expect("listen for diagnostic probe");
    let stateless = StatelessSessionConsumerClient::new_unattested_for_test(
        address,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        server_identity,
        scope(),
        material.config(),
    );
    let request = v2_effectful_batch_request(&[0xd2, 0xd3]).await;
    let expected = Err(
        PersistentSessionConsumerV2ExecuteError::OutcomeUnknownBatch {
            request_ids: v2_batch_request_ids(&request),
        },
    );
    assert_eq!(stateless.execute_v2(&request).await, expected);
    let persistent = PersistentSessionConsumerClient::from_stateless(stateless)
        .expect("persistent diagnostic probe");
    assert_eq!(persistent.execute_v2(&request).await, expected);
    assert_eq!(service.0.load(Ordering::SeqCst), 2);
    let _ = persistent.shutdown().await;
    server.abort_and_wait().await;
}

#[tokio::test]
async fn client_errors_preserve_typed_results() {
    let mutation = persistent_v2_effectful_test_request(0xd1).await;
    let request_id = mutation.request_id().expect("exact mutation identity");
    let read = SessionConsumerV2Request::new(
        mutation.scope(),
        SessionConsumerV2Operation::FencedTransitionV2Capability,
    );
    assert_eq!(
        v2_persistent_error(&mutation, false, SessionConsumerClientError::Unavailable),
        PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        }
    );
    assert_eq!(
        v2_persistent_error(&mutation, true, SessionConsumerClientError::Deadline),
        PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id }
    );
    assert_eq!(
        v2_persistent_error(&read, true, SessionConsumerClientError::Deadline),
        PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
            cause: SessionConsumerClientError::Deadline,
        }
    );
}

fn spawn_probe(name: &str, stderr: Stdio) -> Child {
    Command::new(std::env::current_exe().expect("current test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .expect("spawn isolated diagnostic probe")
}

fn finish_probe(mut child: Child) -> Result<Output, String> {
    // A watchdog for the subprocess, independent of the unchanged RPC deadlines.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|error| error.to_string()),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            status => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("diagnostic probe failed to exit: {status:?}"));
            }
        }
    }
}

fn check_probe(
    name: &str,
    sink: &str,
    child: Child,
    expected_lines: &[&str],
    failures: &mut Vec<String>,
) {
    match finish_probe(child) {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !output.status.success() || !stdout.contains("1 passed; 0 failed") {
                failures.push(format!(
                    "{name} with {sink}: status={:?}, stdout={stdout}, stderr={stderr}",
                    output.status
                ));
            }
            let lines = stderr.lines().collect::<Vec<_>>();
            if lines != expected_lines {
                failures.push(format!(
                    "{name} with {sink}: expected {expected_lines:?}, stderr={stderr}"
                ));
            }
        }
        Err(error) => failures.push(format!("{name} with {sink}: {error}")),
    }
}

#[test]
fn diagnostics_are_opt_in_and_preserve_production_results() {
    let mut failures = Vec::new();
    for (name, diagnostic_lines) in [
        (
            CLIENT_PROBE,
            &[
                "sdk_v2_diagnostic_origin=client wrote=false cause=Unavailable",
                "sdk_v2_diagnostic_origin=client wrote=true cause=Deadline",
                "sdk_v2_diagnostic_origin=client wrote=true cause=Deadline",
            ][..],
        ),
        (
            TRANSPORT_PROBE,
            &["sdk_v2_diagnostic_origin=client wrote=true cause=Unavailable"; 2][..],
        ),
        (
            SERVICE_PROBE,
            &["sdk_v2_diagnostic_origin=service_outcome_unknown"; 2][..],
        ),
    ] {
        check_probe(
            name,
            "captured stderr",
            spawn_probe(name, Stdio::piped()),
            if cfg!(feature = "test-control") {
                diagnostic_lines
            } else {
                &[]
            },
            &mut failures,
        );

        if !cfg!(feature = "test-control") {
            let failing = OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("open failing stderr sink");
            check_probe(
                name,
                "failing stderr",
                spawn_probe(name, Stdio::from(failing)),
                &[],
                &mut failures,
            );

            // Retain an undrained reader and fill the writer before handing it
            // to the child. Any synchronous diagnostic write would then stall.
            let (mut writer, reader) = UnixStream::pair().expect("stderr socket pair");
            writer.set_nonblocking(true).expect("nonblocking fill");
            let mut filled = 0;
            loop {
                match writer.write(&[b'x'; 8192]) {
                    Ok(0) => panic!("stderr writer stopped accepting bytes"),
                    Ok(bytes) => filled += bytes,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("fill stderr sink: {error}"),
                }
            }
            assert!(filled > 0, "exercise a full sink");
            writer.set_nonblocking(false).expect("blocking child sink");
            let descriptor: OwnedFd = writer.into();
            check_probe(
                name,
                "full blocking stderr",
                spawn_probe(name, Stdio::from(descriptor)),
                &[],
                &mut failures,
            );
            drop(reader);
        }
    }
    assert!(
        failures.is_empty(),
        "diagnostic sink contract:\n{}",
        failures.join("\n")
    );
}
