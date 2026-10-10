//! Adversarial peers replay a correctly signed proof on a different real TLS stream.
pub(crate) mod cross_slot;

use super::{wire::*, AuthenticationClock, ScopeProcess};
use opc_session_store::scope_authority::{ScopeExecution, ScopeId};
use opc_tls::{AuthenticatedClientConfig, ScopeTlsConnection};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn begin(
    tls: &AuthenticatedClientConfig,
    address: SocketAddr,
    scope: &ScopeBinding,
    header: &Header,
    body: &[u8],
) -> (ScopeTlsConnection<TcpStream>, [u8; 32]) {
    let mut connection = tls
        .begin_handshake()
        .unwrap()
        .connect_scope(
            TcpStream::connect(address).await.unwrap(),
            scope.tls_domain().unwrap(),
        )
        .await
        .unwrap();
    connection
        .write_all(&header.encode().unwrap())
        .await
        .unwrap();
    connection.write_all(body).await.unwrap();
    connection.flush().await.unwrap();
    let mut fixed = [0; HEADER_BYTES];
    connection.read_exact(&mut fixed).await.unwrap();
    let reply = Header::decode(&fixed).unwrap();
    assert!(reply.matches_attempt(header));
    assert_eq!(reply.kind, FrameKind::Challenge);
    let mut challenge = [0; 32];
    connection.read_exact(&mut challenge).await.unwrap();
    (connection, challenge)
}
pub(crate) async fn replay_between_connections(
    tls: &AuthenticatedClientConfig,
    address: SocketAddr,
    scope: &ScopeId,
    process: &ScopeProcess,
    execution: &ScopeExecution,
    clock: &dyn AuthenticationClock,
) {
    let binding = ScopeBinding::from_scope(scope).unwrap();
    let canonical = scope.encode_canonical().unwrap();
    let id = [49; 16];
    let nonce = [50; 32];
    let bytes = CallPayload {
        nonce,
        canonical: canonical.clone(),
    }
    .encode(Method::Current)
    .unwrap();
    let header = Header {
        kind: FrameKind::Call,
        class: Class::SafetyControl,
        method: Method::Current,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: id,
        digest: transport_request_digest(Method::Current, &id, &canonical).unwrap(),
        payload_len: bytes.len(),
    };
    let (mut first, challenge) = begin(tls, address, &binding, &header, &bytes).await;
    let proof = process
        .boot
        .scope_proof(
            &first,
            clock.interval().unwrap(),
            scope,
            execution,
            &header,
            nonce,
            &canonical,
            None,
            challenge,
            None,
        )
        .unwrap();
    let proof_bytes = proof.encode().unwrap();
    let (mut second, second_challenge) = begin(tls, address, &binding, &header, &bytes).await;
    assert_ne!(challenge, second_challenge);
    let proof_header = header
        .response(FrameKind::Proof, proof_bytes.len())
        .unwrap();
    second
        .write_all(&proof_header.encode().unwrap())
        .await
        .unwrap();
    second.write_all(&proof_bytes).await.unwrap();
    second.flush().await.unwrap();
    let mut probe = [0; 1];
    let rejected = tokio::time::timeout(Duration::from_secs(2), second.read(&mut probe))
        .await
        .unwrap();
    assert!(
        !matches!(rejected, Ok(1..)),
        "a correctly signed proof from another connection must not produce any result"
    );
    let mut invalid_signature = proof_bytes;
    *invalid_signature.last_mut().unwrap() ^= 1;
    first
        .write_all(&proof_header.encode().unwrap())
        .await
        .unwrap();
    first.write_all(&invalid_signature).await.unwrap();
    first.flush().await.unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(2), first.read(&mut probe))
        .await
        .unwrap();
    assert!(
        !matches!(rejected, Ok(1..)),
        "matching claims with an invalid signature cannot produce a result"
    );
    drop(first);
    drop(second);
}

pub(crate) async fn controller_cannot_submit_worker_mutation(
    tls: &AuthenticatedClientConfig,
    address: SocketAddr,
    scope: &ScopeId,
    request: &opc_session_store::scope_authority::ScopeAuthorityRequest,
) {
    let binding = ScopeBinding::from_scope(scope).unwrap();
    let mut stream = tls
        .begin_handshake()
        .unwrap()
        .connect_scope(
            TcpStream::connect(address).await.unwrap(),
            binding.tls_domain().unwrap(),
        )
        .await
        .unwrap();
    let header = Header {
        kind: FrameKind::Call,
        class: Class::SafetyControl,
        method: Method::AdmitInitial,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: *request.request_id(),
        digest: request.digest().unwrap(),
        payload_len: 36 + request.encode_canonical().unwrap().len(),
    };
    // Supply only the correlation nonce; withhold the entire canonical body.
    stream.write_all(&header.encode().unwrap()).await.unwrap();
    stream.write_all(&[51; 32]).await.unwrap();
    stream.flush().await.unwrap();
    expect_unauthorized_before_challenge(&mut stream, &header, [51; 32]).await;
}

pub(crate) async fn controller_cannot_submit_batch_mutation(
    tls: &AuthenticatedClientConfig,
    address: SocketAddr,
    target: &opc_session_store::scope_batch::ScopeBatchAttempt,
) {
    let binding = ScopeBinding::from_scope(target.stamp().scope()).unwrap();
    for method in [Method::ApplyBatch, Method::BatchCancel] {
        let mut stream = tls
            .begin_handshake()
            .unwrap()
            .connect_scope(
                TcpStream::connect(address).await.unwrap(),
                binding.tls_domain().unwrap(),
            )
            .await
            .unwrap();
        let header = Header {
            kind: FrameKind::Call,
            class: Class::Normal,
            method,
            installation: *binding.installation(),
            scope: binding.commitment(),
            request_id: *target.request_id(),
            digest: if method == Method::BatchCancel {
                target.cancellation_digest().unwrap()
            } else {
                *target.request_digest()
            },
            payload_len: 36 + target.encode_canonical().unwrap().len(),
        };
        // Only the correlation nonce is sent: no canonical body is available.
        stream.write_all(&header.encode().unwrap()).await.unwrap();
        stream.write_all(&[52; 32]).await.unwrap();
        stream.flush().await.unwrap();
        expect_unauthorized_before_challenge(&mut stream, &header, [52; 32]).await;
    }
}

async fn expect_unauthorized_before_challenge(
    stream: &mut ScopeTlsConnection<TcpStream>,
    call: &Header,
    nonce: [u8; 32],
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut fixed = [0; HEADER_BYTES];
        stream.read_exact(&mut fixed).await.unwrap();
        let response = Header::decode(&fixed).unwrap();
        assert_eq!(
            response.kind,
            FrameKind::Result,
            "a forbidden role never receives a challenge"
        );
        assert!(response.matches_attempt(call));
        let mut body = vec![0; response.payload_len];
        stream.read_exact(&mut body).await.unwrap();
        let payload = ResultPayload::decode(&body).unwrap();
        assert_eq!(payload.nonce, nonce);
        assert_eq!(
            super::rpc_client::payload_error(&payload).unwrap(),
            super::ScopeRpcError::Unauthorized
        );
    })
    .await
    .expect("a role refusal reads no canonical body");
}

pub(crate) fn mismatched_retained_records(
    record: &super::BootAuthorityRecord,
) -> [super::BootAuthorityRecord; 3] {
    let mut scope = record.clone();
    let mut encoded = scope.scope.encode();
    encoded[0] ^= 1;
    scope.scope = ScopeBinding::decode(&encoded).unwrap();
    let mut key = record.clone();
    key.public_key = p256::ecdsa::SigningKey::from_slice(&[7; 32])
        .unwrap()
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut execution = record.clone();
    let old = &execution.execution;
    execution.execution = ScopeExecution::new(
        old.identity().clone(),
        old.admission_generation() + 1,
        *old.workload(),
        *old.process(),
        *old.boot_key(),
    )
    .unwrap();
    [scope, key, execution]
}

pub(crate) async fn noncurrent_emergency_batch(
    tls: &AuthenticatedClientConfig,
    address: SocketAddr,
    request: &opc_session_store::scope_batch::ScopeBatchRequest,
    process: &ScopeProcess,
    clock: &dyn AuthenticationClock,
) -> opc_session_store::scope_batch::ScopeBatchError {
    let scope = request.stamp().scope();
    let binding = ScopeBinding::from_scope(scope).unwrap();
    let canonical = request.encode_canonical().unwrap();
    let nonce = [53; 32];
    let bytes = CallPayload {
        nonce,
        canonical: canonical.clone(),
    }
    .encode(Method::ApplyBatch)
    .unwrap();
    let call = Header {
        kind: FrameKind::Call,
        class: Class::Emergency,
        method: Method::ApplyBatch,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: *request.request_id(),
        digest: request.digest().unwrap(),
        payload_len: bytes.len(),
    };
    let (mut stream, challenge) = begin(tls, address, &binding, &call, &bytes).await;
    let proof = process
        .boot
        .scope_proof(
            &stream,
            clock.interval().unwrap(),
            scope,
            request.stamp().execution(),
            &call,
            nonce,
            &canonical,
            None,
            challenge,
            None,
        )
        .unwrap()
        .encode()
        .unwrap();
    let header = call.response(FrameKind::Proof, proof.len()).unwrap();
    stream.write_all(&header.encode().unwrap()).await.unwrap();
    stream.write_all(&proof).await.unwrap();
    stream.flush().await.unwrap();
    let mut fixed = [0; HEADER_BYTES];
    stream.read_exact(&mut fixed).await.unwrap();
    let response = Header::decode(&fixed).unwrap();
    assert_eq!(response.kind, FrameKind::Result);
    assert!(response.matches_attempt(&call));
    let mut bytes = vec![0; response.payload_len];
    stream.read_exact(&mut bytes).await.unwrap();
    let payload = ResultPayload::decode(&bytes).unwrap();
    assert_eq!(payload.nonce, nonce);
    assert_eq!(payload.status, ResultStatus::BatchError);
    opc_session_store::scope_batch::ScopeBatchError::decode_canonical(&payload.body).unwrap()
}
