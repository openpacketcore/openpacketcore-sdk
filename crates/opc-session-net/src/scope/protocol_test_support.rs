//! Raw test peers deliberately stop before supplying a possession proof.
use super::wire::*;
use opc_session_store::scope_authority::{ScopeAuthorityRequest, ScopeAuthorityStamp, ScopeId};
use opc_tls::{AuthenticatedClientConfig, ScopeTlsConnection};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub(crate) async fn pending_proof(
    tls: AuthenticatedClientConfig,
    address: SocketAddr,
    scope: &ScopeId,
    candidate: Option<&ScopeAuthorityRequest>,
    tag: u8,
) -> ScopeTlsConnection<TcpStream> {
    let (method, canonical, id, digest) = match candidate {
        Some(request) => (
            Method::AdmitInitial,
            request.encode_canonical().unwrap(),
            *request.request_id(),
            request.digest().unwrap(),
        ),
        None => {
            let bytes = scope.encode_canonical().unwrap();
            let id = [tag; 16];
            let digest = transport_request_digest(Method::Current, &id, &bytes).unwrap();
            (Method::Current, bytes, id, digest)
        }
    };
    pending_call(
        tls,
        address,
        scope,
        Class::SafetyControl,
        (method, canonical, id, digest),
        tag,
    )
    .await
}

pub(crate) async fn pending_batch_proof(
    tls: AuthenticatedClientConfig,
    address: SocketAddr,
    stamp: &ScopeAuthorityStamp,
    tag: u8,
) -> ScopeTlsConnection<TcpStream> {
    pending_batch_proof_in_class(tls, address, stamp, Class::Emergency, tag).await
}

pub(crate) async fn pending_batch_proof_in_class(
    tls: AuthenticatedClientConfig,
    address: SocketAddr,
    stamp: &ScopeAuthorityStamp,
    class: Class,
    tag: u8,
) -> ScopeTlsConnection<TcpStream> {
    let method = Method::BatchReopen;
    let canonical = stamp.encode_canonical().unwrap();
    let id = [tag; 16];
    let digest = transport_request_digest(method, &id, &canonical).unwrap();
    pending_call(
        tls,
        address,
        stamp.scope(),
        class,
        (method, canonical, id, digest),
        tag,
    )
    .await
}

async fn pending_call(
    tls: AuthenticatedClientConfig,
    address: SocketAddr,
    scope: &ScopeId,
    class: Class,
    (method, canonical, id, digest): (Method, Vec<u8>, [u8; 16], [u8; 32]),
    tag: u8,
) -> ScopeTlsConnection<TcpStream> {
    let binding = ScopeBinding::from_scope(scope).unwrap();
    let socket = TcpStream::connect(address).await.unwrap();
    let mut connection = tls
        .begin_handshake()
        .unwrap()
        .connect_scope(socket, binding.tls_domain().unwrap())
        .await
        .unwrap();
    let bytes = CallPayload {
        nonce: [tag; 32],
        canonical,
    }
    .encode(method)
    .unwrap();
    let header = Header {
        kind: FrameKind::Call,
        class,
        method,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: id,
        digest,
        payload_len: bytes.len(),
    };
    connection
        .write_all(&header.encode().unwrap())
        .await
        .unwrap();
    connection.write_all(&bytes).await.unwrap();
    connection.flush().await.unwrap();
    let mut fixed = [0; HEADER_BYTES];
    connection.read_exact(&mut fixed).await.unwrap();
    let reply = Header::decode(&fixed).unwrap();
    assert_eq!(reply.kind, FrameKind::Challenge);
    assert!(reply.matches_attempt(&header));
    assert_eq!(reply.payload_len, 32);
    let mut challenge = [0; 32];
    connection.read_exact(&mut challenge).await.unwrap();
    assert_ne!(challenge, [0; 32]);
    connection
}
