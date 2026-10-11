//! Sequential method-17 exchanges keep the same live connection and real boot key.
use super::*;
use opc_tls::ScopeTlsConnection;
use tokio::net::TcpStream;

pub(crate) struct RawChildResponse {
    pub(crate) status: u8,
    pub(crate) body: Vec<u8>,
}

pub(crate) async fn reject_before_proof(
    tls: &opc_tls::AuthenticatedClientConfig,
    address: std::net::SocketAddr,
    scope: &ScopeId,
    canonical: Vec<u8>,
) -> ScopeRpcError {
    let binding = ScopeBinding::from_scope(scope).unwrap();
    let id = [69; 16];
    let nonce = [69; 32];
    let digest = transport_request_digest(Method::ChildRead, &id, &canonical).unwrap();
    let bytes = CallPayload { nonce, canonical }
        .encode(Method::ChildRead)
        .unwrap();
    let call = Header {
        kind: FrameKind::Call,
        class: Class::Normal,
        method: Method::ChildRead,
        installation: *binding.installation(),
        scope: binding.commitment(),
        request_id: id,
        digest,
        payload_len: bytes.len(),
    };
    let mut stream = tls
        .begin_handshake()
        .unwrap()
        .connect_scope(
            TcpStream::connect(address).await.unwrap(),
            binding.tls_domain().unwrap(),
        )
        .await
        .unwrap();
    stream.write_all(&call.encode().unwrap()).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut fixed = [0; HEADER_BYTES];
    stream.read_exact(&mut fixed).await.unwrap();
    let result = Header::decode(&fixed).unwrap();
    assert_eq!(
        result.kind,
        FrameKind::Result,
        "malformed key sets cannot reserve a challenge or reach a native read"
    );
    assert!(result.matches_attempt(&call));
    let mut body = vec![0; result.payload_len];
    stream.read_exact(&mut body).await.unwrap();
    let payload = ResultPayload::decode(&body).unwrap();
    assert_eq!(payload.nonce, nonce);
    assert_eq!(payload.status, ResultStatus::ProvenNoEffect);
    super::super::super::rpc_client::payload_error(&payload).unwrap()
}

impl RawPeer {
    pub(crate) async fn child_read_on(
        &self,
        mut stream: ScopeTlsConnection<TcpStream>,
        request: &ScopeChildReadRequest,
        class: Class,
        tag: u8,
        clock: &dyn AuthenticationClock,
    ) -> (ScopeTlsConnection<TcpStream>, RawChildResponse) {
        let binding = ScopeBinding::from_scope(request.stamp().scope()).unwrap();
        let canonical = request.encode_canonical().unwrap();
        let id = [tag; 16];
        let nonce = [tag; 32];
        let bytes = CallPayload {
            nonce,
            canonical: canonical.clone(),
        }
        .encode(Method::ChildRead)
        .unwrap();
        let call = Header {
            kind: FrameKind::Call,
            class,
            method: Method::ChildRead,
            installation: *binding.installation(),
            scope: binding.commitment(),
            request_id: id,
            digest: transport_request_digest(Method::ChildRead, &id, &canonical).unwrap(),
            payload_len: bytes.len(),
        };
        stream.write_all(&call.encode().unwrap()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
        let mut fixed = [0; HEADER_BYTES];
        stream.read_exact(&mut fixed).await.unwrap();
        let challenge_header = Header::decode(&fixed).unwrap();
        assert_eq!(challenge_header.kind, FrameKind::Challenge);
        assert!(challenge_header.matches_attempt(&call));
        let mut challenge = [0; 32];
        stream.read_exact(&mut challenge).await.unwrap();
        let claims = PossessionClaims {
            call: call.clone(),
            caller_nonce: nonce,
            execution: request.stamp().execution().transport_digest().unwrap(),
            public_key: self.record.public_key,
            authority: None,
            challenge,
            binding: *stream
                .channel_binding(
                    opc_tls::ChannelBindingPurpose::ScopeRequest,
                    clock.interval().unwrap(),
                )
                .unwrap()
                .as_bytes(),
        };
        let signature: Signature = self.key.try_sign(&claims.encode().unwrap()).unwrap();
        let proof = PossessionProof {
            claims,
            signature: signature.normalize_s().to_bytes().into(),
        };
        proof.verify_against(&proof.claims).unwrap();
        let bytes = proof.encode().unwrap();
        stream
            .write_all(
                &call
                    .response(FrameKind::Proof, bytes.len())
                    .unwrap()
                    .encode()
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
        stream.read_exact(&mut fixed).await.unwrap();
        let response = Header::decode(&fixed).unwrap();
        assert_eq!(response.kind, FrameKind::Result);
        assert!(response.matches_attempt(&call));
        let mut bytes = vec![0; response.payload_len];
        stream.read_exact(&mut bytes).await.unwrap();
        let payload = ResultPayload::decode(&bytes).unwrap();
        assert_eq!(payload.nonce, nonce);
        assert_eq!(payload.own_execution, [0; 32]);
        stream
            .channel_binding(
                opc_tls::ChannelBindingPurpose::ScopeResponse,
                clock.interval().unwrap(),
            )
            .unwrap();
        (
            stream,
            RawChildResponse {
                status: payload.status as u8,
                body: payload.body,
            },
        )
    }
}
