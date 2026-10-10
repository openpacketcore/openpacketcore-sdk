//! Raw test peers deliberately bypass the SDK's own-key and local-gate checks.
use super::super::{
    proof::{PossessionClaims, PossessionProof},
    wire::*,
    AuthenticationClock, BootAuthorityRecord, ScopeRpcError,
};
use opc_session_store::{scope_authority::*, scope_batch::*, SessionConsumerIdentity};
use opc_tls::AuthenticatedClientConfig;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct RawPeer {
    key: SigningKey,
    pub(crate) record: BootAuthorityRecord,
}

#[derive(Clone, Copy)]
pub(crate) enum RawCall<'a> {
    Authority(&'a ScopeAuthorityRequest),
    ApplyBatch(&'a ScopeBatchRequest),
    BatchCancel(&'a ScopeBatchAttempt),
    Current,
    Outcome(&'a ScopeAuthorityRequest),
    BatchReopen(&'a ScopeAuthorityStamp),
    BatchLookup(&'a ScopeBatchAttempt),
}
impl RawCall<'_> {
    fn method(self) -> Method {
        match self {
            Self::Authority(request) => match request.operation() {
                ScopeAuthorityOperation::AdmitInitial { .. } => Method::AdmitInitial,
                ScopeAuthorityOperation::SucceedClosed { .. } => Method::SucceedClosed,
                ScopeAuthorityOperation::Close { .. } => Method::Close,
            },
            Self::ApplyBatch(_) => Method::ApplyBatch,
            Self::BatchCancel(_) => Method::BatchCancel,
            Self::Current => Method::Current,
            Self::Outcome(_) => Method::Outcome,
            Self::BatchReopen(_) => Method::BatchReopen,
            Self::BatchLookup(_) => Method::BatchLookup,
        }
    }
    pub(crate) fn label(self) -> String {
        format!("{:?}", self.method())
    }
    pub(crate) fn carries_execution(self) -> bool {
        matches!(
            self,
            Self::Authority(_) | Self::ApplyBatch(_) | Self::BatchCancel(_)
        )
    }
    fn canonical(self, scope: &ScopeId) -> Vec<u8> {
        match self {
            Self::Authority(request) => request.encode_canonical().unwrap(),
            Self::ApplyBatch(request) => request.encode_canonical().unwrap(),
            Self::BatchCancel(attempt) | Self::BatchLookup(attempt) => {
                attempt.encode_canonical().unwrap()
            }
            Self::BatchReopen(stamp) => stamp.encode_canonical().unwrap(),
            Self::Current => scope.encode_canonical().unwrap(),
            Self::Outcome(request) => {
                let mut bytes = scope.encode_canonical().unwrap();
                bytes.extend_from_slice(request.request_id());
                bytes.extend_from_slice(&request.digest().unwrap());
                bytes
            }
        }
    }
}
impl RawPeer {
    pub(crate) fn new(scope: &ScopeId, identity: SessionConsumerIdentity, tag: u8) -> Self {
        let key = SigningKey::from_slice(&[tag; 32]).unwrap();
        let public_key = key.verifying_key().to_sec1_point(true);
        let public_key: [u8; 33] = public_key.as_bytes().try_into().unwrap();
        let execution =
            ScopeExecution::new(identity, 127, [tag; 16], [tag + 1; 16], hash(&public_key))
                .unwrap();
        let record = BootAuthorityRecord::new(
            ScopeBinding::from_scope(scope).unwrap(),
            execution,
            public_key,
            vec![tag; 16],
            b"rv:127".to_vec(),
        )
        .unwrap();
        Self { key, record }
    }

    /// Only a test can construct this inconsistent trusted-reader response:
    /// the public constructor rejects a key that differs from the execution.
    pub(crate) fn inconsistent_retained_record(&self, target: &Self) -> BootAuthorityRecord {
        assert!(BootAuthorityRecord::new(
            target.record.scope.clone(),
            target.record.execution.clone(),
            self.record.public_key,
            vec![1],
            vec![1],
        )
        .is_err());
        let mut record = target.record.clone();
        record.public_key = self.record.public_key;
        record
    }

    pub(crate) async fn send(
        &self,
        tls: &AuthenticatedClientConfig,
        addresses: [SocketAddr; 5],
        scope: &ScopeId,
        claimed_execution: &ScopeExecution,
        call: RawCall<'_>,
        clock: &dyn AuthenticationClock,
    ) -> Result<Vec<u8>, ScopeRpcError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let method = call.method();
            let class = match method {
                Method::ApplyBatch
                | Method::BatchCancel
                | Method::BatchReopen
                | Method::BatchLookup => Class::Normal,
                _ => Class::SafetyControl,
            };
            let binding = ScopeBinding::from_scope(scope).unwrap();
            let canonical = call.canonical(scope);
            let (id, digest) = match call {
                RawCall::Authority(request) => (*request.request_id(), request.digest().unwrap()),
                RawCall::ApplyBatch(request) => (*request.request_id(), request.digest().unwrap()),
                RawCall::BatchCancel(attempt) => (
                    *attempt.request_id(),
                    attempt.cancellation_digest().unwrap(),
                ),
                _ => {
                    let id = [method as u8; 16];
                    (
                        id,
                        transport_request_digest(method, &id, &canonical).unwrap(),
                    )
                }
            };
            let nonce = [method as u8; 32];
            let bytes = CallPayload { nonce, canonical }.encode(method).unwrap();
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
            let (mut stream, challenge) =
                super::begin(tls, addresses[class.index()], &binding, &header, &bytes).await;
            let claims = PossessionClaims {
                call: header.clone(),
                caller_nonce: nonce,
                execution: claimed_execution.transport_digest().unwrap(),
                public_key: self.record.public_key,
                authority: matches!(method, Method::AdmitInitial | Method::SucceedClosed)
                    .then(|| self.record.reference.clone()),
                challenge,
                binding: *stream
                    .channel_binding(
                        opc_tls::ChannelBindingPurpose::ScopeRequest,
                        clock.interval().unwrap(),
                    )
                    .unwrap()
                    .as_bytes(),
            };
            // Sign the target execution with this peer's real key, without the
            // typed client's check that it owns that execution or target slot.
            let signature: Signature = self.key.try_sign(&claims.encode().unwrap()).unwrap();
            let proof = PossessionProof {
                claims,
                signature: signature.normalize_s().to_bytes().into(),
            };
            proof.verify_against(&proof.claims).unwrap();
            let proof = proof.encode().unwrap();
            stream
                .write_all(
                    &header
                        .response(FrameKind::Proof, proof.len())
                        .unwrap()
                        .encode()
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.write_all(&proof).await.unwrap();
            stream.flush().await.unwrap();
            let mut fixed = [0; HEADER_BYTES];
            stream.read_exact(&mut fixed).await.unwrap();
            let response = Header::decode(&fixed).unwrap();
            assert_eq!(response.kind, FrameKind::Result);
            assert!(response.matches_attempt(&header));
            let mut bytes = vec![0; response.payload_len];
            stream.read_exact(&mut bytes).await.unwrap();
            let payload = ResultPayload::decode(&bytes).unwrap();
            assert_eq!(payload.nonce, nonce);
            if matches!(
                payload.status,
                ResultStatus::Committed | ResultStatus::CurrentView
            ) {
                let expected = match call {
                    RawCall::Current | RawCall::BatchReopen(_) | RawCall::BatchLookup(_) => {
                        ResultStatus::CurrentView
                    }
                    _ => ResultStatus::Committed,
                };
                assert_eq!(payload.status, expected);
                Ok(payload.body)
            } else {
                // A store-level batch error is not the authentication refusal
                // this probe requires before dispatch.
                Err(super::super::rpc_client::payload_error(&payload).unwrap())
            }
        })
        .await
        .expect("raw signed scope call completes within the hang guard")
    }
}
