use std::time::Duration;

use opc_session_store::backend::{CompareAndSet, ReplicationEntry, SessionOp, SessionOpResult};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::StoreError;
use opc_session_store::lease::LeaseGuard;
use opc_session_store::model::{OwnerId, SessionKey};
use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{RestoreScanCursor, RestoreScanPage, RestoreScanRequest, RestoreScanScope};
use serde::{Deserialize, Serialize};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ProtocolError;

pub const CONTRACT_VERSION: u32 = 3;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME_SIZE: usize = 8 * 1024;
pub const MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE: usize = 512;
pub const SESSION_NET_ALPN: &[u8] = b"opc-session-net/3";

/// Redaction-safe reason a v3 Hello was rejected before backend dispatch.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelloRejectReason {
    /// A required field was absent, malformed, or outside its fixed bound.
    Malformed,
    /// The authenticated peer did not match the configured membership scope.
    Authentication,
}

/// Architecture-independent restore-scan request carried by protocol v3.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RestoreScanWireRequest {
    scope: RestoreScanScope,
    cursor: Option<u64>,
    limit: u32,
}

impl TryFrom<&RestoreScanRequest> for RestoreScanWireRequest {
    type Error = StoreError;

    fn try_from(request: &RestoreScanRequest) -> Result<Self, Self::Error> {
        request.validate()?;
        let cursor = request
            .cursor
            .map(RestoreScanCursor::offset)
            .map(u64::try_from)
            .transpose()
            .map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "restore scan cursor exceeds the protocol range".to_string(),
                )
            })?;
        let limit = u32::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit exceeds the protocol range".to_string(),
            )
        })?;
        Ok(Self {
            scope: request.scope.clone(),
            cursor,
            limit,
        })
    }
}

impl TryFrom<RestoreScanWireRequest> for RestoreScanRequest {
    type Error = StoreError;

    fn try_from(request: RestoreScanWireRequest) -> Result<Self, Self::Error> {
        let cursor = request
            .cursor
            .map(usize::try_from)
            .transpose()
            .map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "restore scan cursor is not representable on this server".to_string(),
                )
            })?
            .map(RestoreScanCursor::from_offset);
        let limit = usize::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit is not representable on this server".to_string(),
            )
        })?;
        let request = Self {
            scope: request.scope,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Hello {
        contract_version: u32,
        /// Stable client replica ID. The v2 field name is retained solely so
        /// mixed versions can exchange a clean version mismatch.
        node_id: String,
        #[serde(default)]
        expected_server_replica_id: Option<String>,
        #[serde(default)]
        cluster_id: Option<String>,
        #[serde(default)]
        configuration_id: Option<String>,
        #[serde(default)]
        handshake_nonce: Option<uuid::Uuid>,
    },
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
        #[serde(default)]
        request_id: Option<String>,
    },
    DeleteFenced {
        lease: LeaseGuard,
    },
    RefreshTtl {
        lease: LeaseGuard,
        ttl: Duration,
    },
    Batch {
        ops: Vec<SessionOp>,
    },
    ScanRestoreRecords {
        request: RestoreScanWireRequest,
        max_response_frame_size: u32,
    },
    MaxReplicationSequence,
    GetReplicationLog {
        start: u64,
        limit: usize,
    },
    ReplicateEntry {
        entry: ReplicationEntry,
    },
    RebuildReplicationState {
        entries: Vec<ReplicationEntry>,
    },
    Watch {
        start_sequence: u64,
    },
    NextLeaseInfo,
    AcquireLease {
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
    },
    RenewLease {
        lease: LeaseGuard,
        ttl: Duration,
    },
    ReleaseLease {
        lease: LeaseGuard,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    HelloAck {
        contract_version: u32,
        #[serde(default)]
        server_replica_id: Option<String>,
        #[serde(default)]
        accepted_client_replica_id: Option<String>,
        #[serde(default)]
        cluster_id: Option<String>,
        #[serde(default)]
        configuration_id: Option<String>,
        #[serde(default)]
        handshake_nonce: Option<uuid::Uuid>,
    },
    HelloRejected {
        reason: HelloRejectReason,
    },
    Capabilities(BackendCapabilities),
    Get(Result<Option<StoredSessionRecord>, opc_session_store::error::StoreError>),
    CompareAndSet(
        Result<
            opc_session_store::backend::CompareAndSetResult,
            opc_session_store::error::StoreError,
        >,
    ),
    DeleteFenced(Result<(), opc_session_store::error::StoreError>),
    RefreshTtl(Result<(), opc_session_store::error::StoreError>),
    Batch(Result<Vec<SessionOpResult>, opc_session_store::error::StoreError>),
    ScanRestoreRecords(Result<RestoreScanPage, opc_session_store::error::StoreError>),
    MaxReplicationSequence(Result<u64, opc_session_store::error::StoreError>),
    GetReplicationLog(Result<Vec<ReplicationEntry>, opc_session_store::error::StoreError>),
    ReplicateEntry(Result<(), opc_session_store::error::StoreError>),
    RebuildReplicationState(Result<(), opc_session_store::error::StoreError>),
    WatchStream,
    WatchEntry(Result<ReplicationEntry, opc_session_store::error::StoreError>),
    NextLeaseInfo(Result<(u64, u64), opc_session_store::error::StoreError>),
    AcquireLease(Result<LeaseGuard, opc_session_store::error::LeaseError>),
    RenewLease(Result<LeaseGuard, opc_session_store::error::LeaseError>),
    ReleaseLease(Result<(), opc_session_store::error::LeaseError>),
    Error {
        message: String,
    },
}

pub async fn write_frame<W, T>(writer: &mut W, frame: &T) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(frame).map_err(ProtocolError::Serialization)?;
    let len = u32::try_from(json.len()).map_err(|_| ProtocolError::FrameTooLarge(json.len()))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(ProtocolError::Io)?;
    writer.write_all(&json).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Write a complete frame within `timeout`.
///
/// Servers use this for bounded responses so a peer that stops reading cannot
/// retain a connection slot indefinitely.
pub async fn write_frame_within<W, T>(
    writer: &mut W,
    frame: &T,
    timeout: std::time::Duration,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    match tokio::time::timeout(timeout, write_frame(writer, frame)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out writing frame to peer",
        ))),
    }
}

struct BoundedFrameCounter {
    encoded_len: usize,
    max_frame_size: usize,
    exceeded_at: Option<usize>,
}

impl std::io::Write for BoundedFrameCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(attempted) = self.encoded_len.checked_add(buf.len()) else {
            self.exceeded_at = Some(usize::MAX);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encoded frame length overflowed",
            ));
        };
        if attempted > self.max_frame_size {
            self.exceeded_at = Some(attempted);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encoded frame exceeds configured limit",
            ));
        }
        self.encoded_len = attempted;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validate an encoded frame size without allocating the encoded payload.
pub(crate) fn ensure_frame_fits<T>(frame: &T, max_frame_size: usize) -> Result<(), ProtocolError>
where
    T: Serialize,
{
    let mut counter = BoundedFrameCounter {
        encoded_len: 0,
        max_frame_size,
        exceeded_at: None,
    };
    match serde_json::to_writer(&mut counter, frame) {
        Ok(()) => Ok(()),
        Err(_) if counter.exceeded_at.is_some() => Err(ProtocolError::FrameTooLarge(
            counter
                .exceeded_at
                .unwrap_or(max_frame_size.saturating_add(1)),
        )),
        Err(error) => Err(ProtocolError::Serialization(error)),
    }
}

pub async fn read_frame<R, T>(reader: &mut R, max_frame_size: usize) -> Result<T, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(ProtocolError::Io)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max_frame_size {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(ProtocolError::Io)?;
    serde_json::from_slice(&buf).map_err(ProtocolError::Serialization)
}

/// Read a frame, failing with a timed-out I/O error if the whole frame does not
/// arrive within `timeout`.
///
/// Servers must use this rather than [`read_frame`] on accepted connections so
/// that a peer which connects and then stalls (sending nothing, or a partial
/// length prefix) is reaped instead of holding its connection slot forever
/// (slowloris-style exhaustion).
pub async fn read_frame_within<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: std::time::Duration,
) -> Result<T, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    match tokio::time::timeout(timeout, read_frame(reader, max_frame_size)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out reading frame from peer",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_scan_protocol_v3_frames_round_trip() {
        assert_eq!(CONTRACT_VERSION, 3);

        let domain_request = RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(RestoreScanCursor::from_offset(7)),
            limit: 3,
        };
        let request = Request::ScanRestoreRecords {
            request: RestoreScanWireRequest::try_from(&domain_request).expect("wire request"),
            max_response_frame_size: 32_768,
        };
        let encoded = serde_json::to_vec(&request).expect("encode request");
        let decoded: Request = serde_json::from_slice(&encoded).expect("decode request");
        match decoded {
            Request::ScanRestoreRecords {
                request,
                max_response_frame_size,
            } => {
                assert_eq!(
                    RestoreScanRequest::try_from(request).expect("domain request"),
                    domain_request
                );
                assert_eq!(max_response_frame_size, 32_768);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let response = Response::ScanRestoreRecords(Ok(RestoreScanPage::new(Vec::new(), 0, None)));
        let encoded = serde_json::to_vec(&response).expect("encode response");
        let decoded: Response = serde_json::from_slice(&encoded).expect("decode response");
        assert!(matches!(
            decoded,
            Response::ScanRestoreRecords(Ok(RestoreScanPage {
                loaded_count: 0,
                complete: true,
                ..
            }))
        ));
    }

    #[test]
    fn bounded_encoder_rejects_oversized_restore_frame() {
        let response =
            Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable("x".repeat(1024))));
        assert!(matches!(
            ensure_frame_fits(&response, 128),
            Err(ProtocolError::FrameTooLarge(_))
        ));

        let terminal = Response::ScanRestoreRecords(Err(StoreError::RestoreScanResponseTooLarge {
            max_bytes: MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
        }));
        ensure_frame_fits(&terminal, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
            .expect("minimum response budget must fit the terminal error");
    }

    #[tokio::test]
    async fn oversized_declared_frame_is_rejected_before_payload_read() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            writer
                .write_all(&1024_u32.to_be_bytes())
                .await
                .expect("write length");
        });

        let result = read_frame::<_, Response>(&mut reader, 128).await;
        assert!(matches!(result, Err(ProtocolError::FrameTooLarge(1024))));
    }
}
