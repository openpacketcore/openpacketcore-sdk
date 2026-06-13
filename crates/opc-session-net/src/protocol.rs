use std::time::Duration;

use opc_session_store::backend::{CompareAndSet, ReplicationEntry, SessionOp, SessionOpResult};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::lease::LeaseGuard;
use opc_session_store::model::{OwnerId, SessionKey};
use opc_session_store::record::StoredSessionRecord;
use serde::{Deserialize, Serialize};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ProtocolError;

pub const CONTRACT_VERSION: u32 = 1;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Hello {
        contract_version: u32,
        node_id: String,
    },
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
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
    let len = json.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(ProtocolError::Io)?;
    writer.write_all(&json).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
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
