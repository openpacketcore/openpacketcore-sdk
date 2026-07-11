//! Length-prefixed wire framing for the live keymat mirror.
//!
//! `opc-session-net`'s frame helpers are generic, but they live in a crate
//! that hard-depends on the session store and they serialize whole messages
//! through non-zeroizing buffers. Keymat frames therefore use this sibling
//! codec: the JSON header carries **no secrets** (identity, epoch, counters),
//! and key bytes ride only in a raw tail that is read into, assembled in, and
//! wiped from [`Zeroizing`] buffers.
//!
//! Frame layout: `u32 BE header_len | header JSON | u32 BE secret_len |
//! secret bytes`. Only `Install` requests may carry a non-empty tail.

use opc_ipsec_lb::SaId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::SaMirrorError;
use crate::keymat::{
    KeyEpoch, KeymatFormat, MirroredSaKeymat, SaCounterCheckpoint, SaMirrorInstall,
};

/// Mirror wire contract version.
pub(crate) const CONTRACT_VERSION: u32 = 1;

/// Default maximum bytes for a frame header or secret tail.
pub(crate) const DEFAULT_MAX_FRAME_SIZE: usize = 64 * 1024;

/// SA identity as carried on the wire.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireSaId {
    /// IKE SA keyed by responder SPI.
    Ike { responder_spi: u64 },
    /// ESP Child SA keyed by inbound ESP SPI.
    Esp { spi: u32 },
}

impl From<SaId> for WireSaId {
    fn from(sa: SaId) -> Self {
        match sa {
            SaId::Ike { responder_spi } => Self::Ike { responder_spi },
            SaId::Esp { spi } => Self::Esp { spi },
        }
    }
}

impl From<WireSaId> for SaId {
    fn from(sa: WireSaId) -> Self {
        match sa {
            WireSaId::Ike { responder_spi } => Self::Ike { responder_spi },
            WireSaId::Esp { spi } => Self::Esp { spi },
        }
    }
}

/// Mirror request header. Secrets never appear here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum MirrorRequest {
    Hello {
        contract_version: u32,
        node_id: String,
    },
    Install {
        sa: WireSaId,
        epoch: u64,
        format: u64,
        send_iv_next: u64,
        replay_highest_accepted: u64,
    },
    Checkpoint {
        sa: WireSaId,
        epoch: u64,
        send_iv_next: u64,
        replay_highest_accepted: u64,
    },
    Withdraw {
        sa: WireSaId,
        epoch: u64,
    },
}

/// Mirror response header. Rejections carry a static redaction-safe code.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum MirrorResponse {
    HelloAck { contract_version: u32 },
    Accepted,
    Rejected { code: String },
}

impl MirrorRequest {
    pub(crate) fn install_header(install: &SaMirrorInstall) -> Self {
        Self::Install {
            sa: install.sa.into(),
            epoch: install.epoch.get(),
            format: install.keymat.format().get(),
            send_iv_next: install.send_iv_next,
            replay_highest_accepted: install.replay_highest_accepted,
        }
    }

    pub(crate) fn checkpoint_header(checkpoint: &SaCounterCheckpoint) -> Self {
        Self::Checkpoint {
            sa: checkpoint.sa.into(),
            epoch: checkpoint.epoch.get(),
            send_iv_next: checkpoint.send_iv_next,
            replay_highest_accepted: checkpoint.replay_highest_accepted,
        }
    }
}

/// Rebuild a validated install from decoded wire fields and the secret tail.
pub(crate) fn install_from_wire(
    sa: WireSaId,
    epoch: u64,
    format: u64,
    send_iv_next: u64,
    replay_highest_accepted: u64,
    secret: Zeroizing<Vec<u8>>,
) -> Result<SaMirrorInstall, SaMirrorError> {
    let install = SaMirrorInstall {
        sa: sa.into(),
        epoch: KeyEpoch::new(epoch)?,
        keymat: MirroredSaKeymat::new(KeymatFormat::new(format)?, secret)?,
        send_iv_next,
        replay_highest_accepted,
    };
    install.validate()?;
    Ok(install)
}

fn frame_len(label: &'static str, len: usize, max_frame_size: usize) -> Result<u32, SaMirrorError> {
    if len > max_frame_size {
        return Err(SaMirrorError::FrameTooLarge(len));
    }
    u32::try_from(len).map_err(|_| SaMirrorError::protocol(label))
}

/// Write one frame: JSON header plus raw secret tail.
///
/// The assembled frame buffer is zeroized after the write because it may
/// contain key bytes.
pub(crate) async fn write_frame<W, T>(
    writer: &mut W,
    header: &T,
    secret: &[u8],
    max_frame_size: usize,
) -> Result<(), SaMirrorError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let header_json = serde_json::to_vec(header)
        .map_err(|_| SaMirrorError::protocol("frame header encode failed"))?;
    let header_len = frame_len(
        "frame header length overflow",
        header_json.len(),
        max_frame_size,
    )?;
    let secret_len = frame_len("frame secret length overflow", secret.len(), max_frame_size)?;

    let mut frame = Zeroizing::new(Vec::with_capacity(8 + header_json.len() + secret.len()));
    frame.extend_from_slice(&header_len.to_be_bytes());
    frame.extend_from_slice(&header_json);
    frame.extend_from_slice(&secret_len.to_be_bytes());
    frame.extend_from_slice(secret);

    writer
        .write_all(&frame)
        .await
        .map_err(|error| SaMirrorError::io("frame_write", error))?;
    writer
        .flush()
        .await
        .map_err(|error| SaMirrorError::io("frame_write", error))
}

/// Read one frame; the secret tail lands directly in a zeroizing buffer.
pub(crate) async fn read_frame<R, T>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<(T, Zeroizing<Vec<u8>>), SaMirrorError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let header_len = read_len(reader, max_frame_size).await?;
    let mut header_buf = vec![0_u8; header_len];
    reader
        .read_exact(&mut header_buf)
        .await
        .map_err(|error| SaMirrorError::io("frame_read", error))?;
    let header = serde_json::from_slice(&header_buf)
        .map_err(|_| SaMirrorError::protocol("frame header decode failed"))?;

    let secret_len = read_len(reader, max_frame_size).await?;
    let mut secret = Zeroizing::new(vec![0_u8; secret_len]);
    reader
        .read_exact(&mut secret)
        .await
        .map_err(|error| SaMirrorError::io("frame_read", error))?;
    Ok((header, secret))
}

async fn read_len<R>(reader: &mut R, max_frame_size: usize) -> Result<usize, SaMirrorError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(|error| SaMirrorError::io("frame_read", error))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > max_frame_size {
        return Err(SaMirrorError::FrameTooLarge(len));
    }
    Ok(len)
}

/// Read a frame, failing with a timed-out I/O error when the whole frame does
/// not arrive within `timeout`.
///
/// Servers must use this on accepted connections so a peer that connects and
/// stalls is reaped instead of holding its connection slot (slowloris-style
/// exhaustion), matching the session-replication server discipline.
pub(crate) async fn read_frame_within<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: std::time::Duration,
) -> Result<(T, Zeroizing<Vec<u8>>), SaMirrorError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    match tokio::time::timeout(timeout, read_frame(reader, max_frame_size)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(SaMirrorError::Io {
            operation: "frame_read",
            kind: std::io::ErrorKind::TimedOut,
            raw_os_error: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_headers_and_secret_tails() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let header = MirrorRequest::Install {
            sa: WireSaId::Esp { spi: 7 },
            epoch: 3,
            format: 1,
            send_iv_next: 100,
            replay_highest_accepted: 20,
        };
        write_frame(
            &mut client,
            &header,
            b"keymat-bytes",
            DEFAULT_MAX_FRAME_SIZE,
        )
        .await
        .unwrap();

        let (decoded, secret): (MirrorRequest, _) = read_frame(&mut server, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        assert_eq!(decoded, header);
        assert_eq!(&secret[..], b"keymat-bytes");

        let response = MirrorResponse::Rejected {
            code: "stale_epoch".into(),
        };
        write_frame(&mut server, &response, &[], DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();
        let (decoded, secret): (MirrorResponse, _) =
            read_frame(&mut client, DEFAULT_MAX_FRAME_SIZE)
                .await
                .unwrap();
        assert_eq!(decoded, response);
        assert!(secret.is_empty());
    }

    #[tokio::test]
    async fn oversized_frames_fail_closed_in_both_directions() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        assert!(matches!(
            write_frame(&mut client, &MirrorResponse::Accepted, &[0_u8; 128], 64).await,
            Err(SaMirrorError::FrameTooLarge(128))
        ));

        // An announced oversized header is rejected before allocation.
        client
            .write_all(&1_000_000_u32.to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame::<_, MirrorResponse>(&mut server, 64).await,
            Err(SaMirrorError::FrameTooLarge(1_000_000))
        ));
    }

    #[tokio::test]
    async fn stalled_peer_reads_time_out() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let result = read_frame_within::<_, MirrorRequest>(
            &mut server,
            DEFAULT_MAX_FRAME_SIZE,
            std::time::Duration::from_millis(20),
        )
        .await;
        assert!(matches!(
            result,
            Err(SaMirrorError::Io {
                operation: "frame_read",
                kind: std::io::ErrorKind::TimedOut,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn malformed_headers_are_a_static_protocol_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&4_u32.to_be_bytes()).await.unwrap();
        client.write_all(b"!!!!").await.unwrap();
        client.write_all(&0_u32.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_frame::<_, MirrorRequest>(&mut server, DEFAULT_MAX_FRAME_SIZE).await,
            Err(SaMirrorError::Protocol { .. })
        ));
    }

    #[test]
    fn install_from_wire_rebuilds_and_validates() {
        let install = install_from_wire(
            WireSaId::Esp { spi: 7 },
            2,
            1,
            10,
            0,
            Zeroizing::new(vec![0xAA; 32]),
        )
        .unwrap();
        assert_eq!(install.sa, SaId::Esp { spi: 7 });
        assert_eq!(install.epoch.get(), 2);
        assert_eq!(install.keymat.expose_secret_bytes(), &[0xAA; 32]);

        for (epoch, format, send_iv_next, secret) in [
            (0, 1, 10, vec![1_u8]),       // zero epoch
            (2, 0, 10, vec![1_u8]),       // zero format
            (2, 1, 0, vec![1_u8]),        // ESP zero sequence
            (2, 1, 10, Vec::<u8>::new()), // empty keymat
        ] {
            assert!(install_from_wire(
                WireSaId::Esp { spi: 7 },
                epoch,
                format,
                send_iv_next,
                0,
                Zeroizing::new(secret),
            )
            .is_err());
        }
    }
}
