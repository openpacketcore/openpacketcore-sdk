use super::*;
use crate::consensus::snapshot_io::SnapshotIo;
use std::fs::File;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

// Exercise the file operations used by repair independently of scheduling,
// SQLite and quorum work. Both adapters run the same real envelope verifier,
// 128 KiB source/receiver chunks, 1 MiB extraction and 8 KiB promotion copy.
// The Tokio case is also a native syscall reference for the pinned adapter.
async fn repair_file_operations<T>(wrap: impl Fn(File) -> T, count: Option<fn(&T) -> usize>)
where
    T: AsyncRead + AsyncSeek + AsyncWrite + Unpin,
{
    let check_count = |file: &T, expected| {
        if let Some(count) = count {
            assert_eq!(count(file), expected);
        }
    };
    let payload = vec![0x59; 1024 * 1024 - SNAPSHOT_FOOTER_BYTES as usize];
    let checksum: [u8; 32] = Sha256::digest(&payload).into();
    let mut envelope = payload.clone();
    envelope.extend_from_slice(SNAPSHOT_FOOTER_MAGIC);
    envelope
        .extend_from_slice(&super::super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION.to_be_bytes());
    envelope.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&checksum);
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), &envelope).unwrap();
    let received = tempfile::NamedTempFile::new().unwrap();
    let mut receiver = wrap(received.reopen().unwrap());
    let verified = (payload.len() as u64, checksum, envelope.len() as u64);
    let mut offset = 0;
    while offset < envelope.len() as u64 {
        let mut reader = wrap(File::open(source.path()).unwrap());
        assert_eq!(verify_snapshot_reader(&mut reader).await.unwrap(), verified);
        let length = reader.seek(io::SeekFrom::End(0)).await.unwrap();
        reader.seek(io::SeekFrom::Start(offset)).await.unwrap();
        let mut chunk = vec![0; (length - offset).min(128 * 1024) as usize];
        reader.read_exact(&mut chunk).await.unwrap();
        check_count(&reader, 6);
        receiver.seek(io::SeekFrom::Start(offset)).await.unwrap();
        receiver.write_all(&chunk).await.unwrap();
        offset += chunk.len() as u64;
    }
    receiver.flush().await.unwrap();
    check_count(&receiver, 8);
    assert_eq!(std::fs::read(received.path()).unwrap(), envelope);
    drop(receiver);

    let mut verification = wrap(File::open(received.path()).unwrap());
    assert_eq!(
        verify_snapshot_reader(&mut verification).await.unwrap(),
        verified
    );
    check_count(&verification, 4);
    let mut extraction = wrap(File::open(received.path()).unwrap());
    let mut database = wrap(tempfile::tempfile().unwrap());
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = payload.len();
    while remaining > 0 {
        let requested = remaining.min(buffer.len());
        let read = extraction.read(&mut buffer[..requested]).await.unwrap();
        assert_ne!(read, 0);
        database.write_all(&buffer[..read]).await.unwrap();
        remaining -= read;
    }
    database.flush().await.unwrap();
    check_count(&extraction, 0);
    check_count(&database, 0);

    let mut promotion = wrap(File::open(received.path()).unwrap());
    let promoted = tempfile::NamedTempFile::new().unwrap();
    let mut destination = wrap(promoted.reopen().unwrap());
    assert_eq!(
        tokio::io::copy(&mut promotion, &mut destination)
            .await
            .unwrap(),
        envelope.len() as u64
    );
    destination.flush().await.unwrap();
    check_count(&promotion, 0);
    check_count(&destination, 0);
    assert_eq!(std::fs::read(promoted.path()).unwrap(), envelope);
}

#[tokio::test]
async fn repair_file_io_only_positions_for_explicit_seeks() {
    repair_file_operations(
        |file| SnapshotIo::new(file, None),
        Some(SnapshotIo::positioning_calls),
    )
    .await;
}

#[tokio::test]
async fn repair_file_io_with_tokio_file_reference() {
    repair_file_operations(tokio::fs::File::from_std, None).await;
}
