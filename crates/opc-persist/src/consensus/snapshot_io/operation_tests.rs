use super::*;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

fn input_file(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut file, bytes).unwrap();
    std::io::Seek::rewind(&mut file).unwrap();
    file
}

fn positioning_calls(file: &SnapshotIo) -> usize {
    file.handle.file.lock().unwrap().positioning_calls
}

async fn sequential_copy<T>(wrap: impl Fn(File) -> T) -> (T, T)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // The promotion path uses this same 8 KiB tokio::io::copy loop.
    let bytes = vec![0x59; 1024 * 1024];
    let raw_output = tempfile::tempfile().unwrap();
    let mut observed = raw_output.try_clone().unwrap();
    let mut source = wrap(input_file(&bytes));
    let mut destination = wrap(raw_output);
    assert_eq!(
        tokio::io::copy(&mut source, &mut destination)
            .await
            .unwrap(),
        bytes.len() as u64
    );
    destination.flush().await.unwrap();
    std::io::Seek::rewind(&mut observed).unwrap();
    let mut copied = Vec::new();
    std::io::Read::read_to_end(&mut observed, &mut copied).unwrap();
    assert_eq!(copied, bytes);
    (source, destination)
}

#[tokio::test]
async fn sequential_copy_does_not_position_either_file() {
    let (source, destination) = sequential_copy(|file| SnapshotIo::new(file, None)).await;
    assert_eq!(
        (positioning_calls(&source), positioning_calls(&destination)),
        (0, 0),
        "sequential promotion must not seek for each copy buffer or EOF"
    );
}

#[tokio::test]
async fn sequential_copy_with_tokio_file_reference() {
    let _ = sequential_copy(tokio::fs::File::from_std).await;
}

#[tokio::test]
async fn explicit_seeks_position_once_each() {
    let mut file = SnapshotIo::new(input_file(b"abcdefghijklmnop"), None);
    assert_eq!(file.seek(SeekFrom::Start(5)).await.unwrap(), 5);
    assert_eq!(file.seek(SeekFrom::Current(-2)).await.unwrap(), 3);
    assert_eq!(file.seek(SeekFrom::End(-1)).await.unwrap(), 15);
    assert_eq!(positioning_calls(&file), 3);
}

#[tokio::test]
async fn sequential_reads_reuse_initialized_storage() {
    let bytes = vec![0x59; 3 * 8192];
    let mut file = SnapshotIo::new(input_file(&bytes), None);
    let mut output = [0; 8192];
    file.read_exact(&mut output).await.unwrap();
    let buffer = file.read_buffer.as_ptr();
    let capacity = file.read_buffer.capacity();
    for _ in 0..2 {
        file.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [0x59; 8192]);
        assert_eq!(file.read_buffer.as_ptr(), buffer);
        assert_eq!(file.read_buffer.capacity(), capacity);
    }
}

#[tokio::test]
async fn writes_and_short_reads_reuse_initialized_storage() {
    let mut file = SnapshotIo::new(tempfile::tempfile().unwrap(), None);
    let bytes = [0x59; 8192];
    file.write_all(&bytes).await.unwrap();
    file.flush().await.unwrap();
    assert!(file.read_buffer.capacity() >= bytes.len());
    let buffer = file.read_buffer.as_ptr();
    let capacity = file.read_buffer.capacity();
    for _ in 0..2 {
        file.write_all(&bytes).await.unwrap();
        file.flush().await.unwrap();
        assert_eq!(file.read_buffer.as_ptr(), buffer);
        assert_eq!(file.read_buffer.capacity(), capacity);
    }
    file.seek(SeekFrom::Start(0)).await.unwrap();
    let mut prefix = [0; 2];
    file.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, [0x59; 2]);
    assert_eq!(file.read_buffer.as_ptr(), buffer);
    assert_eq!(file.read_buffer.capacity(), capacity);
    assert!(file.read_buffer.len() >= bytes.len());
}

#[tokio::test]
async fn cancelled_read_only_repositions_when_discarding_unread_bytes() {
    let mut file = SnapshotIo::new(input_file(b"abcdefghij"), None);
    let handle = file.handle.clone();
    let mut output = [0; 8];
    let mut read = Box::pin(file.read(&mut output));
    std::future::poll_fn(|cx| {
        let _held = handle.file.lock().unwrap();
        assert!(read.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(read);
    let mut prefix = [0; 2];
    file.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"ab");
    assert_eq!(positioning_calls(&file), 0);
    file.write_all(b"XY").await.unwrap();
    file.write_all(b"ZW").await.unwrap();
    file.flush().await.unwrap();
    assert_eq!(positioning_calls(&file), 1);
    file.seek(SeekFrom::Start(0)).await.unwrap();
    let mut all = Vec::new();
    file.read_to_end(&mut all).await.unwrap();
    assert_eq!(all, b"abXYZWghij");
}

#[tokio::test]
async fn invalid_relative_seek_preserves_buffered_read_position() {
    let mut file = SnapshotIo::new(input_file(b"abcdefghij"), None);
    let handle = file.handle.clone();
    let mut output = [0; 8];
    let mut read = Box::pin(file.read(&mut output));
    std::future::poll_fn(|cx| {
        let _held = handle.file.lock().unwrap();
        assert!(read.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(read);
    let mut prefix = [0; 2];
    file.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"ab");
    assert_eq!(
        file.seek(SeekFrom::Current(-3)).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut rest = [0; 8];
    file.read_exact(&mut rest).await.unwrap();
    assert_eq!(&rest, b"cdefghij");
    assert_eq!(positioning_calls(&file), 0);
}

#[tokio::test]
async fn failed_write_returns_initialized_buffer_for_the_next_read() {
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(source.path(), [0x59; 16 * 1024]).unwrap();
    let mut file = SnapshotIo::new(File::open(source.path()).unwrap(), None);
    file.write_all(&[0; 8192]).await.unwrap();
    assert!(file.flush().await.is_err(), "descriptor is read-only");
    assert!(file.read_buffer.len() >= 8192);
    let buffer = file.read_buffer.as_ptr();
    let mut output = [0; 2];
    file.read_exact(&mut output).await.unwrap();
    assert_eq!(output, [0x59; 2]);
    assert_eq!(file.read_buffer.as_ptr(), buffer);
    assert_eq!(positioning_calls(&file), 1);
}
