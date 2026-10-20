use super::main_file_identity;
use rusqlite::Connection;
use std::os::unix::fs::MetadataExt as _;

#[test]
fn main_file_identity_accepts_sparse_files_larger_than_i32_max() {
    // Keep this original descriptor alive until after SQLite closes: even a
    // fixture's independent close would release SQLite's process-owned locks.
    let file = tempfile::NamedTempFile::new().expect("create database file");
    let connection = Connection::open(file.path()).expect("open SQLite database");
    connection
        .execute_batch("CREATE TABLE sentinel(value INTEGER); INSERT INTO sentinel VALUES (42)")
        .expect("initialize SQLite database");
    let size = (i32::MAX as u64) + 1 + 4096;
    file.as_file()
        .set_len(size)
        .expect("extend sparse database");
    let metadata = file.as_file().metadata().expect("full-width file metadata");
    assert_eq!(metadata.len(), size);
    let value: i64 = connection
        .query_row("SELECT value FROM sentinel", [], |row| row.get(0))
        .expect("SQLite can read a file beyond the narrow stat size limit");
    assert_eq!(value, 42);

    // On the supported i686 GNU target, establish that this real fixture
    // cannot be represented by the narrow libc ABI that caused the regression.
    #[cfg(all(target_arch = "x86", target_env = "gnu"))]
    {
        use std::os::fd::AsRawFd as _;
        if std::mem::size_of::<libc::off_t>() == 4 {
            let mut narrow = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat borrows the live file and receives writable storage
            // for its complete ABI structure. No uninitialized fields are read.
            let result = unsafe { libc::fstat(file.as_file().as_raw_fd(), narrow.as_mut_ptr()) };
            let error = std::io::Error::last_os_error();
            assert_eq!(result, -1, "the fixture must exceed the narrow stat ABI");
            assert_eq!(error.raw_os_error(), Some(libc::EOVERFLOW));
        }
    }

    let expected = (metadata.dev(), metadata.ino());
    assert_eq!(main_file_identity(&connection), Ok(expected));
    assert_eq!(
        connection
            .query_row("SELECT value FROM sentinel", [], |row| row.get::<_, i64>(0))
            .expect("the borrowed identity lookup leaves SQLite usable"),
        42
    );
}
