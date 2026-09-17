//! Readiness publication for the XFRM process-recovery test harnesses.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

struct StagedFile(Option<PathBuf>);

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn publish(path: &Path, bytes: &[u8]) -> io::Result<()> {
    publish_with_hook(path, bytes, || Ok(()))
}

pub fn publish_with_hook(
    path: &Path,
    bytes: &[u8],
    before_publication: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("readiness path has no parent"))?;
    let mut name = path
        .file_name()
        .ok_or_else(|| io::Error::other("readiness path has no file name"))?
        .to_os_string();
    name.push(".pending");
    let staged_path = parent.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged_path)?;
    // Own cleanup only after create_new succeeds; a competing publisher's
    // staging file must survive our failed attempt.
    let mut staged = StagedFile(Some(staged_path));
    file.write_all(bytes)?;
    file.sync_all()?;
    before_publication()?;
    // Linking publishes a complete inode atomically and, unlike rename,
    // preserves create_new's refusal to replace any existing final name.
    fs::hard_link(staged.0.as_ref().expect("owned staging path"), path)?;
    // Disarm before unlink: another publisher may acquire the staging name
    // immediately afterward, and our guard must never unlink its new file.
    let staged_path = staged.0.take().expect("owned staging path");
    fs::remove_file(staged_path)?;
    File::open(parent)?.sync_all()
}
