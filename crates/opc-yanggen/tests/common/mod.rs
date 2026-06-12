//! Shared helpers for tests that compile generated code in scratch projects.

use std::fs;
use std::path::Path;

/// Read the exact version of `krate` from the workspace `Cargo.lock`.
///
/// Scratch projects resolve dependencies fresh (they have no lockfile), which
/// makes them hostage to upstream releases: a transitive crate published
/// after the workspace lockfile can fail to build in the scratch while the
/// workspace itself is green. Pinning floating transitive dependencies to the
/// locked versions keeps both resolutions identical.
pub fn locked_version(workspace_dir: &Path, krate: &str) -> String {
    let lock = fs::read_to_string(workspace_dir.join("Cargo.lock")).unwrap();
    let needle = format!("name = \"{krate}\"");
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() == needle {
            if let Some(version_line) = lines.next() {
                if let Some(v) = version_line
                    .trim()
                    .strip_prefix("version = \"")
                    .and_then(|v| v.strip_suffix('"'))
                {
                    return v.to_string();
                }
            }
        }
    }
    panic!("{krate} not found in workspace Cargo.lock");
}
