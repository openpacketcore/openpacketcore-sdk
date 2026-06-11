//! Workspace contract smoke test.
//!
//! Validates that the workspace metadata resolves correctly and that every
//! declared workspace dependency compiles with its configured feature set.

use std::process::Command;

/// Verify `cargo metadata --locked` succeeds and names the expected member.
#[test]
fn cargo_metadata_locked_succeeds() {
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    // Walk up from the test crate manifest until we find Cargo.toml containing a
    // [workspace] section — this is the workspace root. skip(1) skips the crate's
    // own Cargo.toml (which is a package manifest, not a workspace). Unlike fixed-depth
    // .parent() chains, this is robust to the crate being nested at any depth inside
    // the workspace.
    let workspace_root = std::path::Path::new(manifest_dir)
        .ancestors()
        .skip(1)
        .find(|p| p.join("Cargo.toml").is_file())
        .expect("workspace root (Cargo.toml) not found — is the test inside a workspace?");

    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .expect("cargo metadata should spawn");

    assert!(
        output.status.success(),
        "cargo metadata --locked failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("opc-runtime"),
        "workspace metadata should contain opc-runtime member"
    );
}

/// Exercise serde with derive to prove the workspace feature set compiles.
#[test]
fn serde_derive_compiles() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct Smoke {
        id: u64,
        name: String,
    }

    let val = Smoke {
        id: 42,
        name: "opc".into(),
    };
    let json = serde_json::to_string(&val).expect("serialize");
    let round: Smoke = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(val, round);
}

/// Exercise thiserror to prove the workspace dependency compiles.
#[test]
fn thiserror_compiles() {
    #[derive(thiserror::Error, Debug)]
    #[error("smoke error: {0}")]
    struct SmokeError(&'static str);

    let err = SmokeError("test");
    assert_eq!(err.to_string(), "smoke error: test");
}

/// Exercise tokio runtime creation to prove the feature set is sufficient.
#[test]
fn tokio_runtime_compiles() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let out = rt.block_on(async { 42 });
    assert_eq!(out, 42);
}

/// Exercise tracing span creation to prove the dependency compiles.
#[test]
fn tracing_span_compiles() {
    let _span = tracing::info_span!("smoke_span").entered();
    tracing::info!(target: "smoke", "tracing is available");
}

/// Exercise uuid v4 + serde to prove the feature set compiles.
#[test]
fn uuid_v4_serde_compiles() {
    let id = uuid::Uuid::new_v4();
    let json = serde_json::to_string(&id).expect("serialize uuid");
    let round: uuid::Uuid = serde_json::from_str(&json).expect("deserialize uuid");
    assert_eq!(id, round);
}

/// Exercise time to prove the dependency compiles.
#[test]
fn time_compiles() {
    let now = time::OffsetDateTime::now_utc();
    // Stable property: now_utc() must be in UTC, not a local or fixed offset.
    assert_eq!(now.offset(), time::UtcOffset::UTC);
}

/// Exercise async-trait to prove the dependency compiles.
#[test]
fn async_trait_compiles() {
    use async_trait::async_trait;

    #[async_trait]
    trait SmokeTrait {
        async fn smoke(&self) -> u32;
    }

    struct Smoke;

    #[async_trait]
    impl SmokeTrait for Smoke {
        async fn smoke(&self) -> u32 {
            42
        }
    }

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let out = rt.block_on(async { Smoke.smoke().await });
    assert_eq!(out, 42);
}
