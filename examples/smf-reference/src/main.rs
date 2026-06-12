//! Reference SMF binary entry point.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use smf_reference::Smf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config = smf_reference::SmfConfig::default_ref()?;
    let smf = Smf::start(config).await?;

    tracing::info!("reference SMF running; press Ctrl-C to stop");

    // Wait for SIGINT/SIGTERM through the runtime's signal handlers.
    smf.shutdown().await;

    Ok(())
}
