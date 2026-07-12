#![cfg(feature = "insecure-test")]
#![cfg(feature = "legacy-session-net-compat")]

//! Smoke test that the test-only plaintext `RemoteSessionBackend` slots into
//! the `SessionStore` facade.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use opc_session_net::RemoteSessionBackend;
use opc_session_store::{SessionBackend, SessionStore};

#[tokio::test]
async fn remote_backend_slots_into_session_store() {
    let remote = RemoteSessionBackend::new_insecure(
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 1)),
        Some(Duration::from_millis(1)),
    );
    let store = SessionStore::new(remote);
    // Without a server the capability probe times out and falls back to minimal.
    let caps = store.capabilities().await;
    assert!(!caps.atomic_compare_and_set);
}
