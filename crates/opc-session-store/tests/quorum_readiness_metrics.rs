use std::sync::{atomic::Ordering, Arc};

use opc_redaction::metrics::{export_prometheus_text, METRICS};
use opc_session_store::{FakeSessionBackend, SessionStoreBackend};

mod support;

#[tokio::test]
async fn real_readiness_probe_updates_fixed_cardinality_metrics() {
    METRICS.reset_all();
    let members = (0..3)
        .map(|index| {
            let backend: Arc<dyn SessionStoreBackend> = Arc::new(FakeSessionBackend::new());
            support::member(index, backend)
        })
        .collect();
    let store = support::validated_ha(members);

    assert!(store.probe_durable_readiness().await.is_ready());
    assert_eq!(
        METRICS
            .session_durable_readiness_probe_success
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        METRICS
            .session_durable_readiness_configured_voters
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(
        METRICS
            .session_durable_readiness_fresh_reachable_voters
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(
        METRICS
            .session_durable_readiness_agreeing_voters
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(
        METRICS
            .session_durable_readiness_required_quorum
            .load(Ordering::Relaxed),
        2
    );

    let exported = export_prometheus_text();
    assert!(exported
        .contains("opc_session_store_durable_readiness_probe_total{status=\"success\"} 1\n"));
    assert!(exported.contains("opc_session_store_durable_readiness_configured_voters 3\n"));
    assert!(exported.contains("opc_session_store_durable_readiness_agreeing_voters 3\n"));
    assert!(!exported.contains("test-replica-"));
    assert!(!exported.contains(".invalid"));
}
