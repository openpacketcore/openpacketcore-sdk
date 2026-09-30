//! Original TLS receipts at the native/transport checkpoint, with final drains.
//!
//! Connection TLS, frozen material, split containers and nested socket/runtime
//! allocations remain separate. This does not include native crypto, kernel
//! buffers, preexisting providers or arbitrary caller application objects.

use std::sync::{atomic::Ordering, Arc};

use opc_session_net::consensus::capacity_observation::{
    ConsensusBufferObservation, InboundSocketPhase, NativeTransportOverlap, OutboundSocketPhase,
    TlsAllocationObserver, TlsAllocationPhase, TlsAllocationSource, TlsEndpoint,
};

// Fixed metadata tables. This bounds observation storage, not product memory.
// Sources never recycle after closure, across all original shutdown/reopen phases.
const OWNER_LIMIT: usize = 2048;
const RECEIPT_LIMIT: usize = 65_536;
const RECEIPT_BUCKETS: usize = 16_384;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../opc-session-net/tests/support/tls_receipts.rs"
));

pub(super) struct Census(Arc<Observation>);

impl Census {
    pub(super) fn new(transport: &Arc<ConsensusBufferObservation>) -> Arc<Self> {
        let receipts = Observation::new();
        receipts.attach(transport);
        Arc::new(Self(receipts))
    }

    pub(super) fn snapshot(&self) -> Checkpoint {
        Checkpoint(self.0.snapshot())
    }

    pub(super) async fn wait_for_drain(&self) {
        self.0.wait_for_drain().await;
    }
}

pub(super) struct Checkpoint(Snapshot);

#[derive(Debug)]
struct Totals {
    connection: Extent,
    material: Extent,
    split: Extent,
    runtime: Extent,
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsCheckpoint")
            .field("sources", &self.0.owners.len())
            .field("flags", &self.0.flags)
            .field("totals", &self.totals())
            .finish()
    }
}

impl Checkpoint {
    fn totals(&self) -> Totals {
        Totals {
            connection: sum_extents(connection_rows(&self.0).map(|owner| &owner.tls)),
            material: sum_extents(material_rows(&self.0).map(|owner| &owner.tls)),
            split: sum_extents(self.0.owners.iter().map(|owner| &owner.owner_storage)),
            runtime: sum_extents(self.0.owners.iter().map(|owner| &owner.socket)),
        }
    }

    fn endpoint(&self, endpoint: TlsEndpoint) -> &OwnerSnapshot {
        let mut rows = connection_rows(&self.0)
            .filter(|owner| owner.row.source == Some(TlsAllocationSource::Connection(endpoint)));
        let owner = rows
            .next()
            .expect("CONFIG_CAPACITY_NINE_TLS_ENDPOINT_RED: original endpoint absent");
        assert!(
            rows.next().is_none(),
            "one original TLS source per endpoint"
        );
        assert!(
            owner.row.visible && !owner.row.closed,
            "CONFIG_CAPACITY_NINE_TLS_OWNER_RED"
        );
        let material = material_rows(&self.0)
            .find(|material| Some(material.row.id) == owner.row.material)
            .expect("CONFIG_CAPACITY_NINE_TLS_MATERIAL_RED: independent original material source");
        assert!(material.row.origins[TlsAllocationPhase::MaterialConstruct as usize].object > 0);
        owner
    }

    pub(super) fn verify(
        &self,
        transport: &NativeTransportOverlap,
        after_mutation: &Self,
        after_recovery: &Self,
    ) {
        // Assertions follow the real audited commit, snapshot, reopen and joins.
        // Negative controls must preserve that lifecycle before this marker.
        println!("CONFIG_CAPACITY_NINE_TLS_LIFECYCLE real_mtls=true native_transport_lock=true audited_commit=true snapshot=true original_reopen=true joined_shutdown=true full_memory_bound=false");
        assert_conserved(&self.0);
        assert_drained(&after_mutation.0);
        assert_drained(&after_recovery.0);
        for owner in &transport.inbound.owners {
            if matches!(
                owner.phase,
                InboundSocketPhase::Bootstrap | InboundSocketPhase::Negotiated
            ) {
                self.endpoint(TlsEndpoint::Inbound(owner.socket_id));
            }
        }
        for owner in &transport.outbound.sockets {
            if matches!(
                owner.phase,
                OutboundSocketPhase::Bootstrap
                    | OutboundSocketPhase::Returned
                    | OutboundSocketPhase::Ready
                    | OutboundSocketPhase::Claimed
                    | OutboundSocketPhase::Active
                    | OutboundSocketPhase::Cached
            ) {
                self.endpoint(TlsEndpoint::Outbound(owner.socket_id));
            }
        }
        for target in [transport.pair.append_target, transport.pair.snapshot_target] {
            let selected: Vec<_> = transport
                .outbound
                .sockets
                .iter()
                .filter(|owner| {
                    owner.source == transport.pair.source
                        && owner.target == target
                        && owner.phase == OutboundSocketPhase::Active
                })
                .collect();
            assert!(
                !selected.is_empty(),
                "CONFIG_CAPACITY_NINE_TLS_SELECTED_RED"
            );
            for endpoint in selected {
                let owner = self.endpoint(TlsEndpoint::Outbound(endpoint.socket_id));
                assert!(owner.tls.object > 0 && owner.owner_storage.object > 0,
                    "CONFIG_CAPACITY_NINE_TLS_STORAGE_RED: actual selected stream and split storage");
            }
        }
        let totals = self.totals();
        assert!(
            totals.connection.object > 0 && totals.material.object > 0 && totals.split.object > 0,
            "CONFIG_CAPACITY_NINE_TLS_TOTALS_RED"
        );
        assert!(totals.runtime.wrapped >= totals.runtime.object);
        println!("CONFIG_CAPACITY_NINE_TLS_CHECKPOINT sources={} connections={} materials={} connection_object={} connection_wrapped={} material_object={} material_wrapped={} split_object={} split_wrapped={} socket_runtime_object={} socket_runtime_wrapped={} pointer_reuse_tails={} fixed_ledger_bytes={} token_storage_bytes={} snapshot_vector_bytes={} all_scoped_nodes=9 full_memory_bound=false",
            self.0.owners.len(), connection_rows(&self.0).count(), material_rows(&self.0).count(),
            totals.connection.object, totals.connection.wrapped, totals.material.object, totals.material.wrapped,
            totals.split.object, totals.split.wrapped, totals.runtime.object, totals.runtime.wrapped,
            self.0.pointer_reuse_tails, std::mem::size_of_val(&LEDGER), std::mem::size_of::<Observation>(),
            self.0.owners.capacity() * std::mem::size_of::<OwnerSnapshot>());
    }
}
