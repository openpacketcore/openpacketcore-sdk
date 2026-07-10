use crate::{ActionIdempotency, EffectClass, OperationPlan, SchemaPath};

/// Config/state classification of a data node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataNodeAccess {
    /// Configuration (`config true`) node.
    Configuration,
    /// Operational (`config false`) node.
    Operational,
}

/// Server-side allowlist contract for one typed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionContract {
    effect: EffectClass,
    idempotency: ActionIdempotency,
}

impl ActionContract {
    /// Constructs a probe/operate allowlist contract.
    #[must_use]
    pub const fn new(effect: EffectClass, idempotency: ActionIdempotency) -> Self {
        Self {
            effect,
            idempotency,
        }
    }

    /// Allowed effect.
    pub const fn effect(self) -> EffectClass {
        self.effect
    }

    /// Server deduplication contract.
    pub const fn idempotency(self) -> ActionIdempotency {
        self.idempotency
    }
}

/// Schema/action port used while freezing a catalog.
///
/// Implementations are adapters over generated CNF schema metadata and the
/// independently configured server action allowlist.
pub trait CommandSchema: Send + Sync {
    /// Returns config/state classification for a known data node.
    fn data_node_access(&self, path: &SchemaPath) -> Option<DataNodeAccess>;

    /// Returns the server-side contract for an allowlisted action.
    fn action_contract(&self, path: &SchemaPath) -> Option<ActionContract>;

    /// Whether a presentation field exists in this operation's typed result.
    fn result_field_exists(&self, operation: &OperationPlan, field: &SchemaPath) -> bool;
}
