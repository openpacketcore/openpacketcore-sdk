use std::time::Duration;

use crate::{ModelError, SchemaPath};

/// Operator-visible effect class.
///
/// There is intentionally no configuration-mutation variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    /// Bounded state/config read.
    Observe,
    /// Long-lived state subscription.
    Monitor,
    /// Bounded active diagnostic.
    Probe,
    /// Explicit runtime/session mutation.
    Operate,
}

/// Logical datastore/source selected for a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSource {
    /// Operational state only.
    Operational,
    /// Running configuration, read-only.
    RunningConfig,
    /// Both config and state when the transport supports it.
    All,
}

/// One bounded read plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    source: ReadSource,
    paths: Vec<SchemaPath>,
}

impl ReadPlan {
    /// Constructs a read plan. Freeze rejects an empty or oversized path set.
    #[must_use]
    pub fn new(source: ReadSource, paths: impl IntoIterator<Item = SchemaPath>) -> Self {
        Self {
            source,
            paths: paths.into_iter().collect(),
        }
    }

    /// Selected logical source.
    pub const fn source(&self) -> ReadSource {
        self.source
    }

    /// Static schema paths.
    pub fn paths(&self) -> &[SchemaPath] {
        &self.paths
    }
}

/// One operational-state subscription plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribePlan {
    paths: Vec<SchemaPath>,
}

impl SubscribePlan {
    /// Constructs a state subscription. Freeze rejects empty/oversized sets.
    #[must_use]
    pub fn new(paths: impl IntoIterator<Item = SchemaPath>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

    /// Static state schema paths.
    pub fn paths(&self) -> &[SchemaPath] {
        &self.paths
    }
}

/// A bounded set of independent read plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeReadPlan {
    reads: Vec<ReadPlan>,
    allow_partial: bool,
}

impl CompositeReadPlan {
    /// Constructs a composite read.
    #[must_use]
    pub fn new(reads: impl IntoIterator<Item = ReadPlan>, allow_partial: bool) -> Self {
        Self {
            reads: reads.into_iter().collect(),
            allow_partial,
        }
    }

    /// Constituent reads.
    pub fn reads(&self) -> &[ReadPlan] {
        &self.reads
    }

    /// Whether schema-safe partial results are permitted.
    pub const fn allow_partial(&self) -> bool {
        self.allow_partial
    }
}

/// Retry contract for a typed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionIdempotency {
    /// Never retry after possible dispatch.
    NonIdempotent,
    /// Target deduplicates a protocol-independent idempotency key.
    TargetDeduplicated,
}

/// One allowlisted typed action invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPlan {
    path: SchemaPath,
    idempotency: ActionIdempotency,
}

impl ActionPlan {
    /// Constructs an action reference.
    #[must_use]
    pub fn new(path: SchemaPath, idempotency: ActionIdempotency) -> Self {
        Self { path, idempotency }
    }

    /// Static modeled action path.
    pub fn path(&self) -> &SchemaPath {
        &self.path
    }

    /// Retry/deduplication contract.
    pub const fn idempotency(&self) -> ActionIdempotency {
        self.idempotency
    }
}

/// Transport-neutral execution primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationPlan {
    /// One read.
    Get(ReadPlan),
    /// One state subscription.
    Subscribe(SubscribePlan),
    /// One typed allowlisted action.
    Invoke(ActionPlan),
    /// Bounded independent reads combined for presentation.
    Composite(CompositeReadPlan),
}

/// Per-command execution bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    deadline: Duration,
    max_output_bytes: usize,
    max_items: usize,
}

impl ExecutionLimits {
    /// Constructs explicit non-zero execution bounds.
    pub const fn new(
        deadline: Duration,
        max_output_bytes: usize,
        max_items: usize,
    ) -> Result<Self, ModelError> {
        if deadline.is_zero() {
            return Err(ModelError::Zero {
                field: "execution_deadline",
            });
        }
        if max_output_bytes == 0 {
            return Err(ModelError::Zero {
                field: "max_output_bytes",
            });
        }
        if max_items == 0 {
            return Err(ModelError::Zero { field: "max_items" });
        }
        Ok(Self {
            deadline,
            max_output_bytes,
            max_items,
        })
    }

    /// Request deadline.
    pub const fn deadline(self) -> Duration {
        self.deadline
    }

    /// Maximum encoded result bytes.
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    /// Maximum rows/events/items.
    pub const fn max_items(self) -> usize {
        self.max_items
    }
}
