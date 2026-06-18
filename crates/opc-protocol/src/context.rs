use crate::error::{EncodeError, EncodeErrorCode};

/// Protocol version selector for decode/encode behavior.
///
/// Protocol crates SHOULD define a `const` for each supported major version
/// and gate feature behavior on `protocol_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProtocolVersion(pub u8);

impl ProtocolVersion {
    /// Create a new protocol version identifier.
    pub const fn new(major: u8) -> Self {
        Self(major)
    }

    /// Major version number.
    pub const fn major(self) -> u8 {
        self.0
    }
}

/// Validation strictness level.
///
/// Data-plane fast paths SHOULD use the minimum level needed for safe routing
/// and leave expensive semantic validation to control-plane paths where
/// appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ValidationLevel {
    /// Parse enough for routing decisions only (allocation-free fast path).
    HeaderOnly,
    /// Verify lengths and container structure.
    #[default]
    Structural,
    /// Enforce field cardinality, enum ranges, and critical IE rules.
    Strict,
    /// Invoke NF-specific semantic validators.
    ProcedureAware,
}

/// Policy for encountering unknown Information Elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UnknownIePolicy {
    /// Silently ignore and drop unknown IEs.
    Drop,
    /// Preserve unknown IEs for forwarding or round-trip.
    #[default]
    Preserve,
    /// Reject messages containing unknown IEs.
    Reject,
}

/// Policy for duplicate Information Elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DuplicateIePolicy {
    /// Use the first occurrence.
    First,
    /// Use the last occurrence.
    #[default]
    Last,
    /// Reject messages containing duplicate IEs.
    Reject,
}

/// Per-decode security limits and conformance controls.
///
/// Protocol crates MUST define safe defaults and expose these limits through
/// profile configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecodeContext {
    /// Protocol version to assume when version fields are absent or ambiguous.
    pub protocol_version: ProtocolVersion,
    /// Maximum nesting depth for container IEs.
    pub max_depth: usize,
    /// Maximum number of IEs in a single message.
    pub max_ies: usize,
    /// Maximum byte length of a single message.
    pub max_message_len: usize,
    /// How to handle unknown IEs.
    pub unknown_ie_policy: UnknownIePolicy,
    /// How to handle duplicate IEs.
    pub duplicate_ie_policy: DuplicateIePolicy,
    /// How strictly to validate fields and containers.
    pub validation_level: ValidationLevel,
    /// Allocation budget for fast-path decode operations.
    pub allocation_budget: AllocationBudget,
}

impl DecodeContext {
    /// Conservative defaults suitable for untrusted network input.
    pub const fn conservative() -> Self {
        Self {
            protocol_version: ProtocolVersion::new(1),
            max_depth: 8,
            max_ies: 128,
            max_message_len: 8192,
            unknown_ie_policy: UnknownIePolicy::Reject,
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            validation_level: ValidationLevel::Strict,
            allocation_budget: AllocationBudget::FAST_PATH,
        }
    }
}

impl Default for DecodeContext {
    fn default() -> Self {
        Self {
            protocol_version: ProtocolVersion::new(1),
            max_depth: 16,
            max_ies: 256,
            max_message_len: 65535,
            unknown_ie_policy: UnknownIePolicy::default(),
            duplicate_ie_policy: DuplicateIePolicy::default(),
            validation_level: ValidationLevel::default(),
            allocation_budget: AllocationBudget::default(),
        }
    }
}

/// Per-encode configuration.
///
/// Encoders MUST fail before writing if required capacity exceeds the
/// configured `max_message_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncodeContext {
    /// Protocol version to emit.
    pub protocol_version: ProtocolVersion,
    /// When `true`, retain original padding, unknown IEs, and field ordering.
    /// When `false` (the default), produce canonical output.
    pub raw_preserving: bool,
    /// Maximum byte length of a single encoded message.
    pub max_message_len: usize,
}

impl Default for EncodeContext {
    fn default() -> Self {
        Self {
            protocol_version: ProtocolVersion::new(1),
            raw_preserving: false,
            max_message_len: 65535,
        }
    }
}

impl EncodeContext {
    /// Verify that `required` bytes fit within [`Self::max_message_len`].
    ///
    /// Returns `CapacityExceeded` when `required > max_message_len`,
    /// making the "fail before writing" contract a one-liner for implementers.
    pub const fn check_capacity(&self, required: usize) -> Result<(), EncodeError> {
        if required > self.max_message_len {
            Err(EncodeError::new(EncodeErrorCode::CapacityExceeded {
                required,
                available: self.max_message_len,
            }))
        } else {
            Ok(())
        }
    }
}

/// Allocation budget for protocol operations.
///
/// Fast-path targets from RFC 005:
/// - Fixed header decode: 0 heap allocations.
/// - Routing-key partial decode: 0 heap allocations.
/// - Full message decode: protocol-specific, bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationBudget {
    /// Target heap allocations for the fast-path decoder.
    pub decode_heap_allocations_fast_path: usize,
    /// Maximum temporary scratch bytes the decoder may allocate.
    pub decode_max_temporary_bytes: usize,
    /// Maximum temporary scratch bytes the encoder may allocate.
    pub encode_max_temporary_bytes: usize,
}

impl AllocationBudget {
    /// Zero-allocation fast-path budget.
    pub const FAST_PATH: Self = Self {
        decode_heap_allocations_fast_path: 0,
        decode_max_temporary_bytes: 1024,
        encode_max_temporary_bytes: 1024,
    };
}

impl Default for AllocationBudget {
    fn default() -> Self {
        Self::FAST_PATH
    }
}
