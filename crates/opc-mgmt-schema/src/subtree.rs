//! Bounded, schema-driven NETCONF subtree content comparisons.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::{LeafType, NodeKind, NodeMeta, NumericRangeIntervalMeta, SchemaRegistry};

mod admission_audit;
#[doc(hidden)]
pub use admission_audit::AdmissionAudit;
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub use admission_audit::{take_admission_observations, AdmissionObservation};

mod plan;
#[cfg(test)]
mod work_audit;
pub use plan::{
    merge_bounded, AuthorizedSubtreePlan, SubtreeAccessKind, SubtreeAccessObserver, SubtreeBranch,
    SubtreeMatch, SubtreeOutput, SubtreePlan, SubtreePredicate, SubtreeProjection, SubtreeScalar,
    SubtreeScope,
};

/// A fixed, payload-free subtree planning or evaluation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtreeError {
    /// A checked node, byte or work bound was exhausted.
    TooBig,
    /// Schema metadata describes an unsupported comparison or projection.
    Unsupported,
    /// A filter uses text on a structural node or otherwise invalid shape.
    Invalid,
    /// An authorized projection contains inconsistent schema or identity data.
    Projection,
}

impl std::fmt::Display for SubtreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooBig => "subtree read exceeds a limit",
            Self::Unsupported => "subtree read is not supported",
            Self::Invalid => "invalid subtree filter",
            Self::Projection => "subtree projection failed",
        })
    }
}

impl std::error::Error for SubtreeError {}

/// One checked work budget shared by parsing, planning and evaluation.
///
/// Clones share the remaining allowance. Charge visits and bytes before any
/// corresponding access, comparison, copy or index insertion. Diagnostics do
/// not expose the allowance or observed work.
#[derive(Clone)]
pub struct SubtreeBudget(Arc<SubtreeWork>);

struct SubtreeWork {
    remaining: AtomicUsize,
    predicate_trials: AtomicUsize,
    #[cfg(test)]
    observed: [AtomicUsize; 3],
}

impl std::fmt::Debug for SubtreeBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubtreeBudget")
    }
}

impl SubtreeBudget {
    /// Measures a single deduction before independently observed work begins.
    /// Only `testkit` and unit-test builds retain or enforce observations.
    #[doc(hidden)]
    #[inline]
    pub fn audit_admission(
        &self,
        phase: &'static str,
        charge: impl FnOnce() -> Result<(), SubtreeError>,
    ) -> Result<AdmissionAudit, SubtreeError> {
        AdmissionAudit::measure(self, phase, charge)
    }

    /// Remaining allowance for deterministic server-side work accounting.
    /// Never include this in a client error or predicate diagnostic.
    pub fn remaining(&self) -> usize {
        self.0.remaining.load(Ordering::Relaxed)
    }

    /// Predicate admissions, including prepaid trials skipped during evaluation.
    /// Never include this in a client error, audit event or metric label.
    pub fn predicate_trials(&self) -> usize {
        self.0.predicate_trials.load(Ordering::Relaxed)
    }

    fn begin_predicate_trial(&self) -> Result<(), SubtreeError> {
        let work = self.audit_admission("predicate trial", || self.charge(1))?;
        work.visit();
        self.record_predicate_trials(1);
        Ok(())
    }

    fn record_predicate_trials(&self, count: usize) {
        // Each trial consumes a unit from the finite, non-resettable budget,
        // individually or in a checked complete evaluation reservation. Unused
        // trial slots are not refunded, so this counter cannot expose a join.
        self.0.predicate_trials.fetch_add(count, Ordering::Relaxed);
    }

    /// Creates a positive budget and deducts work already performed by parsing.
    pub fn new(limit: usize, parsed_work: usize) -> Result<Self, SubtreeError> {
        if limit == 0 {
            return Err(SubtreeError::TooBig);
        }
        let remaining = limit.checked_sub(parsed_work).ok_or(SubtreeError::TooBig)?;
        Ok(Self(Arc::new(SubtreeWork {
            remaining: AtomicUsize::new(remaining),
            predicate_trials: AtomicUsize::new(0),
            #[cfg(test)]
            observed: std::array::from_fn(|_| AtomicUsize::new(0)),
        })))
    }

    /// Charges work before performing it, without wrapping or resetting.
    pub fn charge(&self, units: usize) -> Result<(), SubtreeError> {
        let mut remaining = self.0.remaining.load(Ordering::Relaxed);
        loop {
            let next = remaining.checked_sub(units).ok_or(SubtreeError::TooBig)?;
            match self.0.remaining.compare_exchange_weak(
                remaining,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => remaining = current,
            }
        }
    }

    /// Charges both inputs before a text comparison, including failed matches.
    pub fn compare(&self, left: &str, right: &str) -> Result<bool, SubtreeError> {
        let work = self.audit_admission("text comparison", || {
            self.charge(
                left.len()
                    .checked_add(right.len())
                    .ok_or(SubtreeError::TooBig)?,
            )
        })?;
        let result = work.text_cmp(left, right).is_eq();
        #[cfg(test)]
        self.audit_text_cmp(left, right);
        Ok(result)
    }

    /// Copies text only after charging every retained byte.
    pub fn copy(&self, text: &str) -> Result<String, SubtreeError> {
        let work = self.audit_admission("text copy", || self.charge(text.len()))?;
        self.audit_move(text.len());
        let copied = text.to_owned();
        work.moved(copied.len());
        Ok(copied)
    }

    /// Captures a masked key as a fixed-width identity, never as wire text.
    ///
    /// Only this request's projection retains the digest. Both config and state
    /// capture must use it for non-cleartext keys before any matching work.
    /// Hashing charges one fixed visit and the 64 retained hexadecimal bytes,
    /// independent of raw key length. This is not a constant-time guarantee.
    pub fn masked_identity(&self, value: &str) -> Result<String, SubtreeError> {
        let work = self.audit_admission("masked identity", || self.charge(65))?;
        work.visit();
        let digest = Sha256::digest(value.as_bytes());
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut identity = String::with_capacity(64);
        for byte in digest {
            identity.push(char::from(HEX[usize::from(byte >> 4)]));
            identity.push(char::from(HEX[usize::from(byte & 15)]));
        }
        work.moved(identity.len());
        Ok(identity)
    }

    /// Looks up an exact canonical schema path, charging every visited entry.
    /// Bare paths are deliberately not accepted at this already-resolved layer.
    pub fn node(
        &self,
        registry: &dyn SchemaRegistry,
        path: &str,
    ) -> Result<&'static NodeMeta, SubtreeError> {
        let nodes = registry.nodes();
        let mut lo = 0;
        let mut hi = nodes.len();
        while lo < hi {
            let visit = self.audit_admission("schema index visit", || self.charge(1))?;
            self.audit_visit(1);
            let middle = lo + (hi - lo) / 2;
            visit.visit();
            let node = &nodes[middle];
            let work = self.audit_admission("schema path comparison", || {
                self.charge(
                    path.len()
                        .checked_add(node.path.len())
                        .ok_or(SubtreeError::TooBig)?,
                )
            })?;
            #[cfg(test)]
            self.audit_text_cmp(node.path, path);
            match work.text_cmp(node.path, path) {
                std::cmp::Ordering::Equal => return Ok(node),
                std::cmp::Ordering::Less => lo = middle + 1,
                std::cmp::Ordering::Greater => hi = middle,
            }
        }
        Err(SubtreeError::Unsupported)
    }

    #[cfg(test)]
    pub(crate) fn audit_scope(&self, phase: &'static str) -> work_audit::Scope {
        work_audit::Scope::new(self, phase)
    }

    #[cfg(test)]
    fn audit_observed(&self) -> [usize; 3] {
        std::array::from_fn(|index| self.0.observed[index].load(Ordering::Relaxed))
    }

    #[cfg(test)]
    fn audit_add(&self, index: usize, units: usize) {
        let counter = &self.0.observed[index];
        let mut observed = counter.load(Ordering::Relaxed);
        loop {
            let next = observed.checked_add(units).expect("observed work overflow");
            match counter.compare_exchange_weak(
                observed,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
    }

    pub(crate) fn audit_visit(&self, _units: usize) {
        #[cfg(test)]
        self.audit_add(0, _units);
    }

    pub(crate) fn audit_move(&self, _units: usize) {
        #[cfg(test)]
        self.audit_add(2, _units);
    }

    #[cfg(test)]
    pub(crate) fn audit_text_cmp(&self, left: &str, right: &str) -> std::cmp::Ordering {
        for (left, right) in left.bytes().zip(right.bytes()) {
            self.audit_add(1, 1);
            let order = left.cmp(&right);
            if !order.is_eq() {
                return order;
            }
        }
        left.len().cmp(&right.len())
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ScalarValue {
    Boolean(bool),
    Integer(i128),
    Text(String),
    Never,
}

/// A type-checked predicate whose raw literal is never included in diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct ScalarPredicate {
    value: ScalarValue,
    kind: LeafType,
    ranges: &'static [NumericRangeIntervalMeta],
}

impl std::fmt::Debug for ScalarPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScalarPredicate(<redacted>)")
    }
}

impl ScalarPredicate {
    /// Compiles a scalar predicate using schema metadata alone.
    ///
    /// A masked or unclassified source leaf is refused for every caller before
    /// authorization. Non-key identityref, decimal64 and custom types are also
    /// refused. Key comparisons retain canonical integer/boolean semantics and
    /// literal comparison for other key types. Invalid supported literals are
    /// unsatisfiable rather than falling back to text comparison.
    pub fn compile(
        registry: &dyn SchemaRegistry,
        path: &'static str,
        literal: &str,
        key: bool,
        budget: &SubtreeBudget,
    ) -> Result<Self, SubtreeError> {
        let source = budget.node(registry, path)?;
        match source.kind {
            NodeKind::Leaf => {}
            NodeKind::LeafList => return Err(SubtreeError::Unsupported),
            NodeKind::Container | NodeKind::List => return Err(SubtreeError::Invalid),
        }
        // The registry method is authoritative: absent classification must not
        // inherit a permissive class from a different lookup or target leaf.
        let work = budget.audit_admission("predicate classification", || budget.charge(1))?;
        work.visit();
        if !registry
            .data_class(path)
            .is_some_and(crate::DataClass::allows_cleartext)
        {
            return Err(SubtreeError::Unsupported);
        }
        let target = resolve_scalar_target(registry, source, budget)?;
        let kind = target.leaf_type.ok_or(SubtreeError::Unsupported)?;
        if !key
            && !matches!(
                kind,
                LeafType::Boolean
                    | LeafType::Uint16
                    | LeafType::Uint32
                    | LeafType::Int64
                    | LeafType::String
                    | LeafType::Enumeration { .. }
                    | LeafType::Empty
            )
        {
            return Err(SubtreeError::Unsupported);
        }
        let ranges = if key {
            &[]
        } else {
            scalar_ranges(registry, target.path, budget)?
        };
        let value = parse_scalar(kind, ranges, literal, key, budget)?;
        Ok(Self {
            value,
            kind,
            ranges,
        })
    }

    /// Whether the literal can match any reported value.
    pub fn is_satisfiable(&self) -> bool {
        !matches!(self.value, ScalarValue::Never)
    }

    /// Canonical key request text after the literal has passed type checking.
    pub fn canonical_literal(
        &self,
        budget: &SubtreeBudget,
    ) -> Result<Option<String>, SubtreeError> {
        match &self.value {
            ScalarValue::Never => Ok(None),
            ScalarValue::Boolean(value) => {
                budget.copy(if *value { "true" } else { "false" }).map(Some)
            }
            ScalarValue::Integer(value) => {
                let work =
                    budget.audit_admission("integer literal rendering", || budget.charge(20))?;
                let rendered = value.to_string();
                work.moved(rendered.len());
                Ok(Some(rendered))
            }
            ScalarValue::Text(value) => budget.copy(value).map(Some),
        }
    }

    /// Compares one authorized, reported scalar without decoding unrelated data.
    pub fn matches(&self, reported: &str, budget: &SubtreeBudget) -> Result<bool, SubtreeError> {
        budget.begin_predicate_trial()?;
        let work = budget.audit_admission("scalar comparison", || {
            budget.charge(self.comparison_work(reported.len())?)
        })?;
        Ok(match &self.value {
            ScalarValue::Never => false,
            ScalarValue::Text(expected) => work.text_cmp(expected, reported).is_eq(),
            _ => {
                work.bytes_read(reported);
                self.matches_value(reported)
            }
        })
    }

    fn comparison_work(&self, reported_bytes: usize) -> Result<usize, SubtreeError> {
        match &self.value {
            ScalarValue::Never => Ok(0),
            ScalarValue::Text(expected) => expected
                .len()
                .checked_add(reported_bytes)
                .ok_or(SubtreeError::TooBig),
            ScalarValue::Boolean(_) | ScalarValue::Integer(_) => Ok(reported_bytes),
        }
    }

    fn matches_value(&self, reported: &str) -> bool {
        match &self.value {
            ScalarValue::Never => false,
            ScalarValue::Text(expected) => expected == reported,
            ScalarValue::Boolean(expected) => match reported {
                "true" => *expected,
                "false" => !*expected,
                _ => false,
            },
            ScalarValue::Integer(expected) => {
                parse_integer(self.kind, reported).is_some_and(|value| value == *expected)
            }
        }
    }
}

/// Canonicalizes an internal identity without granting access to its payload.
/// Masked keys may identify an authorized selection, but cannot be predicates.
pub fn canonical_key(
    registry: &dyn SchemaRegistry,
    path: &str,
    value: &str,
    budget: &SubtreeBudget,
) -> Result<Option<String>, SubtreeError> {
    let node = budget.node(registry, path)?;
    let target = resolve_scalar_target(registry, node, budget)?;
    let kind = target.leaf_type.ok_or(SubtreeError::Unsupported)?;
    let classification = budget.audit_admission("key classification", || budget.charge(1))?;
    classification.visit();
    if !registry
        .data_class(path)
        .is_some_and(crate::DataClass::allows_cleartext)
    {
        // Mandatory provider identity validation retains raw text only here.
        // Its independently bounded input cannot contribute hidden byte counts
        // to the caller's matching allowance. Charge one validation unit;
        // downstream matching retains only masked_identity's fixed-width form.
        let work = budget.audit_admission("masked key validation", || budget.charge(1))?;
        work.visit();
        return Ok(match kind {
            LeafType::Boolean => matches!(value, "true" | "false").then(|| value.to_owned()),
            LeafType::Uint8
            | LeafType::Uint16
            | LeafType::Uint32
            | LeafType::Uint64
            | LeafType::Int8
            | LeafType::Int16
            | LeafType::Int32
            | LeafType::Int64 => parse_key_integer(kind, value).map(|integer| integer.to_string()),
            _ => Some(value.to_owned()),
        });
    }
    let value = parse_scalar(kind, &[], value, true, budget)?;
    ScalarPredicate {
        value,
        kind,
        ranges: &[],
    }
    .canonical_literal(budget)
}

fn parse_integer(kind: LeafType, text: &str) -> Option<i128> {
    let value = text.parse::<i128>().ok()?;
    match kind {
        LeafType::Uint8 if u8::try_from(value).is_ok() => Some(value),
        LeafType::Uint16 if u16::try_from(value).is_ok() => Some(value),
        LeafType::Uint32 if u32::try_from(value).is_ok() => Some(value),
        LeafType::Uint64 if u64::try_from(value).is_ok() => Some(value),
        LeafType::Int8 if i8::try_from(value).is_ok() => Some(value),
        LeafType::Int16 if i16::try_from(value).is_ok() => Some(value),
        LeafType::Int32 if i32::try_from(value).is_ok() => Some(value),
        LeafType::Int64 if i64::try_from(value).is_ok() => Some(value),
        _ => None,
    }
}

fn parse_key_integer(kind: LeafType, text: &str) -> Option<i128> {
    // Key identity follows the path codec's unsigned lexical rules, including
    // rejection of negative zero. Non-key comparisons retain their own codec.
    if text.starts_with('-')
        && matches!(
            kind,
            LeafType::Uint8 | LeafType::Uint16 | LeafType::Uint32 | LeafType::Uint64
        )
    {
        return None;
    }
    parse_integer(kind, text)
}

fn parse_scalar(
    kind: LeafType,
    ranges: &[NumericRangeIntervalMeta],
    literal: &str,
    key: bool,
    budget: &SubtreeBudget,
) -> Result<ScalarValue, SubtreeError> {
    let decoding = budget.audit_admission("scalar decoding", || budget.charge(literal.len()))?;
    decoding.bytes_read(literal);
    Ok(match kind {
        LeafType::Boolean => match literal {
            "true" => ScalarValue::Boolean(true),
            "false" => ScalarValue::Boolean(false),
            _ => ScalarValue::Never,
        },
        LeafType::Uint8
        | LeafType::Uint16
        | LeafType::Uint32
        | LeafType::Uint64
        | LeafType::Int8
        | LeafType::Int16
        | LeafType::Int32
        | LeafType::Int64 => {
            let integer = if key {
                parse_key_integer(kind, literal)
            } else {
                parse_integer(kind, literal)
            };
            let Some(integer) = integer else {
                return Ok(ScalarValue::Never);
            };
            let mut allowed = ranges.is_empty();
            for interval in ranges {
                let work = budget.audit_admission("numeric range interval", || budget.charge(1))?;
                work.visit();
                allowed |=
                    integer >= i128::from(interval.min) && integer <= i128::from(interval.max);
            }
            if allowed {
                ScalarValue::Integer(integer)
            } else {
                ScalarValue::Never
            }
        }
        LeafType::Enumeration { values } if !key => {
            let mut allowed = false;
            for value in values {
                let work = budget.audit_admission("enumeration member", || budget.charge(1))?;
                work.visit();
                allowed |= budget.compare(value.name, literal)?;
            }
            if allowed {
                ScalarValue::Text(budget.copy(literal)?)
            } else {
                ScalarValue::Never
            }
        }
        LeafType::Empty if !key => ScalarValue::Never,
        _ => ScalarValue::Text(budget.copy(literal)?),
    })
}

fn scalar_ranges(
    registry: &dyn SchemaRegistry,
    path: &str,
    budget: &SubtreeBudget,
) -> Result<&'static [NumericRangeIntervalMeta], SubtreeError> {
    for range in registry.numeric_ranges() {
        let work = budget.audit_admission("range schema visit", || budget.charge(1))?;
        work.visit();
        if budget.compare(range.path, path)? {
            return Ok(range.intervals);
        }
    }
    Ok(&[])
}

fn resolve_scalar_target(
    registry: &dyn SchemaRegistry,
    mut node: &'static NodeMeta,
    budget: &SubtreeBudget,
) -> Result<&'static NodeMeta, SubtreeError> {
    // The fixed depth bounds even registries supplied by custom bindings. A
    // repeated node is refused without examining any referenced instance.
    let mut visited = [""; 64];
    for depth in 0..visited.len() {
        let target_visit = budget.audit_admission("leafref target visit", || budget.charge(1))?;
        target_visit.visit();
        for previous in &visited[..depth] {
            let work = budget.audit_admission("leafref cycle visit", || budget.charge(1))?;
            work.visit();
            if budget.compare(previous, node.path)? {
                return Err(SubtreeError::Unsupported);
            }
        }
        visited[depth] = node.path;
        match node.leaf_type {
            Some(LeafType::LeafRef { target_path }) => {
                let target = resolve_relative_target(node.path, target_path, budget)?;
                node = budget.node(registry, &target)?;
                if node.kind != NodeKind::Leaf {
                    return Err(SubtreeError::Unsupported);
                }
            }
            Some(_) => return Ok(node),
            None => return Err(SubtreeError::Unsupported),
        }
    }
    Err(SubtreeError::Unsupported)
}

fn resolve_relative_target(
    source: &str,
    target: &str,
    budget: &SubtreeBudget,
) -> Result<String, SubtreeError> {
    let decoding = budget.audit_admission("leafref path decoding", || {
        budget.charge(
            source
                .len()
                .checked_add(target.len())
                .ok_or(SubtreeError::TooBig)?,
        )
    })?;
    decoding.bytes_read(source);
    decoding.bytes_read(target);
    let prefix = source
        .rsplit('/')
        .next()
        .and_then(|name| name.split_once(':'))
        .map(|(prefix, _)| prefix)
        .ok_or(SubtreeError::Unsupported)?;
    let mut segments = Vec::new();
    if !target.starts_with('/') {
        for segment in source.trim_start_matches('/').split('/') {
            let work = budget.audit_admission("leafref source segment", || budget.charge(1))?;
            work.moved(1);
            segments.push(segment);
        }
    }
    for segment in target.strip_prefix('/').unwrap_or(target).split('/') {
        let work = budget.audit_admission("leafref target segment", || budget.charge(1))?;
        work.visit();
        match segment {
            ".." => {
                segments.pop().ok_or(SubtreeError::Unsupported)?;
            }
            "." => {}
            "" => return Err(SubtreeError::Unsupported),
            name => {
                let work = budget.audit_admission("leafref segment append", || budget.charge(1))?;
                work.moved(1);
                segments.push(name);
            }
        }
    }
    if segments.is_empty() {
        return Err(SubtreeError::Unsupported);
    }
    let bytes = segments.iter().try_fold(0usize, |sum, segment| {
        let qualifier = if segment.contains(':') {
            0
        } else {
            prefix.len() + 1
        };
        sum.checked_add(1)
            .and_then(|sum| sum.checked_add(qualifier))
            .and_then(|sum| sum.checked_add(segment.len()))
            .ok_or(SubtreeError::TooBig)
    })?;
    let rendering = budget.audit_admission("leafref path rendering", || budget.charge(bytes))?;
    let mut result = String::with_capacity(bytes);
    for segment in segments {
        result.push('/');
        if !segment.contains(':') {
            result.push_str(prefix);
            result.push(':');
        }
        result.push_str(segment);
    }
    rendering.moved(result.len());
    Ok(result)
}

#[cfg(test)]
mod tests;
