//! Authorization pruning and evaluation preserve the original sibling scopes.

use super::{ScalarPredicate, SubtreeBudget, SubtreeError};
use crate::{DefaultReport, NetconfInstanceSelector, NetconfXmlNode, NodeKind, SchemaRegistry};

/// One scalar match after resolving its namespace and type.
#[derive(Debug, Clone)]
pub struct SubtreeMatch {
    /// Canonical leaf schema path.
    pub path: &'static str,
    /// Canonical typed comparison, with redacted diagnostics.
    pub predicate: ScalarPredicate,
    /// Whether this leaf is available in the requested datastore scope.
    pub in_scope: bool,
    /// Identifying keys required at every ancestor list.
    pub keys: Vec<&'static str>,
}

/// One content test; namespace-wildcard resolutions are alternatives.
#[derive(Debug, Clone)]
pub struct SubtreePredicate {
    /// At least one authorized alternative must match the same sibling instance.
    pub alternatives: Vec<SubtreeMatch>,
}

/// An output node and all identities required to read it.
#[derive(Debug, Clone)]
pub struct SubtreeOutput {
    /// Canonical schema path.
    pub path: &'static str,
    /// Required keys from the owning and all ancestor lists.
    pub keys: Vec<&'static str>,
}

/// A selection or one independently constrained containment branch.
#[derive(Debug, Clone)]
pub struct SubtreeBranch {
    /// Canonical schema path of the selected node.
    pub path: &'static str,
    /// All identifying keys required before entering this branch.
    pub keys: Vec<&'static str>,
    /// Child sibling constraints for a containment node.
    pub children: Option<Box<SubtreeScope>>,
    /// An empty selection expands to these individually authorized nodes.
    pub outputs: Vec<SubtreeOutput>,
}

/// Content tests and output selections sharing one data sibling instance.
#[derive(Debug, Clone, Default)]
pub struct SubtreeScope {
    /// Conjunctive tests at this exact sibling scope.
    pub predicates: Vec<SubtreePredicate>,
    /// Independent selection/containment alternatives.
    pub branches: Vec<SubtreeBranch>,
    /// Matches without selection/containment siblings select these siblings.
    pub implicit_outputs: Vec<SubtreeOutput>,
}

/// A bounded schema plan before policy decisions have been applied.
#[derive(Debug)]
pub struct SubtreePlan {
    scopes: Vec<SubtreeScope>,
    paths: Vec<&'static str>,
    budget: SubtreeBudget,
}

impl SubtreePlan {
    /// Records the complete output/predicate/identity authorization batch.
    /// The compiler must also bound each intermediate scope before insertion.
    pub fn new(
        scopes: Vec<SubtreeScope>,
        budget: SubtreeBudget,
        node_limit: usize,
    ) -> Result<Self, SubtreeError> {
        let mut paths = Vec::new();
        for scope in &scopes {
            collect_paths(scope, &mut paths, &budget, node_limit)?;
        }
        Ok(Self {
            scopes,
            paths,
            budget,
        })
    }

    /// Complete schema batch, including identifying keys and match dependencies.
    pub fn authorization_paths(&self) -> &[&'static str] {
        &self.paths
    }

    /// Shared compilation and execution allowance, including authorization batching.
    pub const fn budget(&self) -> &SubtreeBudget {
        &self.budget
    }

    /// Applies one captured policy decision set before any data access.
    /// Losing a predicate or required identity prunes its dependent scope;
    /// losing an output-only node does not remove permitted siblings.
    pub fn authorize(
        self,
        allowed: impl Fn(&str) -> bool,
        node_limit: usize,
    ) -> Result<AuthorizedSubtreePlan, SubtreeError> {
        let mut scopes = Vec::new();
        for scope in self.scopes {
            if let Some(scope) = prune_scope(scope, &allowed, &self.budget)? {
                self.budget.charge(1)?;
                scopes.push(scope);
            }
        }
        let mut paths = Vec::new();
        for scope in &scopes {
            collect_paths(scope, &mut paths, &self.budget, node_limit)?;
        }
        // Keep all exact structural prefixes once, after authorization, instead
        // of rescanning every dependency for every projected row and child.
        let mut structural_paths = Vec::new();
        for path in &paths {
            let mut prefix = *path;
            while !prefix.is_empty() {
                self.budget
                    .charge(prefix.len().checked_add(1).ok_or(SubtreeError::TooBig)?)?;
                insert_path(&mut structural_paths, prefix, &self.budget, node_limit)?;
                prefix = prefix.rsplit_once('/').map_or("", |(parent, _)| parent);
            }
        }
        Ok(AuthorizedSubtreePlan {
            scopes,
            paths,
            structural_paths,
            budget: self.budget,
        })
    }
}

/// A plan whose remaining branches have complete pre-access authorization.
#[derive(Debug)]
pub struct AuthorizedSubtreePlan {
    scopes: Vec<SubtreeScope>,
    paths: Vec<&'static str>,
    structural_paths: Vec<&'static str>,
    budget: SubtreeBudget,
}

impl AuthorizedSubtreePlan {
    /// Nodes needed by surviving output and predicates, including identities.
    pub fn paths(&self) -> &[&'static str] {
        &self.paths
    }
    /// The same checked allowance used during compilation.
    pub const fn budget(&self) -> &SubtreeBudget {
        &self.budget
    }
    /// Whether all request alternatives were pruned without reading data.
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Whether a surviving predicate or output requires configuration data.
    /// Identity-only dependencies of state values do not require config rows.
    pub fn needs_configuration(&self, registry: &dyn SchemaRegistry) -> Result<bool, SubtreeError> {
        for scope in &self.scopes {
            if scope_needs_configuration(scope, registry, &self.budget)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Preserves each surviving branch's partial canonical key constraints.
    pub fn instance_selectors(
        &self,
        limit: usize,
    ) -> Result<Vec<NetconfInstanceSelector>, SubtreeError> {
        let mut selectors = Vec::new();
        for scope in &self.scopes {
            scope_selectors(scope, &[], &mut selectors, &self.budget, limit)?;
        }
        Ok(selectors)
    }

    /// Context for typed projection of the authorized config portion.
    pub fn projection<'a>(
        &'a self,
        registry: &'a dyn SchemaRegistry,
        report: DefaultReport,
    ) -> SubtreeProjection<'a> {
        SubtreeProjection {
            registry,
            paths: &self.paths,
            structural_paths: &self.structural_paths,
            budget: &self.budget,
            report,
            observer: None,
        }
    }

    /// Evaluates authorized, bounded and already validated captured inputs.
    /// Results are deduplicated and retain the input instance order.
    pub fn evaluate(
        &self,
        registry: &dyn SchemaRegistry,
        input: &[NetconfXmlNode],
    ) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
        let mut candidates = Vec::new();
        for scope in &self.scopes {
            if let Some(nodes) = evaluate_scope(scope, input, &[], registry, &self.budget)? {
                self.budget.charge(nodes.len())?;
                candidates.extend(nodes);
            }
        }
        let mut selected = Vec::new();
        merge_bounded(registry, &mut selected, candidates, &self.budget)?;
        order_like(&mut selected, input, &[], &self.budget)?;
        Ok(selected)
    }
}

fn scope_selectors(
    scope: &SubtreeScope,
    inherited: &[(&'static str, String)],
    selectors: &mut Vec<NetconfInstanceSelector>,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<(), SubtreeError> {
    let mut keys = Vec::new();
    for (path, value) in inherited {
        budget.charge(1)?;
        keys.push((*path, budget.copy(value)?));
    }
    for predicate in &scope.predicates {
        // Within a resolved parent a qualified key has one schema resolution.
        // Wildcard root alternatives cannot be list keys.
        if let [test] = predicate.alternatives.as_slice() {
            let mut identifying = false;
            for key in &test.keys {
                budget.charge(1)?;
                identifying |= budget.compare(key, test.path)?;
            }
            if identifying {
                let Some(value) = test.predicate.canonical_literal(budget)? else {
                    return Ok(());
                };
                let mut exists = false;
                for (path, previous) in &keys {
                    budget.charge(1)?;
                    if budget.compare(path, test.path)? {
                        if !budget.compare(previous, &value)? {
                            return Ok(());
                        }
                        exists = true;
                    }
                }
                if !exists {
                    budget.charge(1)?;
                    keys.push((test.path, value));
                }
            }
        }
    }
    let mut add = |path: &'static str| -> Result<(), SubtreeError> {
        if selectors.len() >= limit {
            return Err(SubtreeError::TooBig);
        }
        let mut constraints = Vec::new();
        for (key, value) in &keys {
            budget.charge(1)?;
            budget.charge(
                path.len()
                    .checked_add(key.len())
                    .ok_or(SubtreeError::TooBig)?,
            )?;
            if key.rsplit_once('/').is_some_and(|(parent, _)| {
                path.strip_prefix(parent)
                    .is_some_and(|rest| rest.starts_with('/'))
            }) {
                budget.charge(1)?;
                constraints.push((*key, budget.copy(value)?));
            }
        }
        budget.charge(1)?;
        selectors.push(NetconfInstanceSelector {
            schema_path: path,
            keys: constraints,
        });
        Ok(())
    };
    for predicate in &scope.predicates {
        for test in &predicate.alternatives {
            add(test.path)?;
        }
    }
    for output in &scope.implicit_outputs {
        add(output.path)?;
    }
    for branch in &scope.branches {
        for output in &branch.outputs {
            add(output.path)?;
        }
    }
    for branch in &scope.branches {
        if let Some(children) = &branch.children {
            scope_selectors(children, &keys, selectors, budget, limit)?;
        }
    }
    Ok(())
}

fn insert_path(
    paths: &mut Vec<&'static str>,
    path: &'static str,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<(), SubtreeError> {
    let mut lo = 0;
    let mut hi = paths.len();
    while lo < hi {
        budget.charge(1)?;
        let middle = lo + (hi - lo) / 2;
        budget.charge(
            path.len()
                .checked_add(paths[middle].len())
                .ok_or(SubtreeError::TooBig)?,
        )?;
        match paths[middle].cmp(path) {
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => lo = middle + 1,
            std::cmp::Ordering::Greater => hi = middle,
        }
    }
    if paths.len() >= limit {
        return Err(SubtreeError::TooBig);
    }
    budget.charge(paths.len() - lo + 1)?;
    paths.insert(lo, path);
    Ok(())
}

fn collect_paths(
    scope: &SubtreeScope,
    paths: &mut Vec<&'static str>,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<(), SubtreeError> {
    for predicate in &scope.predicates {
        for alternative in &predicate.alternatives {
            insert_path(paths, alternative.path, budget, limit)?;
            for key in &alternative.keys {
                insert_path(paths, key, budget, limit)?;
            }
        }
    }
    for output in &scope.implicit_outputs {
        insert_path(paths, output.path, budget, limit)?;
        for key in &output.keys {
            insert_path(paths, key, budget, limit)?;
        }
    }
    for branch in &scope.branches {
        insert_path(paths, branch.path, budget, limit)?;
        for key in &branch.keys {
            insert_path(paths, key, budget, limit)?;
        }
        for output in &branch.outputs {
            insert_path(paths, output.path, budget, limit)?;
            for key in &output.keys {
                insert_path(paths, key, budget, limit)?;
            }
        }
        if let Some(children) = &branch.children {
            collect_paths(children, paths, budget, limit)?;
        }
    }
    Ok(())
}

fn permitted(
    path: &str,
    allowed: &impl Fn(&str) -> bool,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    budget.charge(path.len().checked_add(1).ok_or(SubtreeError::TooBig)?)?;
    Ok(allowed(path))
}

fn permitted_keys(
    keys: &[&str],
    allowed: &impl Fn(&str) -> bool,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    for key in keys {
        if !permitted(key, allowed, budget)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prune_outputs(
    outputs: Vec<SubtreeOutput>,
    allowed: &impl Fn(&str) -> bool,
    budget: &SubtreeBudget,
) -> Result<Vec<SubtreeOutput>, SubtreeError> {
    let mut retained = Vec::new();
    for output in outputs {
        budget.charge(1)?;
        if permitted(output.path, allowed, budget)?
            && permitted_keys(&output.keys, allowed, budget)?
        {
            budget.charge(1)?;
            retained.push(output);
        }
    }
    Ok(retained)
}

fn prune_scope(
    mut scope: SubtreeScope,
    allowed: &impl Fn(&str) -> bool,
    budget: &SubtreeBudget,
) -> Result<Option<SubtreeScope>, SubtreeError> {
    budget.charge(1)?;
    for predicate in &mut scope.predicates {
        let mut alternatives = Vec::new();
        for test in std::mem::take(&mut predicate.alternatives) {
            budget.charge(1)?;
            if test.in_scope
                && test.predicate.is_satisfiable()
                && permitted(test.path, allowed, budget)?
                && permitted_keys(&test.keys, allowed, budget)?
            {
                budget.charge(1)?;
                alternatives.push(test);
            }
        }
        predicate.alternatives = alternatives;
        if predicate.alternatives.is_empty() {
            return Ok(None);
        }
    }
    scope.implicit_outputs = prune_outputs(scope.implicit_outputs, allowed, budget)?;
    let mut branches = Vec::new();
    for mut branch in scope.branches {
        budget.charge(1)?;
        if !permitted_keys(&branch.keys, allowed, budget)? {
            continue;
        }
        if let Some(children) = branch.children {
            let Some(children) = prune_scope(*children, allowed, budget)? else {
                continue;
            };
            budget.charge(1)?;
            branch.children = Some(Box::new(children));
        } else {
            branch.outputs = prune_outputs(branch.outputs, allowed, budget)?;
            if branch.outputs.is_empty() {
                continue;
            }
        }
        budget.charge(1)?;
        branches.push(branch);
    }
    scope.branches = branches;
    Ok((!scope.predicates.is_empty()
        || !scope.branches.is_empty()
        || !scope.implicit_outputs.is_empty())
    .then_some(scope))
}

fn scope_needs_configuration(
    scope: &SubtreeScope,
    registry: &dyn SchemaRegistry,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    budget.charge(1)?;
    let config = |path: &str| match budget.node(registry, path) {
        Ok(node) => Ok(node.config),
        Err(SubtreeError::Unsupported) => Ok(false),
        Err(error) => Err(error),
    };
    for predicate in &scope.predicates {
        for test in &predicate.alternatives {
            if config(test.path)? {
                return Ok(true);
            }
        }
    }
    for output in &scope.implicit_outputs {
        if config(output.path)? {
            return Ok(true);
        }
    }
    for branch in &scope.branches {
        for output in &branch.outputs {
            if config(output.path)? {
                return Ok(true);
            }
        }
        if let Some(children) = &branch.children {
            if scope_needs_configuration(children, registry, budget)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Borrowed scalar access used by generated projectors before allocating text.
#[derive(Clone, Copy)]
pub enum SubtreeScalar<'a> {
    /// Boolean leaf.
    Boolean(bool),
    /// Signed integral leaf.
    Integer(i64),
    /// Unsigned integral leaf.
    Unsigned(u64),
    /// Existing decimal output representation; never a non-key predicate codec.
    Decimal(f64),
    /// String, enumeration or existing identityref text.
    Text(&'a str),
    /// Empty leaf.
    Empty,
}

impl std::fmt::Debug for SubtreeScalar<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SubtreeScalar(<redacted>)")
    }
}

impl SubtreeScalar<'_> {
    // Only the public schema default determines comparison work. Masked text
    // is borrowed, never encoded or copied merely to decide default omission.
    fn matches_default(self, default: &str, budget: &SubtreeBudget) -> Result<bool, SubtreeError> {
        budget.charge(default.len().checked_mul(2).ok_or(SubtreeError::TooBig)?)?;
        Ok(match self {
            Self::Text(value) => value == default,
            Self::Empty => default.is_empty(),
            Self::Boolean(value) => default == if value { "true" } else { "false" },
            Self::Integer(value) => {
                budget.charge(20)?;
                default
                    .parse::<i64>()
                    .is_ok_and(|expected| expected.to_string() == default && value == expected)
            }
            Self::Unsigned(value) => {
                budget.charge(20)?;
                default
                    .parse::<u64>()
                    .is_ok_and(|expected| expected.to_string() == default && value == expected)
            }
            Self::Decimal(value) => {
                budget.charge(327)?;
                default.parse::<f64>().is_ok_and(|expected| {
                    expected.to_string() == default
                        && ((value.is_nan() && expected.is_nan())
                            || (value == expected
                                && value.is_sign_negative() == expected.is_sign_negative()))
                })
            }
        })
    }

    /// Encodes the existing wire representation after charging its allocation.
    pub fn encode(self, budget: &SubtreeBudget) -> Result<String, SubtreeError> {
        match self {
            Self::Text(value) => budget.copy(value),
            Self::Empty => Ok(String::new()),
            Self::Boolean(value) => budget.copy(if value { "true" } else { "false" }),
            Self::Integer(value) => {
                budget.charge(20)?;
                Ok(value.to_string())
            }
            Self::Unsigned(value) => {
                budget.charge(20)?;
                Ok(value.to_string())
            }
            Self::Decimal(value) => {
                budget.charge(327)?;
                Ok(value.to_string())
            }
        }
    }
}

/// Authorized inputs for a generated typed configuration projector.
pub struct SubtreeProjection<'a> {
    registry: &'a dyn SchemaRegistry,
    paths: &'a [&'static str],
    structural_paths: &'a [&'static str],
    budget: &'a SubtreeBudget,
    report: DefaultReport,
    observer: Option<&'a dyn SubtreeAccessObserver>,
}

/// A typed access phase, recorded before the corresponding model inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtreeAccessKind {
    /// Checking container presence or entering an authorized list.
    Structure,
    /// Inspecting one authorized list row, before extracting its identity.
    Row,
    /// Inspecting a selected scalar's presence or value.
    Value,
}

/// Optional request-local instrumentation for pre-access control-flow checks.
/// Observations contain schema paths only, never row identities or values.
pub trait SubtreeAccessObserver: Send + Sync {
    /// Called after authorization and work checks, before typed access.
    fn before_read(&self, path: &'static str, kind: SubtreeAccessKind);
}

impl<'a> SubtreeProjection<'a> {
    /// Attaches server-side access instrumentation without changing selection.
    pub fn with_observer(mut self, observer: &'a dyn SubtreeAccessObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Gates one row before key extraction or projection consistency checks.
    pub fn row(&self, path: &'static str) -> Result<(), SubtreeError> {
        self.budget.charge(1)?;
        if let Some(observer) = self.observer {
            observer.before_read(path, SubtreeAccessKind::Row);
        }
        Ok(())
    }
    /// Shared checked work allowance.
    pub const fn budget(&self) -> &SubtreeBudget {
        self.budget
    }
    /// Appends projected nodes only after charging the destination insertions.
    pub fn append(
        &self,
        target: &mut Vec<NetconfXmlNode>,
        incoming: Vec<NetconfXmlNode>,
    ) -> Result<(), SubtreeError> {
        self.budget.charge(incoming.len())?;
        target.extend(incoming);
        Ok(())
    }
    /// Whether this exact schema node has a surviving authorized dependency.
    /// Every binary-search probe consumes the shared work allowance.
    pub fn selected(&self, path: &str) -> Result<bool, SubtreeError> {
        self.contains_path(self.paths, path)
    }
    /// Whether an authorized path needs this structural ancestor.
    /// Prefixes are precomputed once during authorization, with bounded probes.
    pub fn subtree_selected(&self, path: &str) -> Result<bool, SubtreeError> {
        self.contains_path(self.structural_paths, path)
    }

    fn contains_path(&self, paths: &[&str], path: &str) -> Result<bool, SubtreeError> {
        let mut lo = 0;
        let mut hi = paths.len();
        while lo < hi {
            self.budget.charge(1)?;
            let middle = lo + (hi - lo) / 2;
            self.budget.charge(
                path.len()
                    .checked_add(paths[middle].len())
                    .ok_or(SubtreeError::TooBig)?,
            )?;
            match paths[middle].cmp(path) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Less => lo = middle + 1,
                std::cmp::Ordering::Greater => hi = middle,
            }
        }
        Ok(false)
    }
    /// Gates a candidate node before any field, value or row access.
    pub fn enter(&self, path: &'static str, structural: bool) -> Result<bool, SubtreeError> {
        self.budget.charge(1)?;
        let permitted = if structural {
            self.subtree_selected(path)?
        } else {
            self.selected(path)?
        };
        if permitted {
            if let Some(observer) = self.observer {
                observer.before_read(
                    path,
                    if structural {
                        SubtreeAccessKind::Structure
                    } else {
                        SubtreeAccessKind::Value
                    },
                );
            }
        }
        Ok(permitted)
    }
    /// A schema default is available only in modes that would report it.
    pub fn default(&self, path: &str) -> Result<Option<&'static str>, SubtreeError> {
        if !matches!(
            self.report,
            DefaultReport::ReportAll | DefaultReport::ReportAllTagged
        ) {
            return Ok(None);
        }
        Ok(self.budget.node(self.registry, path)?.default)
    }
    /// Captures a complete key after authorization, before any byte-based work.
    /// Masked keys use the same fixed-width identity as operational capture.
    pub fn key(
        &self,
        path: &'static str,
        value: SubtreeScalar<'_>,
    ) -> Result<String, SubtreeError> {
        self.budget.charge(1)?;
        if self
            .registry
            .data_class(path)
            .is_some_and(crate::DataClass::allows_cleartext)
        {
            return value.encode(self.budget);
        }
        self.budget.charge(1)?;
        use std::borrow::Cow;
        let raw = match value {
            SubtreeScalar::Text(value) => Cow::Borrowed(value),
            SubtreeScalar::Empty => Cow::Borrowed(""),
            SubtreeScalar::Boolean(value) => Cow::Borrowed(if value { "true" } else { "false" }),
            SubtreeScalar::Integer(value) => Cow::Owned(value.to_string()),
            SubtreeScalar::Unsigned(value) => Cow::Owned(value.to_string()),
            SubtreeScalar::Decimal(value) => Cow::Owned(value.to_string()),
        };
        self.budget.masked_identity(&raw)
    }

    /// Projects a present scalar using the same default-report rules as XML.
    pub fn scalar(
        &self,
        path: &'static str,
        value: SubtreeScalar<'_>,
        is_defaulted: bool,
    ) -> Result<Option<NetconfXmlNode>, SubtreeError> {
        self.scalar_at(path, value, is_defaulted, None)
    }

    /// Projects one leaf-list member, retaining its capture position if masked.
    /// The position keeps distinct masked members separate without raw payloads.
    pub fn leaf_list_scalar(
        &self,
        path: &'static str,
        value: SubtreeScalar<'_>,
        ordinal: usize,
    ) -> Result<Option<NetconfXmlNode>, SubtreeError> {
        self.scalar_at(path, value, false, Some(ordinal))
    }

    fn scalar_at(
        &self,
        path: &'static str,
        value: SubtreeScalar<'_>,
        is_defaulted: bool,
        ordinal: Option<usize>,
    ) -> Result<Option<NetconfXmlNode>, SubtreeError> {
        if is_defaulted && self.report == DefaultReport::Explicit {
            return Ok(None);
        }
        if is_defaulted && self.report == DefaultReport::Trim {
            if let Some(default) = self.budget.node(self.registry, path)?.default {
                if value.matches_default(default, self.budget)? {
                    return Ok(None);
                }
            }
        }
        self.budget.charge(1)?;
        let masked = !self
            .registry
            .data_class(path)
            .is_some_and(crate::DataClass::allows_cleartext);
        let payload = if masked {
            // The same fixed placeholder used by RedactedValue::Mask. Its
            // bytes, never the hidden scalar's bytes, enter the captured tree.
            self.budget.copy("<redacted>")?
        } else {
            value.encode(self.budget)?
        };
        self.budget.charge(1)?;
        let mut node = NetconfXmlNode::scalar(path, payload, is_defaulted);
        if masked {
            node.masked_ordinal = ordinal;
        }
        Ok(Some(node))
    }
}

/// Sizes only the already-authorized capture, without testing identity values.
/// Masked keys are fixed-width digests before reaching any of these operations.
#[derive(Default)]
struct CapturedWork {
    nodes: usize,
    keys: usize,
    schema_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
    leaf_lists: Vec<&'static str>,
}

fn add_work(total: &mut usize, units: usize) -> Result<(), SubtreeError> {
    *total = total.checked_add(units).ok_or(SubtreeError::TooBig)?;
    Ok(())
}

fn multiply_work(left: usize, right: usize) -> Result<usize, SubtreeError> {
    left.checked_mul(right).ok_or(SubtreeError::TooBig)
}

impl CapturedWork {
    fn include_keys(
        &mut self,
        keys: &[(&'static str, String)],
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        // Admit the metadata visits before inspecting any tuple component.
        budget.charge(keys.len())?;
        add_work(&mut self.keys, keys.len())?;
        for (path, value) in keys {
            add_work(&mut self.key_bytes, path.len())?;
            add_work(&mut self.key_bytes, value.len())?;
        }
        Ok(())
    }

    fn include_nodes(
        &mut self,
        nodes: &[NetconfXmlNode],
        registry: Option<&dyn SchemaRegistry>,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        for node in nodes {
            budget.charge(1)?;
            add_work(&mut self.nodes, 1)?;
            add_work(&mut self.schema_bytes, node.schema_path.len())?;
            add_work(
                &mut self.value_bytes,
                node.value.as_ref().map_or(0, String::len),
            )?;
            self.include_keys(&node.keys, budget)?;
            if let Some(registry) = registry {
                // Resolve every input node before a merge can skip descendants
                // or stop at a matching row. These searches use schema only.
                if budget.node(registry, node.schema_path)?.kind == NodeKind::LeafList {
                    budget.charge(1)?;
                    self.leaf_lists.push(node.schema_path);
                }
            }
            self.include_nodes(&node.children, registry, budget)?;
        }
        Ok(())
    }

    fn identity_bytes(&self) -> Result<usize, SubtreeError> {
        self.schema_bytes
            .checked_add(self.key_bytes)
            .ok_or(SubtreeError::TooBig)
    }

    fn merge_units(&self) -> Result<usize, SubtreeError> {
        // Each original node is processed at most once and can inspect at most
        // N candidates and N leaf-list paths. Complete tuple bytes cover every
        // component even when an unequal prefix would stop the actual compare.
        // Scalar equality can run during both candidate search and acceptance.
        // Four N² units cover probes/control work; the remaining terms cover
        // all compared bytes, component visits, recursion and insertions.
        let mut units = multiply_work(multiply_work(self.nodes, self.nodes)?, 4)?;
        let mut per_node = self.identity_bytes()?;
        add_work(&mut per_node, self.schema_bytes)?;
        per_node = multiply_work(per_node, 2)?;
        add_work(&mut per_node, multiply_work(self.value_bytes, 4)?)?;
        add_work(&mut per_node, multiply_work(self.keys, 2)?)?;
        add_work(&mut per_node, 8)?;
        add_work(&mut units, multiply_work(self.nodes, per_node)?)?;
        Ok(units)
    }

    fn ordering_units(&self) -> Result<usize, SubtreeError> {
        // All input/selected candidate pairs and every possible vector shift
        // are reserved, including candidates skipped after an early match.
        // The K×N term also covers identity-key searches in child selections.
        // Descendant order passes spend this one reservation, not a new charge
        // whose size could depend on which hidden identity matched first.
        let mut units = multiply_work(multiply_work(self.nodes, self.nodes)?, 4)?;
        add_work(
            &mut units,
            multiply_work(multiply_work(self.nodes, self.keys)?, 2)?,
        )?;
        let mut compared_bytes = self.identity_bytes()?;
        add_work(&mut compared_bytes, self.value_bytes)?;
        let mut repetitions = multiply_work(self.nodes, 3)?;
        add_work(&mut repetitions, self.keys)?;
        add_work(&mut units, multiply_work(repetitions, compared_bytes)?)?;
        add_work(&mut units, multiply_work(self.nodes, 8)?)?;
        add_work(&mut units, multiply_work(self.keys, 2)?)?;
        Ok(units)
    }
}

/// Proof that a complete identity phase was admitted before its first compare.
/// Early exits may save CPU work but never change or refund the shared charge.
struct IdentityReservation;

impl IdentityReservation {
    fn admit(budget: &SubtreeBudget, units: usize) -> Result<Self, SubtreeError> {
        budget.charge(units)?;
        Ok(Self)
    }

    fn same_identity(&self, left: &NetconfXmlNode, right: &NetconfXmlNode) -> bool {
        left.schema_path == right.schema_path
            && left.keys == right.keys
            && left.masked_ordinal == right.masked_ordinal
    }

    fn same_value(&self, left: &Option<String>, right: &Option<String>) -> bool {
        left == right
    }
}

/// Joins complete captures under a value-independent, prepaid identity bound.
/// Submit the complete batch: incrementally merging prefixes would let the
/// previously matched identities affect the size of later reservations.
pub fn merge_bounded(
    registry: &dyn SchemaRegistry,
    existing: &mut Vec<NetconfXmlNode>,
    incoming: Vec<NetconfXmlNode>,
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    if incoming.is_empty() {
        return Ok(());
    }
    let mut work = CapturedWork::default();
    work.include_nodes(existing, Some(registry), budget)?;
    work.include_nodes(&incoming, Some(registry), budget)?;
    let reservation = IdentityReservation::admit(budget, work.merge_units()?)?;
    merge_reserved(existing, incoming, &work.leaf_lists, &reservation)
}

fn merge_reserved(
    existing: &mut Vec<NetconfXmlNode>,
    incoming: Vec<NetconfXmlNode>,
    leaf_lists: &[&str],
    reservation: &IdentityReservation,
) -> Result<(), SubtreeError> {
    for mut node in incoming {
        let leaf_list = leaf_lists.contains(&node.schema_path);
        let mut found = None;
        for (index, previous) in existing.iter().enumerate() {
            if reservation.same_identity(previous, &node) {
                if leaf_list && !reservation.same_value(&previous.value, &node.value) {
                    continue;
                }
                found = Some(index);
                break;
            }
        }
        if let Some(index) = found {
            let previous = &mut existing[index];
            if !reservation.same_value(&previous.value, &node.value)
                || previous.is_defaulted != node.is_defaulted
            {
                return Err(SubtreeError::Projection);
            }
            merge_reserved(
                &mut previous.children,
                std::mem::take(&mut node.children),
                leaf_lists,
                reservation,
            )?;
        } else {
            existing.push(node);
        }
    }
    Ok(())
}

fn copy_shell(
    node: &NetconfXmlNode,
    budget: &SubtreeBudget,
) -> Result<NetconfXmlNode, SubtreeError> {
    budget.charge(1)?;
    let mut result = NetconfXmlNode::branch(node.schema_path);
    for (path, value) in &node.keys {
        budget.charge(1)?;
        result.keys.push((*path, budget.copy(value)?));
    }
    if let Some(value) = &node.value {
        result.value = Some(budget.copy(value)?);
    }
    result.is_defaulted = node.is_defaulted;
    result.masked_ordinal = node.masked_ordinal;
    Ok(result)
}

fn selected_copy(
    node: &NetconfXmlNode,
    outputs: &[SubtreeOutput],
    budget: &SubtreeBudget,
) -> Result<Option<NetconfXmlNode>, SubtreeError> {
    budget.charge(1)?;
    let mut selected = false;
    for output in outputs {
        budget.charge(1)?;
        selected |= budget.compare(output.path, node.schema_path)?;
    }
    let mut children = Vec::new();
    for child in &node.children {
        if let Some(child) = selected_copy(child, outputs, budget)? {
            budget.charge(1)?;
            children.push(child);
        }
    }
    if !selected && children.is_empty() {
        return Ok(None);
    }
    if node.value.is_some() && !selected {
        return Ok(None);
    }
    let mut result = copy_shell(node, budget)?;
    result.children = children;
    Ok(Some(result))
}

fn evaluate_scope(
    scope: &SubtreeScope,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    registry: &dyn SchemaRegistry,
    budget: &SubtreeBudget,
) -> Result<Option<Vec<NetconfXmlNode>>, SubtreeError> {
    let mut matched = Vec::new();
    let mut matched_keys = Vec::new();
    for predicate in &scope.predicates {
        let mut satisfied = false;
        for alternative in &predicate.alternatives {
            for (path, value) in keys {
                budget.charge(1)?;
                if budget.compare(path, alternative.path)?
                    && alternative.predicate.matches(value, budget)?
                {
                    satisfied = true;
                    budget.charge(1)?;
                    matched_keys.push(NetconfXmlNode::scalar(path, budget.copy(value)?, false));
                }
            }
            for (index, node) in input.iter().enumerate() {
                budget.charge(1)?;
                if budget.compare(node.schema_path, alternative.path)? {
                    if let Some(value) = &node.value {
                        if alternative.predicate.matches(value, budget)? {
                            satisfied = true;
                            budget.charge(1)?;
                            matched.push(index);
                        }
                    }
                }
            }
        }
        if !satisfied {
            return Ok(None);
        }
    }
    // Collect the complete sibling batch before deduplication. A successful
    // hidden-key search must not shrink or grow a later reservation's input.
    let mut candidates = matched_keys;
    for index in matched {
        budget.charge(1)?;
        candidates.push(copy_shell(&input[index], budget)?);
    }
    if !scope.implicit_outputs.is_empty() {
        for node in input {
            if let Some(copy) = selected_copy(node, &scope.implicit_outputs, budget)? {
                budget.charge(1)?;
                candidates.push(copy);
            }
        }
    }
    for branch in &scope.branches {
        for (path, value) in keys {
            budget.charge(1)?;
            if budget.compare(path, branch.path)? && branch.children.is_none() {
                let mut selected = false;
                for output in &branch.outputs {
                    budget.charge(1)?;
                    selected |= budget.compare(output.path, path)?;
                }
                if selected {
                    budget.charge(1)?;
                    candidates.push(NetconfXmlNode::scalar(path, budget.copy(value)?, false));
                }
            }
        }
        for node in input {
            budget.charge(1)?;
            if !budget.compare(node.schema_path, branch.path)? {
                continue;
            }
            let selected = if let Some(scope) = &branch.children {
                if let Some(children) =
                    evaluate_scope(scope, &node.children, &node.keys, registry, budget)?
                {
                    if children.is_empty() {
                        None
                    } else {
                        let mut copy = copy_shell(node, budget)?;
                        copy.children = children;
                        Some(copy)
                    }
                } else {
                    None
                }
            } else {
                selected_copy(node, &branch.outputs, budget)?
            };
            if let Some(selected) = selected {
                budget.charge(1)?;
                candidates.push(selected);
            }
        }
    }
    let mut result = Vec::new();
    merge_bounded(registry, &mut result, candidates, budget)?;
    Ok(Some(result))
}

fn order_like(
    selected: &mut Vec<NetconfXmlNode>,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    let mut work = CapturedWork::default();
    work.include_nodes(selected, None, budget)?;
    work.include_nodes(input, None, budget)?;
    work.include_keys(keys, budget)?;
    let reservation = IdentityReservation::admit(budget, work.ordering_units()?)?;
    order_reserved(selected, input, keys, &reservation)
}

fn order_reserved(
    selected: &mut Vec<NetconfXmlNode>,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    reservation: &IdentityReservation,
) -> Result<(), SubtreeError> {
    let mut ordered = Vec::new();
    // Identity keys are retained separately from projected child values. A key
    // selected or matched by the filter still occupies its schema-order slot.
    for (path, value) in keys {
        let mut index = 0;
        while index < selected.len() {
            let node = &selected[index];
            if *path == node.schema_path {
                if !node.keys.is_empty()
                    || !node.children.is_empty()
                    || !node.value.as_ref().is_some_and(|actual| value == actual)
                {
                    return Err(SubtreeError::Projection);
                }
                let node = selected.remove(index);
                ordered.push(node);
                break;
            }
            index += 1;
        }
    }
    for original in input {
        let mut index = 0;
        while index < selected.len() {
            if reservation.same_identity(original, &selected[index])
                && reservation.same_value(&original.value, &selected[index].value)
            {
                let mut node = selected.remove(index);
                order_reserved(
                    &mut node.children,
                    &original.children,
                    &original.keys,
                    reservation,
                )?;
                ordered.push(node);
                break;
            }
            index += 1;
        }
    }
    if !selected.is_empty() {
        return Err(SubtreeError::Projection);
    }
    *selected = ordered;
    Ok(())
}
