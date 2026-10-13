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
        Ok(AuthorizedSubtreePlan {
            scopes,
            paths,
            budget: self.budget,
        })
    }
}

/// A plan whose remaining branches have complete pre-access authorization.
#[derive(Debug)]
pub struct AuthorizedSubtreePlan {
    scopes: Vec<SubtreeScope>,
    paths: Vec<&'static str>,
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
        let mut selected = Vec::new();
        for scope in &self.scopes {
            if let Some(nodes) = evaluate_scope(scope, input, &[], registry, &self.budget)? {
                merge_bounded(registry, &mut selected, nodes, &self.budget)?;
            }
        }
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
    pub fn selected(&self, path: &str) -> bool {
        self.paths.binary_search(&path).is_ok()
    }
    /// Whether an authorized path needs this structural ancestor.
    pub fn subtree_selected(&self, path: &str) -> bool {
        self.paths.iter().any(|candidate| {
            *candidate == path
                || candidate
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }
    /// Gates a candidate node before any field, value or row access.
    pub fn enter(&self, path: &'static str, structural: bool) -> Result<bool, SubtreeError> {
        let permitted = if structural {
            self.subtree_selected(path)
        } else {
            self.selected(path)
        };
        if permitted {
            self.budget.charge(1)?;
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

fn same_identity(
    left: &NetconfXmlNode,
    right: &NetconfXmlNode,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    budget.charge(1)?;
    if !budget.compare(left.schema_path, right.schema_path)?
        || left.keys.len() != right.keys.len()
        || left.masked_ordinal != right.masked_ordinal
    {
        return Ok(false);
    }
    for ((left_path, left_value), (right_path, right_value)) in left.keys.iter().zip(&right.keys) {
        if !budget.compare(left_path, right_path)? || !budget.compare(left_value, right_value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Joins validated trees by complete identities, charging each candidate and byte.
pub fn merge_bounded(
    registry: &dyn SchemaRegistry,
    existing: &mut Vec<NetconfXmlNode>,
    incoming: Vec<NetconfXmlNode>,
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    for mut node in incoming {
        budget.charge(1)?;
        let kind = budget.node(registry, node.schema_path)?.kind;
        let mut found = None;
        for (index, previous) in existing.iter().enumerate() {
            if same_identity(previous, &node, budget)? {
                if kind == NodeKind::LeafList
                    && !optional_value_equal(&previous.value, &node.value, budget)?
                {
                    continue;
                }
                found = Some(index);
                break;
            }
        }
        if let Some(index) = found {
            let previous = &mut existing[index];
            if !optional_value_equal(&previous.value, &node.value, budget)?
                || previous.is_defaulted != node.is_defaulted
            {
                return Err(SubtreeError::Projection);
            }
            merge_bounded(
                registry,
                &mut previous.children,
                std::mem::take(&mut node.children),
                budget,
            )?;
        } else {
            budget.charge(1)?;
            existing.push(node);
        }
    }
    Ok(())
}

fn optional_value_equal(
    left: &Option<String>,
    right: &Option<String>,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => budget.compare(left, right),
        _ => Ok(false),
    }
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
    let mut result = Vec::new();
    merge_bounded(registry, &mut result, matched_keys, budget)?;
    for index in matched {
        merge_bounded(
            registry,
            &mut result,
            vec![copy_shell(&input[index], budget)?],
            budget,
        )?;
    }
    if !scope.implicit_outputs.is_empty() {
        for node in input {
            if let Some(copy) = selected_copy(node, &scope.implicit_outputs, budget)? {
                merge_bounded(registry, &mut result, vec![copy], budget)?;
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
                    merge_bounded(
                        registry,
                        &mut result,
                        vec![NetconfXmlNode::scalar(path, budget.copy(value)?, false)],
                        budget,
                    )?;
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
                merge_bounded(registry, &mut result, vec![selected], budget)?;
            }
        }
    }
    Ok(Some(result))
}

fn order_like(
    selected: &mut Vec<NetconfXmlNode>,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    let mut ordered = Vec::new();
    // Identity keys are retained separately from projected child values. A key
    // selected or matched by the filter still occupies its schema-order slot.
    for (path, value) in keys {
        let mut index = 0;
        while index < selected.len() {
            budget.charge(1)?;
            let node = &selected[index];
            if budget.compare(path, node.schema_path)? {
                if !node.keys.is_empty()
                    || !node.children.is_empty()
                    || !node
                        .value
                        .as_ref()
                        .map(|actual| budget.compare(value, actual))
                        .transpose()?
                        .unwrap_or(false)
                {
                    return Err(SubtreeError::Projection);
                }
                budget.charge(selected.len() - index)?;
                let node = selected.remove(index);
                budget.charge(1)?;
                ordered.push(node);
                break;
            }
            index += 1;
        }
    }
    for original in input {
        let mut index = 0;
        while index < selected.len() {
            budget.charge(1)?;
            if same_identity(original, &selected[index], budget)?
                && optional_value_equal(&original.value, &selected[index].value, budget)?
            {
                budget.charge(selected.len() - index)?;
                let mut node = selected.remove(index);
                order_like(
                    &mut node.children,
                    &original.children,
                    &original.keys,
                    budget,
                )?;
                budget.charge(1)?;
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
