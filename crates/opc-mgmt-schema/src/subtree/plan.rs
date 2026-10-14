//! Authorization pruning and evaluation preserve the original sibling scopes.

use super::{ScalarPredicate, SubtreeBudget, SubtreeError};
use crate::{DefaultReport, NetconfInstanceSelector, NetconfXmlNode, NodeKind, SchemaRegistry};

mod evaluation;
mod identity;
#[cfg(test)]
use identity::order_reserved;
use identity::{
    copy_nodes, merge_reserved, merge_selected, ordered_nodes, IdentityReservation, SelectedNode,
};

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
                let _admission = self
                    .budget
                    .audit_admission("plan authorize visit 1", || self.budget.charge(1))?;
                _admission.visit();
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
                let work = self.budget.audit_admission("structural prefix scan", || {
                    self.budget
                        .charge(prefix.len().checked_add(1).ok_or(SubtreeError::TooBig)?)
                })?;
                work.bytes_read(prefix);
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

    /// Joins and evaluates the complete, authorized and validated captures.
    ///
    /// Supply configuration and provider captures before identity coalescing.
    /// Their original metadata sizes the complete join/evaluation/order envelope;
    /// no later charge depends on a merged tree's shape. Results are deduplicated
    /// and retain the input instance order.
    pub fn evaluate(
        &self,
        registry: &dyn SchemaRegistry,
        input: &[NetconfXmlNode],
    ) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
        // Sizing has its own bounded allowance. Its partial progress is not a
        // shared observation: a raw provider sort can reorder metadata visits.
        // Admit metadata plus all dependent data work atomically once sized.
        let available = self.budget.remaining();
        let sizing = SubtreeBudget::new(available, 0)?;
        let work = evaluation::EvaluationWork::measure(&self.scopes, input, registry, &sizing)?;
        let mut units = available - sizing.remaining();
        add_work(&mut units, work.units)?;
        let reservation = IdentityReservation::admit(&self.budget, units)?;
        #[cfg(test)]
        reservation.executor_allowance(work.units);
        self.budget.record_predicate_trials(work.predicate_trials);
        let mut joined = Vec::new();
        merge_reserved(
            &mut joined,
            copy_nodes(input, &reservation),
            &work.leaf_lists,
            &reservation,
        )?;
        let mut candidates = Vec::new();
        for scope in &self.scopes {
            if let Some(nodes) = evaluate_scope(scope, &joined, &[], &reservation)? {
                reservation.moved(nodes.len());
                candidates.extend(nodes);
            }
        }
        let selected = merge_selected(candidates, &reservation)?;
        Ok(ordered_nodes(selected, &reservation))
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
        let _admission =
            budget.audit_admission("plan scope_selectors visit 1", || budget.charge(1))?;
        _admission.visit();
        keys.push((*path, budget.copy(value)?));
    }
    for predicate in &scope.predicates {
        // Within a resolved parent a qualified key has one schema resolution.
        // Wildcard root alternatives cannot be list keys.
        if let [test] = predicate.alternatives.as_slice() {
            let mut identifying = false;
            for key in &test.keys {
                let _admission =
                    budget.audit_admission("plan scope_selectors visit 2", || budget.charge(1))?;
                _admission.visit();
                identifying |= budget.compare(key, test.path)?;
            }
            if identifying {
                let Some(value) = test.predicate.canonical_literal(budget)? else {
                    return Ok(());
                };
                let mut exists = false;
                for (path, previous) in &keys {
                    let _admission = budget
                        .audit_admission("plan scope_selectors visit 3", || budget.charge(1))?;
                    _admission.visit();
                    if budget.compare(path, test.path)? {
                        if !budget.compare(previous, &value)? {
                            return Ok(());
                        }
                        exists = true;
                    }
                }
                if !exists {
                    let _admission = budget
                        .audit_admission("plan scope_selectors visit 4", || budget.charge(1))?;
                    _admission.visit();
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
            let _admission =
                budget.audit_admission("plan scope_selectors visit 5", || budget.charge(1))?;
            _admission.visit();
            let work = budget.audit_admission("selector ancestor scan", || {
                budget.charge(
                    path.len()
                        .checked_add(key.len())
                        .ok_or(SubtreeError::TooBig)?,
                )
            })?;
            work.bytes_read(key);
            if key.rsplit_once('/').is_some_and(|(parent, _)| {
                work.bytes_read(path);
                path.strip_prefix(parent)
                    .is_some_and(|rest| rest.starts_with('/'))
            }) {
                let _admission =
                    budget.audit_admission("plan scope_selectors visit 7", || budget.charge(1))?;
                _admission.visit();
                constraints.push((*key, budget.copy(value)?));
            }
        }
        let _admission =
            budget.audit_admission("plan scope_selectors visit 8", || budget.charge(1))?;
        _admission.visit();
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
        let _admission = budget.audit_admission("plan insert_path visit 1", || budget.charge(1))?;
        _admission.visit();
        let middle = lo + (hi - lo) / 2;
        let work = budget.audit_admission("path index comparison", || {
            budget.charge(
                path.len()
                    .checked_add(paths[middle].len())
                    .ok_or(SubtreeError::TooBig)?,
            )
        })?;
        match work.text_cmp(paths[middle], path) {
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => lo = middle + 1,
            std::cmp::Ordering::Greater => hi = middle,
        }
    }
    if paths.len() >= limit {
        return Err(SubtreeError::TooBig);
    }
    let work = budget.audit_admission("path index insertion", || {
        budget.charge(paths.len() - lo + 1)
    })?;
    paths.insert(lo, path);
    work.moved(paths[lo..].len());
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
    let work = budget.audit_admission("policy path lookup", || {
        budget.charge(path.len().checked_add(1).ok_or(SubtreeError::TooBig)?)
    })?;
    work.visit();
    work.bytes_read(path);
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
        let _admission =
            budget.audit_admission("plan prune_outputs visit 1", || budget.charge(1))?;
        _admission.visit();
        if permitted(output.path, allowed, budget)?
            && permitted_keys(&output.keys, allowed, budget)?
        {
            let _admission =
                budget.audit_admission("plan prune_outputs visit 2", || budget.charge(1))?;
            _admission.visit();
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
    let _admission = budget.audit_admission("plan prune_scope visit 1", || budget.charge(1))?;
    _admission.visit();
    for predicate in &mut scope.predicates {
        let mut alternatives = Vec::new();
        for test in std::mem::take(&mut predicate.alternatives) {
            let _admission =
                budget.audit_admission("plan prune_scope visit 2", || budget.charge(1))?;
            _admission.visit();
            if test.in_scope
                && test.predicate.is_satisfiable()
                && permitted(test.path, allowed, budget)?
                && permitted_keys(&test.keys, allowed, budget)?
            {
                let _admission =
                    budget.audit_admission("plan prune_scope visit 3", || budget.charge(1))?;
                _admission.visit();
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
        let _admission = budget.audit_admission("plan prune_scope visit 4", || budget.charge(1))?;
        _admission.visit();
        if !permitted_keys(&branch.keys, allowed, budget)? {
            continue;
        }
        if let Some(children) = branch.children {
            let Some(children) = prune_scope(*children, allowed, budget)? else {
                continue;
            };
            let _admission =
                budget.audit_admission("plan prune_scope visit 5", || budget.charge(1))?;
            _admission.visit();
            branch.children = Some(Box::new(children));
        } else {
            branch.outputs = prune_outputs(branch.outputs, allowed, budget)?;
            if branch.outputs.is_empty() {
                continue;
            }
        }
        let _admission = budget.audit_admission("plan prune_scope visit 6", || budget.charge(1))?;
        _admission.visit();
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
    let _admission = budget.audit_admission("plan scope_needs_configuration visit 1", || {
        budget.charge(1)
    })?;
    _admission.visit();
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
        let comparison = budget.audit_admission("default comparison", || {
            budget.charge(default.len().checked_mul(2).ok_or(SubtreeError::TooBig)?)
        })?;
        Ok(match self {
            Self::Text(value) => comparison.text_cmp(value, default).is_eq(),
            Self::Empty => default.is_empty(),
            Self::Boolean(value) => comparison
                .text_cmp(default, if value { "true" } else { "false" })
                .is_eq(),
            Self::Integer(value) => {
                let work =
                    budget.audit_admission("signed default rendering", || budget.charge(20))?;
                comparison.bytes_read(default);
                default.parse::<i64>().is_ok_and(|expected| {
                    let rendered = expected.to_string();
                    work.moved(rendered.len());
                    comparison.text_cmp(&rendered, default).is_eq() && value == expected
                })
            }
            Self::Unsigned(value) => {
                let work =
                    budget.audit_admission("unsigned default rendering", || budget.charge(20))?;
                comparison.bytes_read(default);
                default.parse::<u64>().is_ok_and(|expected| {
                    let rendered = expected.to_string();
                    work.moved(rendered.len());
                    comparison.text_cmp(&rendered, default).is_eq() && value == expected
                })
            }
            Self::Decimal(value) => {
                let work =
                    budget.audit_admission("decimal default rendering", || budget.charge(327))?;
                comparison.bytes_read(default);
                default.parse::<f64>().is_ok_and(|expected| {
                    let rendered = expected.to_string();
                    work.moved(rendered.len());
                    comparison.text_cmp(&rendered, default).is_eq()
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
                let work =
                    budget.audit_admission("signed scalar rendering", || budget.charge(20))?;
                let rendered = value.to_string();
                work.moved(rendered.len());
                Ok(rendered)
            }
            Self::Unsigned(value) => {
                let work =
                    budget.audit_admission("unsigned scalar rendering", || budget.charge(20))?;
                let rendered = value.to_string();
                work.moved(rendered.len());
                Ok(rendered)
            }
            Self::Decimal(value) => {
                let work =
                    budget.audit_admission("decimal scalar rendering", || budget.charge(327))?;
                let rendered = value.to_string();
                work.moved(rendered.len());
                Ok(rendered)
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
        let _admission = self
            .budget
            .audit_admission("plan row visit 1", || self.budget.charge(1))?;
        _admission.visit();
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
        let work = self
            .budget
            .audit_admission("projection append", || self.budget.charge(incoming.len()))?;
        target.extend(work.iter(incoming));
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
            let _admission = self
                .budget
                .audit_admission("plan contains_path visit 1", || self.budget.charge(1))?;
            _admission.visit();
            let middle = lo + (hi - lo) / 2;
            let work = self
                .budget
                .audit_admission("projection path comparison", || {
                    self.budget.charge(
                        path.len()
                            .checked_add(paths[middle].len())
                            .ok_or(SubtreeError::TooBig)?,
                    )
                })?;
            match work.text_cmp(paths[middle], path) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Less => lo = middle + 1,
                std::cmp::Ordering::Greater => hi = middle,
            }
        }
        Ok(false)
    }
    /// Gates a candidate node before any field, value or row access.
    pub fn enter(&self, path: &'static str, structural: bool) -> Result<bool, SubtreeError> {
        let _admission = self
            .budget
            .audit_admission("plan enter visit 1", || self.budget.charge(1))?;
        _admission.visit();
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
        let _admission = self
            .budget
            .audit_admission("plan key visit 1", || self.budget.charge(1))?;
        _admission.visit();
        if self
            .registry
            .data_class(path)
            .is_some_and(crate::DataClass::allows_cleartext)
        {
            return value.encode(self.budget);
        }
        let _admission = self
            .budget
            .audit_admission("plan key visit 2", || self.budget.charge(1))?;
        _admission.visit();
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
        let _admission = self
            .budget
            .audit_admission("plan scalar_at visit 1", || self.budget.charge(1))?;
        _admission.visit();
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
        let _admission = self
            .budget
            .audit_admission("plan scalar_at visit 2", || self.budget.charge(1))?;
        _admission.visit();
        let mut node = NetconfXmlNode::scalar(path, payload, is_defaulted);
        if masked {
            node.masked_ordinal = ordinal;
        }
        Ok(Some(node))
    }
}

/// Sizes only the already-authorized capture, without testing identity values.
/// Masked keys are fixed-width digests before reaching any of these operations.
#[derive(Clone, Default)]
struct CapturedWork {
    nodes: usize,
    // Maximum sibling batch in one row; nodes remains the original total.
    row_nodes: usize,
    keys: usize,
    schema_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
    largest_identity: usize,
    largest_value: usize,
    largest_keys: usize,
    largest_key_path: usize,
    largest_key_value: usize,
    leaf_lists: Vec<&'static str>,
}

fn add_work(total: &mut usize, units: usize) -> Result<(), SubtreeError> {
    *total = total.checked_add(units).ok_or(SubtreeError::TooBig)?;
    Ok(())
}

fn multiply_work(left: usize, right: usize) -> Result<usize, SubtreeError> {
    left.checked_mul(right).ok_or(SubtreeError::TooBig)
}

// ceil(log2(nodes + 1)), without overflowing at usize::MAX.
fn index_levels(nodes: usize) -> usize {
    (usize::BITS - nodes.leading_zeros()) as usize
}

fn sort_levels(nodes: usize) -> usize {
    index_levels(nodes.saturating_sub(1))
}

fn normalize_leaf_lists(
    paths: &mut Vec<&'static str>,
    budget: &SubtreeBudget,
) -> Result<usize, SubtreeError> {
    #[cfg(test)]
    let _audit = budget.audit_scope("leaf-list normalization");
    let sizing = budget.audit_admission("leaf-list path sizing", || budget.charge(paths.len()))?;
    let largest = paths
        .iter()
        .map(|path| {
            budget.audit_visit(1);
            sizing.visit();
            path.len()
        })
        .max()
        .unwrap_or(0);
    let comparison = multiply_work(largest, 2)?
        .checked_add(1)
        .ok_or(SubtreeError::TooBig)?;
    let mut per_path = multiply_work(
        sort_levels(paths.len()),
        comparison.checked_add(1).ok_or(SubtreeError::TooBig)?,
    )?;
    add_work(&mut per_path, comparison)?;
    add_work(&mut per_path, 4)?;
    let ordering = budget.audit_admission("leaf-list path ordering", || {
        budget.charge(multiply_work(paths.len(), per_path)?)
    })?;
    let compare = |left: &str, right: &str| {
        #[cfg(test)]
        budget.audit_text_cmp(left, right);
        ordering.text_cmp(left, right)
    };
    let order = identity::sorted_indices(
        paths.len(),
        |left, right| compare(paths[left], paths[right]),
        |units| {
            budget.audit_move(units);
            ordering.moved(units);
        },
    );
    let mut normalized: Vec<&'static str> = Vec::new();
    for index in order {
        budget.audit_visit(1);
        ordering.visit();
        if normalized
            .last()
            .is_none_or(|previous| !compare(previous, paths[index]).is_eq())
        {
            budget.audit_move(1);
            ordering.moved(1);
            normalized.push(paths[index]);
        }
    }
    *paths = normalized;
    Ok(largest)
}

fn leaf_probe_units(
    work: &CapturedWork,
    visits: usize,
    paths: usize,
    largest_path: usize,
) -> Result<usize, SubtreeError> {
    let mut comparison = largest_path;
    add_work(&mut comparison, work.largest_identity)?;
    add_work(&mut comparison, 2)?;
    if paths == 0 {
        return Ok(0);
    }
    multiply_work(multiply_work(visits, index_levels(paths) + 1)?, comparison)
}

impl CapturedWork {
    fn include_keys(
        &mut self,
        keys: &[(&'static str, String)],
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        // Admit the metadata visits before inspecting any tuple component.
        let work = budget.audit_admission("captured key metadata", || budget.charge(keys.len()))?;
        add_work(&mut self.keys, keys.len())?;
        for (path, value) in work.iter(keys) {
            add_work(&mut self.key_bytes, path.len())?;
            add_work(&mut self.key_bytes, value.len())?;
            self.largest_key_path = self.largest_key_path.max(path.len());
            self.largest_key_value = self.largest_key_value.max(value.len());
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
            let _admission =
                budget.audit_admission("plan include_nodes visit 1", || budget.charge(1))?;
            _admission.visit();
            add_work(&mut self.nodes, 1)?;
            add_work(&mut self.row_nodes, 1)?;
            add_work(&mut self.schema_bytes, node.schema_path.len())?;
            add_work(
                &mut self.value_bytes,
                node.value.as_ref().map_or(0, String::len),
            )?;
            self.include_keys(&node.keys, budget)?;
            let mut identity = node.schema_path.len();
            for (path, value) in &node.keys {
                add_work(&mut identity, path.len())?;
                add_work(&mut identity, value.len())?;
            }
            self.largest_identity = self.largest_identity.max(identity);
            self.largest_value = self
                .largest_value
                .max(node.value.as_ref().map_or(0, String::len));
            self.largest_keys = self.largest_keys.max(node.keys.len());
            if let Some(registry) = registry {
                // Resolve every input node before a merge can skip descendants
                // or stop at a matching row. These searches use schema only.
                if budget.node(registry, node.schema_path)?.kind == NodeKind::LeafList {
                    let _admission = budget
                        .audit_admission("plan include_nodes visit 2", || budget.charge(1))?;
                    _admission.visit();
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

    fn comparison_units(&self) -> Result<usize, SubtreeError> {
        // Tuple and leaf-list comparisons advance both operands together.
        // Each byte position is visited once; key/option/length probes add
        // three units per key and five per complete comparison.
        let mut units = self.largest_identity;
        add_work(&mut units, self.largest_value)?;
        add_work(&mut units, multiply_work(self.largest_keys, 3)?)?;
        add_work(&mut units, 5)?;
        Ok(units)
    }

    fn merge_units(&self) -> Result<usize, SubtreeError> {
        let comparison = self.comparison_units()?;
        // One indexed sort per sibling batch, one adjacent-run comparison per
        // node, and one scalar/default conflict check per coalescing node.
        let passes = sort_levels(self.row_nodes.min(self.nodes));
        let mut per_node = multiply_work(
            passes,
            comparison.checked_add(1).ok_or(SubtreeError::TooBig)?,
        )?;
        add_work(&mut per_node, comparison)?;
        add_work(&mut per_node, multiply_work(self.largest_value, 2)?)?;
        add_work(&mut per_node, 16)?;
        let mut units = multiply_work(self.nodes, per_node)?;
        // Linear tuple visits also make every captured total participate in
        // checked arithmetic, even for empty or synthetic metadata.
        add_work(&mut units, multiply_work(self.identity_bytes()?, 2)?)?;
        add_work(&mut units, multiply_work(self.value_bytes, 2)?)?;
        add_work(&mut units, multiply_work(self.keys, 2)?)?;
        Ok(units)
    }

    fn selection_merge_units(&self) -> Result<usize, SubtreeError> {
        // Source positions replace repeated identity-tuple comparisons. Keep
        // the scalar/default conflict checks when equal positions coalesce.
        let mut per_node = multiply_work(sort_levels(self.row_nodes.min(self.nodes)), 2)?;
        add_work(&mut per_node, multiply_work(self.largest_value, 2)?)?;
        add_work(&mut per_node, 16)?;
        multiply_work(self.nodes, per_node)
    }

    #[cfg(test)]
    fn ordering_units(&self) -> Result<usize, SubtreeError> {
        let mut work = self.clone();
        // The standalone test wrapper pools selected nodes, source nodes and
        // owner keys. Each key can produce one additional scalar probe.
        add_work(&mut work.nodes, self.keys)?;
        add_work(&mut work.row_nodes, self.keys)?;
        work.largest_identity = work.largest_identity.max(self.largest_key_path);
        work.largest_value = work.largest_value.max(self.largest_key_value);
        let mut units = multiply_work(work.merge_units()?, 2)?;
        add_work(&mut units, multiply_work(work.nodes, 16)?)?;
        Ok(units)
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
    let leaf_bytes = normalize_leaf_lists(&mut work.leaf_lists, budget)?;
    let mut units = work.merge_units()?;
    add_work(
        &mut units,
        leaf_probe_units(&work, work.nodes, work.leaf_lists.len(), leaf_bytes)?,
    )?;
    let reservation = IdentityReservation::admit(budget, units)?;
    merge_reserved(existing, incoming, &work.leaf_lists, &reservation)
}

fn selected_copy(
    node: &NetconfXmlNode,
    index: usize,
    keys: &[(&'static str, String)],
    outputs: &[SubtreeOutput],
    reservation: &IdentityReservation,
) -> Result<Option<SelectedNode>, SubtreeError> {
    reservation.compared(1);
    let mut selected = false;
    for output in outputs {
        selected |= reservation.path_eq(output.path, node.schema_path);
    }
    let mut children = Vec::new();
    for (index, child) in node.children.iter().enumerate() {
        if let Some(child) = selected_copy(child, index, &node.keys, outputs, reservation)? {
            reservation.moved(1);
            children.push(child);
        }
    }
    if !selected && children.is_empty() {
        return Ok(None);
    }
    if node.value.is_some() && !selected {
        return Ok(None);
    }
    let mut result = SelectedNode::capture(node, index, keys, reservation)?;
    result.children = children;
    Ok(Some(result))
}

fn evaluate_scope(
    scope: &SubtreeScope,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    reservation: &IdentityReservation,
) -> Result<Option<Vec<SelectedNode>>, SubtreeError> {
    let mut matched = Vec::new();
    let mut matched_keys = Vec::new();
    for predicate in &scope.predicates {
        let mut satisfied = false;
        for alternative in &predicate.alternatives {
            for (index, (path, value)) in keys.iter().enumerate() {
                if reservation.path_eq(path, alternative.path)
                    && reservation.matches(&alternative.predicate, value)
                {
                    satisfied = true;
                    matched_keys.push(SelectedNode::key(path, value, index, reservation));
                }
            }
            for (index, node) in input.iter().enumerate() {
                if reservation.path_eq(node.schema_path, alternative.path) {
                    if let Some(value) = &node.value {
                        if reservation.matches(&alternative.predicate, value) {
                            satisfied = true;
                            reservation.moved(1);
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
    // All dependent phases spend the envelope measured before the input join.
    // These intermediate forests never determine a new work charge.
    let mut candidates = matched_keys;
    for index in matched {
        reservation.moved(1);
        candidates.push(SelectedNode::capture(
            &input[index],
            index,
            keys,
            reservation,
        )?);
    }
    if !scope.implicit_outputs.is_empty() {
        for (index, node) in input.iter().enumerate() {
            if let Some(copy) =
                selected_copy(node, index, keys, &scope.implicit_outputs, reservation)?
            {
                reservation.moved(1);
                candidates.push(copy);
            }
        }
    }
    for branch in &scope.branches {
        for (index, (path, value)) in keys.iter().enumerate() {
            if reservation.path_eq(path, branch.path) && branch.children.is_none() {
                let mut selected = false;
                for output in &branch.outputs {
                    selected |= reservation.path_eq(output.path, path);
                }
                if selected {
                    candidates.push(SelectedNode::key(path, value, index, reservation));
                }
            }
        }
        for (index, node) in input.iter().enumerate() {
            if !reservation.path_eq(node.schema_path, branch.path) {
                continue;
            }
            let selected = if let Some(scope) = &branch.children {
                if let Some(children) =
                    evaluate_scope(scope, &node.children, &node.keys, reservation)?
                {
                    if children.is_empty() {
                        None
                    } else {
                        let mut copy = SelectedNode::capture(node, index, keys, reservation)?;
                        copy.children = children;
                        Some(copy)
                    }
                } else {
                    None
                }
            } else {
                selected_copy(node, index, keys, &branch.outputs, reservation)?
            };
            if let Some(selected) = selected {
                reservation.moved(1);
                candidates.push(selected);
            }
        }
    }
    Ok(Some(merge_selected(candidates, reservation)?))
}

#[cfg(test)]
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

#[cfg(test)]
mod tests;
