//! Compile namespace-aware subtree scopes before policy or data access.

use std::collections::BTreeMap;

use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::subtree::{
    AdmissionAudit, ScalarPredicate, SubtreeBranch, SubtreeBudget, SubtreeError, SubtreeMatch,
    SubtreeOutput, SubtreePlan, SubtreePredicate, SubtreeScope,
};
use opc_mgmt_schema::{NodeKind, NodeMeta, SchemaRegistry};

use super::FilterError;
use crate::xml::{SubtreeFilter, SubtreeNode};

#[derive(Clone, Copy)]
pub(crate) enum ContentScope {
    Config,
    State,
    All,
}

impl ContentScope {
    fn contains(self, config: bool) -> bool {
        match self {
            Self::Config => config,
            Self::State => !config,
            Self::All => true,
        }
    }
}

#[derive(Clone, Copy)]
struct Resolved {
    registry: &'static dyn SchemaRegistry,
    node: &'static NodeMeta,
}

struct Compiler<'a> {
    registries: &'a [&'static dyn SchemaRegistry],
    scope: ContentScope,
    budget: SubtreeBudget,
    retained: usize,
    limit: usize,
}

pub(crate) fn compile_content(
    registries: &[&'static dyn SchemaRegistry],
    filter: &SubtreeFilter,
    scope: ContentScope,
    limits: &MgmtLimits,
) -> Result<SubtreePlan, FilterError> {
    let budget = SubtreeBudget::new(limits.max_subtree_filter_work_units, filter.parse_work())
        .map_err(map_error)?;
    let mut compiler = Compiler {
        registries,
        scope,
        budget,
        retained: 0,
        limit: limits.max_subtree_filter_nodes,
    };
    // Root siblings in the same actual namespace share their predicates. A
    // wildcard root is resolved independently in every supported namespace.
    let mut groups = BTreeMap::<&'static str, Vec<(&SubtreeNode, Vec<Resolved>)>>::new();
    for raw in filter.roots() {
        let nodes = compiler.resolve(None, raw)?;
        let mut per_namespace = BTreeMap::<&'static str, Vec<Resolved>>::new();
        for node in nodes {
            let namespace = compiler.namespace(node)?;
            let lookup = compiler.namespace_index_work(&per_namespace, namespace)?;
            // An occupied index consumes the lookup text in its opaque comparison.
            if !per_namespace.is_empty() {
                lookup.bytes_read(namespace);
            }
            compiler.retain()?;
            per_namespace.entry(namespace).or_default().push(node);
        }
        for (namespace, nodes) in per_namespace {
            let lookup = compiler.namespace_index_work(&groups, namespace)?;
            if !groups.is_empty() {
                lookup.bytes_read(namespace);
            }
            compiler.retain()?;
            groups.entry(namespace).or_default().push((raw, nodes));
        }
    }
    let mut scopes = Vec::new();
    for (namespace, siblings) in groups {
        compiler.retain()?;
        scopes.push(compiler.resolved_scope(None, siblings, Some(namespace))?);
    }
    SubtreePlan::new(scopes, compiler.budget, limits.max_subtree_filter_nodes).map_err(map_error)
}

fn map_error(error: SubtreeError) -> FilterError {
    match error {
        SubtreeError::TooBig => FilterError::ContentLimit,
        SubtreeError::Unsupported => FilterError::UnsupportedContent,
        SubtreeError::Invalid | SubtreeError::Projection => FilterError::UnknownNode,
    }
}

impl Compiler<'_> {
    fn namespace_index_work<T>(
        &self,
        index: &BTreeMap<&str, T>,
        namespace: &str,
    ) -> Result<AdmissionAudit, FilterError> {
        let sizing = self
            .budget
            .audit_admission("namespace index sizing", || self.budget.charge(index.len()))
            .map_err(map_error)?;
        let bytes = sizing.iter(index.keys()).try_fold(0usize, |sum, key| {
            sum.checked_add(key.len())
                .and_then(|sum| sum.checked_add(namespace.len()))
                .ok_or(FilterError::ContentLimit)
        })?;
        self.budget
            .audit_admission("namespace index lookup", || self.budget.charge(bytes))
            .map_err(map_error)
    }
    fn retain(&mut self) -> Result<(), FilterError> {
        if self.retained >= self.limit {
            return Err(FilterError::ContentLimit);
        }
        let _admission = self
            .budget
            .audit_admission("content retain visit 1", || self.budget.charge(1))
            .map_err(map_error)?;
        _admission.visit();
        self.retained += 1;
        Ok(())
    }

    fn namespace(&self, resolved: Resolved) -> Result<&'static str, FilterError> {
        for model in resolved.registry.served_models() {
            let _admission = self
                .budget
                .audit_admission("content namespace visit 1", || self.budget.charge(1))
                .map_err(map_error)?;
            _admission.visit();
            if self
                .budget
                .compare(model.name, resolved.node.module)
                .map_err(map_error)?
            {
                return Ok(model.namespace);
            }
        }
        Err(FilterError::UnknownNamespace)
    }

    fn resolve(
        &mut self,
        parent: Option<Resolved>,
        raw: &SubtreeNode,
    ) -> Result<Vec<Resolved>, FilterError> {
        let name = raw.element();
        if !name.namespace.is_empty() {
            let mut known = false;
            for registry in self.registries {
                for model in registry.served_models() {
                    let _admission = self
                        .budget
                        .audit_admission("content resolve visit 1", || self.budget.charge(1))
                        .map_err(map_error)?;
                    _admission.visit();
                    known |= self
                        .budget
                        .compare(&name.namespace, model.namespace)
                        .map_err(map_error)?;
                }
            }
            if !known {
                return Err(FilterError::UnknownNamespace);
            }
        }
        let mut found = Vec::new();
        if let Some(parent) = parent {
            for path in parent.node.child_paths {
                let node = self.budget.node(parent.registry, path).map_err(map_error)?;
                self.consider(
                    Resolved {
                        registry: parent.registry,
                        node,
                    },
                    raw,
                    &mut found,
                )?;
            }
        } else {
            for registry in self.registries {
                for node in registry.nodes() {
                    let _admission = self
                        .budget
                        .audit_admission("content resolve visit 2", || self.budget.charge(1))
                        .map_err(map_error)?;
                    _admission.visit();
                    let path_audit = self
                        .budget
                        .audit_admission("root schema scan", || self.budget.charge(node.path.len()))
                        .map_err(map_error)?;
                    path_audit.bytes_read(node.path);
                    if !node.path.trim_start_matches('/').contains('/') {
                        self.consider(
                            Resolved {
                                registry: *registry,
                                node,
                            },
                            raw,
                            &mut found,
                        )?;
                    }
                }
            }
        }
        if found.is_empty() {
            Err(FilterError::UnknownNode)
        } else {
            Ok(found)
        }
    }

    fn consider(
        &mut self,
        node: Resolved,
        raw: &SubtreeNode,
        found: &mut Vec<Resolved>,
    ) -> Result<(), FilterError> {
        let _admission = self
            .budget
            .audit_admission("content consider visit 1", || self.budget.charge(1))
            .map_err(map_error)?;
        _admission.visit();
        let local = node
            .node
            .path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .split_once(':')
            .map_or("", |(_, local)| local);
        if !self
            .budget
            .compare(local, &raw.element().local)
            .map_err(map_error)?
        {
            return Ok(());
        }
        let namespace = self.namespace(node)?;
        if !raw.element().namespace.is_empty()
            && !self
                .budget
                .compare(namespace, &raw.element().namespace)
                .map_err(map_error)?
        {
            return Ok(());
        }
        self.retain()?;
        found.push(node);
        Ok(())
    }

    fn scope(
        &mut self,
        parent: Resolved,
        raw: &[SubtreeNode],
    ) -> Result<SubtreeScope, FilterError> {
        let mut siblings = Vec::new();
        for raw in raw {
            let nodes = self.resolve(Some(parent), raw)?;
            self.retain()?;
            siblings.push((raw, nodes));
        }
        self.resolved_scope(Some(parent), siblings, None)
    }

    fn resolved_scope(
        &mut self,
        parent: Option<Resolved>,
        siblings: Vec<(&SubtreeNode, Vec<Resolved>)>,
        root_namespace: Option<&'static str>,
    ) -> Result<SubtreeScope, FilterError> {
        let mut scope = SubtreeScope::default();
        for (raw, nodes) in siblings {
            if let Some(literal) = raw.text() {
                let mut alternatives = Vec::new();
                for resolved in nodes {
                    match resolved.node.kind {
                        NodeKind::Leaf => {}
                        NodeKind::LeafList => return Err(FilterError::UnsupportedContent),
                        NodeKind::Container | NodeKind::List => {
                            return Err(FilterError::UnknownNode)
                        }
                    }
                    let keys = self.keys(resolved)?;
                    let mut key = false;
                    for path in &keys {
                        let _admission = self
                            .budget
                            .audit_admission("content resolved_scope visit 1", || {
                                self.budget.charge(1)
                            })
                            .map_err(map_error)?;
                        _admission.visit();
                        key |= self
                            .budget
                            .compare(path, resolved.node.path)
                            .map_err(map_error)?;
                    }
                    let predicate = ScalarPredicate::compile(
                        resolved.registry,
                        resolved.node.path,
                        literal,
                        key,
                        &self.budget,
                    )
                    .map_err(map_error)?;
                    self.retain()?;
                    alternatives.push(SubtreeMatch {
                        path: resolved.node.path,
                        predicate,
                        in_scope: self.scope.contains(resolved.node.config)
                            || (key && matches!(self.scope, ContentScope::State)),
                        keys,
                    });
                }
                self.retain()?;
                scope.predicates.push(SubtreePredicate { alternatives });
            } else {
                for resolved in nodes {
                    let keys = self.keys(resolved)?;
                    let (children, outputs) = if raw.children().is_empty() {
                        (None, self.expand(resolved)?)
                    } else {
                        if !matches!(resolved.node.kind, NodeKind::Container | NodeKind::List) {
                            return Err(FilterError::UnknownNode);
                        }
                        let children = self.scope(resolved, raw.children())?;
                        self.retain()?;
                        (Some(Box::new(children)), Vec::new())
                    };
                    self.retain()?;
                    scope.branches.push(SubtreeBranch {
                        path: resolved.node.path,
                        keys,
                        children,
                        outputs,
                    });
                }
            }
        }
        if !scope.predicates.is_empty() && scope.branches.is_empty() {
            if let Some(parent) = parent {
                for path in parent.node.child_paths {
                    let node = self.budget.node(parent.registry, path).map_err(map_error)?;
                    let expanded = self.expand(Resolved {
                        registry: parent.registry,
                        node,
                    })?;
                    let outputs = self
                        .budget
                        .audit_admission("implicit child outputs", || {
                            self.budget.charge(expanded.len())
                        })
                        .map_err(map_error)?;
                    scope.implicit_outputs.extend(outputs.iter(expanded));
                }
            } else {
                // A root sibling set is bounded to the predicate's namespace.
                if let Some(namespace) = root_namespace {
                    for registry in self.registries {
                        for node in registry.nodes() {
                            let _admission = self
                                .budget
                                .audit_admission("content resolved_scope visit 3", || {
                                    self.budget.charge(1)
                                })
                                .map_err(map_error)?;
                            _admission.visit();
                            let path_audit = self
                                .budget
                                .audit_admission("implicit root schema scan", || {
                                    self.budget.charge(node.path.len())
                                })
                                .map_err(map_error)?;
                            path_audit.bytes_read(node.path);
                            if node.path.trim_start_matches('/').contains('/') {
                                continue;
                            }
                            let resolved = Resolved {
                                registry: *registry,
                                node,
                            };
                            if self
                                .budget
                                .compare(self.namespace(resolved)?, namespace)
                                .map_err(map_error)?
                            {
                                let expanded = self.expand(resolved)?;
                                let outputs = self
                                    .budget
                                    .audit_admission("implicit root outputs", || {
                                        self.budget.charge(expanded.len())
                                    })
                                    .map_err(map_error)?;
                                scope.implicit_outputs.extend(outputs.iter(expanded));
                            }
                        }
                    }
                }
            }
        }
        Ok(scope)
    }

    fn keys(&mut self, resolved: Resolved) -> Result<Vec<&'static str>, FilterError> {
        let mut ancestry = Vec::new();
        let mut path = resolved.node.path;
        loop {
            let node = self
                .budget
                .node(resolved.registry, path)
                .map_err(map_error)?;
            if node.kind == NodeKind::List {
                if node.key_leaves.is_empty() {
                    return Err(FilterError::UnsupportedContent);
                }
                let _admission = self
                    .budget
                    .audit_admission("content keys visit 1", || self.budget.charge(1))
                    .map_err(map_error)?;
                _admission.visit();
                ancestry.push(node);
            }
            let Some((parent, _)) = path.rsplit_once('/') else {
                break;
            };
            if parent.is_empty() {
                break;
            }
            path = parent;
        }
        let mut keys = Vec::new();
        for list in ancestry.into_iter().rev() {
            for declared in list.key_leaves {
                let mut found = None;
                for path in list.child_paths {
                    let node = self
                        .budget
                        .node(resolved.registry, path)
                        .map_err(map_error)?;
                    let local = node.path.rsplit(':').next().unwrap_or("");
                    let declared = declared.rsplit(':').next().unwrap_or(declared);
                    if self.budget.compare(local, declared).map_err(map_error)? {
                        if node.kind != NodeKind::Leaf {
                            return Err(FilterError::UnsupportedContent);
                        }
                        found = Some(node.path);
                        break;
                    }
                }
                self.retain()?;
                keys.push(found.ok_or(FilterError::UnsupportedContent)?);
            }
        }
        Ok(keys)
    }

    fn expand(&mut self, root: Resolved) -> Result<Vec<SubtreeOutput>, FilterError> {
        self.retain()?;
        let mut pending = vec![root];
        let mut outputs = Vec::new();
        while let Some(resolved) = pending.pop() {
            let _admission = self
                .budget
                .audit_admission("content expand visit 1", || self.budget.charge(1))
                .map_err(map_error)?;
            _admission.visit();
            if self.scope.contains(resolved.node.config) {
                let keys = self.keys(resolved)?;
                self.retain()?;
                outputs.push(SubtreeOutput {
                    path: resolved.node.path,
                    keys,
                });
            }
            for path in resolved.node.child_paths.iter().rev() {
                let node = self
                    .budget
                    .node(resolved.registry, path)
                    .map_err(map_error)?;
                self.retain()?;
                pending.push(Resolved {
                    registry: resolved.registry,
                    node,
                });
            }
        }
        Ok(outputs)
    }
}
