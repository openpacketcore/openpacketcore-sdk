//! Schema-only dependencies of a readable data node.

use std::collections::{BTreeMap, BTreeSet};

use opc_config_model::TrustedPrincipal;
use opc_mgmt_schema::{NodeKind, SchemaRegistry};

use crate::{
    AuthzError, PathDecision, PolicySource, ReadAction, ReadAuthorizer, ReadTrace, ResolvedPolicy,
};

/// One requested schema node, before any stored values are inspected.
#[derive(Debug, Clone, Copy)]
pub struct ReadNode<'a> {
    /// Predicate-free schema path. Instance predicates never grant access.
    pub path: &'a str,
    /// Whether a provider may return an opaque value containing this subtree.
    /// Every descendant must be permitted because the adapter does not rewrite
    /// provider JSON. Identifying keys must also permit cleartext paths.
    pub opaque: bool,
}

impl<'a> ReadNode<'a> {
    /// A node projected by a schema-aware renderer.
    pub const fn projected(path: &'a str) -> Self {
        Self {
            path,
            opaque: false,
        }
    }

    /// A node supplied as an opaque operational value or event.
    pub const fn operational(path: &'a str) -> Self {
        Self { path, opaque: true }
    }
}

/// Decisions and identifying dependencies from one policy context.
#[derive(Debug, Clone, Default)]
pub struct AuthorizedReadSelection {
    /// One effective decision per input node, in input order. A missing or
    /// denied identifying key denies its dependent node, including list nodes.
    pub decisions: Vec<PathDecision>,
    /// Allowed schema nodes in the complete batch, including dependencies.
    /// Streams retain these schema paths to detect revoked access. No instance
    /// identifier is retained in this set.
    pub permitted_paths: BTreeSet<String>,
    keys: Vec<Vec<&'static str>>,
    material: Vec<bool>,
}

impl AuthorizedReadSelection {
    /// Identifying key schema paths for an input node, including ancestor keys.
    pub fn identifying_keys(&self, index: usize) -> &[&'static str] {
        self.keys.get(index).map_or(&[], Vec::as_slice)
    }

    /// Expands an allowed XML selection with its permitted identifying keys.
    /// XML list entries carry their key elements even in a direct child read.
    /// Structural selections alone contribute no key output: a denied child
    /// must not turn into an entry containing only an unrequested key.
    /// Call only with the schema paths used to create this result.
    pub fn xml_paths(&self, requested: &[&'static str]) -> Vec<&'static str> {
        self.xml_paths_where(requested, |_| true)
    }

    /// Expands permitted XML data that is available for this response.
    ///
    /// `include` filters requested data before introducing identifying keys.
    /// This avoids key-only entries when a requested operational value is absent.
    /// Selected structural ancestors are retained only for included data and
    /// never grant permission to an unselected child.
    pub fn xml_paths_where(
        &self,
        requested: &[&'static str],
        include: impl Fn(&str) -> bool,
    ) -> Vec<&'static str> {
        let mut paths = BTreeSet::new();
        for (index, (decision, path)) in self.decisions.iter().zip(requested).enumerate() {
            if decision.allowed && self.material.get(index) == Some(&true) && include(path) {
                paths.insert(*path);
                paths.extend(self.identifying_keys(index).iter().copied());
            }
        }
        let structural = self
            .decisions
            .iter()
            .zip(requested)
            .filter(|(decision, path)| {
                decision.allowed && paths.iter().any(|data| below(path, data))
            })
            .map(|(_, path)| *path)
            .collect::<Vec<_>>();
        paths.extend(structural);
        paths.into_iter().collect()
    }
}

impl<P: PolicySource> ReadAuthorizer<'_, P> {
    /// Authorizes requested nodes and all their identity dependencies together.
    ///
    /// `previously_permitted` extends the same batch for stream revocation
    /// checks. It must contain only schema paths from earlier evaluations.
    /// This function never reads stored rows, extracts keys or parses values.
    pub fn authorize_selection(
        &self,
        principal: &TrustedPrincipal,
        action: ReadAction,
        requested: &[ReadNode<'_>],
        previously_permitted: &BTreeSet<String>,
    ) -> Result<AuthorizedReadSelection, AuthzError> {
        let resolved = self
            .policy_source()
            .active_policy_context_for_principal(principal)?;
        Ok(self.authorize_selection_resolved(&resolved, action, requested, previously_permitted))
    }

    /// Evaluates a complete selection against a caller-owned policy snapshot.
    /// This is the multi-registry counterpart of [`Self::authorize_selection`].
    pub fn authorize_selection_resolved(
        &self,
        resolved: &ResolvedPolicy,
        action: ReadAction,
        requested: &[ReadNode<'_>],
        previously_permitted: &BTreeSet<String>,
    ) -> AuthorizedReadSelection {
        self.authorize_selection_resolved_with_trace(
            resolved,
            action,
            requested,
            previously_permitted,
            ReadTrace::Emit,
        )
    }

    /// Evaluates a subscription event without emitting authorization traces.
    ///
    /// Uses the same caller-owned policy context, evaluator, and complete schema
    /// dependency batch as [`Self::authorize_selection_resolved`]. Suppressing
    /// per-event traces prevents a denied event from revealing hidden activity.
    /// Requests, snapshots, and independent authorization-control reevaluations
    /// must use the ordinary traced entry point instead.
    pub fn authorize_event_selection_resolved(
        &self,
        resolved: &ResolvedPolicy,
        requested: &[ReadNode<'_>],
        previously_permitted: &BTreeSet<String>,
    ) -> AuthorizedReadSelection {
        self.authorize_selection_resolved_with_trace(
            resolved,
            ReadAction::Subscribe,
            requested,
            previously_permitted,
            ReadTrace::Suppress,
        )
    }

    fn authorize_selection_resolved_with_trace(
        &self,
        resolved: &ResolvedPolicy,
        action: ReadAction,
        requested: &[ReadNode<'_>],
        previously_permitted: &BTreeSet<String>,
        trace: ReadTrace,
    ) -> AuthorizedReadSelection {
        let registry = self.registry();
        let requirements = requested
            .iter()
            .map(|request| {
                let Some(node) = registry.node(request.path) else {
                    return Requirements::default();
                };
                let mut requirement = Requirements {
                    valid: true,
                    ..Requirements::default()
                };
                requirement.paths.insert(node.path);
                requirement.add_keys(registry, node.path, request.opaque);
                if request.opaque {
                    if !node.data_class.allows_cleartext() {
                        requirement.valid = false;
                    }
                    for descendant in registry
                        .nodes()
                        .iter()
                        .filter(|child| below(node.path, child.path))
                    {
                        requirement.paths.insert(descendant.path);
                        requirement.add_keys(registry, descendant.path, true);
                        if !descendant.data_class.allows_cleartext() {
                            requirement.valid = false;
                        }
                    }
                }
                requirement
            })
            .collect::<Vec<_>>();
        let mut batch = previously_permitted
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for requirement in &requirements {
            batch.extend(requirement.paths.iter().copied());
        }
        let batch = batch.into_iter().collect::<Vec<_>>();
        let decisions = self.authorize_resolved_with_trace(resolved, action, &batch, trace);
        let allowed = batch
            .iter()
            .copied()
            .zip(decisions.iter().map(|d| d.allowed))
            .collect::<BTreeMap<_, _>>();
        let permitted_paths = decisions
            .into_iter()
            .filter(|d| d.allowed)
            .map(|d| d.path)
            .collect();
        let effective = requested
            .iter()
            .zip(&requirements)
            .map(|(request, requirement)| PathDecision {
                path: registry
                    .node(request.path)
                    .map_or(crate::INVALID_SCHEMA_PATH, |n| n.path)
                    .to_string(),
                allowed: requirement.valid
                    && requirement
                        .paths
                        .iter()
                        .all(|path| allowed.get(path) == Some(&true)),
            })
            .collect();
        AuthorizedReadSelection {
            decisions: effective,
            permitted_paths,
            material: requested
                .iter()
                .map(|request| {
                    registry.node(request.path).is_some_and(|node| {
                        request.opaque
                            || node.presence
                            || matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList)
                    })
                })
                .collect(),
            keys: requirements
                .into_iter()
                .map(|r| r.keys.into_iter().collect())
                .collect(),
        }
    }
}

#[derive(Default)]
struct Requirements {
    valid: bool,
    paths: BTreeSet<&'static str>,
    keys: BTreeSet<&'static str>,
}

impl Requirements {
    fn add_keys(&mut self, registry: &dyn SchemaRegistry, path: &str, cleartext: bool) {
        for list in registry.nodes().iter().filter(|node| {
            node.kind == NodeKind::List && (node.path == path || below(node.path, path))
        }) {
            for key in list.key_leaves {
                let key_node = list
                    .child_paths
                    .iter()
                    .filter_map(|path| registry.node(path))
                    .find(|child| {
                        let name = child.path.rsplit('/').next().unwrap_or_default();
                        if key.contains(':') {
                            name == *key
                        } else {
                            child.module == list.module && name.rsplit(':').next() == Some(*key)
                        }
                    });
                let Some(key_node) = key_node.filter(|node| node.kind == NodeKind::Leaf) else {
                    self.valid = false;
                    continue;
                };
                self.keys.insert(key_node.path);
                self.paths.insert(key_node.path);
                if cleartext && !key_node.data_class.allows_cleartext() {
                    self.valid = false;
                }
            }
        }
    }
}

fn below(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests;
