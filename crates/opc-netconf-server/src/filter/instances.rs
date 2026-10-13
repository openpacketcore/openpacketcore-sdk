//! Schema-only planning for correlated subtree list-key content matches.

use opc_mgmt_schema::{NetconfInstanceBranch, NetconfKeyPredicate};

use super::*;
use crate::xml::{FilterElement, SubtreeNode};

/// Normalizes structural selection while preserving each branch's literal
/// instance constraints. This runs before authorization or any stored-row access.
pub(crate) fn prepare_instance_read_filter(
    registry: &'static dyn SchemaRegistry,
    filter: Option<&Filter>,
    limits: &MgmtLimits,
) -> Result<(Option<Filter>, Vec<NetconfInstanceBranch>), FilterError> {
    let Some(Filter::Subtree(tree)) = filter else {
        if let Some(Filter::XPath(xpath)) = filter {
            if xpath.select().contains('[') {
                return Err(FilterError::UnsupportedXPath);
            }
        }
        return Ok((filter.cloned(), Vec::new()));
    };
    if tree.roots().is_empty() {
        return Ok((filter.cloned(), Vec::new()));
    }
    let mut plan = Planner {
        registry,
        limits,
        normalized: SubtreeFilter::default(),
        branches: Vec::new(),
    };
    for root in tree.roots() {
        let candidates = resolve_element(registry, "", root.element());
        match candidates {
            Ok(candidates) if !candidates.is_empty() => {
                for node in candidates {
                    plan.walk(root, node, &[root.element().clone()], &[], true)?;
                }
            }
            _ => {
                // Discovery registries retain their existing structural filters.
                // Their adapters have no concrete-instance selection contract.
                if has_text(root) {
                    return Err(FilterError::UnsupportedSubtree);
                }
                for selection in tree
                    .selections()
                    .iter()
                    .filter(|selection| selection.elements().first() == Some(root.element()))
                {
                    plan.normalized.push(selection.clone());
                }
            }
        }
    }
    Ok((Some(Filter::Subtree(plan.normalized)), plan.branches))
}

fn has_text(node: &SubtreeNode) -> bool {
    node.text().is_some() || node.children().iter().any(has_text)
}

fn resolve_element(
    registry: &'static dyn SchemaRegistry,
    parent: &str,
    element: &FilterElement,
) -> Result<Vec<&'static NodeMeta>, FilterError> {
    let prefixes = prefixes_for_namespace(registry, &element.namespace)?;
    let nodes = prefixes
        .into_iter()
        .filter_map(|prefix| registry.node(&format!("{parent}/{prefix}:{}", element.local)))
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        Err(FilterError::UnknownNode)
    } else {
        Ok(nodes)
    }
}

struct Planner<'a> {
    registry: &'static dyn SchemaRegistry,
    limits: &'a MgmtLimits,
    normalized: SubtreeFilter,
    branches: Vec<NetconfInstanceBranch>,
}

impl Planner<'_> {
    fn walk(
        &mut self,
        tree: &SubtreeNode,
        node: &'static NodeMeta,
        elements: &[FilterElement],
        inherited: &[NetconfKeyPredicate],
        mut valid: bool,
    ) -> Result<(), FilterError> {
        if tree.text().is_some() {
            return Err(FilterError::UnsupportedSubtree);
        }
        let mut predicates = inherited.to_vec();
        let mut matched_keys = std::collections::BTreeSet::new();
        for child in tree
            .children()
            .iter()
            .filter(|child| child.text().is_some())
        {
            let candidates = resolve_element(self.registry, node.path, child.element())?;
            let [key] = candidates.as_slice() else {
                return Err(FilterError::UnsupportedSubtree);
            };
            let name = key
                .path
                .rsplit('/')
                .next()
                .ok_or(FilterError::UnknownNode)?;
            if node.kind != NodeKind::List
                || opc_mgmt_path::declared_key(self.registry, node, name).map(|key| key.path)
                    != Some(key.path)
                || !matched_keys.insert(key.path)
            {
                return Err(FilterError::UnsupportedSubtree);
            }
            if !opc_mgmt_path::key_allows_cleartext(self.registry, key.path) {
                return Err(FilterError::MaskedKeyMatch);
            }
            let raw = child.text().ok_or(FilterError::UnsupportedSubtree)?;
            if let Some(value) = opc_mgmt_path::canonical_key_value(self.registry, key.path, raw) {
                let mut literal = String::new();
                opc_mgmt_path::append_key_predicate(&mut literal, name, &value)
                    .map_err(|_| FilterError::UnsupportedSubtree)?;
                predicates.push(NetconfKeyPredicate {
                    list_path: node.path,
                    key_path: key.path,
                    value,
                });
            } else {
                valid = false;
            }
        }
        let children = tree
            .children()
            .iter()
            .filter(|child| child.text().is_none())
            .collect::<Vec<_>>();
        if children.is_empty() {
            if valid {
                let mut paths = Vec::new();
                add_ancestors(self.registry, node.path, DataPathScope::All, &mut paths);
                add_path(self.registry, node.path, DataPathScope::All, &mut paths);
                add_descendants(self.registry, node.path, DataPathScope::All, &mut paths);
                self.limits.check_paths(paths.len())?;
                let selected = paths.clone();
                for list in self.registry.nodes().iter().filter(|list| {
                    list.kind == NodeKind::List
                        && selected.iter().any(|path| {
                            **path == *list.path
                                || path
                                    .strip_prefix(list.path)
                                    .is_some_and(|tail| tail.starts_with('/'))
                        })
                }) {
                    for key in list.key_leaves {
                        let key = opc_mgmt_path::declared_key(self.registry, list, key)
                            .ok_or(FilterError::UnknownNode)?;
                        paths.push(key.path);
                    }
                }
                paths.sort_unstable();
                paths.dedup();
                self.limits
                    .check_paths(self.branches.len().saturating_add(1))?;
                self.branches.push(NetconfInstanceBranch {
                    schema_paths: paths,
                    predicates,
                });
                self.normalized
                    .push(SubtreeSelection::new(elements.to_vec(), true));
            }
        } else {
            for child in children {
                for child_node in resolve_element(self.registry, node.path, child.element())? {
                    let mut child_elements = elements.to_vec();
                    child_elements.push(child.element().clone());
                    self.walk(child, child_node, &child_elements, &predicates, valid)?;
                }
            }
        }
        Ok(())
    }
}
