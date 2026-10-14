//! One envelope for every phase downstream of the first identity join.
//!
//! Sizing uses only the original capture's schema paths, counts and lengths.
//! `Shape` deliberately cannot hold a key identity or a scalar value. Scope
//! estimates retain original row totals and maxima. Indexed sibling operations
//! use logarithmic bounds without assuming which fragments will coalesce.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KeySize {
    path: &'static str,
    bytes: usize,
}

struct Shape {
    path: &'static str,
    kind: NodeKind,
    metadata_work: usize,
    value_bytes: Option<usize>,
    keys: Vec<KeySize>,
    children: Vec<Shape>,
    shell: Footprint,
    tree: Footprint,
}

fn metadata_units(path: &str, keys: &[KeySize], children: &[Shape]) -> Result<usize, SubtreeError> {
    let mut units = path.len();
    add_work(&mut units, 6)?;
    for key in keys {
        add_work(&mut units, key.path.len())?;
        add_work(&mut units, 2)?;
    }
    for child in children {
        add_work(&mut units, child.metadata_work)?;
    }
    Ok(units)
}

impl Shape {
    fn compare_metadata(&self, other: &Self, budget: &SubtreeBudget) -> std::cmp::Ordering {
        budget
            .audit_text_cmp(self.path, other.path)
            .then_with(|| {
                budget.audit_visit(1);
                self.value_bytes.cmp(&other.value_bytes)
            })
            .then_with(|| {
                for (left, right) in self.keys.iter().zip(&other.keys) {
                    budget.audit_visit(1);
                    let order = budget.audit_text_cmp(left.path, right.path).then_with(|| {
                        budget.audit_visit(1);
                        left.bytes.cmp(&right.bytes)
                    });
                    if !order.is_eq() {
                        return order;
                    }
                }
                budget.audit_visit(1);
                self.keys.len().cmp(&other.keys.len())
            })
            .then_with(|| {
                self.children
                    .iter()
                    .zip(&other.children)
                    .map(|(left, right)| left.compare_metadata(right, budget))
                    .find(|order| !order.is_eq())
                    .unwrap_or_else(|| {
                        budget.audit_visit(1);
                        self.children.len().cmp(&other.children.len())
                    })
            })
    }
}

fn normalize_shapes(shapes: &mut [Shape], budget: &SubtreeBudget) -> Result<(), SubtreeError> {
    #[cfg(test)]
    let _audit = budget.audit_scope("shape normalization");
    budget.charge(shapes.len())?;
    let mut per_level = 0;
    for shape in shapes.iter() {
        budget.audit_visit(1);
        add_work(&mut per_level, multiply_work(shape.metadata_work, 2)?)?;
        add_work(&mut per_level, 2)?;
    }
    let mut units = multiply_work(sort_levels(shapes.len()), per_level)?;
    add_work(&mut units, multiply_work(shapes.len(), 8)?)?;
    budget.charge(units)?;
    // Metadata alone is sorted; all comparison/move work is prepaid. The
    // capture order and every identity/payload remain outside this operation.
    let order = identity::sorted_indices(
        shapes.len(),
        |left, right| shapes[left].compare_metadata(&shapes[right], budget),
        |units| budget.audit_move(units),
    );
    let mut destination = vec![0; shapes.len()];
    budget.audit_move(destination.len());
    for (to, from) in order.into_iter().enumerate() {
        budget.audit_move(1);
        destination[from] = to;
    }
    for index in 0..shapes.len() {
        budget.audit_visit(1);
        while destination[index] != index {
            let next = destination[index];
            shapes.swap(index, next);
            destination.swap(index, next);
            budget.audit_move(2);
        }
    }
    Ok(())
}

#[derive(Default)]
struct SelectionEstimate {
    work: Footprint,
    roots: usize,
}

impl SelectionEstimate {
    fn append(
        &mut self,
        work: &Footprint,
        roots: usize,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        self.work.append(work, budget)?;
        add_work(&mut self.roots, roots)
    }
}

impl CapturedWork {
    fn append(&mut self, other: &Self) -> Result<(), SubtreeError> {
        add_work(&mut self.nodes, other.nodes)?;
        add_work(&mut self.row_nodes, other.row_nodes)?;
        add_work(&mut self.keys, other.keys)?;
        add_work(&mut self.schema_bytes, other.schema_bytes)?;
        add_work(&mut self.key_bytes, other.key_bytes)?;
        add_work(&mut self.value_bytes, other.value_bytes)?;
        self.largest_identity = self.largest_identity.max(other.largest_identity);
        self.largest_value = self.largest_value.max(other.largest_value);
        self.largest_keys = self.largest_keys.max(other.largest_keys);
        self.largest_key_path = self.largest_key_path.max(other.largest_key_path);
        self.largest_key_value = self.largest_key_value.max(other.largest_key_value);
        Ok(())
    }

    fn copy_units(&self) -> Result<usize, SubtreeError> {
        let mut units = multiply_work(self.nodes, 2)?;
        add_work(&mut units, self.keys)?;
        add_work(&mut units, self.key_bytes)?;
        add_work(&mut units, self.value_bytes)?;
        Ok(units)
    }

    fn add_keys(&mut self, keys: &[KeySize]) -> Result<(), SubtreeError> {
        add_work(&mut self.keys, keys.len())?;
        for key in keys {
            add_work(&mut self.key_bytes, key.path.len())?;
            add_work(&mut self.key_bytes, key.bytes)?;
            self.largest_key_path = self.largest_key_path.max(key.path.len());
            self.largest_key_value = self.largest_key_value.max(key.bytes);
        }
        Ok(())
    }

    fn clamp(&mut self, cap: &Self) {
        self.nodes = self.nodes.min(cap.nodes);
        self.row_nodes = self.row_nodes.min(cap.row_nodes);
        self.keys = self.keys.min(cap.keys);
        self.schema_bytes = self.schema_bytes.min(cap.schema_bytes);
        self.key_bytes = self.key_bytes.min(cap.key_bytes);
        self.value_bytes = self.value_bytes.min(cap.value_bytes);
        self.largest_identity = self.largest_identity.min(cap.largest_identity);
        self.largest_value = self.largest_value.min(cap.largest_value);
        self.largest_keys = self.largest_keys.min(cap.largest_keys);
        self.largest_key_path = self.largest_key_path.min(cap.largest_key_path);
        self.largest_key_value = self.largest_key_value.min(cap.largest_key_value);
    }
}

#[derive(Clone)]
struct SiblingGroup {
    parent: &'static str,
    work: CapturedWork,
}

// Indexed operations stay within a sibling vector. Sum original row counts
// and retain the largest per-row tuple, instead of multiplying pooled bytes
// by pooled nodes. A pooled logarithm bounds every possible fragment join.
#[derive(Clone, Default)]
struct Footprint {
    total: CapturedWork,
    siblings: Vec<SiblingGroup>,
    // A node's stored keys participate in its parent's identity comparisons,
    // and in its own children's ordering. Keep both locations explicitly.
    child_keys: Vec<SiblingGroup>,
}

fn add_group(
    groups: &mut Vec<SiblingGroup>,
    parent: &'static str,
    work: &CapturedWork,
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    for group in groups.iter_mut() {
        budget.charge(1)?;
        budget.audit_visit(1);
        if budget.compare(group.parent, parent)? {
            return group.work.append(work);
        }
    }
    budget.charge(1)?;
    budget.audit_move(1);
    groups.push(SiblingGroup {
        parent,
        work: work.clone(),
    });
    Ok(())
}

fn clamp_groups(
    groups: &mut [SiblingGroup],
    caps: &[SiblingGroup],
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    for group in groups {
        budget.charge(1)?;
        budget.audit_visit(1);
        let mut cap = &CapturedWork::default();
        for candidate in caps {
            budget.charge(1)?;
            budget.audit_visit(1);
            if budget.compare(candidate.parent, group.parent)? {
                cap = &candidate.work;
                break;
            }
        }
        group.work.clamp(cap);
    }
    Ok(())
}

fn group_work(
    groups: &[SiblingGroup],
    parent: &str,
    budget: &SubtreeBudget,
) -> Result<CapturedWork, SubtreeError> {
    for group in groups {
        budget.charge(1)?;
        budget.audit_visit(1);
        if budget.compare(group.parent, parent)? {
            return Ok(group.work.clone());
        }
    }
    Ok(CapturedWork::default())
}

impl Footprint {
    fn shell(
        path: &'static str,
        total: CapturedWork,
        budget: &SubtreeBudget,
    ) -> Result<Self, SubtreeError> {
        budget.charge(path.len())?;
        budget.audit_visit(path.len());
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        budget.charge(1)?;
        budget.audit_move(1);
        let siblings = vec![SiblingGroup {
            parent,
            work: total.clone(),
        }];
        let mut child_keys = Vec::new();
        if total.keys != 0 {
            budget.charge(1)?;
            budget.audit_move(1);
            child_keys.push(SiblingGroup {
                parent: path,
                work: CapturedWork {
                    keys: total.keys,
                    key_bytes: total.key_bytes,
                    largest_keys: total.keys,
                    largest_key_path: total.largest_key_path,
                    largest_key_value: total.largest_key_value,
                    ..CapturedWork::default()
                },
            });
        }
        Ok(Self {
            total,
            siblings,
            child_keys,
        })
    }

    fn copy_metadata(&self, budget: &SubtreeBudget) -> Result<Self, SubtreeError> {
        budget.charge(self.siblings.len())?;
        budget.charge(self.child_keys.len())?;
        budget.audit_move(self.siblings.len());
        budget.audit_move(self.child_keys.len());
        Ok(self.clone())
    }

    fn append(&mut self, other: &Self, budget: &SubtreeBudget) -> Result<(), SubtreeError> {
        self.total.append(&other.total)?;
        for group in &other.siblings {
            add_group(&mut self.siblings, group.parent, &group.work, budget)?;
        }
        for group in &other.child_keys {
            add_group(&mut self.child_keys, group.parent, &group.work, budget)?;
        }
        Ok(())
    }

    fn copy_units(&self) -> Result<usize, SubtreeError> {
        self.total.copy_units()
    }

    fn merge_units(&self, budget: &SubtreeBudget) -> Result<usize, SubtreeError> {
        let mut units = 0;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            budget.audit_visit(1);
            add_work(&mut units, group.work.merge_units()?)?;
        }
        Ok(units)
    }

    fn selection_merge_units(&self, budget: &SubtreeBudget) -> Result<usize, SubtreeError> {
        let mut units = 0;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            budget.audit_visit(1);
            add_work(&mut units, group.work.selection_merge_units()?)?;
        }
        Ok(units)
    }

    fn position_ordering_units(&self, budget: &SubtreeBudget) -> Result<usize, SubtreeError> {
        let mut units = 0;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            budget.audit_visit(1);
            let work = &group.work;
            let mut per_node = multiply_work(sort_levels(work.row_nodes.min(work.nodes)), 2)?;
            add_work(&mut per_node, 6)?;
            add_work(&mut units, multiply_work(work.nodes, per_node)?)?;
        }
        Ok(units)
    }

    fn position_lookup_units(
        &self,
        owner_keys: &[SiblingGroup],
        budget: &SubtreeBudget,
    ) -> Result<usize, SubtreeError> {
        let mut units = 0;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            budget.audit_visit(1);
            let keys = group_work(owner_keys, group.parent, budget)?;
            if keys.largest_keys == 0 {
                continue;
            }
            let mut probe = group.work.largest_identity;
            add_work(&mut probe, keys.largest_key_path)?;
            add_work(&mut probe, 1)?;
            let mut per_node = multiply_work(probe, keys.largest_keys)?;
            add_work(&mut per_node, keys.largest_key_value)?;
            add_work(&mut per_node, group.work.largest_value)?;
            add_work(&mut per_node, 4)?;
            add_work(&mut units, multiply_work(group.work.nodes, per_node)?)?;
        }
        Ok(units)
    }

    fn limit_rows(
        &mut self,
        bounds: &[SiblingGroup],
        copies: usize,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        for group in &mut self.siblings {
            budget.charge(1)?;
            budget.audit_visit(1);
            let width = group_work(bounds, group.parent, budget)?.nodes;
            group.work.row_nodes = group.work.row_nodes.min(multiply_work(width, copies)?);
        }
        Ok(())
    }

    #[cfg(test)]
    fn ordering_units(&self, input: &Self, budget: &SubtreeBudget) -> Result<usize, SubtreeError> {
        let mut units = multiply_work(input.total.nodes, 4)?;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            budget.audit_visit(1);
            let selected = &group.work;
            let source = group_work(&input.siblings, group.parent, budget)?;
            let keys = group_work(&input.child_keys, group.parent, budget)?;
            // The selected index is built once for each parent row. Probes
            // come only from original source nodes or original captured keys.
            let mut probe = source.clone();
            probe.largest_identity = probe.largest_identity.max(keys.largest_key_path);
            probe.largest_value = probe.largest_value.max(keys.largest_key_value);
            let probes = source
                .nodes
                .checked_add(keys.keys)
                .ok_or(SubtreeError::TooBig)?;
            let mut comparison = selected.largest_identity;
            add_work(&mut comparison, probe.largest_identity)?;
            add_work(&mut comparison, selected.largest_value)?;
            add_work(&mut comparison, probe.largest_value)?;
            add_work(&mut comparison, selected.largest_keys)?;
            add_work(&mut comparison, probe.largest_keys)?;
            add_work(&mut comparison, 8)?;
            let per_probe = multiply_work(
                index_levels(selected.row_nodes.min(selected.nodes)) + 1,
                comparison,
            )?;
            add_work(&mut units, multiply_work(probes, per_probe)?)?;
            add_work(&mut units, selected.merge_units()?)?;
            add_work(&mut units, multiply_work(selected.nodes, 12)?)?;
            add_work(&mut units, multiply_work(probes, 4)?)?;
            add_work(&mut units, source.identity_bytes()?)?;
            add_work(&mut units, source.value_bytes)?;
            add_work(&mut units, keys.key_bytes)?;
        }
        Ok(units)
    }

    fn selection_cap(&self, budget: &SubtreeBudget) -> Result<Self, SubtreeError> {
        let mut cap = self.copy_metadata(budget)?;
        // Deduplication can retain every source node and materialize each
        // captured key once. Each new key scalar belongs to the owning node's
        // child group. Complete key bytes bound both path and scalar bytes.
        for group in &self.child_keys {
            let scalars = CapturedWork {
                nodes: group.work.keys,
                row_nodes: group.work.keys,
                schema_bytes: group.work.key_bytes,
                value_bytes: group.work.key_bytes,
                largest_identity: group.work.largest_key_path,
                largest_value: group.work.largest_key_value,
                ..CapturedWork::default()
            };
            cap.total.append(&scalars)?;
            add_group(&mut cap.siblings, group.parent, &scalars, budget)?;
        }
        Ok(cap)
    }

    fn clamp(&mut self, cap: &Self, budget: &SubtreeBudget) -> Result<(), SubtreeError> {
        self.total.clamp(&cap.total);
        clamp_groups(&mut self.siblings, &cap.siblings, budget)?;
        clamp_groups(&mut self.child_keys, &cap.child_keys, budget)
    }
}

fn capture_shape(
    nodes: &[NetconfXmlNode],
    registry: &dyn SchemaRegistry,
    budget: &SubtreeBudget,
    leaf_lists: &mut Vec<&'static str>,
    parent: &str,
) -> Result<Vec<Shape>, SubtreeError> {
    #[cfg(test)]
    let _audit = budget.audit_scope("capture sizing");
    budget.charge(nodes.len())?;
    let mut shapes = Vec::new();
    for node in nodes {
        budget.audit_visit(1);
        let mut path_work = node.schema_path.len();
        add_work(&mut path_work, parent.len())?;
        add_work(&mut path_work, 1)?;
        budget.charge(path_work)?;
        budget.audit_visit(node.schema_path.len());
        if node.schema_path.rsplit_once('/').map(|(parent, _)| parent) != Some(parent) {
            return Err(SubtreeError::Projection);
        }
        budget.charge(node.keys.len())?;
        let keys: Vec<_> = node
            .keys
            .iter()
            .map(|(path, value)| {
                budget.audit_move(1);
                KeySize {
                    path,
                    bytes: value.len(),
                }
            })
            .collect();
        let mut shell = CapturedWork {
            nodes: 1,
            row_nodes: 1,
            schema_bytes: node.schema_path.len(),
            value_bytes: node.value.as_ref().map_or(0, String::len),
            ..CapturedWork::default()
        };
        budget.audit_visit(keys.len());
        shell.add_keys(&keys)?;
        shell.largest_identity = shell.identity_bytes()?;
        shell.largest_value = shell.value_bytes;
        shell.largest_keys = shell.keys;
        let shell = Footprint::shell(node.schema_path, shell, budget)?;
        let metadata = budget.node(registry, node.schema_path)?;
        let kind = metadata.kind;
        // Cardinality bounds must also hold for a custom projector's capture.
        if (kind != NodeKind::List && !node.keys.is_empty())
            || (kind != NodeKind::LeafList && node.masked_ordinal.is_some())
        {
            return Err(SubtreeError::Projection);
        }
        if kind == NodeKind::List {
            if node.keys.len() != metadata.key_leaves.len() {
                return Err(SubtreeError::Projection);
            }
            for ((path, _), declared) in node.keys.iter().zip(metadata.key_leaves) {
                let mut units = path.len();
                add_work(&mut units, node.schema_path.len())?;
                add_work(&mut units, multiply_work(declared.len(), 2)?)?;
                add_work(&mut units, 2)?;
                budget.charge(units)?;
                budget.audit_visit(path.len());
                let Some((parent, name)) = path.rsplit_once('/') else {
                    return Err(SubtreeError::Projection);
                };
                let local = name.split_once(':').map_or(name, |(_, local)| local);
                if parent != node.schema_path || (name != *declared && local != *declared) {
                    return Err(SubtreeError::Projection);
                }
            }
        }
        if kind == NodeKind::LeafList {
            budget.charge(1)?;
            budget.audit_move(1);
            leaf_lists.push(node.schema_path);
        }
        let children = capture_shape(
            &node.children,
            registry,
            budget,
            leaf_lists,
            node.schema_path,
        )?;
        let mut tree = shell.copy_metadata(budget)?;
        for child in &children {
            tree.append(&child.tree, budget)?;
        }
        budget.charge(
            keys.len()
                .checked_add(children.len())
                .ok_or(SubtreeError::TooBig)?,
        )?;
        budget.audit_visit(keys.len());
        budget.audit_visit(children.len());
        let metadata_work = metadata_units(node.schema_path, &keys, &children)?;
        shapes.push(Shape {
            path: node.schema_path,
            kind,
            metadata_work,
            value_bytes: node.value.as_ref().map(String::len),
            keys,
            children,
            shell,
            tree,
        });
    }
    normalize_shapes(&mut shapes, budget)?;
    Ok(shapes)
}

fn forest_work(input: &[&Shape], budget: &SubtreeBudget) -> Result<Footprint, SubtreeError> {
    budget.charge(input.len())?;
    let mut work = Footprint::default();
    for node in input {
        budget.audit_visit(1);
        work.append(&node.tree, budget)?;
    }
    Ok(work)
}

fn scalar_work(key: &KeySize, budget: &SubtreeBudget) -> Result<Footprint, SubtreeError> {
    Footprint::shell(
        key.path,
        CapturedWork {
            nodes: 1,
            row_nodes: 1,
            schema_bytes: key.path.len(),
            value_bytes: key.bytes,
            largest_identity: key.path.len(),
            largest_value: key.bytes,
            ..CapturedWork::default()
        },
        budget,
    )
}

// After the initial join, a scalar/container schema path occurs at most once
// under any one parent. Lists and leaf-lists may retain every original node.
// These are schema bounds, not observations of a joined or selected forest.
fn row_bounds(shapes: &[Shape], budget: &SubtreeBudget) -> Result<Vec<SiblingGroup>, SubtreeError> {
    #[cfg(test)]
    let _audit = budget.audit_scope("row bounds");
    fn add_path(
        paths: &mut Vec<(&'static str, usize)>,
        path: &'static str,
        repeating: bool,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        for (previous, count) in paths.iter_mut() {
            budget.charge(1)?;
            budget.audit_visit(1);
            if budget.compare(previous, path)? {
                if repeating {
                    add_work(count, 1)?;
                }
                return Ok(());
            }
        }
        budget.charge(1)?;
        budget.audit_move(1);
        paths.push((path, 1));
        Ok(())
    }
    fn visit(
        shapes: &[Shape],
        paths: &mut Vec<(&'static str, usize)>,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        for shape in shapes {
            budget.charge(1)?;
            budget.audit_visit(1);
            add_path(
                paths,
                shape.path,
                matches!(shape.kind, NodeKind::List | NodeKind::LeafList),
                budget,
            )?;
            for key in &shape.keys {
                budget.charge(1)?;
                budget.audit_visit(1);
                add_path(paths, key.path, false, budget)?;
            }
            visit(&shape.children, paths, budget)?;
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(shapes, &mut paths, budget)?;
    let mut groups = Vec::new();
    for (path, nodes) in paths {
        budget.charge(path.len())?;
        budget.audit_visit(path.len());
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        add_group(
            &mut groups,
            parent,
            &CapturedWork {
                nodes,
                ..CapturedWork::default()
            },
            budget,
        )?;
    }
    Ok(groups)
}

pub(super) struct EvaluationWork {
    pub(super) units: usize,
    pub(super) predicate_trials: usize,
    pub(super) leaf_lists: Vec<&'static str>,
    leaf_list_bytes: usize,
    row_bounds: Vec<SiblingGroup>,
    owner_keys: Vec<SiblingGroup>,
}

impl EvaluationWork {
    pub(super) fn measure(
        scopes: &[SubtreeScope],
        input: &[NetconfXmlNode],
        registry: &dyn SchemaRegistry,
        budget: &SubtreeBudget,
    ) -> Result<Self, SubtreeError> {
        #[cfg(test)]
        let _audit = budget.audit_scope("sizing");
        let mut work = Self {
            units: 0,
            predicate_trials: 0,
            leaf_lists: Vec::new(),
            leaf_list_bytes: 0,
            row_bounds: Vec::new(),
            owner_keys: Vec::new(),
        };
        let shapes = capture_shape(input, registry, budget, &mut work.leaf_lists, "")?;
        work.row_bounds = row_bounds(&shapes, budget)?;
        budget.charge(shapes.len())?;
        let input: Vec<_> = shapes
            .iter()
            .inspect(|_| {
                budget.audit_move(1);
            })
            .collect();
        let raw = forest_work(&input, budget)?;
        budget.charge(raw.child_keys.len())?;
        budget.audit_move(raw.child_keys.len());
        work.owner_keys = raw.child_keys.clone();
        work.leaf_list_bytes = normalize_leaf_lists(&mut work.leaf_lists, budget)?;
        add_work(&mut work.units, raw.copy_units()?)?;
        work.merge(&raw, input.len(), budget)?;
        let mut candidates = SelectionEstimate::default();
        for scope in scopes {
            budget.charge(1)?;
            budget.audit_visit(1);
            let selected = work.scope(scope, &input, &[], "", budget)?;
            add_work(&mut work.units, selected.roots)?;
            candidates.append(&selected.work, selected.roots, budget)?;
        }
        work.merge_selection(&candidates.work, candidates.roots, "", budget)?;
        candidates.work.clamp(&raw.selection_cap(budget)?, budget)?;
        candidates.work.limit_rows(&work.row_bounds, 1, budget)?;
        add_work(
            &mut work.units,
            candidates.work.position_ordering_units(budget)?,
        )?;
        Ok(work)
    }

    fn merge(
        &mut self,
        captured: &Footprint,
        _roots: usize,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        add_work(&mut self.units, captured.merge_units(budget)?)?;
        add_work(
            &mut self.units,
            leaf_probe_units(
                &captured.total,
                captured.total.nodes,
                self.leaf_lists.len(),
                self.leaf_list_bytes,
            )?,
        )
    }

    fn merge_selection(
        &mut self,
        candidates: &Footprint,
        roots: usize,
        parent: &str,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        // Each scope merge starts empty. With at most one possible incoming
        // root across all instances, insertion cannot compare identities or
        // recurse into children. This bound uses original-fragment counts,
        // never the number of roots left by an actual identity merge.
        let width = group_work(&candidates.siblings, parent, budget)?.row_nodes;
        if roots <= 1 || width <= 1 {
            add_work(&mut self.units, roots)
        } else {
            add_work(&mut self.units, candidates.selection_merge_units(budget)?)
        }
    }

    fn copy(&mut self, input: &Footprint, budget: &SubtreeBudget) -> Result<(), SubtreeError> {
        add_work(&mut self.units, input.copy_units()?)?;
        add_work(
            &mut self.units,
            input.position_lookup_units(&self.owner_keys, budget)?,
        )
    }

    fn path_probe(
        &mut self,
        left: &str,
        right: &str,
        budget: &SubtreeBudget,
    ) -> Result<bool, SubtreeError> {
        add_work(&mut self.units, 1)?;
        add_work(&mut self.units, left.len())?;
        add_work(&mut self.units, right.len())?;
        // These comparisons concern schema paths, never captured identities.
        budget.charge(1)?;
        budget.compare(left, right)
    }

    fn predicate(&mut self, predicate: &ScalarPredicate, bytes: usize) -> Result<(), SubtreeError> {
        add_work(&mut self.predicate_trials, 1)?;
        add_work(&mut self.units, 1)?;
        add_work(&mut self.units, predicate.comparison_work(bytes)?)
    }

    fn select(
        &mut self,
        input: &Footprint,
        outputs: &[SubtreeOutput],
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        // All descendants may be visited and copied, including an ancestor
        // shell made necessary by a child from another coalescing fragment.
        add_work(&mut self.units, input.total.nodes)?;
        budget.charge(outputs.len())?;
        for output in outputs {
            budget.audit_visit(1);
            let per_node = output
                .path
                .len()
                .checked_add(1)
                .ok_or(SubtreeError::TooBig)?;
            add_work(&mut self.units, multiply_work(input.total.nodes, per_node)?)?;
            add_work(&mut self.units, input.total.schema_bytes)?;
        }
        self.copy(input, budget)
    }

    fn scope(
        &mut self,
        scope: &SubtreeScope,
        input: &[&Shape],
        keys: &[KeySize],
        parent: &'static str,
        budget: &SubtreeBudget,
    ) -> Result<SelectionEstimate, SubtreeError> {
        #[cfg(test)]
        let _audit = budget.audit_scope("scope sizing");
        let mut available = forest_work(input, budget)?;
        available.limit_rows(&self.row_bounds, 1, budget)?;
        let mut candidates = SelectionEstimate::default();
        budget.charge(scope.predicates.len())?;
        for predicate in &scope.predicates {
            budget.audit_visit(1);
            budget.charge(predicate.alternatives.len())?;
            for alternative in &predicate.alternatives {
                budget.audit_visit(1);
                for key in keys {
                    if self.path_probe(key.path, alternative.path, budget)? {
                        self.predicate(&alternative.predicate, key.bytes)?;
                        let scalar = scalar_work(key, budget)?;
                        self.copy(&scalar, budget)?;
                        candidates.append(&scalar, 1, budget)?;
                    }
                }
                for node in input {
                    if self.path_probe(node.path, alternative.path, budget)? {
                        if let Some(bytes) = node.value_bytes {
                            self.predicate(&alternative.predicate, bytes)?;
                            add_work(&mut self.units, 1)?;
                            self.copy(&node.shell, budget)?;
                            candidates.append(&node.shell, 1, budget)?;
                        }
                    }
                }
            }
        }
        if !scope.implicit_outputs.is_empty() {
            self.select(&available, &scope.implicit_outputs, budget)?;
            candidates.append(&available, input.len(), budget)?;
        }
        budget.charge(scope.branches.len())?;
        for branch in &scope.branches {
            budget.audit_visit(1);
            for key in keys {
                if self.path_probe(key.path, branch.path, budget)? && branch.children.is_none() {
                    for output in &branch.outputs {
                        self.path_probe(output.path, key.path, budget)?;
                    }
                    let scalar = scalar_work(key, budget)?;
                    self.copy(&scalar, budget)?;
                    candidates.append(&scalar, 1, budget)?;
                }
            }
            let mut matching = Vec::new();
            for node in input {
                if self.path_probe(node.path, branch.path, budget)? {
                    budget.charge(1)?;
                    budget.audit_move(1);
                    matching.push(*node);
                }
            }
            if let Some(child_scope) = &branch.children {
                let mut children = Vec::new();
                let mut child_keys = Vec::new();
                for node in matching {
                    budget.charge(node.children.len())?;
                    budget.charge(node.keys.len())?;
                    budget.audit_move(node.children.len());
                    children.extend(node.children.iter());
                    budget.audit_move(node.keys.len());
                    child_keys.extend_from_slice(&node.keys);
                    self.copy(&node.shell, budget)?;
                    candidates.append(&node.shell, 1, budget)?;
                }
                // Original row totals cover all possible coalescing fragments.
                // Merge/order costs use each row's tuple maxima and an index
                // depth, never a product of pooled node and byte totals.
                let selected =
                    self.scope(child_scope, &children, &child_keys, branch.path, budget)?;
                candidates.work.append(&selected.work, budget)?;
            } else {
                let mut selected = forest_work(&matching, budget)?;
                selected.limit_rows(&self.row_bounds, 1, budget)?;
                self.select(&selected, &branch.outputs, budget)?;
                candidates.append(&selected, matching.len(), budget)?;
            }
        }
        // Each predicate/selection can contribute a copy of a joined input.
        // Keys can also be materialized as scalars. The multiplicity comes
        // only from the request; schema cardinality bounds each row's width.
        let mut copies = usize::from(!scope.implicit_outputs.is_empty());
        for predicate in &scope.predicates {
            add_work(&mut copies, multiply_work(predicate.alternatives.len(), 2)?)?;
        }
        for branch in &scope.branches {
            add_work(&mut copies, if branch.children.is_some() { 1 } else { 2 })?;
        }
        candidates
            .work
            .limit_rows(&self.row_bounds, copies, budget)?;
        self.merge_selection(&candidates.work, candidates.roots, parent, budget)?;
        let mut cap = available.selection_cap(budget)?;
        budget.charge(keys.len())?;
        for key in keys {
            budget.audit_visit(1);
            cap.append(&scalar_work(key, budget)?, budget)?;
        }
        candidates.work.clamp(&cap, budget)?;
        candidates.work.limit_rows(&self.row_bounds, 1, budget)?;
        candidates.roots = candidates.roots.min(
            input
                .len()
                .checked_add(keys.len())
                .ok_or(SubtreeError::TooBig)?,
        );
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_normalization_charges_the_sum_at_each_level() {
        fn shape(children: Vec<Shape>) -> Shape {
            let path = "/m:root";
            Shape {
                path,
                kind: NodeKind::Container,
                metadata_work: metadata_units(path, &[], &children).unwrap(),
                value_bytes: None,
                keys: Vec::new(),
                children,
                shell: Footprint::default(),
                tree: Footprint::default(),
            }
        }
        for count in [0, 1, 2, 7, 100, 1024] {
            let large = shape((0..100).map(|_| shape(Vec::new())).collect());
            let large_metadata = large.metadata_work;
            let small_metadata = shape(Vec::new()).metadata_work;
            let mut shapes = vec![large];
            shapes.extend((0..count).map(|_| shape(Vec::new())));
            let n = count + 1;
            let expected = n
                + sort_levels(n) * (2 * (large_metadata + count * small_metadata) + 2 * n)
                + 8 * n;
            let budget = SubtreeBudget::new(usize::MAX, 0).unwrap();
            normalize_shapes(&mut shapes, &budget).unwrap();
            assert_eq!(
                usize::MAX - budget.remaining(),
                expected,
                "{count} small shapes"
            );
        }
    }

    #[test]
    fn metadata_normalization_preserves_charges_across_interleaved_schema_groups() {
        fn shape(path: &'static str, children: Vec<Shape>, budget: &SubtreeBudget) -> Shape {
            let value_bytes = children.is_empty().then_some(5);
            let shell = Footprint::shell(
                path,
                CapturedWork {
                    nodes: 1,
                    schema_bytes: path.len(),
                    value_bytes: value_bytes.unwrap_or(0),
                    ..CapturedWork::default()
                },
                budget,
            )
            .unwrap();
            let mut tree = shell.copy_metadata(budget).unwrap();
            for child in &children {
                tree.append(&child.tree, budget).unwrap();
            }
            Shape {
                path,
                kind: if children.is_empty() {
                    NodeKind::Leaf
                } else {
                    NodeKind::Container
                },
                metadata_work: metadata_units(path, &[], &children).unwrap(),
                value_bytes,
                keys: Vec::new(),
                children,
                shell,
                tree,
            }
        }
        let mut expected = None;
        for order in [[0, 0, 1], [0, 1, 0], [1, 0, 0]] {
            let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
            let mut captures = Vec::new();
            for index in order {
                let (branch, leaf) = [
                    ("/m:root/m:a", "/m:root/m:a/m:value"),
                    ("/m:root/m:b", "/m:root/m:b/m:value"),
                ][index];
                let leaf = shape(leaf, Vec::new(), &budget);
                let branch = shape(branch, vec![leaf], &budget);
                captures.push(shape("/m:root", vec![branch], &budget));
            }
            normalize_shapes(&mut captures, &budget).unwrap();
            let nodes: Vec<_> = captures.iter().collect();
            let footprint = forest_work(&nodes, &budget).unwrap();
            assert_eq!(footprint.total.nodes, 9);
            if let Some(expected) = expected {
                assert_eq!(budget.remaining(), expected);
            } else {
                expected = Some(budget.remaining());
            }
        }
    }

    #[test]
    fn evaluation_envelope_arithmetic_is_checked() {
        let one = CapturedWork {
            nodes: 1,
            keys: 1,
            schema_bytes: 1,
            key_bytes: 1,
            value_bytes: 1,
            ..CapturedWork::default()
        };
        for field in 0..5 {
            let mut value = one.clone();
            match field {
                0 => value.nodes = usize::MAX,
                1 => value.keys = usize::MAX,
                2 => value.schema_bytes = usize::MAX,
                3 => value.key_bytes = usize::MAX,
                4 => value.value_bytes = usize::MAX,
                _ => unreachable!(),
            }
            assert_eq!(value.clone().append(&one), Err(SubtreeError::TooBig));
            let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
            let shape = Footprint::shell("/m:a", value.clone(), &budget).unwrap();
            assert_eq!(
                shape.selection_cap(&budget).err(),
                Some(SubtreeError::TooBig)
            );
            assert_eq!(shape.merge_units(&budget), Err(SubtreeError::TooBig));
            assert_eq!(
                shape.ordering_units(&shape, &budget),
                Err(SubtreeError::TooBig)
            );
            if field != 2 {
                assert_eq!(value.copy_units(), Err(SubtreeError::TooBig));
            }
        }
        let counted = CapturedWork {
            row_nodes: 1,
            largest_identity: 1,
            largest_value: 1,
            largest_keys: 1,
            largest_key_path: 1,
            largest_key_value: 1,
            ..one.clone()
        };
        for field in 0..6 {
            let mut value = counted.clone();
            match field {
                0 => value.row_nodes = usize::MAX,
                1 => value.largest_identity = usize::MAX,
                2 => value.largest_value = usize::MAX,
                3 => value.largest_keys = usize::MAX,
                4 => value.largest_key_path = usize::MAX,
                5 => value.largest_key_value = usize::MAX,
                _ => unreachable!(),
            }
            let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
            if field == 0 {
                assert_eq!(value.clone().append(&counted), Err(SubtreeError::TooBig));
            } else if field <= 3 {
                assert_eq!(value.merge_units(), Err(SubtreeError::TooBig));
            }
            if field != 0 {
                let shape = Footprint::shell("/m:a", value.clone(), &budget).unwrap();
                let owners = [SiblingGroup {
                    parent: "",
                    work: value,
                }];
                assert_eq!(
                    shape.position_lookup_units(&owners, &budget),
                    Err(SubtreeError::TooBig)
                );
            }
        }
        let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
        let huge = CapturedWork {
            nodes: usize::MAX,
            row_nodes: usize::MAX,
            ..counted.clone()
        };
        assert_eq!(huge.selection_merge_units(), Err(SubtreeError::TooBig));
        let shape = Footprint::shell("/m:a", huge, &budget).unwrap();
        assert_eq!(
            shape.selection_merge_units(&budget),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            shape.position_ordering_units(&budget),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            shape.position_lookup_units(
                &[SiblingGroup {
                    parent: "",
                    work: counted.clone()
                }],
                &budget
            ),
            Err(SubtreeError::TooBig)
        );
        let mut shape = Footprint::shell("/m:a", counted, &budget).unwrap();
        let bounds = [SiblingGroup {
            parent: "",
            work: CapturedWork {
                nodes: usize::MAX,
                ..CapturedWork::default()
            },
        }];
        assert_eq!(
            shape.limit_rows(&bounds, 2, &budget),
            Err(SubtreeError::TooBig)
        );
        let make = || EvaluationWork {
            units: 0,
            predicate_trials: 0,
            leaf_lists: Vec::new(),
            leaf_list_bytes: 0,
            row_bounds: Vec::new(),
            owner_keys: Vec::new(),
        };
        let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
        let mut work = make();
        work.units = usize::MAX;
        assert_eq!(
            work.path_probe("/m:a", "/m:a", &budget),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(budget.remaining(), 1_000_000);
        let mut work = make();
        work.leaf_list_bytes = usize::MAX;
        let one = Footprint::shell("/m:a", one, &budget).unwrap();
        assert_eq!(work.merge(&one, 2, &budget), Err(SubtreeError::TooBig));
        let mut work = make();
        let nodes = Footprint {
            total: CapturedWork {
                nodes: usize::MAX,
                ..CapturedWork::default()
            },
            ..Footprint::default()
        };
        assert_eq!(
            work.select(
                &nodes,
                &[SubtreeOutput {
                    path: "/m:a",
                    keys: Vec::new()
                }],
                &budget
            ),
            Err(SubtreeError::TooBig)
        );
    }
}
