//! One envelope for every phase downstream of the first identity join.
//!
//! Sizing uses only the original capture's schema paths, counts and lengths.
//! `Shape` deliberately cannot hold a key identity or a scalar value. Scope
//! estimates pool all possible parent instances before bounding comparisons;
//! they never assume that two capture fragments will, or will not, coalesce.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KeySize {
    path: &'static str,
    bytes: usize,
}

struct Shape {
    path: &'static str,
    value_bytes: Option<usize>,
    keys: Vec<KeySize>,
    children: Vec<Shape>,
    shell: Footprint,
    tree: Footprint,
}

impl Shape {
    fn compare_metadata(&self, other: &Self) -> std::cmp::Ordering {
        self.path
            .cmp(other.path)
            .then_with(|| self.value_bytes.cmp(&other.value_bytes))
            .then_with(|| self.keys.cmp(&other.keys))
            .then_with(|| {
                self.children
                    .iter()
                    .zip(&other.children)
                    .map(|(left, right)| left.compare_metadata(right))
                    .find(|order| !order.is_eq())
                    .unwrap_or_else(|| self.children.len().cmp(&other.children.len()))
            })
    }
}

fn normalize_shapes(shapes: &mut [Shape], budget: &SubtreeBudget) -> Result<(), SubtreeError> {
    budget.charge(shapes.len())?;
    let mut comparison = 0;
    for shape in shapes.iter() {
        let mut units = multiply_work(shape.tree.total.nodes, 4)?;
        add_work(&mut units, multiply_work(shape.tree.total.keys, 2)?)?;
        add_work(&mut units, shape.tree.total.identity_bytes()?)?;
        comparison = comparison.max(units);
    }
    let pairs = multiply_work(shapes.len(), shapes.len().saturating_sub(1))? / 2;
    let per_pair = multiply_work(comparison, 2)?
        .checked_add(2)
        .ok_or(SubtreeError::TooBig)?;
    budget.charge(multiply_work(pairs, per_pair)?)?;
    // Only metadata is sorted. The real captured data keeps its input order.
    // Prepay the entire insertion sort, including early equal-prefix exits.
    for index in 1..shapes.len() {
        let mut current = index;
        while current > 0
            && shapes[current - 1]
                .compare_metadata(&shapes[current])
                .is_gt()
        {
            shapes.swap(current - 1, current);
            current -= 1;
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
        add_work(&mut self.keys, other.keys)?;
        add_work(&mut self.schema_bytes, other.schema_bytes)?;
        add_work(&mut self.key_bytes, other.key_bytes)?;
        add_work(&mut self.value_bytes, other.value_bytes)
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
        }
        Ok(())
    }

    fn clamp(&mut self, cap: &Self) {
        self.nodes = self.nodes.min(cap.nodes);
        self.keys = self.keys.min(cap.keys);
        self.schema_bytes = self.schema_bytes.min(cap.schema_bytes);
        self.key_bytes = self.key_bytes.min(cap.key_bytes);
        self.value_bytes = self.value_bytes.min(cap.value_bytes);
    }
}

#[derive(Clone)]
struct SiblingGroup {
    parent: &'static str,
    work: CapturedWork,
}

// Comparisons and vector shifts stay within a sibling vector. Group by its
// schema parent, pooling ALL original instances of that parent. Thus grouping
// never assumes anything about equality of captured row identities.
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
        if budget.compare(group.parent, parent)? {
            return group.work.append(work);
        }
    }
    budget.charge(1)?;
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
        let mut cap = &CapturedWork::default();
        for candidate in caps {
            budget.charge(1)?;
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
        let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
        budget.charge(1)?;
        let siblings = vec![SiblingGroup {
            parent,
            work: total.clone(),
        }];
        let mut child_keys = Vec::new();
        if total.keys != 0 {
            budget.charge(1)?;
            child_keys.push(SiblingGroup {
                parent: path,
                work: CapturedWork {
                    keys: total.keys,
                    key_bytes: total.key_bytes,
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
            let work = &group.work;
            let mut per_node = multiply_work(work.identity_bytes()?, 2)?;
            add_work(&mut per_node, multiply_work(work.value_bytes, 4)?)?;
            add_work(&mut per_node, multiply_work(work.keys, 2)?)?;
            add_work(&mut per_node, 8)?;
            add_work(&mut units, multiply_work(work.nodes, per_node)?)?;
            add_work(
                &mut units,
                multiply_work(multiply_work(work.nodes, work.nodes)?, 4)?,
            )?;
        }
        Ok(units)
    }

    fn ordering_units(&self, input: &Self, budget: &SubtreeBudget) -> Result<usize, SubtreeError> {
        // Input and selection have distinct roles: only input nodes probe,
        // only selected nodes move, and only input keys order child scalars.
        // Pooling instances by schema still bounds every possible correlation.
        let mut units = multiply_work(input.total.nodes, 4)?;
        budget.charge(self.siblings.len())?;
        for group in &self.siblings {
            let selected = &group.work;
            let source = group_work(&input.siblings, group.parent, budget)?;
            let keys = group_work(&input.child_keys, group.parent, budget)?;
            add_work(&mut units, multiply_work(selected.nodes, 4)?)?;
            add_work(&mut units, multiply_work(keys.keys, 4)?)?;
            let source_probes = source
                .nodes
                .checked_add(keys.keys)
                .ok_or(SubtreeError::TooBig)?;
            add_work(
                &mut units,
                multiply_work(multiply_work(selected.nodes, source_probes)?, 4)?,
            )?;
            add_work(
                &mut units,
                multiply_work(multiply_work(selected.nodes, selected.nodes)?, 2)?,
            )?;
            let mut source_bytes = source.identity_bytes()?;
            add_work(&mut source_bytes, source.value_bytes)?;
            add_work(&mut source_bytes, multiply_work(source.keys, 2)?)?;
            add_work(&mut source_bytes, keys.key_bytes)?;
            add_work(&mut units, multiply_work(selected.nodes, source_bytes)?)?;
            let mut selected_bytes = selected.identity_bytes()?;
            add_work(&mut selected_bytes, selected.value_bytes)?;
            add_work(&mut selected_bytes, multiply_work(selected.keys, 2)?)?;
            add_work(&mut units, multiply_work(source.nodes, selected_bytes)?)?;
            let key_scalar_bytes = selected
                .schema_bytes
                .checked_add(selected.value_bytes)
                .ok_or(SubtreeError::TooBig)?;
            add_work(&mut units, multiply_work(keys.keys, key_scalar_bytes)?)?;
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
                schema_bytes: group.work.key_bytes,
                value_bytes: group.work.key_bytes,
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
) -> Result<Vec<Shape>, SubtreeError> {
    budget.charge(nodes.len())?;
    let mut shapes = Vec::new();
    for node in nodes {
        budget.charge(node.keys.len())?;
        let keys: Vec<_> = node
            .keys
            .iter()
            .map(|(path, value)| KeySize {
                path,
                bytes: value.len(),
            })
            .collect();
        let mut shell = CapturedWork {
            nodes: 1,
            schema_bytes: node.schema_path.len(),
            value_bytes: node.value.as_ref().map_or(0, String::len),
            ..CapturedWork::default()
        };
        shell.add_keys(&keys)?;
        let shell = Footprint::shell(node.schema_path, shell, budget)?;
        if budget.node(registry, node.schema_path)?.kind == NodeKind::LeafList {
            budget.charge(1)?;
            leaf_lists.push(node.schema_path);
        }
        let children = capture_shape(&node.children, registry, budget, leaf_lists)?;
        let mut tree = shell.copy_metadata(budget)?;
        for child in &children {
            tree.append(&child.tree, budget)?;
        }
        shapes.push(Shape {
            path: node.schema_path,
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
        work.append(&node.tree, budget)?;
    }
    Ok(work)
}

fn scalar_work(key: &KeySize, budget: &SubtreeBudget) -> Result<Footprint, SubtreeError> {
    Footprint::shell(
        key.path,
        CapturedWork {
            nodes: 1,
            schema_bytes: key.path.len(),
            value_bytes: key.bytes,
            ..CapturedWork::default()
        },
        budget,
    )
}

pub(super) struct EvaluationWork {
    pub(super) units: usize,
    pub(super) predicate_trials: usize,
    pub(super) leaf_lists: Vec<&'static str>,
    leaf_list_bytes: usize,
}

impl EvaluationWork {
    pub(super) fn measure(
        scopes: &[SubtreeScope],
        input: &[NetconfXmlNode],
        registry: &dyn SchemaRegistry,
        budget: &SubtreeBudget,
    ) -> Result<Self, SubtreeError> {
        let mut work = Self {
            units: 0,
            predicate_trials: 0,
            leaf_lists: Vec::new(),
            leaf_list_bytes: 0,
        };
        let shapes = capture_shape(input, registry, budget, &mut work.leaf_lists)?;
        budget.charge(shapes.len())?;
        let input: Vec<_> = shapes.iter().collect();
        let raw = forest_work(&input, budget)?;
        budget.charge(work.leaf_lists.len())?;
        for path in &work.leaf_lists {
            add_work(&mut work.leaf_list_bytes, path.len())?;
        }
        add_work(&mut work.units, raw.copy_units()?)?;
        work.merge(&raw, input.len(), budget)?;
        let mut candidates = SelectionEstimate::default();
        for scope in scopes {
            budget.charge(1)?;
            let selected = work.scope(scope, &input, &[], budget)?;
            add_work(&mut work.units, selected.roots)?;
            candidates.append(&selected.work, selected.roots, budget)?;
        }
        work.merge(&candidates.work, candidates.roots, budget)?;
        candidates.work.clamp(&raw.selection_cap(budget)?, budget)?;
        add_work(
            &mut work.units,
            candidates.work.ordering_units(&raw, budget)?,
        )?;
        Ok(work)
    }

    fn merge(
        &mut self,
        candidates: &Footprint,
        roots: usize,
        budget: &SubtreeBudget,
    ) -> Result<(), SubtreeError> {
        // Each scope merge starts empty. With at most one possible incoming
        // root across all instances, insertion cannot compare identities or
        // recurse into children. This bound uses original-fragment counts,
        // never the number of roots left by an actual identity merge.
        let visits = if roots <= 1 {
            add_work(&mut self.units, roots)?;
            roots
        } else {
            add_work(&mut self.units, candidates.merge_units(budget)?)?;
            candidates.total.nodes
        };
        // Every merge uses the same complete capture's leaf-list schema table.
        // A small selection can therefore scan more entries than it has nodes.
        let count = self.leaf_lists.len();
        add_work(&mut self.units, multiply_work(visits, count)?)?;
        add_work(
            &mut self.units,
            multiply_work(visits, self.leaf_list_bytes)?,
        )?;
        add_work(
            &mut self.units,
            multiply_work(count, candidates.total.schema_bytes)?,
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
            let per_node = output
                .path
                .len()
                .checked_add(1)
                .ok_or(SubtreeError::TooBig)?;
            add_work(&mut self.units, multiply_work(input.total.nodes, per_node)?)?;
            add_work(&mut self.units, input.total.schema_bytes)?;
        }
        add_work(&mut self.units, input.copy_units()?)
    }

    fn scope(
        &mut self,
        scope: &SubtreeScope,
        input: &[&Shape],
        keys: &[KeySize],
        budget: &SubtreeBudget,
    ) -> Result<SelectionEstimate, SubtreeError> {
        let available = forest_work(input, budget)?;
        let mut candidates = SelectionEstimate::default();
        budget.charge(scope.predicates.len())?;
        for predicate in &scope.predicates {
            budget.charge(predicate.alternatives.len())?;
            for alternative in &predicate.alternatives {
                for key in keys {
                    if self.path_probe(key.path, alternative.path, budget)? {
                        self.predicate(&alternative.predicate, key.bytes)?;
                        let scalar = scalar_work(key, budget)?;
                        add_work(&mut self.units, scalar.copy_units()?)?;
                        candidates.append(&scalar, 1, budget)?;
                    }
                }
                for node in input {
                    if self.path_probe(node.path, alternative.path, budget)? {
                        if let Some(bytes) = node.value_bytes {
                            self.predicate(&alternative.predicate, bytes)?;
                            add_work(&mut self.units, 1)?;
                            add_work(&mut self.units, node.shell.copy_units()?)?;
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
            for key in keys {
                if self.path_probe(key.path, branch.path, budget)? && branch.children.is_none() {
                    for output in &branch.outputs {
                        self.path_probe(output.path, key.path, budget)?;
                    }
                    let scalar = scalar_work(key, budget)?;
                    add_work(&mut self.units, scalar.copy_units()?)?;
                    candidates.append(&scalar, 1, budget)?;
                }
            }
            let mut matching = Vec::new();
            for node in input {
                if self.path_probe(node.path, branch.path, budget)? {
                    budget.charge(1)?;
                    matching.push(*node);
                }
            }
            if let Some(child_scope) = &branch.children {
                let mut children = Vec::new();
                let mut child_keys = Vec::new();
                for node in matching {
                    budget.charge(node.children.len())?;
                    budget.charge(node.keys.len())?;
                    children.extend(node.children.iter());
                    child_keys.extend_from_slice(&node.keys);
                    add_work(&mut self.units, node.shell.copy_units()?)?;
                    candidates.append(&node.shell, 1, budget)?;
                }
                // Pool all original fragments for this schema scope. Bounding
                // each fragment separately would miss comparisons and children
                // that become siblings after a masked-identity join.
                let selected = self.scope(child_scope, &children, &child_keys, budget)?;
                candidates.work.append(&selected.work, budget)?;
            } else {
                let selected = forest_work(&matching, budget)?;
                self.select(&selected, &branch.outputs, budget)?;
                candidates.append(&selected, matching.len(), budget)?;
            }
        }
        self.merge(&candidates.work, candidates.roots, budget)?;
        let mut cap = available.selection_cap(budget)?;
        budget.charge(keys.len())?;
        for key in keys {
            cap.append(&scalar_work(key, budget)?, budget)?;
        }
        candidates.work.clamp(&cap, budget)?;
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
        let make = || EvaluationWork {
            units: 0,
            predicate_trials: 0,
            leaf_lists: Vec::new(),
            leaf_list_bytes: 0,
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
