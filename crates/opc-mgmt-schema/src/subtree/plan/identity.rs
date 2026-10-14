//! Indexed executors spend one admission made from the original captures.

use super::*;
use std::cmp::Ordering;

/// Bottom-up stable merge sort of positions. Each pass compares and moves at
/// most `len` positions, and there are `sort_levels(len)` passes.
/// Moving positions avoids copying trees or shifting a sibling vector.
pub(super) fn sorted_indices(
    len: usize,
    mut compare: impl FnMut(usize, usize) -> Ordering,
    mut moves: impl FnMut(usize),
) -> Vec<usize> {
    let mut order: Vec<_> = (0..len).collect();
    let mut scratch = vec![0; len];
    moves(len);
    moves(len);
    let mut width = 1usize;
    while width < len {
        let mut start = 0;
        while start < len {
            let middle = start.saturating_add(width).min(len);
            let end = middle.saturating_add(width).min(len);
            let (mut left, mut right) = (start, middle);
            for slot in &mut scratch[start..end] {
                if left < middle && (right == end || !compare(order[left], order[right]).is_gt()) {
                    *slot = order[left];
                    left += 1;
                } else {
                    *slot = order[right];
                    right += 1;
                }
                moves(1);
            }
            start = end;
        }
        std::mem::swap(&mut order, &mut scratch);
        width = width.saturating_mul(2);
    }
    order
}

/// Proof that a complete identity phase was admitted before its first compare.
/// Early exits may save CPU work but never change or refund the shared charge.
pub(super) struct IdentityReservation {
    #[cfg(test)]
    audit: std::cell::Cell<WorkAudit>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct WorkAudit {
    pub(super) admitted: usize,
    pub(super) executor_allowance: usize,
    pub(super) comparisons: usize,
    pub(super) copies: usize,
    pub(super) moves: usize,
}

#[cfg(test)]
impl WorkAudit {
    pub(super) fn actual(self) -> usize {
        self.comparisons
            .checked_add(self.copies)
            .and_then(|units| units.checked_add(self.moves))
            .expect("executor work overflow")
    }
}

#[cfg(test)]
std::thread_local! {
    static AUDITS: std::cell::RefCell<Vec<WorkAudit>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn take_audits() -> Vec<WorkAudit> {
    AUDITS.with(|audits| std::mem::take(&mut *audits.borrow_mut()))
}

#[cfg(test)]
impl Drop for IdentityReservation {
    fn drop(&mut self) {
        let audit = self.audit.get();
        AUDITS.with(|audits| audits.borrow_mut().push(audit));
        if !std::thread::panicking() {
            assert!(audit.actual() <= audit.executor_allowance, "{audit:?}");
        }
    }
}

impl IdentityReservation {
    pub(super) fn admit(budget: &SubtreeBudget, units: usize) -> Result<Self, SubtreeError> {
        budget.charge(units)?;
        Ok(Self {
            #[cfg(test)]
            audit: std::cell::Cell::new(WorkAudit {
                admitted: units,
                executor_allowance: units,
                ..WorkAudit::default()
            }),
        })
    }

    #[cfg(test)]
    pub(super) fn executor_allowance(&self, units: usize) {
        self.audit.update(|mut audit| {
            assert!(units <= audit.admitted);
            audit.executor_allowance = units;
            audit
        });
    }

    pub(super) fn moved(&self, _units: usize) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.moves = audit.moves.checked_add(_units).expect("move work overflow");
            audit
        });
    }

    fn copied(&self, _units: usize) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.copies = audit
                .copies
                .checked_add(_units)
                .expect("copy work overflow");
            audit
        });
    }

    pub(super) fn compared(&self, _units: usize) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.comparisons = audit
                .comparisons
                .checked_add(_units)
                .expect("compare work overflow");
            audit
        });
    }

    fn text_cmp(&self, left: &str, right: &str) -> Ordering {
        #[cfg(test)]
        {
            // Count byte comparisons at the operation, including equal prefixes.
            // No reservation formula or original-capture estimate is used here.
            for (left, right) in left.bytes().zip(right.bytes()) {
                self.compared(1);
                let order = left.cmp(&right);
                if !order.is_eq() {
                    return order;
                }
            }
            self.compared(1);
            left.len().cmp(&right.len())
        }
        #[cfg(not(test))]
        left.cmp(right)
    }

    pub(super) fn path_eq(&self, left: &str, right: &str) -> bool {
        self.text_cmp(left, right).is_eq()
    }

    fn identity_cmp(&self, left: &NetconfXmlNode, right: &NetconfXmlNode) -> Ordering {
        self.text_cmp(left.schema_path, right.schema_path)
            .then_with(|| {
                for ((left_path, left_value), (right_path, right_value)) in
                    left.keys.iter().zip(&right.keys)
                {
                    self.compared(1);
                    let order = self
                        .text_cmp(left_path, right_path)
                        .then_with(|| self.text_cmp(left_value, right_value));
                    if !order.is_eq() {
                        return order;
                    }
                }
                self.compared(1);
                left.keys.len().cmp(&right.keys.len())
            })
            .then_with(|| {
                self.compared(1);
                left.masked_ordinal.cmp(&right.masked_ordinal)
            })
    }

    fn value_cmp(&self, left: &Option<String>, right: &Option<String>) -> Ordering {
        self.compared(1);
        match (left, right) {
            (Some(left), Some(right)) => self.text_cmp(left, right),
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
        }
    }

    pub(super) fn matches(&self, predicate: &ScalarPredicate, reported: &str) -> bool {
        self.compared(1);
        // Text equality uses the same byte counter as identity comparisons.
        // Typed parsing visits at most the reported bytes, counted separately
        // from the indexed executors and without inspecting any hidden value.
        if let super::super::ScalarValue::Text(expected) = &predicate.value {
            return self.path_eq(expected, reported);
        }
        if matches!(&predicate.value, super::super::ScalarValue::Never) {
            return false;
        }
        self.compared(reported.len());
        predicate.matches_value(reported)
    }

    pub(super) fn scalar(&self, path: &'static str, value: &str) -> NetconfXmlNode {
        self.copied(2 + value.len());
        NetconfXmlNode::scalar(path, value.to_owned(), false)
    }
}

pub(super) fn copy_shell(
    node: &NetconfXmlNode,
    reservation: &IdentityReservation,
) -> NetconfXmlNode {
    reservation.copied(1);
    let mut result = NetconfXmlNode::branch(node.schema_path);
    for (path, value) in &node.keys {
        reservation.copied(1 + value.len());
        result.keys.push((*path, value.clone()));
    }
    if let Some(value) = &node.value {
        reservation.copied(value.len());
        result.value = Some(value.clone());
    }
    result.is_defaulted = node.is_defaulted;
    result.masked_ordinal = node.masked_ordinal;
    result
}

pub(super) fn copy_nodes(
    nodes: &[NetconfXmlNode],
    reservation: &IdentityReservation,
) -> Vec<NetconfXmlNode> {
    nodes
        .iter()
        .map(|node| {
            let mut copy = copy_shell(node, reservation);
            copy.children = copy_nodes(&node.children, reservation);
            reservation.moved(1);
            copy
        })
        .collect()
}

fn leaf_list(path: &str, paths: &[&str], reservation: &IdentityReservation) -> bool {
    let index = lower_bound(paths.len(), |index| {
        reservation.text_cmp(paths[index], path)
    });
    index < paths.len() && reservation.path_eq(paths[index], path)
}

fn lower_bound(len: usize, mut compare: impl FnMut(usize) -> Ordering) -> usize {
    let (mut left, mut right) = (0, len);
    while left < right {
        let middle = left + (right - left) / 2;
        if compare(middle).is_lt() {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    left
}

pub(super) fn merge_reserved(
    existing: &mut Vec<NetconfXmlNode>,
    incoming: Vec<NetconfXmlNode>,
    leaf_lists: &[&str],
    reservation: &IdentityReservation,
) -> Result<(), SubtreeError> {
    if incoming.is_empty() {
        return Ok(());
    }
    reservation.moved(incoming.len());
    existing.extend(incoming);
    let kinds: Vec<_> = existing
        .iter()
        .map(|node| leaf_list(node.schema_path, leaf_lists, reservation))
        .collect();
    reservation.moved(kinds.len());
    let compare = |left: usize, right: usize| {
        reservation
            .identity_cmp(&existing[left], &existing[right])
            .then_with(|| {
                if kinds[left] {
                    reservation.value_cmp(&existing[left].value, &existing[right].value)
                } else {
                    Ordering::Equal
                }
            })
    };
    let order = sorted_indices(existing.len(), compare, |units| reservation.moved(units));
    // Discover every equal run while all candidates are still available. Each
    // run is coalesced once, including one batch merge of all of its children.
    let mut runs = Vec::new();
    let mut start = 0;
    for end in 1..=order.len() {
        if end == order.len() || !compare(order[start], order[end]).is_eq() {
            runs.push(start..end);
            reservation.moved(1);
            start = end;
        }
    }
    let mut slots: Vec<_> = std::mem::take(existing).into_iter().map(Some).collect();
    reservation.moved(slots.len());
    for run in runs {
        let first = order[run.start];
        let mut node = slots[first].take().expect("unique sorted position");
        let mut children = std::mem::take(&mut node.children);
        if run.len() > 1 {
            for &index in &order[run.start + 1..run.end] {
                let other = slots[index].take().expect("unique sorted position");
                reservation.compared(1);
                if !reservation.value_cmp(&node.value, &other.value).is_eq()
                    || node.is_defaulted != other.is_defaulted
                {
                    return Err(SubtreeError::Projection);
                }
                reservation.moved(other.children.len());
                children.extend(other.children);
            }
        }
        // Normalize singleton subtrees too. Later selection indexes rely on
        // this complete join, including scalars supplied by custom projectors.
        merge_reserved(&mut node.children, children, leaf_lists, reservation)?;
        reservation.moved(1);
        slots[first] = Some(node);
    }
    // Stable sorting put the first occurrence at the front of each equal run.
    // Its original slot restores source order in one pass, without shifts.
    reservation.moved(slots.len());
    *existing = slots.into_iter().flatten().collect();
    Ok(())
}

/// The initial join defines a request-local identity index for each row: key
/// slots first, then original child positions. Selection carries those slots
/// through copies and unions, so later phases need no key-identity searches.
pub(super) struct SelectedNode {
    position: usize,
    node: NetconfXmlNode,
    pub(super) children: Vec<SelectedNode>,
}

impl SelectedNode {
    pub(super) fn key(
        path: &'static str,
        value: &str,
        position: usize,
        reservation: &IdentityReservation,
    ) -> Self {
        Self {
            position,
            node: reservation.scalar(path, value),
            children: Vec::new(),
        }
    }

    pub(super) fn capture(
        node: &NetconfXmlNode,
        index: usize,
        keys: &[(&'static str, String)],
        reservation: &IdentityReservation,
    ) -> Result<Self, SubtreeError> {
        let mut position = keys.len().checked_add(index).ok_or(SubtreeError::TooBig)?;
        for (slot, (path, value)) in keys.iter().enumerate() {
            if reservation.path_eq(path, node.schema_path) {
                reservation.compared(3);
                if !node.keys.is_empty()
                    || !node.children.is_empty()
                    || !node
                        .value
                        .as_ref()
                        .is_some_and(|actual| reservation.path_eq(value, actual))
                {
                    return Err(SubtreeError::Projection);
                }
                position = slot;
                break;
            }
        }
        Ok(Self {
            position,
            node: copy_shell(node, reservation),
            children: Vec::new(),
        })
    }
}

pub(super) fn merge_selected(
    mut candidates: Vec<SelectedNode>,
    reservation: &IdentityReservation,
) -> Result<Vec<SelectedNode>, SubtreeError> {
    if candidates.len() <= 1 {
        reservation.moved(candidates.len());
        return Ok(candidates);
    }
    let order = sorted_indices(
        candidates.len(),
        |left, right| {
            reservation.compared(1);
            candidates[left].position.cmp(&candidates[right].position)
        },
        |units| reservation.moved(units),
    );
    let mut runs = Vec::new();
    let mut start = 0;
    for end in 1..=order.len() {
        reservation.compared(1);
        if end == order.len()
            || candidates[order[start]].position != candidates[order[end]].position
        {
            runs.push(start..end);
            reservation.moved(1);
            start = end;
        }
    }
    let mut slots: Vec<_> = candidates.drain(..).map(Some).collect();
    reservation.moved(slots.len());
    for run in runs {
        let mut node = slots[order[run.start]]
            .take()
            .expect("unique sorted position");
        if run.len() > 1 {
            let mut children = std::mem::take(&mut node.children);
            for &index in &order[run.start + 1..run.end] {
                let other = slots[index].take().expect("unique sorted position");
                reservation.compared(1);
                if !reservation
                    .value_cmp(&node.node.value, &other.node.value)
                    .is_eq()
                    || node.node.is_defaulted != other.node.is_defaulted
                {
                    return Err(SubtreeError::Projection);
                }
                reservation.moved(other.children.len());
                children.extend(other.children);
            }
            node.children = merge_selected(children, reservation)?;
        }
        reservation.moved(1);
        candidates.push(node);
    }
    Ok(candidates)
}

pub(super) fn ordered_nodes(
    selected: Vec<SelectedNode>,
    reservation: &IdentityReservation,
) -> Vec<NetconfXmlNode> {
    let order = sorted_indices(
        selected.len(),
        |left, right| {
            reservation.compared(1);
            selected[left].position.cmp(&selected[right].position)
        },
        |units| reservation.moved(units),
    );
    let mut slots: Vec<_> = selected.into_iter().map(Some).collect();
    reservation.moved(slots.len());
    order
        .into_iter()
        .map(|index| {
            let mut selected = slots[index].take().expect("unique sorted position");
            selected.node.children = ordered_nodes(selected.children, reservation);
            reservation.moved(1);
            selected.node
        })
        .collect()
}

#[cfg(test)]
pub(super) fn order_reserved(
    selected: &mut Vec<NetconfXmlNode>,
    input: &[NetconfXmlNode],
    keys: &[(&'static str, String)],
    reservation: &IdentityReservation,
) -> Result<(), SubtreeError> {
    if selected.is_empty() {
        return Ok(());
    }
    let compare = |left: &NetconfXmlNode, right: &NetconfXmlNode| {
        reservation
            .identity_cmp(left, right)
            .then_with(|| reservation.value_cmp(&left.value, &right.value))
    };
    let order = sorted_indices(
        selected.len(),
        |left, right| compare(&selected[left], &selected[right]),
        |units| reservation.moved(units),
    );
    let mut next: Vec<_> = (0..order.len()).collect();
    let mut used = vec![false; selected.len()];
    let mut positions = Vec::new();
    reservation.moved(next.len());
    reservation.moved(used.len());
    // Keys precede children, as in the original projection order. Key schema
    // paths identify scalars; malformed values/structure still refuse output.
    for (path, value) in keys {
        let start = lower_bound(order.len(), |index| {
            reservation.text_cmp(selected[order[index]].schema_path, path)
        });
        if start < order.len() {
            let index = order[start];
            let node = &selected[index];
            if !used[index] && reservation.path_eq(node.schema_path, path) {
                reservation.compared(3);
                if !node.keys.is_empty()
                    || !node.children.is_empty()
                    || !node
                        .value
                        .as_ref()
                        .is_some_and(|actual| reservation.path_eq(actual, value))
                {
                    return Err(SubtreeError::Projection);
                }
                used[index] = true;
                next[start] += 1;
                positions.push((index, None));
                reservation.moved(3);
            }
        }
    }
    for (source, original) in input.iter().enumerate() {
        let start = lower_bound(order.len(), |index| {
            compare(&selected[order[index]], original)
        });
        if start < order.len() {
            let cursor = next[start];
            if cursor < order.len() {
                let index = order[cursor];
                if !used[index] && compare(&selected[index], original).is_eq() {
                    used[index] = true;
                    next[start] += 1;
                    positions.push((index, Some(source)));
                    reservation.moved(3);
                }
            }
        }
    }
    reservation.compared(1);
    if positions.len() != selected.len() {
        return Err(SubtreeError::Projection);
    }
    let mut slots: Vec<_> = std::mem::take(selected).into_iter().map(Some).collect();
    reservation.moved(slots.len());
    for (index, source) in positions {
        let mut node = slots[index]
            .take()
            .expect("one assignment per selected node");
        if let Some(source) = source {
            order_reserved(
                &mut node.children,
                &input[source].children,
                &input[source].keys,
                reservation,
            )?;
        }
        selected.push(node);
        reservation.moved(1);
    }
    Ok(())
}

#[cfg(test)]
mod comparison_tests {
    use super::*;

    #[test]
    fn tuple_comparison_bound_covers_full_prefixes_and_leaf_list_values() {
        for bytes in [0, 1, 64, 1024] {
            for keys in 0..4 {
                for mismatch in 0..3 {
                    let mut left =
                        NetconfXmlNode::scalar("/m:root/m:peer", "v".repeat(bytes), false);
                    for path in [
                        "/m:root/m:peer/m:first",
                        "/m:root/m:peer/m:second",
                        "/m:root/m:peer/m:third",
                    ]
                    .into_iter()
                    .take(keys)
                    {
                        left.keys.push((path, "k".repeat(bytes)));
                    }
                    let mut right = left.clone();
                    if mismatch == 1 {
                        right.value.as_mut().unwrap().push('x');
                    }
                    if mismatch == 2 {
                        if let Some((_, key)) = right.keys.last_mut() {
                            key.push('x');
                        } else {
                            right.masked_ordinal = Some(1);
                        }
                    }
                    let metadata = SubtreeBudget::new(1_000_000, 0).unwrap();
                    let mut work = CapturedWork::default();
                    work.include_nodes(&[left.clone(), right.clone()], None, &metadata)
                        .unwrap();
                    let allowance = work.comparison_units().unwrap();
                    let budget = SubtreeBudget::new(allowance, 0).unwrap();
                    take_audits();
                    {
                        let reservation = IdentityReservation::admit(&budget, allowance).unwrap();
                        let order = reservation
                            .identity_cmp(&left, &right)
                            .then_with(|| reservation.value_cmp(&left.value, &right.value));
                        assert_eq!(order.is_eq(), mismatch == 0);
                    }
                    let audits = take_audits();
                    assert_eq!(audits.len(), 1);
                    assert_eq!(audits[0].admitted, allowance);
                    assert!(audits[0].comparisons > 0 && audits[0].actual() <= allowance);
                }
            }
        }
    }
}
