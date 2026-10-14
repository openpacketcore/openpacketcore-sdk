//! Atomic acceptance of complete canonical provider instances before matching.

use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalRequest, OperationalValueShape};
use opc_mgmt_path::{append_key_predicate, parse_canonical_path};
use opc_mgmt_schema::subtree::{canonical_key, AuthorizedSubtreePlan, SubtreeBudget, SubtreeError};
use opc_mgmt_schema::{
    NetconfInstanceSelector, NetconfXmlNode, NodeKind, NodeMeta, SchemaRegistry,
};

use crate::binding::NetconfConfigBinding;

mod audit;
use audit::Reservation;

pub(super) fn read<C: OpcConfig, B: NetconfConfigBinding<C>>(
    binding: &B,
    plan: &AuthorizedSubtreePlan,
    registry: &dyn SchemaRegistry,
    limits: &MgmtLimits,
) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
    let budget = plan.budget();
    let mut selectors = Vec::new();
    for selector in plan.instance_selectors(limits.max_subtree_filter_nodes)? {
        let node = match budget.node(registry, selector.schema_path) {
            Ok(node) => node,
            Err(SubtreeError::Unsupported) => continue,
            Err(error) => return Err(error),
        };
        if !node.config && matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList) {
            budget.charge(1)?;
            selectors.push(selector);
        }
    }
    if selectors.is_empty() {
        return Ok(Vec::new());
    }
    let mut requested: Vec<YangPath> = Vec::new();
    for selector in &selectors {
        let canonical = request_path(registry, selector, budget, limits.max_value_bytes)?;
        let mut duplicate = false;
        for previous in &requested {
            budget.charge(1)?;
            if budget.compare(previous.as_str(), &canonical)? {
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            if requested.len() >= limits.max_paths_per_request {
                return Err(SubtreeError::TooBig);
            }
            budget.charge(1)?;
            requested.push(YangPath::new(canonical).map_err(|_| SubtreeError::Projection)?);
        }
    }
    let request = OperationalRequest::new(requested)
        .with_max_values(limits.max_paths_per_request)
        .with_max_value_bytes(limits.max_value_bytes);
    let response = binding
        .get_operational_state(&request)
        .map_err(|_| SubtreeError::Projection)?;
    // Independent complete-response limits precede parsing, indexing or trials.
    if response.values.len() > request.max_values {
        return Err(SubtreeError::TooBig);
    }
    budget.charge(response.values.len())?;
    for value in &response.values {
        if value.path().as_str().len() > limits.max_value_bytes
            || value.value_json().len() > limits.max_value_bytes
        {
            return Err(SubtreeError::TooBig);
        }
    }
    let mut accepted = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for value in &response.values {
        budget.charge(1)?;
        if value.origin().is_some() {
            return Err(SubtreeError::Projection);
        }
        let path = value.path().as_str();
        let (node, ancestors, identity, path_identity) =
            instance(registry, path, budget, limits.max_value_bytes)?;
        let path_work = path_identity.len();
        if node.config || !matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList) {
            return Err(SubtreeError::Projection);
        }
        if !requested_instance(&selectors, node.path, &identity, budget)? {
            return Err(SubtreeError::Projection);
        }
        budget.charge(1)?;
        seen.push(path_identity);
        // OperationalValue has already validated the immutable JSON. Its shape
        // proof lets masked non-key output avoid decoding or retaining raw text.
        budget.charge(1)?;
        match value.json_shape() {
            OperationalValueShape::Null => continue,
            OperationalValueShape::Structured => return Err(SubtreeError::Projection),
            OperationalValueShape::Scalar => {}
        }
        budget.charge(identity.len())?;
        let mut key_search_work = identity.len();
        #[cfg(test)]
        let mut masked_keys = false;
        for key in &identity {
            #[cfg(test)]
            {
                masked_keys |= key.masked;
            }
            add_work(&mut key_search_work, key.path.len())?;
            add_work(&mut key_search_work, node.path.len())?;
        }
        budget.charge(key_search_work)?;
        let identity_value = identity.iter().find(|key| key.path == node.path);
        budget.charge(1)?;
        let masked = !registry
            .data_class(node.path)
            .is_some_and(opc_mgmt_schema::DataClass::allows_cleartext);
        let raw = if masked && identity_value.is_none() {
            budget.copy("<redacted>")?
        } else {
            // A masked key still requires raw key/payload consistency validation.
            // Its bytes are independently capped above; matching charges one
            // fixed validation unit and retains only the captured surrogate.
            budget.charge(if masked {
                1
            } else {
                value
                    .value_json()
                    .len()
                    .checked_mul(3)
                    .ok_or(SubtreeError::TooBig)?
            })?;
            let json: serde_json::Value =
                serde_json::from_str(value.value_json()).map_err(|_| SubtreeError::Projection)?;
            match json {
                serde_json::Value::Null => continue,
                serde_json::Value::String(raw) => raw,
                serde_json::Value::Bool(value) => {
                    let text = if value { "true" } else { "false" };
                    if masked {
                        text.to_owned()
                    } else {
                        budget.copy(text)?
                    }
                }
                serde_json::Value::Number(value) => {
                    if !masked {
                        budget.charge(327)?;
                    }
                    value.to_string()
                }
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                    return Err(SubtreeError::Projection);
                }
            }
        };
        // Even values which would fail a predicate must pass identity validation.
        let captured = if let Some(key) = identity_value {
            let canonical = canonical_key(registry, node.path, &raw, budget)?
                .ok_or(SubtreeError::Projection)?;
            let consistent = if masked {
                budget.charge(1)?;
                key.raw == canonical
            } else {
                budget.compare(&key.raw, &canonical)?
            };
            if !consistent {
                return Err(SubtreeError::Projection);
            }
            if masked {
                budget.copy(&key.captured)?
            } else {
                raw
            }
        } else {
            raw
        };
        budget.charge(1)?;
        let mut tree = NetconfXmlNode::scalar(node.path, captured, false);
        for mut parent in ancestors.into_iter().rev() {
            budget.charge(1)?;
            parent.children.push(tree);
            tree = parent;
        }
        budget.charge(1)?;
        accepted.push(Accepted {
            path,
            captured_bytes: path_work,
            #[cfg(test)]
            masked_keys,
            tree,
        });
    }
    // Detect duplicate complete identities in one indexed batch. A failed
    // equality test or an early duplicate never changes the prepaid work.
    ensure_unique(&seen, budget)?;
    // Canonical output order still uses raw validated paths, with work sized
    // exclusively from captured path identities (fixed width for masked keys).
    // Sorting positions and moving each tree once avoids quadratic shifts.
    order_accepted(accepted, budget)
}

fn ensure_unique(seen: &[String], budget: &SubtreeBudget) -> Result<(), SubtreeError> {
    let sizing = Reservation::admit(budget, seen.len(), "provider identity sizing")?;
    let max_identity = seen
        .iter()
        .map(|value| {
            sizing.visit();
            value.len()
        })
        .max()
        .unwrap_or(0);
    let (identities, reservation) = sorted_positions(
        seen.len(),
        max_identity,
        budget,
        "provider identities",
        |left, right, reservation| reservation.text_cmp(&seen[left], &seen[right]),
    )?;
    for pair in identities.windows(2) {
        reservation.compared();
        if reservation.text_cmp(&seen[pair[0]], &seen[pair[1]]).is_eq() {
            return Err(SubtreeError::Projection);
        }
    }
    Ok(())
}

struct Accepted<'a> {
    path: &'a str,
    captured_bytes: usize,
    #[cfg(test)]
    masked_keys: bool,
    tree: NetconfXmlNode,
}

fn order_accepted(
    accepted: Vec<Accepted<'_>>,
    budget: &SubtreeBudget,
) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
    let sizing = Reservation::admit(budget, accepted.len(), "provider order sizing")?;
    let max_path_work = accepted
        .iter()
        .map(|entry| {
            sizing.visit();
            entry.captured_bytes
        })
        .max()
        .unwrap_or(0);
    let (order, _reservation) = sorted_positions(
        accepted.len(),
        max_path_work,
        budget,
        "provider ordering",
        |left, right, _reservation| {
            // The established hidden-key contract treats raw canonical ordering
            // as a logical comparison, not a raw-secret byte/CPU bound.
            #[cfg(test)]
            if !accepted[left].masked_keys && !accepted[right].masked_keys {
                return _reservation.text_cmp(accepted[left].path, accepted[right].path);
            }
            accepted[left].path.cmp(accepted[right].path)
        },
    )?;
    let movement = Reservation::admit(
        budget,
        accepted.len().checked_mul(2).ok_or(SubtreeError::TooBig)?,
        "provider output",
    )?;
    let mut slots: Vec<_> = accepted
        .into_iter()
        .map(|entry| {
            movement.moved(1);
            Some(entry.tree)
        })
        .collect();
    // Retain every original chain; only the evaluator may coalesce identities
    // after admitting its complete capture-derived envelope.
    order
        .into_iter()
        .map(|index| {
            movement.moved(1);
            slots[index].take().ok_or(SubtreeError::Projection)
        })
        .collect()
}

fn add_work(total: &mut usize, units: usize) -> Result<(), SubtreeError> {
    *total = total.checked_add(units).ok_or(SubtreeError::TooBig)?;
    Ok(())
}

/// A stable merge sort has at most N comparisons and N position moves per
/// level. Include a complete adjacent equality pass for duplicate detection.
fn sorted_positions(
    count: usize,
    captured_bytes: usize,
    budget: &SubtreeBudget,
    phase: &'static str,
    mut compare: impl FnMut(usize, usize, &Reservation) -> std::cmp::Ordering,
) -> Result<(Vec<usize>, Reservation), SubtreeError> {
    let levels = (usize::BITS - count.saturating_sub(1).leading_zeros()) as usize;
    // A captured-text comparison visits at most the smaller operand's bytes.
    // Add one comparison and one position move; canonical-order comparisons
    // are fixed logical operations under the masked-key contract.
    let per_compare = captured_bytes.checked_add(2).ok_or(SubtreeError::TooBig)?;
    let per_node = levels
        .checked_add(1)
        .and_then(|levels| levels.checked_mul(per_compare))
        .and_then(|work| work.checked_add(2))
        .ok_or(SubtreeError::TooBig)?;
    let reservation = Reservation::admit(
        budget,
        count.checked_mul(per_node).ok_or(SubtreeError::TooBig)?,
        phase,
    )?;
    let mut order: Vec<_> = (0..count).collect();
    let mut scratch = vec![0; count];
    reservation.moved(count);
    reservation.moved(count);
    let mut width = 1usize;
    while width < count {
        let mut start = 0;
        while start < count {
            let middle = start.saturating_add(width).min(count);
            let end = middle.saturating_add(width).min(count);
            let (mut left, mut right) = (start, middle);
            for slot in &mut scratch[start..end] {
                if left < middle
                    && (right == end || {
                        reservation.compared();
                        !compare(order[left], order[right], &reservation).is_gt()
                    })
                {
                    *slot = order[left];
                    left += 1;
                } else {
                    *slot = order[right];
                    right += 1;
                }
                reservation.moved(1);
            }
            start = end;
        }
        std::mem::swap(&mut order, &mut scratch);
        width = width.saturating_mul(2);
    }
    Ok((order, reservation))
}

fn requested_instance(
    selectors: &[NetconfInstanceSelector],
    path: &str,
    identity: &[InstanceKey],
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    budget.charge(selectors.len())?;
    let mut work = selectors.len();
    for selector in selectors {
        add_work(&mut work, selector.schema_path.len())?;
        add_work(&mut work, path.len())?;
        budget.charge(selector.keys.len())?;
        add_work(&mut work, selector.keys.len())?;
        for (key, expected) in &selector.keys {
            budget.charge(identity.len())?;
            add_work(&mut work, identity.len())?;
            for actual in identity {
                add_work(&mut work, key.len())?;
                add_work(&mut work, actual.path.len())?;
                add_work(&mut work, expected.len())?;
                add_work(&mut work, actual.captured.len())?;
            }
        }
    }
    // Selector constraints themselves are schema-approved cleartext. Captured
    // tuples can also contain masked components; reserve the whole product
    // before any path, component or selector comparison can stop the search.
    budget.charge(work)?;
    Ok(selectors.iter().any(|selector| {
        selector.schema_path == path
            && selector.keys.iter().all(|(key, expected)| {
                identity
                    .iter()
                    .any(|actual| *key == actual.path && *expected == actual.captured)
            })
    }))
}

fn append(
    out: &mut String,
    value: &str,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<(), SubtreeError> {
    let len = out
        .len()
        .checked_add(value.len())
        .ok_or(SubtreeError::TooBig)?;
    if len > limit {
        return Err(SubtreeError::TooBig);
    }
    budget.charge(value.len())?;
    out.push_str(value);
    Ok(())
}

fn append_key(
    out: &mut String,
    name: &str,
    value: &str,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<(), SubtreeError> {
    let extra = name
        .len()
        .checked_add(value.len())
        .and_then(|len| len.checked_add(5))
        .ok_or(SubtreeError::TooBig)?;
    if out.len().checked_add(extra).ok_or(SubtreeError::TooBig)? > limit {
        return Err(SubtreeError::TooBig);
    }
    budget.charge(extra.checked_add(value.len()).ok_or(SubtreeError::TooBig)?)?;
    append_key_predicate(out, name, value).map_err(|_| SubtreeError::Projection)
}

fn key_nodes(
    registry: &dyn SchemaRegistry,
    list: &NodeMeta,
    budget: &SubtreeBudget,
) -> Result<Vec<&'static NodeMeta>, SubtreeError> {
    let mut keys = Vec::new();
    let (prefix, _) = list
        .path
        .rsplit('/')
        .next()
        .and_then(|name| name.split_once(':'))
        .ok_or(SubtreeError::Projection)?;
    for name in list.key_leaves {
        budget.charge(1)?;
        budget.charge(
            list.path
                .len()
                .checked_add(prefix.len())
                .and_then(|len| len.checked_add(name.len()))
                .and_then(|len| len.checked_add(2))
                .ok_or(SubtreeError::TooBig)?,
        )?;
        let path = if name.contains(':') {
            format!("{}/{name}", list.path)
        } else {
            format!("{}/{prefix}:{name}", list.path)
        };
        let node = budget.node(registry, &path)?;
        if node.kind != NodeKind::Leaf {
            return Err(SubtreeError::Projection);
        }
        budget.charge(1)?;
        keys.push(node);
    }
    Ok(keys)
}

fn request_path(
    registry: &dyn SchemaRegistry,
    selector: &NetconfInstanceSelector,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<String, SubtreeError> {
    let mut schema = String::new();
    let mut canonical = String::new();
    for name in selector.schema_path.trim_start_matches('/').split('/') {
        budget.charge(1)?;
        append(&mut schema, "/", budget, limit)?;
        append(&mut schema, name, budget, limit)?;
        append(&mut canonical, "/", budget, limit)?;
        append(&mut canonical, name, budget, limit)?;
        let node = budget.node(registry, &schema)?;
        for key in key_nodes(registry, node, budget)? {
            for (path, value) in &selector.keys {
                budget.charge(1)?;
                if budget.compare(path, key.path)? {
                    let name = key
                        .path
                        .rsplit('/')
                        .next()
                        .ok_or(SubtreeError::Projection)?;
                    append_key(&mut canonical, name, value, budget, limit)?;
                    break;
                }
            }
        }
    }
    Ok(canonical)
}

struct InstanceKey {
    path: &'static str,
    // Public schema classification for the test-only work counter.
    #[cfg(test)]
    masked: bool,
    // Raw text survives only until mandatory provider consistency validation.
    raw: String,
    // All selection, joins, copies and output identity use this representation.
    captured: String,
}

type Instance = (
    &'static NodeMeta,
    Vec<NetconfXmlNode>,
    Vec<InstanceKey>,
    String,
);

fn instance(
    registry: &dyn SchemaRegistry,
    path: &str,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<Instance, SubtreeError> {
    // The complete provider byte cap precedes this mandatory syntax pass. Raw
    // key validation has a fixed admission charge; cleartext names and keys are
    // metered below, before their canonical copies. Hidden lengths never enter
    // the matching allowance, including this path's later equality/sort costs.
    budget.charge(1)?;
    let segments = parse_canonical_path(path).map_err(|_| SubtreeError::Projection)?;
    let mut schema = String::new();
    let mut canonical = String::new();
    let mut path_identity = String::new();
    let mut ancestors = Vec::new();
    let mut identity = Vec::new();
    let mut leaf = None;
    for (index, segment) in segments.iter().enumerate() {
        budget.charge(1)?;
        budget.charge(
            segment
                .name
                .len()
                .checked_add(1)
                .ok_or(SubtreeError::TooBig)?,
        )?;
        append(&mut schema, "/", budget, limit)?;
        append(&mut schema, &segment.name, budget, limit)?;
        let node = budget.node(registry, &schema).map_err(|error| {
            if error == SubtreeError::Unsupported {
                SubtreeError::Projection
            } else {
                error
            }
        })?;
        append(&mut canonical, "/", budget, limit)?;
        append(&mut canonical, &segment.name, budget, limit)?;
        append(&mut path_identity, "/", budget, usize::MAX)?;
        append(&mut path_identity, &segment.name, budget, usize::MAX)?;
        budget.charge(1)?;
        let mut branch = NetconfXmlNode::branch(node.path);
        match node.kind {
            NodeKind::List => {
                let keys = key_nodes(registry, node, budget)?;
                if keys.is_empty() || keys.len() != segment.keys.len() {
                    return Err(SubtreeError::Projection);
                }
                for (key, (name, value)) in keys.into_iter().zip(&segment.keys) {
                    let expected = key
                        .path
                        .rsplit('/')
                        .next()
                        .ok_or(SubtreeError::Projection)?;
                    if !budget.compare(expected, name)? {
                        return Err(SubtreeError::Projection);
                    }
                    budget.charge(1)?;
                    let masked = !registry
                        .data_class(key.path)
                        .is_some_and(opc_mgmt_schema::DataClass::allows_cleartext);
                    let normalized = canonical_key(registry, key.path, value, budget)?
                        .ok_or(SubtreeError::Projection)?;
                    let captured = if masked {
                        budget.charge(1)?;
                        if normalized != *value {
                            return Err(SubtreeError::Projection);
                        }
                        // This is provider validation, bounded by the input path
                        // cap, not a retained raw matching identity.
                        let raw_bytes = name
                            .len()
                            .checked_add(normalized.len())
                            .and_then(|bytes| bytes.checked_add(5))
                            .ok_or(SubtreeError::TooBig)?;
                        if canonical
                            .len()
                            .checked_add(raw_bytes)
                            .ok_or(SubtreeError::TooBig)?
                            > limit
                        {
                            return Err(SubtreeError::TooBig);
                        }
                        budget.charge(name.len().checked_add(6).ok_or(SubtreeError::TooBig)?)?;
                        append_key_predicate(&mut canonical, name, &normalized)
                            .map_err(|_| SubtreeError::Projection)?;
                        budget.masked_identity(&normalized)?
                    } else {
                        if !budget.compare(&normalized, value)? {
                            return Err(SubtreeError::Projection);
                        }
                        append_key(&mut canonical, name, &normalized, budget, limit)?;
                        budget.copy(&normalized)?
                    };
                    append_key(&mut path_identity, name, &captured, budget, usize::MAX)?;
                    budget.charge(2)?;
                    identity.push(InstanceKey {
                        path: key.path,
                        #[cfg(test)]
                        masked,
                        raw: normalized,
                        captured: budget.copy(&captured)?,
                    });
                    branch.keys.push((key.path, captured));
                }
            }
            _ if !segment.keys.is_empty() => return Err(SubtreeError::Projection),
            _ => {}
        }
        if index + 1 == segments.len() {
            leaf = Some(node);
        } else {
            if !matches!(node.kind, NodeKind::Container | NodeKind::List) {
                return Err(SubtreeError::Projection);
            }
            budget.charge(1)?;
            ancestors.push(branch);
        }
    }
    budget.charge(
        path_identity
            .len()
            .checked_mul(2)
            .ok_or(SubtreeError::TooBig)?,
    )?;
    if path != canonical {
        return Err(SubtreeError::Projection);
    }
    Ok((
        leaf.ok_or(SubtreeError::Projection)?,
        ancestors,
        identity,
        path_identity,
    ))
}

#[cfg(test)]
mod index_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn provider_phases_count_work_at_capacity_and_preserve_order() {
        for count in [0, 1, 2, 3, 7, 31, 100, 1024] {
            let mut expected = None;
            for arrangement in 0..3 {
                let mut paths: Vec<_> = (0..count)
                    .map(|index| format!("{}-{index:04}", "p".repeat(64)))
                    .collect();
                if arrangement == 1 {
                    paths.reverse();
                }
                if arrangement == 2 {
                    paths.sort_by_key(|path| path.as_bytes().last().copied());
                }
                let budget =
                    SubtreeBudget::new(MgmtLimits::default().max_subtree_filter_work_units, 0)
                        .unwrap();
                audit::take_audits();
                ensure_unique(&paths, &budget).unwrap();
                let accepted = paths
                    .iter()
                    .map(|path| Accepted {
                        path,
                        captured_bytes: path.len(),
                        masked_keys: false,
                        tree: NetconfXmlNode::scalar("/m:value", path.clone(), false),
                    })
                    .collect();
                let ordered = order_accepted(accepted, &budget).unwrap();
                let mut sorted = paths.clone();
                sorted.sort();
                assert_eq!(
                    ordered
                        .iter()
                        .map(|node| node.value.as_ref().unwrap())
                        .collect::<Vec<_>>(),
                    sorted.iter().collect::<Vec<_>>()
                );
                let used = MgmtLimits::default().max_subtree_filter_work_units - budget.remaining();
                if let Some(previous) = expected {
                    assert_eq!(used, previous);
                }
                expected = Some(used);
                let audits = audit::take_audits();
                assert_eq!(audits.len(), 5);
                for phase in [
                    "provider identity sizing",
                    "provider identities",
                    "provider order sizing",
                    "provider ordering",
                    "provider output",
                ] {
                    let audit = audits.iter().find(|audit| audit.phase == phase).unwrap();
                    assert!(audit.actual() <= audit.admitted, "{audit:?}");
                    if count > 1 {
                        assert!(audit.actual() > 0, "{audit:?}");
                    }
                }
                if count > 1 {
                    let identity = audits
                        .iter()
                        .find(|audit| audit.phase == "provider identities")
                        .unwrap();
                    assert!(identity.comparisons > 0 && identity.bytes > 0 && identity.moves > 0);
                    let ordering = audits
                        .iter()
                        .find(|audit| audit.phase == "provider ordering")
                        .unwrap();
                    assert!(ordering.comparisons > 0 && ordering.bytes > 0 && ordering.moves > 0);
                    paths[1] = paths[0].clone();
                    let budget = SubtreeBudget::new(usize::MAX, 0).unwrap();
                    assert_eq!(
                        ensure_unique(&paths, &budget),
                        Err(SubtreeError::Projection)
                    );
                    assert!(audit::take_audits()
                        .iter()
                        .all(|audit| audit.actual() <= audit.admitted));
                }
            }
        }
        // Raw masked-key lengths are intentionally outside logical ordering
        // charges. Preserve canonical order even with long shared prefixes.
        let paths: Vec<_> = (0..100)
            .rev()
            .map(|index| format!("{}-{index:04}", "hidden".repeat(512)))
            .collect();
        let budget =
            SubtreeBudget::new(MgmtLimits::default().max_subtree_filter_work_units, 0).unwrap();
        let accepted = paths
            .iter()
            .map(|path| Accepted {
                path,
                captured_bytes: 64,
                masked_keys: true,
                tree: NetconfXmlNode::scalar("/m:value", path.clone(), false),
            })
            .collect();
        let ordered = order_accepted(accepted, &budget).unwrap();
        assert!(ordered.windows(2).all(|pair| pair[0].value < pair[1].value));
        assert!(audit::take_audits()
            .iter()
            .all(|audit| audit.actual() <= audit.admitted));
    }

    #[test]
    fn provider_index_sort_admits_before_comparing_and_is_order_independent() {
        let count = 1024;
        let mut expected_used = None;
        for reverse in [false, true] {
            let mut paths: Vec<_> = (0..count).map(|index| format!("{index:04}")).collect();
            if reverse {
                paths.reverse();
            }
            let budget =
                SubtreeBudget::new(MgmtLimits::default().max_subtree_filter_work_units, 0).unwrap();
            let mut comparisons = 0;
            let (order, _reservation) = sorted_positions(
                count,
                64,
                &budget,
                "test sort",
                |left, right, reservation| {
                    comparisons += 1;
                    reservation.text_cmp(&paths[left], &paths[right])
                },
            )
            .unwrap();
            assert_eq!(
                order.iter().map(|index| &paths[*index]).collect::<Vec<_>>(),
                {
                    let mut expected: Vec<_> = paths.iter().collect();
                    expected.sort();
                    expected
                }
            );
            assert!(
                comparisons <= count * 10,
                "1024 positions need at most ten merge-sort levels"
            );
            let used = MgmtLimits::default().max_subtree_filter_work_units - budget.remaining();
            if let Some(expected) = expected_used {
                assert_eq!(used, expected);
            }
            expected_used = Some(used);
            let refused = SubtreeBudget::new(used - 1, 0).unwrap();
            assert_eq!(
                sorted_positions(count, 64, &refused, "refused sort", |_, _, _| panic!(
                    "comparison before admission"
                ))
                .map(|(order, _)| order),
                Err(SubtreeError::TooBig)
            );
            assert_eq!(refused.remaining(), used - 1);
        }
        let budget = SubtreeBudget::new(1, 0).unwrap();
        assert_eq!(
            sorted_positions(
                usize::MAX,
                usize::MAX,
                &budget,
                "overflow sort",
                |_, _, _| panic!("overflow before admission")
            )
            .map(|(order, _)| order),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(budget.remaining(), 1);
    }
}
