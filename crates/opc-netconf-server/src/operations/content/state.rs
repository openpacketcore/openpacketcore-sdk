//! Atomic acceptance of complete canonical provider instances before matching.

use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalRequest, OperationalValueShape};
use opc_mgmt_path::{append_key_predicate, parse_canonical_path};
use opc_mgmt_schema::subtree::{
    canonical_key, merge_bounded, AuthorizedSubtreePlan, SubtreeBudget, SubtreeError,
};
use opc_mgmt_schema::{
    NetconfInstanceSelector, NetconfXmlNode, NodeKind, NodeMeta, SchemaRegistry,
};

use crate::binding::NetconfConfigBinding;

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
        if contains_path_identity(&seen, &path_identity, budget)? {
            return Err(SubtreeError::Projection);
        }
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
        for key in &identity {
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
        accepted.push((path, path_work, tree));
    }
    // Canonical order still uses the raw validated path. Precharge insertion
    // sort's complete worst case so comparison/move count cannot reveal hidden
    // key order, and use only fixed-width identities to measure path work.
    let count = accepted.len();
    budget.charge(count.checked_mul(2).ok_or(SubtreeError::TooBig)?)?;
    let max_path_work = accepted.iter().map(|(_, work, _)| *work).max().unwrap_or(0);
    let pairs = count
        .checked_mul(count.saturating_sub(1))
        .ok_or(SubtreeError::TooBig)?
        / 2;
    let per_pair = max_path_work
        .checked_mul(2)
        .and_then(|work| work.checked_add(2))
        .ok_or(SubtreeError::TooBig)?;
    budget.charge(pairs.checked_mul(per_pair).ok_or(SubtreeError::TooBig)?)?;
    for index in 1..count {
        let mut current = index;
        while current > 0 && accepted[current - 1].0 > accepted[current].0 {
            accepted.swap(current - 1, current);
            current -= 1;
        }
    }
    let mut output = Vec::new();
    // One complete batch keeps reservation sizes independent of which earlier
    // hidden identities merged, or where their raw sort order placed them.
    budget.charge(accepted.len())?;
    let trees = accepted.into_iter().map(|(_, _, tree)| tree).collect();
    merge_bounded(registry, &mut output, trees, budget)?;
    Ok(output)
}

fn add_work(total: &mut usize, units: usize) -> Result<(), SubtreeError> {
    *total = total.checked_add(units).ok_or(SubtreeError::TooBig)?;
    Ok(())
}

fn contains_path_identity(
    previous: &[String],
    path: &str,
    budget: &SubtreeBudget,
) -> Result<bool, SubtreeError> {
    budget.charge(previous.len())?;
    let mut work = previous.len();
    for candidate in previous {
        add_work(&mut work, candidate.len())?;
        add_work(&mut work, path.len())?;
    }
    // Every candidate is prepaid even if a duplicate is found at the front.
    budget.charge(work)?;
    Ok(previous.iter().any(|candidate| candidate == path))
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
