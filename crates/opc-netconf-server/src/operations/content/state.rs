//! Atomic acceptance of complete canonical provider instances before matching.

use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::OperationalRequest;
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
        for previous in &seen {
            budget.charge(1)?;
            if budget.compare(previous, path)? {
                return Err(SubtreeError::Projection);
            }
        }
        let (node, ancestors, identity) = instance(registry, path, budget, limits.max_value_bytes)?;
        if node.config || !matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList) {
            return Err(SubtreeError::Projection);
        }
        let mut requested = false;
        for selector in &selectors {
            budget.charge(1)?;
            if !budget.compare(selector.schema_path, node.path)? {
                continue;
            }
            let mut matches = true;
            for (key, expected) in &selector.keys {
                let mut found = false;
                for (path, actual) in &identity {
                    budget.charge(1)?;
                    if budget.compare(key, path)? && budget.compare(expected, actual)? {
                        found = true;
                        break;
                    }
                }
                matches &= found;
            }
            if matches {
                requested = true;
                break;
            }
        }
        if !requested {
            return Err(SubtreeError::Projection);
        }
        budget.charge(1)?;
        seen.push(budget.copy(path)?);
        // JSON parsing/copies are bounded in advance by the encoded byte count.
        budget.charge(
            value
                .value_json()
                .len()
                .checked_mul(3)
                .ok_or(SubtreeError::TooBig)?,
        )?;
        let json: serde_json::Value =
            serde_json::from_str(value.value_json()).map_err(|_| SubtreeError::Projection)?;
        let raw = match json {
            serde_json::Value::Null => continue,
            serde_json::Value::String(raw) => raw,
            serde_json::Value::Bool(value) => budget.copy(if value { "true" } else { "false" })?,
            serde_json::Value::Number(value) => {
                budget.charge(327)?;
                value.to_string()
            }
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                return Err(SubtreeError::Projection);
            }
        };
        // Even values which would fail a predicate must pass identity validation.
        for (path, key) in &identity {
            budget.charge(1)?;
            if budget.compare(path, node.path)? {
                let canonical = canonical_key(registry, node.path, &raw, budget)?
                    .ok_or(SubtreeError::Projection)?;
                if !budget.compare(key, &canonical)? {
                    return Err(SubtreeError::Projection);
                }
                break;
            }
        }
        budget.charge(1)?;
        let mut tree = NetconfXmlNode::scalar(node.path, raw, false);
        for mut parent in ancestors.into_iter().rev() {
            budget.charge(1)?;
            parent.children.push(tree);
            tree = parent;
        }
        budget.charge(1)?;
        accepted.push(tree);
    }
    let mut output = Vec::new();
    for tree in accepted {
        merge_bounded(registry, &mut output, vec![tree], budget)?;
    }
    Ok(output)
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

type Instance = (
    &'static NodeMeta,
    Vec<NetconfXmlNode>,
    Vec<(&'static str, String)>,
);

fn instance(
    registry: &dyn SchemaRegistry,
    path: &str,
    budget: &SubtreeBudget,
    limit: usize,
) -> Result<Instance, SubtreeError> {
    // Precharge a bound for syntax visits and retained path/key copies.
    budget.charge(path.len().checked_mul(4).ok_or(SubtreeError::TooBig)?)?;
    let segments = parse_canonical_path(path).map_err(|_| SubtreeError::Projection)?;
    let mut schema = String::new();
    let mut canonical = String::new();
    let mut ancestors = Vec::new();
    let mut identity = Vec::new();
    let mut leaf = None;
    for (index, segment) in segments.iter().enumerate() {
        budget.charge(1)?;
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
                    let normalized = canonical_key(registry, key.path, value, budget)?
                        .ok_or(SubtreeError::Projection)?;
                    if !budget.compare(&normalized, value)? {
                        return Err(SubtreeError::Projection);
                    }
                    append_key(&mut canonical, name, &normalized, budget, limit)?;
                    budget.charge(2)?;
                    identity.push((key.path, budget.copy(&normalized)?));
                    branch.keys.push((key.path, normalized));
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
    if !budget.compare(path, &canonical)? {
        return Err(SubtreeError::Projection);
    }
    Ok((leaf.ok_or(SubtreeError::Projection)?, ancestors, identity))
}
