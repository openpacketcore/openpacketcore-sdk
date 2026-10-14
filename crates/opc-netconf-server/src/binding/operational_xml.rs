//! Scalar operational projection retaining qualified ancestry and raw identities.

use opc_mgmt_opstate::OperationalResponse;
use opc_mgmt_path::{CanonicalPath, ResolvedPath};
use opc_mgmt_schema::{merge_netconf_data, NetconfDataNode, NodeKind, SchemaRegistry};

use super::BindingError;

fn invalid() -> BindingError {
    BindingError::projection("invalid NETCONF operational projection")
}

/// Checks a reported key against its complete, validated identity before masking.
pub(crate) fn validate_key_payload(
    registry: &dyn SchemaRegistry,
    resolved: &ResolvedPath,
    value_json: &str,
) -> Result<(), BindingError> {
    let Some((parent_path, name)) = resolved.node.path.rsplit_once('/') else {
        return Ok(());
    };
    let Some(parent) = registry.node(parent_path) else {
        return Ok(());
    };
    if !opc_mgmt_path::declared_key(registry, parent, name)
        .is_some_and(|key| key.path == resolved.node.path)
    {
        return Ok(());
    }
    let parsed = CanonicalPath::parse(resolved.canonical.as_str()).map_err(|_| invalid())?;
    let list = parsed.segments().iter().rev().nth(1).ok_or_else(invalid)?;
    let identity = list
        .keys
        .iter()
        .find_map(|(name, identity)| {
            opc_mgmt_path::declared_key(registry, parent, name)
                .filter(|key| key.path == resolved.node.path)
                .map(|_| *identity)
        })
        .ok_or_else(invalid)?;
    if scalar_value(value_json)?.ok_or_else(invalid)? != identity {
        return Err(invalid());
    }
    Ok(())
}

fn scalar_value(value_json: &str) -> Result<Option<String>, BindingError> {
    match serde_json::from_str(value_json).map_err(|_| invalid())? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(raw) => Ok(Some(raw)),
        serde_json::Value::Bool(raw) => Ok(Some(raw.to_string())),
        serde_json::Value::Number(raw) => Ok(Some(raw.to_string())),
        _ => Err(invalid()),
    }
}

pub(super) fn operational_nodes(
    registry: &'static dyn SchemaRegistry,
    paths: &[&'static str],
    operational: &OperationalResponse,
) -> Result<Vec<NetconfDataNode>, BindingError> {
    let mut forest = Vec::new();
    for value in &operational.values {
        let resolved =
            opc_mgmt_path::resolve_instance(registry, value.path()).map_err(|_| invalid())?;
        if !paths.contains(&resolved.node.path) {
            continue;
        }
        if resolved.node.config {
            return Err(invalid());
        }
        let parsed = CanonicalPath::parse(value.path().as_str()).map_err(|_| invalid())?;
        if resolved.node.kind != NodeKind::Leaf {
            if parsed
                .segments()
                .iter()
                .all(|segment| segment.keys.is_empty())
            {
                continue;
            }
            return Err(invalid());
        }
        validate_key_payload(registry, &resolved, value.value_json())?;
        let Some(raw) = scalar_value(value.value_json())? else {
            continue;
        };
        let mut ancestors = Vec::new();
        let mut schema = String::new();
        for segment in parsed
            .segments()
            .iter()
            .take(parsed.segments().len().saturating_sub(1))
        {
            schema.push('/');
            schema.push_str(segment.name);
            let ancestor = registry.node(&schema).ok_or_else(invalid)?;
            if !matches!(ancestor.kind, NodeKind::Container | NodeKind::List)
                || (ancestor.kind == NodeKind::List && ancestor.key_leaves.is_empty())
            {
                return Err(invalid());
            }
            let mut keys = Vec::new();
            for (name, identity) in &segment.keys {
                let key =
                    opc_mgmt_path::declared_key(registry, ancestor, name).ok_or_else(invalid)?;
                keys.push(NetconfDataNode::leaf(
                    key.path,
                    (*identity).to_string(),
                    false,
                ));
            }
            ancestors.push((ancestor.path, keys));
        }
        let mut current = NetconfDataNode::leaf(resolved.node.path, raw, false);
        for (path, mut keys) in ancestors.into_iter().rev() {
            if !keys.iter().any(|key| key.path == current.path) {
                keys.push(current);
            }
            current = NetconfDataNode::branch(path, keys);
        }
        forest.push(current);
    }
    let mut merged = Vec::new();
    merge_netconf_data(registry, &mut merged, forest).map_err(|_| invalid())?;
    Ok(merged)
}
