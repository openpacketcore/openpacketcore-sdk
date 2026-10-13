//! Scalar operational projection retaining qualified ancestry and raw identities.

use opc_mgmt_opstate::OperationalResponse;
use opc_mgmt_path::CanonicalPath;
use opc_mgmt_schema::{merge_netconf_data, NetconfDataNode, NodeKind, SchemaRegistry};

use super::BindingError;

fn invalid() -> BindingError {
    BindingError::projection("invalid NETCONF operational projection")
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
        if resolved.node.config || resolved.node.kind != NodeKind::Leaf {
            return Err(invalid());
        }
        let parsed = CanonicalPath::parse(value.path().as_str()).map_err(|_| invalid())?;
        let raw = match serde_json::from_str(value.value_json()).map_err(|_| invalid())? {
            serde_json::Value::Null => continue,
            serde_json::Value::String(raw) => raw,
            serde_json::Value::Bool(raw) => raw.to_string(),
            serde_json::Value::Number(raw) => raw.to_string(),
            _ => return Err(invalid()),
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
                if key.path == resolved.node.path && raw != *identity {
                    return Err(invalid());
                }
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
