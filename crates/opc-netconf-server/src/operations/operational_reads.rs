//! Bounded concrete operational selections shared by get and operational get-data.

use opc_config_model::{OpcConfig, YangPath};
use opc_mgmt_authz::ReadNode;
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalRequest, OperationalResponse, OperationalResponseError};
use opc_mgmt_path::{PathSegment, RequestPath};
use opc_mgmt_schema::{NetconfInstanceBranch, NodeKind, SchemaRegistry};

use crate::{binding::NetconfConfigBinding, error::RpcError};

pub(crate) fn read_node<'a>(registry: &dyn SchemaRegistry, path: &'a str) -> ReadNode<'a> {
    match registry.node(path) {
        Some(node) if !node.config && matches!(node.kind, NodeKind::Container | NodeKind::List) => {
            ReadNode::operational(path)
        }
        _ => ReadNode::projected(path),
    }
}

pub(crate) fn read_operational<C: OpcConfig, B: NetconfConfigBinding<C>>(
    binding: &B,
    state_paths: &[&'static str],
    branches: &[NetconfInstanceBranch],
    limits: &MgmtLimits,
) -> Result<(OperationalResponse, Vec<&'static str>), RpcError> {
    if state_paths.is_empty() {
        return Ok((OperationalResponse::default(), Vec::new()));
    }
    let registry = binding.schema_registry();
    let mut requested = std::collections::BTreeMap::new();
    for path in state_paths {
        if branches.is_empty() {
            requested.insert(
                (*path).to_string(),
                YangPath::new(*path).map_err(|_| RpcError::operation_failed())?,
            );
            continue;
        }
        for branch in branches
            .iter()
            .filter(|branch| branch.schema_paths.contains(path))
        {
            let mut prefix = String::new();
            let mut elements = Vec::new();
            for name in path.trim_start_matches('/').split('/') {
                prefix.push('/');
                prefix.push_str(name);
                elements.push(PathSegment::with_keys(
                    name,
                    branch
                        .predicates
                        .iter()
                        .filter(|predicate| predicate.list_path == prefix)
                        .map(|predicate| {
                            (
                                predicate.key_path.rsplit('/').next().unwrap_or_default(),
                                predicate.value.as_str(),
                            )
                        }),
                ));
            }
            let resolved =
                opc_mgmt_path::resolve_read(registry, &RequestPath::from_elems(elements))
                    .map_err(|_| RpcError::operation_failed())?;
            if let Some(resolved) = resolved {
                requested.insert(resolved.canonical.as_str().to_string(), resolved.canonical);
            }
            limits
                .check_paths(requested.len())
                .map_err(|_| RpcError::too_big())?;
        }
    }
    if requested.is_empty() {
        return Ok((OperationalResponse::default(), Vec::new()));
    }
    limits
        .check_paths(requested.len())
        .map_err(|_| RpcError::too_big())?;
    let request = OperationalRequest::new(requested.into_values())
        .with_max_values(limits.max_paths_per_request)
        .with_max_value_bytes(limits.max_value_bytes);
    let mut response = binding
        .get_operational_state(&request)
        .map_err(|_| RpcError::operation_failed())?;
    response
        .validate_for_request(&request)
        .map_err(|error| match error {
            OperationalResponseError::LimitExceeded => RpcError::too_big(),
            _ => RpcError::operation_failed(),
        })?;
    let mut available = Vec::new();
    for value in &response.values {
        let resolved = opc_mgmt_path::resolve_instance(registry, value.path())
            .map_err(|_| RpcError::operation_failed())?;
        if resolved.node.config || !state_paths.contains(&resolved.node.path) {
            return Err(RpcError::operation_failed());
        }
        available.push(resolved.node.path);
    }
    available.sort_unstable();
    available.dedup();
    response
        .values
        .sort_by(|a, b| a.path().as_str().cmp(b.path().as_str()));
    Ok((response, available))
}

pub(crate) fn config_render_paths(
    registry: &dyn SchemaRegistry,
    authorization: &opc_mgmt_authz::AuthorizedReadSelection,
    selected: &[&'static str],
    configuration: &[&'static str],
    available_state: &[&'static str],
) -> Vec<&'static str> {
    let mut paths = authorization.xml_paths_where(selected, |path| configuration.contains(&path));
    paths.extend(
        authorization
            .xml_paths_where(selected, |path| available_state.contains(&path))
            .into_iter()
            .filter(|path| {
                registry.node(path).is_some_and(|node| {
                    node.config && matches!(node.kind, NodeKind::Container | NodeKind::List)
                })
            }),
    );
    paths.retain(|path| registry.node(path).is_some_and(|node| node.config));
    paths.sort_unstable();
    paths.dedup();
    paths
}
