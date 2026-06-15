//! Read-only gNMI Get handling.

#![allow(deprecated)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use opc_config_model::{OpcConfig, TrustedPrincipal, YangPath};
use opc_mgmt_authz::{ReadAction, ReadAuthorizer};
use opc_mgmt_opstate::{OperationalError, OperationalRequest, OperationalResponse};
use opc_mgmt_schema::{NodeKind, SchemaRegistry};

use crate::binding::{ReadSelection, ReadSelectionEntry};
use crate::metrics::{record_nacm_denials, GnmiNacmAction};
use crate::proto::gnmi;
use crate::proto_adapter::path_from_proto;
use crate::{
    Encoding, GnmiConfigBinding, GnmiError, GnmiJsonUpdate, GnmiPath, GnmiServer, ResolvedGnmiPath,
};

/// Executes a read-only gNMI Get request.
pub(crate) fn handle_get<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    request: &gnmi::GetRequest,
) -> Result<gnmi::GetResponse, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let encoding = encoding_from_proto(request.encoding)?;
    if !server.profile().encodings().supports(encoding) {
        return Err(GnmiError::from(encoding));
    }

    let data_type = GetDataType::from_proto(request.r#type)?;
    let model_filter = ModelFilter::new(server.binding().schema(), &request.use_models)?;
    let prefix = request.prefix.as_ref().map(path_from_proto).transpose()?;
    let request_paths = request
        .path
        .iter()
        .map(path_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    if prefix.as_ref().is_some_and(path_has_target) || request_paths.iter().any(path_has_target) {
        return Err(GnmiError::unimplemented(
            "non-empty gNMI target is not supported",
        ));
    }
    let selected_entries = select_paths(
        server.binding().schema(),
        server.limits(),
        prefix.as_ref(),
        &request_paths,
        data_type,
        &model_filter,
    )?;

    if selected_entries.is_empty() {
        return Ok(gnmi::GetResponse {
            notification: Vec::new(),
            error: None,
            extension: Vec::new(),
        });
    }

    let authz_source = server.binding().policy_source();
    let authz = ReadAuthorizer::new(server.binding().schema(), authz_source.as_ref())
        .map_err(|_| GnmiError::schema("gNMI read authorizer setup failed"))?;
    let decision_input = selected_entries
        .iter()
        .map(ReadSelectionEntry::schema_path)
        .collect::<Vec<_>>();
    let decisions = authz
        .authorize(principal, ReadAction::Read, &decision_input)
        .map_err(|_| GnmiError::unavailable("gNMI read policy source unavailable"))?;

    let denied_count = decisions
        .iter()
        .filter(|decision| !decision.allowed)
        .count();
    record_nacm_denials(GnmiNacmAction::Read, denied_count);

    let allowed_entries = decisions
        .iter()
        .zip(selected_entries.iter())
        .filter_map(|(decision, entry)| decision.allowed.then_some(entry.clone()))
        .collect::<Vec<_>>();

    let config_entries = allowed_entries
        .iter()
        .filter(|entry| {
            server
                .binding()
                .schema()
                .node(entry.schema_path())
                .is_some_and(|node| node.config)
        })
        .cloned()
        .collect::<Vec<_>>();
    let state_entries = allowed_entries
        .iter()
        .filter(|entry| {
            server
                .binding()
                .schema()
                .node(entry.schema_path())
                .is_some_and(|node| !node.config)
        })
        .cloned()
        .collect::<Vec<_>>();

    let operational = read_operational(server.binding(), &state_entries)?;
    let state_entries_with_values = state_entries_with_values(&state_entries, &operational);
    let config_entries = config_entries_for_render(server.binding().schema(), &config_entries);

    if config_entries.is_empty() && state_entries_with_values.is_empty() {
        return Ok(gnmi::GetResponse {
            notification: Vec::new(),
            error: None,
            extension: Vec::new(),
        });
    }

    let snapshot = server.binding().config_bus().current_snapshot();
    let config_paths = schema_paths_for_entries(&config_entries);
    let state_paths = schema_paths_for_entries(&state_entries_with_values);
    let updates = server
        .binding()
        .render_get_json(
            snapshot.config.as_ref(),
            ReadSelection::with_entries(&config_paths, &config_entries),
            &operational,
            ReadSelection::with_entries(&state_paths, &state_entries_with_values),
        )
        .map_err(|err| GnmiError::schema(err.detail().to_string()))?;

    let updates = updates
        .iter()
        .map(|update| update_to_proto(update, encoding, server.limits()))
        .collect::<Result<Vec<_>, _>>()?;

    let notification = if updates.is_empty() {
        Vec::new()
    } else {
        vec![gnmi::Notification {
            timestamp: now_nanos(),
            prefix: None,
            update: updates,
            delete: Vec::new(),
            atomic: true,
        }]
    };

    Ok(gnmi::GetResponse {
        notification,
        error: None,
        extension: Vec::new(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetDataType {
    All,
    Config,
    State,
    Operational,
}

impl GetDataType {
    fn from_proto(value: i32) -> Result<Self, GnmiError> {
        match gnmi::get_request::DataType::try_from(value) {
            Ok(gnmi::get_request::DataType::All) => Ok(Self::All),
            Ok(gnmi::get_request::DataType::Config) => Ok(Self::Config),
            Ok(gnmi::get_request::DataType::State) => Ok(Self::State),
            Ok(gnmi::get_request::DataType::Operational) => Ok(Self::Operational),
            Err(_) => Err(GnmiError::invalid("unknown gNMI Get data type")),
        }
    }

    const fn allows(self, config: bool) -> bool {
        match self {
            Self::All => true,
            Self::Config => config,
            Self::State | Self::Operational => !config,
        }
    }
}

struct ModelFilter {
    modules: Option<HashSet<&'static str>>,
}

impl ModelFilter {
    fn new(
        registry: &'static dyn SchemaRegistry,
        requested: &[gnmi::ModelData],
    ) -> Result<Self, GnmiError> {
        if requested.is_empty() {
            return Ok(Self { modules: None });
        }

        let mut modules = HashSet::new();
        for model in requested {
            let Some(served) = registry.served_models().iter().find(|served| {
                served.name == model.name
                    && (model.version.is_empty() || served.revision == model.version)
            }) else {
                return Err(GnmiError::invalid("gNMI Get requested an unserved model"));
            };
            modules.insert(served.name);
        }
        Ok(Self {
            modules: Some(modules),
        })
    }

    fn allows(&self, module: &str) -> bool {
        self.modules
            .as_ref()
            .is_none_or(|modules| modules.contains(module))
    }
}

fn select_paths(
    registry: &'static dyn SchemaRegistry,
    limits: &opc_mgmt_limits::MgmtLimits,
    prefix: Option<&GnmiPath>,
    request_paths: &[GnmiPath],
    data_type: GetDataType,
    model_filter: &ModelFilter,
) -> Result<Vec<ReadSelectionEntry>, GnmiError> {
    let mut selected = Vec::new();

    if request_paths.is_empty() {
        if let Some(prefix) = prefix.filter(|prefix| !prefix.elems.is_empty()) {
            let resolved = crate::resolve_path(registry, None, prefix)?;
            expand_from_resolved(registry, &resolved, data_type, model_filter, &mut selected)?;
        } else {
            let origin_modules = root_origin_modules(registry, prefix, None)?;
            select_all_matching(
                registry,
                data_type,
                model_filter,
                origin_modules.as_ref(),
                &mut selected,
            )?;
        }
    } else {
        limits
            .check_paths(request_paths.len())
            .map_err(GnmiError::from_limits)?;
        for path in request_paths {
            if path.elems.is_empty() {
                let origin_modules = root_origin_modules(registry, prefix, Some(path))?;
                if let Some(prefix) = prefix {
                    if prefix.elems.is_empty() {
                        select_all_matching(
                            registry,
                            data_type,
                            model_filter,
                            origin_modules.as_ref(),
                            &mut selected,
                        )?;
                    } else {
                        let resolved = crate::resolve_path(registry, None, prefix)?;
                        expand_from_resolved(
                            registry,
                            &resolved,
                            data_type,
                            model_filter,
                            &mut selected,
                        )?;
                    }
                } else {
                    select_all_matching(
                        registry,
                        data_type,
                        model_filter,
                        origin_modules.as_ref(),
                        &mut selected,
                    )?;
                }
                continue;
            }
            let resolved = crate::resolve_path(registry, prefix, path)?;
            expand_from_resolved(registry, &resolved, data_type, model_filter, &mut selected)?;
        }
    }

    limits
        .check_paths(selected.len())
        .map_err(GnmiError::from_limits)?;
    selected.sort_by(|a, b| {
        a.schema_path()
            .cmp(b.schema_path())
            .then_with(|| a.canonical_path().as_str().cmp(b.canonical_path().as_str()))
    });
    selected.dedup_by(|a, b| {
        a.schema_path() == b.schema_path()
            && a.canonical_path().as_str() == b.canonical_path().as_str()
    });
    Ok(selected)
}

fn select_all_matching(
    registry: &'static dyn SchemaRegistry,
    data_type: GetDataType,
    model_filter: &ModelFilter,
    origin_modules: Option<&HashSet<&'static str>>,
    selected: &mut Vec<ReadSelectionEntry>,
) -> Result<(), GnmiError> {
    for node in registry.nodes() {
        if data_type.allows(node.config)
            && model_filter.allows(node.module)
            && origin_modules.is_none_or(|modules| modules.contains(node.module))
        {
            selected.push(ReadSelectionEntry::new(
                node.path,
                YangPath::new(node.path).map_err(|_| GnmiError::schema("invalid schema path"))?,
            ));
        }
    }
    Ok(())
}

fn root_origin_modules(
    registry: &'static dyn SchemaRegistry,
    prefix: Option<&GnmiPath>,
    path: Option<&GnmiPath>,
) -> Result<Option<HashSet<&'static str>>, GnmiError> {
    let prefix_origin = prefix.and_then(|path| path.origin.as_deref());
    let path_origin = path.and_then(|path| path.origin.as_deref());
    let origin = match (prefix_origin, path_origin) {
        (Some(prefix), Some(path)) if prefix != path => {
            return Err(GnmiError::invalid(
                "gNMI prefix origin and path origin differ",
            ));
        }
        (Some(origin), _) | (_, Some(origin)) => Some(origin),
        (None, None) => None,
    };
    let Some(origin) = origin else {
        return Ok(None);
    };
    let modules = registry
        .modules_for_origin(origin)
        .ok_or_else(|| GnmiError::invalid("unknown gNMI origin"))?;
    Ok(Some(modules.iter().copied().collect()))
}

fn expand_from_resolved(
    registry: &'static dyn SchemaRegistry,
    resolved: &ResolvedGnmiPath,
    data_type: GetDataType,
    model_filter: &ModelFilter,
    selected: &mut Vec<ReadSelectionEntry>,
) -> Result<(), GnmiError> {
    if !model_filter.allows(resolved.node.module) {
        return Err(GnmiError::invalid(
            "gNMI Get path is outside the requested model set",
        ));
    }

    let root = resolved.schema_path.as_str();
    for node in registry.nodes() {
        let under_root = node.path == root
            || node
                .path
                .strip_prefix(root)
                .is_some_and(|suffix| suffix.starts_with('/'));
        if under_root && data_type.allows(node.config) && model_filter.allows(node.module) {
            selected.push(ReadSelectionEntry::new(
                node.path,
                canonical_descendant_path(resolved, node.path)?,
            ));
        }
    }
    Ok(())
}

fn canonical_descendant_path(
    resolved: &ResolvedGnmiPath,
    schema_path: &'static str,
) -> Result<YangPath, GnmiError> {
    if schema_path == resolved.schema_path {
        return Ok(resolved.canonical.clone());
    }
    let suffix = schema_path
        .strip_prefix(resolved.schema_path.as_str())
        .ok_or_else(|| GnmiError::schema("invalid selected schema descendant"))?;
    YangPath::new(format!("{}{}", resolved.canonical.as_str(), suffix))
        .map_err(|_| GnmiError::schema("invalid selected canonical path"))
}

fn path_has_target(path: &GnmiPath) -> bool {
    path.target.is_some()
}

fn config_entries_for_render(
    registry: &'static dyn SchemaRegistry,
    entries: &[ReadSelectionEntry],
) -> Vec<ReadSelectionEntry> {
    if entries.iter().any(|entry| {
        registry.node(entry.schema_path()).is_some_and(|node| {
            node.config
                && (node.presence || matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList))
        })
    }) {
        entries.to_vec()
    } else {
        Vec::new()
    }
}

fn schema_paths_for_entries(entries: &[ReadSelectionEntry]) -> Vec<&'static str> {
    let mut paths = entries
        .iter()
        .map(ReadSelectionEntry::schema_path)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn read_operational<C, B>(
    binding: &B,
    state_entries: &[ReadSelectionEntry],
) -> Result<OperationalResponse, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    if state_entries.is_empty() {
        return Ok(OperationalResponse::default());
    }
    let requested = state_entries
        .iter()
        .map(|entry| entry.canonical_path().clone())
        .collect::<Vec<_>>();
    let request = OperationalRequest::new(requested);
    let response = binding
        .operational_state()
        .get(&request)
        .map_err(operational_error)?;
    response
        .validate_for_request(&request)
        .map_err(|_| GnmiError::schema("invalid operational response"))?;
    Ok(response)
}

fn operational_error(err: OperationalError) -> GnmiError {
    match err {
        OperationalError::Unavailable { .. } => {
            GnmiError::unavailable("gNMI operational provider unavailable")
        }
        OperationalError::Internal { .. } | OperationalError::InvalidValue => {
            GnmiError::schema("gNMI operational provider failed")
        }
    }
}

fn state_entries_with_values(
    state_entries: &[ReadSelectionEntry],
    operational: &OperationalResponse,
) -> Vec<ReadSelectionEntry> {
    state_entries
        .iter()
        .filter(|entry| operational.value_for(entry.canonical_path()).is_some())
        .cloned()
        .collect()
}

fn encoding_from_proto(value: i32) -> Result<Encoding, GnmiError> {
    match gnmi::Encoding::try_from(value) {
        Ok(gnmi::Encoding::Json) => Ok(Encoding::Json),
        Ok(gnmi::Encoding::JsonIetf) => Ok(Encoding::JsonIetf),
        Ok(gnmi::Encoding::Bytes) => Ok(Encoding::Bytes),
        Ok(gnmi::Encoding::Proto) => Ok(Encoding::Proto),
        Ok(gnmi::Encoding::Ascii) => Ok(Encoding::Ascii),
        Err(_) => Err(GnmiError::invalid("unknown gNMI encoding")),
    }
}

fn update_to_proto(
    update: &GnmiJsonUpdate,
    encoding: Encoding,
    limits: &opc_mgmt_limits::MgmtLimits,
) -> Result<gnmi::Update, GnmiError> {
    limits
        .check_value_bytes(update.value_json().len())
        .map_err(GnmiError::from_limits)?;
    let value = match encoding {
        Encoding::JsonIetf => {
            gnmi::typed_value::Value::JsonIetfVal(update.value_json().as_bytes().to_vec())
        }
        Encoding::Json => {
            gnmi::typed_value::Value::JsonVal(update.value_json().as_bytes().to_vec())
        }
        Encoding::Bytes | Encoding::Proto | Encoding::Ascii => {
            return Err(GnmiError::from(encoding))
        }
    };
    Ok(gnmi::Update {
        path: Some(yang_path_to_proto(update.path())?),
        value: None,
        val: Some(gnmi::TypedValue { value: Some(value) }),
        duplicates: 0,
    })
}

pub(crate) fn yang_path_to_proto(path: &YangPath) -> Result<gnmi::Path, GnmiError> {
    let elems = split_yang_path(path.as_str())?
        .into_iter()
        .map(segment_to_path_elem)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(gnmi::Path {
        element: Vec::new(),
        origin: String::new(),
        elem: elems,
        target: String::new(),
    })
}

fn split_yang_path(path: &str) -> Result<Vec<&str>, GnmiError> {
    let mut out = Vec::new();
    let mut start = 1;
    let mut quote = false;
    let mut escape = false;
    for (idx, ch) in path.char_indices().skip(1) {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if quote => escape = true,
            '\'' => quote = !quote,
            '/' if !quote => {
                out.push(&path[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if quote || escape {
        return Err(GnmiError::schema("invalid canonical YANG path"));
    }
    if start < path.len() {
        out.push(&path[start..]);
    }
    Ok(out)
}

fn segment_to_path_elem(segment: &str) -> Result<gnmi::PathElem, GnmiError> {
    let (name, predicates) = segment
        .split_once('[')
        .map(|(name, rest)| (name, Some(rest)))
        .unwrap_or((segment, None));
    if name.is_empty() {
        return Err(GnmiError::schema("invalid canonical YANG path segment"));
    }
    let mut elem = gnmi::PathElem {
        name: name.to_string(),
        key: std::collections::HashMap::new(),
    };
    let Some(mut rest) = predicates else {
        return Ok(elem);
    };
    loop {
        let Some(end) = find_predicate_end(rest)? else {
            return Err(GnmiError::schema("invalid canonical YANG key predicate"));
        };
        let predicate = &rest[..end];
        let (key, value) = parse_predicate(predicate)?;
        elem.key.insert(key, value);
        rest = &rest[end + 1..];
        if rest.is_empty() {
            return Ok(elem);
        }
        let Some(next) = rest.strip_prefix('[') else {
            return Err(GnmiError::schema("invalid canonical YANG key predicate"));
        };
        rest = next;
    }
}

fn find_predicate_end(rest: &str) -> Result<Option<usize>, GnmiError> {
    let mut quote = false;
    let mut escape = false;
    for (idx, ch) in rest.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if quote => escape = true,
            '\'' => quote = !quote,
            ']' if !quote => return Ok(Some(idx)),
            _ => {}
        }
    }
    if quote || escape {
        return Err(GnmiError::schema("invalid canonical YANG key predicate"));
    }
    Ok(None)
}

fn parse_predicate(predicate: &str) -> Result<(String, String), GnmiError> {
    let (key, raw_value) = predicate
        .split_once('=')
        .ok_or_else(|| GnmiError::schema("invalid canonical YANG key predicate"))?;
    let Some(quoted) = raw_value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    else {
        return Err(GnmiError::schema("invalid canonical YANG key predicate"));
    };
    Ok((key.to_string(), unescape_predicate_value(quoted)?))
}

fn unescape_predicate_value(value: &str) -> Result<String, GnmiError> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(next) = chars.next() else {
                return Err(GnmiError::schema("invalid canonical YANG key predicate"));
            };
            out.push(next);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

pub(crate) fn now_nanos() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    i64::try_from(nanos).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_yang_path_to_proto_path_preserves_keys() {
        let path = YangPath::new("/sys:system/sys:user[sys:name='a\\'b']/sys:role").expect("path");
        let proto = yang_path_to_proto(&path).expect("proto path");

        assert_eq!(proto.elem[0].name, "sys:system");
        assert_eq!(proto.elem[1].name, "sys:user");
        assert_eq!(proto.elem[1].key.get("sys:name"), Some(&"a'b".to_string()));
        assert_eq!(proto.elem[2].name, "sys:role");
    }
}
