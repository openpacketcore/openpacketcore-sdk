//! Typed discovery inputs for content matching, gated before metadata rows.

use opc_mgmt_schema::subtree::{SubtreeError, SubtreeProjection, SubtreeScalar};
use opc_mgmt_schema::NetconfXmlNode;

use super::*;

pub(crate) fn project_yang_library(
    registry: &dyn SchemaRegistry,
    ctx: &SubtreeProjection<'_>,
) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
    if !ctx.enter(YANG_LIBRARY_ROOT, true)? {
        return Ok(Vec::new());
    }
    if registry.discovery_metadata().is_empty() {
        return Err(SubtreeError::Unsupported);
    }
    let mut root = branch(YANG_LIBRARY_ROOT, ctx)?;
    leaf(
        &mut root,
        YANG_LIBRARY_CONTENT_ID,
        || Ok(registry.schema_digest()),
        ctx,
    )?;
    if ctx.enter(YANG_LIBRARY_MODULE_SET, true)? {
        if !ctx.selected(YANG_LIBRARY_MODULE_SET_NAME)? {
            return Err(SubtreeError::Projection);
        }
        ctx.row(YANG_LIBRARY_MODULE_SET)?;
        let mut set = branch(YANG_LIBRARY_MODULE_SET, ctx)?;
        key(&mut set, YANG_LIBRARY_MODULE_SET_NAME, "complete", ctx)?;
        for import_only in [false, true] {
            let list = if import_only {
                YANG_LIBRARY_IMPORT_ONLY_MODULE
            } else {
                YANG_LIBRARY_MODULE
            };
            if !ctx.enter(list, true)? {
                continue;
            }
            for metadata in registry.discovery_metadata() {
                ctx.row(list)?;
                if (metadata.conformance == ModuleConformance::Import) != import_only {
                    continue;
                }
                let mut module = branch(list, ctx)?;
                let (name, revision, namespace, location) = if import_only {
                    (
                        YANG_LIBRARY_IMPORT_ONLY_MODULE_NAME,
                        YANG_LIBRARY_IMPORT_ONLY_MODULE_REVISION,
                        YANG_LIBRARY_IMPORT_ONLY_MODULE_NAMESPACE,
                        YANG_LIBRARY_IMPORT_ONLY_MODULE_LOCATION,
                    )
                } else {
                    (
                        YANG_LIBRARY_MODULE_NAME,
                        YANG_LIBRARY_MODULE_REVISION,
                        YANG_LIBRARY_MODULE_NAMESPACE,
                        YANG_LIBRARY_MODULE_LOCATION,
                    )
                };
                key(&mut module, name, metadata.name, ctx)?;
                if import_only {
                    key(&mut module, revision, metadata.revision, ctx)?;
                } else if ctx.enter(revision, false)? && !metadata.revision.is_empty() {
                    scalar(&mut module, revision, metadata.revision, ctx)?;
                }
                leaf(
                    &mut module,
                    namespace,
                    || namespace_for(registry, metadata, ctx),
                    ctx,
                )?;
                leaf(&mut module, location, || Ok("NETCONF"), ctx)?;
                if !import_only {
                    if ctx.enter(YANG_LIBRARY_MODULE_FEATURE, false)? {
                        for feature in metadata.features {
                            let _admission = ctx
                                .budget()
                                .audit_admission("content project_yang_library visit 1", || {
                                    ctx.budget().charge(1)
                                })?;
                            _admission.visit();
                            scalar(&mut module, YANG_LIBRARY_MODULE_FEATURE, feature, ctx)?;
                        }
                    }
                    if ctx.enter(YANG_LIBRARY_MODULE_DEVIATION, false)? {
                        for deviation in metadata.deviations {
                            let _admission = ctx
                                .budget()
                                .audit_admission("content project_yang_library visit 2", || {
                                    ctx.budget().charge(1)
                                })?;
                            _admission.visit();
                            scalar(&mut module, YANG_LIBRARY_MODULE_DEVIATION, deviation, ctx)?;
                        }
                    }
                }
                ctx.append(&mut set.children, vec![module])?;
            }
        }
        ctx.append(&mut root.children, vec![set])?;
    }
    Ok(vec![root])
}

pub(crate) fn project_netconf_monitoring(
    registry: &dyn SchemaRegistry,
    ctx: &SubtreeProjection<'_>,
) -> Result<Vec<NetconfXmlNode>, SubtreeError> {
    const ROOT: &str = "/ncm:netconf-state";
    if !ctx.enter(NETCONF_STATE_SCHEMAS, true)? {
        return Ok(Vec::new());
    }
    if registry.discovery_metadata().is_empty() {
        return Err(SubtreeError::Unsupported);
    }
    let mut root = branch(ROOT, ctx)?;
    let mut schemas = branch(NETCONF_STATE_SCHEMAS, ctx)?;
    if ctx.enter(NETCONF_STATE_SCHEMA, true)? {
        for metadata in registry.discovery_metadata() {
            ctx.row(NETCONF_STATE_SCHEMA)?;
            let mut schema = branch(NETCONF_STATE_SCHEMA, ctx)?;
            key(
                &mut schema,
                NETCONF_STATE_SCHEMA_IDENTIFIER,
                metadata.name,
                ctx,
            )?;
            key(
                &mut schema,
                NETCONF_STATE_SCHEMA_VERSION,
                metadata.revision,
                ctx,
            )?;
            key(&mut schema, NETCONF_STATE_SCHEMA_FORMAT, "yang", ctx)?;
            leaf(
                &mut schema,
                NETCONF_STATE_SCHEMA_NAMESPACE,
                || namespace_for(registry, metadata, ctx),
                ctx,
            )?;
            leaf(
                &mut schema,
                NETCONF_STATE_SCHEMA_LOCATION,
                || Ok("NETCONF"),
                ctx,
            )?;
            ctx.append(&mut schemas.children, vec![schema])?;
        }
    }
    ctx.append(&mut root.children, vec![schemas])?;
    Ok(vec![root])
}

fn branch(path: &'static str, ctx: &SubtreeProjection<'_>) -> Result<NetconfXmlNode, SubtreeError> {
    let _admission = ctx
        .budget()
        .audit_admission("content branch visit 1", || ctx.budget().charge(1))?;
    _admission.visit();
    Ok(NetconfXmlNode::branch(path))
}

fn scalar(
    node: &mut NetconfXmlNode,
    path: &'static str,
    value: &str,
    ctx: &SubtreeProjection<'_>,
) -> Result<(), SubtreeError> {
    if let Some(value) = ctx.scalar(path, SubtreeScalar::Text(value), false)? {
        ctx.append(&mut node.children, vec![value])?;
    }
    Ok(())
}

fn leaf<'a>(
    node: &mut NetconfXmlNode,
    path: &'static str,
    value: impl FnOnce() -> Result<&'a str, SubtreeError>,
    ctx: &SubtreeProjection<'_>,
) -> Result<(), SubtreeError> {
    if ctx.enter(path, false)? {
        scalar(node, path, value()?, ctx)?;
    }
    Ok(())
}

fn key(
    node: &mut NetconfXmlNode,
    path: &'static str,
    value: &str,
    ctx: &SubtreeProjection<'_>,
) -> Result<(), SubtreeError> {
    if !ctx.enter(path, false)? {
        return Err(SubtreeError::Projection);
    }
    let _admission = ctx
        .budget()
        .audit_admission("content key visit 1", || ctx.budget().charge(1))?;
    _admission.visit();
    node.keys.push((path, ctx.budget().copy(value)?));
    Ok(())
}

fn namespace_for(
    registry: &dyn SchemaRegistry,
    metadata: &DiscoveryMetadata,
    ctx: &SubtreeProjection<'_>,
) -> Result<&'static str, SubtreeError> {
    for model in registry.served_models() {
        let _admission = ctx
            .budget()
            .audit_admission("content namespace_for visit 1", || ctx.budget().charge(1))?;
        _admission.visit();
        if ctx.budget().compare(model.name, metadata.name)?
            && ctx.budget().compare(model.revision, metadata.revision)?
        {
            return Ok(model.namespace);
        }
    }
    Err(SubtreeError::Projection)
}
