//! Generic, schema-registry-driven NETCONF discovery rendering.
//!
//! This module implements the RFC 8525 YANG Library and RFC 6022 NETCONF
//! monitoring `/netconf-state/schemas` trees from data supplied by
//! [`SchemaRegistry::discovery_metadata`]. It is used by the default
//! `NetconfConfigBinding` discovery hooks when the registry carries generated
//! discovery artifacts, so CNFs do not have to hand-write discovery XML merely
//! to expose their served model set.
//!
//! The renderer is intentionally conservative: it only renders paths that are
//! selected by the server, never fabricates module imports/features/deviations
//! that the registry does not provide, and never invents YANG source text for
//! `<get-schema>`.

use std::io::Write;

use opc_mgmt_schema::{
    DiscoveryMetadata, ModelData, ModuleConformance, SchemaRegistry, SchemaSourceError,
};
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;

use crate::binding::{BindingError, GetSchemaError, GetSchemaRequest, ReadSelection};
use crate::capabilities::NETCONF_MONITORING_NS;
use crate::filter::YANG_LIBRARY_NS;

const YANG_LIBRARY_ROOT: &str = "/yanglib:yang-library";
const YANG_LIBRARY_CONTENT_ID: &str = "/yanglib:yang-library/yanglib:content-id";
const YANG_LIBRARY_MODULE_SET: &str = "/yanglib:yang-library/yanglib:module-set";
const YANG_LIBRARY_MODULE_SET_NAME: &str = "/yanglib:yang-library/yanglib:module-set/yanglib:name";
const YANG_LIBRARY_MODULE: &str = "/yanglib:yang-library/yanglib:module-set/yanglib:module";
const YANG_LIBRARY_MODULE_NAME: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:name";
const YANG_LIBRARY_MODULE_REVISION: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:revision";
const YANG_LIBRARY_MODULE_NAMESPACE: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:namespace";
const YANG_LIBRARY_MODULE_LOCATION: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:location";
const YANG_LIBRARY_MODULE_FEATURE: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:feature";
const YANG_LIBRARY_MODULE_DEVIATION: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:module/yanglib:deviation";
const YANG_LIBRARY_IMPORT_ONLY_MODULE: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module";
const YANG_LIBRARY_IMPORT_ONLY_MODULE_NAME: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:name";
const YANG_LIBRARY_IMPORT_ONLY_MODULE_REVISION: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:revision";
const YANG_LIBRARY_IMPORT_ONLY_MODULE_NAMESPACE: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:namespace";
const YANG_LIBRARY_IMPORT_ONLY_MODULE_LOCATION: &str =
    "/yanglib:yang-library/yanglib:module-set/yanglib:import-only-module/yanglib:location";

const NETCONF_STATE_SCHEMAS: &str = "/ncm:netconf-state/ncm:schemas";
const NETCONF_STATE_SCHEMA: &str = "/ncm:netconf-state/ncm:schemas/ncm:schema";
const NETCONF_STATE_SCHEMA_IDENTIFIER: &str =
    "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier";
const NETCONF_STATE_SCHEMA_VERSION: &str = "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version";
const NETCONF_STATE_SCHEMA_FORMAT: &str = "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format";
const NETCONF_STATE_SCHEMA_NAMESPACE: &str =
    "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace";
const NETCONF_STATE_SCHEMA_LOCATION: &str =
    "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location";

/// Renders the RFC 8525 `/yang-library` operational tree for `selection`.
///
/// Returns an XML fragment suitable for placement inside the server's `<data>`
/// response element. The top-level `<yang-library>` element declares the
/// module's namespace.
pub fn render_yang_library(
    registry: &dyn SchemaRegistry,
    selection: ReadSelection<'_>,
) -> Result<String, BindingError> {
    let meta = registry.discovery_metadata();
    if meta.is_empty() {
        return Err(BindingError::projection(
            "schema registry does not carry generated YANG Library metadata",
        ));
    }

    let root_selected = subtree_selected(selection, YANG_LIBRARY_ROOT);
    if !root_selected {
        return Ok(String::new());
    }

    let mut out = Vec::new();
    let mut writer = Writer::new_with_indent(&mut out, b' ', 2);

    writer
        .write_event(Event::Start(
            BytesStart::new("yang-library").with_attributes([("xmlns", YANG_LIBRARY_NS)]),
        ))
        .map_err(|_| BindingError::projection("failed to write yang-library start"))?;

    if selection.contains(YANG_LIBRARY_CONTENT_ID) {
        write_leaf(&mut writer, "content-id", registry.schema_digest())?;
    }

    let module_set_selected = subtree_selected(selection, YANG_LIBRARY_MODULE_SET);
    if module_set_selected {
        writer
            .write_event(Event::Start(BytesStart::new("module-set")))
            .map_err(|_| BindingError::projection("failed to write module-set start"))?;
        write_leaf_if_selected(
            &mut writer,
            selection,
            YANG_LIBRARY_MODULE_SET_NAME,
            "name",
            "complete",
        )?;

        if subtree_selected(selection, YANG_LIBRARY_MODULE) {
            for d in meta
                .iter()
                .filter(|d| d.conformance == ModuleConformance::Implement)
            {
                write_yang_library_module(&mut writer, registry, selection, d, false)?;
            }
        }

        if subtree_selected(selection, YANG_LIBRARY_IMPORT_ONLY_MODULE) {
            for d in meta
                .iter()
                .filter(|d| d.conformance == ModuleConformance::Import)
            {
                write_yang_library_module(&mut writer, registry, selection, d, true)?;
            }
        }

        writer
            .write_event(Event::End(BytesEnd::new("module-set")))
            .map_err(|_| BindingError::projection("failed to write module-set end"))?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("yang-library")))
        .map_err(|_| BindingError::projection("failed to write yang-library end"))?;

    String::from_utf8(out)
        .map_err(|_| BindingError::projection("invalid UTF-8 in YANG Library XML"))
}

/// Renders the RFC 6022 `/netconf-state/schemas` inventory for `selection`.
///
/// Only the `schemas` subtree is generated from the registry; other
/// `/netconf-state` containers (sessions, statistics, capabilities) are not
/// fabricated.
pub fn render_netconf_monitoring(
    registry: &dyn SchemaRegistry,
    selection: ReadSelection<'_>,
) -> Result<String, BindingError> {
    let meta = registry.discovery_metadata();
    if meta.is_empty() {
        return Err(BindingError::projection(
            "schema registry does not carry generated monitoring metadata",
        ));
    }

    let schemas_selected = subtree_selected(selection, NETCONF_STATE_SCHEMAS);
    if !schemas_selected {
        return Ok(String::new());
    }

    let mut out = Vec::new();
    let mut writer = Writer::new_with_indent(&mut out, b' ', 2);

    writer
        .write_event(Event::Start(
            BytesStart::new("netconf-state").with_attributes([("xmlns", NETCONF_MONITORING_NS)]),
        ))
        .map_err(|_| BindingError::projection("failed to write netconf-state start"))?;
    writer
        .write_event(Event::Start(BytesStart::new("schemas")))
        .map_err(|_| BindingError::projection("failed to write schemas start"))?;

    if subtree_selected(selection, NETCONF_STATE_SCHEMA) {
        for d in meta {
            let namespace = served_namespace(registry, d)?;
            writer
                .write_event(Event::Start(BytesStart::new("schema")))
                .map_err(|_| BindingError::projection("failed to write schema start"))?;
            write_leaf_if_selected(
                &mut writer,
                selection,
                NETCONF_STATE_SCHEMA_IDENTIFIER,
                "identifier",
                d.name,
            )?;
            if !d.revision.is_empty() {
                write_leaf_if_selected(
                    &mut writer,
                    selection,
                    NETCONF_STATE_SCHEMA_VERSION,
                    "version",
                    d.revision,
                )?;
            }
            write_leaf_if_selected(
                &mut writer,
                selection,
                NETCONF_STATE_SCHEMA_FORMAT,
                "format",
                "yang",
            )?;
            write_leaf_if_selected(
                &mut writer,
                selection,
                NETCONF_STATE_SCHEMA_NAMESPACE,
                "namespace",
                namespace,
            )?;
            write_leaf_if_selected(
                &mut writer,
                selection,
                NETCONF_STATE_SCHEMA_LOCATION,
                "location",
                "NETCONF",
            )?;
            writer
                .write_event(Event::End(BytesEnd::new("schema")))
                .map_err(|_| BindingError::projection("failed to write schema end"))?;
        }
    }

    writer
        .write_event(Event::End(BytesEnd::new("schemas")))
        .map_err(|_| BindingError::projection("failed to write schemas end"))?;
    writer
        .write_event(Event::End(BytesEnd::new("netconf-state")))
        .map_err(|_| BindingError::projection("failed to write netconf-state end"))?;

    String::from_utf8(out)
        .map_err(|_| BindingError::projection("invalid UTF-8 in NETCONF monitoring XML"))
}

/// Looks up a YANG module source in the registry.
///
/// `format` other than `yang` is rejected as unsupported. The returned text is
/// raw YANG source; the server escapes it when rendering the `<get-schema>`
/// `<data>` element.
pub fn schema_source(
    registry: &dyn SchemaRegistry,
    request: &GetSchemaRequest,
) -> Result<String, GetSchemaError> {
    match registry.schema_source(
        &request.identifier,
        request.version.as_deref(),
        &request.format,
    ) {
        Ok(text) => Ok(text.to_string()),
        Err(SchemaSourceError::NotFound) => Err(GetSchemaError::NotFound),
        Err(SchemaSourceError::NotUnique) => Err(GetSchemaError::NotUnique),
        Err(SchemaSourceError::UnsupportedFormat) => Err(GetSchemaError::failed(
            "NETCONF get-schema format is not supported",
        )),
    }
}

fn write_yang_library_module<W: Write>(
    writer: &mut Writer<W>,
    registry: &dyn SchemaRegistry,
    selection: ReadSelection<'_>,
    d: &DiscoveryMetadata,
    import_only: bool,
) -> Result<(), BindingError> {
    let namespace = served_namespace(registry, d)?;
    let tag = if import_only {
        "import-only-module"
    } else {
        "module"
    };
    let (name_path, revision_path, namespace_path, location_path) = if import_only {
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

    writer
        .write_event(Event::Start(BytesStart::new(tag)))
        .map_err(|_| BindingError::projection("failed to write module start"))?;
    write_leaf_if_selected(writer, selection, name_path, "name", d.name)?;
    if !d.revision.is_empty() {
        write_leaf_if_selected(writer, selection, revision_path, "revision", d.revision)?;
    }
    write_leaf_if_selected(writer, selection, namespace_path, "namespace", namespace)?;
    write_leaf_if_selected(writer, selection, location_path, "location", "NETCONF")?;

    if !import_only {
        if selection.contains(YANG_LIBRARY_MODULE_FEATURE) {
            for feature in d.features {
                write_leaf(writer, "feature", feature)?;
            }
        }
        if selection.contains(YANG_LIBRARY_MODULE_DEVIATION) {
            for deviation in d.deviations {
                write_leaf(writer, "deviation", deviation)?;
            }
        }
    }

    writer
        .write_event(Event::End(BytesEnd::new(tag)))
        .map_err(|_| BindingError::projection("failed to write module end"))?;
    Ok(())
}

fn served_namespace<'a>(
    registry: &'a dyn SchemaRegistry,
    d: &'a DiscoveryMetadata,
) -> Result<&'a str, BindingError> {
    served_model(registry, d).map(|m| m.namespace)
}

fn served_model<'a>(
    registry: &'a dyn SchemaRegistry,
    d: &'a DiscoveryMetadata,
) -> Result<&'a ModelData, BindingError> {
    registry
        .served_models()
        .iter()
        .find(|m| m.name == d.name && m.revision == d.revision)
        .ok_or_else(|| {
            BindingError::projection(
                "schema registry discovery metadata references an unserved module",
            )
        })
}

fn write_leaf_if_selected<W: Write>(
    writer: &mut Writer<W>,
    selection: ReadSelection<'_>,
    path: &str,
    local: &str,
    value: &str,
) -> Result<(), BindingError> {
    if selection.contains(path) {
        write_leaf(writer, local, value)?;
    }
    Ok(())
}

fn subtree_selected(selection: ReadSelection<'_>, root: &str) -> bool {
    selection.schema_paths().iter().any(|path| {
        path.strip_prefix(root)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    })
}

fn write_leaf<W: Write>(
    writer: &mut Writer<W>,
    local: &str,
    value: &str,
) -> Result<(), BindingError> {
    writer
        .write_event(Event::Start(BytesStart::new(local)))
        .map_err(|_| BindingError::projection("failed to write leaf start"))?;
    writer
        .write_event(Event::Text(quick_xml::events::BytesText::new(value)))
        .map_err(|_| BindingError::projection("failed to write leaf text"))?;
    writer
        .write_event(Event::End(BytesEnd::new(local)))
        .map_err(|_| BindingError::projection("failed to write leaf end"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use opc_mgmt_schema::{
        DiscoveryMetadata, ModelData, ModuleConformance, ModuleImport, SchemaRegistry,
        SchemaSourceError,
    };

    use super::*;

    struct FakeRegistry {
        models: &'static [ModelData],
        discovery: &'static [DiscoveryMetadata],
    }

    impl SchemaRegistry for FakeRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:discovery-test"
        }

        fn served_models(&self) -> &'static [ModelData] {
            self.models
        }

        fn nodes(&self) -> &'static [opc_mgmt_schema::NodeMeta] {
            &[]
        }

        fn origins(&self) -> &'static [opc_mgmt_schema::OriginEntry] {
            &[]
        }

        fn discovery_metadata(&self) -> &'static [DiscoveryMetadata] {
            self.discovery
        }

        fn schema_source(
            &self,
            identifier: &str,
            version: Option<&str>,
            format: &str,
        ) -> Result<&'static str, SchemaSourceError> {
            if format != "yang" {
                return Err(SchemaSourceError::UnsupportedFormat);
            }
            let mut matched = None;
            for d in self.discovery {
                if d.name != identifier {
                    continue;
                }
                if let Some(v) = version {
                    if d.revision != v {
                        continue;
                    }
                }
                if matched.is_some() {
                    return Err(SchemaSourceError::NotUnique);
                }
                matched = Some(d);
            }
            let d = matched.ok_or(SchemaSourceError::NotFound)?;
            d.source.ok_or(SchemaSourceError::NotFound)
        }
    }

    static MODELS: &[ModelData] = &[
        ModelData {
            name: "example",
            revision: "2026-01-01",
            namespace: "urn:opc:example",
            prefix: "ex",
        },
        ModelData {
            name: "example-types",
            revision: "2026-01-01",
            namespace: "urn:opc:example-types",
            prefix: "ext",
        },
        ModelData {
            name: "unavailable",
            revision: "2026-01-01",
            namespace: "urn:opc:unavailable",
            prefix: "un",
        },
    ];

    static IMPORTS: &[ModuleImport] = &[ModuleImport {
        name: "example-types",
        revision: Some("2026-01-01"),
    }];

    static FEATURES: &[&str] = &["feature-a"];

    static DEVIATIONS: &[&str] = &["example-devs"];

    static DISCOVERY: &[DiscoveryMetadata] = &[
        DiscoveryMetadata {
            name: "example",
            revision: "2026-01-01",
            conformance: ModuleConformance::Implement,
            imports: IMPORTS,
            features: FEATURES,
            deviations: DEVIATIONS,
            source: Some("module example { ... }"),
        },
        DiscoveryMetadata {
            name: "example-types",
            revision: "2026-01-01",
            conformance: ModuleConformance::Import,
            imports: &[],
            features: &[],
            deviations: &[],
            source: Some("module example-types { ... }"),
        },
        DiscoveryMetadata {
            name: "unavailable",
            revision: "2026-01-01",
            conformance: ModuleConformance::Implement,
            imports: &[],
            features: &[],
            deviations: &[],
            source: None,
        },
    ];

    fn test_registry() -> FakeRegistry {
        FakeRegistry {
            models: MODELS,
            discovery: DISCOVERY,
        }
    }

    const YANG_LIBRARY_FULL_SELECTION: &[&str] = &[
        YANG_LIBRARY_CONTENT_ID,
        YANG_LIBRARY_MODULE_SET,
        YANG_LIBRARY_MODULE_SET_NAME,
        YANG_LIBRARY_MODULE,
        YANG_LIBRARY_MODULE_NAME,
        YANG_LIBRARY_MODULE_REVISION,
        YANG_LIBRARY_MODULE_NAMESPACE,
        YANG_LIBRARY_MODULE_LOCATION,
        YANG_LIBRARY_MODULE_FEATURE,
        YANG_LIBRARY_MODULE_DEVIATION,
        YANG_LIBRARY_IMPORT_ONLY_MODULE,
        YANG_LIBRARY_IMPORT_ONLY_MODULE_NAME,
        YANG_LIBRARY_IMPORT_ONLY_MODULE_REVISION,
        YANG_LIBRARY_IMPORT_ONLY_MODULE_NAMESPACE,
        YANG_LIBRARY_IMPORT_ONLY_MODULE_LOCATION,
    ];

    const MONITORING_FULL_SELECTION: &[&str] = &[
        NETCONF_STATE_SCHEMAS,
        NETCONF_STATE_SCHEMA,
        NETCONF_STATE_SCHEMA_IDENTIFIER,
        NETCONF_STATE_SCHEMA_VERSION,
        NETCONF_STATE_SCHEMA_FORMAT,
        NETCONF_STATE_SCHEMA_NAMESPACE,
        NETCONF_STATE_SCHEMA_LOCATION,
    ];

    #[test]
    fn yang_library_renders_content_id_from_schema_digest() {
        let registry = test_registry();
        let xml = render_yang_library(&registry, ReadSelection::new(&[YANG_LIBRARY_CONTENT_ID]))
            .expect("render");
        assert!(xml.contains(&format!("xmlns=\"{}\"", crate::filter::YANG_LIBRARY_NS)));
        assert!(xml.contains("<content-id>fnv1a64:discovery-test</content-id>"));
    }

    #[test]
    fn yang_library_content_id_only_when_module_set_not_selected() {
        let registry = test_registry();
        let xml = render_yang_library(&registry, ReadSelection::new(&[YANG_LIBRARY_CONTENT_ID]))
            .expect("render");
        assert!(xml.contains("<content-id>"));
        assert!(!xml.contains("<module-set>"));
    }

    #[test]
    fn yang_library_module_set_includes_selected_features_and_deviations() {
        let registry = test_registry();
        let xml = render_yang_library(&registry, ReadSelection::new(YANG_LIBRARY_FULL_SELECTION))
            .expect("render");
        assert!(xml.contains("<module-set>"));
        assert!(xml.contains("<name>complete</name>"));
        assert!(xml.contains("<name>example</name>"));
        assert!(xml.contains("<revision>2026-01-01</revision>"));
        assert!(xml.contains("<namespace>urn:opc:example</namespace>"));
        assert!(xml.contains("<location>NETCONF</location>"));
        assert!(!xml.contains("<import>"));
        assert!(xml.contains("<name>example-types</name>"));
        assert!(xml.contains("<revision>2026-01-01</revision>"));
        assert!(xml.contains("<feature>feature-a</feature>"));
        assert!(xml.contains("<deviation>example-devs</deviation>"));
    }

    #[test]
    fn yang_library_import_only_module_uses_correct_tag() {
        let registry = test_registry();
        let xml = render_yang_library(
            &registry,
            ReadSelection::new(&[
                YANG_LIBRARY_MODULE,
                YANG_LIBRARY_MODULE_NAME,
                YANG_LIBRARY_IMPORT_ONLY_MODULE,
                YANG_LIBRARY_IMPORT_ONLY_MODULE_NAME,
            ]),
        )
        .expect("render");
        assert!(xml.contains("<module>"));
        assert!(xml.contains("<import-only-module>"));
        assert!(xml.contains("<name>example-types</name>"));
    }

    #[test]
    fn yang_library_honors_leaf_selection_after_nacm() {
        let registry = test_registry();
        let xml = render_yang_library(
            &registry,
            ReadSelection::new(&[YANG_LIBRARY_MODULE, YANG_LIBRARY_MODULE_NAME]),
        )
        .expect("render");
        assert!(xml.contains("<module>"));
        assert!(xml.contains("<name>example</name>"));
        assert!(!xml.contains("<namespace>urn:opc:example</namespace>"));
        assert!(!xml.contains("<revision>2026-01-01</revision>"));
        assert!(!xml.contains("<feature>feature-a</feature>"));
        assert!(!xml.contains("<deviation>example-devs</deviation>"));
        assert!(!xml.contains("<location>NETCONF</location>"));
    }

    #[test]
    fn yang_library_fails_closed_when_discovery_module_is_not_served() {
        static META: &[DiscoveryMetadata] = &[DiscoveryMetadata {
            name: "orphan",
            revision: "2026-01-01",
            conformance: ModuleConformance::Implement,
            imports: &[],
            features: &[],
            deviations: &[],
            source: None,
        }];
        let registry = FakeRegistry {
            models: MODELS,
            discovery: META,
        };
        let err = render_yang_library(
            &registry,
            ReadSelection::new(&[YANG_LIBRARY_MODULE, YANG_LIBRARY_MODULE_NAMESPACE]),
        )
        .expect_err("orphan discovery metadata must fail closed");
        assert!(err.message().contains("unserved module"));
    }

    #[test]
    fn yang_library_returns_empty_when_root_not_selected() {
        let registry = test_registry();
        let xml =
            render_yang_library(&registry, ReadSelection::new(&["/other:root"])).expect("render");
        assert!(xml.is_empty());
    }

    #[test]
    fn yang_library_fails_closed_without_discovery_metadata() {
        let registry = FakeRegistry {
            models: MODELS,
            discovery: &[],
        };
        let err = render_yang_library(&registry, ReadSelection::new(&[YANG_LIBRARY_CONTENT_ID]))
            .expect_err("should fail");
        assert!(err
            .message()
            .contains("does not carry generated YANG Library"));
    }

    #[test]
    fn netconf_monitoring_renders_schemas_inventory() {
        let registry = test_registry();
        let xml =
            render_netconf_monitoring(&registry, ReadSelection::new(MONITORING_FULL_SELECTION))
                .expect("render");
        assert!(xml.contains(&format!(
            "xmlns=\"{}\"",
            crate::capabilities::NETCONF_MONITORING_NS
        )));
        assert!(xml.contains("<identifier>example</identifier>"));
        assert!(xml.contains("<version>2026-01-01</version>"));
        assert!(xml.contains("<format>yang</format>"));
        assert!(xml.contains("<namespace>urn:opc:example</namespace>"));
        assert!(xml.contains("<location>NETCONF</location>"));
    }

    #[test]
    fn netconf_monitoring_honors_leaf_selection_after_nacm() {
        let registry = test_registry();
        let xml = render_netconf_monitoring(
            &registry,
            ReadSelection::new(&[NETCONF_STATE_SCHEMA, NETCONF_STATE_SCHEMA_IDENTIFIER]),
        )
        .expect("render");
        assert!(xml.contains("<schema>"));
        assert!(xml.contains("<identifier>example</identifier>"));
        assert!(!xml.contains("<namespace>urn:opc:example</namespace>"));
        assert!(!xml.contains("<version>2026-01-01</version>"));
        assert!(!xml.contains("<format>yang</format>"));
        assert!(!xml.contains("<location>NETCONF</location>"));
    }

    #[test]
    fn netconf_monitoring_returns_empty_when_schemas_not_selected() {
        let registry = test_registry();
        let xml = render_netconf_monitoring(&registry, ReadSelection::new(&["/ncm:netconf-state"]))
            .expect("render");
        assert!(xml.is_empty());
    }

    #[test]
    fn netconf_monitoring_fails_closed_without_discovery_metadata() {
        let registry = FakeRegistry {
            models: MODELS,
            discovery: &[],
        };
        let err = render_netconf_monitoring(
            &registry,
            ReadSelection::new(&["/ncm:netconf-state/ncm:schemas"]),
        )
        .expect_err("should fail");
        assert!(err
            .message()
            .contains("does not carry generated monitoring"));
    }

    #[test]
    fn schema_source_returns_text_for_matching_name() {
        let registry = test_registry();
        let request = GetSchemaRequest {
            identifier: "example".to_string(),
            version: Some("2026-01-01".to_string()),
            format: "yang".to_string(),
        };
        let text = schema_source(&registry, &request).expect("source");
        assert_eq!(text, "module example { ... }");
    }

    #[test]
    fn schema_source_is_ambiguous_without_version_when_multiple_revisions_match() {
        static META: &[DiscoveryMetadata] = &[
            DiscoveryMetadata {
                name: "example",
                revision: "2026-01-01",
                conformance: ModuleConformance::Implement,
                imports: &[],
                features: &[],
                deviations: &[],
                source: Some("a"),
            },
            DiscoveryMetadata {
                name: "example",
                revision: "2026-02-01",
                conformance: ModuleConformance::Implement,
                imports: &[],
                features: &[],
                deviations: &[],
                source: Some("b"),
            },
        ];
        let registry = FakeRegistry {
            models: MODELS,
            discovery: META,
        };
        let request = GetSchemaRequest {
            identifier: "example".to_string(),
            version: None,
            format: "yang".to_string(),
        };
        let err = schema_source(&registry, &request).expect_err("should fail");
        assert!(matches!(err, GetSchemaError::NotUnique));
    }

    #[test]
    fn schema_source_not_found_for_unknown_identifier() {
        let registry = test_registry();
        let request = GetSchemaRequest {
            identifier: "missing".to_string(),
            version: None,
            format: "yang".to_string(),
        };
        let err = schema_source(&registry, &request).expect_err("should fail");
        assert!(matches!(err, GetSchemaError::NotFound));
    }

    #[test]
    fn schema_source_not_found_when_source_text_missing() {
        let registry = test_registry();
        let request = GetSchemaRequest {
            identifier: "unavailable".to_string(),
            version: Some("2026-01-01".to_string()),
            format: "yang".to_string(),
        };
        let err = schema_source(&registry, &request).expect_err("should fail");
        assert!(matches!(err, GetSchemaError::NotFound));
    }

    #[test]
    fn schema_source_rejects_unsupported_format() {
        let registry = test_registry();
        let request = GetSchemaRequest {
            identifier: "example".to_string(),
            version: Some("2026-01-01".to_string()),
            format: "yin".to_string(),
        };
        let err = schema_source(&registry, &request).expect_err("should fail");
        assert!(matches!(err, GetSchemaError::Failed { .. }));
    }
}
