//! Admit discovery fragment copying from its original, uncoalesced capture.

use opc_mgmt_schema::subtree::{SubtreeBudget, SubtreeError};
use opc_mgmt_schema::{NetconfXmlNode, SchemaRegistry, WITH_DEFAULTS_NS};

pub(super) fn reserve_append(
    registry: &dyn SchemaRegistry,
    input: &[NetconfXmlNode],
    budget: &SubtreeBudget,
) -> Result<(), SubtreeError> {
    // A failed sizing pass must not reveal its position in provider ordering.
    let available = budget.remaining();
    let sizing = SubtreeBudget::new(available, 0)?;
    let bounds = XmlBounds::new(registry, &sizing)?;
    let bytes = bounds.capture_bytes(input, &sizing)?;
    let metadata = available
        .checked_sub(sizing.remaining())
        .ok_or(SubtreeError::TooBig)?;
    budget.charge(add(metadata, bytes)?)
}

struct XmlBounds {
    prefix_bytes: usize,
    default_attribute_bytes: usize,
    namespace_bytes: usize,
}

impl XmlBounds {
    fn new(registry: &dyn SchemaRegistry, budget: &SubtreeBudget) -> Result<Self, SubtreeError> {
        budget.charge(1)?;
        let models = registry.served_models();
        // Among M used prefixes, wd or one of wd1..wdM must be available.
        let default_prefix_bytes = add(3, models.len().max(1).ilog10() as usize)?;
        let mut bounds = Self {
            prefix_bytes: 0,
            default_attribute_bytes: add(default_prefix_bytes, 16)?,
            namespace_bytes: namespace_bytes(default_prefix_bytes, WITH_DEFAULTS_NS.len())?,
        };
        for model in models {
            budget.charge(1)?;
            bounds.prefix_bytes = bounds.prefix_bytes.max(model.prefix.len());
            bounds.namespace_bytes = add(
                bounds.namespace_bytes,
                namespace_bytes(model.prefix.len(), model.namespace.len())?,
            )?;
        }
        Ok(bounds)
    }

    fn element_bytes(&self, path: usize, value: Option<usize>) -> Result<usize, SubtreeError> {
        // A local name is no longer than its captured schema path. Opening and
        // closing tags need two qualified names and five punctuation bytes.
        let name = add(add(path, self.prefix_bytes)?, 1)?;
        let mut bytes = add(multiply(name, 2)?, 5)?;
        if let Some(value) = value {
            // Masking may replace even an empty value with <redacted>. Six is
            // an upper bound for either text or attribute escaping per byte.
            bytes = add(bytes, multiply(value.max("<redacted>".len()), 6)?)?;
            bytes = add(bytes, self.default_attribute_bytes)?;
        }
        Ok(bytes)
    }

    fn node_bytes(
        &self,
        nodes: &[NetconfXmlNode],
        budget: &SubtreeBudget,
    ) -> Result<usize, SubtreeError> {
        let mut bytes = 0;
        for node in nodes {
            budget.charge(1)?;
            bytes = add(
                bytes,
                self.element_bytes(node.schema_path.len(), node.value.as_ref().map(String::len))?,
            )?;
            // A key may be emitted by its owner or materialized as a selected
            // scalar. Count every original key, including duplicate children.
            for (path, value) in &node.keys {
                budget.charge(1)?;
                bytes = add(bytes, self.element_bytes(path.len(), Some(value.len()))?)?;
            }
            bytes = add(bytes, self.node_bytes(&node.children, budget)?)?;
        }
        Ok(bytes)
    }

    fn capture_bytes(
        &self,
        input: &[NetconfXmlNode],
        budget: &SubtreeBudget,
    ) -> Result<usize, SubtreeError> {
        // Evaluation can only retain or coalesce original roots. Namespace
        // declarations are bounded by all served models at every such root.
        add(
            self.node_bytes(input, budget)?,
            multiply(self.namespace_bytes, input.len())?,
        )
    }
}

fn namespace_bytes(prefix: usize, namespace: usize) -> Result<usize, SubtreeError> {
    // Space, xmlns:, =" and the closing quote add ten bytes.
    add(10, multiply(add(prefix, namespace)?, 6)?)
}

fn add(left: usize, right: usize) -> Result<usize, SubtreeError> {
    left.checked_add(right).ok_or(SubtreeError::TooBig)
}

fn multiply(left: usize, right: usize) -> Result<usize, SubtreeError> {
    left.checked_mul(right).ok_or(SubtreeError::TooBig)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::OnceLock;

    use opc_mgmt_schema::{
        DataClass, DefaultReport, ModelData, NetconfXmlRenderContext, NodeMeta, OriginEntry,
    };

    use super::*;
    use crate::filter::yang_library_registry;

    const ROOT: &str = "/yanglib:yang-library";
    const CONTENT: &str = "/yanglib:yang-library/yanglib:content-id";
    const SET: &str = "/yanglib:yang-library/yanglib:module-set";
    const KEY: &str = "/yanglib:yang-library/yanglib:module-set/yanglib:name";

    struct Registry {
        masked: bool,
    }

    impl SchemaRegistry for Registry {
        fn schema_digest(&self) -> &'static str {
            "fragment-bound-test"
        }

        fn served_models(&self) -> &'static [ModelData] {
            static MODELS: OnceLock<Vec<ModelData>> = OnceLock::new();
            MODELS.get_or_init(|| {
                let mut models = yang_library_registry().served_models().to_vec();
                for prefix in ["wd", "wd1"] {
                    models.push(ModelData {
                        name: prefix,
                        revision: "2026-01-01",
                        namespace: "urn:example:\"'&<>é",
                        prefix,
                    });
                }
                models
            })
        }

        fn nodes(&self) -> &'static [NodeMeta] {
            yang_library_registry().nodes()
        }

        fn origins(&self) -> &'static [OriginEntry] {
            &[]
        }

        fn data_class(&self, path: &str) -> Option<DataClass> {
            if self.masked {
                Some(DataClass::SecuritySecret)
            } else {
                yang_library_registry().data_class(path)
            }
        }
    }

    fn capture() -> Vec<NetconfXmlNode> {
        let mut root = NetconfXmlNode::branch(ROOT);
        root.children
            .push(NetconfXmlNode::scalar(CONTENT, "&<>é".repeat(32), true));
        let mut list = NetconfXmlNode::branch(SET);
        list.keys.push((KEY, "&<>\"'".into()));
        list.children
            .push(NetconfXmlNode::scalar(KEY, "&<>\"'", false));
        root.children.push(list);
        vec![root, NetconfXmlNode::scalar(CONTENT, "", true)]
    }

    #[test]
    fn fragment_reservation_covers_escaped_masked_and_defaulted_xml() {
        let input = capture();
        for masked in [false, true] {
            let registry = Registry { masked };
            let budget = SubtreeBudget::new(1_000_000, 0).unwrap();
            let bound = XmlBounds::new(&registry, &budget)
                .unwrap()
                .capture_bytes(&input, &budget)
                .unwrap();
            for report in [DefaultReport::Explicit, DefaultReport::ReportAllTagged] {
                let xml = NetconfXmlRenderContext::new(
                    &registry,
                    &[ROOT, "/wd:root", "/wd1:root"],
                    report,
                )
                .render_nodes(&input)
                .unwrap();
                assert!(bound >= xml.len(), "{bound} < {}", xml.len());
                assert!(xml.contains("&quot;&apos;&amp;&lt;&gt;é"));
                if masked {
                    assert!(xml.contains("&lt;redacted&gt;"));
                } else {
                    assert!(xml.contains("&amp;&lt;&gt;é"));
                }
                if report == DefaultReport::ReportAllTagged {
                    assert!(xml.contains("wd2:default=\"true\""));
                }
            }
        }
    }

    #[test]
    fn fragment_reservation_requires_admission_before_appending() {
        let registry = Registry { masked: true };
        let input = capture();
        let original = input.clone();
        let sizing = SubtreeBudget::new(1_000_000, 0).unwrap();
        let bytes = XmlBounds::new(&registry, &sizing)
            .unwrap()
            .capture_bytes(&input, &sizing)
            .unwrap();
        let metadata = 1_000_000 - sizing.remaining();
        assert!(metadata > 0 && bytes > 0);
        for allowance in [metadata, metadata + bytes - 1] {
            let budget = SubtreeBudget::new(allowance, 0).unwrap();
            assert_eq!(
                reserve_append(&registry, &input, &budget),
                Err(SubtreeError::TooBig)
            );
            assert_eq!(budget.remaining(), allowance);
            assert_eq!(input, original);
        }
        let exact = SubtreeBudget::new(metadata + bytes, 0).unwrap();
        reserve_append(&registry, &input, &exact).unwrap();
        assert_eq!(exact.remaining(), 0);
        assert_eq!(input, original);
    }

    #[test]
    fn fragment_bound_arithmetic_is_checked() {
        let ordinary = || XmlBounds {
            prefix_bytes: 1,
            default_attribute_bytes: 1,
            namespace_bytes: 1,
        };
        assert_eq!(namespace_bytes(usize::MAX, 1), Err(SubtreeError::TooBig));
        assert_eq!(
            namespace_bytes(0, usize::MAX / 6),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            ordinary().element_bytes(usize::MAX, None),
            Err(SubtreeError::TooBig)
        );
        assert_eq!(
            ordinary().element_bytes(1, Some(usize::MAX)),
            Err(SubtreeError::TooBig)
        );
        let mut bounds = ordinary();
        bounds.prefix_bytes = usize::MAX;
        assert_eq!(bounds.element_bytes(1, None), Err(SubtreeError::TooBig));
        let mut bounds = ordinary();
        bounds.default_attribute_bytes = usize::MAX;
        assert_eq!(bounds.element_bytes(1, Some(0)), Err(SubtreeError::TooBig));
        let mut bounds = ordinary();
        bounds.namespace_bytes = usize::MAX;
        let sizing = SubtreeBudget::new(1_000_000, 0).unwrap();
        assert_eq!(
            bounds.capture_bytes(&capture(), &sizing),
            Err(SubtreeError::TooBig)
        );
    }
}
