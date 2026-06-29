//! Generates a schema-backed gNMI Set applicator for generated config roots.

use super::{clean_segment, last_segment, to_pascal_case, RustGenerationError};
use crate::emit::CanonicalInput;
use crate::ir::SchemaNodeKind;
use quote::{format_ident, quote};

/// Emits the `gnmi_set` module for the generated crate.
pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let root = input
        .nodes
        .iter()
        .find(|node| {
            let trimmed = node.path.trim_start_matches('/');
            !trimmed.is_empty() && !trimmed.contains('/')
        })
        .ok_or_else(|| RustGenerationError::new("gnmi_set: no root container found"))?;
    if root.kind != SchemaNodeKind::Container {
        return Err(RustGenerationError::new(
            "gnmi_set: root node must be a container",
        ));
    }

    let root_type = format_ident!(
        "{}",
        to_pascal_case(clean_segment(last_segment(&root.path)))
    );

    let tokens = quote! {
        use opc_gnmi_server::{
            GnmiError, GnmiPatchApplicator, NormalizedSet, NormalizedValue,
        };
        use opc_mgmt_schema::{EnumValueMeta, LeafType, NodeKind, NodeMeta, NumericRangeIntervalMeta};
        use serde_json::{Number, Value};

        /// Generated gNMI Set applicator for this schema.
        pub struct GeneratedGnmiPatchApplicator;

        impl GnmiPatchApplicator<super::types::#root_type> for GeneratedGnmiPatchApplicator {
            fn apply_set(
                &self,
                running: &super::types::#root_type,
                set: &NormalizedSet,
            ) -> Result<super::types::#root_type, GnmiError> {
                let mut candidate = running.clone();
                let deltas = set_to_deltas(set)?;
                super::patch::apply_patch(&mut candidate, &deltas).map_err(|_| {
                    GnmiError::invalid("gNMI Set patch application failed")
                })?;
                Ok(candidate)
            }
        }

        /// Returns the generated gNMI Set applicator for this schema.
        pub fn patcher() -> GeneratedGnmiPatchApplicator {
            GeneratedGnmiPatchApplicator
        }

        fn set_to_deltas(set: &NormalizedSet) -> Result<Vec<super::patch::ConfigDelta>, GnmiError> {
            let mut deltas = Vec::with_capacity(set.len());
            deltas.extend(set.deletes.iter().cloned().map(super::patch::ConfigDelta::Delete));
            for (path, value) in &set.replaces {
                deltas.push(super::patch::ConfigDelta::Replace(
                    path.clone(),
                    patch_value(path.as_str(), value)?,
                ));
            }
            for (path, value) in &set.updates {
                deltas.push(super::patch::ConfigDelta::Update(
                    path.clone(),
                    patch_value(path.as_str(), value)?,
                ));
            }
            for (path, value) in &set.union_replaces {
                deltas.push(super::patch::ConfigDelta::Replace(
                    path.clone(),
                    patch_value(path.as_str(), value)?,
                ));
            }
            Ok(deltas)
        }

        fn patch_value(path: &str, value: &NormalizedValue) -> Result<String, GnmiError> {
            let registry = super::schema_registry::registry();
            let node = registry
                .node(path)
                .ok_or_else(|| GnmiError::invalid("gNMI Set path is not in schema"))?;
            if !node.config {
                return Err(GnmiError::invalid("gNMI Set path is not writable"));
            }
            let parsed: Value = serde_json::from_str(value.json())
                .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"))?;
            match node.kind {
                NodeKind::Leaf => {
                    let leaf_type = node
                        .leaf_type
                        .ok_or_else(|| GnmiError::invalid("gNMI Set leaf has no schema type"))?;
                    leaf_patch_value(leaf_type, registry.numeric_range(path), &parsed)
                }
                NodeKind::LeafList => {
                    let leaf_type = node
                        .leaf_type
                        .ok_or_else(|| GnmiError::invalid("gNMI Set leaf-list has no schema type"))?;
                    leaf_list_patch_value(leaf_type, registry.numeric_range(path), &parsed)
                }
                NodeKind::Container => object_patch_value(&parsed),
                NodeKind::List => list_patch_value(node, &parsed),
            }
        }

        fn object_patch_value(value: &Value) -> Result<String, GnmiError> {
            if !value.is_object() {
                return Err(GnmiError::invalid("gNMI Set subtree value must be a JSON object"));
            }
            serde_json::to_string(value)
                .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"))
        }

        fn list_patch_value(node: &NodeMeta, value: &Value) -> Result<String, GnmiError> {
            if node.key_leaves.is_empty() {
                if !value.is_array() {
                    return Err(GnmiError::invalid("gNMI Set keyless-list value must be a JSON array"));
                }
            } else if !value.is_object() {
                return Err(GnmiError::invalid("gNMI Set keyed-list entry value must be a JSON object"));
            }
            serde_json::to_string(value)
                .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"))
        }

        fn leaf_list_patch_value(
            leaf_type: LeafType,
            numeric_range: &[NumericRangeIntervalMeta],
            value: &Value,
        ) -> Result<String, GnmiError> {
            if let Some(values) = value.as_array() {
                let normalized = values
                    .iter()
                    .map(|value| leaf_json_value(leaf_type, numeric_range, value))
                    .collect::<Result<Vec<_>, _>>()?;
                serde_json::to_string(&normalized)
                    .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"))
            } else {
                leaf_patch_value(leaf_type, numeric_range, value)
            }
        }

        fn leaf_json_value(
            leaf_type: LeafType,
            numeric_range: &[NumericRangeIntervalMeta],
            value: &Value,
        ) -> Result<Value, GnmiError> {
            match leaf_type {
                LeafType::Boolean => Ok(Value::Bool(bool_value(value)?)),
                LeafType::String | LeafType::IdentityRef { .. } | LeafType::LeafRef { .. } => {
                    Ok(Value::String(string_value(value)?.to_string()))
                }
                LeafType::Enumeration { values } => {
                    Ok(Value::String(enum_string_value(values, value)?.to_string()))
                }
                LeafType::Uint16 => {
                    let parsed = uint16_value(value)?;
                    validate_numeric_range(i64::from(parsed), numeric_range)?;
                    Ok(Value::Number(Number::from(parsed)))
                }
                LeafType::Uint32 => {
                    let parsed = uint32_value(value)?;
                    validate_numeric_range(i64::from(parsed), numeric_range)?;
                    Ok(Value::Number(Number::from(parsed)))
                }
                LeafType::Int64 => {
                    let parsed = int64_value(value)?;
                    validate_numeric_range(parsed, numeric_range)?;
                    Ok(Value::String(parsed.to_string()))
                }
                LeafType::Decimal64 => Ok(Value::String(decimal64_value(value)?.to_string())),
                LeafType::Empty => Ok(Value::Array(vec![Value::Null])),
                LeafType::Custom { .. } => Err(GnmiError::unimplemented(
                    "gNMI custom typedef Set codec is outside the generated profile",
                )),
                _ => Err(GnmiError::unimplemented(
                    "gNMI Set codec is outside the generated profile for this leaf type",
                )),
            }
        }

        fn leaf_patch_value(
            leaf_type: LeafType,
            numeric_range: &[NumericRangeIntervalMeta],
            value: &Value,
        ) -> Result<String, GnmiError> {
            match leaf_type {
                LeafType::Boolean => Ok(bool_value(value)?.to_string()),
                LeafType::String | LeafType::IdentityRef { .. } | LeafType::LeafRef { .. } => {
                    Ok(string_value(value)?.to_string())
                }
                LeafType::Enumeration { values } => {
                    Ok(enum_string_value(values, value)?.to_string())
                }
                LeafType::Uint16 => {
                    let parsed = uint16_value(value)?;
                    validate_numeric_range(i64::from(parsed), numeric_range)?;
                    Ok(parsed.to_string())
                }
                LeafType::Uint32 => {
                    let parsed = uint32_value(value)?;
                    validate_numeric_range(i64::from(parsed), numeric_range)?;
                    Ok(parsed.to_string())
                }
                LeafType::Int64 => {
                    let parsed = int64_value(value)?;
                    validate_numeric_range(parsed, numeric_range)?;
                    Ok(parsed.to_string())
                }
                LeafType::Decimal64 => Ok(decimal64_value(value)?.to_string()),
                LeafType::Empty => {
                    if value.is_null()
                        || matches!(value.as_array(), Some(values) if values.len() == 1 && values[0].is_null())
                    {
                        Ok(String::new())
                    } else {
                        Err(GnmiError::invalid("gNMI empty leaf value must be null or [null]"))
                    }
                }
                LeafType::Custom { .. } => Err(GnmiError::unimplemented(
                    "gNMI custom typedef Set codec is outside the generated profile",
                )),
                _ => Err(GnmiError::unimplemented(
                    "gNMI Set codec is outside the generated profile for this leaf type",
                )),
            }
        }

        fn bool_value(value: &Value) -> Result<bool, GnmiError> {
            value
                .as_bool()
                .ok_or_else(|| GnmiError::invalid("gNMI boolean leaf value must be a JSON boolean"))
        }

        fn string_value(value: &Value) -> Result<&str, GnmiError> {
            value
                .as_str()
                .ok_or_else(|| GnmiError::invalid("gNMI string leaf value must be a JSON string"))
        }

        fn enum_string_value<'a>(
            values: &[EnumValueMeta],
            value: &'a Value,
        ) -> Result<&'a str, GnmiError> {
            let raw = string_value(value)?;
            if values.iter().any(|allowed| allowed.name == raw) {
                Ok(raw)
            } else {
                Err(GnmiError::invalid("gNMI enumeration leaf value is not allowed"))
            }
        }

        fn uint16_value(value: &Value) -> Result<u16, GnmiError> {
            let raw = value
                .as_u64()
                .ok_or_else(|| GnmiError::invalid("gNMI uint16 leaf value must be a JSON number"))?;
            u16::try_from(raw)
                .map_err(|_| GnmiError::invalid("gNMI uint16 leaf value is out of range"))
        }

        fn uint32_value(value: &Value) -> Result<u32, GnmiError> {
            let raw = value
                .as_u64()
                .ok_or_else(|| GnmiError::invalid("gNMI uint32 leaf value must be a JSON number"))?;
            u32::try_from(raw)
                .map_err(|_| GnmiError::invalid("gNMI uint32 leaf value is out of range"))
        }

        fn int64_value(value: &Value) -> Result<i64, GnmiError> {
            if let Some(raw) = value.as_i64() {
                return Ok(raw);
            }
            string_value(value)?
                .parse::<i64>()
                .map_err(|_| GnmiError::invalid("gNMI int64 leaf value is invalid"))
        }

        fn validate_numeric_range(
            value: i64,
            numeric_range: &[NumericRangeIntervalMeta],
        ) -> Result<(), GnmiError> {
            if numeric_range.is_empty()
                || numeric_range
                    .iter()
                    .any(|interval| interval.min <= value && value <= interval.max)
            {
                Ok(())
            } else {
                Err(GnmiError::invalid("gNMI numeric leaf value is outside YANG range"))
            }
        }

        fn decimal64_value(value: &Value) -> Result<f64, GnmiError> {
            let parsed = if let Some(raw) = value.as_f64() {
                raw
            } else {
                string_value(value)?
                    .parse::<f64>()
                    .map_err(|_| GnmiError::invalid("gNMI decimal64 leaf value is invalid"))?
            };
            if parsed.is_finite() {
                Ok(parsed)
            } else {
                Err(GnmiError::invalid("gNMI decimal64 leaf value is not finite"))
            }
        }
    };

    Ok(tokens.to_string())
}
