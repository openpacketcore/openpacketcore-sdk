//! Generates a schema-backed gNMI Set applicator for generated config roots.

use super::RustGenerationError;
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

    let nodes_by_path = super::NodeIndex::new(&input.nodes);
    let root_type = format_ident!("{}", nodes_by_path.type_name(root));
    let user_ordered_lists = input
        .nodes
        .iter()
        .filter(|node| {
            node.kind == SchemaNodeKind::List
                && !node.key_leaves.is_empty()
                && super::is_user_ordered(node)
        })
        .map(|node| node.path.as_str())
        .collect::<Vec<_>>();
    let (list_path_parameter, list_path_argument, ordered_list_value) = if user_ordered_lists
        .is_empty()
    {
        (quote! {}, quote! {}, quote! {})
    } else {
        (
            quote! { path: &str, },
            quote! { path, },
            quote! {
                let ordered_paths: &[&str] = &[#(#user_ordered_lists),*];
                if ordered_paths.contains(&node.path) {
                    let segments = super::patch::parse_path(path)
                        .map_err(|_| GnmiError::invalid("gNMI Set path is invalid"))?;
                    if segments.last().is_some_and(|segment| segment.keys.is_empty()) {
                        if !value.is_array() {
                            return Err(GnmiError::invalid("gNMI Set user-ordered list value must be a JSON array"));
                        }
                        return serde_json::to_string(value)
                            .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"));
                    }
                }
            },
        )
    };

    let extended = super::has_extended_integers(input);
    let resolve_references = extended || super::strings::has_constraints(input);
    let resolve_scalar = if resolve_references {
        quote! { let scalar = scalar_node(node)?; }
    } else {
        quote! {}
    };
    let scalar_ident = if resolve_references {
        format_ident!("scalar")
    } else {
        format_ident!("node")
    };
    let range_path = if resolve_references {
        quote! { scalar.path }
    } else {
        quote! { path }
    };
    let numeric_type = if extended {
        quote! { i128 }
    } else {
        quote! { i64 }
    };
    let signed_range_value = if extended {
        quote! { i128::from(parsed) }
    } else {
        quote! { parsed }
    };
    let extra_json_arms = if extended {
        quote! {
                    LeafType::Uint8 => {
                        let parsed = uint8_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(Value::Number(Number::from(parsed)))
                    }
                    LeafType::Int8 => {
                        let parsed = int8_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(Value::Number(Number::from(parsed)))
                    }
                    LeafType::Int16 => {
                        let parsed = int16_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(Value::Number(Number::from(parsed)))
                    }
                    LeafType::Int32 => {
                        let parsed = int32_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(Value::Number(Number::from(parsed)))
                    }
                    LeafType::Uint64 => {
                        let parsed = uint64_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(Value::String(parsed.to_string()))
                    }
        }
    } else {
        quote! {}
    };
    let extra_patch_arms = if extended {
        quote! {
                    LeafType::Uint8 => {
                        let parsed = uint8_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(parsed.to_string())
                    }
                    LeafType::Int8 => {
                        let parsed = int8_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(parsed.to_string())
                    }
                    LeafType::Int16 => {
                        let parsed = int16_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(parsed.to_string())
                    }
                    LeafType::Int32 => {
                        let parsed = int32_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(parsed.to_string())
                    }
                    LeafType::Uint64 => {
                        let parsed = uint64_value(value)?;
                        validate_numeric_range(i128::from(parsed), numeric_range)?;
                        Ok(parsed.to_string())
                    }
        }
    } else {
        quote! {}
    };
    let extra_integer_helpers = if extended {
        quote! {
            fn uint8_value(value: &Value) -> Result<u8, GnmiError> {
                let raw = value
                    .as_u64()
                    .ok_or_else(|| GnmiError::invalid("gNMI uint8 leaf value must be a JSON number"))?;
                u8::try_from(raw)
                    .map_err(|_| GnmiError::invalid("gNMI uint8 leaf value is out of range"))
            }
            fn int8_value(value: &Value) -> Result<i8, GnmiError> {
                let raw = value
                    .as_i64()
                    .ok_or_else(|| GnmiError::invalid("gNMI int8 leaf value must be a JSON number"))?;
                i8::try_from(raw)
                    .map_err(|_| GnmiError::invalid("gNMI int8 leaf value is out of range"))
            }
            fn int16_value(value: &Value) -> Result<i16, GnmiError> {
                let raw = value
                    .as_i64()
                    .ok_or_else(|| GnmiError::invalid("gNMI int16 leaf value must be a JSON number"))?;
                i16::try_from(raw)
                    .map_err(|_| GnmiError::invalid("gNMI int16 leaf value is out of range"))
            }
            fn int32_value(value: &Value) -> Result<i32, GnmiError> {
                let raw = value
                    .as_i64()
                    .ok_or_else(|| GnmiError::invalid("gNMI int32 leaf value must be a JSON number"))?;
                i32::try_from(raw)
                    .map_err(|_| GnmiError::invalid("gNMI int32 leaf value is out of range"))
            }
            fn uint64_value(value: &Value) -> Result<u64, GnmiError> {
                if let Some(raw) = value.as_u64() {
                    return Ok(raw);
                }
                string_value(value)?
                    .parse::<u64>()
                    .map_err(|_| GnmiError::invalid("gNMI uint64 leaf value is invalid"))
            }
        }
    } else {
        quote! {}
    };
    let scalar_helper = if resolve_references {
        quote! {
        fn scalar_node(mut node: &NodeMeta) -> Result<&NodeMeta, GnmiError> {
            let registry = super::schema_registry::registry();
            for _ in 0..=registry.nodes().len() {
                if let Some(LeafType::LeafRef { target_path }) = node.leaf_type {
                    node = registry.node(target_path)
                        .ok_or_else(|| GnmiError::invalid("gNMI leafref target is missing"))?;
                } else {
                    return Ok(node);
                }
            }
            Err(GnmiError::invalid("gNMI leafref cycle"))
        }    }
    } else {
        quote! {}
    };
    let range_type = if super::has_extended_integers(input) {
        quote! { IntegerRangeIntervalMeta as NumericRangeIntervalMeta }
    } else {
        quote! { NumericRangeIntervalMeta }
    };
    let range_method = if super::has_extended_integers(input) {
        format_ident!("integer_range")
    } else {
        format_ident!("numeric_range")
    };
    let string_failure = if super::strings::has_constraints(input) {
        quote! { |error: opc_config_model::ConfigError| {
            if error.message() == "string violates YANG constraints" { GnmiError::invalid("string violates YANG constraints") }
            else { GnmiError::invalid("gNMI Set patch application failed") }
        } }
    } else {
        quote! { |_| { GnmiError::invalid("gNMI Set patch application failed") } }
    };
    let tokens = quote! {
        use opc_gnmi_server::{
            GnmiError, GnmiPatchApplicator, NormalizedSet, NormalizedValue,
        };
        use opc_mgmt_schema::{EnumValueMeta, LeafType, NodeKind, NodeMeta, #range_type};
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
                super::patch::apply_patch(&mut candidate, &deltas).map_err(#string_failure)?;
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
                    #resolve_scalar
                    let leaf_type = #scalar_ident.leaf_type
                        .ok_or_else(|| GnmiError::invalid("gNMI Set leaf has no schema type"))?;
                    leaf_patch_value(leaf_type, registry.#range_method(#range_path), &parsed)
                }
                NodeKind::LeafList => {
                    #resolve_scalar
                    let leaf_type = #scalar_ident.leaf_type
                        .ok_or_else(|| GnmiError::invalid("gNMI Set leaf-list has no schema type"))?;
                    leaf_list_patch_value(leaf_type, registry.#range_method(#range_path), &parsed)
                }
                NodeKind::Container => object_patch_value(&parsed),
                NodeKind::List => list_patch_value(node, #list_path_argument &parsed),
            }
        }

        #scalar_helper

        fn object_patch_value(value: &Value) -> Result<String, GnmiError> {
            if !value.is_object() {
                return Err(GnmiError::invalid("gNMI Set subtree value must be a JSON object"));
            }
            serde_json::to_string(value)
                .map_err(|_| GnmiError::invalid("gNMI Set value is not valid JSON"))
        }

        fn list_patch_value(node: &NodeMeta, #list_path_parameter value: &Value) -> Result<String, GnmiError> {
            #ordered_list_value
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
                #extra_json_arms
                LeafType::Boolean => Ok(Value::Bool(bool_value(value)?)),
                LeafType::String | LeafType::IdentityRef { .. } | LeafType::LeafRef { .. } => {
                    Ok(Value::String(string_value(value)?.to_string()))
                }
                LeafType::Enumeration { values } => {
                    Ok(Value::String(enum_string_value(values, value)?.to_string()))
                }




                LeafType::Uint16 => {
                    let parsed = uint16_value(value)?;
                    validate_numeric_range(#numeric_type::from(parsed), numeric_range)?;
                    Ok(Value::Number(Number::from(parsed)))
                }
                LeafType::Uint32 => {
                    let parsed = uint32_value(value)?;
                    validate_numeric_range(#numeric_type::from(parsed), numeric_range)?;
                    Ok(Value::Number(Number::from(parsed)))
                }

                LeafType::Int64 => {
                    let parsed = int64_value(value)?;
                    validate_numeric_range(#signed_range_value, numeric_range)?;
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
                #extra_patch_arms
                LeafType::Boolean => Ok(bool_value(value)?.to_string()),
                LeafType::String | LeafType::IdentityRef { .. } | LeafType::LeafRef { .. } => {
                    Ok(string_value(value)?.to_string())
                }
                LeafType::Enumeration { values } => {
                    Ok(enum_string_value(values, value)?.to_string())
                }




                LeafType::Uint16 => {
                    let parsed = uint16_value(value)?;
                    validate_numeric_range(#numeric_type::from(parsed), numeric_range)?;
                    Ok(parsed.to_string())
                }
                LeafType::Uint32 => {
                    let parsed = uint32_value(value)?;
                    validate_numeric_range(#numeric_type::from(parsed), numeric_range)?;
                    Ok(parsed.to_string())
                }

                LeafType::Int64 => {
                    let parsed = int64_value(value)?;
                    validate_numeric_range(#signed_range_value, numeric_range)?;
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









        #extra_integer_helpers

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
            value: #numeric_type,
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
