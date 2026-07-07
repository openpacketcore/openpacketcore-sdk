//! Lightweight JSON Schema validation engine for OpenPacketCore.
//!
//! Not a general-purpose JSON Schema implementation — covers the subset
//! used by RFC 006 and RFC 012 schemas, with a pluggable `format` validator.
//!
//! # Example
//! ```
//! use serde_json::Value;
//!
//! let schema: Value = serde_json::from_str(r#"{ "type": "string", "minLength": 1 }"#).unwrap();
//! let instance: Value = serde_json::from_str(r#""hello""#).unwrap();
//! opc_schema_validate::validate(&schema, &instance).unwrap();
//! ```

use serde_json::Value;

/// Validate an instance against a schema, ignoring all `format` declarations.
///
/// For schemas that use `format`, use [`validate_with_format`] and supply a
/// callback that handles the recognised format names.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    validate_with_format(schema, instance, "$", &|_, _, _| Ok(()))
}

/// Validate an instance against a schema with a custom `format` handler.
///
/// The `format_validator` callback receives `(value, format_name, json_path)`
/// and should return `Ok(())` when the value satisfies the format constraint,
/// or an explanatory `Err(String)` otherwise.
pub fn validate_with_format(
    schema: &Value,
    instance: &Value,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    validate_node(schema, instance, path, format_validator)
}

fn validate_node(
    schema: &Value,
    instance: &Value,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    validate_schema_keywords(schema, path)?;

    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        let mut matches = 0usize;
        let mut errors = Vec::new();
        for branch in one_of {
            match validate_node(branch, instance, path, format_validator) {
                Ok(()) => matches += 1,
                Err(err) => errors.push(err),
            }
        }
        if matches != 1 {
            return Err(format!(
                "{path}: expected exactly one oneOf branch to match, got {matches}; branch errors: {}",
                errors.join(" | ")
            ));
        }
    }

    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array) {
        let mut errors = Vec::new();
        let mut matched = false;
        for branch in any_of {
            match validate_node(branch, instance, path, format_validator) {
                Ok(()) => {
                    matched = true;
                    break;
                }
                Err(err) => errors.push(err),
            }
        }
        if !matched {
            return Err(format!(
                "{path}: expected at least one anyOf branch to match; branch errors: {}",
                errors.join(" | ")
            ));
        }
    }

    if let Some(expected) = schema.get("const") {
        if instance != expected {
            return Err(format!(
                "{path}: expected const value {}, got {}",
                render_json(expected),
                render_json(instance)
            ));
        }
    }

    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        if !options.iter().any(|option| option == instance) {
            return Err(format!(
                "{path}: value {} not present in enum {}",
                render_json(instance),
                serde_json::to_string(options).unwrap_or_else(|_| "<unrenderable>".to_string())
            ));
        }
    }

    if let Some(expected_type) = schema.get("type") {
        validate_type(expected_type, instance, path)?;
    }

    match instance {
        Value::Object(object) => validate_object(schema, object, path, format_validator)?,
        Value::Array(items) => validate_array(schema, items, path, format_validator)?,
        Value::String(string) => validate_string(schema, string, path, format_validator)?,
        Value::Number(number) => validate_number(schema, number, path)?,
        Value::Bool(_) | Value::Null => {}
    }

    Ok(())
}

fn validate_schema_keywords(schema: &Value, path: &str) -> Result<(), String> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };

    for (keyword, value) in object {
        match keyword.as_str() {
            "$comment" | "$id" | "$schema" | "$defs" | "default" | "definitions" | "deprecated"
            | "description" | "examples" | "readOnly" | "title" | "writeOnly" => {}
            "oneOf"
            | "anyOf"
            | "const"
            | "enum"
            | "type"
            | "required"
            | "properties"
            | "additionalProperties"
            | "minItems"
            | "items"
            | "minLength"
            | "format"
            | "minimum" => {
                if keyword == "items" && value.is_array() {
                    return Err(format!(
                        "{path}: unsupported schema keyword 'items' tuple form"
                    ));
                }
            }
            "allOf" | "$ref" | "not" | "if" | "then" | "else" | "multipleOf" | "uniqueItems"
            | "patternProperties" | "contains" | "dependencies" | "dependentRequired"
            | "dependentSchemas" | "propertyNames" | "prefixItems" | "additionalItems"
            | "maxLength" | "pattern" | "maxItems" | "maximum" | "exclusiveMinimum"
            | "exclusiveMaximum" => {
                return Err(format!("{path}: unsupported schema keyword '{keyword}'"));
            }
            _ => return Err(format!("{path}: unsupported schema keyword '{keyword}'")),
        }
    }

    Ok(())
}

fn validate_type(expected_type: &Value, instance: &Value, path: &str) -> Result<(), String> {
    if expected_type.is_array() {
        return Err(format!(
            "{path}: array-of-types syntax not supported; use oneOf instead"
        ));
    }
    let Some(expected_type) = expected_type.as_str() else {
        return Err(format!("{path}: unsupported schema type declaration"));
    };

    let type_matches = match expected_type {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        "number" => instance.is_number(),
        "boolean" => instance.is_boolean(),
        _ => return Err(format!("{path}: unsupported schema type '{expected_type}'")),
    };

    if type_matches {
        Ok(())
    } else {
        Err(format!(
            "{path}: expected type {expected_type}, got {}",
            json_type_name(instance)
        ))
    }
}

fn validate_object(
    schema: &Value,
    object: &serde_json::Map<String, Value>,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(key) {
                return Err(format!("{path}: missing required property '{key}'"));
            }
        }
    }

    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (key, property_schema) in properties {
            if let Some(value) = object.get(key) {
                validate_node(
                    property_schema,
                    value,
                    &format!("{path}.{key}"),
                    format_validator,
                )?;
            }
        }
    }

    match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => {
            for key in object.keys() {
                if !properties.is_some_and(|props| props.contains_key(key)) {
                    return Err(format!("{path}: unexpected property '{key}'"));
                }
            }
        }
        Some(additional_schema @ Value::Object(_)) => {
            for (key, value) in object {
                if !properties.is_some_and(|props| props.contains_key(key)) {
                    validate_node(
                        additional_schema,
                        value,
                        &format!("{path}.{key}"),
                        format_validator,
                    )?;
                }
            }
        }
        Some(Value::Bool(true)) | None => {}
        Some(_) => {
            return Err(format!(
                "{path}: unsupported additionalProperties declaration"
            ))
        }
    }

    Ok(())
}

fn validate_array(
    schema: &Value,
    items: &[Value],
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    if schema.get("maxItems").is_some() {
        return Err(format!("{path}: unsupported schema keyword 'maxItems'"));
    }

    if let Some(min_items) = schema.get("minItems").and_then(Value::as_u64) {
        if items.len() < min_items as usize {
            return Err(format!(
                "{path}: expected at least {min_items} item(s), got {}",
                items.len()
            ));
        }
    }

    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            validate_node(
                item_schema,
                item,
                &format!("{path}[{index}]"),
                format_validator,
            )?;
        }
    }

    Ok(())
}

fn validate_string(
    schema: &Value,
    string: &str,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    if schema.get("maxLength").is_some() {
        return Err(format!("{path}: unsupported schema keyword 'maxLength'"));
    }
    if schema.get("pattern").is_some() {
        return Err(format!("{path}: unsupported schema keyword 'pattern'"));
    }

    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
        let len = string.chars().count();
        if len < min_length as usize {
            return Err(format!(
                "{path}: expected string length >= {min_length}, got {len}"
            ));
        }
    }

    if let Some(format_name) = schema.get("format").and_then(Value::as_str) {
        format_validator(string, format_name, path)?;
    }

    Ok(())
}

fn validate_number(schema: &Value, number: &serde_json::Number, path: &str) -> Result<(), String> {
    if schema.get("maximum").is_some() {
        return Err(format!("{path}: unsupported schema keyword 'maximum'"));
    }
    if schema.get("exclusiveMinimum").is_some() {
        return Err(format!(
            "{path}: unsupported schema keyword 'exclusiveMinimum'"
        ));
    }
    if schema.get("exclusiveMaximum").is_some() {
        return Err(format!(
            "{path}: unsupported schema keyword 'exclusiveMaximum'"
        ));
    }

    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        let value = number
            .as_f64()
            .ok_or_else(|| format!("{path}: unsupported numeric value"))?;
        if value < minimum {
            return Err(format!("{path}: expected number >= {minimum}, got {value}"));
        }
    }

    Ok(())
}

fn json_type_name(instance: &Value) -> &'static str {
    match instance {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => {
            "integer"
        }
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn render_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unrenderable>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unsupported_structural_keywords_fail_closed() {
        let cases = [
            ("allOf", json!({"allOf": [{"type": "string"}]}), json!(7)),
            ("$ref", json!({"$ref": "#/$defs/Secret"}), json!("x")),
            ("not", json!({"not": {"type": "string"}}), json!("x")),
            (
                "multipleOf",
                json!({"type": "number", "multipleOf": 5}),
                json!(7),
            ),
            (
                "uniqueItems",
                json!({"type": "array", "uniqueItems": true}),
                json!([1, 1]),
            ),
            (
                "patternProperties",
                json!({"type": "object", "patternProperties": {"^x": {"type": "string"}}}),
                json!({"x": 7}),
            ),
            (
                "dependencies",
                json!({"type": "object", "dependencies": {"a": ["b"]}}),
                json!({"a": true}),
            ),
            (
                "propertyNames",
                json!({"type": "object", "propertyNames": {"pattern": "^x"}}),
                json!({"y": true}),
            ),
            (
                "contains",
                json!({"type": "array", "contains": {"const": 1}}),
                json!([2]),
            ),
            (
                "items",
                json!({"type": "array", "items": [{"type": "string"}]}),
                json!([1]),
            ),
        ];

        for (keyword, schema, instance) in cases {
            let err = validate(&schema, &instance).expect_err("unsupported keyword must reject");
            assert!(
                err.contains(keyword),
                "error for {keyword} should name the unsupported keyword: {err}"
            );
        }
    }
}
