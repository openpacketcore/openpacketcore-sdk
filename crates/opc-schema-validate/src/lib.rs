//! Bounded JSON Schema validation for SDK-owned schemas.
//!
//! This is intentionally not a general-purpose JSON Schema implementation.
//! It preflights every node of its supported subset before inspecting an
//! instance, so unsupported or malformed declarations cannot hide in unused
//! definitions or short-circuited composition branches.
//!
//! # Example
//! ```
//! use serde_json::Value;
//!
//! let schema: Value = serde_json::from_str(r#"{ "type": "string", "minLength": 1 }"#).unwrap();
//! let instance: Value = serde_json::from_str(r#""hello""#).unwrap();
//! opc_schema_validate::validate(&schema, &instance).unwrap();
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use regex::Regex;
use serde_json::Value;

/// Maximum schema nodes accepted during complete schema preflight.
pub const MAX_SCHEMA_NODES: usize = 16_384;
/// Maximum nesting depth accepted during complete schema preflight.
pub const MAX_SCHEMA_DEPTH: usize = 128;
/// Maximum preflight operations, including `required` and `enum` contents.
pub const MAX_PREFLIGHT_WORK: usize = 65_536;
/// Maximum `required` property names across one schema.
pub const MAX_REQUIRED_PROPERTIES: usize = 4_096;
/// Maximum UTF-8 bytes across all `required` property names in one schema.
pub const MAX_REQUIRED_BYTES: usize = 1_048_576;
/// Maximum `enum` values across one schema.
pub const MAX_ENUM_VALUES: usize = 4_096;
/// Maximum serialized JSON bytes across all `enum` values in one schema.
pub const MAX_ENUM_SERIALIZED_BYTES: usize = 1_048_576;
/// Maximum validation subproblems evaluated for one instance.
pub const MAX_VALIDATION_WORK: usize = 65_536;
/// Maximum array cardinality admitted by the `uniqueItems` implementation.
pub const MAX_UNIQUE_ITEMS: usize = 4_096;
/// Maximum serialized JSON bytes examined by `uniqueItems` in one validation.
pub const MAX_UNIQUE_SERIALIZED_BYTES: usize = 1_048_576;

const MAX_REPORTED_COMPOSITION_ERRORS: usize = 8;
const MAX_RENDERED_ERROR_BYTES: usize = 256;

/// Validate an instance against a bounded SDK-owned JSON Schema subset,
/// ignoring all `format` declarations.
///
/// The complete schema is preflighted before validation. Unsupported or
/// malformed declarations, remote/unresolved references, cyclic local
/// references, or configured resource limits return an error deterministically.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    validate_with_format(schema, instance, "$", &|_, _, _| Ok(()))
}

/// Validate an instance against a bounded SDK-owned JSON Schema subset with a
/// caller-supplied `format` validator.
///
/// The `format_validator` callback receives `(value, format_name, json_path)`.
/// It runs only after the complete schema has passed deterministic preflight.
pub fn validate_with_format(
    schema: &Value,
    instance: &Value,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
) -> Result<(), String> {
    preflight_schema(schema)?;
    let mut context = ValidationContext::default();
    validate_node(
        schema,
        schema,
        instance,
        path,
        format_validator,
        &mut context,
        0,
    )
}

#[derive(Default)]
struct PreflightState {
    schema_nodes: usize,
    work: usize,
    required_properties: usize,
    required_bytes: usize,
    enum_values: usize,
    enum_serialized_bytes: usize,
    active_references: BTreeSet<usize>,
    completed_references: BTreeMap<String, usize>,
}

impl PreflightState {
    fn consume_work(&mut self, path: &str) -> Result<(), String> {
        self.work = self.work.checked_add(1).ok_or_else(|| {
            format!("{path}: schema preflight work limit exceeds {MAX_PREFLIGHT_WORK}")
        })?;
        if self.work > MAX_PREFLIGHT_WORK {
            return Err(format!(
                "{path}: schema preflight work limit exceeds {MAX_PREFLIGHT_WORK}"
            ));
        }
        Ok(())
    }

    fn add_required_property(&mut self, name: &str, path: &str) -> Result<(), String> {
        self.required_properties = self.required_properties.checked_add(1).ok_or_else(|| {
            format!("{path}: required entry limit exceeds {MAX_REQUIRED_PROPERTIES}")
        })?;
        if self.required_properties > MAX_REQUIRED_PROPERTIES {
            return Err(format!(
                "{path}: required entry limit exceeds {MAX_REQUIRED_PROPERTIES}"
            ));
        }
        self.required_bytes = self
            .required_bytes
            .checked_add(name.len())
            .ok_or_else(|| format!("{path}: required byte limit exceeds {MAX_REQUIRED_BYTES}"))?;
        if self.required_bytes > MAX_REQUIRED_BYTES {
            return Err(format!(
                "{path}: required byte limit exceeds {MAX_REQUIRED_BYTES}"
            ));
        }
        Ok(())
    }

    fn add_enum_value(&mut self, value: &Value, path: &str) -> Result<(), String> {
        self.enum_values = self
            .enum_values
            .checked_add(1)
            .ok_or_else(|| format!("{path}: enum entry limit exceeds {MAX_ENUM_VALUES}"))?;
        if self.enum_values > MAX_ENUM_VALUES {
            return Err(format!(
                "{path}: enum entry limit exceeds {MAX_ENUM_VALUES}"
            ));
        }
        let remaining = MAX_ENUM_SERIALIZED_BYTES
            .checked_sub(self.enum_serialized_bytes)
            .ok_or_else(|| {
                format!("{path}: enum byte limit exceeds {MAX_ENUM_SERIALIZED_BYTES}")
            })?;
        let bytes =
            bounded_json_byte_len(value, remaining, path, "enum", MAX_ENUM_SERIALIZED_BYTES)?;
        self.enum_serialized_bytes =
            self.enum_serialized_bytes
                .checked_add(bytes)
                .ok_or_else(|| {
                    format!("{path}: enum byte limit exceeds {MAX_ENUM_SERIALIZED_BYTES}")
                })?;
        Ok(())
    }
}

fn preflight_schema(root: &Value) -> Result<(), String> {
    let mut state = PreflightState::default();
    preflight_schema_node(root, root, "$", 0, &mut state).map(|_| ())
}

fn preflight_schema_node(
    root: &Value,
    schema: &Value,
    path: &str,
    depth: usize,
    state: &mut PreflightState,
) -> Result<usize, String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    state.schema_nodes = state
        .schema_nodes
        .checked_add(1)
        .ok_or_else(|| format!("{path}: schema node limit exceeds {MAX_SCHEMA_NODES}"))?;
    if state.schema_nodes > MAX_SCHEMA_NODES {
        return Err(format!(
            "{path}: schema node limit exceeds {MAX_SCHEMA_NODES}"
        ));
    }
    state.consume_work(path)?;

    let object = match schema {
        Value::Bool(_) => return Ok(depth),
        Value::Object(object) => object,
        _ => {
            return Err(format!(
                "{path}: invalid schema must be an object or boolean"
            ))
        }
    };

    let mut maximum_depth = depth;

    for (keyword, value) in object {
        match keyword.as_str() {
            "$comment" | "$id" | "$schema" | "description" | "title" => {
                require_string(value, keyword, path)?;
            }
            "$defs" => {
                for (name, definition) in require_object(value, keyword, path)? {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        definition,
                        &schema_path(path, "$defs", name),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?);
                }
            }
            "default" => {}
            "examples" => {
                require_array(value, keyword, path)?;
            }
            "deprecated" | "readOnly" | "writeOnly" => {
                require_boolean(value, keyword, path)?;
            }
            "$ref" => {
                let reference = require_string(value, keyword, path)?;
                let target = resolve_local_reference(root, reference, path)?;
                maximum_depth = maximum_depth.max(preflight_reference(
                    root,
                    reference,
                    target,
                    path,
                    next_preflight_depth(depth, path)?,
                    state,
                )?);
            }
            "allOf" | "anyOf" | "oneOf" => {
                let branches = require_nonempty_array(value, keyword, path)?;
                for (index, branch) in branches.iter().enumerate() {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        branch,
                        &array_path(path, keyword, index),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?);
                }
            }
            "const" => {}
            "enum" => {
                for (index, enum_value) in require_nonempty_array(value, keyword, path)?
                    .iter()
                    .enumerate()
                {
                    preflight_enum_value(enum_value, &array_path(path, keyword, index), 0, state)?;
                    state.add_enum_value(enum_value, &array_path(path, keyword, index))?;
                }
            }
            "type" => {
                let kind = require_string(value, keyword, path)?;
                if !matches!(
                    kind,
                    "object" | "array" | "string" | "integer" | "number" | "boolean"
                ) {
                    return Err(format!("{path}: invalid schema type '{kind}'"));
                }
            }
            "required" => {
                let mut names = BTreeSet::new();
                for name in require_array(value, keyword, path)? {
                    state.consume_work(path)?;
                    let name = require_string(name, keyword, path)?;
                    state.add_required_property(name, path)?;
                    if !names.insert(name) {
                        return Err(format!(
                            "{path}: invalid schema required contains duplicate '{name}'"
                        ));
                    }
                }
            }
            "properties" => {
                for (name, property_schema) in require_object(value, keyword, path)? {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        property_schema,
                        &schema_path(path, keyword, name),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?);
                }
            }
            "additionalProperties" => match value {
                Value::Bool(_) => {}
                Value::Object(_) => {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        value,
                        &schema_keyword_path(path, keyword),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?)
                }
                _ => {
                    return Err(format!(
                        "{path}: invalid schema additionalProperties must be a boolean or schema"
                    ));
                }
            },
            "minItems" | "maxItems" | "minLength" | "maxLength" => {
                require_usize(value, keyword, path)?;
            }
            "prefixItems" => {
                for (index, item_schema) in require_array(value, keyword, path)?.iter().enumerate()
                {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        item_schema,
                        &array_path(path, keyword, index),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?);
                }
            }
            "items" => match value {
                Value::Bool(_) => {}
                Value::Object(_) => {
                    maximum_depth = maximum_depth.max(preflight_schema_node(
                        root,
                        value,
                        &schema_keyword_path(path, keyword),
                        next_preflight_depth(depth, path)?,
                        state,
                    )?)
                }
                _ => {
                    return Err(format!(
                        "{path}: invalid schema items must be a boolean or single schema"
                    ));
                }
            },
            "uniqueItems" => {
                require_boolean(value, keyword, path)?;
            }
            "pattern" => {
                let pattern = require_string(value, keyword, path)?;
                Regex::new(pattern).map_err(|error| {
                    format!("{path}: invalid schema pattern '{pattern}': {error}")
                })?;
            }
            "format" => {
                require_string(value, keyword, path)?;
            }
            "minimum" | "maximum" => {
                require_number(value, keyword, path)?;
            }
            "not" | "if" | "then" | "else" | "multipleOf" | "patternProperties" | "contains"
            | "dependencies" | "dependentRequired" | "dependentSchemas" | "propertyNames"
            | "additionalItems" | "exclusiveMinimum" | "exclusiveMaximum" | "definitions" => {
                return Err(format!("{path}: unsupported schema keyword '{keyword}'"));
            }
            _ => return Err(format!("{path}: unsupported schema keyword '{keyword}'")),
        }
    }

    Ok(maximum_depth)
}

fn next_preflight_depth(depth: usize, path: &str) -> Result<usize, String> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| format!("{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"))?;
    if next > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    Ok(next)
}

fn preflight_reference(
    root: &Value,
    reference: &str,
    target: &Value,
    path: &str,
    depth: usize,
    state: &mut PreflightState,
) -> Result<usize, String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    if let Some(relative_depth) = state.completed_references.get(reference) {
        let maximum_depth = depth
            .checked_add(*relative_depth)
            .ok_or_else(|| format!("{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"))?;
        if maximum_depth > MAX_SCHEMA_DEPTH {
            return Err(format!(
                "{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}"
            ));
        }
        return Ok(maximum_depth);
    }
    let target_key = value_address(target);
    if !state.active_references.insert(target_key) {
        return Err(format!(
            "{path}: cyclic local schema reference '{reference}'"
        ));
    }
    let result = preflight_schema_node(root, target, path, depth, state);
    state.active_references.remove(&target_key);
    match result {
        Ok(maximum_depth) => {
            let relative_depth = maximum_depth.checked_sub(depth).ok_or_else(|| {
                format!("{path}: schema nesting depth exceeds {MAX_SCHEMA_DEPTH}")
            })?;
            state
                .completed_references
                .insert(reference.to_owned(), relative_depth);
            Ok(maximum_depth)
        }
        Err(error) => Err(error),
    }
}

fn preflight_enum_value(
    value: &Value,
    path: &str,
    depth: usize,
    state: &mut PreflightState,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: enum value nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    state.consume_work(path)?;
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                preflight_enum_value(
                    value,
                    &array_path(path, "", index),
                    next_enum_value_depth(depth, path)?,
                    state,
                )?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                preflight_enum_value(
                    value,
                    &instance_path(path, name),
                    next_enum_value_depth(depth, path)?,
                    state,
                )?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn next_enum_value_depth(depth: usize, path: &str) -> Result<usize, String> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| format!("{path}: enum value nesting depth exceeds {MAX_SCHEMA_DEPTH}"))?;
    if next > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: enum value nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    Ok(next)
}

struct BoundedByteCounter {
    remaining: usize,
    written: usize,
}

struct BoundedErrorRenderer {
    remaining: usize,
    rendered: Vec<u8>,
}

impl Write for BoundedErrorRenderer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "rendered JSON exceeds diagnostic limit",
            ));
        }
        self.remaining -= buffer.len();
        self.rendered.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for BoundedByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "serialized JSON exceeds configured limit",
            ));
        }
        self.remaining -= buffer.len();
        self.written = self
            .written
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized JSON byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_byte_len(
    value: &Value,
    remaining: usize,
    path: &str,
    kind: &str,
    maximum: usize,
) -> Result<usize, String> {
    let mut counter = BoundedByteCounter {
        remaining,
        written: 0,
    };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| format!("{path}: {kind} byte limit exceeds {maximum}"))?;
    Ok(counter.written)
}

fn render_json_for_error(value: &Value) -> String {
    let mut renderer = BoundedErrorRenderer {
        remaining: MAX_RENDERED_ERROR_BYTES,
        rendered: Vec::with_capacity(MAX_RENDERED_ERROR_BYTES),
    };
    if serde_json::to_writer(&mut renderer, value).is_err() {
        return "<redacted>".to_owned();
    }
    String::from_utf8(renderer.rendered).unwrap_or_else(|_| "<redacted>".to_owned())
}

#[derive(Default)]
struct ValidationContext {
    work: usize,
    unique_serialized_bytes: usize,
    successful_subproblems: BTreeSet<(usize, usize, String)>,
    compiled_patterns: BTreeMap<usize, Regex>,
}

impl ValidationContext {
    fn consume_work(&mut self, path: &str) -> Result<(), String> {
        self.work = self.work.checked_add(1).ok_or_else(|| {
            format!("{path}: validation work limit exceeds {MAX_VALIDATION_WORK}")
        })?;
        if self.work > MAX_VALIDATION_WORK {
            return Err(format!(
                "{path}: validation work limit exceeds {MAX_VALIDATION_WORK}"
            ));
        }
        Ok(())
    }

    fn add_unique_value(&mut self, value: &Value, path: &str) -> Result<(), String> {
        let remaining = MAX_UNIQUE_SERIALIZED_BYTES
            .checked_sub(self.unique_serialized_bytes)
            .ok_or_else(|| {
                format!(
                    "{path}: uniqueItems serialized byte limit exceeds {MAX_UNIQUE_SERIALIZED_BYTES}"
                )
            })?;
        let bytes = bounded_json_byte_len(
            value,
            remaining,
            path,
            "uniqueItems serialized",
            MAX_UNIQUE_SERIALIZED_BYTES,
        )?;
        self.unique_serialized_bytes =
            self.unique_serialized_bytes
                .checked_add(bytes)
                .ok_or_else(|| {
                    format!(
                "{path}: uniqueItems serialized byte limit exceeds {MAX_UNIQUE_SERIALIZED_BYTES}"
            )
                })?;
        Ok(())
    }

    fn pattern(&mut self, schema: &Value, pattern: &str, path: &str) -> Result<Regex, String> {
        let key = value_address(schema);
        if let Some(compiled) = self.compiled_patterns.get(&key) {
            return Ok(compiled.clone());
        }
        let compiled = Regex::new(pattern)
            .map_err(|error| format!("{path}: invalid schema pattern '{pattern}': {error}"))?;
        self.compiled_patterns.insert(key, compiled.clone());
        Ok(compiled)
    }
}

fn next_schema_depth(depth: usize, path: &str) -> Result<usize, String> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| format!("{path}: validation schema depth exceeds {MAX_SCHEMA_DEPTH}"))?;
    if next > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: validation schema depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    Ok(next)
}

fn validate_node(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
    context: &mut ValidationContext,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: validation schema depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    let key = (
        value_address(schema),
        value_address(instance),
        path.to_owned(),
    );
    if context.successful_subproblems.contains(&key) {
        return Ok(());
    }
    context.consume_work(path)?;

    let result = validate_node_inner(
        root,
        schema,
        instance,
        path,
        format_validator,
        context,
        depth,
    );
    if result.is_ok() {
        context.successful_subproblems.insert(key);
    }
    result
}

fn validate_node_inner(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
    context: &mut ValidationContext,
    depth: usize,
) -> Result<(), String> {
    match schema {
        Value::Bool(true) => return Ok(()),
        Value::Bool(false) => return Err(format!("{path}: rejected by false schema")),
        Value::Object(_) => {}
        _ => {
            return Err(format!(
                "{path}: invalid schema must be an object or boolean"
            ))
        }
    }

    if let Some(reference) = schema.get("$ref") {
        let reference = require_string(reference, "$ref", path)?;
        let target = resolve_local_reference(root, reference, path)?;
        validate_node(
            root,
            target,
            instance,
            path,
            format_validator,
            context,
            next_schema_depth(depth, path)?,
        )?;
    }

    if let Some(all_of) = schema.get("allOf") {
        for branch in require_nonempty_array(all_of, "allOf", path)? {
            validate_node(
                root,
                branch,
                instance,
                path,
                format_validator,
                context,
                next_schema_depth(depth, path)?,
            )?;
        }
    }

    if let Some(one_of) = schema.get("oneOf") {
        let mut matches = 0usize;
        let mut errors = Vec::new();
        for branch in require_nonempty_array(one_of, "oneOf", path)? {
            match validate_node(
                root,
                branch,
                instance,
                path,
                format_validator,
                context,
                next_schema_depth(depth, path)?,
            ) {
                Ok(()) => matches += 1,
                Err(error) if errors.len() < MAX_REPORTED_COMPOSITION_ERRORS => errors.push(error),
                Err(_) => {}
            }
        }
        if matches != 1 {
            return Err(format!(
                "{path}: expected exactly one oneOf branch to match, got {matches}; branch errors: {}",
                errors.join(" | ")
            ));
        }
    }

    if let Some(any_of) = schema.get("anyOf") {
        let mut errors = Vec::new();
        let mut matched = false;
        for branch in require_nonempty_array(any_of, "anyOf", path)? {
            match validate_node(
                root,
                branch,
                instance,
                path,
                format_validator,
                context,
                next_schema_depth(depth, path)?,
            ) {
                Ok(()) => {
                    matched = true;
                    break;
                }
                Err(error) if errors.len() < MAX_REPORTED_COMPOSITION_ERRORS => errors.push(error),
                Err(_) => {}
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
        if !json_schema_equal(instance, expected, context, path)? {
            context.consume_work(path)?;
            return Err(format!(
                "{path}: expected const value {}, got {}",
                render_json_for_error(expected),
                render_json_for_error(instance)
            ));
        }
    }

    if let Some(options) = schema.get("enum") {
        let options = require_nonempty_array(options, "enum", path)?;
        let instance_key = json_schema_equality_key(instance, context, path, 0)?;
        let mut matches = false;
        for option in options {
            context.consume_work(path)?;
            if instance_key == json_schema_equality_key(option, context, path, 0)? {
                matches = true;
                break;
            }
        }
        if !matches {
            context.consume_work(path)?;
            return Err(format!(
                "{path}: value {} is not present in enum ({} permitted values)",
                render_json_for_error(instance),
                options.len()
            ));
        }
    }

    if let Some(expected_type) = schema.get("type") {
        validate_type(require_string(expected_type, "type", path)?, instance, path)?;
    }

    match instance {
        Value::Object(object) => {
            validate_object(root, schema, object, path, format_validator, context, depth)?
        }
        Value::Array(items) => {
            validate_array(root, schema, items, path, format_validator, context, depth)?
        }
        Value::String(string) => validate_string(schema, string, path, format_validator, context)?,
        Value::Number(number) => validate_number(schema, number, path)?,
        Value::Bool(_) | Value::Null => {}
    }

    Ok(())
}

fn validate_type(expected_type: &str, instance: &Value, path: &str) -> Result<(), String> {
    let type_matches = match expected_type {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        "number" => instance.is_number(),
        "boolean" => instance.is_boolean(),
        _ => return Err(format!("{path}: invalid schema type '{expected_type}'")),
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
    root: &Value,
    schema: &Value,
    object: &serde_json::Map<String, Value>,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
    context: &mut ValidationContext,
    depth: usize,
) -> Result<(), String> {
    if let Some(required) = schema.get("required") {
        for name in require_array(required, "required", path)? {
            let name = require_string(name, "required", path)?;
            if !object.contains_key(name) {
                return Err(format!("{path}: missing required property '{name}'"));
            }
        }
    }

    let properties = match schema.get("properties") {
        Some(properties) => Some(require_object(properties, "properties", path)?),
        None => None,
    };
    if let Some(properties) = properties {
        for (name, property_schema) in properties {
            if let Some(value) = object.get(name) {
                validate_node(
                    root,
                    property_schema,
                    value,
                    &instance_path(path, name),
                    format_validator,
                    context,
                    next_schema_depth(depth, path)?,
                )?;
            }
        }
    }

    match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => {
            for name in object.keys() {
                context.consume_work(path)?;
                if !properties.is_some_and(|properties| properties.contains_key(name)) {
                    return Err(format!("{path}: unexpected property '{name}'"));
                }
            }
        }
        Some(Value::Bool(true)) | None => {}
        Some(additional_schema @ Value::Object(_)) => {
            for (name, value) in object {
                context.consume_work(path)?;
                if !properties.is_some_and(|properties| properties.contains_key(name)) {
                    validate_node(
                        root,
                        additional_schema,
                        value,
                        &instance_path(path, name),
                        format_validator,
                        context,
                        next_schema_depth(depth, path)?,
                    )?;
                }
            }
        }
        Some(_) => {
            return Err(format!(
                "{path}: invalid schema additionalProperties must be a boolean or schema"
            ));
        }
    }

    Ok(())
}

fn validate_array(
    root: &Value,
    schema: &Value,
    items: &[Value],
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
    context: &mut ValidationContext,
    depth: usize,
) -> Result<(), String> {
    if let Some(minimum) = schema.get("minItems") {
        let minimum = require_usize(minimum, "minItems", path)?;
        if items.len() < minimum {
            return Err(format!(
                "{path}: expected at least {minimum} item(s), got {}",
                items.len()
            ));
        }
    }
    if let Some(maximum) = schema.get("maxItems") {
        let maximum = require_usize(maximum, "maxItems", path)?;
        if items.len() > maximum {
            return Err(format!(
                "{path}: expected at most {maximum} item(s), got {}",
                items.len()
            ));
        }
    }

    let prefix_items = match schema.get("prefixItems") {
        Some(prefix_items) => require_array(prefix_items, "prefixItems", path)?,
        None => &[],
    };
    for (index, item_schema) in prefix_items.iter().enumerate() {
        if let Some(item) = items.get(index) {
            validate_node(
                root,
                item_schema,
                item,
                &array_path(path, "", index),
                format_validator,
                context,
                next_schema_depth(depth, path)?,
            )?;
        }
    }

    if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
        if items.len() > MAX_UNIQUE_ITEMS {
            return Err(format!(
                "{path}: uniqueItems array length exceeds {MAX_UNIQUE_ITEMS}"
            ));
        }
        let mut unique_items = BTreeSet::new();
        for (index, item) in items.iter().enumerate() {
            let item_path = array_path(path, "", index);
            check_json_value_depth_and_work(item, context, &item_path, 0)?;
            context.add_unique_value(item, &item_path)?;
            let equality_key = json_schema_equality_key(item, context, &item_path, 0)?;
            if !unique_items.insert(equality_key) {
                return Err(format!(
                    "{path}[{index}]: duplicate item violates uniqueItems"
                ));
            }
        }
    }

    if let Some(item_schema) = schema.get("items") {
        match item_schema {
            Value::Bool(false) if items.len() > prefix_items.len() => {
                return Err(format!(
                    "{path}: expected at most {} item(s), got {}",
                    prefix_items.len(),
                    items.len()
                ));
            }
            Value::Bool(false) | Value::Bool(true) => {}
            Value::Object(_) => {
                for (index, item) in items.iter().enumerate().skip(prefix_items.len()) {
                    validate_node(
                        root,
                        item_schema,
                        item,
                        &array_path(path, "", index),
                        format_validator,
                        context,
                        next_schema_depth(depth, path)?,
                    )?;
                }
            }
            _ => {
                return Err(format!(
                    "{path}: invalid schema items must be a boolean or single schema"
                ));
            }
        }
    }

    Ok(())
}

fn validate_string(
    schema: &Value,
    string: &str,
    path: &str,
    format_validator: &dyn Fn(&str, &str, &str) -> Result<(), String>,
    context: &mut ValidationContext,
) -> Result<(), String> {
    if let Some(minimum) = schema.get("minLength") {
        let minimum = require_usize(minimum, "minLength", path)?;
        let length = string.chars().count();
        if length < minimum {
            return Err(format!(
                "{path}: expected string length >= {minimum}, got {length}"
            ));
        }
    }
    if let Some(maximum) = schema.get("maxLength") {
        let maximum = require_usize(maximum, "maxLength", path)?;
        let length = string.chars().count();
        if length > maximum {
            return Err(format!(
                "{path}: expected string length <= {maximum}, got {length}"
            ));
        }
    }
    if let Some(pattern) = schema.get("pattern") {
        let pattern = require_string(pattern, "pattern", path)?;
        if !context.pattern(schema, pattern, path)?.is_match(string) {
            return Err(format!("{path}: string does not match pattern '{pattern}'"));
        }
    }
    if let Some(format_name) = schema.get("format") {
        format_validator(string, require_string(format_name, "format", path)?, path)?;
    }
    Ok(())
}

fn validate_number(schema: &Value, number: &serde_json::Number, path: &str) -> Result<(), String> {
    let value = number
        .as_f64()
        .ok_or_else(|| format!("{path}: unsupported numeric value"))?;
    if let Some(minimum) = schema.get("minimum") {
        let minimum = require_number(minimum, "minimum", path)?;
        if value < minimum {
            return Err(format!("{path}: expected number >= {minimum}, got {value}"));
        }
    }
    if let Some(maximum) = schema.get("maximum") {
        let maximum = require_number(maximum, "maximum", path)?;
        if value > maximum {
            return Err(format!("{path}: expected number <= {maximum}, got {value}"));
        }
    }
    Ok(())
}

fn resolve_local_reference<'a>(
    root: &'a Value,
    reference: &str,
    path: &str,
) -> Result<&'a Value, String> {
    let pointer = reference
        .strip_prefix('#')
        .ok_or_else(|| format!("{path}: remote schema reference is unsupported: '{reference}'"))?;
    root.pointer(pointer)
        .ok_or_else(|| format!("{path}: unresolved local schema reference '{reference}'"))
}

fn require_string<'a>(value: &'a Value, keyword: &str, path: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{path}: invalid schema {keyword} must be a string"))
}

fn require_boolean(value: &Value, keyword: &str, path: &str) -> Result<(), String> {
    if value.is_boolean() {
        Ok(())
    } else {
        Err(format!(
            "{path}: invalid schema {keyword} must be a boolean"
        ))
    }
}

fn require_array<'a>(value: &'a Value, keyword: &str, path: &str) -> Result<&'a [Value], String> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{path}: invalid schema {keyword} must be an array"))
}

fn require_nonempty_array<'a>(
    value: &'a Value,
    keyword: &str,
    path: &str,
) -> Result<&'a [Value], String> {
    let values = require_array(value, keyword, path)?;
    if values.is_empty() {
        return Err(format!(
            "{path}: invalid schema {keyword} must not be empty"
        ));
    }
    Ok(values)
}

fn require_object<'a>(
    value: &'a Value,
    keyword: &str,
    path: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{path}: invalid schema {keyword} must be an object"))
}

fn require_usize(value: &Value, keyword: &str, path: &str) -> Result<usize, String> {
    value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("{path}: invalid schema {keyword} must be a non-negative integer"))
}

fn require_number(value: &Value, keyword: &str, path: &str) -> Result<f64, String> {
    value
        .as_f64()
        .ok_or_else(|| format!("{path}: invalid schema {keyword} must be a number"))
}

fn value_address(value: &Value) -> usize {
    value as *const Value as usize
}

fn schema_keyword_path(path: &str, keyword: &str) -> String {
    format!("{path}.{keyword}")
}

fn schema_path(path: &str, keyword: &str, name: &str) -> String {
    format!("{}.{}['{}']", path, keyword, name)
}

fn instance_path(path: &str, name: &str) -> String {
    format!("{path}.{name}")
}

fn array_path(path: &str, keyword: &str, index: usize) -> String {
    if keyword.is_empty() {
        format!("{path}[{index}]")
    } else {
        format!("{path}.{keyword}[{index}]")
    }
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum JsonSchemaEqualityKey {
    Null,
    Boolean(bool),
    Number(NormalizedJsonNumber),
    String(String),
    Array(Vec<JsonSchemaEqualityKey>),
    Object(BTreeMap<String, JsonSchemaEqualityKey>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NormalizedJsonNumber {
    negative: bool,
    digits: String,
    exponent: i64,
}

fn json_schema_equal(
    left: &Value,
    right: &Value,
    context: &mut ValidationContext,
    path: &str,
) -> Result<bool, String> {
    Ok(json_schema_equality_key(left, context, path, 0)?
        == json_schema_equality_key(right, context, path, 0)?)
}

fn check_json_value_depth_and_work(
    value: &Value,
    context: &mut ValidationContext,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: JSON value nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    context.consume_work(path)?;
    match value {
        Value::Array(values) => {
            let nested_depth = next_json_value_depth(depth, path)?;
            for (index, value) in values.iter().enumerate() {
                check_json_value_depth_and_work(
                    value,
                    context,
                    &array_path(path, "", index),
                    nested_depth,
                )?;
            }
        }
        Value::Object(values) => {
            let nested_depth = next_json_value_depth(depth, path)?;
            for (name, value) in values {
                check_json_value_depth_and_work(
                    value,
                    context,
                    &instance_path(path, name),
                    nested_depth,
                )?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn json_schema_equality_key(
    value: &Value,
    context: &mut ValidationContext,
    path: &str,
    depth: usize,
) -> Result<JsonSchemaEqualityKey, String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: JSON value nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    context.consume_work(path)?;
    match value {
        Value::Null => Ok(JsonSchemaEqualityKey::Null),
        Value::Bool(value) => Ok(JsonSchemaEqualityKey::Boolean(*value)),
        Value::Number(value) => Ok(JsonSchemaEqualityKey::Number(normalize_json_number(
            value, path,
        )?)),
        Value::String(value) => Ok(JsonSchemaEqualityKey::String(value.clone())),
        Value::Array(values) => {
            let nested_depth = next_json_value_depth(depth, path)?;
            values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    json_schema_equality_key(
                        value,
                        context,
                        &array_path(path, "", index),
                        nested_depth,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map(JsonSchemaEqualityKey::Array)
        }
        Value::Object(values) => {
            let nested_depth = next_json_value_depth(depth, path)?;
            values
                .iter()
                .map(|(name, value)| {
                    Ok((
                        name.clone(),
                        json_schema_equality_key(
                            value,
                            context,
                            &instance_path(path, name),
                            nested_depth,
                        )?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()
                .map(JsonSchemaEqualityKey::Object)
        }
    }
}

fn normalize_json_number(
    value: &serde_json::Number,
    path: &str,
) -> Result<NormalizedJsonNumber, String> {
    let text = value.to_string();
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, text.as_str()),
    };
    let exponent_marker = unsigned.find(['e', 'E']);
    let (mantissa, explicit_exponent) = match exponent_marker {
        Some(index) => {
            let (mantissa, exponent) = unsigned.split_at(index);
            let exponent = &exponent[1..];
            let exponent = exponent
                .parse::<i64>()
                .map_err(|_| format!("{path}: cannot normalize JSON number"))?;
            (mantissa, exponent)
        }
        None => (unsigned, 0),
    };
    let (whole, fractional) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{path}: cannot normalize JSON number"));
    }
    let mut digits = String::with_capacity(whole.len() + fractional.len());
    digits.push_str(whole);
    digits.push_str(fractional);
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(NormalizedJsonNumber {
            negative: false,
            digits: String::new(),
            exponent: 0,
        });
    }
    let trailing_zeros = digits
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'0')
        .count();
    let significant_len = digits.len() - trailing_zeros;
    let fractional_len = i64::try_from(fractional.len())
        .map_err(|_| format!("{path}: cannot normalize JSON number"))?;
    let trailing_zeros = i64::try_from(trailing_zeros)
        .map_err(|_| format!("{path}: cannot normalize JSON number"))?;
    let exponent = explicit_exponent
        .checked_sub(fractional_len)
        .and_then(|exponent| exponent.checked_add(trailing_zeros))
        .ok_or_else(|| format!("{path}: cannot normalize JSON number"))?;
    Ok(NormalizedJsonNumber {
        negative,
        digits: digits[..significant_len].to_owned(),
        exponent,
    })
}

fn next_json_value_depth(depth: usize, path: &str) -> Result<usize, String> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| format!("{path}: JSON value nesting depth exceeds {MAX_SCHEMA_DEPTH}"))?;
    if next > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "{path}: JSON value nesting depth exceeds {MAX_SCHEMA_DEPTH}"
        ));
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bottom_up_reference_chain(length: usize) -> Value {
        assert!(length > 0, "reference chain needs a leaf");
        let mut definitions = serde_json::Map::new();
        definitions.insert("node-00000".to_owned(), Value::Bool(true));
        for index in 1..length {
            let name = format!("node-{index:05}");
            let prior = format!("node-{:05}", index - 1);
            definitions.insert(name, json!({"$ref": format!("#/$defs/{prior}")}));
        }
        let last = format!("node-{:05}", length - 1);
        json!({"$defs": definitions, "$ref": format!("#/$defs/{last}")})
    }

    fn schema_with_definition_count(count: usize) -> Value {
        let mut definitions = serde_json::Map::new();
        for index in 0..count {
            definitions.insert(format!("node-{index:05}"), Value::Bool(true));
        }
        json!({"$defs": definitions})
    }

    fn schema_with_required_count(count: usize) -> (Value, Value) {
        let names = (0..count)
            .map(|index| Value::String(format!("field-{index:05}")))
            .collect::<Vec<_>>();
        let object = names
            .iter()
            .filter_map(Value::as_str)
            .map(|name| (name.to_owned(), Value::Null))
            .collect();
        (json!({"required": names}), Value::Object(object))
    }

    fn nested_array_value(depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        value
    }

    #[test]
    fn malformed_supported_keyword_shapes_fail_closed() {
        let cases = [
            ("$comment", json!({"$comment": false})),
            ("$id", json!({"$id": false})),
            ("$schema", json!({"$schema": false})),
            ("$defs", json!({"$defs": []})),
            ("examples", json!({"examples": {}})),
            ("deprecated", json!({"deprecated": null})),
            ("readOnly", json!({"readOnly": null})),
            ("writeOnly", json!({"writeOnly": null})),
            ("description", json!({"description": false})),
            ("title", json!({"title": false})),
            ("$ref", json!({"$ref": 7})),
            ("allOf", json!({"allOf": {}})),
            ("anyOf", json!({"anyOf": []})),
            ("oneOf", json!({"oneOf": [7]})),
            ("enum", json!({"enum": []})),
            ("type", json!({"type": ["string"]})),
            ("required", json!({"required": ["id", "id"]})),
            ("properties", json!({"properties": []})),
            ("additionalProperties", json!({"additionalProperties": 7})),
            ("minItems", json!({"minItems": -1})),
            ("maxItems", json!({"maxItems": "1"})),
            ("prefixItems", json!({"prefixItems": {}})),
            ("items", json!({"items": []})),
            ("uniqueItems", json!({"uniqueItems": 1})),
            ("minLength", json!({"minLength": -1})),
            ("maxLength", json!({"maxLength": "1"})),
            ("pattern", json!({"pattern": 7})),
            ("format", json!({"format": true})),
            ("minimum", json!({"minimum": "0"})),
            ("maximum", json!({"maximum": []})),
        ];

        for (keyword, schema) in cases {
            let error = validate(&schema, &json!(null)).expect_err("malformed schema rejects");
            assert!(
                error.contains(keyword),
                "missing keyword {keyword}: {error}"
            );
            assert!(
                error.contains("invalid schema"),
                "unexpected error: {error}"
            );
        }

        let error = validate(&json!({"pattern": "("}), &json!(null))
            .expect_err("invalid regular expression rejects");
        assert!(
            error.contains("invalid schema pattern"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unsupported_keywords_are_rejected_even_when_unreachable() {
        for schema in [
            json!({"$defs": {"unused": {"not": {"type": "string"}}}}),
            json!({"properties": {"optional": {"contains": {"const": 1}}}}),
            json!({"allOf": [{"type": "string"}, {"dependentRequired": {"a": ["b"]}}]}),
        ] {
            let error = validate(&schema, &json!(null)).expect_err("unsupported keyword rejects");
            assert!(
                error.contains("unsupported schema keyword"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn remote_unresolved_and_cyclic_local_references_fail_closed() {
        let cases = [
            json!({"$ref": "https://schema.invalid/example"}),
            json!({"$ref": "#/$defs/missing", "$defs": {}}),
            json!({"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}}, "$ref": "#/$defs/a"}),
        ];

        for schema in cases {
            let error = validate(&schema, &json!(null)).expect_err("invalid reference rejects");
            assert!(
                error.contains("reference"),
                "reference failure is explicit: {error}"
            );
        }
    }

    #[test]
    fn schema_node_and_reference_depth_bounds_are_exact_and_fail_closed() {
        validate(
            &schema_with_definition_count(MAX_SCHEMA_NODES - 1),
            &json!(null),
        )
        .expect("the schema node limit is inclusive");
        let error = validate(
            &schema_with_definition_count(MAX_SCHEMA_NODES),
            &json!(null),
        )
        .expect_err("one node over the schema node limit rejects");
        assert!(
            error.contains("schema node limit"),
            "unexpected error: {error}"
        );

        validate(&bottom_up_reference_chain(MAX_SCHEMA_DEPTH), &json!(null))
            .expect("the schema reference depth limit is inclusive");
        let error = validate(
            &bottom_up_reference_chain(MAX_SCHEMA_DEPTH + 1),
            &json!(null),
        )
        .expect_err("bottom-up reference chain beyond the depth limit rejects");
        assert!(
            error.contains("schema nesting depth exceeds"),
            "unexpected error: {error}"
        );

        let runtime_schema = bottom_up_reference_chain(MAX_SCHEMA_DEPTH + 1);
        let mut context = ValidationContext::default();
        let error = validate_node(
            &runtime_schema,
            &runtime_schema,
            &json!(null),
            "$",
            &|_, _, _| Ok(()),
            &mut context,
            0,
        )
        .expect_err("runtime reference depth rejects before an unbounded descent");
        assert!(
            error.contains("validation schema depth exceeds"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn required_and_enum_preflight_limits_are_exact_and_fail_closed() {
        let (schema, instance) = schema_with_required_count(MAX_REQUIRED_PROPERTIES);
        validate(&schema, &instance).expect("the required entry limit is inclusive");
        let (schema, instance) = schema_with_required_count(MAX_REQUIRED_PROPERTIES + 1);
        let error = validate(&schema, &instance).expect_err("one required entry over rejects");
        assert!(
            error.contains("required entry limit"),
            "unexpected error: {error}"
        );

        let exact_required_name = "x".repeat(MAX_REQUIRED_BYTES);
        validate(&json!({"required": [exact_required_name]}), &json!(null))
            .expect("the required byte limit is inclusive");
        let oversized_required_name = "x".repeat(MAX_REQUIRED_BYTES + 1);
        let error = validate(
            &json!({"required": [oversized_required_name]}),
            &json!(null),
        )
        .expect_err("one required byte over rejects");
        assert!(
            error.contains("required byte limit"),
            "unexpected error: {error}"
        );

        let enum_values: Vec<Value> = (0..MAX_ENUM_VALUES).map(|index| json!(index)).collect();
        validate(&json!({"enum": enum_values}), &json!(MAX_ENUM_VALUES - 1))
            .expect("the enum entry limit is inclusive");
        let enum_values: Vec<Value> = (0..=MAX_ENUM_VALUES).map(|index| json!(index)).collect();
        let error = validate(&json!({"enum": enum_values}), &json!(null))
            .expect_err("one enum entry over rejects");
        assert!(
            error.contains("enum entry limit"),
            "unexpected error: {error}"
        );

        let exact_enum_value = "x".repeat(MAX_ENUM_SERIALIZED_BYTES - 2);
        validate(
            &json!({"enum": [exact_enum_value.clone()]}),
            &json!(exact_enum_value),
        )
        .expect("the enum byte limit is inclusive");
        let oversized_enum_value = "x".repeat(MAX_ENUM_SERIALIZED_BYTES - 1);
        let error = validate(&json!({"enum": [oversized_enum_value]}), &json!(null))
            .expect_err("one enum byte over rejects");
        assert!(
            error.contains("enum byte limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn schema_preflight_work_limit_is_exact_and_fail_closed() {
        let exact_values = (0..MAX_ENUM_VALUES)
            .map(|index| {
                let length = if index == 0 { 14 } else { 15 };
                Value::Array(std::iter::repeat_n(Value::Null, length).collect())
            })
            .collect::<Vec<_>>();
        validate(
            &json!({"enum": exact_values.clone()}),
            exact_values.first().expect("enum has a first value"),
        )
        .expect("the preflight work limit is inclusive");

        let oversized_values = (0..MAX_ENUM_VALUES)
            .map(|_| Value::Array(std::iter::repeat_n(Value::Null, 15).collect()))
            .collect::<Vec<_>>();
        let error = validate(&json!({"enum": oversized_values}), &json!(null))
            .expect_err("one preflight operation over rejects");
        assert!(
            error.contains("schema preflight work limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn branching_reference_dag_is_bounded_and_validation_work_exhaustion_fails_closed() {
        let mut definitions = serde_json::Map::new();
        definitions.insert("leaf".to_owned(), json!({"type": "integer"}));
        let mut prior = "leaf".to_owned();
        for index in 0..20 {
            let name = format!("branch-{index}");
            definitions.insert(
                name.clone(),
                json!({"allOf": [{"$ref": format!("#/$defs/{prior}")}, {"$ref": format!("#/$defs/{prior}")}]}),
            );
            prior = name;
        }
        let dag_schema = json!({"$defs": definitions, "$ref": format!("#/$defs/{prior}")});
        validate(&dag_schema, &json!(7))
            .expect("shared local-reference DAG validates once per subproblem");

        let exact_instance = Value::Array(
            (0..MAX_VALIDATION_WORK - 1)
                .map(|index| json!(index))
                .collect(),
        );
        validate(&json!({"type": "array", "items": {}}), &exact_instance)
            .expect("the validation work limit is inclusive");

        let expensive_instance =
            Value::Array((0..MAX_VALIDATION_WORK).map(|index| json!(index)).collect());
        let error = validate(&json!({"type": "array", "items": {}}), &expensive_instance)
            .expect_err("work cap rejects expensive validation");
        assert!(
            error.contains("validation work limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unique_items_is_nonquadratic_and_strictly_bounded() {
        let schema = json!({"type": "array", "uniqueItems": true});
        let accepted = Value::Array((0..MAX_UNIQUE_ITEMS).map(|index| json!(index)).collect());
        validate(&schema, &accepted).expect("bounded distinct items validate");

        let oversized = Value::Array((0..=MAX_UNIQUE_ITEMS).map(|index| json!(index)).collect());
        let error = validate(&schema, &oversized).expect_err("oversized uniqueItems rejects");
        assert!(
            error.contains("uniqueItems array length"),
            "unexpected error: {error}"
        );

        assert!(validate(&schema, &json!([1, 1])).is_err());
        assert!(validate(&schema, &json!([1, 1.0])).is_err());
        let nested_equivalents: Value =
            serde_json::from_str(r#"[[1,{"number":1.0}],[1.0,{"number":1e0}]]"#)
                .expect("nested numeric JSON parses");
        assert!(validate(&schema, &nested_equivalents).is_err());
        let signed_zero_equivalents: Value =
            serde_json::from_str("[0,-0.0]").expect("signed-zero JSON parses");
        assert!(validate(&schema, &signed_zero_equivalents).is_err());
        let distinct_large_integers: Value =
            serde_json::from_str("[9007199254740992,9007199254740993]")
                .expect("large integers parse without float conversion");
        validate(&schema, &distinct_large_integers)
            .expect("distinct large integers are not collapsed through f64");
        validate(&json!({"enum": [1]}), &json!(1.0))
            .expect("enum uses mathematical numeric equality too");

        let exact_byte_limited = Value::Array(vec![Value::String(
            "x".repeat(MAX_UNIQUE_SERIALIZED_BYTES - 2),
        )]);
        validate(&schema, &exact_byte_limited).expect("the uniqueItems byte limit is inclusive");

        let byte_limited =
            Value::Array(vec![Value::String("x".repeat(MAX_UNIQUE_SERIALIZED_BYTES))]);
        let error = validate(&schema, &byte_limited)
            .expect_err("oversized uniqueItems serialization rejects");
        assert!(
            error.contains("uniqueItems serialized byte limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unique_items_depth_is_checked_before_serialization() {
        let schema = json!({"type": "array", "uniqueItems": true});
        let at_limit = Value::Array(vec![nested_array_value(MAX_SCHEMA_DEPTH)]);
        validate(&schema, &at_limit).expect("the JSON value nesting limit is inclusive");

        let one_over = Value::Array(vec![nested_array_value(MAX_SCHEMA_DEPTH + 1)]);
        let one_over_error = validate(&schema, &one_over)
            .expect_err("one JSON value nesting level over rejects before serialization");
        assert!(
            one_over_error.contains("JSON value nesting depth exceeds"),
            "unexpected error: {one_over_error}"
        );

        let very_deep = Value::Array(vec![nested_array_value(MAX_SCHEMA_DEPTH * 32)]);
        let error = validate(&schema, &very_deep)
            .expect_err("deep uniqueItems values reject before serialization can recurse");
        assert_eq!(
            error, one_over_error,
            "the bounded error is stable regardless of unvisited nesting"
        );
    }

    #[test]
    fn local_composition_tuple_bounds_patterns_and_uniqueness_are_enforced() {
        let schema = json!({
            "$defs": {
                "lower_hex": {"type": "string", "pattern": "^[0-9a-f]{4}$", "maxLength": 4},
                "positive": {"type": "integer", "minimum": 1}
            },
            "allOf": [
                {"type": "array", "minItems": 2, "maxItems": 2, "uniqueItems": true},
                {"prefixItems": [{"$ref": "#/$defs/positive"}, {"$ref": "#/$defs/lower_hex"}], "items": false}
            ]
        });
        validate(&schema, &json!([1, "cafe"])).expect("complete local schema validates");
        for invalid in [
            json!([1, "cafe", 3]),
            json!([0, "cafe"]),
            json!([1, "CAFE"]),
        ] {
            assert!(validate(&schema, &invalid).is_err());
        }
    }

    #[test]
    fn inclusive_numeric_maximum_is_enforced() {
        let schema = json!({"type": "integer", "minimum": 0, "maximum": 10_000_000});

        validate(&schema, &json!(0)).expect("minimum is accepted");
        validate(&schema, &json!(10_000_000)).expect("maximum is inclusive");
        let error = validate(&schema, &json!(10_000_001)).expect_err("one over must reject");
        assert!(error.contains("<= 10000000"), "unexpected error: {error}");
    }
}
