use opc_evidence::RequirementId;
use serde_json::Value;
use std::str::FromStr;

pub fn validate_yaml_str_against_schema(
    schema_str: &str,
    instance_yaml: &str,
) -> Result<(), String> {
    let schema: Value = serde_json::from_str(schema_str)
        .map_err(|err| format!("schema JSON parse error: {err}"))?;
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(instance_yaml)
        .map_err(|err| format!("instance YAML parse error: {err}"))?;
    let instance = serde_json::to_value(yaml_value)
        .map_err(|err| format!("instance YAML->JSON conversion error: {err}"))?;
    validate_value_against_schema(&schema, &instance)
}

pub fn validate_value_against_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    opc_schema_validate::validate_with_format(
        schema,
        instance,
        "$",
        &|string, format_name, path| match format_name {
            "opc-requirement-id" => RequirementId::from_str(string)
                .map(|_| ())
                .map_err(|err| format!("{path}: invalid requirement id '{string}': {err}")),
            other => Err(format!("{path}: unsupported format '{other}'")),
        },
    )
}
