use opc_evidence::RequirementId;
use serde_json::Value;
use std::str::FromStr;
use std::sync::OnceLock;

const SCENARIO_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc012/v1/scenario.schema.json"
));

static SCHEMA: OnceLock<Value> = OnceLock::new();

pub(crate) fn validate_scenario_document(instance: &Value) -> Result<(), crate::TestbedError> {
    let schema = SCHEMA.get_or_init(|| {
        serde_json::from_str(SCENARIO_SCHEMA_JSON)
            .expect("compile-time scenario schema must be valid JSON")
    });
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
    .map_err(crate::TestbedError::Validation)
}
