use opc_evidence::RequirementId;
use serde_json::Value;
use std::str::FromStr;
use std::sync::OnceLock;

pub fn validate_json_str_against_schema(
    schema_str: &str,
    instance_str: &str,
) -> Result<(), String> {
    let schema: Value = serde_json::from_str(schema_str)
        .map_err(|err| format!("schema JSON parse error: {err}"))?;
    let instance: Value = serde_json::from_str(instance_str)
        .map_err(|err| format!("instance JSON parse error: {err}"))?;
    validate_value_against_schema(&schema, &instance)
}

pub fn validate_value_against_schema(schema: &Value, instance: &Value) -> Result<(), String> {
    opc_schema_validate::validate_with_format(schema, instance, "$", &validate_format)
}

fn validate_format(string: &str, format_name: &str, path: &str) -> Result<(), String> {
    static DATE_FMT: OnceLock<Vec<time::format_description::FormatItem<'static>>> = OnceLock::new();
    match format_name {
        "date" => {
            let format = DATE_FMT.get_or_init(|| {
                time::format_description::parse("[year]-[month]-[day]")
                    .expect("valid date format description")
            });
            time::Date::parse(string, format)
                .map(|_| ())
                .map_err(|err| format!("{path}: invalid date '{string}': {err}"))
        }
        "date-time" => {
            time::OffsetDateTime::parse(string, &time::format_description::well_known::Rfc3339)
                .map(|_| ())
                .map_err(|err| format!("{path}: invalid date-time '{string}': {err}"))
        }
        "opc-requirement-id" => RequirementId::from_str(string)
            .map(|_| ())
            .map_err(|err| format!("{path}: invalid requirement id '{string}': {err}")),
        "opc-gap-id" => {
            let digits = string.strip_prefix("GAP-").unwrap_or("");
            if digits.len() == 6 && digits.chars().all(|ch| ch.is_ascii_digit()) {
                Ok(())
            } else {
                Err(format!("{path}: invalid gap id '{string}'"))
            }
        }
        "opc-sha256" => {
            let digest = string.strip_prefix("sha256:").unwrap_or("");
            if digest.len() == 64
                && digest
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
            {
                Ok(())
            } else {
                Err(format!("{path}: invalid sha256 digest '{string}'"))
            }
        }
        other => Err(format!("{path}: unsupported format '{other}'")),
    }
}
