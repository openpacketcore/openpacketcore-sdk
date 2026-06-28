#![allow(dead_code, unused_imports)]

#[path = "../support/schema_support.rs"]
pub mod schema_support;

pub use opc_evidence::*;

pub const EVIDENCE_RECORD_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/evidence-record.schema.json"
));
pub const GAP_RECORD_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/gap-record.schema.json"
));
pub const BUNDLE_MANIFEST_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/bundle-manifest.schema.json"
));
pub const CONFORMANCE_REPORT_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/conformance-report.schema.json"
));
pub const REQUIREMENT_INVENTORY_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/requirement-inventory.schema.json"
));
pub const PERFORMANCE_BASELINE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/performance-baseline.schema.json"
));
pub const VEX_POLICY_RESULT_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/vex-policy-result.schema.json"
));
pub const PACKET_CORE_PROTOCOL_EVIDENCE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/packet-core-protocol-evidence.schema.json"
));
pub const PACKET_CORE_ATTACH_EVIDENCE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/packet-core-attach-evidence.schema.json"
));
pub const PACKET_CORE_KERNEL_DATAPLANE_EVIDENCE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/packet-core-kernel-dataplane-evidence.schema.json"
));
pub const PACKET_CORE_EVIDENCE_PACK_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schemas/rfc006/v1/packet-core-evidence-pack.schema.json"
));

// ---------------------------------------------------------------------------
// JSON fixture format validation helpers
// ---------------------------------------------------------------------------

pub fn validate_date_format(value: &str, format: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty string".to_string());
    }
    match format {
        "date" => {
            static DATE_FMT: once_cell::sync::Lazy<
                Vec<time::format_description::FormatItem<'static>>,
            > = once_cell::sync::Lazy::new(|| {
                time::format_description::parse("[year]-[month]-[day]")
                    .expect("valid date format description")
            });
            time::Date::parse(value, &DATE_FMT)
                .map(|_| ())
                .map_err(|e| format!("date parse error: {e}"))
        }
        "date-time" => {
            if value.contains(' ') {
                return Err("date-time must use 'T' separator, not space".to_string());
            }
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map(|_| ())
                .map_err(|e| format!("date-time parse error: {e}"))
        }
        _ => Ok(()),
    }
}

pub fn validate_formats_on_object(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Option<String> {
    for (key, value) in obj {
        let field_path = format!("{path}.{key}");
        if let Some(s) = value.as_str() {
            let format_hint = match key.as_str() {
                "created" | "created_date" => Some("date"),
                "last_updated" | "generation_timestamp" | "updated_at" => Some("date-time"),
                _ => None,
            };
            if let Some(fmt) = format_hint {
                if let Err(err) = validate_date_format(s, fmt) {
                    return Some(format!(
                        "{field_path} (format '{fmt}') validation failed: {err}; value: {s:?}"
                    ));
                }
            }
        }
        if let Some(inner) = value.as_object() {
            if let Some(err) = validate_formats_on_object(inner, &field_path) {
                return Some(err);
            }
        }
        if let Some(arr) = value.as_array() {
            for (i, item) in arr.iter().enumerate() {
                if let Some(inner) = item.as_object() {
                    if let Some(err) =
                        validate_formats_on_object(inner, &format!("{field_path}[{i}]"))
                    {
                        return Some(err);
                    }
                }
            }
        }
    }
    None
}

pub fn validate_fixture_formats(raw_json: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(raw_json).map_err(|e| format!("JSON parse error: {e}"))?;

    if let Some(obj) = value.as_object() {
        if let Some(err) = validate_formats_on_object(obj, "<root>") {
            return Err(err);
        }
    } else if let Some(arr) = value.as_array() {
        for (i, item) in arr.iter().enumerate() {
            if let Some(obj) = item.as_object() {
                if let Some(err) = validate_formats_on_object(obj, &format!("<root>[{i}]")) {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture Constructors
// ---------------------------------------------------------------------------

pub fn valid_gap() -> Gap {
    use time::Date;
    Gap::new(
        "GAP-000001",
        "Test gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec!["REQ-3GPP-TS29281-R18-5.1-001".into()],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("opc-proto-gtp".into()),
            target_release: Some("0.3.0".into()),
            mitigation: Some("Reject in strict mode.".into()),
            security_impact: Some("Low.".into()),
            security_approval: None,
            performance_impact: None,
        },
    )
    .expect("valid_gap() should always produce a valid gap")
}

pub fn valid_gap_options() -> GapOptions {
    GapOptions {
        owner: Some("opc-proto-gtp".into()),
        target_release: Some("0.3.0".into()),
        mitigation: Some("Reject in strict mode.".into()),
        security_impact: Some("Low.".into()),
        security_approval: None,
        performance_impact: None,
    }
}

pub fn make_open_gap() -> Gap {
    use time::Date;
    Gap::new(
        "GAP-000001",
        "Open gap",
        GapStatus::Open,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("team-x".into()),
            mitigation: Some("Will fix in next release".into()),
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn make_closed_gap() -> Gap {
    use time::Date;
    Gap::new(
        "GAP-000002",
        "Closed gap",
        GapStatus::Closed,
        GapSeverity::Low,
        vec![],
        Date::from_calendar_date(2026, time::Month::January, 1).unwrap(),
        GapOptions {
            owner: Some("team-x".into()),
            mitigation: Some("Fixed in 0.2.0".into()),
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn make_deferred_gap() -> Gap {
    use time::Date;
    Gap::new(
        "GAP-000003",
        "Deferred gap",
        GapStatus::Deferred,
        GapSeverity::Medium,
        vec![],
        Date::from_calendar_date(2026, time::Month::May, 19).unwrap(),
        GapOptions {
            owner: Some("team-y".into()),
            mitigation: Some("Deferred to next release".into()),
            ..Default::default()
        },
    )
    .unwrap()
}
