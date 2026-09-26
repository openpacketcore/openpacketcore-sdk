//! Frozen-original behavior comparison for a later principal parser correction.
//! Preserve durable classification and exact fields against the original parser.

use super::super::{
    config_principal_matches_aad, config_principal_metadata_is_valid, config_recovery_required,
    config_replay_lookup_digest, config_rollback_label, parse_config_principal,
    validate_replay_lookup_digest, validate_rollback_label, ConfigPrincipalMetadata,
    ParsedConfigPrincipal,
};

#[rustfmt::skip]
mod frozen_original {
    use super::{ConfigPrincipalMetadata, ParsedConfigPrincipal,
        validate_replay_lookup_digest, validate_rollback_label};
    use serde::de::{IgnoredAny, MapAccess, Visitor};
    use serde::{Deserialize, Deserializer};
    use std::fmt;

    #[derive(Debug, Default)]
    struct ConfigPrincipalMetadataProbe {
        is_object: bool,
        saw_reserved_field: bool,
        saw_principal: bool,
        principal: Option<String>,
        saw_replay_lookup_digest: bool,
        replay_lookup_digest: Option<String>,
        saw_recovery_required: bool,
        recovery_required: Option<bool>,
        saw_rollback_label: bool,
        rollback_label: Option<String>,
        duplicate_reserved_field: bool,
        unknown_field: bool,
        invalid_field_type: bool,
    }

    impl<'de> Deserialize<'de> for ConfigPrincipalMetadataProbe {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ProbeVisitor;

            impl<'de> Visitor<'de> for ProbeVisitor {
                type Value = ConfigPrincipalMetadataProbe;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a JSON object")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut probe = ConfigPrincipalMetadataProbe {
                        is_object: true,
                        ..ConfigPrincipalMetadataProbe::default()
                    };
                    while let Some(field) = map.next_key::<String>()? {
                        match field.as_str() {
                            "principal" => {
                                probe.saw_reserved_field = true;
                                if probe.saw_principal {
                                    probe.duplicate_reserved_field = true;
                                }
                                probe.saw_principal = true;
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::String(principal) => {
                                        probe.principal = Some(principal);
                                    }
                                    _ => probe.invalid_field_type = true,
                                }
                            }
                            "replay_lookup_digest" => {
                                probe.saw_reserved_field = true;
                                if probe.saw_replay_lookup_digest {
                                    probe.duplicate_reserved_field = true;
                                }
                                probe.saw_replay_lookup_digest = true;
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Null => probe.replay_lookup_digest = None,
                                    serde_json::Value::String(digest) => {
                                        probe.replay_lookup_digest = Some(digest);
                                    }
                                    _ => probe.invalid_field_type = true,
                                }
                            }
                            "recovery_required" => {
                                probe.saw_reserved_field = true;
                                if probe.saw_recovery_required {
                                    probe.duplicate_reserved_field = true;
                                }
                                probe.saw_recovery_required = true;
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Bool(required) => {
                                        probe.recovery_required = Some(required);
                                    }
                                    _ => probe.invalid_field_type = true,
                                }
                            }
                            "rollback_label" => {
                                probe.saw_reserved_field = true;
                                if probe.saw_rollback_label {
                                    probe.duplicate_reserved_field = true;
                                }
                                probe.saw_rollback_label = true;
                                let value = map.next_value::<serde_json::Value>()?;
                                match value {
                                    serde_json::Value::Null => probe.rollback_label = None,
                                    serde_json::Value::String(label) => {
                                        probe.rollback_label = Some(label);
                                    }
                                    _ => probe.invalid_field_type = true,
                                }
                            }
                            _ => {
                                probe.unknown_field = true;
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                    Ok(probe)
                }
            }

            deserializer.deserialize_any(ProbeVisitor)
        }
    }

    pub(super) fn parse_config_principal(stored: &str) -> ParsedConfigPrincipal {
        let Ok(probe) = serde_json::from_str::<ConfigPrincipalMetadataProbe>(stored) else {
            return ParsedConfigPrincipal::Legacy;
        };
        if !probe.is_object || !probe.saw_reserved_field {
            return ParsedConfigPrincipal::Legacy;
        }
        if probe.duplicate_reserved_field
            || probe.unknown_field
            || probe.invalid_field_type
            || !probe.saw_principal
            || !probe.saw_recovery_required
        {
            return ParsedConfigPrincipal::Invalid;
        }
        let Some(principal) = probe.principal else {
            return ParsedConfigPrincipal::Invalid;
        };
        let Some(recovery_required) = probe.recovery_required else {
            return ParsedConfigPrincipal::Invalid;
        };
        if principal.is_empty()
            || probe
                .replay_lookup_digest
                .as_deref()
                .is_some_and(|digest| validate_replay_lookup_digest(digest).is_err())
            || probe
                .rollback_label
                .as_deref()
                .is_some_and(|label| validate_rollback_label(label).is_err())
        {
            return ParsedConfigPrincipal::Invalid;
        }
        ParsedConfigPrincipal::Wrapped(ConfigPrincipalMetadata {
            principal,
            replay_lookup_digest: probe.replay_lookup_digest,
            recovery_required,
            rollback_label: probe.rollback_label,
        })
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Legacy,
    Wrapped,
    Invalid,
}

// No Debug implementation: assertion output must not print a principal value.
#[derive(PartialEq, Eq)]
struct Signature {
    class: Class,
    principal: Option<String>,
    replay: Option<String>,
    recovery: Option<bool>,
    rollback: Option<String>,
}

fn signature(parsed: ParsedConfigPrincipal) -> Signature {
    match parsed {
        ParsedConfigPrincipal::Legacy | ParsedConfigPrincipal::Invalid => Signature {
            class: if matches!(parsed, ParsedConfigPrincipal::Legacy) {
                Class::Legacy
            } else {
                Class::Invalid
            },
            principal: None,
            replay: None,
            recovery: None,
            rollback: None,
        },
        ParsedConfigPrincipal::Wrapped(metadata) => Signature {
            class: Class::Wrapped,
            principal: Some(metadata.principal),
            replay: metadata.replay_lookup_digest,
            recovery: Some(metadata.recovery_required),
            rollback: metadata.rollback_label,
        },
    }
}

fn compare(stored: &str, expected_class: Option<Class>) {
    let original = signature(frozen_original::parse_config_principal(stored));
    let current = signature(parse_config_principal(stored));
    assert!(
        current == original,
        "original classification and exact fields must match"
    );
    if let Some(expected) = expected_class {
        assert_eq!(original.class, expected, "fixed fixture classification");
    }
    assert_eq!(
        config_principal_metadata_is_valid(stored),
        original.class != Class::Invalid
    );
    let valid_aad = match original.class {
        Class::Legacy => stored,
        Class::Wrapped => original.principal.as_deref().expect("wrapped principal"),
        Class::Invalid => "synthetic-rejection-probe",
    };
    assert_eq!(
        config_principal_matches_aad(stored, valid_aad),
        original.class != Class::Invalid
    );
    match original.class {
        Class::Invalid => {
            assert!(config_replay_lookup_digest(stored).is_err());
            assert!(config_recovery_required(stored).is_err());
            assert!(config_rollback_label(stored).is_err());
        }
        Class::Legacy | Class::Wrapped => {
            assert!(config_replay_lookup_digest(stored).ok() == Some(original.replay));
            assert!(
                config_recovery_required(stored).ok() == Some(original.recovery.unwrap_or(false))
            );
            assert!(config_rollback_label(stored).ok() == Some(original.rollback));
        }
    }
}

fn wrapper(field: &str, value: &str) -> String {
    match field {
        "principal" => format!(r#"{{"principal":{value},"recovery_required":false}}"#),
        "recovery_required" => {
            format!(r#"{{"principal":"synthetic","recovery_required":{value}}}"#)
        }
        "replay_lookup_digest" | "rollback_label" => {
            format!(r#"{{"principal":"synthetic","recovery_required":false,"{field}":{value}}}"#)
        }
        _ => panic!("unsupported synthetic fixture field"),
    }
}

const FIELDS: [&str; 4] = [
    "principal",
    "replay_lookup_digest",
    "recovery_required",
    "rollback_label",
];

#[test]
fn config_capacity_957_principal_parser_preserves_fixed_classes_and_fields() {
    for stored in [
        "synthetic",
        "",
        "null",
        "false",
        "7",
        "[]",
        "{}",
        r#"{"unknown":[]}"#,
    ] {
        compare(stored, Some(Class::Legacy));
    }
    for stored in [
        r#"{"principal":"synthetic","recovery_required":false}"#,
        r#"{"principal":"synthetic","recovery_required":true,"rollback_label":"savepoint"}"#,
        r#"{"principal":"synthetic","recovery_required":false,"rollback_label":null,"replay_lookup_digest":null}"#,
        r#"{"recovery_required":false,"\u0070rincipal":"synthetic"}"#,
    ] {
        compare(stored, Some(Class::Wrapped));
    }
    for stored in [
        r#"{"principal":[]}"#,
        r#"{"principal":"","recovery_required":false}"#,
        r#"{"recovery_required":false}"#,
        r#"{"principal":"synthetic"}"#,
        r#"{"principal":"synthetic","recovery_required":false,"unknown":null}"#,
        r#"{"principal":"synthetic","principal":"other","recovery_required":false}"#,
        r#"{"principal":"synthetic","recovery_required":false,"recovery_required":true}"#,
        r#"{"principal":"synthetic","recovery_required":false,"replay_lookup_digest":null,"replay_lookup_digest":null}"#,
        r#"{"principal":"synthetic","recovery_required":false,"rollback_label":null,"rollback_label":null}"#,
    ] {
        compare(stored, Some(Class::Invalid));
    }
    for stored in [
        r#"{"principal":[],"recovery_required":false,}"#,
        r#"{"principal":[],"recovery_required":false} trailing"#,
        r#"{"principal":[],"recovery_required":false,"unknown":[}"#,
    ] {
        compare(stored, Some(Class::Legacy));
    }
}

#[test]
fn config_capacity_957_principal_parser_preserves_value_numeric_and_late_syntax_rules() {
    // IgnoredAny does not validate surrogate pairing in unknown strings.
    compare(
        r#"{"principal":"synthetic","recovery_required":false,"unknown":"\uD800"}"#,
        Some(Class::Invalid),
    );

    for field in FIELDS {
        for value in [
            "0",
            "-0",
            "1.5",
            "18446744073709551616",
            "[]",
            "{}",
            "[0]",
            r#"{"x":0}"#,
        ] {
            compare(&wrapper(field, value), Some(Class::Invalid));
        }
        for value in ["1e999", "-1e999", "[1e999]", r#"{"x":1e999}"#] {
            let expected = if serde_json::from_str::<serde_json::Value>("1e999").is_ok() {
                Class::Invalid
            } else {
                Class::Legacy
            };
            compare(&wrapper(field, value), Some(expected));
        }
        for value in ["[0,]", r#"{"x":0,}"#, r#"["\uD800"]"#, r#"{"x":"\uD800"}"#] {
            compare(&wrapper(field, value), Some(Class::Legacy));
        }
    }
    // Unknown fields retain the original IgnoredAny behavior, which can differ
    // from Value's numeric conversion. A correction must not homogenize them.
    compare(
        r#"{"principal":"synthetic","recovery_required":false,"unknown":1e999}"#,
        Some(Class::Invalid),
    );
}

#[test]
fn config_capacity_957_principal_parser_preserves_first_raw_token_semantics() {
    const RAW: &str = "$serde_json::private::RawValue";
    let replay = "a".repeat(64);
    for (field, scalar) in [
        ("principal", r#""synthetic""#.to_owned()),
        (
            "replay_lookup_digest",
            serde_json::to_string(&replay).expect("synthetic digest"),
        ),
        ("recovery_required", "true".to_owned()),
        ("rollback_label", r#""savepoint""#.to_owned()),
    ] {
        let encoded = serde_json::to_string(&scalar).expect("synthetic embedded JSON");
        compare(
            &wrapper(field, &format!(r#"{{"{RAW}":{encoded}}}"#)),
            Some(Class::Wrapped),
        );
        compare(
            &wrapper(field, &format!(r#"{{"ordinary":0,"{RAW}":{encoded}}}"#)),
            Some(Class::Invalid),
        );
        compare(
            &wrapper(field, &format!(r#"{{"{RAW}":{encoded},"ordinary":0}}"#)),
            Some(Class::Legacy),
        );
        compare(
            &wrapper(field, &format!(r#"{{"{RAW}":false}}"#)),
            Some(Class::Legacy),
        );
        for embedded in [
            "[]",
            "{}",
            "[0]",
            "1e999",
            "[1e999]",
            "[0,]",
            "null trailing",
        ] {
            let encoded = serde_json::to_string(embedded).expect("synthetic embedded value");
            compare(&wrapper(field, &format!(r#"{{"{RAW}":{encoded}}}"#)), None);
        }
    }
}

#[test]
fn config_capacity_957_principal_parser_preserves_depth_and_scalar_boundaries() {
    for field in FIELDS {
        for depth in [1, 2, 32, 64, 125, 126, 127, 128, 129, 130, 132] {
            let value = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            compare(&wrapper(field, &value), None);
        }
        for value in [
            "null",
            "true",
            "false",
            r#""""#,
            r#""synthetic""#,
            r#""\u0073ynthetic""#,
            r#""\uD834\uDD1E""#,
        ] {
            compare(&wrapper(field, value), None);
        }
    }
    for value in [
        "a".repeat(63),
        "a".repeat(64),
        "a".repeat(65),
        "A".repeat(64),
    ] {
        compare(
            &wrapper(
                "replay_lookup_digest",
                &serde_json::to_string(&value).expect("synthetic digest"),
            ),
            None,
        );
    }
    for value in [
        "a".repeat(127),
        "a".repeat(128),
        "a".repeat(129),
        " padded ".to_owned(),
        "line\ncontrol".to_owned(),
    ] {
        compare(
            &wrapper(
                "rollback_label",
                &serde_json::to_string(&value).expect("synthetic label"),
            ),
            None,
        );
    }
}

#[test]
fn config_capacity_957_principal_parser_preserves_number_tokens_and_nested_raw_values() {
    const RAW: &str = "$serde_json::private::RawValue";
    const NUMBER: &str = "$serde_json::private::Number";
    for field in FIELDS {
        for scalar in [
            r#""0""#,
            r#""1e999""#,
            r#""invalid""#,
            "false",
            "null",
            "[]",
        ] {
            for value in [
                format!(r#"{{"{NUMBER}":{scalar}}}"#),
                format!(r#"{{"{NUMBER}":{scalar},"x":0}}"#),
                format!(r#"{{"x":0,"{NUMBER}":{scalar}}}"#),
            ] {
                compare(&wrapper(field, &value), None);
            }
        }
        for embedded in [
            r#""synthetic""#,
            r#"["\uD800"]"#,
            r#"{"ordinary":1e999}"#,
            "[0,]",
            "null trailing",
            r#"{"same":[],"same":0}"#,
        ] {
            let mut value = embedded.to_owned();
            for _ in 0..5 {
                value = format!(
                    r#"{{"{RAW}":{}}}"#,
                    serde_json::to_string(&value).expect("synthetic raw JSON")
                );
                compare(&wrapper(field, &value), None);
                compare(&wrapper(field, &format!("[{value}]")), None);
                compare(&wrapper(field, &format!(r#"{{"ordinary":{value}}}"#)), None);
            }
        }
    }
}
