//! Compare tenant extraction with the frozen original Value-based function.
//! Synthetic cases retain the original output and error-to-fallback behavior.

#[rustfmt::skip]
mod frozen_original {
    use crate::types::wrapped_config_principal;

    pub fn extract_tenant(principal: &str) -> String {
        let wrapped = wrapped_config_principal(principal);
        let principal = wrapped.as_deref().unwrap_or(principal);
        if let Some(tenant) = serde_json::from_str::<serde_json::Value>(principal)
            .ok()
            .and_then(|principal| {
                principal
                    .get("tenant")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned)
            })
        {
            return tenant;
        }
        if let Some(rest) = principal.strip_prefix("spiffe://") {
            let mut segs = rest.split('/');
            while let Some(seg) = segs.next() {
                if seg == "tenant" {
                    if let Some(tenant) = segs.next() {
                        return tenant.to_string();
                    }
                }
            }
        }
        "default".to_string()
    }
}

fn compare(stored: &str, expected: Option<&str>) {
    let original = frozen_original::extract_tenant(stored);
    if let Some(expected) = expected {
        assert!(original == expected, "fixed original tenant selection");
    }
    assert!(
        crate::types::extract_tenant(stored) == original,
        "tenant extraction must preserve the original result"
    );
}

fn wrap(principal: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "principal": principal,
        "recovery_required": false,
    }))
    .expect("synthetic principal wrapper")
}

fn compare_raw_and_wrapped(principal: &str, expected: Option<&str>) {
    compare(principal, expected);
    compare(&wrap(principal), expected);
}

fn raw_token(embedded: &str) -> String {
    format!(
        r#"{{"$serde_json::private::RawValue":{}}}"#,
        serde_json::to_string(embedded).expect("synthetic embedded JSON")
    )
}

#[test]
fn config_capacity_957_tenant_projection_preserves_fields_and_duplicates() {
    for (principal, expected) in [
        ("null", "default"),
        ("true", "default"),
        ("7", "default"),
        (r#""scalar""#, "default"),
        ("[]", "default"),
        ("{}", "default"),
        (r#"{"tenant":"chosen"}"#, "chosen"),
        (r#"{"tenant":""}"#, ""),
        (r#"{"\u0074enant":"chosen"}"#, "chosen"),
        (r#"{"Tenant":"chosen"}"#, "default"),
        (r#"{"nested":{"tenant":"chosen"}}"#, "default"),
        (r#"{"tenant":["chosen"]}"#, "default"),
        (r#"{"tenant":{"tenant":"chosen"}}"#, "default"),
        (r#"{"tenant":false}"#, "default"),
        (r#"{"tenant":null}"#, "default"),
        (r#"{"tenant":"first","tenant":"last"}"#, "last"),
        (r#"{"tenant":"first","tenant":null}"#, "default"),
        (r#"{"tenant":"first","tenant":[]}"#, "default"),
        (r#"{"tenant":false,"tenant":"last"}"#, "last"),
        (r#"{"x":[0,{"y":1}],"tenant":"chosen","x":[]}"#, "chosen"),
        (r#"{"tenant":"chosen","principal":false}"#, "chosen"),
        (
            r#"{"tenant":"chosen","principal":"inner","recovery_required":false}"#,
            "chosen",
        ),
    ] {
        compare_raw_and_wrapped(principal, Some(expected));
    }
}

#[test]
fn config_capacity_957_tenant_projection_validates_unselected_values() {
    for principal in [
        r#"{"tenant":"chosen","x":"\uD800"}"#,
        r#"{"x":"\uD800","tenant":"chosen"}"#,
        r#"{"tenant":"chosen","x":["\uD800"]}"#,
        r#"{"tenant":"chosen","x":{"y":"\uD800"}}"#,
        r#"{"tenant":"chosen","x":[0,]}"#,
        r#"{"tenant":"chosen","x":{"y":0,}}"#,
        r#"{"tenant":"chosen","x":false,}"#,
        r#"{"tenant":"chosen"} trailing"#,
        r#"{"tenant":"chosen","x":"unterminated}"#,
    ] {
        compare_raw_and_wrapped(principal, Some("default"));
    }
    let numeric = if serde_json::from_str::<serde_json::Value>("1e999").is_ok() {
        "chosen"
    } else {
        "default"
    };
    for value in ["1e999", "-1e999", "[1e999]", r#"{"nested":1e999}"#] {
        compare_raw_and_wrapped(
            &format!(r#"{{"tenant":"chosen","x":{value}}}"#),
            Some(numeric),
        );
        compare_raw_and_wrapped(
            &format!(r#"{{"x":{value},"tenant":"chosen"}}"#),
            Some(numeric),
        );
    }
}

#[test]
fn config_capacity_957_tenant_projection_preserves_wrappers_and_spiffe() {
    for (principal, expected) in [
        ("spiffe://domain/tenant/chosen/service", "chosen"),
        ("spiffe://tenant/chosen", "chosen"),
        ("spiffe://domain/tenant/", ""),
        ("spiffe://domain/tenant", "default"),
        ("spiffe://domain/tenant//tenant/later", ""),
        ("spiffe://domain/Tenant/chosen", "default"),
        ("spiffe://domain/tenant/with%20space", "with%20space"),
        ("SPIFFE://domain/tenant/chosen", "default"),
        ("synthetic", "default"),
    ] {
        compare_raw_and_wrapped(principal, Some(expected));
        compare(&wrap(&wrap(principal)), Some("default"));
    }
    for principal in [
        r#"{"principal":"spiffe://domain/tenant/chosen","recovery_required":false,"extra":0}"#,
        r#"{"principal":"spiffe://domain/tenant/chosen","recovery_required":false,"principal":"other"}"#,
        r#"{"principal":"spiffe://domain/tenant/chosen"}"#,
        r#"{"principal":"spiffe://domain/tenant/chosen","recovery_required":null}"#,
        r#"{"principal":"spiffe://domain/tenant/chosen","recovery_required":false,"rollback_label":" padded "}"#,
    ] {
        compare(principal, Some("default"));
    }
}

#[test]
fn config_capacity_957_tenant_projection_preserves_first_raw_token() {
    const RAW: &str = "$serde_json::private::RawValue";
    let enabled = matches!(
        serde_json::from_str::<serde_json::Value>(&raw_token("null")),
        Ok(serde_json::Value::Null)
    );
    let embedded = r#"{"tenant":"chosen"}"#;
    compare_raw_and_wrapped(
        &raw_token(embedded),
        Some(if enabled { "chosen" } else { "default" }),
    );
    let encoded = serde_json::to_string(embedded).expect("synthetic embedded JSON");
    compare_raw_and_wrapped(
        &format!(r#"{{"ordinary":0,"{RAW}":{encoded},"tenant":"outer"}}"#),
        Some("outer"),
    );
    compare_raw_and_wrapped(
        &format!(r#"{{"{RAW}":{encoded},"tenant":"outer"}}"#),
        Some(if enabled { "default" } else { "outer" }),
    );
    compare_raw_and_wrapped(
        &format!(r#"{{"tenant":{}}}"#, raw_token(r#""chosen""#)),
        Some(if enabled { "chosen" } else { "default" }),
    );
    for token_value in ["false", "null", "[]", "{}", "0", r#""invalid""#] {
        let value = format!(r#"{{"{RAW}":{token_value}}}"#);
        for principal in [
            value.clone(),
            format!(r#"{{"tenant":"chosen","unknown":{value}}}"#),
            format!(r#"{{"tenant":{value}}}"#),
        ] {
            compare_raw_and_wrapped(&principal, None);
        }
    }
}

#[test]
fn config_capacity_957_tenant_projection_preserves_number_tokens_and_nested_raw() {
    const NUMBER: &str = "$serde_json::private::Number";
    for token_value in [
        r#""0""#,
        r#""1e999""#,
        r#""invalid""#,
        "null",
        "false",
        "[]",
    ] {
        for principal in [
            format!(r#"{{"{NUMBER}":{token_value},"tenant":"chosen"}}"#),
            format!(r#"{{"tenant":"chosen","{NUMBER}":{token_value}}}"#),
            format!(r#"{{"tenant":"chosen","unknown":{{"{NUMBER}":{token_value}}}}}"#),
            format!(r#"{{"tenant":{{"{NUMBER}":{token_value}}}}}"#),
        ] {
            compare_raw_and_wrapped(&principal, None);
        }
    }
    for embedded in [
        r#"{"tenant":"chosen"}"#,
        r#"{"tenant":"first","tenant":null}"#,
        r#"{"tenant":"chosen","x":1e999}"#,
        r#"{"tenant":"chosen","x":"\uD800"}"#,
        "[0,]",
        "null trailing",
    ] {
        let mut value = embedded.to_owned();
        for _ in 0..5 {
            value = raw_token(&value);
            compare_raw_and_wrapped(&value, None);
            compare_raw_and_wrapped(
                &format!(r#"{{"tenant":"chosen","unknown":[{value}]}}"#),
                None,
            );
        }
    }
}

#[test]
fn config_capacity_957_tenant_projection_preserves_depth_and_string_boundaries() {
    for depth in [1, 2, 32, 64, 125, 126, 127, 128, 129, 130, 132] {
        let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        compare_raw_and_wrapped(
            &format!(r#"{{"tenant":"chosen","unknown":{nested}}}"#),
            None,
        );
        compare_raw_and_wrapped(
            &format!(r#"{{"unknown":{nested},"tenant":"chosen"}}"#),
            None,
        );
    }
    for value in ["", " chosen ", "line\ncontrol", "\u{1D11E}", "\u{0}"] {
        let encoded = serde_json::to_string(value).expect("synthetic tenant string");
        compare_raw_and_wrapped(&format!(r#"{{"tenant":{encoded}}}"#), Some(value));
    }
    for size in [1, 127, 128, 129, 8192, 16384, 65536] {
        let value = "t".repeat(size);
        let encoded = serde_json::to_string(&value).expect("synthetic tenant string");
        compare_raw_and_wrapped(&format!(r#"{{"tenant":{encoded}}}"#), Some(&value));
    }
}
