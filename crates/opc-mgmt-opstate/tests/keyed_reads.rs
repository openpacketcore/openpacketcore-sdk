use opc_config_model::YangPath;
use opc_mgmt_opstate::{
    OperationalError, OperationalEvent, OperationalEventError, OperationalRequest,
    OperationalResponse, OperationalResponseError, OperationalSubscriptionRequest,
    OperationalValue, Origin,
};

fn path(value: &str) -> YangPath {
    YangPath::new(value).unwrap()
}

fn value(value: &str) -> OperationalValue {
    OperationalValue::new(path(value), "true").unwrap()
}

const CONCRETE: &str =
    "/ex:system/ex:site[ex:region='east'][ex:id='7']/ex:peer[ex:name='a'][ex:slot='2']/ex:up";

#[test]
fn operational_response_count_limit_precedes_instance_validation() {
    let request = OperationalRequest::new([path("/ex:list/ex:value")]);
    let mut values = (0..1024)
        .map(|index| value(&format!("/ex:list[ex:key='{index}']/ex:value")))
        .collect::<Vec<_>>();
    assert_eq!(
        OperationalResponse::new(values.clone()).validate_for_request(&request),
        Ok(())
    );
    values.push(value("/ex:list[ex:key='overflow']/ex:value"));
    let error = OperationalResponse::new(values)
        .validate_for_request(&request)
        .unwrap_err();
    assert_eq!(error.to_string(), "operational response limit exceeded");
}

#[test]
fn operational_response_path_limit_precedes_instance_validation() {
    let prefix = "/ex:list[ex:key='";
    let suffix = "']/ex:value";
    let at_limit = format!(
        "{prefix}{}{suffix}",
        "x".repeat(1024 * 1024 - prefix.len() - suffix.len())
    );
    let request = OperationalRequest::new([path("/ex:list/ex:value")]);
    assert_eq!(
        OperationalResponse::new([value(&at_limit)]).validate_for_request(&request),
        Ok(())
    );
    let oversized = at_limit.replacen("[ex:key='", "[ex:key='x", 1);
    let error = OperationalResponse::new([value(&oversized)])
        .validate_for_request(&request)
        .unwrap_err();
    assert_eq!(error.to_string(), "operational response limit exceeded");
    let invalid_then_oversized =
        OperationalResponse::new([value("/ex:unsolicited"), value(&oversized)]);
    assert_eq!(
        invalid_then_oversized
            .validate_for_request(&request)
            .unwrap_err()
            .to_string(),
        "operational response limit exceeded"
    );
}

#[test]
fn operational_response_payload_limit_precedes_instance_validation() {
    let request = OperationalRequest::new([path("/ex:list/ex:value")]);
    let json = format!("\"{}\"", "x".repeat(1024 * 1024 - 2));
    let at_limit = OperationalValue::new(path("/ex:list[ex:key='a']/ex:value"), &json).unwrap();
    assert_eq!(
        OperationalResponse::new([at_limit]).validate_for_request(&request),
        Ok(())
    );
    let oversized = OperationalValue::new(
        path("/ex:list[ex:key='a']/ex:value"),
        format!("\"x{}\"", "x".repeat(1024 * 1024 - 2)),
    )
    .unwrap();
    let error = OperationalResponse::new([oversized.clone()])
        .validate_for_request(&request)
        .unwrap_err();
    assert_eq!(error.to_string(), "operational response limit exceeded");
    assert_eq!(
        OperationalResponse::new([value("/ex:unsolicited"), oversized])
            .validate_for_request(&request)
            .unwrap_err()
            .to_string(),
        "operational response limit exceeded"
    );
}

#[test]
fn operational_response_matches_key_subsets() {
    for selector in [
        "/ex:system/ex:site/ex:peer/ex:up",
        "/ex:system/ex:site[ex:region='east']/ex:peer[ex:slot='2']/ex:up",
        CONCRETE,
    ] {
        let response = OperationalResponse::new([value(CONCRETE)]);
        assert_eq!(
            response.validate_for_request(&OperationalRequest::new([path(selector)])),
            Ok(())
        );
        assert_eq!(
            response.value_for(&path(CONCRETE)).unwrap().value_json(),
            "true"
        );
    }
    let broad = path("/ex:system/ex:site/ex:peer/ex:up");
    let response = OperationalResponse::new([value(CONCRETE)]);
    assert!(response.value_for(&broad).is_none());
    assert_eq!(
        response.validate_for_request(&OperationalRequest::new([broad, path(CONCRETE)])),
        Ok(())
    );
    assert_eq!(
        OperationalResponse::default()
            .validate_for_request(&OperationalRequest::new([path(CONCRETE)])),
        Ok(())
    );
}

#[test]
fn operational_response_rejects_invalid_members_atomically() {
    let request = OperationalRequest::new([path(CONCRETE)]);
    for invalid in [
        CONCRETE.replace("'east'", "'west'"),
        CONCRETE.replace("ex:up", "other:up"),
        CONCRETE.replace("ex:up", "ex:down"),
        format!("{CONCRETE}/ex:child"),
        CONCRETE.replace("[ex:region='east']", ""),
    ] {
        let response = OperationalResponse::new([value(CONCRETE), value(&invalid)]);
        assert_eq!(
            response.validate_for_request(&request),
            Err(OperationalResponseError::UnexpectedPath)
        );
    }
}

#[test]
fn operational_response_rejects_malformed_identical_paths() {
    for invalid in [
        "/ex:list[ex:key='a'][ex:key='a']/ex:value",
        "/ex:list[ex:key='a']/ex:bad name",
        "/ex:list[ex:key=a]/ex:value",
        "/ex:list[ex:key='a']junk/ex:value",
        "/ex:list[ex:key='a']/",
        "/ex:list//ex:value",
        "/ex:list[ex:key='a]/ex:value",
    ] {
        // Exact equality must not bypass syntax validation.
        let request = OperationalRequest::new([path(invalid)]);
        assert_eq!(
            OperationalResponse::new([value(invalid)]).validate_for_request(&request),
            Err(OperationalResponseError::UnexpectedPath)
        );
    }
}

#[test]
fn operational_events_reject_duplicate_predicates() {
    let event = OperationalEvent::Delete {
        path: path("/ex:list[ex:key='a'][ex:key='a']/ex:value"),
    };
    let request = OperationalSubscriptionRequest::new([path("/ex:list/ex:value")]);
    assert_eq!(
        event.validate_for_request(&request),
        Err(OperationalEventError::UnexpectedPath)
    );
}

#[test]
fn operational_events_reject_invalid_qualified_names() {
    let invalid = "/ex:list[ex:key='a']/ex:bad name";
    let event = OperationalEvent::Delete {
        path: path(invalid),
    };
    assert_eq!(
        event.validate_for_request(&OperationalSubscriptionRequest::new([path(invalid)])),
        Err(OperationalEventError::UnexpectedPath)
    );
}

#[test]
fn operational_response_rejects_duplicate_values_after_expansion() {
    let request = OperationalRequest::new([path("/ex:system/ex:site/ex:peer/ex:up")]);
    assert_eq!(
        OperationalResponse::new([value(CONCRETE), value(CONCRETE)]).validate_for_request(&request),
        Err(OperationalResponseError::DuplicatePath)
    );
}

#[test]
fn operational_response_rejects_unsolicited_origin_after_expansion() {
    let request = OperationalRequest::new([path("/ex:system/ex:site/ex:peer/ex:up")]);
    let response = OperationalResponse::new([value(CONCRETE).with_origin(Some(Origin::Dynamic))]);
    assert_eq!(
        response.validate_for_request(&request),
        Err(OperationalResponseError::UnexpectedOrigin)
    );
    assert_eq!(
        response.validate_for_request(&request.with_origin()),
        Ok(())
    );
}

#[test]
fn operational_canonical_asterisk_is_literal() {
    let selector = "/ex:list[ex:key='*']/ex:value";
    let request = OperationalRequest::new([path(selector)]);
    assert_eq!(
        OperationalResponse::new([value(selector)]).validate_for_request(&request),
        Ok(())
    );
    assert_eq!(
        OperationalResponse::new([value("/ex:list[ex:key='a']/ex:value")])
            .validate_for_request(&request),
        Err(OperationalResponseError::UnexpectedPath)
    );
}

#[test]
fn operational_paths_round_trip_canonical_literals() {
    for literal in [
        r"'a\b'",
        r"'trailing\'",
        r#""apostrophe's""#,
        "'a]/=雪'",
        "''",
    ] {
        let concrete = format!("/ex:list[ex:key={literal}]/ex:value");
        let event = OperationalEvent::Delete {
            path: path(&concrete),
        };
        assert_eq!(
            event.validate_for_request(&OperationalSubscriptionRequest::new([path(&concrete)])),
            Ok(())
        );
        assert_eq!(
            OperationalResponse::new([value(&concrete)])
                .validate_for_request(&OperationalRequest::new([path("/ex:list/ex:value")])),
            Ok(())
        );
    }
}

#[test]
fn operational_backslashes_do_not_alias_another_identity() {
    let event = OperationalEvent::Delete {
        path: path(r"/ex:list[ex:key='a\b']/ex:value"),
    };
    assert_eq!(
        event.validate_for_request(&OperationalSubscriptionRequest::new([path(
            "/ex:list[ex:key='ab']/ex:value"
        )])),
        Err(OperationalEventError::UnexpectedPath)
    );
}

#[test]
fn operational_expansion_preserves_sensitive_encoding_and_debug() {
    let marked = path("/ex:list[ex:key='identity-marker']/ex:value");
    let payload = OperationalValue::new(marked.clone(), r#""payload-marker""#).unwrap();
    let diagnostics = [
        format!("{:?}", OperationalRequest::new([marked.clone()])),
        format!(
            "{:?}",
            OperationalSubscriptionRequest::new([marked.clone()])
        ),
        format!("{payload:?}"),
        format!("{:?}", OperationalResponse::new([payload.clone()])),
        format!("{:?}", OperationalEvent::Update(payload)),
        format!("{:?}", OperationalEvent::Delete { path: marked }),
        format!(
            "{:?}",
            OperationalError::internal("identity-marker payload-marker")
        ),
    ];
    for diagnostic in diagnostics {
        assert!(!diagnostic.contains("identity-marker"));
        assert!(!diagnostic.contains("payload-marker"));
    }
}
