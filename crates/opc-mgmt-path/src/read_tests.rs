use super::*;
use opc_mgmt_schema::{DataClass, LeafType, ModelData, OriginEntry};

struct Registry {
    key_type: LeafType,
    class: Option<DataClass>,
}

const fn leaf(path: &'static str) -> NodeMeta {
    NodeMeta {
        path,
        module: "example",
        kind: NodeKind::Leaf,
        config: false,
        leaf_type: Some(LeafType::String),
        key_leaves: &[],
        data_class: DataClass::Public,
        default: None,
        has_default: false,
        presence: false,
        child_paths: &[],
    }
}

static NODES: &[NodeMeta] = &[
    NodeMeta {
        kind: NodeKind::Container,
        leaf_type: None,
        ..leaf("/ex:system")
    },
    NodeMeta {
        leaf_type: Some(LeafType::Boolean),
        ..leaf("/ex:system/ex:enabled")
    },
    NodeMeta {
        kind: NodeKind::List,
        leaf_type: None,
        key_leaves: &["id", "zone"],
        ..leaf("/ex:system/ex:list")
    },
    NodeMeta {
        kind: NodeKind::List,
        leaf_type: None,
        key_leaves: &["name"],
        ..leaf("/ex:system/ex:list/ex:child")
    },
    leaf("/ex:system/ex:list/ex:child/ex:name"),
    leaf("/ex:system/ex:list/ex:child/ex:value"),
    leaf("/ex:system/ex:list/ex:id"),
    leaf("/ex:system/ex:list/ex:value"),
    leaf("/ex:system/ex:list/ex:zone"),
    NodeMeta {
        kind: NodeKind::List,
        leaf_type: None,
        key_leaves: &["token"],
        ..leaf("/ex:system/ex:secret-list")
    },
    leaf("/ex:system/ex:secret-list/ex:token"),
];

impl SchemaRegistry for Registry {
    fn schema_digest(&self) -> &'static str {
        "example"
    }
    fn served_models(&self) -> &'static [ModelData] {
        &[ModelData {
            name: "example",
            revision: "",
            namespace: "urn:example",
            prefix: "ex",
        }]
    }
    fn origins(&self) -> &'static [OriginEntry] {
        &[]
    }
    fn nodes(&self) -> &'static [NodeMeta] {
        NODES
    }
    fn leaf_type(&self, path: &str) -> Option<LeafType> {
        if path == "/ex:system/ex:list/ex:id" {
            Some(self.key_type)
        } else {
            self.node(path).and_then(|node| node.leaf_type)
        }
    }
    fn data_class(&self, path: &str) -> Option<DataClass> {
        if path == "/ex:system/ex:list/ex:id" {
            self.class
        } else {
            self.node(path).map(|node| node.data_class)
        }
    }
}

fn public() -> Registry {
    Registry {
        key_type: LeafType::String,
        class: Some(DataClass::Public),
    }
}

fn request(id: &str) -> RequestPath {
    RequestPath::from_elems([
        PathSegment::new("ex:system"),
        PathSegment::with_keys("ex:list", [("zone", "east"), ("id", id)]),
        PathSegment::new("ex:value"),
    ])
}

#[test]
fn operational_read_selection_accepts_partial_ancestor_keys_without_weakening_writes() {
    let input = RequestPath::from_elems([
        PathSegment::new("ex:system"),
        PathSegment::with_keys("ex:list", [("zone", "east")]),
        PathSegment::with_keys("ex:child", [("name", "a")]),
        PathSegment::new("ex:value"),
    ]);
    assert!(matches!(
        resolve(&public(), &input),
        Err(PathError::MissingKeys { .. })
    ));
    let selected = resolve_read(&public(), &input).unwrap().unwrap();
    assert_eq!(
        selected.canonical.as_str(),
        "/ex:system/ex:list[ex:zone='east']/ex:child[ex:name='a']/ex:value"
    );
}

#[test]
fn operational_requested_integer_keys_are_canonicalized() {
    for key_type in [LeafType::Uint16, LeafType::Uint32, LeafType::Int64] {
        let registry = Registry {
            key_type,
            ..public()
        };
        assert_eq!(
            resolve_read(&registry, &request("+001"))
                .unwrap()
                .unwrap()
                .canonical
                .as_str(),
            "/ex:system/ex:list[ex:id='1'][ex:zone='east']/ex:value"
        );
        assert!(resolve_read(&registry, &request("not-an-integer"))
            .unwrap()
            .is_none());
    }
}

fn assert_integer_key_width(key_type: LeafType, minimum: &str, maximum: &str) {
    let registry = Registry {
        key_type,
        ..public()
    };
    let instance = |value: &str| {
        YangPath::new(format!(
            "/ex:system/ex:list[ex:id='{value}'][ex:zone='east']/ex:value"
        ))
        .unwrap()
    };
    for value in [minimum, maximum, "0", "1"] {
        assert_eq!(
            resolve_read(&registry, &request(value))
                .unwrap()
                .unwrap()
                .canonical,
            instance(value)
        );
        assert_eq!(
            resolve_instance(&registry, &instance(value))
                .unwrap()
                .canonical,
            instance(value)
        );
    }
    for value in ["+001", "001"] {
        assert_eq!(
            resolve_read(&registry, &request(value))
                .unwrap()
                .unwrap()
                .canonical,
            instance("1")
        );
        assert_eq!(
            resolve_instance(&registry, &instance(value))
                .unwrap_err()
                .to_string(),
            "malformed path: non-canonical instance path"
        );
    }
    for value in [
        (minimum.parse::<i128>().unwrap() - 1).to_string(),
        (maximum.parse::<i128>().unwrap() + 1).to_string(),
        "not-an-integer".to_string(),
    ] {
        assert!(resolve_read(&registry, &request(&value)).unwrap().is_none());
        assert_eq!(
            resolve_instance(&registry, &instance(&value))
                .unwrap_err()
                .to_string(),
            "malformed path: invalid canonical key"
        );
    }
}

#[test]
fn operational_uint8_keys_follow_declared_width() {
    assert_integer_key_width(LeafType::Uint8, "0", "255");
}

#[test]
fn operational_uint64_keys_follow_declared_width() {
    assert_integer_key_width(LeafType::Uint64, "0", "18446744073709551615");
}

#[test]
fn operational_int8_keys_follow_declared_width() {
    assert_integer_key_width(LeafType::Int8, "-128", "127");
}

#[test]
fn operational_int16_keys_follow_declared_width() {
    assert_integer_key_width(LeafType::Int16, "-32768", "32767");
}

#[test]
fn operational_int32_keys_follow_declared_width() {
    assert_integer_key_width(LeafType::Int32, "-2147483648", "2147483647");
}

#[test]
fn operational_requested_boolean_keys_use_the_leafref_target_type() {
    for key_type in [
        LeafType::Boolean,
        LeafType::LeafRef {
            target_path: "/ex:system/ex:enabled",
        },
    ] {
        let registry = Registry {
            key_type,
            ..public()
        };
        assert_eq!(
            resolve_read(&registry, &request("true"))
                .unwrap()
                .unwrap()
                .canonical
                .as_str(),
            "/ex:system/ex:list[ex:id='true'][ex:zone='east']/ex:value"
        );
        assert!(resolve_read(&registry, &request("TRUE")).unwrap().is_none());
        assert!(resolve_read(&registry, &request("1")).unwrap().is_none());
    }
}

#[test]
fn operational_read_builder_preserves_xpath_literals() {
    for (raw, literal) in [
        (r"a\b", r"'a\b'"),
        (r"end\", r"'end\'"),
        ("it's", "\"it's\""),
        ("a]/=雪", "'a]/=雪'"),
    ] {
        let selected = resolve_read(&public(), &request(raw)).unwrap().unwrap();
        let expected = format!("/ex:system/ex:list[ex:id={literal}][ex:zone='east']/ex:value");
        assert_eq!(selected.canonical.as_str(), expected);
        assert_eq!(
            CanonicalPath::parse(&expected).unwrap().segments()[1].keys[0].1,
            raw
        );
        assert_eq!(
            resolve_instance(&public(), &selected.canonical)
                .unwrap()
                .canonical,
            selected.canonical
        );
    }
    assert!(resolve_read(&public(), &request("both'\"quotes")).is_err());
}

#[test]
fn operational_instances_require_complete_declared_keys() {
    for input in [
        "/ex:system/ex:list[ex:id='a']/ex:value",
        "/ex:system/ex:list[ex:id='a'][ex:zone='east'][ex:unknown='x']/ex:value",
        "/ex:system[ex:id='a']/ex:list[ex:id='a'][ex:zone='east']/ex:value",
        "/example:system/ex:list[ex:id='a'][ex:zone='east']/ex:value",
        "/ex:system/ex:list[ex:zone='east'][ex:id='a']/ex:value",
        "/ex:system/ex:list[ex:id=\"a\"][ex:zone='east']/ex:value",
        "/ex:system/ex:list[ex:id='a'][ex:zone='east']/ex:child/ex:value",
    ] {
        assert!(
            resolve_instance(&public(), &YangPath::new(input).unwrap()).is_err(),
            "{input}"
        );
    }
}

#[test]
fn operational_reported_integer_and_boolean_keys_must_already_be_canonical() {
    for (key_type, input) in [
        (LeafType::Uint32, "01"),
        (LeafType::Int64, "+1"),
        (LeafType::Boolean, "TRUE"),
        (
            LeafType::LeafRef {
                target_path: "/ex:system/ex:enabled",
            },
            "1",
        ),
    ] {
        let registry = Registry {
            key_type,
            ..public()
        };
        let input = YangPath::new(format!(
            "/ex:system/ex:list[ex:id='{input}'][ex:zone='east']/ex:value"
        ))
        .unwrap();
        assert!(resolve_instance(&registry, &input).is_err());
    }
}

#[test]
fn operational_masked_key_match_is_refused_before_access() {
    for class in [
        Some(DataClass::SecuritySecret),
        Some(DataClass::LawfulIntercept),
        None,
    ] {
        let registry = Registry { class, ..public() };
        for guess in ["correct-marker", "incorrect-marker"] {
            let error = resolve_read(&registry, &request(guess)).unwrap_err();
            assert_eq!(error.to_string(), "masked key match is not supported");
            assert!(!format!("{error:?}").contains(guess));
        }
        let input = RequestPath::from_elems([
            PathSegment::new("ex:system"),
            PathSegment::new("ex:list"),
            PathSegment::new("ex:value"),
        ]);
        assert!(resolve_read(&registry, &input).unwrap().is_some());
    }
    let secret_name = RequestPath::from_elems([
        PathSegment::new("ex:system"),
        PathSegment::with_keys("ex:secret-list", [("token", "marker")]),
    ]);
    assert_eq!(
        resolve_read(&public(), &secret_name)
            .unwrap_err()
            .to_string(),
        "masked key match is not supported"
    );
}

#[test]
fn operational_path_debug_omits_request_keys() {
    let input = request("identity-marker");
    let resolved = resolve(&public(), &input).unwrap();
    for diagnostic in [
        format!("{input:?}"),
        format!("{resolved:?}"),
        format!("{:?}", input.elems[1]),
    ] {
        assert!(!diagnostic.contains("identity-marker"));
    }
}

#[test]
fn operational_key_classification_uses_leaf_name_not_module_prefix() {
    struct SecretPrefix;
    impl SchemaRegistry for SecretPrefix {
        fn schema_digest(&self) -> &'static str {
            "public-key"
        }
        fn served_models(&self) -> &'static [ModelData] {
            &[ModelData {
                name: "example",
                revision: "",
                namespace: "urn:example",
                prefix: "secret",
            }]
        }
        fn origins(&self) -> &'static [OriginEntry] {
            &[]
        }
        fn nodes(&self) -> &'static [NodeMeta] {
            static NODES: &[NodeMeta] = &[
                NodeMeta {
                    kind: NodeKind::List,
                    leaf_type: None,
                    key_leaves: &["id"],
                    child_paths: &["/secret:list/secret:id"],
                    ..leaf("/secret:list")
                },
                leaf("/secret:list/secret:id"),
            ];
            NODES
        }
    }
    let input = RequestPath::from_elems([
        PathSegment::with_keys("secret:list", [("id", "public-marker")]),
        PathSegment::new("secret:id"),
    ]);
    assert_eq!(
        resolve_read(&SecretPrefix, &input)
            .unwrap()
            .unwrap()
            .canonical
            .as_str(),
        "/secret:list[secret:id='public-marker']/secret:id"
    );
}
