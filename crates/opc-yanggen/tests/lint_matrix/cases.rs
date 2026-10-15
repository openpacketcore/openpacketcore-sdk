use opc_yanggen::{
    generation_input_from_yang_sources, CanonicalInput, CompareOp, ConstraintBinding,
    ConstraintExpr, Literal, PathAnchor, PathExpr, SchemaNodeKind, TypeRef, YangSource,
};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Legacy,
    Expanded,
    State,
}

impl Profile {
    pub const ALL: [Self; 3] = [Self::Legacy, Self::Expanded, Self::State];

    pub fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Expanded => "expanded",
            Self::State => "state",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    U32,
    U64,
    String,
    SensitiveU32,
    SensitiveString,
    Composite,
}

impl Key {
    pub const ALL: [Self; 6] = [
        Self::U32,
        Self::U64,
        Self::String,
        Self::SensitiveU32,
        Self::SensitiveString,
        Self::Composite,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::String => "string",
            Self::SensitiveU32 => "sensitive_u32",
            Self::SensitiveString => "sensitive_string",
            Self::Composite => "composite",
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Self::U32 => "key id; leaf id { type uint32; }",
            Self::U64 => "key id; leaf id { type uint64; }",
            Self::String => "key id; leaf id { type string; }",
            Self::SensitiveU32 => "key secret-id; leaf secret-id { type uint32; }",
            Self::SensitiveString => "key secret-id; leaf secret-id { type string; }",
            Self::Composite => {
                "key 'region name'; leaf region { type uint32; } leaf name { type string; }"
            }
        }
    }

    fn rows(self) -> Value {
        match self {
            Self::U32 => json!([
                {"id": u32::MAX - 1, "count": 7}, {"id": u32::MAX, "count": 9}
            ]),
            Self::U64 => json!([
                {"id": "9223372036854775808", "count": 7},
                {"id": "18446744073709551615", "count": 9}
            ]),
            Self::String => json!([{"id": "a", "count": 7}, {"id": "z", "count": 9}]),
            Self::SensitiveU32 => json!([
                {"secret-id": u32::MAX - 1, "count": 7},
                {"secret-id": u32::MAX, "count": 9}
            ]),
            Self::SensitiveString => json!([
                {"secret-id": "a", "count": 7}, {"secret-id": "z", "count": 9}
            ]),
            Self::Composite => json!([
                {"region": 1, "name": "a", "count": 7},
                {"region": 1, "name": "z", "count": 9}
            ]),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ordering {
    System,
    User,
    NestedSystem,
    NestedUser,
}

impl Ordering {
    const ALL: [Self; 4] = [
        Self::System,
        Self::User,
        Self::NestedSystem,
        Self::NestedUser,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::NestedSystem => "nested_system",
            Self::NestedUser => "nested_user",
        }
    }

    fn nested(self) -> bool {
        matches!(self, Self::NestedSystem | Self::NestedUser)
    }
}

pub struct Case {
    pub name: String,
    profile: Profile,
    key: Key,
    config: bool,
    ordering: Ordering,
    unique: bool,
    constraint: Option<&'static str>,
}

pub fn matrix(profile: Profile, key: Key) -> Vec<Case> {
    let mut cases = Vec::new();
    for config in [true, false] {
        for ordering in Ordering::ALL {
            for unique in [false, true] {
                cases.push(Case {
                    name: format!(
                        "{}_{}_{}_{}_{}",
                        profile.name(),
                        key.name(),
                        if config { "config" } else { "state" },
                        ordering.name(),
                        if unique { "unique" } else { "plain" },
                    ),
                    profile,
                    key,
                    config,
                    ordering,
                    unique,
                    constraint: None,
                });
            }
        }
    }
    cases
}

pub fn canonical_constraints(profile: Profile) -> Vec<Case> {
    ["must", "when"]
        .into_iter()
        .map(|kind| Case {
            name: format!("{}_canonical_{kind}", profile.name()),
            profile,
            key: Key::String,
            config: true,
            ordering: Ordering::NestedSystem,
            unique: false,
            constraint: Some(kind),
        })
        .collect()
}

impl Case {
    pub fn schema(&self) -> String {
        let row = format!(
            "list row {{ config {}; ordered-by {}; {} {} leaf count {{ type uint32; }} }}",
            self.config,
            if self.ordering == Ordering::User {
                "user"
            } else {
                "system"
            },
            self.key.schema(),
            if self.unique { "unique count;" } else { "" },
        );
        let lists = if self.ordering.nested() {
            format!(
                "list parent {{ key name; ordered-by {}; leaf name {{ type string; }} {row} }}",
                if self.ordering == Ordering::NestedUser {
                    "user"
                } else {
                    "system"
                },
            )
        } else {
            row
        };
        // A config-only expanded case deliberately has no state anchor. A state
        // row necessarily also enables the state profile; uint64 enables both.
        let anchor = match self.profile {
            Profile::Legacy => "",
            Profile::Expanded => "leaf marker { type uint8; }",
            Profile::State => {
                "container telemetry { config false; list sample { key name; leaf name { type string; } } }"
            }
        };
        format!(
            "module key-matrix {{ yang-version 1.1; namespace 'urn:example:key-matrix'; prefix m;
             container root {{ {anchor} {lists} }} }}"
        )
    }

    pub fn input(&self) -> CanonicalInput {
        let mut input = generation_input_from_yang_sources(
            &self.name,
            &[YangSource::new(
                format!("{}.yang", self.name),
                self.schema(),
            )],
        )
        .unwrap()
        .to_canonical();
        if let Some(kind) = self.constraint {
            input.constraints.push(ConstraintBinding {
                target_path: "/m:root/m:parent/m:row/m:count".into(),
                kind: Some(kind.into()),
                expr: ConstraintExpr::Compare {
                    op: CompareOp::Gte,
                    left: Box::new(ConstraintExpr::Path(PathExpr {
                        anchor: PathAnchor::Parent,
                        segments: vec!["count".into()],
                    })),
                    right: Box::new(ConstraintExpr::Literal(Literal::Number(1))),
                },
                ..Default::default()
            });
        }
        input
    }

    pub fn coverage(&self, input: &CanonicalInput) -> Value {
        let has_state = input.nodes.iter().any(|node| {
            !node.config && node.kind == SchemaNodeKind::List && !node.key_leaves.is_empty()
        });
        let expanded = input
            .nodes
            .iter()
            .any(|node| matches!(node.type_ref, Some(TypeRef::Uint8 | TypeRef::Uint64)));
        assert_eq!(has_state, self.profile == Profile::State || !self.config);
        assert_eq!(
            expanded,
            self.profile == Profile::Expanded || self.key == Key::U64
        );
        json!({
            "case": self.name, "requested_profile": self.profile.name(),
            "expanded_profile": expanded, "state_list_profile": has_state,
            "key": self.key.name(), "config": self.config,
            "ordering": self.ordering.name(), "unique": self.unique,
            "effective_row_ordering": if self.config && self.ordering == Ordering::User {
                "user"
            } else { "system" },
            "canonical_constraint": self.constraint,
        })
    }

    pub fn runtime_test(&self) -> String {
        if let Some(kind) = self.constraint {
            let error = if kind == "must" {
                "Constraint failed: ../count >= 1"
            } else {
                "Field must be absent when condition is unsatisfied: ../count >= 1"
            };
            return format!(
                r#"#[test]
fn {name}() {{
    use crate::{name}::types::Root;
    for (count, expected) in [(None, Ok(())), (Some(1_u32), Ok(())),
        (Some(0_u32), Err(ValidationError::semantics({error:?})))] {{
        let mut second = json!({{"id": "b"}});
        if let Some(count) = count {{ second["count"] = json!(count); }}
        let root: Root = serde_json::from_value(json!({{"parent": [
            {{"name": "one", "row": [{{"id": "a", "count": 1}}]}},
            {{"name": "two", "row": [second]}}
        ]}})).unwrap();
        assert_eq!(root.validate_semantics(&context()), expected);
    }}
}}
"#,
                name = self.name,
            );
        }
        let rows = self.key.rows().to_string();
        let wrap = if self.ordering.nested() {
            "json!({\"parent\": [{\"name\": \"parent\", \"row\": rows}]})"
        } else {
            "json!({\"row\": rows})"
        };
        let access = if self.ordering.nested() {
            "valid.parent.values().next().unwrap().row"
        } else {
            "valid.row"
        };
        let unique_expected = if self.unique {
            "Err(ValidationError::semantics(\"duplicate entry found in list unique constraint\"))"
        } else {
            "Ok(())"
        };
        let patch_test = if self.config && self.ordering == Ordering::NestedUser {
            format!(
                r#"
    use crate::{name}::patch::{{apply_patch, ConfigDelta}};
    let path = opc_config_model::YangPath::new("/m:root/m:parent[name='parent']/m:row").unwrap();
    let mut patched = root(serde_json::from_str({rows:?}).unwrap());
    patched.parent.values_mut().next().unwrap().row.clear();
    apply_patch(&mut patched, &[ConfigDelta::Merge(path.clone(), {rows:?}.into())]).unwrap();
    assert_eq!(patched, valid);
    let before = patched.clone();
    let mut duplicate_keys: Vec<serde_json::Value> = serde_json::from_str({rows:?}).unwrap();
    duplicate_keys[1] = duplicate_keys[0].clone();
    assert_eq!(apply_patch(&mut patched, &[ConfigDelta::Merge(path,
        serde_json::to_string(&duplicate_keys).unwrap())]),
        Err(opc_config_model::ConfigError::new("invalid-value", "invalid keyed list")));
    assert_eq!(patched, before);
"#,
                name = self.name,
            )
        } else {
            String::new()
        };
        format!(
            r#"#[test]
fn {name}() {{
    use crate::{name}::types::Root;
    fn root(rows: serde_json::Value) -> Root {{ serde_json::from_value({wrap}).unwrap() }}
    let rows: serde_json::Value = serde_json::from_str({rows:?}).unwrap();
    let valid = root(rows.clone());
    let mut observed: Vec<_> = {access}.values().map(|row| serde_json::to_value(row).unwrap()).collect();
    let mut expected = rows.as_array().unwrap().clone();
    observed.sort_by_key(|row| row.to_string());
    expected.sort_by_key(|row| row.to_string());
    assert_eq!(observed, expected, "keys and values survive extraction");
    let roundtrip: Root = serde_json::from_value(serde_json::to_value(&valid).unwrap()).unwrap();
    assert_eq!(roundtrip, valid);
    valid.validate_semantics(&context()).unwrap();
    let mut duplicate_values = rows.clone();
    duplicate_values[1]["count"] = json!(7);
    assert_eq!(root(duplicate_values).validate_semantics(&context()), {unique_expected});
    let mut absent = rows;
    for row in absent.as_array_mut().unwrap() {{ row.as_object_mut().unwrap().remove("count"); }}
    root(absent).validate_semantics(&context()).unwrap();
    {patch_test}
}}
"#,
            name = self.name,
        )
    }
}
