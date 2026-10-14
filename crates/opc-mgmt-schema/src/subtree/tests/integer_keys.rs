use super::*;

static INTEGER_NODES: &[NodeMeta] = &[
    leaf("/m:i16", LeafType::Int16, DataClass::Public),
    leaf("/m:i32", LeafType::Int32, DataClass::Public),
    leaf("/m:i64", LeafType::Int64, DataClass::Public),
    leaf("/m:i8", LeafType::Int8, DataClass::Public),
    leaf(
        "/m:ref",
        LeafType::LeafRef {
            target_path: "/m:u64",
        },
        DataClass::Public,
    ),
    leaf("/m:u16", LeafType::Uint16, DataClass::Public),
    leaf("/m:u32", LeafType::Uint32, DataClass::Public),
    leaf("/m:u64", LeafType::Uint64, DataClass::Public),
    leaf("/m:u8", LeafType::Uint8, DataClass::Public),
];

struct IntegerRegistry {
    masked: bool,
}

impl SchemaRegistry for IntegerRegistry {
    fn schema_digest(&self) -> &'static str {
        "integer-key-fixture"
    }

    fn served_models(&self) -> &'static [ModelData] {
        Registry.served_models()
    }

    fn origins(&self) -> &'static [OriginEntry] {
        &[]
    }

    fn nodes(&self) -> &'static [NodeMeta] {
        INTEGER_NODES
    }

    fn data_class(&self, path: &str) -> Option<DataClass> {
        self.node(path).map(|_| {
            if self.masked {
                DataClass::SecuritySecret
            } else {
                DataClass::Public
            }
        })
    }
}

#[test]
fn integer_keys_normalize_every_width_and_leafrefs() {
    let registry = IntegerRegistry { masked: false };
    for node in INTEGER_NODES {
        let budget = budget();
        let predicate =
            ScalarPredicate::compile(&registry, node.path, "+007", true, &budget).unwrap();
        assert!(predicate.is_satisfiable(), "{}", node.path);
        assert_eq!(
            predicate.canonical_literal(&budget).unwrap().as_deref(),
            Some("7"),
            "{}",
            node.path
        );
        assert!(predicate.matches("7", &budget).unwrap(), "{}", node.path);
        assert!(!predicate.matches("8", &budget).unwrap(), "{}", node.path);
        assert_eq!(
            canonical_key(&registry, node.path, "+007", &budget)
                .unwrap()
                .as_deref(),
            Some("7"),
            "{}",
            node.path
        );
    }
}

#[test]
fn integer_keys_accept_exact_width_boundaries() {
    let registry = IntegerRegistry { masked: false };
    for (path, literal) in [
        ("/m:i8", "-128"),
        ("/m:i8", "127"),
        ("/m:i16", "-32768"),
        ("/m:i16", "32767"),
        ("/m:i32", "-2147483648"),
        ("/m:i32", "2147483647"),
        ("/m:i64", "-9223372036854775808"),
        ("/m:i64", "9223372036854775807"),
        ("/m:u8", "255"),
        ("/m:u16", "65535"),
        ("/m:u32", "4294967295"),
        ("/m:u64", "18446744073709551615"),
        ("/m:ref", "18446744073709551615"),
    ] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&registry, path, literal, true, &budget).unwrap();
        assert!(predicate.is_satisfiable(), "{path}");
        assert_eq!(
            predicate.canonical_literal(&budget).unwrap().as_deref(),
            Some(literal),
            "{path}"
        );
        assert!(predicate.matches(literal, &budget).unwrap(), "{path}");
    }
}

#[test]
fn integer_keys_reject_overflow_and_unsigned_negative_zero() {
    let registry = IntegerRegistry { masked: false };
    for (path, literal) in [
        ("/m:i8", "-129"),
        ("/m:i8", "128"),
        ("/m:i16", "-32769"),
        ("/m:i16", "32768"),
        ("/m:i32", "-2147483649"),
        ("/m:i32", "2147483648"),
        ("/m:i64", "-9223372036854775809"),
        ("/m:i64", "9223372036854775808"),
        ("/m:u8", "256"),
        ("/m:u16", "65536"),
        ("/m:u32", "4294967296"),
        ("/m:u64", "18446744073709551616"),
        ("/m:ref", "18446744073709551616"),
        ("/m:u8", "-0"),
        ("/m:u16", "-0"),
        ("/m:u32", "-0"),
        ("/m:u64", "-0"),
        ("/m:ref", "-0"),
    ] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&registry, path, literal, true, &budget).unwrap();
        assert!(!predicate.is_satisfiable(), "{path}: {literal}");
        assert_eq!(predicate.canonical_literal(&budget).unwrap(), None);
        assert!(!predicate.matches(literal, &budget).unwrap());
        assert_eq!(
            canonical_key(&registry, path, literal, &budget).unwrap(),
            None
        );
    }
}

#[test]
fn integer_keys_masked_identities_normalize_without_allowing_predicates() {
    let registry = IntegerRegistry { masked: true };
    for node in INTEGER_NODES {
        let budget = budget();
        assert_eq!(
            canonical_key(&registry, node.path, "+007", &budget)
                .unwrap()
                .as_deref(),
            Some("7"),
            "{}",
            node.path
        );
        assert_eq!(
            canonical_key(&registry, node.path, "18446744073709551616", &budget).unwrap(),
            None,
            "{}",
            node.path
        );
        assert_eq!(
            ScalarPredicate::compile(&registry, node.path, "+007", true, &budget),
            Err(SubtreeError::Unsupported)
        );
    }
    assert_eq!(
        canonical_key(&registry, "/m:ref", "18446744073709551615", &budget())
            .unwrap()
            .as_deref(),
        Some("18446744073709551615")
    );
    for path in ["/m:u8", "/m:u16", "/m:u32", "/m:u64", "/m:ref"] {
        assert_eq!(
            canonical_key(&registry, path, "-0", &budget()).unwrap(),
            None
        );
    }
}

#[test]
fn integer_keys_keep_the_reviewed_non_key_comparison_scope() {
    let registry = IntegerRegistry { masked: false };
    for path in ["/m:i8", "/m:i16", "/m:i32", "/m:u8", "/m:u64", "/m:ref"] {
        assert_eq!(
            ScalarPredicate::compile(&registry, path, "7", false, &budget()),
            Err(SubtreeError::Unsupported)
        );
    }
    for path in ["/m:u16", "/m:u32", "/m:i64"] {
        let budget = budget();
        let predicate = ScalarPredicate::compile(&registry, path, "-0", false, &budget).unwrap();
        assert!(predicate.matches("0", &budget).unwrap());
        assert_eq!(
            predicate.canonical_literal(&budget).unwrap().as_deref(),
            Some("0")
        );
    }
}
