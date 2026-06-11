use opc_nacm::{
    ModuleRegistry, NacmAction, NacmEffect, NacmEvaluator, NacmPolicy, NacmRule, PolicyVersion,
    YangPath, YangPathPattern,
};
use std::str::FromStr;

fn registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry
        .register_module("ietf-interfaces", "if")
        .expect("register interface module");
    registry
        .register_module("ietf-system", "sys")
        .expect("register system module");
    registry
}

#[test]
fn normalizes_paths_to_canonical_module_names() {
    let registry = registry();
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");

    assert_eq!(
        path.to_string(),
        "/ietf-interfaces:interfaces/ietf-interfaces:interface/ietf-interfaces:config/ietf-interfaces:name"
    );
    assert_eq!(path.segments()[0].module(), "ietf-interfaces");
    assert_eq!(path.segments()[3].name(), "name");
}

#[test]
fn rejects_ambiguous_module_prefixes() {
    let mut registry = registry();
    registry
        .register_module("openconfig-interfaces", "if")
        .expect("add conflicting prefix");

    let err = YangPath::parse("/if:interfaces/interface", &registry).expect_err("ambiguous path");
    assert_eq!(err.kind(), "yang path");
    assert!(err.message().contains("ambiguous module prefix 'if'"));
}

#[test]
fn rejects_invalid_yang_identifier_shapes() {
    let registry = registry();

    let digit_led = YangPath::parse("/if:interfaces/9bad", &registry)
        .expect_err("digit-led node name must be rejected");
    assert!(digit_led
        .message()
        .contains("node name must start with an ASCII letter or '_'"));

    let dot_led = YangPath::parse("/if:interfaces/.bad", &registry)
        .expect_err("dot-led node name must be rejected");
    assert!(dot_led
        .message()
        .contains("node name must start with an ASCII letter or '_'"));
}

#[test]
fn allows_trailing_hyphen_identifiers() {
    let mut registry = ModuleRegistry::new();
    registry
        .register_module("ietf-interfaces-", "if-")
        .expect("trailing hyphen module and prefix");

    let path = YangPath::parse("/if-:interfaces-/if-:leaf-", &registry)
        .expect("trailing hyphen path should parse");
    assert_eq!(
        path.to_string(),
        "/ietf-interfaces-:interfaces-/ietf-interfaces-:leaf-"
    );
}

#[test]
fn defaults_to_deny_when_no_rule_matches() {
    let registry = registry();
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");
    let policy = NacmPolicy::builder(PolicyVersion::new(11)).build();
    let mut evaluator = NacmEvaluator::new();

    let decision = evaluator.evaluate(&policy, &path, NacmAction::Read);
    assert_eq!(decision.effect(), NacmEffect::Deny);
    assert!(!decision.is_allowed());
    assert_eq!(decision.matched_rule_index(), None);
    assert_eq!(decision.policy_version(), PolicyVersion::new(11));
}

#[test]
fn separates_actions_for_the_same_normalized_path() {
    let registry = registry();
    let path = YangPath::parse("/if:interfaces/interface", &registry).expect("normalize path");
    let pattern =
        YangPathPattern::parse("/if:interfaces/interface", &registry).expect("normalize rule");

    let policy = NacmPolicy::builder(PolicyVersion::new(7))
        .add_rule(NacmRule::allow(NacmAction::Read, pattern.clone()))
        .add_rule(NacmRule::allow(NacmAction::Create, pattern.clone()))
        .add_rule(NacmRule::allow(NacmAction::Delete, pattern.clone()))
        .add_rule(NacmRule::allow(NacmAction::Exec, pattern.clone()))
        .add_rule(NacmRule::allow(NacmAction::Subscribe, pattern.clone()))
        .add_rule(NacmRule::allow(NacmAction::SecurityAdmin, pattern))
        .build();

    let mut evaluator = NacmEvaluator::new();

    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::Read)
        .is_allowed());
    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::Create)
        .is_allowed());
    assert!(!evaluator
        .evaluate(&policy, &path, NacmAction::Update)
        .is_allowed());
    assert!(!evaluator
        .evaluate(&policy, &path, NacmAction::Replace)
        .is_allowed());
    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::Delete)
        .is_allowed());
    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::Exec)
        .is_allowed());
    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::Subscribe)
        .is_allowed());
    assert!(evaluator
        .evaluate(&policy, &path, NacmAction::SecurityAdmin)
        .is_allowed());
}

#[test]
fn wildcard_and_subtree_patterns_match_descendants_but_not_siblings() {
    let registry = registry();
    let subtree_rule = YangPathPattern::parse("/if:interfaces/*/config/**", &registry)
        .expect("normalize subtree rule");
    let exact_rule = YangPathPattern::parse("/if:interfaces/*/config", &registry)
        .expect("normalize exact wildcard rule");

    let descendant = YangPath::parse("/if:interfaces/interface/config/name", &registry)
        .expect("descendant path");
    let exact = YangPath::parse("/if:interfaces/interface/config", &registry).expect("exact path");
    let sibling = YangPath::parse("/if:interfaces/interface/state", &registry).expect("sibling");

    assert!(subtree_rule.matches(&descendant));
    assert!(subtree_rule.matches(&exact));
    assert!(exact_rule.matches(&exact));
    assert!(!exact_rule.matches(&descendant));
    assert!(!subtree_rule.matches(&sibling));
}

#[test]
fn rule_order_is_first_match_not_most_specific_match() {
    let registry = registry();
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");

    let policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/if:interfaces/*/**", &registry).expect("earlier broad rule"),
        ))
        .add_rule(NacmRule::deny(
            NacmAction::Read,
            YangPathPattern::parse("/if:interfaces/interface/config/name", &registry)
                .expect("later exact rule"),
        ))
        .build();

    let mut evaluator = NacmEvaluator::new();
    let decision = evaluator.evaluate(&policy, &path, NacmAction::Read);
    assert!(decision.is_allowed());
    assert_eq!(decision.matched_rule_index(), Some(0));
}

#[test]
fn cache_is_invalidated_when_policy_version_changes() {
    let registry = registry();
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");
    let allow_pattern =
        YangPathPattern::parse("/if:interfaces/interface/config/**", &registry).expect("pattern");

    let allow_policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Read, allow_pattern))
        .build();
    let deny_policy = NacmPolicy::builder(PolicyVersion::new(2)).build();

    let mut evaluator = NacmEvaluator::new();

    let warm = evaluator.evaluate(&allow_policy, &path, NacmAction::Read);
    assert!(warm.is_allowed());
    assert!(!warm.cache_hit());
    assert_eq!(evaluator.cached_entries(), 1);
    assert_eq!(
        evaluator.cached_policy_version(),
        Some(PolicyVersion::new(1))
    );

    let cached = evaluator.evaluate(&allow_policy, &path, NacmAction::Read);
    assert!(cached.is_allowed());
    assert!(cached.cache_hit());
    assert_eq!(evaluator.cached_entries(), 1);

    let invalidated = evaluator.evaluate(&deny_policy, &path, NacmAction::Read);
    assert!(!invalidated.is_allowed());
    assert!(!invalidated.cache_hit());
    assert_eq!(invalidated.policy_version(), PolicyVersion::new(2));
    assert_eq!(
        evaluator.cached_policy_version(),
        Some(PolicyVersion::new(2))
    );
    assert_eq!(evaluator.cached_entries(), 1);
}

#[test]
fn cache_is_invalidated_when_policy_identity_changes_at_same_version() {
    let registry = registry();
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");
    let allow_pattern =
        YangPathPattern::parse("/if:interfaces/interface/config/**", &registry).expect("pattern");

    let allow_policy = NacmPolicy::builder(PolicyVersion::new(1))
        .add_rule(NacmRule::allow(NacmAction::Read, allow_pattern))
        .build();
    let deny_policy = NacmPolicy::empty(PolicyVersion::new(1));

    let mut evaluator = NacmEvaluator::new();

    let warm = evaluator.evaluate(&allow_policy, &path, NacmAction::Read);
    assert!(warm.is_allowed());
    assert!(!warm.cache_hit());

    let invalidated = evaluator.evaluate(&deny_policy, &path, NacmAction::Read);
    assert!(!invalidated.is_allowed());
    assert!(!invalidated.cache_hit());
    assert_eq!(evaluator.cached_entries(), 1);
}

#[test]
fn cache_capacity_is_bounded() {
    let registry = registry();
    let first =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("first path");
    let second = YangPath::parse("/if:interfaces/interface/state/admin-status", &registry)
        .expect("second path");

    let policy = NacmPolicy::builder(PolicyVersion::new(9))
        .add_rule(NacmRule::allow(
            NacmAction::Read,
            YangPathPattern::parse("/if:interfaces/interface/**", &registry)
                .expect("allow subtree"),
        ))
        .build();

    let mut evaluator = NacmEvaluator::with_cache_capacity(1);

    let first_decision = evaluator.evaluate(&policy, &first, NacmAction::Read);
    assert!(first_decision.is_allowed());
    assert_eq!(evaluator.cached_entries(), 1);

    let second_decision = evaluator.evaluate(&policy, &second, NacmAction::Read);
    assert!(second_decision.is_allowed());
    assert_eq!(evaluator.cached_entries(), 1);

    let first_after_eviction = evaluator.evaluate(&policy, &first, NacmAction::Read);
    assert!(first_after_eviction.is_allowed());
    assert!(!first_after_eviction.cache_hit());
    assert_eq!(evaluator.cached_entries(), 1);
}

#[test]
fn default_module_normalizes_unqualified_segments() {
    let registry = registry();
    let path = YangPath::parse_with_default_module(
        "/interfaces/interface/config/name",
        &registry,
        Some("ietf-interfaces"),
    )
    .expect("normalize with default module");

    assert_eq!(
        path.to_string(),
        "/ietf-interfaces:interfaces/ietf-interfaces:interface/ietf-interfaces:config/ietf-interfaces:name"
    );
}

#[test]
fn default_module_rejects_prefix_inputs() {
    let registry = registry();

    let path_err =
        YangPath::parse_with_default_module("/interfaces/interface", &registry, Some("if"))
            .expect_err("prefix default module must be rejected for paths");
    assert!(path_err
        .message()
        .contains("must be a canonical module name, not a prefix"));

    let pattern_err = YangPathPattern::parse_with_default_module(
        "/interfaces/interface/**",
        &registry,
        Some("if"),
    )
    .expect_err("prefix default module must be rejected for patterns");
    assert!(pattern_err
        .message()
        .contains("must be a canonical module name, not a prefix"));
}

#[test]
fn default_module_rejects_unknown_canonical_module_inputs() {
    let registry = registry();

    let path_err = YangPath::parse_with_default_module(
        "/interfaces/interface",
        &registry,
        Some("ietf-interfaxes"),
    )
    .expect_err("unknown default module must be rejected for paths");
    assert!(path_err.message().contains("unknown default module"));

    let pattern_err = YangPathPattern::parse_with_default_module(
        "/interfaces/interface/**",
        &registry,
        Some("ietf-interfaxes"),
    )
    .expect_err("unknown default module must be rejected for patterns");
    assert!(pattern_err.message().contains("unknown default module"));
}

#[test]
fn default_module_normalizes_unqualified_pattern_segments() {
    let registry = registry();
    let pattern = YangPathPattern::parse_with_default_module(
        "/interfaces/interface/config/**",
        &registry,
        Some("ietf-interfaces"),
    )
    .expect("normalize pattern with default module");
    let path =
        YangPath::parse("/if:interfaces/interface/config/name", &registry).expect("normalize path");

    assert!(pattern.matches(&path));
    assert_eq!(
        pattern.to_string(),
        "/ietf-interfaces:interfaces/ietf-interfaces:interface/ietf-interfaces:config/**"
    );
}

#[test]
fn nacm_action_round_trips_through_strings() {
    for action in NacmAction::ALL {
        let encoded = action.as_str();
        let decoded = NacmAction::from_str(encoded).expect("action should parse");
        assert_eq!(decoded, action);
    }

    let err = NacmAction::from_str("bogus").expect_err("unknown action must fail");
    assert_eq!(err.kind(), "nacm action");
    assert!(err.message().contains("unknown action 'bogus'"));
}
