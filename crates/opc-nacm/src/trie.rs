use std::collections::BTreeMap;

use crate::{
    action::NacmAction,
    path::{QualifiedNodeName, YangPath, YangPathPatternSegment},
    policy::{NacmEffect, NacmRule},
};

#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    pub(crate) index: usize,
    pub(crate) effect: NacmEffect,
    action: NacmAction,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct RuleTrie {
    root: RuleTrieNode,
}

#[derive(Debug, Default, Clone)]
struct RuleTrieNode {
    exact_children: BTreeMap<QualifiedNodeName, RuleTrieNode>,
    module_wildcard_children: BTreeMap<String, RuleTrieNode>,
    any_child: Option<Box<RuleTrieNode>>,
    exact_rules: Vec<CompiledRule>,
    subtree_rules: Vec<CompiledRule>,
}

impl RuleTrie {
    pub(crate) fn from_rules(rules: &[NacmRule]) -> Self {
        let mut trie = Self::default();
        for (index, rule) in rules.iter().enumerate() {
            trie.insert(index, rule);
        }
        trie
    }

    pub(crate) fn lookup(&self, path: &YangPath, action: NacmAction) -> Option<&CompiledRule> {
        let mut best_match = None;
        self.root.collect(path, 0, action, &mut best_match);
        best_match
    }

    fn insert(&mut self, index: usize, rule: &NacmRule) {
        let compiled = CompiledRule {
            index,
            effect: rule.effect(),
            action: rule.action(),
        };

        let mut node = &mut self.root;
        for segment in rule.path().segments() {
            node = match segment {
                YangPathPatternSegment::Exact(name) => {
                    node.exact_children.entry(name.clone()).or_default()
                }
                YangPathPatternSegment::WildcardModule(module) => node
                    .module_wildcard_children
                    .entry(module.clone())
                    .or_default(),
                YangPathPatternSegment::WildcardAny => node
                    .any_child
                    .get_or_insert_with(|| Box::new(RuleTrieNode::default()))
                    .as_mut(),
            };
        }

        if rule.path().is_subtree() {
            node.subtree_rules.push(compiled);
        } else {
            node.exact_rules.push(compiled);
        }
    }
}

impl RuleTrieNode {
    fn collect<'a>(
        &'a self,
        path: &YangPath,
        index: usize,
        action: NacmAction,
        best_match: &mut Option<&'a CompiledRule>,
    ) {
        if matches!(best_match, Some(rule) if rule.index == 0) {
            return;
        }

        for rule in &self.subtree_rules {
            if rule.action == action {
                select_first_inserted(best_match, rule);
                if matches!(best_match, Some(best) if best.index == 0) {
                    return;
                }
            }
        }

        if index == path.len() {
            for rule in &self.exact_rules {
                if rule.action == action {
                    select_first_inserted(best_match, rule);
                    if matches!(best_match, Some(best) if best.index == 0) {
                        return;
                    }
                }
            }
            return;
        }

        let segment = &path.segments()[index];

        if let Some(child) = self.exact_children.get(segment) {
            child.collect(path, index + 1, action, best_match);
        }

        if let Some(child) = self.module_wildcard_children.get(segment.module()) {
            child.collect(path, index + 1, action, best_match);
        }

        if let Some(child) = self.any_child.as_deref() {
            child.collect(path, index + 1, action, best_match);
        }
    }
}

fn select_first_inserted<'a>(
    best_match: &mut Option<&'a CompiledRule>,
    candidate: &'a CompiledRule,
) {
    match best_match {
        Some(current) if current.index <= candidate.index => {}
        _ => {
            *best_match = Some(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        path::{ModuleRegistry, YangPath, YangPathPattern},
        policy::{NacmPolicy, PolicyVersion},
    };

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
    fn earlier_rule_wins_over_later_more_specific_rule() {
        let registry = registry();
        let path = YangPath::parse("/if:interfaces/if:interface/if:config/if:name", &registry)
            .expect("parse path");

        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/*/**", &registry).expect("wildcard rule"),
            ))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:interface/if:config/if:name", &registry)
                    .expect("exact rule"),
            ))
            .build();

        let decision = policy.evaluate(&path, NacmAction::Read);
        assert_eq!(decision.effect(), NacmEffect::Allow);
        assert_eq!(decision.matched_rule_index(), Some(0));
    }

    #[test]
    fn earlier_rule_wins_when_specificity_is_equal() {
        let registry = registry();
        let path = YangPath::parse("/if:interfaces/if:interface", &registry).expect("parse path");

        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:interface", &registry)
                    .expect("exact allow rule"),
            ))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:interface", &registry)
                    .expect("exact deny rule"),
            ))
            .build();

        let decision = policy.evaluate(&path, NacmAction::Read);
        assert_eq!(decision.effect(), NacmEffect::Allow);
        assert_eq!(decision.matched_rule_index(), Some(0));
    }

    #[test]
    fn module_wildcard_matches_same_module_child() {
        let registry = registry();
        let path = YangPath::parse("/if:interfaces/if:interface", &registry).expect("parse path");

        // `if:*` matches any single segment in the ietf-interfaces module.
        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:*", &registry)
                    .expect("module wildcard rule"),
            ))
            .build();

        let decision = policy.evaluate(&path, NacmAction::Read);
        assert_eq!(decision.effect(), NacmEffect::Allow);
        assert_eq!(decision.matched_rule_index(), Some(0));
    }

    #[test]
    fn module_wildcard_default_denies_unmatched_path() {
        let registry = registry();
        // A path in a different subtree than the module-wildcard rule covers.
        let path = YangPath::parse("/sys:system", &registry).expect("parse path");

        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:*", &registry)
                    .expect("module wildcard rule"),
            ))
            .build();

        // No rule matches, so the default-deny posture applies.
        let decision = policy.evaluate(&path, NacmAction::Read);
        assert_eq!(decision.effect(), NacmEffect::Deny);
        assert_eq!(decision.matched_rule_index(), None);
    }

    #[test]
    fn earlier_exact_deny_beats_later_module_wildcard_allow() {
        let registry = registry();
        let path = YangPath::parse("/if:interfaces/if:interface", &registry).expect("parse path");

        let policy = NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:interface", &registry)
                    .expect("exact deny rule"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/if:interfaces/if:*", &registry)
                    .expect("module wildcard allow rule"),
            ))
            .build();

        // First-match ordering: the earlier exact deny wins over the wildcard.
        let decision = policy.evaluate(&path, NacmAction::Read);
        assert_eq!(decision.effect(), NacmEffect::Deny);
        assert_eq!(decision.matched_rule_index(), Some(0));
    }
}
