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
    min_rule_index: Option<usize>,
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
        let mut visited_nodes = 0;
        self.root
            .collect(path, 0, action, &mut best_match, &mut visited_nodes);
        best_match
    }

    #[cfg(test)]
    fn lookup_with_visit_count(
        &self,
        path: &YangPath,
        action: NacmAction,
    ) -> (Option<&CompiledRule>, usize) {
        let mut best_match = None;
        let mut visited_nodes = 0;
        self.root
            .collect(path, 0, action, &mut best_match, &mut visited_nodes);
        (best_match, visited_nodes)
    }

    fn insert(&mut self, index: usize, rule: &NacmRule) {
        let compiled = CompiledRule {
            index,
            effect: rule.effect(),
            action: rule.action(),
        };

        let mut node = &mut self.root;
        node.record_reachable_rule(index);
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
            node.record_reachable_rule(index);
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
        visited_nodes: &mut usize,
    ) {
        *visited_nodes += 1;

        if self.cannot_beat(best_match) {
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
            child.collect(path, index + 1, action, best_match, visited_nodes);
        }

        if let Some(child) = self.module_wildcard_children.get(segment.module()) {
            child.collect(path, index + 1, action, best_match, visited_nodes);
        }

        if let Some(child) = self.any_child.as_deref() {
            child.collect(path, index + 1, action, best_match, visited_nodes);
        }
    }

    fn record_reachable_rule(&mut self, index: usize) {
        self.min_rule_index = Some(
            self.min_rule_index
                .map(|current| current.min(index))
                .unwrap_or(index),
        );
    }

    fn cannot_beat(&self, best_match: &Option<&CompiledRule>) -> bool {
        let Some(min_rule_index) = self.min_rule_index else {
            return true;
        };
        matches!(best_match, Some(best) if min_rule_index >= best.index)
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

    #[test]
    fn lookup_prunes_higher_index_wildcard_subtrees_after_low_index_match() {
        let registry = registry();
        let depth = 64;
        let exact = deep_path(depth);
        let path = YangPath::parse(&exact, &registry).expect("parse deep path");
        let mut rules = vec![
            NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system", &registry).expect("nonmatching rule"),
            ),
            NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse(&exact, &registry).expect("early exact rule"),
            ),
        ];

        for wildcard_at in 0..depth {
            rules.push(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse(
                    &deep_path_with_wildcard(depth, wildcard_at, "if:*"),
                    &registry,
                )
                .expect("module wildcard rule"),
            ));
            rules.push(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse(
                    &deep_path_with_wildcard(depth, wildcard_at, "*"),
                    &registry,
                )
                .expect("any wildcard rule"),
            ));
        }

        let trie = RuleTrie::from_rules(&rules);
        let (matched, visited) = trie.lookup_with_visit_count(&path, NacmAction::Read);

        assert_eq!(matched.map(|rule| rule.index), Some(1));
        assert!(
            visited <= depth * 3 + 4,
            "visited {visited} nodes for depth {depth}"
        );
    }

    fn deep_path(depth: usize) -> String {
        let segments = (0..depth)
            .map(|i| format!("if:n{i}"))
            .collect::<Vec<_>>()
            .join("/");
        format!("/{segments}")
    }

    fn deep_path_with_wildcard(depth: usize, wildcard_at: usize, wildcard: &str) -> String {
        let segments = (0..depth)
            .map(|i| {
                if i == wildcard_at {
                    wildcard.to_string()
                } else {
                    format!("if:n{i}")
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        format!("/{segments}")
    }
}
