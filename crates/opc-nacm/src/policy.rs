use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    action::NacmAction,
    path::{YangPath, YangPathPattern},
    trie::RuleTrie,
};

/// Monotonic policy generation used to invalidate cached authorization results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Allow/deny effect for a matching NACM rule and final authorization outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NacmEffect {
    Allow,
    Deny,
}

impl NacmEffect {
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for NacmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

/// Single normalized NACM rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NacmRule {
    action: NacmAction,
    effect: NacmEffect,
    path: YangPathPattern,
}

impl NacmRule {
    pub fn new(action: NacmAction, effect: NacmEffect, path: YangPathPattern) -> Self {
        Self {
            action,
            effect,
            path,
        }
    }

    pub fn allow(action: NacmAction, path: YangPathPattern) -> Self {
        Self::new(action, NacmEffect::Allow, path)
    }

    pub fn deny(action: NacmAction, path: YangPathPattern) -> Self {
        Self::new(action, NacmEffect::Deny, path)
    }

    pub fn action(&self) -> NacmAction {
        self.action
    }

    pub fn effect(&self) -> NacmEffect {
        self.effect
    }

    pub fn path(&self) -> &YangPathPattern {
        &self.path
    }
}

/// Result of evaluating a single action/path request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationDecision {
    effect: NacmEffect,
    matched_rule_index: Option<usize>,
    cache_hit: bool,
    policy_version: PolicyVersion,
}

impl AuthorizationDecision {
    pub(crate) const fn new(
        effect: NacmEffect,
        matched_rule_index: Option<usize>,
        cache_hit: bool,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            effect,
            matched_rule_index,
            cache_hit,
            policy_version,
        }
    }

    pub fn effect(&self) -> NacmEffect {
        self.effect
    }

    pub fn is_allowed(&self) -> bool {
        self.effect.is_allowed()
    }

    pub fn matched_rule_index(&self) -> Option<usize> {
        self.matched_rule_index
    }

    pub fn cache_hit(&self) -> bool {
        self.cache_hit
    }

    pub fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }
}

/// Immutable compiled NACM policy with trie-backed lookup.
#[derive(Debug, Clone)]
pub struct NacmPolicy {
    version: PolicyVersion,
    cache_namespace: u64,
    rules: Vec<NacmRule>,
    trie: RuleTrie,
}

impl NacmPolicy {
    pub fn new(version: PolicyVersion, rules: Vec<NacmRule>) -> Self {
        NacmPolicyBuilder { version, rules }.build()
    }

    pub fn empty(version: PolicyVersion) -> Self {
        Self::new(version, Vec::new())
    }

    pub fn builder(version: PolicyVersion) -> NacmPolicyBuilder {
        NacmPolicyBuilder::new(version)
    }

    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    pub(crate) fn cache_namespace(&self) -> u64 {
        self.cache_namespace
    }

    pub fn rules(&self) -> &[NacmRule] {
        &self.rules
    }

    pub fn evaluate(&self, path: &YangPath, action: NacmAction) -> AuthorizationDecision {
        match self.trie.lookup(path, action) {
            Some(rule) => {
                AuthorizationDecision::new(rule.effect, Some(rule.index), false, self.version)
            }
            None => AuthorizationDecision::new(NacmEffect::Deny, None, false, self.version),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NacmPolicyBuilder {
    version: PolicyVersion,
    rules: Vec<NacmRule>,
}

impl NacmPolicyBuilder {
    pub fn new(version: PolicyVersion) -> Self {
        Self {
            version,
            rules: Vec::new(),
        }
    }

    pub fn add_rule(mut self, rule: NacmRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn push_rule(&mut self, rule: NacmRule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn build(self) -> NacmPolicy {
        let trie = RuleTrie::from_rules(&self.rules);
        NacmPolicy {
            version: self.version,
            cache_namespace: next_policy_cache_namespace(),
            rules: self.rules,
            trie,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedDecision {
    effect: NacmEffect,
    matched_rule_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PolicyCacheKey {
    namespace: u64,
    version: PolicyVersion,
}

const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// Evaluator with a bounded cache that is invalidated whenever the active
/// policy identity changes.
#[derive(Debug)]
pub struct NacmEvaluator {
    cached_policy: Option<PolicyCacheKey>,
    cache_capacity: usize,
    cache_entries: usize,
    cache: HashMap<NacmAction, HashMap<YangPath, CachedDecision>>,
    eviction_order: VecDeque<(NacmAction, YangPath)>,
}

impl NacmEvaluator {
    pub fn new() -> Self {
        Self::with_cache_capacity(DEFAULT_CACHE_CAPACITY)
    }

    pub fn with_cache_capacity(cache_capacity: usize) -> Self {
        Self {
            cached_policy: None,
            cache_capacity,
            cache_entries: 0,
            cache: HashMap::new(),
            eviction_order: VecDeque::new(),
        }
    }

    pub fn evaluate(
        &mut self,
        policy: &NacmPolicy,
        path: &YangPath,
        action: NacmAction,
    ) -> AuthorizationDecision {
        let start = std::time::Instant::now();
        let policy_key = PolicyCacheKey {
            namespace: policy.cache_namespace(),
            version: policy.version(),
        };
        if self.cached_policy != Some(policy_key) {
            self.clear_cache();
            self.cached_policy = Some(policy_key);
        }

        let decision = if let Some(cached) = self
            .cache
            .get(&action)
            .and_then(|entries| entries.get(path))
        {
            AuthorizationDecision::new(
                cached.effect,
                cached.matched_rule_index,
                true,
                policy.version(),
            )
        } else {
            let dec = policy.evaluate(path, action);
            self.insert_cache_entry(
                action,
                path.clone(),
                CachedDecision {
                    effect: dec.effect(),
                    matched_rule_index: dec.matched_rule_index(),
                },
            );
            dec
        };

        let elapsed = start.elapsed().as_secs_f64();
        opc_redaction::metrics::METRICS
            .nacm_eval_latency
            .observe(elapsed);

        if decision.is_allowed() {
            opc_redaction::metrics::METRICS
                .nacm_eval_allow
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .nacm_eval_deny
                .fetch_add(1, Ordering::Relaxed);
            if decision.matched_rule_index().is_none() {
                opc_redaction::metrics::METRICS
                    .nacm_default_deny
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        decision
    }

    pub fn cached_entries(&self) -> usize {
        self.cache_entries
    }

    pub fn cached_policy_version(&self) -> Option<PolicyVersion> {
        self.cached_policy.map(|policy| policy.version)
    }

    fn clear_cache(&mut self) {
        self.cache.clear();
        self.eviction_order.clear();
        self.cache_entries = 0;
    }

    fn insert_cache_entry(&mut self, action: NacmAction, path: YangPath, decision: CachedDecision) {
        if self.cache_capacity == 0 {
            return;
        }

        while self.cache_entries >= self.cache_capacity {
            self.evict_oldest_entry();
        }

        let action_entries = self.cache.entry(action).or_default();
        let inserted = action_entries.insert(path.clone(), decision).is_none();
        if inserted {
            self.eviction_order.push_back((action, path));
            self.cache_entries += 1;
        }
    }

    fn evict_oldest_entry(&mut self) {
        while let Some((action, path)) = self.eviction_order.pop_front() {
            let Some(action_entries) = self.cache.get_mut(&action) else {
                continue;
            };

            if action_entries.remove(&path).is_some() {
                self.cache_entries = self.cache_entries.saturating_sub(1);
            }

            if action_entries.is_empty() {
                self.cache.remove(&action);
            }

            break;
        }
    }
}

impl Default for NacmEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

fn next_policy_cache_namespace() -> u64 {
    static NEXT_POLICY_CACHE_NAMESPACE: AtomicU64 = AtomicU64::new(1);
    NEXT_POLICY_CACHE_NAMESPACE.fetch_add(1, Ordering::Relaxed)
}
