//! Clone-shared scheduling of intersecting kernel keys. This is exclusion,
//! not ownership authority: every effect still verifies its exact readback.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::collection::{OwnedRouteRuleScope, RouteSteeringIpFamily};
use crate::error::RouteSteeringError;
use crate::model::{IpPrefix, ReadbackIndeterminateReason, RouteRequest, RuleRequest};
use crate::validation::{canonical_route_request, source_only_rules_are_provably_disjoint};

// Limits the number of blocking transport workers owned by one backend.
// Waiting operations remain async and never occupy a blocking worker.
const MAX_CONCURRENT_OPERATIONS: usize = 64;

#[derive(Clone)]
pub(crate) enum OperationScope {
    Global,
    Route(RouteRequest),
    Rule(RuleRequest),
    Pair(RouteRequest, RuleRequest),
    Collection(OwnedRouteRuleScope),
}

impl OperationScope {
    fn route_key(&self) -> Option<(RouteSteeringIpFamily, u32, Option<IpPrefix>)> {
        match self {
            Self::Route(route) | Self::Pair(route, _) => {
                let route = canonical_route_request(route);
                Some((
                    family(route.destination.is_ipv4()),
                    route.table,
                    Some(route.destination),
                ))
            }
            Self::Collection(scope) => Some((scope.family(), scope.table(), None)),
            _ => None,
        }
    }

    fn rule_key(&self) -> Option<(RouteSteeringIpFamily, u32, Option<&RuleRequest>)> {
        match self {
            Self::Rule(rule) | Self::Pair(_, rule) => Some((
                family(crate::collection::rule_is_ipv4(rule)),
                rule.priority,
                Some(rule),
            )),
            Self::Collection(scope) => Some((scope.family(), scope.rule_priority(), None)),
            _ => None,
        }
    }

    fn conflicts(&self, other: &Self) -> bool {
        if matches!(self, Self::Global) || matches!(other, Self::Global) {
            return true;
        }
        if let (Some((af, table, prefix)), Some((other_af, other_table, other_prefix))) =
            (self.route_key(), other.route_key())
        {
            if af == other_af
                && table == other_table
                && (prefix.is_none() || other_prefix.is_none() || prefix == other_prefix)
            {
                return true;
            }
        }
        if let (Some((af, priority, rule)), Some((other_af, other_priority, other_rule))) =
            (self.rule_key(), other.rule_key())
        {
            if af == other_af && priority == other_priority {
                return !matches!((rule, other_rule), (Some(first), Some(second))
                    if source_only_rules_are_provably_disjoint(first, second));
            }
        }
        false
    }
}

fn family(ipv4: bool) -> RouteSteeringIpFamily {
    if ipv4 {
        RouteSteeringIpFamily::Ipv4
    } else {
        RouteSteeringIpFamily::Ipv6
    }
}

#[derive(Default)]
pub(crate) struct OperationScheduler {
    state: Mutex<SchedulerState>,
    changed: Notify,
}

#[derive(Default)]
struct SchedulerState {
    next_ticket: u64,
    requests: BTreeMap<u64, Request>,
}

struct Request {
    scope: OperationScope,
    active: bool,
}

pub(crate) struct OperationPermit {
    scheduler: Arc<OperationScheduler>,
    ticket: u64,
}

impl OperationScheduler {
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        scope: OperationScope,
    ) -> Result<OperationPermit, RouteSteeringError> {
        let ticket = {
            let mut state = self.state.lock().map_err(|_| scheduling_unavailable())?;
            let ticket = state
                .next_ticket
                .checked_add(1)
                .ok_or_else(scheduling_unavailable)?;
            state.next_ticket = ticket;
            state.requests.insert(
                ticket,
                Request {
                    scope,
                    active: false,
                },
            );
            ticket
        };
        // Also removes a queued reservation if its async caller is cancelled.
        let permit = OperationPermit {
            scheduler: Arc::clone(self),
            ticket,
        };
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.try_activate(ticket)? {
                return Ok(permit);
            }
            changed.await;
        }
    }

    fn try_activate(&self, ticket: u64) -> Result<bool, RouteSteeringError> {
        let mut state = self.state.lock().map_err(|_| scheduling_unavailable())?;
        let request = state
            .requests
            .get(&ticket)
            .ok_or_else(scheduling_unavailable)?;
        let mut active = 0;
        for (&other_ticket, other) in &state.requests {
            if other_ticket == ticket {
                continue;
            }
            active += usize::from(other.active);
            // Earlier conflicting requests retain their order. A queued
            // request for a different key does not block independent work.
            if (other.active || other_ticket < ticket) && request.scope.conflicts(&other.scope) {
                return Ok(false);
            }
        }
        if active >= MAX_CONCURRENT_OPERATIONS {
            return Ok(false);
        }
        state
            .requests
            .get_mut(&ticket)
            .ok_or_else(scheduling_unavailable)?
            .active = true;
        Ok(true)
    }
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.scheduler.state.lock() {
            state.requests.remove(&self.ticket);
        }
        self.scheduler.changed.notify_waiters();
    }
}

fn scheduling_unavailable() -> RouteSteeringError {
    RouteSteeringError::indeterminate(ReadbackIndeterminateReason::ConcurrentModification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::task::Poll;

    fn rule(host: u8) -> RuleRequest {
        RuleRequest {
            source: Some(IpPrefix::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)),
                32,
            )),
            destination: None,
            fwmark: None,
            table: 1000,
            priority: 900,
        }
    }

    #[test]
    fn rule_exclusion_requires_the_complete_source_only_disjointness_contract() {
        let first = OperationScope::Rule(rule(10));
        assert!(first.conflicts(&first));
        assert!(!first.conflicts(&OperationScope::Rule(rule(11))));
        for variant in 0..5 {
            let mut other = rule(11);
            match variant {
                0 => other.source.as_mut().unwrap().prefix_len = 24,
                1 => other.source.as_mut().unwrap().prefix_len = 0,
                2 => other.table += 1,
                3 => other.destination = other.source,
                _ => other.fwmark = Some(crate::model::FirewallMark { value: 1, mask: 1 }),
            }
            assert!(first.conflicts(&OperationScope::Rule(other)));
        }
        let scope =
            OwnedRouteRuleScope::new(RouteSteeringIpFamily::Ipv4, 1000, 42, None, 900).unwrap();
        assert!(first.conflicts(&OperationScope::Collection(scope)));
        assert!(first.conflicts(&OperationScope::Global));
    }

    #[tokio::test]
    async fn cancelled_queue_entries_release_order_without_losing_live_exclusion() {
        let scheduler = Arc::new(OperationScheduler::default());
        let owner = scheduler
            .acquire(OperationScope::Rule(rule(10)))
            .await
            .unwrap();
        let mut abandoned = Box::pin(scheduler.acquire(OperationScope::Rule(rule(10))));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(abandoned.as_mut().poll(cx).is_pending())).await
        );
        assert_eq!(scheduler.state.lock().unwrap().requests.len(), 2);
        drop(abandoned);
        assert_eq!(scheduler.state.lock().unwrap().requests.len(), 1);
        let independent = scheduler
            .acquire(OperationScope::Rule(rule(11)))
            .await
            .unwrap();
        assert_eq!(
            scheduler
                .state
                .lock()
                .unwrap()
                .requests
                .values()
                .filter(|r| r.active)
                .count(),
            2
        );
        drop(owner);
        let successor = scheduler
            .acquire(OperationScope::Rule(rule(10)))
            .await
            .unwrap();
        drop(successor);
        drop(independent);
        assert!(scheduler.state.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn canonical_routes_and_complete_scopes_reserve_their_broad_conflict_keys() {
        let mut first = RouteRequest {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 129)), 24),
            oif_ifindex: 42,
            table: 1000,
            priority: None,
        };
        let scope = OperationScope::Route(first.clone());
        first.destination.address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        first.oif_ifindex += 1;
        first.priority = Some(20);
        assert!(scope.conflicts(&OperationScope::Route(first.clone())));
        first.table += 1;
        assert!(!scope.conflicts(&OperationScope::Route(first)));
        let collection = OperationScope::Collection(
            OwnedRouteRuleScope::new(RouteSteeringIpFamily::Ipv4, 1000, 99, Some(30), 901).unwrap(),
        );
        assert!(scope.conflicts(&collection));
        assert!(!OperationScope::Rule(rule(10)).conflicts(&collection));
    }

    #[tokio::test]
    async fn independent_workers_remain_bounded_and_waiters_do_not_hold_slots() {
        let scheduler = Arc::new(OperationScheduler::default());
        let mut permits = Vec::new();
        for host in 1..=u8::try_from(MAX_CONCURRENT_OPERATIONS).unwrap() {
            permits.push(
                scheduler
                    .acquire(OperationScope::Rule(rule(host)))
                    .await
                    .unwrap(),
            );
        }
        let blocked = scheduler.acquire(OperationScope::Rule(rule(200)));
        tokio::pin!(blocked);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(blocked.as_mut().poll(cx).is_pending())).await
        );
        assert_eq!(
            scheduler
                .state
                .lock()
                .unwrap()
                .requests
                .values()
                .filter(|r| r.active)
                .count(),
            MAX_CONCURRENT_OPERATIONS
        );
        drop(permits.pop());
        let last = blocked.await.unwrap();
        assert_eq!(
            scheduler
                .state
                .lock()
                .unwrap()
                .requests
                .values()
                .filter(|r| r.active)
                .count(),
            MAX_CONCURRENT_OPERATIONS
        );
        drop(last);
        drop(permits);
        assert!(scheduler.state.lock().unwrap().requests.is_empty());
    }
}
