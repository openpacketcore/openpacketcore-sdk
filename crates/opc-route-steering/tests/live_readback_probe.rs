#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use opc_route_steering::{
    FirewallMark, IpPrefix, LinuxRouteSteeringBackend, LinuxRuleProtocolCapability,
    OwnedRouteRuleScope, OwnedRouteRuleSet, ReadbackIndeterminateReason, RouteConvergenceOutcome,
    RouteReadback, RouteRequest, RouteRuleRollback, RouteSteeringBackend, RouteSteeringIpFamily,
    RuleConvergenceOutcome, RuleReadback, RuleRequest,
};

const OWNED_PROTOCOL: &str = "242";

fn ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().unwrap();
    assert!(status.success(), "ip command failed");
}

fn ip_stdout(args: &[&str]) -> String {
    let output = Command::new("ip").args(args).output().unwrap();
    assert!(output.status.success(), "ip command failed");
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn live_absent_documentation_prefix_readback_completes() {
    let backend = LinuxRouteSteeringBackend::new();
    let request = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 127)), 32),
        oif_ifindex: 1,
        table: 4_000_000_001,
        priority: Some(u32::MAX - 1),
    };
    assert_eq!(
        backend.read_route(&request).await.unwrap(),
        RouteReadback::Absent
    );
}

#[tokio::test]
async fn live_absent_documentation_rule_readback_completes() {
    let backend = LinuxRouteSteeringBackend::new();
    let request = RuleRequest {
        source: Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 127)), 32)),
        destination: None,
        fwmark: None,
        table: 4_000_000_001,
        priority: u32::MAX,
    };
    assert_eq!(
        backend.read_rule(&request).await.unwrap(),
        RuleReadback::Absent
    );
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_default_route_readback_is_table_scoped_and_same_table_fail_closed() {
    const OWNED_TABLE: u32 = 4_000_000_420;
    const FOREIGN_TABLE: u32 = 4_000_000_421;

    ip(&["link", "add", "up420", "type", "dummy"]);
    ip(&["link", "set", "up420", "up"]);
    let ifindex = ip_stdout(&["-o", "link", "show", "dev", "up420"])
        .split_once(':')
        .unwrap()
        .0
        .trim()
        .parse::<u32>()
        .unwrap();

    let backend = LinuxRouteSteeringBackend::new();
    let route = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        oif_ifindex: ifindex,
        table: OWNED_TABLE,
        priority: None,
    };

    ip(&[
        "route",
        "add",
        "unreachable",
        "default",
        "table",
        &FOREIGN_TABLE.to_string(),
        "metric",
        "42760",
    ]);
    assert_eq!(
        backend.converge_route(route.clone()).await.unwrap(),
        RouteConvergenceOutcome::Installed
    );
    assert_eq!(
        backend.converge_route(route.clone()).await.unwrap(),
        RouteConvergenceOutcome::ExactAlreadyPresent
    );
    backend.remove_converged_route(route.clone()).await.unwrap();
    assert_eq!(
        backend.read_route(&route).await.unwrap(),
        RouteReadback::Absent
    );

    let foreign = Command::new("ip")
        .args([
            "route",
            "show",
            "table",
            &FOREIGN_TABLE.to_string(),
            "type",
            "unreachable",
        ])
        .output()
        .unwrap();
    assert!(foreign.status.success());
    assert!(String::from_utf8_lossy(&foreign.stdout).contains("unreachable default"));
    ip(&[
        "route",
        "del",
        "unreachable",
        "default",
        "table",
        &FOREIGN_TABLE.to_string(),
        "metric",
        "42760",
    ]);

    ip(&[
        "route",
        "add",
        "unreachable",
        "default",
        "table",
        &OWNED_TABLE.to_string(),
        "metric",
        "42760",
    ]);
    assert_eq!(
        backend.converge_route(route.clone()).await.unwrap(),
        RouteConvergenceOutcome::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject)
    );
    assert_eq!(
        backend.read_route(&route).await.unwrap(),
        RouteReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject)
    );
    ip(&[
        "route",
        "del",
        "unreachable",
        "default",
        "table",
        &OWNED_TABLE.to_string(),
        "metric",
        "42760",
    ]);
    ip(&["link", "del", "up420"]);
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_privileged_pair_converges_retries_and_removes_exact_state() {
    let backend = LinuxRouteSteeringBackend::new();
    let prefix = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24);
    let route = RouteRequest {
        destination: prefix,
        oif_ifindex: 1,
        table: 4_000_000_001,
        priority: Some(u32::MAX - 1),
    };
    let rule = RuleRequest {
        source: Some(prefix),
        destination: None,
        fwmark: None,
        table: route.table,
        priority: u32::MAX - 1,
    };

    let installed = backend
        .converge_route_and_rule(route.clone(), rule.clone())
        .await
        .unwrap();
    assert_eq!(installed.route, RouteConvergenceOutcome::Installed);
    assert_eq!(installed.rule, RuleConvergenceOutcome::Installed);
    assert_eq!(installed.rollback, RouteRuleRollback::NotNeeded);
    assert_eq!(
        backend.rule_protocol_capability(),
        LinuxRuleProtocolCapability::Confirmed
    );
    assert_eq!(
        backend.read_route(&route).await.unwrap(),
        RouteReadback::ExactPresent
    );
    assert_eq!(
        backend.read_rule(&rule).await.unwrap(),
        RuleReadback::ExactPresent
    );

    let retried = backend
        .converge_route_and_rule(route.clone(), rule.clone())
        .await
        .unwrap();
    assert_eq!(retried.route, RouteConvergenceOutcome::ExactAlreadyPresent);
    assert_eq!(retried.rule, RuleConvergenceOutcome::ExactAlreadyPresent);
    assert_eq!(retried.rollback, RouteRuleRollback::NotNeeded);

    backend.remove_converged_rule(rule.clone()).await.unwrap();
    backend.remove_converged_route(route.clone()).await.unwrap();
    assert_eq!(
        backend.read_rule(&rule).await.unwrap(),
        RuleReadback::Absent
    );
    assert_eq!(
        backend.read_route(&route).await.unwrap(),
        RouteReadback::Absent
    );

    let mark_only_rule = RuleRequest {
        source: None,
        destination: None,
        fwmark: Some(FirewallMark {
            value: 0x400,
            mask: 0xff00,
        }),
        table: route.table,
        priority: u32::MAX - 2,
    };
    assert_eq!(
        backend.converge_rule(mark_only_rule.clone()).await.unwrap(),
        RuleConvergenceOutcome::Installed
    );
    assert_eq!(
        backend.read_rule(&mark_only_rule).await.unwrap(),
        RuleReadback::ExactPresent
    );
    assert_eq!(
        backend.converge_rule(mark_only_rule.clone()).await.unwrap(),
        RuleConvergenceOutcome::ExactAlreadyPresent
    );
    backend
        .remove_converged_rule(mark_only_rule.clone())
        .await
        .unwrap();
    assert_eq!(
        backend.read_rule(&mark_only_rule).await.unwrap(),
        RuleReadback::Absent
    );

    let ipv6_prefix = IpPrefix::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
        64,
    );
    let ipv6_route = RouteRequest {
        destination: ipv6_prefix,
        oif_ifindex: 1,
        table: route.table,
        priority: Some(u32::MAX - 3),
    };
    let ipv6_rule = RuleRequest {
        source: Some(ipv6_prefix),
        destination: None,
        fwmark: None,
        table: route.table,
        priority: u32::MAX - 3,
    };
    let ipv6_installed = backend
        .converge_route_and_rule(ipv6_route.clone(), ipv6_rule.clone())
        .await
        .unwrap();
    assert_eq!(ipv6_installed.route, RouteConvergenceOutcome::Installed);
    assert_eq!(ipv6_installed.rule, RuleConvergenceOutcome::Installed);
    assert_eq!(ipv6_installed.rollback, RouteRuleRollback::NotNeeded);
    assert_eq!(
        backend.read_route(&ipv6_route).await.unwrap(),
        RouteReadback::ExactPresent
    );
    assert_eq!(
        backend.read_rule(&ipv6_rule).await.unwrap(),
        RuleReadback::ExactPresent
    );
    backend
        .remove_converged_rule(ipv6_rule.clone())
        .await
        .unwrap();
    backend
        .remove_converged_route(ipv6_route.clone())
        .await
        .unwrap();
    assert_eq!(
        backend.read_rule(&ipv6_rule).await.unwrap(),
        RuleReadback::Absent
    );
    assert_eq!(
        backend.read_route(&ipv6_route).await.unwrap(),
        RouteReadback::Absent
    );
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_owned_collection_same_priority_siblings_retry_and_remove_exactly() {
    let backend = LinuxRouteSteeringBackend::new();
    let scope = OwnedRouteRuleScope::new(RouteSteeringIpFamily::Ipv4, 1000, 1, None, 900).unwrap();
    let first = RuleRequest {
        source: Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 32)),
        destination: None,
        fwmark: None,
        table: 1000,
        priority: 900,
    };
    let second = RuleRequest {
        source: Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), 32)),
        destination: None,
        fwmark: None,
        table: 1000,
        priority: 900,
    };
    let both =
        OwnedRouteRuleSet::new(scope, Vec::new(), vec![first.clone(), second.clone()]).unwrap();

    let installed = backend
        .reconcile_owned_route_rules(both.clone())
        .await
        .unwrap();
    assert_eq!(installed.installed_rules, 2);
    assert_eq!(installed.snapshot.rules(), &[first.clone(), second.clone()]);

    let retried = backend.reconcile_owned_route_rules(both).await.unwrap();
    assert_eq!(retried.retained_rules, 2);
    assert_eq!(retried.installed_rules, 0);

    let only_second = OwnedRouteRuleSet::new(scope, Vec::new(), vec![second.clone()]).unwrap();
    let reduced = backend
        .reconcile_owned_route_rules(only_second)
        .await
        .unwrap();
    assert_eq!(reduced.removed_rules, 1);
    assert_eq!(reduced.snapshot.rules(), &[second]);

    let empty = OwnedRouteRuleSet::new(scope, Vec::new(), Vec::new()).unwrap();
    let cleaned = backend.reconcile_owned_route_rules(empty).await.unwrap();
    assert!(cleaned.snapshot.rules().is_empty());
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_multiple_candidates_are_conflicts_and_exact_removal_preserves_them() {
    let backend = LinuxRouteSteeringBackend::new();
    let route = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 64)), 26),
        oif_ifindex: 1,
        table: 4_000_000_101,
        priority: Some(101),
    };
    ip(&[
        "route",
        "add",
        "198.51.100.64/26",
        "dev",
        "lo",
        "table",
        "4000000101",
        "metric",
        "101",
        "scope",
        "global",
        "protocol",
        OWNED_PROTOCOL,
    ]);
    ip(&[
        "route",
        "add",
        "198.51.100.64/26",
        "dev",
        "lo",
        "table",
        "4000000101",
        "metric",
        "102",
        "scope",
        "global",
        "protocol",
        OWNED_PROTOCOL,
    ]);
    let conflict = match backend.read_route(&route).await.unwrap() {
        RouteReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected route readback: {other:?}"),
    };
    assert_eq!(conflict.candidate_count().get(), 2);
    assert!(conflict.mismatch().priority);
    assert!(!conflict.mismatch().kernel_semantics);
    assert!(backend.remove_converged_route(route.clone()).await.is_err());
    assert!(matches!(
        backend.read_route(&route).await.unwrap(),
        RouteReadback::Conflict(_)
    ));

    let rule = RuleRequest {
        source: Some(route.destination),
        destination: None,
        fwmark: None,
        table: route.table,
        priority: 30_101,
    };
    ip(&[
        "rule",
        "add",
        "priority",
        "30101",
        "from",
        "198.51.100.64/26",
        "table",
        "4000000101",
        "protocol",
        OWNED_PROTOCOL,
    ]);
    ip(&[
        "rule",
        "add",
        "priority",
        "30101",
        "to",
        "203.0.113.64/26",
        "table",
        "4000000101",
        "protocol",
        OWNED_PROTOCOL,
    ]);
    let conflict = match backend.read_rule(&rule).await.unwrap() {
        RuleReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected rule readback: {other:?}"),
    };
    assert_eq!(conflict.candidate_count().get(), 2);
    assert!(!conflict.mismatch().kernel_semantics);
    assert!(backend.remove_converged_rule(rule.clone()).await.is_err());
    assert!(matches!(
        backend.read_rule(&rule).await.unwrap(),
        RuleReadback::Conflict(_)
    ));
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_foreign_protocol_and_zero_mark_rules_are_never_adopted_or_deleted() {
    let backend = LinuxRouteSteeringBackend::new();
    let foreign_route = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 128)), 26),
        oif_ifindex: 1,
        table: 4_000_000_102,
        priority: Some(201),
    };
    ip(&[
        "route",
        "add",
        "203.0.113.128/26",
        "dev",
        "lo",
        "table",
        "4000000102",
        "metric",
        "201",
        "protocol",
        "99",
    ]);
    let conflict = match backend.read_route(&foreign_route).await.unwrap() {
        RouteReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected route readback: {other:?}"),
    };
    assert!(conflict.mismatch().kernel_semantics);
    assert!(backend
        .remove_converged_route(foreign_route.clone())
        .await
        .is_err());
    assert!(matches!(
        backend.read_route(&foreign_route).await.unwrap(),
        RouteReadback::Conflict(_)
    ));

    let foreign_rule = RuleRequest {
        source: Some(foreign_route.destination),
        destination: None,
        fwmark: None,
        table: foreign_route.table,
        priority: 30_102,
    };
    ip(&[
        "rule",
        "add",
        "priority",
        "30102",
        "from",
        "203.0.113.128/26",
        "table",
        "4000000102",
        "protocol",
        "99",
    ]);
    let conflict = match backend.read_rule(&foreign_rule).await.unwrap() {
        RuleReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected rule readback: {other:?}"),
    };
    assert!(conflict.mismatch().kernel_semantics);
    assert!(backend
        .remove_converged_rule(foreign_rule.clone())
        .await
        .is_err());
    assert!(matches!(
        backend.read_rule(&foreign_rule).await.unwrap(),
        RuleReadback::Conflict(_)
    ));

    let marked_request = RuleRequest {
        source: None,
        destination: None,
        fwmark: Some(FirewallMark {
            value: 1,
            mask: 0xff,
        }),
        table: 4_000_000_103,
        priority: 30_103,
    };
    ip(&[
        "rule",
        "add",
        "priority",
        "30103",
        "fwmark",
        "0/255",
        "table",
        "4000000103",
        "protocol",
        OWNED_PROTOCOL,
    ]);
    let conflict = match backend.read_rule(&marked_request).await.unwrap() {
        RuleReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected rule readback: {other:?}"),
    };
    assert!(conflict.mismatch().firewall_mark);
    assert!(backend
        .remove_converged_rule(marked_request.clone())
        .await
        .is_err());
    assert!(matches!(
        backend.read_rule(&marked_request).await.unwrap(),
        RuleReadback::Conflict(_)
    ));

    let legacy_request = RuleRequest {
        source: None,
        destination: None,
        fwmark: Some(FirewallMark {
            value: 2,
            mask: 0xff,
        }),
        table: 4_000_000_103,
        priority: 30_104,
    };
    ip(&[
        "rule",
        "add",
        "priority",
        "30104",
        "fwmark",
        "2/255",
        "table",
        "4000000103",
    ]);
    let conflict = match backend.read_rule(&legacy_request).await.unwrap() {
        RuleReadback::Conflict(conflict) => conflict,
        other => panic!("unexpected legacy rule readback: {other:?}"),
    };
    assert!(conflict.mismatch().kernel_semantics);
    assert!(backend
        .remove_converged_rule(legacy_request.clone())
        .await
        .is_err());
    assert!(matches!(
        backend.read_rule(&legacy_request).await.unwrap(),
        RuleReadback::Conflict(_)
    ));
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN in an isolated network namespace"]
async fn live_default_route_priorities_and_cancelled_clone_pair_are_stable() {
    let backend = LinuxRouteSteeringBackend::new();
    let ipv4 = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 192)), 26),
        oif_ifindex: 1,
        table: 4_000_000_104,
        priority: None,
    };
    assert_eq!(
        backend.converge_route(ipv4.clone()).await.unwrap(),
        RouteConvergenceOutcome::Installed
    );
    let mut ipv4_zero = ipv4.clone();
    ipv4_zero.priority = Some(0);
    assert_eq!(
        backend.read_route(&ipv4_zero).await.unwrap(),
        RouteReadback::ExactPresent
    );
    backend.remove_converged_route(ipv4_zero).await.unwrap();

    let ipv6 = RouteRequest {
        destination: IpPrefix::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)),
            64,
        ),
        oif_ifindex: 1,
        table: 4_000_000_105,
        priority: None,
    };
    assert_eq!(
        backend.converge_route(ipv6.clone()).await.unwrap(),
        RouteConvergenceOutcome::Installed
    );
    let mut ipv6_zero = ipv6.clone();
    ipv6_zero.priority = Some(0);
    assert_eq!(
        backend.read_route(&ipv6_zero).await.unwrap(),
        RouteReadback::ExactPresent
    );
    backend.remove_converged_route(ipv6_zero).await.unwrap();

    let pair_route = RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 128)), 26),
        oif_ifindex: 1,
        table: 4_000_000_106,
        priority: Some(301),
    };
    let pair_rule = RuleRequest {
        source: Some(pair_route.destination),
        destination: None,
        fwmark: None,
        table: pair_route.table,
        priority: 30_106,
    };
    ip(&[
        "rule",
        "add",
        "priority",
        "30106",
        "from",
        "192.0.2.128/26",
        "table",
        "4000000107",
        "protocol",
        "99",
    ]);
    let worker = backend.clone();
    let route_for_worker = pair_route.clone();
    let rule_for_worker = pair_rule.clone();
    let task = tokio::spawn(async move {
        worker
            .converge_route_and_rule(route_for_worker, rule_for_worker)
            .await
    });
    tokio::task::yield_now().await;
    task.abort();

    let follower = backend.clone();
    let outcome = follower
        .converge_route_and_rule(pair_route.clone(), pair_rule.clone())
        .await
        .unwrap();
    assert_eq!(
        outcome.route,
        RouteConvergenceOutcome::InstalledThenRolledBack
    );
    assert!(matches!(outcome.rule, RuleConvergenceOutcome::Conflict(_)));
    assert_eq!(
        backend.read_route(&pair_route).await.unwrap(),
        RouteReadback::Absent
    );
    assert!(matches!(
        backend.read_rule(&pair_rule).await.unwrap(),
        RuleReadback::Conflict(_)
    ));
}
