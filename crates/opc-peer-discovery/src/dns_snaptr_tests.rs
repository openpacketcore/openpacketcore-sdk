//! Paused-time S-NAPTR scheduling and retry fixtures.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::*;

#[path = "../tests/support/snaptr_wire.rs"]
mod wire;
use wire::*;

struct FakeDns {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, u16)>>>,
    respond: Arc<super::super::TestDatagram>,
}

impl FakeDns {
    async fn new(respond: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static) -> Self {
        Self::new_async(move |q| std::future::ready(respond(&q))).await
    }

    async fn new_async<F, R>(respond: F) -> Self
    where
        F: Fn(Vec<u8>) -> R + Send + Sync + 'static,
        R: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        Self {
            address: "127.0.0.1:5353".parse().unwrap(),
            requests,
            respond: Arc::new(move |q| {
                let (owner, kind, _) = question(&q);
                seen.lock().unwrap().push((owner, kind));
                let response = respond(q);
                Box::pin(async move {
                    match response.await {
                        Some(response) => {
                            // Datagram delivery becomes ready on a later poll;
                            // a retry cannot synchronously send and consume it.
                            tokio::task::yield_now().await;
                            response
                        }
                        None => std::future::pending().await,
                    }
                })
            }),
        }
    }

    fn client(&self, config: DnsClientConfig) -> Result<DnsClient, DnsError> {
        let mut client = DnsClient::new(config)?;
        Arc::get_mut(&mut client.inner).unwrap().test_datagram = Some(self.respond.clone());
        Ok(client)
    }

    fn seen(&self) -> Vec<(String, u16)> {
        self.requests.lock().unwrap().clone()
    }
}

fn slow_first_dns(branch: &'static str) -> impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync {
    move |q| {
        let (owner, kind, _) = question(q);
        let silent = match branch {
            "delegation" | "srv-owner" => CHILD,
            "address" | "srv-target" => HOST,
            _ => unreachable!(),
        };
        if owner == silent {
            return None;
        }
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(
                    ROOT,
                    1,
                    0,
                    match branch {
                        "delegation" => "",
                        "address" => "a",
                        _ => "s",
                    },
                    SERVICE,
                    "",
                    if branch == "address" { HOST } else { CHILD },
                    900,
                ),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 900),
            ],
            (CHILD, 33) => vec![srv(CHILD, 0, 0, 2123, HOST, 900)],
            (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 900)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    }
}

fn assert_backtracked(response: DnsClientResponse, dns: &FakeDns, silent: &str) {
    assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.2:2123"
    );
    assert_eq!(answer.expires_at(), Some(time(301_000)));
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
    assert!(response.outcomes.iter().any(
        |outcome| outcome.owner.as_str() == silent && outcome.result == Err(DnsError::Timeout)
    ));
    assert!(dns.seen().iter().any(|(owner, _)| owner == OTHER));
}

async fn default_proportions_backtrack(branch: &'static str) {
    let dns = FakeDns::new(slow_first_dns(branch)).await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        // Keep the default attempts and automatic-budget proportions.
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_backtracked(
        response,
        &dns,
        if matches!(branch, "address" | "srv-target") {
            HOST
        } else {
            CHILD
        },
    );
}

#[tokio::test(start_paused = true)]
async fn slow_first_delegation_with_default_attempts_and_automatic_budget_backtracks() {
    default_proportions_backtrack("delegation").await;
}

#[tokio::test(start_paused = true)]
async fn slow_first_address_with_default_attempts_and_automatic_budget_backtracks() {
    default_proportions_backtrack("address").await;
}

#[tokio::test(start_paused = true)]
async fn slow_first_srv_owner_with_default_attempts_and_automatic_budget_backtracks() {
    default_proportions_backtrack("srv-owner").await;
}

#[tokio::test(start_paused = true)]
async fn slow_first_srv_target_with_default_attempts_and_automatic_budget_backtracks() {
    default_proportions_backtrack("srv-target").await;
}

#[tokio::test(start_paused = true)]
async fn slow_first_delegation_with_unmodified_default_limits_backtracks() {
    let dns = FakeDns::new(slow_first_dns("delegation")).await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        // No timeout, retry, concurrency, work-limit or overall-budget tuning.
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_backtracked(response, &dns, CHILD);
}

#[tokio::test(start_paused = true)]
async fn non_root_question_cap_leaves_backtracking_time_with_one_slot() {
    let dns = FakeDns::new(slow_first_dns("delegation")).await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_backtracked(response, &dns, CHILD);
}

#[tokio::test(start_paused = true)]
async fn sibling_scheduler_refills_free_slots_without_waiting_for_the_first_branch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let release_first = Arc::new(tokio::sync::Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(Mutex::new(Vec::new()));
    let dns = FakeDns::new_async({
        let release_first = release_first.clone();
        let active = active.clone();
        let peak = peak.clone();
        let finished = finished.clone();
        move |q| {
            let release_first = release_first.clone();
            let active = active.clone();
            let peak = peak.clone();
            let finished = finished.clone();
            async move {
                let (owner, kind, _) = question(&q);
                if kind == 35 {
                    return Some(reply(
                        &q,
                        0,
                        &(0..5)
                            .map(|i| {
                                naptr(
                                    ROOT,
                                    1,
                                    i,
                                    "a",
                                    SERVICE,
                                    "",
                                    &format!("host{i}.example.invalid."),
                                    900,
                                )
                            })
                            .collect::<Vec<_>>(),
                        &[],
                        &[],
                    ));
                }
                let i: u8 = owner
                    .strip_prefix("host")
                    .unwrap()
                    .split('.')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                if i == 0 {
                    release_first.notified().await;
                }
                finished.lock().unwrap().push(i);
                if i == 2 {
                    release_first.notify_one();
                }
                active.fetch_sub(1, Ordering::SeqCst);
                Some(reply(
                    &q,
                    0,
                    &[address(&owner, &format!("192.0.2.{}", i + 1), 900)],
                    &[],
                    &[],
                ))
            }
        }
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.timeout = Duration::from_millis(500);
    cfg.max_srv_concurrent_targets = 2;
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|candidate| candidate.peer().endpoint.to_string())
            .collect::<Vec<_>>(),
        (1..=5)
            .map(|i| format!("192.0.2.{i}:2123"))
            .collect::<Vec<_>>()
    );
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    let finished = finished.lock().unwrap();
    assert!(
        finished.iter().position(|i| *i == 2).unwrap()
            < finished.iter().position(|i| *i == 0).unwrap()
    );
}

#[tokio::test(start_paused = true)]
async fn healthy_nested_sibling_progresses_while_earlier_question_is_pending() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        if owner == CHILD {
            return None;
        }
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 2, 0, "", SERVICE, "", OTHER, 90),
            ],
            (OTHER, 35) => vec![naptr(OTHER, 1, 0, "a", SERVICE, "", HOST, 90)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.timeout = Duration::from_secs(1);
    cfg.snaptr_refresh_timeout = Duration::from_millis(100);
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:2123"
    );
    assert!(
        response
            .outcomes
            .iter()
            .any(|outcome| outcome.owner.as_str() == CHILD
                && outcome.result == Err(DnsError::Timeout))
    );
}

#[tokio::test(start_paused = true)]
async fn late_higher_rank_replaces_an_early_full_endpoint_pool() {
    for delegated in [false, true] {
        let lower_finished = Arc::new(tokio::sync::Notify::new());
        let dns = FakeDns::new_async(move |q| {
            let lower_finished = lower_finished.clone();
            async move {
                let (owner, kind, _) = question(&q);
                let answers = if owner == ROOT && kind == 35 {
                    vec![
                        naptr(
                            ROOT,
                            1,
                            0,
                            if delegated { "" } else { "a" },
                            SERVICE,
                            "",
                            if delegated { CHILD } else { HOST },
                            900,
                        ),
                        naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 900),
                    ]
                } else if owner == CHILD && kind == 35 {
                    lower_finished.notified().await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 900)]
                } else {
                    if owner == HOST && !delegated {
                        lower_finished.notified().await;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    } else if owner == OTHER {
                        lower_finished.notify_one();
                    }
                    let first = if owner == HOST { 1 } else { 17 };
                    (first..first + 16)
                        .map(|i| address(&owner, &format!("192.0.2.{i}"), 900))
                        .collect()
                };
                Some(reply(&q, 0, &answers, &[], &[]))
            }
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.timeout = Duration::from_millis(500);
        cfg.partial_failure_ttl = Duration::ZERO;
        let answer = dns
            .client(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await
            .result
            .unwrap();
        assert_eq!(
            answer
                .candidates()
                .iter()
                .map(|candidate| candidate.peer().endpoint.to_string())
                .collect::<Vec<_>>(),
            (1..=16)
                .map(|i| format!("192.0.2.{i}:2123"))
                .collect::<Vec<_>>()
        );
        assert_eq!(answer.expires_at(), Some(time(901_000)));
        assert_eq!(answer.snaptr_hosts().unwrap().len(), 1);
        assert_eq!(answer.snaptr_hosts().unwrap()[0].name().as_str(), HOST);
        assert!(answer.snaptr_coverage().unwrap().incomplete);
    }
}

#[tokio::test(start_paused = true)]
async fn malformed_unrelated_first_service_tokens_are_filtered_and_allow_diameter_fallback() {
    for services in ["bad_tag:x", "abcdefghijklmnopqrstuvwxyzabcdefg:x", "bäd:x"] {
        for matching in [false, true] {
            let dns = FakeDns::new(move |q| {
                let (owner, kind, _) = question(q);
                let answers = if kind == 35 {
                    let mut records = vec![naptr(REALM, 1, 0, "u", services, "ignored", ".", 90)];
                    if matching {
                        records.push(naptr(
                            REALM,
                            2,
                            0,
                            "a",
                            "aaa+ap16777264:diameter.sctp",
                            "",
                            HOST,
                            90,
                        ));
                    }
                    records
                } else {
                    vec![address(&owner, "192.0.2.1", 90)]
                };
                Some(reply(q, 0, &answers, &[], &[]))
            })
            .await;
            let q = query_for(REALM, "aaa+ap16777264", "diameter.sctp");
            let response = dns
                .client(config(dns.address))
                .unwrap()
                .resolve_with_seed(&q, now, 0)
                .await;
            assert!(response.snaptr_branches.is_empty(), "{services}");
            if matching {
                let answer = response.result.unwrap();
                assert_eq!(answer.candidates().len(), 1);
                assert_eq!(answer.snaptr_coverage().unwrap().filtered_records, 1);
                assert_eq!(answer.snaptr_coverage().unwrap().refused_branches, 0);
            } else {
                assert_eq!(
                    response.snaptr_root().unwrap().kind,
                    SnaptrRootKind::PresentNoMatch(SnaptrNoMatch::NotAdvertised)
                );
                let expected = DnsError::Snaptr {
                    reason: SnaptrFailure::NoMatchingService(SnaptrNoMatch::NotAdvertised),
                    expires_at: Some(time(91_000)),
                };
                assert_eq!(response.result, Err(expected));
                let mut cache = DnsCache::default();
                let token = start(&mut cache, &q, now());
                assert!(cache.finish_refresh(token, response.result, now()));
                assert_eq!(
                    cache.lookup(&q.cache_key(), now()).result,
                    DnsCachedResult::Negative(expected)
                );
                assert_eq!(dns.seen().len(), 1);
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn short_explicit_budget_reserves_backtracking_time_for_each_non_root_kind() {
    for branch in ["delegation", "address", "srv-owner", "srv-target"] {
        let dns = FakeDns::new(slow_first_dns(branch)).await;
        let cfg = DnsClientConfig {
            servers: vec![dns.address],
            timeout: Duration::from_secs(1),
            snaptr_refresh_timeout: Duration::from_millis(200),
            max_srv_concurrent_targets: 1,
            ..DnsClientConfig::default()
        };
        let response = dns
            .client(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await;
        assert_backtracked(
            response,
            &dns,
            if matches!(branch, "address" | "srv-target") {
                HOST
            } else {
                CHILD
            },
        );
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_questions_never_exceed_the_configured_ceiling() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for limit in [1, 2, 4] {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let dns = FakeDns::new_async({
            let active = active.clone();
            let peak = peak.clone();
            let received = received.clone();
            let release = release.clone();
            move |q| {
                let active = active.clone();
                let peak = peak.clone();
                let received = received.clone();
                let release = release.clone();
                async move {
                    let (owner, kind, _) = question(&q);
                    if kind == 35 {
                        return Some(reply(
                            &q,
                            0,
                            &(0..7)
                                .map(|i| {
                                    naptr(
                                        ROOT,
                                        i,
                                        0,
                                        "a",
                                        SERVICE,
                                        "",
                                        &format!("host{i}.example.invalid."),
                                        900,
                                    )
                                })
                                .collect::<Vec<_>>(),
                            &[],
                            &[],
                        ));
                    }
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    if count >= limit {
                        received.notify_one();
                    }
                    release.acquire().await.unwrap().forget();
                    active.fetch_sub(1, Ordering::SeqCst);
                    let i: u8 = owner
                        .strip_prefix("host")
                        .unwrap()
                        .split('.')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    Some(reply(
                        &q,
                        0,
                        &[address(&owner, &format!("192.0.2.{}", i + 1), 900)],
                        &[],
                        &[],
                    ))
                }
            }
        })
        .await;
        let mut cfg = config(dns.address);
        cfg.timeout = Duration::from_secs(1);
        cfg.max_srv_concurrent_targets = limit;
        let client = dns.client(cfg).unwrap();
        let q = query();
        let mut resolution = Box::pin(client.resolve_with_seed(&q, now, 0));
        tokio::select! {
            _ = &mut resolution => panic!("blocked questions completed"),
            _ = received.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("concurrency ceiling was not reached"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut resolution)
                .await
                .is_err()
        );
        assert_eq!(peak.load(Ordering::SeqCst), limit);
        assert_eq!(dns.seen().len(), 1 + limit);
        release.add_permits(7);
        assert_eq!(resolution.await.result.unwrap().candidates().len(), 7);
        assert!(peak.load(Ordering::SeqCst) <= limit);
    }
}

#[tokio::test(start_paused = true)]
async fn late_higher_rank_replaces_the_worst_alternate_path() {
    let release_first = Arc::new(tokio::sync::Notify::new());
    let dns = FakeDns::new_async(move |q| {
        let release_first = release_first.clone();
        async move {
            let (owner, kind, _) = question(&q);
            if kind == 35 {
                return Some(reply(
                    &q,
                    0,
                    &(0..7)
                        .map(|i| {
                            naptr(
                                ROOT,
                                i,
                                0,
                                "a",
                                SERVICE,
                                "",
                                &format!("host{i}.example.invalid."),
                                900,
                            )
                        })
                        .collect::<Vec<_>>(),
                    &[],
                    &[],
                ));
            }
            let i: u8 = owner
                .strip_prefix("host")
                .unwrap()
                .split('.')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            if i == 0 {
                release_first.notified().await;
            }
            if i == 6 {
                release_first.notify_one();
            }
            Some(reply(
                &q,
                0,
                &[address(&owner, "192.0.2.1", 90 + u32::from(i))],
                &[],
                &[],
            ))
        }
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.timeout = Duration::from_millis(500);
    cfg.partial_failure_ttl = Duration::ZERO;
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0]
            .snaptr()
            .unwrap()
            .paths()
            .iter()
            .map(|path| path.terminal_host().as_str())
            .collect::<Vec<_>>(),
        (0..4)
            .map(|i| format!("host{i}.example.invalid."))
            .collect::<Vec<_>>()
    );
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_paths, 3);
    assert_eq!(answer.snaptr_coverage().unwrap().omitted_hosts, 3);
    assert_eq!(answer.expires_at(), Some(time(91_000)));
}

#[tokio::test(start_paused = true)]
async fn pre_query_loop_refusal_does_not_spend_another_logical_lookup() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
            ],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "", SERVICE, "", ROOT, 90)],
            (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.max_snaptr_lookups = 3;
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    let coverage = answer.snaptr_coverage().unwrap();
    assert_eq!(coverage.refused_branches, 1);
    assert_eq!(coverage.failed_branches, 0);
    assert_eq!(coverage.unfinished_lookups, 0);
    assert_eq!(
        response.snaptr_branches[0].error,
        DnsError::Snaptr {
            reason: SnaptrFailure::Loop,
            expires_at: None
        }
    );
    assert_eq!(response.outcomes.len(), 3);
    assert_eq!(
        dns.seen().iter().filter(|(owner, _)| owner == ROOT).count(),
        1
    );
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn admitted_lower_branch_failure_is_reported_after_the_endpoint_pool_fills() {
    let lower_started = Arc::new(tokio::sync::Notify::new());
    let dns = FakeDns::new_async(move |q| {
        let lower_started = lower_started.clone();
        async move {
            let (owner, kind, _) = question(&q);
            let answers = if kind == 35 {
                vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 900),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 900),
                ]
            } else if owner == OTHER {
                lower_started.notify_one();
                tokio::time::sleep(Duration::from_millis(10)).await;
                return Some(reply(&q, 5, &[], &[], &[]));
            } else {
                lower_started.notified().await;
                (1..=16)
                    .map(|i| address(&owner, &format!("192.0.2.{i}"), 900))
                    .collect()
            };
            Some(reply(&q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.partial_failure_ttl = Duration::from_secs(2);
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert_eq!(answer.expires_at(), Some(time(901_000)));
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
    assert_eq!(answer.snaptr_coverage().unwrap().unvisited_branches, 0);
    assert!(
        response
            .outcomes
            .iter()
            .any(|outcome| outcome.owner.as_str() == OTHER
                && outcome.result == Err(DnsError::Refused))
    );
}

#[tokio::test(start_paused = true)]
async fn shared_in_flight_children_do_not_spend_the_record_budget_before_progressing() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => (0..32)
                .map(|i| naptr(ROOT, i, 0, "", SERVICE, "", CHILD, 90))
                .collect(),
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.edns_payload_size = 4096;
    cfg.max_snaptr_records = 32;
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 4);
    assert!(answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn silent_ipv6_family_keeps_ipv4_and_backtracking_time() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 900),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 900),
            ],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 900)],
            (HOST, 28) => return None,
            (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 900)],
            (OTHER, 28) => vec![address(OTHER, "2001:db8::2", 900)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_secs(1),
        snaptr_refresh_timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(
            &query().with_address_family(AddressFamilyPolicy::DualStack),
            now,
            0,
        )
        .await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|candidate| candidate.peer().endpoint.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.1:2123", "[2001:db8::2]:2123", "192.0.2.2:2123"]
    );
    assert_eq!(answer.expires_at(), Some(time(301_000)));
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
    assert!(response
        .outcomes
        .iter()
        .any(|outcome| outcome.owner.as_str() == HOST
            && outcome.record_type == DnsRecordType::Aaaa
            && outcome.result == Err(DnsError::Timeout)));
    assert_eq!(dns.seen().len(), 5);
}

#[tokio::test(start_paused = true)]
async fn root_question_keeps_the_default_retry_budget() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let roots = Arc::new(AtomicUsize::new(0));
    let received = roots.clone();
    let dns = FakeDns::new(move |q| {
        let (owner, kind, _) = question(q);
        let answers = if kind == 35 {
            if received.fetch_add(1, Ordering::SeqCst) == 0 {
                return None;
            }
            vec![naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 900)]
        } else {
            vec![address(&owner, "192.0.2.1", 900)]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(roots.load(Ordering::SeqCst), 2);
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn first_semantic_refusal_uses_path_rank_instead_of_arrival_order() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 2, 0, "u", SERVICE, "", HOST, 90),
            ],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "!bad!", HOST, 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let response = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let earlier = DnsError::Snaptr {
        reason: SnaptrFailure::RegexpNotEmpty,
        expires_at: None,
    };
    assert_eq!(response.result, Err(earlier));
    assert_eq!(response.snaptr_branches.len(), 2);
    assert_eq!(response.snaptr_branches[0].error, earlier);
    assert_eq!(
        response.snaptr_branches[1].error,
        DnsError::Snaptr {
            reason: SnaptrFailure::UnsupportedFlag,
            expires_at: None
        }
    );
    assert_eq!(dns.seen().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn late_higher_rank_failure_keeps_its_detail_when_the_trace_is_full() {
    let lower_started = Arc::new(tokio::sync::Notify::new());
    let dns = FakeDns::new_async(move |q| {
        let lower_started = lower_started.clone();
        async move {
            let (owner, kind, _) = question(&q);
            let (answers, additional) = match (owner.as_str(), kind) {
                (ROOT, 35) => (
                    vec![
                        naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                        naptr(ROOT, 2, 0, "s", SERVICE, "", OTHER, 90),
                    ],
                    vec![],
                ),
                (CHILD, 35) => {
                    lower_started.notified().await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    return Some(reply(&q, 5, &[], &[], &[]));
                }
                (OTHER, 33) => {
                    lower_started.notify_one();
                    (
                        (0..8)
                            .map(|i| {
                                srv(OTHER, i, 0, 2123, &format!("alias{i}.example.invalid."), 90)
                            })
                            .collect(),
                        (0..8)
                            .map(|i| rr(&format!("alias{i}.example.invalid."), 5, 90, &name(HOST)))
                            .collect(),
                    )
                }
                _ => panic!("unexpected question {owner} {kind}"),
            };
            Some(reply(&q, 0, &answers, &[], &additional))
        }
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.edns_payload_size = 4096;
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    assert_eq!(
        response.result,
        Err(DnsError::Snaptr {
            reason: SnaptrFailure::NoUsablePath,
            expires_at: None
        })
    );
    assert_eq!(response.snaptr_branches.len(), 5);
    assert_eq!(response.snaptr_branches[0].error, DnsError::Refused);
    assert!(response.snaptr_branches[1..]
        .iter()
        .all(|branch| branch.error == DnsError::MalformedAnswer));
    assert_eq!(response.outcomes.len(), 3);
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn single_path_retries_a_lost_child_packet() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let children = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new_async({
        let children = children.clone();
        move |q| {
            let children = children.clone();
            async move {
                let (owner, kind, _) = question(&q);
                let answers = match (owner.as_str(), kind) {
                    (ROOT, 35) => vec![naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)],
                    (CHILD, 35) if children.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                    (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
                    (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                    _ => panic!("unexpected question {owner} {kind}"),
                };
                Some(reply(&q, 0, &answers, &[], &[]))
            }
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:2123"
    );
    assert_eq!(answer.expires_at(), Some(time(91_000)));
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(children.load(Ordering::SeqCst), 2);
    assert_eq!(dns.seen().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn single_slow_healthy_chain_uses_the_remaining_refresh_deadline() {
    let dns = FakeDns::new_async(|q| async move {
        let (owner, kind, _) = question(&q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90)],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
            (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        // Three answers use 330 ms of virtual time within the 400 ms budget.
        tokio::time::sleep(Duration::from_millis(110)).await;
        Some(reply(&q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:2123"
    );
    assert_eq!(answer.expires_at(), Some(time(91_000)));
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(dns.seen().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn question_recovers_its_remaining_deadline_when_siblings_finish() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let children = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new({
        let children = children.clone();
        move |q| {
            let (owner, kind, _) = question(q);
            let answers = match (owner.as_str(), kind) {
                (ROOT, 35) => vec![
                    naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                ],
                (CHILD, 35) if children.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
                (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 90)],
                _ => panic!("unexpected question {owner} {kind}"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(
        answer
            .candidates()
            .iter()
            .map(|candidate| candidate.peer().endpoint.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.1:2123", "192.0.2.2:2123"]
    );
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(children.load(Ordering::SeqCst), 2);
    assert_eq!(dns.seen().len(), 5);
}

#[tokio::test(start_paused = true)]
async fn shared_only_paths_retry_the_same_in_flight_question() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for concurrency in [1, 4] {
        let children = Arc::new(AtomicUsize::new(0));
        let dns = FakeDns::new({
            let children = children.clone();
            move |q| {
                let (owner, kind, _) = question(q);
                let answers = match (owner.as_str(), kind) {
                    (ROOT, 35) => vec![
                        naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                        naptr(ROOT, 2, 0, "", SERVICE, "", CHILD, 90),
                    ],
                    (CHILD, 35) if children.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                    (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
                    (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                    _ => panic!("unexpected question {owner} {kind}"),
                };
                Some(reply(q, 0, &answers, &[], &[]))
            }
        })
        .await;
        let cfg = DnsClientConfig {
            servers: vec![dns.address],
            timeout: Duration::from_millis(200),
            max_srv_concurrent_targets: concurrency,
            ..DnsClientConfig::default()
        };
        let answer = dns
            .client(cfg)
            .unwrap()
            .resolve_with_seed(&query(), now, 0)
            .await
            .result
            .unwrap();
        assert_eq!(answer.candidates().len(), 1, "concurrency={concurrency}");
        assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 2);
        assert!(!answer.snaptr_coverage().unwrap().incomplete);
        assert_eq!(children.load(Ordering::SeqCst), 2);
        assert_eq!(dns.seen().len(), 4);
    }
}

#[tokio::test(start_paused = true)]
async fn queued_alternative_reserves_no_more_than_one_exchange_timeout() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let children = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new({
        let children = children.clone();
        move |q| {
            let (owner, kind, _) = question(q);
            let answers = match (owner.as_str(), kind) {
                (ROOT, 35) => vec![
                    naptr(ROOT, 1, 0, "", SERVICE, "", CHILD, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                ],
                (CHILD, 35) if children.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
                (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 90)],
                _ => panic!("unexpected question {owner} {kind}"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        snaptr_refresh_timeout: Duration::from_secs(1),
        max_srv_concurrent_targets: 1,
        ..DnsClientConfig::default()
    };
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(children.load(Ordering::SeqCst), 2);
    assert_eq!(dns.seen().len(), 5);
}

#[tokio::test(start_paused = true)]
async fn lower_ranked_questions_are_not_started_after_the_pool_is_full() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
            ],
            (HOST, 1) => (1..=16)
                .map(|i| address(HOST, &format!("192.0.2.{i}"), 90))
                .collect(),
            (OTHER, 1) => vec![address(OTHER, "192.0.2.254", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.max_srv_concurrent_targets = 1;
    cfg.partial_failure_ttl = Duration::ZERO;
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 16);
    assert_eq!(answer.expires_at(), Some(time(91_000)));
    assert_eq!(dns.seen(), [(ROOT.to_owned(), 35), (HOST.to_owned(), 1)]);
    assert_eq!(answer.snaptr_coverage().unwrap().unvisited_branches, 1);
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 0);
}

#[tokio::test(start_paused = true)]
async fn an_exhausted_address_allowance_does_not_cap_the_only_usable_question() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hosts = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new({
        let hosts = hosts.clone();
        move |q| {
            let (owner, kind, _) = question(q);
            let answers = match (owner.as_str(), kind) {
                (ROOT, 35) => vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                ],
                (HOST, 1) if hosts.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                _ => panic!("unexpected question {owner} {kind}"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        max_srv_address_lookups: 1,
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(hosts.load(Ordering::SeqCst), 2);
    assert_eq!(dns.seen().len(), 3);
    assert!(response.outcomes.iter().any(|outcome| {
        outcome.owner.as_str() == OTHER && outcome.result == Err(DnsError::LimitExceeded)
    }));
}

#[tokio::test(start_paused = true)]
async fn admitted_failure_freshness_depends_on_rank_and_a_full_prefix() {
    for size in [15, 16] {
        for failed_first in [false, true] {
            for rcode in [Some(5), Some(3), None] {
                let failure_started = Arc::new(tokio::sync::Notify::new());
                let dns = FakeDns::new_async(move |q| {
                    let failure_started = failure_started.clone();
                    async move {
                        let (owner, kind, _) = question(&q);
                        let answers = match (owner.as_str(), kind) {
                            (ROOT, 35) => vec![
                                naptr(
                                    ROOT,
                                    if failed_first { 2 } else { 1 },
                                    0,
                                    "a",
                                    SERVICE,
                                    "",
                                    HOST,
                                    900,
                                ),
                                naptr(
                                    ROOT,
                                    if failed_first { 1 } else { 2 },
                                    0,
                                    "a",
                                    SERVICE,
                                    "",
                                    OTHER,
                                    900,
                                ),
                            ],
                            (OTHER, 1) => {
                                failure_started.notify_one();
                                tokio::time::sleep(Duration::from_millis(20)).await;
                                return rcode.map(|code| {
                                    reply(&q, code, &[], &[soa("example.invalid.", 10, 10)], &[])
                                });
                            }
                            (HOST, 1) => {
                                failure_started.notified().await;
                                (1..=size)
                                    .map(|i| address(HOST, &format!("192.0.2.{i}"), 900))
                                    .collect()
                            }
                            _ => panic!("unexpected question {owner} {kind}"),
                        };
                        Some(reply(&q, 0, &answers, &[], &[]))
                    }
                })
                .await;
                let mut cfg = config(dns.address);
                cfg.partial_failure_ttl = Duration::from_secs(2);
                let response = dns
                    .client(cfg)
                    .unwrap()
                    .resolve_with_seed(&query(), now, 0)
                    .await;
                let answer = response.result.unwrap();
                let expected = if size == 16 && !failed_first {
                    time(901_000)
                } else if rcode == Some(3) {
                    time(11_000)
                } else {
                    time(3_000)
                };
                assert_eq!(answer.candidates().len(), size);
                assert_eq!(
                    answer.expires_at(),
                    Some(expected),
                    "size={size} failed_first={failed_first} rcode={rcode:?}"
                );
                assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
                assert_eq!(response.snaptr_branches.len(), 1);
                assert!(response
                    .outcomes
                    .iter()
                    .any(|outcome| outcome.owner.as_str() == OTHER && outcome.result.is_err()));
                assert_eq!(dns.seen().len(), 3);
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_short_budget_keeps_healthy_queued_branches() {
    let dns = FakeDns::new_async(|q| async move {
        let (owner, kind, _) = question(&q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
            ],
            (HOST | OTHER, 1) => {
                tokio::time::sleep(Duration::from_millis(60)).await;
                vec![address(
                    &owner,
                    if owner == HOST {
                        "192.0.2.1"
                    } else {
                        "192.0.2.2"
                    },
                    90,
                )]
            }
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(&q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_secs(1),
        snaptr_refresh_timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        ..DnsClientConfig::default()
    };
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert_eq!(answer.expires_at(), Some(time(91_000)));
    assert!(!answer.snaptr_coverage().unwrap().incomplete);
    assert_eq!(
        dns.seen(),
        [
            (ROOT.to_owned(), 35),
            (HOST.to_owned(), 1),
            (OTHER.to_owned(), 1)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn single_terminal_questions_keep_their_configured_retries() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for lost in [0, 1, 2, 3] {
        let drops = Arc::new(AtomicUsize::new(0));
        let dns = FakeDns::new({
            let drops = drops.clone();
            move |q| {
                let (owner, kind, _) = question(q);
                let lost_key = match lost {
                    1 => (CHILD, 33),
                    3 => (HOST, 28),
                    _ => (HOST, 1),
                };
                if (owner.as_str(), kind) == lost_key && drops.fetch_add(1, Ordering::SeqCst) == 0 {
                    return None;
                }
                let answers = match (owner.as_str(), kind) {
                    (ROOT, 35) if lost == 1 || lost == 2 => {
                        vec![naptr(ROOT, 1, 0, "s", SERVICE, "", CHILD, 90)]
                    }
                    (ROOT, 35) => vec![naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90)],
                    (CHILD, 33) => vec![srv(CHILD, 0, 0, 2123, HOST, 90)],
                    (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                    (HOST, 28) => vec![address(HOST, "2001:db8::1", 90)],
                    _ => panic!("unexpected question {owner} {kind}"),
                };
                Some(reply(q, 0, &answers, &[], &[]))
            }
        })
        .await;
        let cfg = DnsClientConfig {
            servers: vec![dns.address],
            timeout: Duration::from_millis(200),
            ..DnsClientConfig::default()
        };
        let query = query().with_address_family(if lost == 3 {
            AddressFamilyPolicy::Ipv6Only
        } else {
            AddressFamilyPolicy::Ipv4Only
        });
        let answer = dns
            .client(cfg)
            .unwrap()
            .resolve_with_seed(&query, now, 0)
            .await
            .result
            .unwrap();
        assert_eq!(answer.candidates().len(), 1, "lost={lost}");
        assert_eq!(answer.expires_at(), Some(time(91_000)));
        assert!(!answer.snaptr_coverage().unwrap().incomplete);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(dns.seen().len(), if lost == 1 || lost == 2 { 4 } else { 3 });
    }
}

#[tokio::test(start_paused = true)]
async fn cached_delegations_to_the_same_question_do_not_cut_its_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for flag in ["", "s"] {
        for dual_stack in [false, true] {
            let hosts = Arc::new(AtomicUsize::new(0));
            let dns = FakeDns::new({
                let hosts = hosts.clone();
                move |q| {
                    let (owner, kind, _) = question(q);
                    if owner == HOST
                        && kind == if dual_stack { 28 } else { 1 }
                        && hosts.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        return None;
                    }
                    let answers = match (owner.as_str(), kind) {
                        (ROOT, 35) => vec![
                            naptr(ROOT, 1, 0, flag, SERVICE, "", CHILD, 90),
                            naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
                            naptr(ROOT, 3, 0, flag, SERVICE, "", CHILD, 90),
                        ],
                        (CHILD, 35) => vec![naptr(CHILD, 1, 0, "a", SERVICE, "", HOST, 90)],
                        (CHILD, 33) => vec![srv(CHILD, 0, 0, 2123, HOST, 90)],
                        (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                        (HOST, 28) => vec![address(HOST, "2001:db8::1", 90)],
                        _ => panic!("unexpected question {owner} {kind}"),
                    };
                    Some(reply(q, 0, &answers, &[], &[]))
                }
            })
            .await;
            let cfg = DnsClientConfig {
                servers: vec![dns.address],
                timeout: Duration::from_millis(200),
                max_srv_concurrent_targets: 1,
                ..DnsClientConfig::default()
            };
            let query = query().with_address_family(if dual_stack {
                AddressFamilyPolicy::DualStack
            } else {
                AddressFamilyPolicy::Ipv4Only
            });
            let answer = dns
                .client(cfg)
                .unwrap()
                .resolve_with_seed(&query, now, 0)
                .await
                .result
                .unwrap();
            assert_eq!(
                answer.candidates().len(),
                if dual_stack { 2 } else { 1 },
                "flag={flag} dual_stack={dual_stack}"
            );
            assert!(answer.candidates().iter().all(|candidate| candidate
                .snaptr()
                .unwrap()
                .paths()
                .len()
                == 3));
            assert!(!answer.snaptr_coverage().unwrap().incomplete);
            assert_eq!(hosts.load(Ordering::SeqCst), 2);
            assert_eq!(dns.seen().len(), if dual_stack { 5 } else { 4 });
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_cached_delegation_can_still_offer_an_independent_alternative() {
    const DEEP: &str = "deep.example.invalid.";
    const LEAF: &str = "leaf.example.invalid.";
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT, 35) => vec![
                naptr(ROOT, 1, 0, "", SERVICE, "", DEEP, 90),
                naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 3, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 4, 0, "", SERVICE, "", CHILD, 90),
            ],
            (DEEP, 35) => vec![naptr(DEEP, 1, 0, "", SERVICE, "", CHILD, 90)],
            (CHILD, 35) => vec![naptr(CHILD, 1, 0, "", SERVICE, "", LEAF, 90)],
            (LEAF, 35) => vec![naptr(LEAF, 1, 0, "a", SERVICE, "", OTHER, 90)],
            (HOST, 1) => return None,
            (OTHER, 1) => vec![address(OTHER, "192.0.2.2", 90)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        max_snaptr_depth: 3,
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.2:2123"
    );
    assert!(response.snaptr_branches.iter().any(|branch| matches!(
        branch.error,
        DnsError::Snaptr {
            reason: SnaptrFailure::DepthLimit,
            ..
        }
    )));
    assert!(response
        .outcomes
        .iter()
        .any(|outcome| outcome.owner.as_str() == HOST && outcome.result == Err(DnsError::Timeout)));
    assert!(dns.seen().contains(&(LEAF.to_owned(), 35)));
    assert!(dns.seen().contains(&(OTHER.to_owned(), 1)));
}

#[tokio::test(start_paused = true)]
async fn queued_duplicates_use_the_lookup_allowance_before_a_new_alternative() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hosts = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new({
        let hosts = hosts.clone();
        move |q| {
            let (owner, kind, _) = question(q);
            let answers = match (owner.as_str(), kind) {
                (ROOT, 35) => vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 3, 0, "a", SERVICE, "", OTHER, 90),
                ],
                (HOST, 1) if hosts.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                (HOST, 1) => vec![address(HOST, "192.0.2.1", 90)],
                _ => panic!("unexpected question {owner} {kind}"),
            };
            Some(reply(q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        max_srv_concurrent_targets: 1,
        max_snaptr_lookups: 3,
        ..DnsClientConfig::default()
    };
    let answer = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await
        .result
        .unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(answer.candidates()[0].snaptr().unwrap().paths().len(), 2);
    assert_eq!(hosts.load(Ordering::SeqCst), 2);
    assert_eq!(
        dns.seen(),
        [
            (ROOT.to_owned(), 35),
            (HOST.to_owned(), 1),
            (HOST.to_owned(), 1)
        ]
    );
    assert_eq!(answer.snaptr_coverage().unwrap().unfinished_lookups, 1);
}

#[tokio::test(start_paused = true)]
async fn short_refresh_budget_keeps_healthy_siblings_and_records_the_failed_branch() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        if owner == CHILD {
            return None;
        }
        let answers = if kind == 35 {
            vec![
                naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                naptr(ROOT, 2, 0, "", SERVICE, "", CHILD, 90),
                naptr(ROOT, 3, 0, "a", SERVICE, "", OTHER, 90),
            ]
        } else {
            vec![address(
                &owner,
                if owner == HOST {
                    "192.0.2.1"
                } else {
                    "192.0.2.2"
                },
                90,
            )]
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let mut cfg = config(dns.address);
    cfg.snaptr_refresh_timeout = Duration::from_millis(30);
    cfg.partial_failure_ttl = Duration::from_secs(2);
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 2);
    assert_eq!(answer.expires_at(), Some(time(3_000)));
    // After both healthy siblings finish, the only remaining question keeps
    // the full refresh deadline instead of being cut for backtracking.
    assert_eq!(answer.snaptr_coverage().unwrap().unfinished_lookups, 1);
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
    assert_eq!(answer.snaptr_coverage().unwrap().unvisited_branches, 0);
    assert!(response
        .outcomes
        .iter()
        .any(|o| o.owner.as_str() == CHILD && o.result == Err(DnsError::Timeout)));
    assert!(dns.seen().iter().any(|(owner, _)| owner == OTHER));
}

#[tokio::test(start_paused = true)]
async fn running_dead_sibling_does_not_cut_a_healthy_retry() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hosts = Arc::new(AtomicUsize::new(0));
    let dns = FakeDns::new_async({
        let hosts = hosts.clone();
        move |q| {
            let hosts = hosts.clone();
            async move {
                let (owner, kind, _) = question(&q);
                let answers = match (owner.as_str(), kind) {
                    (ROOT, 35) => vec![
                        naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                        naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                    ],
                    (HOST, 1) if hosts.fetch_add(1, Ordering::SeqCst) == 0 => return None,
                    (HOST, 1) => {
                        // The retried datagram becomes ready on the next poll.
                        // This is scheduler ordering, not elapsed host time.
                        tokio::task::yield_now().await;
                        vec![address(HOST, "192.0.2.1", 90)]
                    }
                    (OTHER, 1) => return None,
                    _ => panic!("unexpected question {owner} {kind}"),
                };
                Some(reply(&q, 0, &answers, &[], &[]))
            }
        }
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:2123"
    );
    assert_eq!(hosts.load(Ordering::SeqCst), 2);
    assert!(
        response
            .outcomes
            .iter()
            .any(|outcome| outcome.owner.as_str() == OTHER
                && outcome.result == Err(DnsError::Timeout))
    );
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
}

#[tokio::test(start_paused = true)]
async fn running_dead_sibling_does_not_cut_a_slow_healthy_answer() {
    let dns = FakeDns::new_async(|q| async move {
        let (owner, kind, _) = question(&q);
        let (delay, answers) = match (owner.as_str(), kind) {
            (ROOT, 35) => (
                100,
                vec![
                    naptr(ROOT, 1, 0, "a", SERVICE, "", HOST, 90),
                    naptr(ROOT, 2, 0, "a", SERVICE, "", OTHER, 90),
                ],
            ),
            (HOST, 1) => (180, vec![address(HOST, "192.0.2.1", 90)]),
            (OTHER, 1) => return None,
            _ => panic!("unexpected question {owner} {kind}"),
        };
        // Virtual time reproduces the deadline ordering without a host-clock margin.
        tokio::time::sleep(Duration::from_millis(delay)).await;
        Some(reply(&q, 0, &answers, &[], &[]))
    })
    .await;
    let cfg = DnsClientConfig {
        servers: vec![dns.address],
        timeout: Duration::from_millis(200),
        ..DnsClientConfig::default()
    };
    let response = dns
        .client(cfg)
        .unwrap()
        .resolve_with_seed(&query(), now, 0)
        .await;
    let answer = response.result.unwrap();
    assert_eq!(answer.candidates().len(), 1);
    assert_eq!(
        answer.candidates()[0].peer().endpoint.to_string(),
        "192.0.2.1:2123"
    );
    assert_eq!(
        dns.seen()
            .iter()
            .filter(|(owner, kind)| owner == HOST && *kind == 1)
            .count(),
        1
    );
    assert!(
        response
            .outcomes
            .iter()
            .any(|outcome| outcome.owner.as_str() == OTHER
                && outcome.result == Err(DnsError::Timeout))
    );
    assert_eq!(answer.snaptr_coverage().unwrap().failed_branches, 1);
}
