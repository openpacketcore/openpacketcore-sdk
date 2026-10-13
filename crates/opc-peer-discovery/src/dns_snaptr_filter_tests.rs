//! Filtering exercises the resolver's completed paths through injected DNS I/O.
use super::*;

const ROOT_FILTER: &str = "discovery.example.invalid.";
const SERVICES: &str = "x-example:x-test";
const U: &str = "u.example.invalid.";
const B: &str = "b.example.invalid.";
const A: &str = "a.example.invalid.";
const F: &str = "failed.example.invalid.";

fn filter_query() -> DnsQuery {
    query_for(ROOT_FILTER, "x-example", "x-test")
}

async fn three_hosts(ttls: [u32; 3]) -> (FakeDns, DnsClientResponse) {
    let dns = FakeDns::new(move |q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT_FILTER, 35) => [U, B, A]
                .into_iter()
                .enumerate()
                .map(|(i, host)| {
                    naptr(
                        ROOT_FILTER,
                        (i as u16 + 1) * 10,
                        0,
                        "a",
                        SERVICES,
                        "",
                        host,
                        900,
                    )
                })
                .collect(),
            (U, 1) => vec![address(U, "192.0.2.1", ttls[0])],
            (B, 1) => vec![address(B, "192.0.2.2", ttls[1])],
            (A, 1) => vec![address(A, "192.0.2.1", ttls[2])],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let response = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&filter_query(), now, 0)
        .await;
    (dns, response)
}

fn selections(answer: &DnsAnswer) -> Vec<(String, String)> {
    answer
        .candidates()
        .iter()
        .map(|candidate| {
            (
                candidate.snaptr().unwrap().paths()[0]
                    .terminal_host()
                    .as_str()
                    .to_owned(),
                candidate.peer().endpoint.to_string(),
            )
        })
        .collect()
}

fn expected(rows: &[(&str, &str)]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn check_references(answer: &DnsAnswer) {
    let hosts = answer.snaptr_hosts().unwrap();
    let mut counts: Vec<Vec<usize>> = answer
        .candidates()
        .iter()
        .map(|c| vec![0; c.snaptr().unwrap().paths().len()])
        .collect();
    for host in hosts {
        assert_eq!(host.rank(), host.addresses()[0].candidate_index());
        let mut previous = None;
        for address in host.addresses() {
            let index = address.candidate_index();
            assert!(previous.is_none_or(|old| old < index));
            previous = Some(index);
            let candidate = &answer.candidates()[index];
            assert_eq!(host.port(), candidate.peer().endpoint.port());
            assert_eq!(host.transport(), candidate.peer().transport);
            for &path in address.path_indices() {
                assert_eq!(
                    candidate.snaptr().unwrap().paths()[path].terminal_host(),
                    host.name()
                );
                counts[index][path] += 1;
            }
        }
    }
    assert!(counts.iter().flatten().all(|count| *count == 1));
    for (i, candidate) in answer.candidates().iter().enumerate() {
        assert_eq!(candidate.peer().weight, u16::MAX - i as u16);
        assert_eq!(
            candidate.records(),
            Some(candidate.snaptr().unwrap().paths()[0].records())
        );
    }
}

#[tokio::test(start_paused = true)]
async fn path_filter_promotes_the_surviving_path_and_next_endpoint() {
    let (dns, response) = three_hosts([90; 3]).await;
    let original = response.result.as_ref().unwrap();
    assert_eq!(
        selections(original),
        expected(&[(U, "192.0.2.1:2123"), (B, "192.0.2.2:2123")])
    );
    let seen = dns.seen();
    let filtered = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    assert_eq!(
        selections(&filtered),
        expected(&[(B, "192.0.2.2:2123"), (A, "192.0.2.1:2123")])
    );
    let next = filtered
        .candidates()
        .iter()
        .find(|c| c.peer().endpoint.ip().to_string() != "192.0.2.2")
        .unwrap();
    assert_eq!(
        next.snaptr().unwrap().paths()[0].terminal_host().as_str(),
        A
    );
    assert_eq!(next.records().unwrap().last().unwrap().owner.as_str(), A);
    assert!(!filtered
        .snaptr_hosts()
        .unwrap()
        .iter()
        .any(|h| h.name().as_str() == U));
    assert_eq!(dns.seen(), seen);
    check_references(&filtered);
    let alternate_removed = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != A)
        .unwrap()
        .unwrap();
    assert_eq!(selections(&alternate_removed), selections(original));
    assert_eq!(
        alternate_removed.candidates()[0]
            .snaptr()
            .unwrap()
            .paths()
            .len(),
        1
    );
    check_references(&alternate_removed);
}

#[tokio::test(start_paused = true)]
async fn path_filter_callbacks_follow_original_traversal_once_and_pure_filters_compose() {
    let (_, response) = three_hosts([90; 3]).await;
    let original = response.result.unwrap();
    let mut visited = Vec::new();
    assert_eq!(
        original
            .filter_snaptr_paths(|p| {
                visited.push(p.terminal_host().as_str().to_owned());
                true
            })
            .unwrap(),
        Some(original.clone())
    );
    assert_eq!(visited, vec![U, B, A]);
    let no_u = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    let composed = no_u
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != B)
        .unwrap();
    let together = original
        .filter_snaptr_paths(|p| ![U, B].contains(&p.terminal_host().as_str()))
        .unwrap();
    assert_eq!(composed, together);
    assert_eq!(
        selections(together.as_ref().unwrap()),
        expected(&[(A, "192.0.2.1:2123")])
    );
    assert_eq!(original.filter_snaptr_paths(|_| false).unwrap(), None);
}

fn publish(query: &DnsQuery, answer: &DnsAnswer) -> DnsCache {
    let mut cache = DnsCache::default();
    let DnsRefresh::Start(token) = cache
        .begin_refresh(query, now(), Duration::from_secs(1))
        .unwrap()
    else {
        panic!("refresh was not admitted");
    };
    assert!(cache.finish_refresh(token, Ok(answer.clone()), now()));
    cache
}

#[tokio::test(start_paused = true)]
async fn path_filter_cached_authority_changes_preserve_fresh_stale_and_retry_state() {
    let (dns, response) = three_hosts([1, 90, 90]).await;
    let original = response.result.as_ref().unwrap();
    let query = filter_query();
    let mut cache = publish(&query, original);
    for at in [now(), time(2_001)] {
        let before = cache.lookup(&query.cache_key(), at);
        let cached = match &before.result {
            DnsCachedResult::Fresh(answer) => {
                assert_eq!(at, now());
                answer
            }
            DnsCachedResult::Stale { answer, .. } => {
                assert_eq!(at, time(2_001));
                answer
            }
            _ => panic!("expected original cached positive"),
        };
        let seen = dns.seen();
        assert_eq!(
            cached.filter_snaptr_paths(|_| true).unwrap().as_ref(),
            Some(original)
        );
        let no_u = cached
            .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
            .unwrap()
            .unwrap();
        assert_eq!(
            selections(&no_u),
            expected(&[(B, "192.0.2.2:2123"), (A, "192.0.2.1:2123")])
        );
        assert_eq!(no_u.expires_at(), Some(time(91_000)));
        check_references(&no_u);
        let only_a = cached
            .filter_snaptr_paths(|p| p.terminal_host().as_str() == A)
            .unwrap()
            .unwrap();
        assert_eq!(selections(&only_a), expected(&[(A, "192.0.2.1:2123")]));
        check_references(&only_a);
        assert!(cached.filter_snaptr_paths(|_| false).unwrap().is_none());
        let reallowed = cached.filter_snaptr_paths(|_| true).unwrap().unwrap();
        assert_eq!(&reallowed, original);
        assert_eq!(cache.lookup(&query.cache_key(), at), before);
        assert_eq!(dns.seen(), seen);
    }
    let DnsRefresh::Start(token) = cache
        .begin_refresh(&query, time(2_001), Duration::from_secs(1))
        .unwrap()
    else {
        panic!("refresh");
    };
    assert!(cache.finish_refresh(token, Err(DnsError::Timeout), time(2_002)));
    let before = cache.lookup(&query.cache_key(), time(2_002));
    assert_eq!(before.last_error, Some(DnsError::Timeout));
    original.filter_snaptr_paths(|_| false).unwrap();
    assert_eq!(cache.lookup(&query.cache_key(), time(2_002)), before);
    assert_eq!(response.snaptr_root().unwrap().kind, SnaptrRootKind::Match);
}

#[tokio::test(start_paused = true)]
async fn path_filter_keeps_absolute_record_deadlines_and_both_answer_bounds() {
    for short_ttl in [0, 1, 0x8000_0000] {
        let (_, response) = three_hosts([short_ttl, 90, 80]).await;
        let original = response.result.unwrap();
        let filtered = original
            .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
            .unwrap()
            .unwrap();
        assert_eq!(filtered.expires_at(), Some(time(81_000)));
        assert_eq!(
            original.expires_at(),
            Some(time(if short_ttl == 1 { 2_000 } else { 1_000 }))
        );
        tokio::time::advance(Duration::from_secs(100)).await;
        assert_eq!(
            original
                .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
                .unwrap(),
            Some(filtered.clone())
        );
        let only_u = original
            .filter_snaptr_paths(|p| p.terminal_host().as_str() == U)
            .unwrap()
            .unwrap();
        assert_eq!(only_u.expires_at(), original.expires_at());
        for (ordinary, negative, expiry) in [(4_000, 5_000, 4_000), (5_000, 4_000, 4_000)] {
            let bounded = original
                .clone()
                .with_freshness_bound(time(ordinary))
                .with_negative_freshness_bound(time(negative));
            let retained = bounded
                .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
                .unwrap()
                .unwrap();
            assert_eq!(retained.expires_at(), Some(time(expiry)));
            let cache = publish(&filter_query(), &retained);
            assert_eq!(
                cache.lookup(&filter_query().cache_key(), now()).fresh_until,
                Some(time(expiry))
            );
        }
        for candidate in filtered.candidates() {
            let matching = original
                .candidates()
                .iter()
                .find(|c| c.peer().endpoint == candidate.peer().endpoint)
                .unwrap();
            let path = &candidate.snaptr().unwrap().paths()[0];
            assert!(matching.snaptr().unwrap().paths().contains(path));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn path_filter_rejects_non_snaptr_and_incomplete_metadata_before_callbacks() {
    let (_, response) = three_hosts([90; 3]).await;
    let original = response.result.unwrap();
    let source = &original.candidates()[0];
    let mut invalid = vec![DnsAnswer::new(original.candidates().to_vec()).unwrap()];
    for mode in [
        ServiceDiscoveryMode::Address,
        ServiceDiscoveryMode::Service,
        ServiceDiscoveryMode::Snaptr,
    ] {
        let mut peer = source.peer().clone();
        peer.source = PeerCandidateSource::Resolver(mode);
        let candidate = DnsCandidate::new(peer, source.records().unwrap().to_vec()).unwrap();
        invalid.push(DnsAnswer::new(vec![candidate.clone()]).unwrap());
        invalid.push(DnsAnswer::new(vec![source.clone(), candidate]).unwrap());
    }
    invalid.push(DnsAnswer::new(vec![DnsCandidate::without_ttl(source.peer().clone())]).unwrap());
    let mut missing_rank = source.clone();
    missing_rank.snaptr.as_mut().unwrap().paths[0].rank = Box::default();
    let mut mixed = DnsAnswer::new(vec![source.clone(), missing_rank]).unwrap();
    mixed.snaptr_hosts = original.snaptr_hosts.clone();
    mixed.snaptr_coverage = original.snaptr_coverage;
    invalid.push(mixed);
    for answer in invalid {
        let mut calls = 0;
        assert_eq!(
            answer.filter_snaptr_paths(|_| {
                calls += 1;
                true
            }),
            Err(DnsError::InvalidQuery)
        );
        assert_eq!(calls, 0);
    }
}

async fn ordered_fixture(
    ordering: SnaptrOrdering,
    seed: u64,
    reverse_wire: bool,
    reverse_completion: bool,
    octets: [usize; 3],
    srv_mode: bool,
) -> (DnsAnswer, Vec<String>) {
    let completed = Arc::new(Mutex::new(Vec::new()));
    let trace = completed.clone();
    let dns = FakeDns::new_async(move |q| {
        let trace = trace.clone();
        async move {
            let (owner, kind, _) = question(&q);
            let mut answers = match (owner.as_str(), kind) {
                (ROOT_FILTER, 35) if srv_mode => vec![naptr(
                    ROOT_FILTER,
                    1,
                    0,
                    "s",
                    SERVICES,
                    "",
                    "_test._udp.example.invalid.",
                    900,
                )],
                ("_test._udp.example.invalid.", 33) => [U, B, A]
                    .into_iter()
                    .enumerate()
                    .map(|(i, host)| {
                        srv(
                            "_test._udp.example.invalid.",
                            0,
                            [0, 5, 9][i],
                            4040,
                            host,
                            900,
                        )
                    })
                    .collect(),
                (ROOT_FILTER, 35) => [U, B, A]
                    .into_iter()
                    .enumerate()
                    .map(|(i, host)| {
                        naptr(
                            ROOT_FILTER,
                            1,
                            if ordering == SnaptrOrdering::ThreeGpp {
                                [0, 32768, 65535][i]
                            } else {
                                7
                            },
                            "a",
                            SERVICES,
                            "",
                            host,
                            900,
                        )
                    })
                    .collect(),
                (U | B | A, 1) => {
                    let i = [U, B, A].iter().position(|h| *h == owner).unwrap();
                    tokio::time::sleep(Duration::from_millis(if reverse_completion {
                        (3 - i) as u64 * 10
                    } else {
                        (i + 1) as u64 * 10
                    }))
                    .await;
                    trace.lock().unwrap().push(owner.clone());
                    // Shared octets collapse hosts onto one endpoint and expose original path positions.
                    vec![address(&owner, &format!("192.0.2.{}", octets[i]), 900)]
                }
                _ => panic!("unexpected question {owner} {kind}"),
            };
            if reverse_wire {
                answers.reverse();
            }
            Some(reply(&q, 0, &answers, &[], &[]))
        }
    })
    .await;
    let query = filter_query()
        .with_snaptr_filter(SnaptrFilter::new("x-example", "x-test", ordering).unwrap())
        .unwrap();
    let answer = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&query, now, seed)
        .await
        .result
        .unwrap();
    let trace = completed.lock().unwrap().clone();
    (answer, trace)
}

#[tokio::test(start_paused = true)]
async fn path_filter_preserves_seeded_naptr_and_srv_draws_across_wire_and_completion_order() {
    for ordering in [SnaptrOrdering::Rfc3958, SnaptrOrdering::ThreeGpp] {
        for srv_mode in [false, true] {
            for seed in [0, 1, 7, 31] {
                let (control, forward) =
                    ordered_fixture(ordering, seed, false, false, [1, 2, 3], srv_mode).await;
                let host_order: Vec<_> = selections(&control).into_iter().map(|(h, _)| h).collect();
                assert_eq!(forward, vec![U, B, A]);
                for reverse_wire in [false, true] {
                    let (shared, reverse) =
                        ordered_fixture(ordering, seed, reverse_wire, true, [1, 1, 1], srv_mode)
                            .await;
                    assert_eq!(reverse, vec![A, B, U]);
                    let mut visited = Vec::new();
                    let retained = shared
                        .filter_snaptr_paths(|p| {
                            visited.push(p.terminal_host().as_str().to_owned());
                            p.terminal_host().as_str() != host_order[0]
                        })
                        .unwrap()
                        .unwrap();
                    assert_eq!(visited, host_order);
                    let paths = retained.candidates()[0].snaptr().unwrap().paths();
                    assert_eq!(
                        paths
                            .iter()
                            .map(|p| p.terminal_host().as_str())
                            .collect::<Vec<_>>(),
                        host_order[1..]
                    );
                    if srv_mode {
                        for path in paths {
                            let raw = path.srv().unwrap();
                            let i = [U, B, A]
                                .iter()
                                .position(|h| *h == path.terminal_host().as_str())
                                .unwrap();
                            assert_eq!(
                                (raw.priority(), raw.weight(), raw.port()),
                                (0, [0, 5, 9][i], 4040)
                            );
                        }
                    }
                    check_references(&retained);
                    // The first and last drawn hosts share X. Excluding the first must
                    // move the middle host's Y ahead of X; only retained draw positions show it.
                    let octets = [U, B, A].map(|h| if h == host_order[1] { 2 } else { 1 });
                    let (pair, _) =
                        ordered_fixture(ordering, seed, reverse_wire, true, octets, srv_mode).await;
                    let port = if srv_mode { 4040 } else { 2123 };
                    let (x, y) = (format!("192.0.2.1:{port}"), format!("192.0.2.2:{port}"));
                    assert_eq!(selections(&pair)[0].1, x);
                    let moved = pair
                        .filter_snaptr_paths(|p| p.terminal_host().as_str() != host_order[0])
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        selections(&moved),
                        expected(&[
                            (host_order[1].as_str(), y.as_str()),
                            (host_order[2].as_str(), x.as_str()),
                        ])
                    );
                    check_references(&moved);
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn path_filter_preserves_ancestor_precedence_over_child_numeric_order() {
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT_FILTER, 35) => vec![
                naptr(
                    ROOT_FILTER,
                    10,
                    0,
                    "",
                    SERVICES,
                    "",
                    "early.example.invalid.",
                    900,
                ),
                naptr(
                    ROOT_FILTER,
                    20,
                    0,
                    "",
                    SERVICES,
                    "",
                    "late.example.invalid.",
                    900,
                ),
            ],
            ("early.example.invalid.", 35) => vec![
                naptr(&owner, 100, 0, "a", SERVICES, "", U, 900),
                naptr(&owner, 900, 0, "a", SERVICES, "", B, 900),
            ],
            ("late.example.invalid.", 35) => vec![naptr(&owner, 1, 0, "a", SERVICES, "", A, 900)],
            (U | A, 1) => vec![address(&owner, "192.0.2.1", 900)],
            (B, 1) => vec![address(B, "192.0.2.2", 900)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let original = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&filter_query(), now, 0)
        .await
        .result
        .unwrap();
    let filtered = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    assert_eq!(
        selections(&filtered),
        expected(&[(B, "192.0.2.2:2123"), (A, "192.0.2.1:2123")])
    );
    assert_eq!(
        filtered.candidates()[0].snaptr().unwrap().paths()[0].hops()[1].order(),
        900
    );
    assert_eq!(
        filtered.candidates()[1].snaptr().unwrap().paths()[0].hops()[1].order(),
        1
    );
    check_references(&filtered);
}

#[tokio::test(start_paused = true)]
async fn path_filter_srv_priority_ports_and_multiple_addresses_keep_distinct_endpoints() {
    const SRV_OWNER: &str = "_test._udp.example.invalid.";
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT_FILTER, 35) => vec![naptr(ROOT_FILTER, 1, 0, "s", SERVICES, "", SRV_OWNER, 900)],
            (SRV_OWNER, 33) => vec![
                srv(SRV_OWNER, 1, 0, 4040, U, 900),
                srv(SRV_OWNER, 2, 5, 4040, B, 900),
                srv(SRV_OWNER, 3, 9, 4040, A, 900),
                srv(SRV_OWNER, 4, 0, 5050, A, 900),
            ],
            (U | A, 1) => vec![
                address(&owner, "192.0.2.1", 900),
                address(&owner, "192.0.2.2", 900),
            ],
            (B, 1) => vec![address(B, "192.0.2.3", 900)],
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let original = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&filter_query(), now, 3)
        .await
        .result
        .unwrap();
    let filtered = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    assert_eq!(
        selections(&filtered),
        expected(&[
            (B, "192.0.2.3:4040"),
            (A, "192.0.2.1:4040"),
            (A, "192.0.2.2:4040"),
            (A, "192.0.2.1:5050"),
            (A, "192.0.2.2:5050"),
        ])
    );
    for candidate in filtered.candidates() {
        let raw = candidate.snaptr().unwrap().paths()[0].srv().unwrap();
        assert_eq!(raw.port(), candidate.peer().endpoint.port());
        assert_eq!(
            raw.target(),
            candidate.snaptr().unwrap().paths()[0].terminal_host()
        );
    }
    check_references(&filtered);
}

#[tokio::test(start_paused = true)]
async fn path_filter_after_full_prefix_preserves_original_failure_scope_and_cache_schedule() {
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let dns = FakeDns::new_async(move |q| {
        let barrier = barrier.clone();
        async move {
            let (owner, kind, _) = question(&q);
            let answers = match (owner.as_str(), kind) {
                (ROOT_FILTER, 35) => [U, F, A]
                    .into_iter()
                    .enumerate()
                    .map(|(i, host)| {
                        naptr(
                            ROOT_FILTER,
                            (i as u16 + 1) * 10,
                            0,
                            "a",
                            SERVICES,
                            "",
                            host,
                            900,
                        )
                    })
                    .collect(),
                (U | F | A, 1) => {
                    barrier.wait().await;
                    match owner.as_str() {
                        U => (1..=16)
                            .map(|i| address(U, &format!("192.0.2.{i}"), 900))
                            .collect(),
                        F => {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            return Some(reply(&q, 5, &[], &[], &[]));
                        }
                        A => {
                            tokio::time::sleep(Duration::from_millis(40)).await;
                            vec![address(A, "192.0.2.1", 900)]
                        }
                        _ => unreachable!(),
                    }
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
        .resolve_with_seed(&filter_query(), now, 0)
        .await;
    let original = response.result.as_ref().unwrap();
    assert_eq!(original.candidates().len(), 16);
    assert_eq!(original.candidates()[0].snaptr().unwrap().paths().len(), 2);
    assert_eq!(original.expires_at(), Some(time(901_000)));
    assert_eq!(original.snaptr_coverage().unwrap().failed_branches, 1);
    assert!(original.snaptr_coverage().unwrap().incomplete);
    let diagnostics = (
        response.outcomes.clone(),
        response.snaptr_branches.clone(),
        response.snaptr_root().cloned(),
        response.sources.clone(),
    );
    let cache = publish(&filter_query(), original);
    let before = cache.lookup(&filter_query().cache_key(), now());
    let seen = dns.seen();
    let filtered = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    assert_eq!(selections(&filtered), expected(&[(A, "192.0.2.1:2123")]));
    assert_eq!(filtered.expires_at(), Some(time(901_000)));
    assert_eq!(filtered.snaptr_coverage(), original.snaptr_coverage());
    assert_eq!(
        (
            response.outcomes.clone(),
            response.snaptr_branches.clone(),
            response.snaptr_root().cloned(),
            response.sources.clone()
        ),
        diagnostics
    );
    assert!(response
        .outcomes
        .iter()
        .any(|o| o.owner.as_str() == F && o.result.is_err()));
    assert_eq!(cache.lookup(&filter_query().cache_key(), now()), before);
    assert_eq!(dns.seen(), seen);
    assert_eq!(
        original.filter_snaptr_paths(|_| true).unwrap().as_ref(),
        Some(original)
    );
    check_references(&filtered);
}

#[tokio::test(start_paused = true)]
async fn path_filter_keeps_omissions_refusals_failures_and_incomplete_host_flags() {
    const C: &str = "c.example.invalid.";
    let dns = FakeDns::new(|q| {
        let (owner, kind, _) = question(q);
        let answers = match (owner.as_str(), kind) {
            (ROOT_FILTER, 35) => {
                let mut records: Vec<_> = [U, B, A, C, B, F]
                    .into_iter()
                    .enumerate()
                    .map(|(i, host)| {
                        naptr(ROOT_FILTER, i as u16 + 1, 0, "a", SERVICES, "", host, 900)
                    })
                    .collect();
                records.push(naptr(
                    ROOT_FILTER,
                    0,
                    0,
                    "a",
                    SERVICES,
                    "!forbidden!",
                    "refused.example.invalid.",
                    900,
                ));
                records
            }
            (U | B | A | C, 1) => vec![address(&owner, "192.0.2.1", 900)],
            (F, 1) => return Some(reply(q, 5, &[], &[], &[])),
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(q, 0, &answers, &[], &[]))
    })
    .await;
    let original = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(&filter_query(), now, 0)
        .await
        .result
        .unwrap();
    let coverage = original.snaptr_coverage().unwrap();
    assert_eq!(coverage.omitted_paths, 1);
    assert_eq!(coverage.refused_branches, 1);
    assert_eq!(coverage.failed_branches, 1);
    assert!(coverage.incomplete);
    assert!(!original
        .snaptr_hosts()
        .unwrap()
        .iter()
        .find(|h| h.name().as_str() == B)
        .unwrap()
        .complete());
    assert_eq!(
        original.filter_snaptr_paths(|_| true).unwrap(),
        Some(original.clone())
    );
    let retained = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() != U)
        .unwrap()
        .unwrap();
    assert_eq!(retained.snaptr_coverage(), Some(coverage));
    assert_eq!(retained.expires_at(), original.expires_at());
    assert_eq!(retained.candidates()[0].snaptr().unwrap().paths().len(), 3);
    for host in retained.snaptr_hosts().unwrap() {
        let before = original
            .snaptr_hosts()
            .unwrap()
            .iter()
            .find(|old| old.name() == host.name() && old.port() == host.port())
            .unwrap();
        assert_eq!(host.complete(), before.complete());
    }
    check_references(&retained);
}

#[tokio::test(start_paused = true)]
async fn path_filter_retains_shared_rrset_minima_and_staggered_observations() {
    let start = tokio::time::Instant::now();
    let dns = FakeDns::new_async(|q| async move {
        let (owner, kind, _) = question(&q);
        let answers = match (owner.as_str(), kind) {
            (ROOT_FILTER, 35) => vec![
                naptr(ROOT_FILTER, 10, 0, "a", SERVICES, "", U, 2),
                naptr(ROOT_FILTER, 20, 0, "a", SERVICES, "", B, 900),
            ],
            (U, 1) => vec![address(U, "192.0.2.1", 900)],
            (B, 1) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                vec![address(B, "192.0.2.2", 900)]
            }
            _ => panic!("unexpected question {owner} {kind}"),
        };
        Some(reply(&q, 0, &answers, &[], &[]))
    })
    .await;
    let response = dns
        .client(config(dns.address))
        .unwrap()
        .resolve_with_seed(
            &filter_query(),
            || time(1_000 + start.elapsed().as_millis() as u64),
            0,
        )
        .await;
    let original = response.result.unwrap();
    let retained = original
        .filter_snaptr_paths(|p| p.terminal_host().as_str() == B)
        .unwrap()
        .unwrap();
    let records = retained.candidates()[0].records().unwrap();
    assert_eq!(records[0].observed_at, time(1_000));
    assert_eq!(records.last().unwrap().observed_at, time(1_500));
    assert_eq!(retained.expires_at(), Some(time(3_000)));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(
        retained.filter_snaptr_paths(|_| true).unwrap(),
        Some(retained.clone())
    );
    assert_eq!(retained.expires_at(), Some(time(3_000)));
}
