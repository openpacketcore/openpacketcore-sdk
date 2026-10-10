//! Replacement-only S-NAPTR traversal with bounded, ranked concurrent branches.

use std::collections::{HashMap, HashSet};
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;
use crate::dns_wire::{NaptrAnswer, NaptrRecord, SrvAnswer, SrvRecord};
use crate::{
    DiscoveryTarget, DnsName, DnsRecord, PeerCandidate, SnaptrBranchOutcome, SnaptrCoverage,
    SnaptrFailure, SnaptrFilter, SnaptrFlag, SnaptrHop, SnaptrHost, SnaptrHostAddress,
    SnaptrNoMatch, SnaptrOrdering, SnaptrPath, SnaptrProvenance, SnaptrRootKind,
    SnaptrRootObservation, SnaptrSrv,
};

fn refusal(reason: SnaptrFailure) -> DnsError {
    DnsError::Snaptr {
        reason,
        expires_at: None,
    }
}

fn matches_service(
    record: &NaptrRecord,
    filter: &SnaptrFilter,
) -> Result<Option<bool>, SnaptrFailure> {
    let mut fields = record.services.split(|byte| *byte == b':');
    let first = fields.next().unwrap_or_default();
    let relay = filter.diameter() && first.eq_ignore_ascii_case(b"aaa+ap4294967295");
    // An unrelated application is not parsed as S-NAPTR: ENUM/legacy grammar
    // and arbitrary regexp/flags must not poison an otherwise healthy answer.
    if !relay && !first.eq_ignore_ascii_case(filter.service().as_bytes()) {
        return Ok(None);
    }
    if !crate::snaptr::valid_tag(first) {
        return Err(SnaptrFailure::MalformedService);
    }
    let protocols: Vec<_> = fields.collect();
    if protocols.iter().any(|tag| !crate::snaptr::valid_tag(tag)) {
        return Err(SnaptrFailure::MalformedService);
    }
    if protocols.is_empty() && filter.diameter() {
        return Ok(Some(false));
    }
    Ok(protocols
        .iter()
        .any(|tag| tag.eq_ignore_ascii_case(filter.protocol().as_bytes()))
        .then_some(true))
}

#[derive(Clone)]
struct MatchedNaptr {
    record: NaptrRecord,
    advertised: Result<bool, SnaptrFailure>,
}

struct PreparedNaptr {
    records: Vec<MatchedNaptr>,
    chain: Vec<DnsRecord>,
    classification: SnaptrRootKind,
    filtered: usize,
}

type NaptrKey<'a> = (u16, u16, Vec<u8>, Vec<u8>, &'a [u8], Option<&'a str>);

fn record_key(record: &NaptrRecord) -> NaptrKey<'_> {
    (
        record.order,
        record.preference,
        record.flags.to_ascii_lowercase(),
        record.services.to_ascii_lowercase(),
        &record.regexp,
        record.replacement.as_ref().map(DnsName::as_str),
    )
}

fn prepare_naptr(
    mut answer: NaptrAnswer,
    filter: &SnaptrFilter,
    seed: u64,
) -> Result<PreparedNaptr, DnsError> {
    answer.records.sort_by(|a, b| {
        record_key(a)
            .cmp(&record_key(b))
            .then_with(|| a.services.cmp(&b.services))
            .then_with(|| a.flags.cmp(&b.flags))
    });
    answer
        .records
        .dedup_by(|a, b| record_key(a) == record_key(b));
    let mut records = Vec::new();
    let mut filtered = 0;
    let mut extended = false;
    let mut legacy = false;
    let mut malformed = false;
    let mut matched = false;
    for record in answer.records {
        let first = record
            .services
            .split(|byte| *byte == b':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        extended |= first.starts_with(b"aaa+ap");
        legacy |= matches!(first.as_slice(), b"aaa" | b"aaa+d2t" | b"aaa+d2s");
        let advertised = match matches_service(&record, filter) {
            Ok(Some(value)) => {
                matched = true;
                Ok(value)
            }
            Ok(None) => {
                filtered += 1;
                continue;
            }
            Err(error) => {
                malformed = true;
                Err(error)
            }
        };
        records.push(MatchedNaptr { record, advertised });
    }
    let classification = if matched {
        SnaptrRootKind::Match
    } else {
        SnaptrRootKind::PresentNoMatch(if malformed {
            SnaptrNoMatch::MalformedRequestedService
        } else if !filter.diameter() {
            SnaptrNoMatch::ServiceNotOffered
        } else if extended {
            SnaptrNoMatch::ExtendedPresentNoMatch
        } else if legacy {
            SnaptrNoMatch::LegacyOnly
        } else {
            SnaptrNoMatch::NotAdvertised
        })
    };
    let owner = &answer.chain.last().ok_or(DnsError::MalformedAnswer)?.owner;
    let seed = order::snaptr_seed(seed, 35, owner, filter);
    let records = match filter.ordering() {
        SnaptrOrdering::Rfc3958 => order::weighted_order(
            records,
            seed,
            |value| (value.record.order, value.record.preference),
            |_| 1,
        )?,
        SnaptrOrdering::ThreeGpp => order::weighted_order(
            records,
            seed,
            |value| value.record.order,
            |value| u16::MAX - value.record.preference,
        )?,
    };
    Ok(PreparedNaptr {
        records,
        chain: answer.chain,
        classification,
        filtered,
    })
}

fn hop(value: &MatchedNaptr) -> Result<SnaptrHop, DnsError> {
    let protocol_advertised = value.advertised.map_err(refusal)?;
    let record = &value.record;
    if !record.regexp.is_empty() {
        return Err(refusal(SnaptrFailure::RegexpNotEmpty));
    }
    let flag = match record.flags.as_ref() {
        [] => SnaptrFlag::Delegation,
        [b'a' | b'A'] => SnaptrFlag::Address,
        [b's' | b'S'] => SnaptrFlag::Service,
        _ => return Err(refusal(SnaptrFailure::UnsupportedFlag)),
    };
    let replacement = record
        .replacement
        .as_ref()
        .filter(|name| {
            name.as_str() != "."
                && name
                    .as_str()
                    .trim_end_matches('.')
                    .parse::<IpAddr>()
                    .is_err()
        })
        .ok_or_else(|| refusal(SnaptrFailure::InvalidReplacement))?
        .clone();
    Ok(SnaptrHop {
        order: record.order,
        preference: record.preference,
        flag,
        services: std::str::from_utf8(&record.services)
            .map_err(|_| refusal(SnaptrFailure::MalformedService))?
            .into(),
        replacement,
        protocol_advertised,
    })
}

#[derive(Clone)]
enum Parsed {
    Naptr(Arc<PreparedNaptr>),
    Srv(Arc<SrvAnswer>),
    Addresses(Arc<AddressData>),
}

struct AddressData {
    result: Result<Vec<DnsCandidate>, DnsError>,
    alias: bool,
}

#[derive(Clone)]
struct Evaluation {
    result: Result<Parsed, DnsError>,
    observed_at: PeerDiscoveryTime,
    counted: bool,
}

#[derive(Clone, Default)]
struct Path {
    records: Vec<DnsRecord>,
    hops: Vec<SnaptrHop>,
    visited: Vec<DnsName>,
    // Indices in the seeded NAPTR/SRV order, followed by the address index
    // for a completed path. Lexicographic order preserves ancestor priority.
    rank: Vec<usize>,
}

#[derive(Clone)]
enum Work {
    Naptr {
        owner: DnsName,
        path: Path,
        root: bool,
    },
    Hop {
        value: MatchedNaptr,
        path: Path,
    },
    NaptrRecords {
        answer: Arc<PreparedNaptr>,
        next: usize,
        path: Path,
    },
    Srv {
        owner: DnsName,
        path: Path,
    },
    SrvTarget {
        record: SrvRecord,
        answer: Arc<SrvAnswer>,
        path: Path,
    },
    SrvRecords {
        answer: Arc<SrvAnswer>,
        next: usize,
        path: Path,
    },
    Addresses {
        host: DnsName,
        port: u16,
        path: Path,
    },
    AddressFamily(Box<AddressWork>),
}

impl Work {
    fn path(&self) -> &Path {
        match self {
            Self::Naptr { path, .. }
            | Self::Hop { path, .. }
            | Self::NaptrRecords { path, .. }
            | Self::Srv { path, .. }
            | Self::SrvTarget { path, .. }
            | Self::SrvRecords { path, .. }
            | Self::Addresses { path, .. } => path,
            Self::AddressFamily(work) => &work.path,
        }
    }
}

#[derive(Clone)]
struct AddressWork {
    host: DnsName,
    port: u16,
    path: Path,
    srv: Option<(Arc<SrvAnswer>, SrvRecord)>,
    kinds: &'static [u16],
    next: usize,
    found: Vec<DnsCandidate>,
    family_outcomes: Vec<usize>,
    entirely_budget_blocked: bool,
}

#[derive(Clone)]
struct Question {
    owner: DnsName,
    kind: u16,
    root: bool,
    supplied: Option<(Result<Parsed, DnsError>, PeerDiscoveryTime)>,
}

#[derive(Clone)]
struct Task {
    work: Work,
    question: Option<Question>,
    evaluation: Option<Evaluation>,
}

impl Task {
    fn new(work: Work) -> Self {
        Self {
            work,
            question: None,
            evaluation: None,
        }
    }

    fn request(work: Work, question: Question) -> Self {
        Self {
            work,
            question: Some(question),
            evaluation: None,
        }
    }
}

struct Pending<F> {
    key: (DnsName, u16),
    future: Pin<Box<F>>,
    waiters: Vec<Task>,
    backtrack_at: Option<Pin<Box<tokio::time::Sleep>>>,
}

type LookupResult = (Evaluation, Option<DnsResponseSource>);

fn poll_questions<F: Future<Output = LookupResult>>(
    pending: &mut Vec<Pending<F>>,
    completed: &mut Vec<(Pending<F>, LookupResult)>,
    queued_network_work: bool,
    now: &impl Fn() -> PeerDiscoveryTime,
    cx: &mut Context<'_>,
) -> Poll<()> {
    let before = pending.len();
    let mut at = 0;
    while at < pending.len() {
        match pending[at].future.as_mut().poll(cx) {
            Poll::Ready(result) => completed.push((pending.remove(at), result)),
            Poll::Pending => at += 1,
        }
    }
    if pending.len() < before || pending.is_empty() {
        // Process completed branches before deciding whether another branch
        // still needs time. Do not cancel a retry whose only sibling finished.
        return Poll::Ready(());
    }
    for at in 0..pending.len() {
        if queued_network_work
            && pending[at]
                .backtrack_at
                .as_mut()
                .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            let evaluation = Evaluation {
                result: Err(DnsError::Timeout),
                observed_at: now(),
                counted: true,
            };
            // Recompute alternatives after each cancellation: the last
            // remaining question keeps its original transport future.
            completed.push((pending.remove(at), (evaluation, None)));
            return Poll::Ready(());
        }
    }
    Poll::Pending
}

#[derive(Clone)]
struct RankedPath {
    rank: Vec<usize>,
    value: SnaptrPath,
}

#[derive(Clone)]
struct Endpoint {
    peer: PeerCandidate,
    paths: Vec<RankedPath>,
}

#[derive(Clone)]
struct Traversal<'a> {
    client: &'a DnsClient,
    query: &'a DnsQuery,
    filter: &'a SnaptrFilter,
    seed: u64,
    session: srv::RefreshSession,
    memo: HashMap<(DnsName, u16), Evaluation>,
    response: DnsClientResponse,
    lookups: usize,
    expansions: usize,
    srv_records: usize,
    targets: HashSet<DnsName>,
    skipped_srv_targets: HashSet<DnsName>,
    visited_srv_targets: HashSet<DnsName>,
    address_lookups: usize,
    endpoints: Vec<Endpoint>,
    coverage: SnaptrCoverage,
    incomplete_hosts: HashSet<(DnsName, u16)>,
    omitted_hosts: HashSet<(DnsName, u16)>,
    freshness_bound: Option<PeerDiscoveryTime>,
    negative_bound: Option<PeerDiscoveryTime>,
    first_refusal: Option<(Vec<usize>, DnsError)>,
    budget_error: Option<DnsError>,
    current_rank: Vec<usize>,
    source_ranks: Vec<Vec<usize>>,
    outcome_ranks: Vec<Vec<usize>>,
    branch_ranks: Vec<Vec<usize>>,
    root_finished: bool,
}

impl Traversal<'_> {
    fn internal_query(&self, owner: &DnsName) -> Result<DnsQuery, DnsError> {
        let mut input = self.query.input().clone();
        input.target = DiscoveryTarget::new(owner.as_str());
        input.mode = ServiceDiscoveryMode::Address;
        // Neutral internal port allows memoization across SRV ports. Public
        // S-NAPTR validation already required a nonzero service default.
        input.default_port = Some(0);
        Ok(DnsQuery::new(input)?
            .with_address_family(self.query.address_family())
            .with_resolver_profile(self.query.resolver_profile().clone())
            .with_source_plane(self.query.source_plane().clone()))
    }

    fn exhausted(
        &mut self,
        error: DnsError,
        observed_at: PeerDiscoveryTime,
        counted: bool,
    ) -> Evaluation {
        if error == DnsError::Timeout || self.budget_error.is_none() {
            self.budget_error = Some(error);
        }
        self.coverage.unfinished_lookups += 1;
        Evaluation {
            result: Err(error),
            observed_at,
            counted,
        }
    }

    // Reserve logical and wire work before admitting a question. In-flight
    // duplicates consume logical allowance but share the same exchange.
    fn reserve(
        &mut self,
        question: &Question,
        in_flight: bool,
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> Option<Evaluation> {
        if self.lookups == self.client.inner.config.max_snaptr_lookups {
            return Some(self.exhausted(DnsError::LimitExceeded, now(), false));
        }
        self.lookups += 1;
        if tokio::time::Instant::now() >= self.session.deadline {
            return Some(self.exhausted(DnsError::Timeout, now(), true));
        }
        if let Some((result, observed_at)) = &question.supplied {
            return Some(Evaluation {
                result: result.clone(),
                observed_at: *observed_at,
                counted: true,
            });
        }
        if let Some(cached) = self.memo.get(&(question.owner.clone(), question.kind)) {
            return Some(cached.clone());
        }
        if !in_flight && matches!(question.kind, 1 | 28) {
            if self.address_lookups == self.client.inner.config.max_srv_address_lookups {
                return Some(self.exhausted(DnsError::LimitExceeded, now(), true));
            }
            self.address_lookups += 1;
        }
        None
    }

    async fn lookup(
        client: &DnsClient,
        query: Result<DnsQuery, DnsError>,
        filter: &SnaptrFilter,
        seed: u64,
        question: Question,
        deadline: tokio::time::Instant,
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> LookupResult {
        let query = match query {
            Ok(query) => query,
            Err(error) => {
                return (
                    Evaluation {
                        result: Err(error),
                        observed_at: now(),
                        counted: true,
                    },
                    None,
                )
            }
        };
        let config = &client.inner.config;
        // The scheduler may cancel for backtracking while another branch can
        // use the time. Keep the original deadline here so removing that cap
        // preserves the live exchange and its configured retries/fallbacks.
        let session = srv::RefreshSession { deadline };
        let kind = question.kind;
        let (result, source) = session
            .lookup(client, &query, kind, now, |message, at| {
                match kind {
                    35 => message
                        .naptr(&query, at, config.max_cname_chain)
                        .and_then(|answer| prepare_naptr(answer, filter, seed))
                        .map(|answer| Parsed::Naptr(Arc::new(answer))),
                    33 => {
                        let mut answer = message.srv(&query, at, config.max_cname_chain)?;
                        let owner = &answer.chain.last().ok_or(DnsError::MalformedAnswer)?.owner;
                        answer.records = srv::weighted_order(
                            std::mem::take(&mut answer.records),
                            order::snaptr_seed(seed, 33, owner, filter),
                        )?;
                        Ok(Parsed::Srv(Arc::new(answer)))
                    }
                    1 | 28 => {
                        let alias = message.target_is_alias(query.name());
                        let result = message.resolve(&query, kind, at, config.max_cname_chain);
                        // Even a data-less alias rejects the whole SRV target.
                        if alias {
                            Ok(Parsed::Addresses(Arc::new(AddressData { result, alias })))
                        } else {
                            result.map(|found| {
                                Parsed::Addresses(Arc::new(AddressData {
                                    result: Ok(found),
                                    alias,
                                }))
                            })
                        }
                    }
                    _ => Err(DnsError::InvalidQuery),
                }
            })
            .await;
        let observed_at = source
            .as_ref()
            .map_or_else(now, |source| source.observed_at);
        (
            Evaluation {
                result,
                observed_at,
                counted: true,
            },
            source,
        )
    }

    fn outcome(
        &mut self,
        owner: &DnsName,
        kind: u16,
        evaluation: &Evaluation,
        result: Result<(), DnsError>,
    ) {
        if !evaluation.counted {
            return;
        }
        if let Ok(record_type) = dns_wire::record_type(kind) {
            self.outcome_ranks.push(self.current_rank.clone());
            self.response.outcomes.push(DnsQueryOutcome {
                owner: owner.clone(),
                record_type,
                result,
                observed_at: evaluation.observed_at,
            });
        }
    }

    fn failed(&mut self, error: DnsError, records: &[DnsRecord], observed_at: PeerDiscoveryTime) {
        self.coverage.incomplete = true;
        let semantic = matches!(
            error,
            DnsError::Snaptr {
                reason: SnaptrFailure::UnsupportedFlag
                    | SnaptrFailure::RegexpNotEmpty
                    | SnaptrFailure::MalformedService
                    | SnaptrFailure::InvalidReplacement
                    | SnaptrFailure::Loop
                    | SnaptrFailure::DepthLimit
                    | SnaptrFailure::ProvenanceLimit,
                ..
            }
        );
        if semantic {
            self.coverage.refused_branches += 1;
            if self
                .first_refusal
                .as_ref()
                .is_none_or(|(rank, _)| self.current_rank < *rank)
            {
                self.first_refusal = Some((self.current_rank.clone(), error));
            }
        } else {
            self.coverage.failed_branches += 1;
        }
        // An already admitted failure below a complete prefix cannot change
        // that prefix. Its outcome and coverage remain visible below.
        if !self.outside_prefix(&self.current_rank) {
            let negative = error.negative_deadline();
            let mut deadline = negative.unwrap_or_else(|| {
                observed_at
                    .checked_add(self.client.inner.config.partial_failure_ttl)
                    .unwrap_or(observed_at)
            });
            if let Some(prefix) = records.iter().map(DnsRecord::expires_at).min() {
                deadline = deadline.min(prefix);
            }
            let bound = if negative.is_some() {
                &mut self.negative_bound
            } else {
                &mut self.freshness_bound
            };
            *bound = Some(bound.map_or(deadline, |previous| previous.min(deadline)));
        }
        // Keep the best-ranked details within the actual work bound, even
        // when an earlier branch fails after later ones. Cached counters
        // include every refusal visible in a packet, including omitted traces.
        let at = self
            .branch_ranks
            .partition_point(|rank| rank <= &self.current_rank);
        let bound = self.expansions + self.lookups;
        if self.response.snaptr_branches.len() == bound {
            self.coverage.omitted_branch_outcomes += 1;
            if at == bound {
                return;
            }
            self.response.snaptr_branches.pop();
            self.branch_ranks.pop();
        }
        self.branch_ranks.insert(at, self.current_rank.clone());
        self.response.snaptr_branches.insert(
            at,
            SnaptrBranchOutcome {
                error,
                records: records
                    .iter()
                    .take(DnsCandidate::MAX_RECORDS)
                    .cloned()
                    .collect(),
                observed_at,
            },
        );
    }

    fn skip_pending(&mut self, pending: &[Task]) {
        if pending.is_empty() {
            return;
        }
        self.coverage.incomplete = true;
        for work in pending {
            self.coverage.unvisited_branches += 1;
            match &work.work {
                Work::Hop { value, .. } => {
                    self.coverage.unexpanded_records += 1;
                    self.mark_unexpanded_hop(value);
                }
                Work::NaptrRecords { answer, next, .. } => {
                    let remaining = &answer.records[*next..];
                    self.coverage.unvisited_branches += remaining.len() - 1;
                    self.coverage.unexpanded_records += remaining.len();
                    for value in remaining {
                        self.mark_unexpanded_hop(value);
                    }
                }
                Work::Addresses { host, port, .. } => {
                    self.incomplete_hosts.insert((host.clone(), *port));
                }
                Work::SrvTarget { record, .. } => {
                    self.response.skipped_srv_records += 1;
                    self.skipped_srv_targets.insert(record.target.clone());
                    self.incomplete_hosts
                        .insert((record.target.clone(), record.port));
                }
                Work::SrvRecords { answer, next, .. } => {
                    let remaining = &answer.records[*next..];
                    self.coverage.unvisited_branches += remaining.len() - 1;
                    self.response.skipped_srv_records += remaining.len();
                    for record in remaining {
                        self.skipped_srv_targets.insert(record.target.clone());
                        self.incomplete_hosts
                            .insert((record.target.clone(), record.port));
                    }
                }
                Work::AddressFamily(work) => {
                    self.incomplete_hosts.insert((work.host.clone(), work.port));
                    if work.srv.is_some() {
                        self.response.skipped_srv_records += 1;
                        self.skipped_srv_targets.insert(work.host.clone());
                    }
                }
                _ => {}
            }
        }
    }

    fn mark_unexpanded_hop(&mut self, value: &MatchedNaptr) {
        if value.record.flags.eq_ignore_ascii_case(b"a") {
            if let Some(host) = &value.record.replacement {
                self.incomplete_hosts
                    .insert((host.clone(), self.query.input().default_port.unwrap_or(0)));
            }
        }
    }

    fn add_address(
        &mut self,
        address: DnsCandidate,
        host: &DnsName,
        port: u16,
        path: &Path,
        srv: Option<SnaptrSrv>,
        observed_at: PeerDiscoveryTime,
    ) {
        let mut records = path.records.clone();
        if let Some(terminal) = address.records() {
            records.extend_from_slice(terminal);
        }
        if records.len() > DnsCandidate::MAX_RECORDS {
            self.failed(
                refusal(SnaptrFailure::ProvenanceLimit),
                &records,
                observed_at,
            );
            self.incomplete_hosts.insert((host.clone(), port));
            return;
        }
        let endpoint = SocketAddr::new(address.peer().endpoint.ip(), port);
        let provenance = SnaptrPath {
            records: records.into(),
            hops: path.hops.clone().into_boxed_slice(),
            terminal_host: host.clone(),
            srv,
        };
        let ranked = RankedPath {
            rank: path.rank.clone(),
            value: provenance,
        };
        if let Some(index) = self
            .endpoints
            .iter()
            .position(|entry| entry.peer.endpoint == endpoint)
        {
            let existing = &mut self.endpoints[index];
            if let Some(previous) = existing
                .paths
                .iter_mut()
                .find(|previous| previous.value == ranked.value)
            {
                previous.rank = previous.rank.clone().min(ranked.rank);
            } else {
                existing.paths.push(ranked);
            }
            existing.paths.sort_by(|a, b| a.rank.cmp(&b.rank));
            if existing.paths.len() > 4 {
                if let Some(omitted) = existing.paths.pop() {
                    self.coverage.incomplete = true;
                    self.coverage.omitted_paths += 1;
                    self.omit_host(&omitted.value, port);
                }
            }
        } else {
            self.endpoints.push(Endpoint {
                peer: PeerCandidate::resolved(
                    self.query.input().service.clone(),
                    endpoint,
                    self.query.input().transport,
                    ServiceDiscoveryMode::Snaptr,
                    0,
                    0,
                ),
                paths: vec![ranked],
            });
        }
        self.endpoints
            .sort_by(|a, b| a.paths[0].rank.cmp(&b.paths[0].rank));
        if self.endpoints.len() > DnsAnswer::MAX_CANDIDATES {
            if let Some(omitted) = self.endpoints.pop() {
                self.coverage.incomplete = true;
                self.coverage.omitted_addresses += 1;
                for path in omitted.paths {
                    self.omit_host(&path.value, omitted.peer.endpoint.port());
                }
            }
        }
    }

    fn omit_host(&mut self, path: &SnaptrPath, port: u16) {
        self.incomplete_hosts
            .insert((path.terminal_host.clone(), port));
        self.omitted_hosts
            .insert((path.terminal_host.clone(), port));
    }

    fn begin_addresses(
        &mut self,
        host: DnsName,
        port: u16,
        path: Path,
        srv_data: Option<(Arc<SrvAnswer>, SrvRecord)>,
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> Option<Task> {
        if !self.targets.contains(&host)
            && self.targets.len() == self.client.inner.config.max_srv_targets
        {
            self.budget_error.get_or_insert(DnsError::LimitExceeded);
            self.failed(DnsError::LimitExceeded, &path.records, now());
            self.incomplete_hosts.insert((host.clone(), port));
            if srv_data.is_some() {
                self.skipped_srv_targets.insert(host);
            }
            self.response.skipped_srv_records += usize::from(srv_data.is_some());
            return None;
        }
        self.targets.insert(host.clone());
        if let Some((answer, _)) = &srv_data {
            if answer.target_is_alias(&host) {
                self.visited_srv_targets.insert(host.clone());
                self.failed(DnsError::MalformedAnswer, &path.records, answer.observed_at);
                self.incomplete_hosts.insert((host, port));
                return None;
            }
        }
        let kinds: &[u16] = match self.query.address_family() {
            AddressFamilyPolicy::Ipv4Only => &[1],
            AddressFamilyPolicy::Ipv6Only => &[28],
            AddressFamilyPolicy::DualStack => &[1, 28],
        };
        Some(Task::new(Work::AddressFamily(Box::new(AddressWork {
            host,
            port,
            path,
            srv: srv_data,
            kinds,
            next: 0,
            found: Vec::new(),
            family_outcomes: Vec::new(),
            entirely_budget_blocked: true,
        }))))
    }

    fn address_step(
        &mut self,
        mut work: Box<AddressWork>,
        evaluation: Option<Evaluation>,
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> Option<Task> {
        if let Some(&kind) = work.kinds.get(work.next) {
            let Some(evaluation) = evaluation else {
                let supplied = work.srv.as_ref().and_then(|(answer, _)| {
                    self.internal_query(&work.host)
                        .ok()
                        .and_then(|query| answer.addresses(&query, kind))
                        .map(|result| {
                            (
                                result.map(|values| {
                                    Parsed::Addresses(Arc::new(AddressData {
                                        result: Ok(values),
                                        alias: false,
                                    }))
                                }),
                                answer.observed_at,
                            )
                        })
                });
                let question = Question {
                    owner: work.host.clone(),
                    kind,
                    root: false,
                    supplied,
                };
                return Some(Task::request(Work::AddressFamily(work), question));
            };
            let mut alias = false;
            let result = match &evaluation.result {
                Ok(Parsed::Addresses(data)) if work.srv.is_some() && data.alias => {
                    alias = true;
                    Err(DnsError::MalformedAnswer)
                }
                Ok(Parsed::Addresses(data)) => data.result.clone().and_then(|values| {
                    if values.is_empty() {
                        Err(DnsError::Unavailable)
                    } else {
                        Ok(values)
                    }
                }),
                Ok(_) => Err(DnsError::MalformedAnswer),
                Err(error) => Err(*error),
            };
            // Refuse an overlong shared chain once per family, keeping the
            // complete failed prefix for its freshness bound.
            let mut failed_prefix = work.path.records.clone();
            let result = result.and_then(|values| {
                if let Some(records) =
                    values
                        .iter()
                        .filter_map(DnsCandidate::records)
                        .find(|records| {
                            work.path.records.len() + records.len() > DnsCandidate::MAX_RECORDS
                        })
                {
                    failed_prefix.extend_from_slice(records);
                    Err(refusal(SnaptrFailure::ProvenanceLimit))
                } else {
                    Ok(values)
                }
            });
            if !matches!(result, Err(DnsError::LimitExceeded)) {
                work.entirely_budget_blocked = false;
                if work.srv.is_some() {
                    self.visited_srv_targets.insert(work.host.clone());
                }
            }
            let index = self.response.outcomes.len();
            self.outcome(
                &work.host,
                kind,
                &evaluation,
                result.as_ref().map(|_| ()).map_err(|error| *error),
            );
            if evaluation.counted {
                work.family_outcomes.push(index);
            }
            match result {
                Ok(mut values) => work.found.append(&mut values),
                Err(error) => {
                    self.failed(error, &failed_prefix, evaluation.observed_at);
                    self.incomplete_hosts.insert((work.host.clone(), work.port));
                }
            }
            if alias {
                // Reject the entire SRV target, including an earlier family.
                for index in work.family_outcomes {
                    self.response.outcomes[index].result = Err(DnsError::MalformedAnswer);
                }
                return None;
            }
            work.next += 1;
            return Some(Task::new(Work::AddressFamily(work)));
        }
        if work.srv.is_some() && work.entirely_budget_blocked {
            self.skipped_srv_targets.insert(work.host.clone());
            self.response.skipped_srv_records += 1;
        }
        work.found
            .sort_by_key(|candidate| crate::dns::destination_rank(candidate.peer().endpoint.ip()));
        let srv = work.srv.as_ref().map(|(answer, record)| SnaptrSrv {
            owner: answer
                .chain
                .last()
                .map_or_else(|| work.host.clone(), |r| r.owner.clone()),
            priority: record.priority,
            weight: record.weight,
            port: record.port,
            target: record.target.clone(),
        });
        for (index, address) in work.found.into_iter().enumerate() {
            let mut path = work.path.clone();
            path.rank.push(index);
            self.add_address(address, &work.host, work.port, &path, srv.clone(), now());
        }
        None
    }

    fn step(
        &mut self,
        task: Task,
        ready: &mut Vec<Task>,
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> Option<Task> {
        match task.work {
            Work::Naptr {
                owner,
                mut path,
                root,
            } => {
                if path.visited.contains(&owner) {
                    self.failed(refusal(SnaptrFailure::Loop), &path.records, now());
                    return None;
                }
                if path.hops.len() >= self.client.inner.config.max_snaptr_depth {
                    self.failed(refusal(SnaptrFailure::DepthLimit), &path.records, now());
                    return None;
                }
                let Some(evaluation) = task.evaluation else {
                    let question = Question {
                        owner: owner.clone(),
                        kind: 35,
                        root,
                        supplied: None,
                    };
                    return Some(Task::request(Work::Naptr { owner, path, root }, question));
                };
                self.outcome(
                    &owner,
                    35,
                    &evaluation,
                    evaluation.result.as_ref().map(|_| ()).map_err(|e| *e),
                );
                let answer = match &evaluation.result {
                    Ok(Parsed::Naptr(answer)) => answer.clone(),
                    result => {
                        let error = result
                            .as_ref()
                            .err()
                            .copied()
                            .unwrap_or(DnsError::MalformedAnswer);
                        if root {
                            if matches!(error, DnsError::NxDomain { .. } | DnsError::NoData { .. })
                            {
                                self.response.snaptr_root = Some(SnaptrRootObservation {
                                    kind: SnaptrRootKind::NoNaptr,
                                    observed_at: evaluation.observed_at,
                                    expires_at: error.negative_deadline(),
                                });
                            }
                            self.response.result = Err(error);
                            self.root_finished = true;
                        } else {
                            self.failed(error, &path.records, evaluation.observed_at);
                        }
                        return None;
                    }
                };
                self.coverage.filtered_records += answer.filtered;
                if root {
                    let expires_at = answer.chain.iter().map(DnsRecord::expires_at).min();
                    self.response.snaptr_root = Some(SnaptrRootObservation {
                        kind: answer.classification,
                        observed_at: evaluation.observed_at,
                        expires_at,
                    });
                    if let SnaptrRootKind::PresentNoMatch(kind) = answer.classification {
                        if kind != SnaptrNoMatch::MalformedRequestedService {
                            self.response.result = Err(DnsError::Snaptr {
                                reason: SnaptrFailure::NoMatchingService(kind),
                                expires_at,
                            });
                            self.root_finished = true;
                            return None;
                        }
                    }
                }
                if answer
                    .chain
                    .iter()
                    .any(|record| path.visited.contains(&record.owner))
                {
                    path.records.extend_from_slice(&answer.chain);
                    self.failed(
                        refusal(SnaptrFailure::Loop),
                        &path.records,
                        evaluation.observed_at,
                    );
                    return None;
                }
                path.visited
                    .extend(answer.chain.iter().map(|record| record.owner.clone()));
                path.records.extend_from_slice(&answer.chain);
                if answer.records.is_empty() {
                    self.failed(
                        refusal(SnaptrFailure::NoUsablePath),
                        &path.records,
                        evaluation.observed_at,
                    );
                }
                if !answer.records.is_empty() {
                    path.rank.push(0);
                    ready.push(Task::new(Work::NaptrRecords {
                        answer,
                        next: 0,
                        path,
                    }));
                }
            }
            Work::NaptrRecords {
                answer,
                next,
                mut path,
            } => {
                if self.expansions == self.client.inner.config.max_snaptr_records {
                    self.budget_error.get_or_insert(DnsError::LimitExceeded);
                    self.failed(DnsError::LimitExceeded, &path.records, now());
                    self.skip_pending(&[Task::new(Work::NaptrRecords { answer, next, path })]);
                    return None;
                }
                // Keep one cursor per observed RRset instead of cloning its
                // whole fan-out for every shared-child continuation.
                let branch = Work::Hop {
                    value: answer.records[next].clone(),
                    path: path.clone(),
                };
                if next + 1 < answer.records.len() {
                    path.rank.pop();
                    path.rank.push(next + 1);
                    ready.push(Task::new(Work::NaptrRecords {
                        answer,
                        next: next + 1,
                        path,
                    }));
                }
                return Some(Task::new(branch));
            }
            Work::SrvRecords {
                answer,
                next,
                mut path,
            } => {
                let branch = Work::SrvTarget {
                    record: answer.records[next].clone(),
                    answer: answer.clone(),
                    path: path.clone(),
                };
                if next + 1 < answer.records.len() {
                    path.rank.pop();
                    path.rank.push(next + 1);
                    ready.push(Task::new(Work::SrvRecords {
                        answer,
                        next: next + 1,
                        path,
                    }));
                }
                return Some(Task::new(branch));
            }
            Work::Hop { value, mut path } => {
                if self.expansions == self.client.inner.config.max_snaptr_records {
                    self.coverage.unexpanded_records += 1;
                    self.coverage.unvisited_branches += 1;
                    self.mark_unexpanded_hop(&value);
                    self.budget_error.get_or_insert(DnsError::LimitExceeded);
                    self.failed(DnsError::LimitExceeded, &path.records, now());
                    return None;
                }
                self.expansions += 1;
                let hop = match hop(&value) {
                    Ok(hop) => hop,
                    Err(error) => {
                        self.failed(error, &path.records, now());
                        return None;
                    }
                };
                if path.records.len() >= DnsCandidate::MAX_RECORDS {
                    self.failed(
                        refusal(SnaptrFailure::ProvenanceLimit),
                        &path.records,
                        now(),
                    );
                    return None;
                }
                let flag = hop.flag;
                let owner = hop.replacement.clone();
                path.hops.push(hop);
                return Some(Task::new(match flag {
                    SnaptrFlag::Delegation => Work::Naptr {
                        owner,
                        path,
                        root: false,
                    },
                    SnaptrFlag::Service => Work::Srv { owner, path },
                    SnaptrFlag::Address => Work::Addresses {
                        host: owner,
                        port: self.query.input().default_port.unwrap_or(0),
                        path,
                    },
                }));
            }
            Work::Srv { owner, mut path } => {
                let Some(evaluation) = task.evaluation else {
                    let question = Question {
                        owner: owner.clone(),
                        kind: 33,
                        root: false,
                        supplied: None,
                    };
                    return Some(Task::request(Work::Srv { owner, path }, question));
                };
                self.outcome(
                    &owner,
                    33,
                    &evaluation,
                    evaluation.result.as_ref().map(|_| ()).map_err(|e| *e),
                );
                match evaluation.result {
                    Ok(Parsed::Srv(answer)) => {
                        path.records.extend_from_slice(&answer.chain);
                        if !answer.records.is_empty() {
                            path.rank.push(0);
                            ready.push(Task::new(Work::SrvRecords {
                                answer,
                                next: 0,
                                path,
                            }));
                        }
                    }
                    result => self.failed(
                        result.err().unwrap_or(DnsError::MalformedAnswer),
                        &path.records,
                        evaluation.observed_at,
                    ),
                }
            }
            Work::SrvTarget {
                record,
                answer,
                path,
            } => {
                if self.srv_records == self.client.inner.config.max_srv_records {
                    self.budget_error.get_or_insert(DnsError::LimitExceeded);
                    self.response.skipped_srv_records += 1;
                    self.skipped_srv_targets.insert(record.target.clone());
                    self.incomplete_hosts
                        .insert((record.target.clone(), record.port));
                    self.coverage.unvisited_branches += 1;
                    self.failed(DnsError::LimitExceeded, &path.records, now());
                    return None;
                }
                self.srv_records += 1;
                return self.begin_addresses(
                    record.target.clone(),
                    record.port,
                    path,
                    Some((answer, record)),
                    now,
                );
            }
            Work::Addresses { host, port, path } => {
                return self.begin_addresses(host, port, path, None, now)
            }
            Work::AddressFamily(work) => return self.address_step(work, task.evaluation, now),
        }
        None
    }

    fn outside_prefix(&self, rank: &[usize]) -> bool {
        self.endpoints.len() == DnsAnswer::MAX_CANDIDATES
            && self
                .endpoints
                .last()
                .is_some_and(|endpoint| rank > endpoint.paths[0].rank.as_slice())
    }

    // Pop one real continuation and apply the prefix rule. Inspection uses the
    // same function, so stopped families and completed observations cannot drift.
    fn next_ready(&mut self, ready: &mut Vec<Task>) -> Option<Task> {
        while !ready.is_empty() {
            ready.sort_by(|a, b| b.work.path().rank.cmp(&a.work.path().rank));
            let mut task = ready.pop()?;
            self.current_rank.clone_from(&task.work.path().rank);
            if self.outside_prefix(&self.current_rank) && task.evaluation.is_none() {
                match &mut task.work {
                    Work::AddressFamily(work)
                        if work.next == work.kinds.len() || !work.found.is_empty() =>
                    {
                        // Keep observed families, but do not start a lower-ranked
                        // family after a complete prefix has been assembled.
                        if work.next != work.kinds.len() {
                            self.coverage.incomplete = true;
                            self.coverage.unvisited_branches += 1;
                            self.incomplete_hosts.insert((work.host.clone(), work.port));
                            work.next = work.kinds.len();
                            task.question = None;
                        }
                    }
                    _ => {
                        self.skip_pending(&[task]);
                        continue;
                    }
                }
            }
            return Some(task);
        }
        None
    }

    fn queued_network_work<F>(
        &self,
        ready: &[Task],
        pending: &[Pending<F>],
        now: &impl Fn() -> PeerDiscoveryTime,
    ) -> bool {
        if ready.is_empty() {
            return false;
        }
        // Replay the actual reducer on a bounded snapshot, once per ready-queue
        // change. This preserves lazy logical admission: eagerly expanding every
        // shared waiter can spend the record allowance before its child returns.
        // There is no second set of loop/depth/budget/alias/prefix rules.
        let mut inspection = self.clone();
        let mut ready = ready.to_vec();
        let observed_at = now();
        let now = || observed_at;
        while let Some(mut task) = inspection.next_ready(&mut ready) {
            if let Some(question) = task.question.take() {
                let shared = pending
                    .iter()
                    .any(|work| work.key == (question.owner.clone(), question.kind));
                if let Some(evaluation) = inspection.reserve(&question, shared, &now) {
                    task.evaluation = Some(evaluation);
                    ready.push(task);
                } else if !shared {
                    // Only a new exchange waiting for a slot can use one freed
                    // by backtracking. A running sibling already has its slot.
                    return true;
                }
            } else if let Some(next) = inspection.step(task, &mut ready, &now) {
                ready.push(next);
            }
            if inspection.root_finished {
                break;
            }
        }
        false
    }

    async fn run(&mut self, now: &impl Fn() -> PeerDiscoveryTime) {
        let client = self.client;
        let filter = self.filter;
        let mut ready = vec![Task::new(Work::Naptr {
            owner: self.query.name().clone(),
            path: Path::default(),
            root: true,
        })];
        let mut pending: Vec<Pending<_>> = Vec::new();
        loop {
            while let Some(mut task) = self.next_ready(&mut ready) {
                if let Some(question) = task.question.take() {
                    let key = (question.owner.clone(), question.kind);
                    let shared = pending.iter().position(|work| work.key == key);
                    let local = question.supplied.is_some()
                        || self.memo.contains_key(&key)
                        || self.lookups == client.inner.config.max_snaptr_lookups
                        || tokio::time::Instant::now() >= self.session.deadline;
                    // Shared exchanges still occupy a slot per logical
                    // continuation: duplicates must not spend every expansion
                    // before the first child gets a chance to make progress.
                    let active = pending.iter().map(|work| work.waiters.len()).sum::<usize>();
                    if !local && active == client.inner.config.max_srv_concurrent_targets {
                        task.question = Some(question);
                        ready.push(task);
                        break;
                    }
                    if let Some(evaluation) = self.reserve(&question, shared.is_some(), now) {
                        task.evaluation = Some(evaluation);
                        ready.push(task);
                    } else if let Some(index) = shared {
                        pending[index].waiters.push(task);
                    } else {
                        // Reserve at most one exchange timeout, and at most
                        // half the time left on admission, for another branch.
                        // The timer is enforced only while such a branch exists.
                        let backtrack_at = (!question.root).then(|| {
                            let remaining = self
                                .session
                                .deadline
                                .saturating_duration_since(tokio::time::Instant::now());
                            let reserve = client.inner.config.timeout.min(remaining / 2);
                            Box::pin(tokio::time::sleep_until(self.session.deadline - reserve))
                        });
                        let query = self.internal_query(&question.owner);
                        let future = Box::pin(Self::lookup(
                            client,
                            query,
                            filter,
                            self.seed,
                            question,
                            self.session.deadline,
                            now,
                        ));
                        pending.push(Pending {
                            key,
                            future,
                            waiters: vec![task],
                            backtrack_at,
                        });
                    }
                } else if let Some(next) = self.step(task, &mut ready, now) {
                    ready.push(next);
                }
                if self.root_finished {
                    return;
                }
            }
            if pending.is_empty() {
                break;
            }
            let queued_network_work = self.queued_network_work(&ready, &pending, now);
            let mut completed = Vec::new();
            poll_fn(|cx| {
                poll_questions(&mut pending, &mut completed, queued_network_work, now, cx)
            })
            .await;
            for (work, (evaluation, source)) in completed {
                self.memo.insert(work.key, evaluation.clone());
                if let Some(source) = source {
                    self.source_ranks.push(
                        work.waiters
                            .iter()
                            .map(|task| task.work.path().rank.clone())
                            .min()
                            .unwrap_or_default(),
                    );
                    self.response.sources.push(source);
                }
                for mut task in work.waiters {
                    task.evaluation = Some(
                        if evaluation
                            .result
                            .as_ref()
                            .is_err_and(|error| *error == DnsError::Timeout)
                            && tokio::time::Instant::now() >= self.session.deadline
                        {
                            self.exhausted(DnsError::Timeout, evaluation.observed_at, true)
                        } else {
                            evaluation.clone()
                        },
                    );
                    ready.push(task);
                }
            }
        }
        self.response.skipped_srv_targets = self
            .skipped_srv_targets
            .difference(&self.visited_srv_targets)
            .count();
        self.coverage.unexpanded_srv_records = self.response.skipped_srv_records;
        self.coverage.unexpanded_srv_targets = self.response.skipped_srv_targets;
        order_trace(&mut self.response.sources, &mut self.source_ranks);
        order_trace(&mut self.response.outcomes, &mut self.outcome_ranks);
        order_trace(&mut self.response.snaptr_branches, &mut self.branch_ranks);
        self.response.result = if self.endpoints.is_empty() {
            Err(self
                .budget_error
                .or(self.first_refusal.as_ref().map(|(_, error)| *error))
                .unwrap_or_else(|| refusal(SnaptrFailure::NoUsablePath)))
        } else {
            self.finish_answer()
        };
    }

    fn finish_answer(&mut self) -> Result<DnsAnswer, DnsError> {
        let mut hosts: Vec<HostBuilder> = Vec::new();
        // Primary host slots are reserved before considering alternate names.
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if let Some(path) = endpoint.paths.first() {
                host_entry(
                    &mut hosts,
                    &path.value.terminal_host,
                    endpoint.peer.endpoint.port(),
                    index,
                )
                .add(index, 0);
            }
        }
        let mut candidates = Vec::with_capacity(self.endpoints.len());
        for (index, mut endpoint) in std::mem::take(&mut self.endpoints).into_iter().enumerate() {
            let mut paths = Vec::new();
            for ranked in endpoint.paths {
                let path = ranked.value;
                let port = endpoint.peer.endpoint.port();
                if !paths.is_empty() {
                    if hosts.len() == DnsAnswer::MAX_CANDIDATES
                        && !hosts
                            .iter()
                            .any(|host| host.name == path.terminal_host && host.port == port)
                    {
                        self.coverage.incomplete = true;
                        self.coverage.omitted_paths += 1;
                        self.omitted_hosts
                            .insert((path.terminal_host.clone(), port));
                        continue;
                    }
                    host_entry(&mut hosts, &path.terminal_host, port, index)
                        .add(index, paths.len());
                }
                paths.push(path);
            }
            endpoint.peer.weight = crate::dns::selection_weight(index);
            let records = paths
                .first()
                .ok_or(DnsError::MalformedAnswer)?
                .records
                .clone();
            let mut candidate = DnsCandidate::new(endpoint.peer, records.to_vec())?;
            candidate.records = Some(records);
            candidate.snaptr = Some(SnaptrProvenance {
                origin: self.query.name().clone(),
                filter: self.filter.clone(),
                paths: paths.into_boxed_slice(),
            });
            candidates.push(candidate);
        }
        self.coverage.omitted_hosts = self
            .omitted_hosts
            .iter()
            .filter(|(name, port)| {
                !hosts
                    .iter()
                    .any(|host| host.name == *name && host.port == *port)
            })
            .count();
        hosts.sort_by_key(|host| host.rank);
        let hosts = hosts
            .into_iter()
            .map(|mut host| {
                let complete = !self
                    .incomplete_hosts
                    .contains(&(host.name.clone(), host.port));
                host.addresses.sort_by_key(|(index, _)| *index);
                SnaptrHost {
                    name: host.name,
                    port: host.port,
                    transport: self.query.input().transport,
                    rank: host.rank,
                    complete,
                    addresses: host
                        .addresses
                        .into_iter()
                        .map(|(candidate_index, paths)| SnaptrHostAddress {
                            candidate_index,
                            path_indices: paths.into_boxed_slice(),
                        })
                        .collect(),
                }
            })
            .collect();
        let mut answer = DnsAnswer::new(candidates)?;
        answer.snaptr_hosts = Some(hosts);
        answer.snaptr_coverage = Some(self.coverage);
        if let Some(bound) = self.freshness_bound {
            answer = answer.with_freshness_bound(bound);
        }
        if let Some(bound) = self.negative_bound {
            answer = answer.with_negative_freshness_bound(bound);
        }
        Ok(answer)
    }
}

fn order_trace<T>(values: &mut Vec<T>, ranks: &mut Vec<Vec<usize>>) {
    let mut entries: Vec<_> = std::mem::take(ranks)
        .into_iter()
        .zip(std::mem::take(values))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    *values = entries.into_iter().map(|(_, value)| value).collect();
}

struct HostBuilder {
    name: DnsName,
    port: u16,
    rank: usize,
    addresses: Vec<(usize, Vec<usize>)>,
}

impl HostBuilder {
    fn add(&mut self, candidate: usize, path: usize) {
        if let Some((_, paths)) = self
            .addresses
            .iter_mut()
            .find(|(index, _)| *index == candidate)
        {
            paths.push(path);
        } else {
            self.addresses.push((candidate, vec![path]));
        }
    }
}

fn host_entry<'a>(
    hosts: &'a mut Vec<HostBuilder>,
    name: &DnsName,
    port: u16,
    rank: usize,
) -> &'a mut HostBuilder {
    let index = hosts
        .iter()
        .position(|host| host.name == *name && host.port == port)
        .unwrap_or_else(|| {
            hosts.push(HostBuilder {
                name: name.clone(),
                port,
                rank,
                addresses: Vec::new(),
            });
            hosts.len() - 1
        });
    hosts[index].rank = hosts[index].rank.min(rank);
    &mut hosts[index]
}

impl DnsClient {
    pub(super) async fn resolve_snaptr(
        &self,
        query: &DnsQuery,
        now: &impl Fn() -> PeerDiscoveryTime,
        seed: Option<u64>,
    ) -> DnsClientResponse {
        let Some(filter) = query.snaptr_filter() else {
            return DnsClientResponse::error(DnsError::InvalidQuery);
        };
        let seed = match seed {
            Some(value) => value,
            None => {
                let mut bytes = [0; 8];
                if getrandom::fill(&mut bytes).is_err() {
                    return DnsClientResponse::error(DnsError::Unavailable);
                }
                u64::from_ne_bytes(bytes)
            }
        };
        let mut traversal = Traversal {
            client: self,
            query,
            filter,
            seed,
            session: srv::RefreshSession {
                deadline: tokio::time::Instant::now() + self.inner.config.snaptr_refresh_timeout,
            },
            memo: HashMap::new(),
            response: DnsClientResponse::error(DnsError::Unavailable),
            lookups: 0,
            expansions: 0,
            srv_records: 0,
            targets: HashSet::new(),
            skipped_srv_targets: HashSet::new(),
            visited_srv_targets: HashSet::new(),
            address_lookups: 0,
            endpoints: Vec::new(),
            coverage: SnaptrCoverage::default(),
            incomplete_hosts: HashSet::new(),
            omitted_hosts: HashSet::new(),
            freshness_bound: None,
            negative_bound: None,
            first_refusal: None,
            budget_error: None,
            current_rank: Vec::new(),
            source_ranks: Vec::new(),
            outcome_ranks: Vec::new(),
            branch_ranks: Vec::new(),
            root_finished: false,
        };
        traversal.run(now).await;
        traversal.response
    }
}

#[cfg(test)]
#[path = "dns_snaptr_tests.rs"]
mod tests;
