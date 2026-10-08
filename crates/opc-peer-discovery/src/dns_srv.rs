//! RFC 2782 ordering and bounded target expansion over the shared transport.

use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;
use crate::dns_wire::{SrvAnswer, SrvRecord};
use crate::{DiscoveryTarget, PeerCandidate};

struct SrvSession {
    deadline: tokio::time::Instant,
}

impl SrvSession {
    async fn lookup<T>(
        &self,
        client: &DnsClient,
        query: &DnsQuery,
        kind: u16,
        now: &impl Fn() -> PeerDiscoveryTime,
        parse: impl Fn(Message, PeerDiscoveryTime) -> Result<T, DnsError>,
    ) -> (Result<T, DnsError>, Option<DnsResponseSource>) {
        if tokio::time::Instant::now() >= self.deadline {
            return (Err(DnsError::Timeout), None);
        }
        tokio::time::timeout_at(
            self.deadline,
            client.lookup_with_history(
                query,
                kind,
                now,
                parse,
                Some(&client.inner.server_timeouts),
            ),
        )
        .await
        .unwrap_or((Err(DnsError::Timeout), None))
    }
}

#[derive(Default)]
struct SrvRefresh {
    sources: Vec<DnsResponseSource>,
    outcomes: Vec<DnsQueryOutcome>,
    lookups: usize,
    freshness_bound: Option<PeerDiscoveryTime>,
    negative_freshness_bound: Option<PeerDiscoveryTime>,
    skipped_records: usize,
    skipped_targets: usize,
}

impl SrvRefresh {
    fn merge(&mut self, mut other: Self) {
        self.sources.append(&mut other.sources);
        self.outcomes.append(&mut other.outcomes);
        for (bound, added) in [
            (&mut self.freshness_bound, other.freshness_bound),
            (
                &mut self.negative_freshness_bound,
                other.negative_freshness_bound,
            ),
        ] {
            if let Some(added) = added {
                *bound = Some(bound.map_or(added, |old| old.min(added)));
            }
        }
    }

    fn record<T>(
        &mut self,
        client: &DnsClient,
        query: &DnsQuery,
        kind: u16,
        result: &Result<T, DnsError>,
        observed_at: PeerDiscoveryTime,
    ) {
        if let Err(error) = result {
            let deadline = client.failure_deadline(*error, observed_at);
            let bound = if error.soa().is_some() {
                &mut self.negative_freshness_bound
            } else {
                &mut self.freshness_bound
            };
            *bound = Some(bound.map_or(deadline, |old| old.min(deadline)));
        }
        self.outcomes.push(DnsQueryOutcome {
            owner: query.name().clone(),
            record_type: record_type(kind),
            result: result.as_ref().map(|_| ()).map_err(|error| *error),
            observed_at,
        });
    }

    fn reject_alias(
        &mut self,
        client: &DnsClient,
        query: &DnsQuery,
        kinds: &[u16],
        observed_at: PeerDiscoveryTime,
    ) {
        increment(&client.inner.counters.malformed);
        for &kind in kinds {
            if let Some(outcome) = self.outcomes.iter_mut().find(|outcome| {
                outcome.owner == *query.name() && outcome.record_type == record_type(kind)
            }) {
                if outcome.result.is_ok() {
                    outcome.result = Err(DnsError::MalformedAnswer);
                    outcome.observed_at = observed_at;
                }
            } else {
                self.record::<()>(
                    client,
                    query,
                    kind,
                    &Err(DnsError::MalformedAnswer),
                    observed_at,
                );
            }
        }
    }
}

struct TargetResponse {
    result: Result<Vec<DnsCandidate>, DnsError>,
    refresh: SrvRefresh,
}

fn poll_targets<F: Future<Output = TargetResponse>>(
    pending: &mut Vec<(usize, Pin<Box<F>>)>,
    results: &mut [Option<TargetResponse>],
    cx: &mut Context<'_>,
) -> Poll<()> {
    let before = pending.len();
    let mut at = 0;
    while at < pending.len() {
        match pending[at].1.as_mut().poll(cx) {
            Poll::Ready(response) => {
                let (index, _) = pending.swap_remove(at);
                results[index] = Some(response);
            }
            Poll::Pending => at += 1,
        }
    }
    if pending.is_empty() || pending.len() < before {
        Poll::Ready(())
    } else {
        Poll::Pending
    }
}

struct SrvExpansion {
    records: Vec<SrvRecord>,
    record_limit: usize,
    results: Vec<Option<TargetResponse>>,
    next_record: usize,
    candidates: Vec<DnsCandidate>,
    last_error: DnsError,
    skipped_records: usize,
}

impl SrvExpansion {
    fn has_candidate_capacity(&self, targets: &[DnsQuery], started: usize) -> bool {
        let mut endpoints = Vec::new();
        for record in &self.records[..self.record_limit] {
            let Some(index) = targets.iter().position(|q| *q.name() == record.target) else {
                continue;
            };
            // Repeated ports for an earlier target can appear after a target
            // we have not started. Do not use that later data to skip its turn.
            if index >= started {
                break;
            }
            if let Some(TargetResponse {
                result: Ok(addresses),
                ..
            }) = &self.results[index]
            {
                for address in addresses {
                    let endpoint = SocketAddr::new(address.peer().endpoint.ip(), record.port);
                    if !endpoints.contains(&endpoint) {
                        endpoints.push(endpoint);
                    }
                    if endpoints.len() == DnsAnswer::MAX_CANDIDATES {
                        return true;
                    }
                }
            }
        }
        false
    }

    // Publish in RFC selection order, regardless of lookup completion order.
    // A not-yet-completed earlier target blocks only this bounded assembly,
    // never the polling of other target futures.
    fn extend_ready(
        &mut self,
        query: &DnsQuery,
        answer: &SrvAnswer,
        targets: &[DnsQuery],
    ) -> Result<(), DnsError> {
        while self.next_record < self.record_limit
            && self.candidates.len() < DnsAnswer::MAX_CANDIDATES
        {
            let record = &self.records[self.next_record];
            let Some(index) = targets.iter().position(|q| *q.name() == record.target) else {
                self.next_record += 1;
                self.skipped_records += 1;
                continue;
            };
            let Some(response) = &self.results[index] else {
                break;
            };
            self.next_record += 1;
            let addresses = match &response.result {
                Ok(addresses) => addresses,
                Err(error) => {
                    self.last_error = *error;
                    self.skipped_records += usize::from(*error == DnsError::LimitExceeded);
                    continue;
                }
            };
            for address in addresses {
                let endpoint = SocketAddr::new(address.peer().endpoint.ip(), record.port);
                if self
                    .candidates
                    .iter()
                    .any(|candidate| candidate.peer().endpoint == endpoint)
                {
                    continue;
                }
                let mut chain = answer.chain.clone();
                chain.extend_from_slice(address.records().ok_or(DnsError::MalformedAnswer)?);
                // The legacy selector consumes this draw, not raw SRV weights.
                let weight = u16::MAX - self.candidates.len() as u16;
                self.candidates.push(DnsCandidate::new(
                    PeerCandidate::resolved(
                        query.input().service.clone(),
                        endpoint,
                        query.input().transport,
                        ServiceDiscoveryMode::Service,
                        record.priority,
                        weight,
                    ),
                    chain,
                )?);
                if self.candidates.len() == DnsAnswer::MAX_CANDIDATES {
                    break;
                }
            }
        }
        Ok(())
    }
}

fn kinds(family: AddressFamilyPolicy) -> &'static [u16] {
    match family {
        AddressFamilyPolicy::Ipv4Only => &[1],
        AddressFamilyPolicy::Ipv6Only => &[28],
        AddressFamilyPolicy::DualStack => &[1, 28],
    }
}

fn record_type(kind: u16) -> DnsRecordType {
    match kind {
        1 => DnsRecordType::A,
        33 => DnsRecordType::Srv,
        _ => DnsRecordType::Aaaa,
    }
}

pub(super) fn valid_query(query: &DnsQuery) -> bool {
    let mut labels = query.name().as_str().splitn(3, '.');
    let service = labels.next().and_then(|label| label.strip_prefix('_'));
    let protocol = labels.next().and_then(|label| label.strip_prefix('_'));
    let domain = labels.next();
    service.is_some_and(dns_wire::valid_host)
        && protocol == Some(query.input().transport.as_str())
        && domain.is_some_and(dns_wire::valid_host)
}

impl DnsClient {
    pub(super) async fn resolve_srv(
        &self,
        query: &DnsQuery,
        now: &impl Fn() -> PeerDiscoveryTime,
        seed: Option<u64>,
    ) -> DnsClientResponse {
        let session = SrvSession {
            deadline: tokio::time::Instant::now() + self.inner.config.srv_refresh_timeout,
        };
        let seed = match seed {
            Some(seed) => seed,
            None => {
                let mut bytes = [0; 8];
                if getrandom::fill(&mut bytes).is_err() {
                    return DnsClientResponse::error(DnsError::Unavailable);
                }
                u64::from_ne_bytes(bytes)
            }
        };
        let config = &self.inner.config;
        let (answer, source) = session
            .lookup(self, query, 33, now, |message, observed_at| {
                message.srv(query, observed_at, config.max_cname_chain)
            })
            .await;
        let observed_at = source
            .as_ref()
            .map(|source| source.observed_at)
            .unwrap_or_else(now);
        let mut refresh = SrvRefresh::default();
        refresh.record(self, query, 33, &answer, observed_at);
        refresh.sources.extend(source);
        let result = match answer {
            Ok(answer) => {
                self.srv_candidates(query, answer, now, seed, &session, &mut refresh)
                    .await
            }
            Err(error) => Err(error),
        };
        DnsClientResponse {
            result: result.map(|mut answer| {
                if let Some(bound) = refresh.freshness_bound {
                    answer = answer.with_freshness_bound(bound);
                }
                if let Some(bound) = refresh.negative_freshness_bound {
                    answer = answer.with_negative_freshness_bound(bound);
                }
                answer
            }),
            sources: refresh.sources,
            outcomes: refresh.outcomes,
            skipped_srv_records: refresh.skipped_records,
            skipped_srv_targets: refresh.skipped_targets,
        }
    }

    async fn srv_candidates(
        &self,
        query: &DnsQuery,
        mut answer: SrvAnswer,
        now: &impl Fn() -> PeerDiscoveryTime,
        seed: u64,
        session: &SrvSession,
        refresh: &mut SrvRefresh,
    ) -> Result<DnsAnswer, DnsError> {
        let config = &self.inner.config;
        let ordered = weighted_order(std::mem::take(&mut answer.records), seed)?;
        let record_limit = ordered.len().min(config.max_srv_records);
        // Plan unique targets in selection order. Work limits never change
        // the weighted draw over the complete valid RRset.
        let mut targets: Vec<DnsQuery> = Vec::new();
        for record in &ordered[..record_limit] {
            if targets.iter().any(|target| *target.name() == record.target)
                || targets.len() == config.max_srv_targets
            {
                continue;
            }
            let mut input = query.input().clone();
            input.target = DiscoveryTarget::new(record.target.as_str());
            input.mode = ServiceDiscoveryMode::Address;
            // Internal neutral port; only the SRV port reaches an endpoint.
            input.default_port = Some(0);
            targets.push(
                DnsQuery::new(input)?
                    .with_address_family(query.address_family())
                    .with_resolver_profile(query.resolver_profile().clone())
                    .with_source_plane(query.source_plane().clone()),
            );
        }
        let mut expansion = SrvExpansion {
            records: ordered,
            record_limit,
            results: (0..targets.len()).map(|_| None).collect(),
            next_record: 0,
            candidates: Vec::new(),
            last_error: DnsError::Unavailable,
            skipped_records: 0,
        };
        let mut pending = Vec::new();
        for (index, target) in targets.iter().enumerate() {
            // Reserve the bounded lookup budget in target/family order, so a
            // faster target cannot steal another target's lookup allowance.
            let needed = if answer.target_is_alias(target.name()) {
                0
            } else {
                kinds(target.address_family())
                    .iter()
                    .filter(|&&kind| !answer.has_addresses(target.name(), kind))
                    .count()
            };
            let allowance = needed.min(config.max_srv_address_lookups - refresh.lookups);
            refresh.lookups += allowance;
            let mut future =
                Box::pin(self.target_response(target, &answer, now, session, allowance));
            // Additional-only targets can finish immediately. Consume them
            // before opening later sockets if they already fill the answer.
            match poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await {
                Poll::Ready(response) => expansion.results[index] = Some(response),
                Poll::Pending => pending.push((index, future)),
            }
            expansion.extend_ready(query, &answer, &targets)?;
            if pending.len() == config.max_srv_concurrent_targets {
                // Refill a free slot as soon as any target completes; a silent
                // target must not stall healthy targets behind its batch.
                poll_fn(|cx| poll_targets(&mut pending, &mut expansion.results, cx)).await;
                expansion.extend_ready(query, &answer, &targets)?;
            }
            if expansion.has_candidate_capacity(&targets, index + 1) {
                break;
            }
        }
        // Finish already-started work within the same overall deadline, keeping
        // per-family progress and outcomes even if the candidate cap is filled.
        while !pending.is_empty() {
            poll_fn(|cx| poll_targets(&mut pending, &mut expansion.results, cx)).await;
        }
        expansion.extend_ready(query, &answer, &targets)?;
        let mut skipped_targets = Vec::new();
        for record in &expansion.records {
            let visited = targets.iter().enumerate().any(|(index, target)| {
                *target.name() == record.target
                    && expansion.results[index]
                        .as_ref()
                        .is_some_and(|response| response.result != Err(DnsError::LimitExceeded))
            });
            if !visited && !skipped_targets.contains(&&record.target) {
                skipped_targets.push(&record.target);
            }
        }
        refresh.skipped_targets = skipped_targets.len();
        refresh.skipped_records =
            expansion.skipped_records + expansion.records.len() - expansion.next_record;
        // Diagnostics use target selection order, including speculative work
        // already started within the concurrency bound before the cap filled.
        for response in expansion.results.into_iter().flatten() {
            refresh.merge(response.refresh);
        }
        if expansion.candidates.is_empty() {
            Err(expansion.last_error)
        } else {
            DnsAnswer::new(expansion.candidates)
        }
    }

    async fn target_response(
        &self,
        query: &DnsQuery,
        answer: &SrvAnswer,
        now: &impl Fn() -> PeerDiscoveryTime,
        session: &SrvSession,
        lookup_limit: usize,
    ) -> TargetResponse {
        let mut refresh = SrvRefresh::default();
        let result = self
            .target_addresses(query, answer, now, session, lookup_limit, &mut refresh)
            .await;
        TargetResponse { result, refresh }
    }

    async fn target_addresses(
        &self,
        query: &DnsQuery,
        answer: &SrvAnswer,
        now: &impl Fn() -> PeerDiscoveryTime,
        session: &SrvSession,
        lookup_limit: usize,
        refresh: &mut SrvRefresh,
    ) -> Result<Vec<DnsCandidate>, DnsError> {
        let kinds = kinds(query.address_family());
        // RFC 2782, Target: an alias is forbidden. A CNAME from either family
        // invalidates this entire target, including addresses already obtained.
        if answer.target_is_alias(query.name()) {
            refresh.reject_alias(self, query, kinds, answer.observed_at);
            return Err(DnsError::MalformedAnswer);
        }
        let mut candidates = Vec::new();
        let mut error = DnsError::Unavailable;
        for &kind in kinds {
            let (result, observed_at) = if let Some(result) = answer.addresses(query, kind) {
                (result, answer.observed_at)
            } else if tokio::time::Instant::now() >= session.deadline {
                (Err(DnsError::Timeout), now())
            } else if refresh.lookups == lookup_limit {
                (Err(DnsError::LimitExceeded), now())
            } else {
                refresh.lookups += 1;
                let (result, source) = session
                    .lookup(self, query, kind, now, |message, observed_at| {
                        if message.target_is_alias(query.name()) {
                            // A terminal sentinel prevents a retry from hiding an
                            // alias violation behind another server's address data.
                            Ok(None)
                        } else {
                            message.resolve(query, kind, observed_at, 0).map(Some)
                        }
                    })
                    .await;
                let observed_at = source
                    .as_ref()
                    .map(|source| source.observed_at)
                    .unwrap_or_else(now);
                refresh.sources.extend(source);
                let result = match result {
                    Ok(Some(found)) => Ok(found),
                    Ok(None) => {
                        refresh.reject_alias(self, query, kinds, observed_at);
                        return Err(DnsError::MalformedAnswer);
                    }
                    Err(error) => Err(error),
                };
                (result, observed_at)
            };
            // An RRset can exist yet contain no address accepted by the family
            // policy (for example mapped IPv4 in an IPv6-only query). Treat
            // that target-family result as a failure, never a fresh success.
            let result = result.and_then(|found| {
                if found.is_empty() {
                    Err(DnsError::Unavailable)
                } else {
                    Ok(found)
                }
            });
            // Preserve target denials for diagnostics and freshness before
            // removing their authority to negatively cache the service key.
            refresh.record(self, query, kind, &result, observed_at);
            match result {
                Ok(mut found) => candidates.append(&mut found),
                // Target absence does not authorize negative caching of the
                // service name. Only the original SRV lookup can provide that.
                Err(DnsError::NxDomain { .. } | DnsError::NoData { .. }) => {
                    error = DnsError::Unavailable
                }
                Err(found) => error = found,
            }
        }
        if candidates.is_empty() {
            return Err(error);
        }
        // RFC 6724 section 6, rule 10: preserve DNS order within equal
        // destination precedence, including server-side address rotation.
        candidates
            .sort_by_key(|candidate| crate::dns::destination_rank(candidate.peer().endpoint.ip()));
        candidates.truncate(DnsAnswer::MAX_CANDIDATES);
        Ok(candidates)
    }
}

fn weighted_order(mut records: Vec<SrvRecord>, seed: u64) -> Result<Vec<SrvRecord>, DnsError> {
    // Canonicalization makes seed injection independent of DNS wire order.
    records.sort_by(|a, b| {
        (a.priority, a.target.as_str(), a.port, a.weight).cmp(&(
            b.priority,
            b.target.as_str(),
            b.port,
            b.weight,
        ))
    });
    let mut random = SelectionRandom(seed);
    let mut ordered = Vec::with_capacity(records.len());
    while let Some(first) = records.first() {
        let end = records
            .iter()
            .take_while(|r| r.priority == first.priority)
            .count();
        let mut group: Vec<_> = records.drain(..end).collect();
        // RFC 2782 permits any initial order. Shuffle so all-zero groups and
        // ties among zero-weight records do not systematically prefer a name.
        for index in (1..group.len()).rev() {
            let other = random.below(index as u64 + 1)? as usize;
            group.swap(index, other);
        }
        group.sort_by_key(|record| record.weight != 0);
        while !group.is_empty() {
            let sum: u64 = group.iter().map(|record| u64::from(record.weight)).sum();
            // RFC 2782 Weight: draw inclusively from 0 through sum, place
            // zero weights first, select the first running sum >= the draw.
            let draw = random.below(sum + 1)?;
            let mut running = 0;
            let index = group
                .iter()
                .position(|record| {
                    running += u64::from(record.weight);
                    running >= draw
                })
                .ok_or(DnsError::MalformedAnswer)?;
            ordered.push(group.remove(index));
        }
    }
    Ok(ordered)
}

// SplitMix64 is selection-only, never a source for query IDs or source ports.
// Explicit wrapping operations make its seeded output portable across targets.
struct SelectionRandom(u64);

impl SelectionRandom {
    fn below(&mut self, bound: u64) -> Result<u64, DnsError> {
        let threshold = bound.wrapping_neg() % bound;
        // Rejection sampling avoids modulo bias; bound work even for an
        // adversarial seed. Actual bounds are at most 128 * u16::MAX + 1.
        for _ in 0..32 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^= value >> 31;
            if value >= threshold {
                return Ok(value % bound);
            }
        }
        Err(DnsError::LimitExceeded)
    }
}
