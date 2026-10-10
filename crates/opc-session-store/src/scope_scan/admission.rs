//! Fair retention admission. A waiter owns a resident ingress credit, never an
//! execution credit needed by the pages of already admitted views.

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetentionLimits {
    pub(super) max_views: usize,
    pub(super) sqlite_readers: usize,
    pub(super) native_bytes: u64,
    pub(super) wal_high_water: u64,
}

impl RetentionLimits {
    pub(crate) fn new(
        max_views: usize,
        sqlite_readers: usize,
        native_bytes: u64,
        wal_high_water: u64,
    ) -> Result<Self, AdmissionError> {
        if max_views == 0
            || sqlite_readers == 0
            || sqlite_readers > max_views
            || native_bytes == 0
            || wal_high_water == 0
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(Self {
            max_views,
            sqlite_readers,
            native_bytes,
            wal_high_water,
        })
    }
}

impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            max_views: 4,
            sqlite_readers: 4,
            native_bytes: 512 * 1024 * 1024,
            wal_high_water: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureCost {
    // Keep the shared accounting model available to tests on every target.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Native(u64),
    Sqlite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    InvalidLimits,
    InvalidCost,
    CaptureTooLarge,
    MetadataExhausted,
    #[cfg(any(test, target_os = "linux"))]
    InvalidReservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AdmissionTicket(u64);

pub(crate) struct AdmissionGrant<R> {
    pub(crate) ticket: AdmissionTicket,
    pub(crate) resident: R,
}

struct Pending<R> {
    ticket: AdmissionTicket,
    cost: CaptureCost,
    resident: R,
}

struct WaitingScope<S, R> {
    scope: S,
    requests: VecDeque<Pending<R>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionMetrics {
    pub(crate) active_views: usize,
    pub(crate) waiting_views: usize,
    pub(crate) native_bytes: u64,
    pub(crate) sqlite_readers: usize,
}

/// `R` must own the caller's bounded resident-request admission. The runtime
/// releases a grant only after its captured rows and in-flight users drain.
pub(crate) struct AdmissionQueue<S, R> {
    limits: RetentionLimits,
    waiting: VecDeque<WaitingScope<S, R>>,
    active: HashMap<AdmissionTicket, CaptureCost>,
    next_ticket: u64,
    waiting_count: usize,
    native_bytes: u64,
    sqlite_readers: usize,
}

impl<S: Eq, R> AdmissionQueue<S, R> {
    pub(crate) fn new(limits: RetentionLimits) -> Self {
        Self {
            limits,
            waiting: VecDeque::new(),
            active: HashMap::new(),
            next_ticket: 1,
            waiting_count: 0,
            native_bytes: 0,
            sqlite_readers: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn enqueue(
        &mut self,
        scope: S,
        cost: CaptureCost,
        resident: R,
    ) -> Result<AdmissionTicket, AdmissionError> {
        self.enqueue_retaining(scope, cost, resident)
            .map_err(|(error, _)| error)
    }

    /// Return rejected resources intact so a caller can drop them outside its
    /// own mutex, including validation and ticket-exhaustion failures.
    pub(crate) fn enqueue_retaining(
        &mut self,
        scope: S,
        cost: CaptureCost,
        resident: R,
    ) -> Result<AdmissionTicket, (AdmissionError, R)> {
        let prepared = (|| {
            if let CaptureCost::Native(bytes) = cost {
                if bytes == 0 {
                    return Err(AdmissionError::InvalidCost);
                }
                if bytes > self.limits.native_bytes {
                    return Err(AdmissionError::CaptureTooLarge);
                }
            }
            let next = self
                .next_ticket
                .checked_add(1)
                .ok_or(AdmissionError::MetadataExhausted)?;
            let waiting_count = self
                .waiting_count
                .checked_add(1)
                .ok_or(AdmissionError::MetadataExhausted)?;
            Ok((next, waiting_count))
        })();
        let (next, waiting_count) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err((error, resident)),
        };
        let ticket = AdmissionTicket(self.next_ticket);
        let request = Pending {
            ticket,
            cost,
            resident,
        };
        if let Some(waiting) = self
            .waiting
            .iter_mut()
            .find(|waiting| waiting.scope == scope)
        {
            waiting.requests.push_back(request);
        } else {
            self.waiting.push_back(WaitingScope {
                scope,
                requests: VecDeque::from([request]),
            });
        }
        self.next_ticket = next;
        self.waiting_count = waiting_count;
        Ok(ticket)
    }

    pub(crate) fn admit_next(
        &mut self,
        retained_wal_bytes: Option<u64>,
    ) -> Option<AdmissionGrant<R>> {
        if self.active.len() >= self.limits.max_views {
            return None;
        }
        // Visit each waiting scope at most once. A scope waiting for a larger
        // reservation must not keep another eligible scope from progressing.
        for _ in 0..self.waiting.len() {
            let mut waiting = self.waiting.pop_front()?;
            let can_admit = waiting
                .requests
                .front()
                .is_some_and(|request| match request.cost {
                    CaptureCost::Native(bytes) => self
                        .native_bytes
                        .checked_add(bytes)
                        .is_some_and(|total| total <= self.limits.native_bytes),
                    CaptureCost::Sqlite => {
                        self.sqlite_readers < self.limits.sqlite_readers
                            && retained_wal_bytes
                                .is_some_and(|bytes| bytes < self.limits.wal_high_water)
                    }
                });
            if !can_admit {
                self.waiting.push_back(waiting);
                continue;
            }
            let request = waiting.requests.pop_front()?;
            if !waiting.requests.is_empty() {
                self.waiting.push_back(waiting);
            }
            match request.cost {
                CaptureCost::Native(bytes) => self.native_bytes += bytes,
                CaptureCost::Sqlite => self.sqlite_readers += 1,
            }
            self.waiting_count -= 1;
            self.active.insert(request.ticket, request.cost);
            return Some(AdmissionGrant {
                ticket: request.ticket,
                resident: request.resident,
            });
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn cancel(&mut self, ticket: AdmissionTicket) -> bool {
        self.take_pending(ticket).is_some()
    }

    /// The registry destroys cancelled resources after releasing its lock.
    pub(crate) fn take_pending(&mut self, ticket: AdmissionTicket) -> Option<R> {
        for scope_index in 0..self.waiting.len() {
            let waiting = &mut self.waiting[scope_index];
            if let Some(index) = waiting
                .requests
                .iter()
                .position(|request| request.ticket == ticket)
            {
                let request = waiting.requests.remove(index)?;
                self.waiting_count -= 1;
                if waiting.requests.is_empty() {
                    self.waiting.remove(scope_index);
                }
                return Some(request.resident);
            }
        }
        None
    }

    pub(crate) fn drain_pending(&mut self) -> Vec<R> {
        self.waiting_count = 0;
        self.waiting
            .drain(..)
            .flat_map(|scope| scope.requests.into_iter().map(|request| request.resident))
            .collect()
    }

    pub(crate) fn is_active(&self, ticket: AdmissionTicket) -> bool {
        self.active.contains_key(&ticket)
    }

    /// Recheck a queued native estimate before capturing any immutable root.
    /// Refusal leaves both the old reservation and the total unchanged.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn adjust_native_cost(
        &mut self,
        ticket: AdmissionTicket,
        bytes: u64,
    ) -> Result<bool, AdmissionError> {
        if bytes == 0 {
            return Err(AdmissionError::InvalidCost);
        }
        if bytes > self.limits.native_bytes {
            return Err(AdmissionError::CaptureTooLarge);
        }
        let Some(CaptureCost::Native(previous)) = self.active.get(&ticket).copied() else {
            return Err(AdmissionError::InvalidReservation);
        };
        let remaining = self
            .native_bytes
            .checked_sub(previous)
            .ok_or(AdmissionError::MetadataExhausted)?;
        let Some(total) = remaining.checked_add(bytes) else {
            return Ok(false);
        };
        if total > self.limits.native_bytes {
            return Ok(false);
        }
        self.active.insert(ticket, CaptureCost::Native(bytes));
        self.native_bytes = total;
        Ok(true)
    }

    pub(crate) fn release(&mut self, ticket: AdmissionTicket) -> bool {
        let Some(cost) = self.active.remove(&ticket) else {
            return false;
        };
        match cost {
            CaptureCost::Native(bytes) => self.native_bytes -= bytes,
            CaptureCost::Sqlite => self.sqlite_readers -= 1,
        }
        true
    }

    pub(crate) fn metrics(&self) -> AdmissionMetrics {
        AdmissionMetrics {
            active_views: self.active.len(),
            waiting_views: self.waiting_count,
            native_bytes: self.native_bytes,
            sqlite_readers: self.sqlite_readers,
        }
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
