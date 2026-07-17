//! Ordered committed-revision history, follower-local watches, and atomic
//! snapshot-plus-resume recovery.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt;
use opc_config_model::OpcConfig;
use opc_types::{ConfigVersion, TxId};
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::commit::ConfigBus;
use crate::datastore::ManagedDatastore;
use crate::restore::validate_stored_schema_digest;
use crate::types::{PublishedSnapshot, StoreError, StoredConfig};

/// Maximum number of complete config revisions returned by one datastore page.
///
/// A watch buffers at most one such page per consumer and emits one revision
/// per stream item. Config payload size remains governed by the config bus's
/// candidate admission limit; this bound prevents record-count amplification.
pub const MAX_CONFIG_HISTORY_PAGE_ENTRIES: usize = 64;

/// Exclusive position in ordered committed running-config history.
///
/// A cursor at version `V` requests only `V + 1` and later. This matches the
/// snapshot recovery contract: install `snapshot@V`, then resume from its
/// cursor without replaying `V` or skipping `V + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRevisionCursor {
    after: ConfigVersion,
}

impl ConfigRevisionCursor {
    /// Creates an exclusive cursor after `version`.
    pub const fn after(version: ConfigVersion) -> Self {
        Self { after: version }
    }

    /// Returns the last revision already installed by the consumer.
    pub const fn version(self) -> ConfigVersion {
        self.after
    }

    fn next_version(self) -> Option<ConfigVersion> {
        self.after.next()
    }
}

/// One immutable running-config revision emitted only after its datastore
/// authority reports it committed, locally applied, and publication-safe.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedConfigHistoryEntry<C: OpcConfig> {
    /// Durable transaction identifier for this revision.
    pub tx_id: TxId,
    /// Gap-free committed running-config version.
    pub version: ConfigVersion,
    /// Complete immutable running-config payload at `version`.
    pub config: C,
}

impl<C: OpcConfig> fmt::Debug for CommittedConfigHistoryEntry<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedConfigHistoryEntry")
            .field("tx_id", &self.tx_id)
            .field("version", &self.version)
            .field("config", &"<redacted>")
            .finish()
    }
}

impl<C: OpcConfig> CommittedConfigHistoryEntry<C> {
    fn try_from_stored(record: StoredConfig<C>) -> Result<Self, StoreError> {
        validate_publication_safe_record(&record)?;
        Ok(Self {
            tx_id: record.tx_id,
            version: record.version,
            config: record.config,
        })
    }
}

/// One bounded, strictly ordered page of committed config revisions.
#[derive(Clone, Serialize)]
pub struct ConfigHistoryPage<C: OpcConfig> {
    requested_from: ConfigRevisionCursor,
    next_cursor: ConfigRevisionCursor,
    entries: Vec<CommittedConfigHistoryEntry<C>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfigHistoryPage<C: OpcConfig> {
    requested_from: ConfigRevisionCursor,
    next_cursor: ConfigRevisionCursor,
    entries: BoundedHistoryEntries<C>,
}

struct BoundedHistoryEntries<C: OpcConfig>(Vec<CommittedConfigHistoryEntry<C>>);

struct BoundedHistoryEntriesVisitor<C: OpcConfig>(std::marker::PhantomData<fn() -> C>);

impl<'de, C> Visitor<'de> for BoundedHistoryEntriesVisitor<C>
where
    C: OpcConfig + Deserialize<'de>,
{
    type Value = BoundedHistoryEntries<C>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_CONFIG_HISTORY_PAGE_ENTRIES} committed config history entries"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let hinted_entries = sequence.size_hint().unwrap_or(0);
        if hinted_entries > MAX_CONFIG_HISTORY_PAGE_ENTRIES {
            return Err(serde::de::Error::invalid_length(hinted_entries, &self));
        }

        let mut entries = Vec::with_capacity(hinted_entries);
        while entries.len() < MAX_CONFIG_HISTORY_PAGE_ENTRIES {
            let Some(entry) = sequence.next_element()? else {
                return Ok(BoundedHistoryEntries(entries));
            };
            entries.push(entry);
        }

        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::invalid_length(
                MAX_CONFIG_HISTORY_PAGE_ENTRIES + 1,
                &self,
            ));
        }

        Ok(BoundedHistoryEntries(entries))
    }
}

impl<'de, C> Deserialize<'de> for BoundedHistoryEntries<C>
where
    C: OpcConfig + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedHistoryEntriesVisitor(std::marker::PhantomData))
    }
}

impl<'de, C> Deserialize<'de> for ConfigHistoryPage<C>
where
    C: OpcConfig + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WireConfigHistoryPage::deserialize(deserializer)?;
        let supplied_next = wire.next_cursor;
        let page =
            Self::try_new(wire.requested_from, wire.entries.0).map_err(serde::de::Error::custom)?;
        if supplied_next != page.next_cursor {
            return Err(serde::de::Error::custom(
                "committed config history page cursor does not match its entries",
            ));
        }
        Ok(page)
    }
}

impl<C: OpcConfig> fmt::Debug for ConfigHistoryPage<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let versions: Vec<_> = self.entries.iter().map(|entry| entry.version).collect();
        formatter
            .debug_struct("ConfigHistoryPage")
            .field("requested_from", &self.requested_from)
            .field("next_cursor", &self.next_cursor)
            .field("versions", &versions)
            .finish()
    }
}

impl<C: OpcConfig> ConfigHistoryPage<C> {
    /// Validates and constructs a transport-neutral history page.
    ///
    /// Entries must begin at the exact successor of `requested_from`, remain
    /// contiguous, and fit the public page bound. Empty pages retain the input
    /// cursor. Wire adapters should call this after decoding an untrusted page.
    pub fn try_new(
        requested_from: ConfigRevisionCursor,
        entries: Vec<CommittedConfigHistoryEntry<C>>,
    ) -> Result<Self, StoreError> {
        if entries.len() > MAX_CONFIG_HISTORY_PAGE_ENTRIES {
            return Err(StoreError::history_page_too_large(format!(
                "committed config history page has {} entries; maximum is {}",
                entries.len(),
                MAX_CONFIG_HISTORY_PAGE_ENTRIES
            )));
        }

        let mut expected = requested_from.next_version();
        let mut next_cursor = requested_from;
        for entry in &entries {
            if expected != Some(entry.version) {
                return Err(StoreError::invalid_history_sequence(
                    "committed config history is not the exact cursor successor",
                ));
            }
            next_cursor = Self::advance_cursor(entry.version);
            expected = entry.version.next();
        }

        Ok(Self {
            requested_from,
            next_cursor,
            entries,
        })
    }

    fn advance_cursor(version: ConfigVersion) -> ConfigRevisionCursor {
        ConfigRevisionCursor::after(version)
    }

    /// Returns the exclusive cursor used to request this page.
    pub const fn requested_from(&self) -> ConfigRevisionCursor {
        self.requested_from
    }

    /// Returns the cursor after the last entry, or the input cursor when empty.
    pub const fn next_cursor(&self) -> ConfigRevisionCursor {
        self.next_cursor
    }

    /// Returns the ordered revisions without exposing mutable page storage.
    pub fn entries(&self) -> &[CommittedConfigHistoryEntry<C>] {
        &self.entries
    }

    /// Consumes the page and returns its ordered revisions.
    pub fn into_entries(self) -> Vec<CommittedConfigHistoryEntry<C>> {
        self.entries
    }

    /// Returns `true` when this page carried no revisions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of revisions in this bounded page.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Gap-free stream of committed running-config revisions.
pub type ConfigRevisionStream<C> =
    BoxStream<'static, Result<CommittedConfigHistoryEntry<C>, StoreError>>;

/// Atomic recovery result: install the complete snapshot, then consume the
/// stream, which begins strictly after the snapshot version.
pub struct ConfigRecovery<C: OpcConfig> {
    snapshot: PublishedSnapshot<C>,
    stream: ConfigRevisionStream<C>,
}

impl<C: OpcConfig> fmt::Debug for ConfigRecovery<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigRecovery")
            .field("tx_id", &self.snapshot.tx_id)
            .field("version", &self.snapshot.version)
            .field("config", &"<redacted>")
            .field("stream", &"<committed-revision-stream>")
            .finish()
    }
}

impl<C: OpcConfig> ConfigRecovery<C> {
    /// Returns the complete snapshot that must be installed before polling the
    /// stream.
    pub fn snapshot(&self) -> &PublishedSnapshot<C> {
        &self.snapshot
    }

    /// Consumes the recovery value into its snapshot and exactly positioned
    /// committed tail.
    pub fn into_parts(self) -> (PublishedSnapshot<C>, ConfigRevisionStream<C>) {
        (self.snapshot, self.stream)
    }
}

struct CommittedWatchState<C: OpcConfig> {
    store: Arc<dyn ManagedDatastore<C>>,
    cursor: ConfigRevisionCursor,
    backlog: VecDeque<CommittedConfigHistoryEntry<C>>,
    repage_immediately: bool,
    terminal: bool,
}

impl<C: OpcConfig> ConfigBus<C> {
    /// Loads one bounded page strictly after `cursor` from this node's local
    /// committed datastore view.
    ///
    /// The returned page is validated again at the bus boundary even when the
    /// adapter already validates it. A duplicate, gap, oversized result, or
    /// schema mismatch fails closed before any payload reaches a consumer.
    pub async fn load_committed_page(
        &self,
        cursor: ConfigRevisionCursor,
        limit: usize,
    ) -> Result<ConfigHistoryPage<C>, StoreError> {
        load_committed_page_from_store(self.store.as_ref(), cursor, limit).await
    }

    /// Opens a follower-local, gap-free committed-revision watch after `from`.
    ///
    /// Registration first captures a durable page and then repeatedly repages
    /// the same local state-machine-applied history. Therefore a revision that
    /// races registration is either in the captured page or the next page;
    /// the stream never depends on leader-local in-memory fanout. Slow
    /// consumers retain at most one bounded page and cannot delay publication
    /// or another consumer. A compacted cursor returns `HistoryCompacted`,
    /// requiring [`ConfigBus::recover_from`] instead of silently skipping. An
    /// applied row whose `recovery_required` marker remains set is not visible;
    /// the watch stays at the last cleared prefix until a successful clear is
    /// itself locally applied.
    pub async fn watch_committed(
        &self,
        from: ConfigVersion,
    ) -> Result<ConfigRevisionStream<C>, StoreError>
    where
        C: 'static,
    {
        let head =
            self.store.load_committed_latest().await?.ok_or_else(|| {
                StoreError::not_found("committed config history has no applied head")
            })?;
        validate_publication_safe_record(&head)?;
        if from > head.version {
            return Err(StoreError::history_cursor_ahead(format!(
                "watch cursor {from} is newer than local committed head {}",
                head.version
            )));
        }
        if from.next().is_none() {
            return Ok(stream::empty().boxed());
        }
        let cursor = ConfigRevisionCursor::after(from);
        let initial = self
            .load_committed_page(cursor, MAX_CONFIG_HISTORY_PAGE_ENTRIES)
            .await?;
        let repage_immediately = !initial.is_empty();
        let state = CommittedWatchState {
            store: Arc::clone(&self.store),
            cursor: initial.next_cursor(),
            backlog: initial.into_entries().into(),
            repage_immediately,
            terminal: false,
        };

        Ok(stream::unfold(state, |mut state| async move {
            loop {
                if state.terminal {
                    return None;
                }
                if let Some(entry) = state.backlog.pop_front() {
                    return Some((Ok(entry), state));
                }
                if !state.repage_immediately {
                    if let Err(error) = state
                        .store
                        .wait_for_committed_change(state.cursor.version())
                        .await
                    {
                        state.terminal = true;
                        return Some((Err(error), state));
                    }
                }

                match load_committed_page_from_store(
                    state.store.as_ref(),
                    state.cursor,
                    MAX_CONFIG_HISTORY_PAGE_ENTRIES,
                )
                .await
                {
                    Ok(page) => {
                        state.repage_immediately = !page.is_empty();
                        state.cursor = page.next_cursor();
                        state.backlog = page.into_entries().into();
                    }
                    Err(error) => {
                        state.terminal = true;
                        return Some((Err(error), state));
                    }
                }
            }
        })
        .boxed())
    }

    /// Atomically recovers a complete local committed snapshot and an ordered
    /// tail positioned strictly after it.
    ///
    /// `known` is a monotonic floor. If it is newer than this follower's local
    /// Openraft-applied head, recovery fails with `HistoryCursorAhead` instead
    /// of moving the consumer backward. A commit racing the head read is
    /// discovered by durable repaging after the selected snapshot, so there is
    /// no snapshot/subscribe gap or overlap.
    pub async fn recover_from(
        &self,
        known: Option<ConfigVersion>,
    ) -> Result<ConfigRecovery<C>, StoreError>
    where
        C: 'static,
    {
        let durable =
            self.store.load_committed_latest().await?.ok_or_else(|| {
                StoreError::not_found("committed config history has no applied head")
            })?;
        validate_publication_safe_record(&durable)?;
        let snapshot = PublishedSnapshot {
            tx_id: Some(durable.tx_id),
            version: durable.version,
            config: Arc::new(durable.config),
        };

        if known.is_some_and(|known| known > snapshot.version) {
            return Err(StoreError::history_cursor_ahead(format!(
                "known config version is newer than local committed head {}",
                snapshot.version
            )));
        }

        let stream = self.watch_committed(snapshot.version).await?;
        Ok(ConfigRecovery { snapshot, stream })
    }
}

fn validate_publication_safe_record<C: OpcConfig>(
    record: &StoredConfig<C>,
) -> Result<(), StoreError> {
    validate_stored_schema_digest(record)?;
    if record.recovery_required {
        return Err(StoreError::restore_recovery_required(
            "committed config revision remains fenced from publication",
        ));
    }
    Ok(())
}

async fn load_committed_page_from_store<C: OpcConfig>(
    store: &dyn ManagedDatastore<C>,
    cursor: ConfigRevisionCursor,
    limit: usize,
) -> Result<ConfigHistoryPage<C>, StoreError> {
    if limit > MAX_CONFIG_HISTORY_PAGE_ENTRIES {
        return Err(StoreError::history_page_too_large(format!(
            "requested {limit} committed config revisions; maximum is {MAX_CONFIG_HISTORY_PAGE_ENTRIES}"
        )));
    }
    if limit == 0 {
        return ConfigHistoryPage::try_new(cursor, Vec::new());
    }

    let records = store.load_since(cursor.version(), limit).await?;
    if records.len() > limit {
        return Err(StoreError::history_page_too_large(
            "committed config datastore returned more entries than requested",
        ));
    }
    let entries = records
        .into_iter()
        .map(CommittedConfigHistoryEntry::try_from_stored)
        .collect::<Result<Vec<_>, _>>()?;
    ConfigHistoryPage::try_new(cursor, entries)
}
