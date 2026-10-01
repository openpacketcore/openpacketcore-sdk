//! Synchronous borrows of the actual native append owners. The encoder context
//! holds numeric extents only and cannot outlive its borrowed append frame.
//! No address, command, JSON buffer or storage handle escapes in a sample.

use super::*;
use opc_consensus::engine::Entry;

/// Concrete checkpoints within one native append, not independently added peaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendStage {
    /// After semantic prevalidation, before the next entry's cancellation
    /// check and JSON count pass.
    EncodingStarted,
    /// The current output has reserved its actual capacity but is still empty.
    JsonAllocated,
    /// The current output contains its first successfully written JSON token.
    JsonWriting,
    /// The emitting pass returned, with its original output still owned.
    JsonWritten,
    /// An emitting pass failed or was cancelled, before its output is dropped.
    JsonRejected,
    /// Encoding rejected without retaining an output for the rejected entry.
    EncodingRejected,
    /// All output Vecs and their descriptor Vec remain live before SQLite writes.
    OutputsReady,
}

/// One simultaneous, redaction-safe append census. Allocator/Arc headers,
/// unrecognized payloads, and the caller's entries Vec backing are excluded.
/// The append API receives a slice, so its original Vec capacity is unknowable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendOwnerSample {
    /// Source bound to the exact connection registration.
    pub source: ConsensusNodeId,
    /// Selected original request, not inferred from a phase maximum.
    pub request: ConsensusRequestId,
    /// Per-registration append generation; repeated checkpoints share this ID.
    pub batch: u64,
    /// Actual synchronous checkpoint.
    pub stage: AppendStage,
    /// Current immutable preparation registrations, held through the callback.
    pub preparations: PreparationTotals,
    /// Total entries in the original borrowed slice.
    pub entries: usize,
    /// Entries whose payload allocation representation is not measured.
    pub unmeasured_entries: usize,
    /// Entries bearing the selected request, including immutable aliases.
    pub selected_entries: usize,
    /// Completed outputs still held in the original descriptor Vec.
    pub completed_outputs: usize,
    /// Allocation union of all recognized original entry payloads.
    pub entry_payload_bytes: usize,
    /// Allocation union of selected original entry payloads only.
    pub selected_entry_bytes: usize,
    /// Actual descriptor Vec capacity in bytes, shared by the whole batch.
    /// Charge once per batch, separately from per-request mutation totals.
    pub descriptor_bytes: usize,
    /// Union of all currently live JSON output capacities, including in-flight.
    pub json_bytes: usize,
    /// Union of selected request's currently live JSON output capacities.
    pub selected_json_bytes: usize,
    /// Current encoder-local Vec capacity; zero outside that synchronous borrow.
    pub current_output_bytes: usize,
    /// Current encoder-local initialized length, for lifecycle diagnostics only.
    pub current_output_len: usize,
    /// Source preparations union before joining the append allocations.
    pub node_prepared_bytes: usize,
    /// Selected immutable preparation union before joining append allocations.
    pub selected_prepared_bytes: usize,
    /// Selected preparation/entry/output union; excludes shared descriptor bytes.
    pub selected_mutation_bytes: usize,
    /// Source preparations/entries/outputs/descriptor allocation-identity union.
    pub node_mutation_bytes: usize,
}

struct Buffers {
    payloads: Allocations,
    selected_payloads: Allocations,
    descriptors: Allocations,
    json: Allocations,
    selected_json: Allocations,
    entries: usize,
    selected_entries: usize,
    unmeasured_entries: usize,
    completed_outputs: usize,
    current_selected: bool,
}

fn selected(entry: &Entry<ConfigRaftTypeConfig>, request: ConsensusRequestId) -> bool {
    matches!(&entry.payload, EntryPayload::Normal(command) if command.request_id == request)
}

impl Buffers {
    fn borrow(
        entries: &[Entry<ConfigRaftTypeConfig>],
        encoded: &Vec<Vec<u8>>,
        request: ConsensusRequestId,
    ) -> Self {
        let mut value = Self {
            payloads: Allocations::new(),
            selected_payloads: Allocations::new(),
            descriptors: Allocations::new(),
            json: Allocations::new(),
            selected_json: Allocations::new(),
            entries: entries.len(),
            selected_entries: 0,
            unmeasured_entries: 0,
            completed_outputs: encoded.len(),
            current_selected: entries
                .get(encoded.len())
                .is_some_and(|entry| selected(entry, request)),
        };
        vector(&mut value.descriptors, encoded);
        for entry in entries {
            let is_selected = selected(entry, request);
            value.selected_entries += usize::from(is_selected);
            let payload = match &entry.payload {
                EntryPayload::Blank => Some(Allocations::new()),
                EntryPayload::Normal(command) => match &command.intent {
                    ConfigMutationIntent::BoundedAppend { commit, .. } => {
                        Some(commit_allocations(commit))
                    }
                    ConfigMutationIntent::AuditedMutation(command) => audited_allocations(command),
                    _ => None,
                },
                EntryPayload::Membership(_) => None,
            };
            if let Some(payload) = payload {
                if is_selected {
                    value
                        .selected_payloads
                        .extend(payload.iter().map(|(&address, &bytes)| (address, bytes)));
                }
                value.payloads.extend(payload);
            } else {
                value.unmeasured_entries += 1;
            }
        }
        for (entry, output) in entries.iter().zip(encoded) {
            vector(&mut value.json, output);
            if selected(entry, request) {
                vector(&mut value.selected_json, output);
            }
        }
        value
    }

    fn capture(&self, shared: &Shared, batch: u64, stage: AppendStage, current: Option<&Vec<u8>>) {
        // The live append/encoder frame protects native owners; this existing
        // drop barrier additionally protects immutable preparations while the
        // observer synchronously joins transport/TLS. Only counters may reenter.
        let preparations = lock(&shared.preparations.state);
        let (mut node, mut selected, _) = preparation_allocations(&preparations, shared);
        let node_prepared_bytes = node.values().sum();
        let selected_prepared_bytes = selected.values().sum();
        let mut json = self.json.clone();
        let mut selected_json = self.selected_json.clone();
        if let Some(output) = current {
            vector(&mut json, output);
            if self.current_selected {
                vector(&mut selected_json, output);
            }
        }
        for allocations in [&self.payloads, &self.descriptors, &json] {
            node.extend(
                allocations
                    .iter()
                    .map(|(&address, &bytes)| (address, bytes)),
            );
        }
        for allocations in [&self.selected_payloads, &selected_json] {
            selected.extend(
                allocations
                    .iter()
                    .map(|(&address, &bytes)| (address, bytes)),
            );
        }
        shared.append_callbacks.fetch_add(1, Ordering::SeqCst);
        shared.observer.observe_append_with_allocations(
            AppendOwnerSample {
                source: shared.source,
                request: shared.request,
                batch,
                stage,
                preparations: preparation_totals(&preparations),
                entries: self.entries,
                selected_entries: self.selected_entries,
                unmeasured_entries: self.unmeasured_entries,
                completed_outputs: self.completed_outputs,
                entry_payload_bytes: self.payloads.values().sum(),
                selected_entry_bytes: self.selected_payloads.values().sum(),
                descriptor_bytes: self.descriptors.values().sum(),
                json_bytes: json.values().sum(),
                selected_json_bytes: selected_json.values().sum(),
                current_output_bytes: current.map_or(0, Vec::capacity),
                current_output_len: current.map_or(0, Vec::len),
                node_prepared_bytes,
                selected_prepared_bytes,
                selected_mutation_bytes: selected.values().sum(),
                node_mutation_bytes: node.values().sum(),
            },
            raft_buffers::AllocationView::new(shared.identity, shared.source, &node),
        );
    }
}

/// Metadata-only scope. Declaration before the output owners ensures counters
/// drain after those locals on errors; callback samples themselves never persist.
pub(crate) struct AppendScope<'a> {
    shared: Arc<Shared>,
    batch: u64,
    borrowed: PhantomData<&'a [Entry<ConfigRaftTypeConfig>]>,
}

impl<'a> AppendScope<'a> {
    pub(crate) fn start(
        conn: &Connection,
        identity: ConsensusIdentity,
        entries: &'a [Entry<ConfigRaftTypeConfig>],
    ) -> Option<Self> {
        let shared = lock(&REGISTRY)
            .get(&(std::ptr::from_ref(conn) as usize))
            .and_then(Weak::upgrade)?;
        if identity != shared.identity
            || !entries.iter().any(|entry| selected(entry, shared.request))
        {
            return None;
        }
        let batch = shared
            .next_append
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .ok()?
            .checked_add(1)?;
        shared.append_scopes.fetch_add(1, Ordering::SeqCst);
        Some(Self {
            shared,
            batch,
            borrowed: PhantomData,
        })
    }

    pub(crate) fn encoding<'b>(
        &'b self,
        entries: &'b [Entry<ConfigRaftTypeConfig>],
        encoded: &'b Vec<Vec<u8>>,
    ) -> Option<EncodingScope<'b>> {
        ENCODING.with(|slot| {
            let mut active = slot.borrow_mut();
            if active.is_some() {
                return None;
            }
            *active = Some(Encoding {
                shared: self.shared.clone(),
                batch: self.batch,
                buffers: Buffers::borrow(entries, encoded, self.shared.request),
            });
            Some(EncodingScope {
                borrowed: PhantomData,
            })
        })
    }

    pub(crate) fn capture(
        &self,
        entries: &[Entry<ConfigRaftTypeConfig>],
        encoded: &Vec<Vec<u8>>,
        stage: AppendStage,
    ) {
        Buffers::borrow(entries, encoded, self.shared.request).capture(
            &self.shared,
            self.batch,
            stage,
            None,
        );
    }
}

impl Drop for AppendScope<'_> {
    fn drop(&mut self) {
        self.shared.append_scopes.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Encoding {
    shared: Arc<Shared>,
    batch: u64,
    buffers: Buffers,
}

thread_local! { static ENCODING: RefCell<Option<Encoding>> = const { RefCell::new(None) }; }

pub(crate) struct EncodingScope<'a> {
    borrowed: PhantomData<(&'a AppendScope<'a>, &'a Vec<Vec<u8>>)>,
}

impl Drop for EncodingScope<'_> {
    fn drop(&mut self) {
        ENCODING.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

pub(crate) fn encoding_output(stage: AppendStage, output: Option<&Vec<u8>>) {
    ENCODING.with(|slot| {
        if let Some(active) = slot.borrow().as_ref() {
            active
                .buffers
                .capture(&active.shared, active.batch, stage, output);
        }
    });
}
