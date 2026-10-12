# Keyed operational-state reads

Status: proposed for review. Addresses [SDK issue #1270](https://github.com/openpacketcore/openpacketcore-sdk/issues/1270).
Source baseline: `d50c92ad1fabeea13aae248b1851a8d7d5d217bb`.

Operational reads must support a list selection with no keys, some keys, or all
keys. Today the response contract requires exact path equality, and both servers
select returned state by exact lookup. A provider reporting several concrete list
instances therefore cannot answer an unkeyed request. Fix the shared contract
first, then preserve those instances through each server's selection and renderer.

## Response contract

`opc-mgmt-opstate::OperationalResponse::validate_for_request` accepts a response
path when it is an instance of at least one requested path:

- Both paths have the same number of segments and the same qualified node names.
- At every segment, every requested key is present with the same literal value.
  Omitted keys select any value; an asterisk has no special meaning.
- Keys added by the response identify the concrete instance. They cannot change
  a supplied key, another segment, a module, or the path depth.

For a synthetic list keyed by `site` and `name`, a request for
`/ex:system/ex:peer/ex:state/ex:up` can receive
`/ex:system/ex:peer[ex:site='east'][ex:name='a']/ex:state/ex:up` and the corresponding
path for peer `b`. Supplying only `site='east'` excludes west; supplying both keys
selects one peer. Apply this rule independently at every nested list level.

This is not a descendant-prefix rule: servers expand a requested subtree using
the schema before calling the provider. A provider cannot use a selected parent
to return arbitrary descendants. Overlapping selectors do not duplicate output;
a provider reporting the same concrete path twice still invalidates the response.
Any out-of-selection path invalidates the whole response, including one mixed
with otherwise valid values. Existing unexpected-origin rejection and omission
for absent state remain; provider failures remain errors. `value_for` keeps its
exact-lookup semantics.

Put the canonical path parser/comparator in `opc-mgmt-path`. Use it for
operational response and event validation, gNMI read selection and wire-path
conversion, and NETCONF instance selection/grouping. Do not leave a consumer
that interprets backslashes as escapes: the canonical builder uses literal
single-quoted values, preserves backslashes, and rejects embedded apostrophes.
Malformed paths, invalid names and duplicate predicates fail closed. Matching
uses equal qualified segment names and literal key values, not string prefixes,
predicate stripping, XPath evaluation or typed-value coercion.

The opstate matcher is protocol-neutral and validates syntax and the instance
relation. Before accepting a reported instance, each server must resolve its
parsed segments with the complete-key resolver and require the re-encoded
canonical path to equal the supplied path. This verifies declared keys, key
order, node kind, qualified names and complete tuples at every ancestor list.
Unknown keys/nodes, missing keys, keys on non-lists and non-canonical aliases
invalidate the whole response. Schema lookup alone is insufficient. Existing
schema-specific key/value type and range validation remains the model/binding's
responsibility; syntax matching must not be described as proving those checks.
Duplicate detection uses the validated concrete identity. `value_for` remains
an exact lookup. Partial-key resolution is a read-selection mode only; writes
and reported concrete instances continue to require complete declared keys.

## Server integration

**gNMI.** Use the partial-key read-selection mode for both prefix and path
resolution in Get and Subscribe planning. Replace exact operational-result
filtering with concrete `ReadSelectionEntry` values carrying the resolved schema
path and complete provider instance path. Preserve them through binding selection,
rendering and wire-path conversion; deduplicate overlapping selectors without
accepting duplicate provider values.

Apply the same matching, strict instance validation, identity dependencies,
payload filtering and limits to Get, ONCE/POLL, initial snapshots, SAMPLE,
heartbeat and resync, and separately to operational ON_CHANGE updates and deletes.
Update the independent ON_CHANGE planner and event handler; they do not inherit
all Get changes. Cover `updates_only`. Use Subscribe permission for every stream
emission, including required keys, with a fresh complete policy context for each
snapshot/event. Revoked identities must not be sent even in deletes. Filter
before output and instance-dependent telemetry. Preserve queue backpressure,
but do not retain per-denied-event activity counts as part of a no-disclosure
claim. ON_CHANGE change detection uses authorized content without fresh
observation timestamps; hidden-only changes must not create visible updates.

**NETCONF.** Carry instance constraints through XML filter parsing, schema
selection, `ReadSelection`, `get` and operational `get-data`, including binding
and generated-renderer contracts. An unkeyed subtree selector selects all
instances. In these two read operations only, admit schema-declared list-key
leaf content matches for partial/exact selection. Key predicates within one
list branch are conjunctive; sibling selection branches are alternatives and
must retain their own descendant selections and nested-list constraints.
Preserve XML namespace identity and literal text through decoding, matching and
escaped output. Bound accumulated filter text and node collection using the
existing XML limits, including text split across parser events.

Supported predicate-free XPath absolute paths, unions and wildcards must expand
the same concrete operational instances and apply the same authorization as
equivalent subtree reads. XPath predicates, including list-key predicates, remain
operation-not-supported; this change does not provide keyed XPath selection.
General non-key content matching and attribute matching remain unsupported.
Preserve `get-config`'s current filter subset and operational `get-data` capability,
config-filter, origin and max-depth restrictions. Do not silently discard an
unsupported predicate or widen a constrained request.

The generic operational XML renderer must group scalar leaves by qualified
container ancestry and complete list-key tuples, emit keys in schema order, and
serialize each actual list instance with normal namespace handling, escaping,
and redaction. Merge configuration and state at the same instance identity for
`get`; distinct instances must remain distinct. The configuration projection must
also honor the original instance selection. Extend the renderer selection contract
in `opc-mgmt-schema` and generated bindings as needed: no schema-only fallback may
widen a constrained read. Empty provider results produce no invented instances,
keys, defaults, or state values.

Expansion renders individually selected state values. Expanded container/list
payloads require a binding that filters and authorizes their children; generic
adapters reject such opaque aggregates. Existing exact-value encoding contracts
remain. The generic NETCONF renderer's unsupported object/array shapes and
keyless-list projection remain unsupported.

## Authorization, filtering, and bounds

Use the existing `ReadAuthorizer` with Read for Get/NETCONF reads and Subscribe
for streams. For each read or snapshot, expand the request's schema selection,
add all required identifying key leaves at every composite and ancestor list,
deduplicate these schema paths, and authorize them in one batch before provider
access. Retain that complete decision set for config and operational projection
throughout this operation. A second call to `authorize` reloads policy and is not
the same snapshot. Each subsequent snapshot/event obtains its own complete
decision set. Policy-source failure fails closed with a fixed reason.
If separate schema registries require separate authorization batches, evaluate
them against the same explicitly captured policy/principal context; do not
assume repeated calls to the current `authorize` API retain that context.

Prune a selected state branch from the provider request if its requested leaf or
any identifying key is denied. Key dependencies are checked even when unrequested
or config-true in a state-only read. They do not add unrelated payload selections
or unrequested gNMI key-leaf updates. A structural node grants no child permission.
Validate the complete provider response, then map every concrete entry back to
the retained schema decisions and original key/model/origin/data-type/protocol
constraints. Expansion supplies new instances, never new schema permissions.
The policy remains schema-node scoped; this introduces no per-instance NACM.

For Get and Subscribe, apply the #1269 identity rule: an otherwise permitted
sensitive key may identify the real instance in a gNMI path. Sensitivity alone
must not restore blanket list suppression. Keep selected sensitive key and
non-key payloads masked. For NETCONF, preserve the existing data-class masking
of key-leaf payloads. Group and merge by the complete authorized identity before
redaction, never by masked key text. A denied key omits the dependent operational
entry in exact and expanded reads; no incomplete identity or invented row is
rendered. This does not authorize unmasking XML payloads or changing unrelated
configuration-renderer missing-key behavior. Generated/custom binding hooks must
honor concrete selections and the same payload contract.

Normal authorization omission reveals no refused instance through paths,
prefixes, payloads, deletes, placeholders, error detail, Debug/log output, audit
records, counts or metric labels. Preserve #435 sensitive model formatters and
use safe diagnostics for path-bearing request/response/event objects. Preserve
request/schema-level audit and denial decisions, deduplicated independently of
provider instance count; do not emit one denial record per hidden row or event.
This includes the authorizer's automatic tracing during stream reevaluation:
per-event authorization must not itself publish hidden-event activity.
Prune schema-denied branches before provider enumeration or config-row traversal.
Do not claim constant-time execution or arbitrary-provider noninterference.
Malformed, duplicate, unsolicited or out-of-request provider output still fails
the whole response with fixed, value-free and observed-count-free diagnostics;
it must not be silently converted to successful omission.

Before server-side parsing/projection or allocating per-entry indexes, reject
a provider response with more than N = `max_paths_per_request` reported values.
Then reject any JSON value whose encoded byte length exceeds
V = `max_value_bytes` before projection. Apply the same checks to both servers and
Subscribe snapshots; retain per-update limits for operational events. Overflow
fails the whole read with no truncated success, using the existing protocol limit
classification and fixed diagnostic detail without actual counts or key lengths.
The defaults are N = 1024 and V = 1 MiB: N times V permits up to 1 GiB of raw JSON
payload alone. These acceptance checks are new requirements on expanded output,
not proof that the baseline already applies them there.

The synchronous provider returns an already allocated vector and receives no
SDK result budget, paging credit or allocation limit. Provider result construction
and peak memory are unbounded by this interface. This design also sets no bound
on canonical response-path bytes, total rendered output, custom renderer work or
overall server memory. Count/per-JSON-value checks do not supply those bounds.
Existing input transport/XML limits do not cap provider allocations or replies.
gNMI queues bound object count using
clamp(floor(`max_subscriber_queue_bytes` / 4096), 1, 1024), default 1024, and await
capacity on send. They do not enforce the configured byte value against actual
expanded messages. A hard end-to-end memory bound would require a separate
provider-budget/streaming and retained-byte/output-limit contract.

## Failing tests first

Give the regressions explicit names and exact outcomes. Required test contracts:

- `operational_response_matches_key_subsets`: no/partial/all keys, nested
  composite lists, literal asterisk, overlap and unchanged exact lookup.
- `operational_response_rejects_invalid_members_atomically`: wrong
  key/module/node/depth, malformed/duplicate predicates, duplicate values,
  unsolicited origin and valid-plus-invalid mixtures.
- `operational_paths_round_trip_canonical_literals` and
  `operational_instances_require_complete_declared_keys`: all parser/encoder
  consumers, literal/trailing backslashes, delimiters, strict concrete paths,
  canonical ordering and unchanged complete-key write rejection.
- `gnmi_operational_get_expands_instances`: real root/prefix/collection/leaf
  requests return exactly zero/one/many selected instances, without fabrication.
- `operational_reads_use_one_policy_context`,
  `operational_denied_key_prunes_allowed_child`,
  `operational_denial_diagnostics_do_not_count_instances` and
  `operational_expansion_preserves_filters`: one context including effective
  groups and all keys, pre-provider pruning, unchanged allowed siblings,
  model/type/origin/branch constraints and no instance-dependent diagnostics.
- `gnmi_keyed_subscribe_snapshots_and_events` and
  `gnmi_keyed_subscribe_revocation_and_hidden_changes`: every snapshot mode,
  ON_CHANGE update/delete, updates_only, partial-key planning, Read versus
  Subscribe, policy failure/revocation and controlled hidden-change observations.
- `netconf_keyed_get_preserves_instance_tree` and
  `netconf_keyed_xpath_and_operational_get_data`: subtree key subsets and branch
  correlation, supported XPath expansion and predicate rejection, operational
  get-data filters, nested/sibling identities, config/state merge, namespaces,
  escaped keys, no defaults/placeholders for absent instances and no widening.
- `operational_expansion_limits_are_checked_before_projection`: configured N/V
  boundaries, overflow from one broad selector, no renderer call or partial
  success after overflow, fixed diagnostics, and an explicit control documenting
  the absence of a canonical-path-byte bound.
- `operational_opaque_aggregate_cannot_bypass_selection` and
  `operational_expansion_preserves_sensitive_encoding_and_debug`: child access
  inside aggregates, permitted sensitive identities, unchanged payload masking
  and #435 Debug/Display/serialization protection.

After the quiet window, record each test's exact command and candidate revision.
Demonstrate separate failing changes for exact-only matching/result lookup,
missing strict path validation, dropping predicates/branch constraints, bypassing
leaf or identity authorization, reloading policy between dependencies, skipping
event enforcement, bypassing response limits and removing diagnostic redaction.
Existing exact-read, denied-leaf, duplicate/origin, unsupported-filter and Debug
tests are preservation controls: they may already pass at baseline and must fail
when their own guard is removed, not necessarily when expansion alone is absent.
Inspect complete decoded paths/payloads, error detail/Debug, logs, audit and metric
observations, including counts. Renderer-only fixtures cannot prove authenticated
server behavior. Record intentional test replacements in the required inventory.

Run the focused contract/server/codegen regressions, then the repository's
required final gates on the implementation candidate. This note changes no stored
format, provider lifecycle, or deployment procedure. Existing origin and NMDA
capability restrictions stay in force.
