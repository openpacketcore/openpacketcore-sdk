# Keyed operational-state reads

Addresses [SDK issue #1270](https://github.com/openpacketcore/openpacketcore-sdk/issues/1270).
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
- At every segment, every requested key is present with the same value under the
  canonical key rules below. Omitted keys select any value; an asterisk inside a
  canonical path is literal.
- Keys added by the response identify the concrete instance. They cannot change a
  supplied key, another segment, a module, or the path depth.

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

Servers order accepted entries by canonical path, never by provider order, so equal
authorized content always renders and fingerprints identically; NETCONF keeps
configuration order for instances present in configuration.

Put the canonical path parser/comparator in `opc-mgmt-path`. Use it for operational
response and event validation, gNMI read selection and wire-path conversion, and NETCONF
instance selection/grouping. The generated gNMI renderer uses this shared builder for
its key predicates. Do not leave a consumer that interprets backslashes as escapes or a
producer that writes them, including the generated gNMI renderer's key predicates. The
canonical builder writes literal values and preserves backslashes, in single quotes, or
in double quotes when the value contains an apostrophe, as XPath literals allow; a value
containing both quote characters fails closed. Malformed paths, invalid names and
duplicate predicates fail closed. Matching uses equal qualified segment names and equal
key values, not string prefixes, predicate stripping or XPath evaluation. Integer and
boolean keys (a leafref key takes its target's type) compare in their RFC 7950 canonical
form: read selection canonicalizes requested values, a requested value invalid for its
type selects nothing, and a reported key that is not already canonical invalidates the
whole response. Other key types compare literally. A reported value at a key leaf must
equal that instance's key, and renderers emit each key once, from the validated
identity.

The opstate matcher is protocol-neutral and validates syntax and the instance relation.
Before accepting a reported instance, each server must resolve its parsed segments with
the complete-key resolver and require the re-encoded canonical path to equal the
supplied path. This verifies declared keys, key order, node kind, qualified names and
complete tuples at every ancestor list. Unknown keys/nodes, missing keys, keys on
non-lists and non-canonical aliases invalidate the whole response. Schema lookup alone
is insufficient. Other type, range and pattern validation remains the model/binding's
responsibility; syntax matching must not be described as proving those checks. Duplicate
detection uses the validated concrete identity. `value_for` remains an exact lookup.
Partial-key resolution is a read-selection mode only; writes and reported concrete
instances continue to require complete declared keys.

## Server integration

**gNMI.** Use the partial-key read-selection mode for both prefix and path resolution in
Get and Subscribe planning. In gNMI read selection, a key value of exactly `*` is the
gNMI wildcard and selects as if that key were omitted; element-name wildcards remain
rejected. Canonical paths and NETCONF keep `*` literal. Replace exact operational-result
filtering with concrete `ReadSelectionEntry` values carrying the resolved schema path
and complete provider instance path. Preserve them through binding selection, rendering
and wire-path conversion; deduplicate overlapping selectors without accepting duplicate
provider values.

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

Exact and expanded Subscribe selections follow #1269's subscription authorization
and revocation contract. Access-policy and resolved-principal-context changes
independently wake every affected active stream, including idle operational-only
ON_CHANGE streams without SAMPLE or heartbeat; periodic authorization polling is not
used. Reevaluate requested nodes, identifying keys, aggregate-descendant
dependencies and the previously permitted schema/dependency set together against one
fresh policy context. Loss of any previously permitted node or dependency ends the
stream with the fixed, value-free status and no keyed delete, without waiting for
another data event. Preserve #1269's atomic notification registration and initial
revision capture, ordered lossless control delivery, revision-completion
acknowledgement, output gating and fail-closed delivery/refresh behavior. Provider
work, hidden events, audit writes and output backpressure must not gate this control
path.

The SDK applies the subscription re-establishment rule in
[RFC 8641 section 3.9](https://www.rfc-editor.org/rfc/rfc8641.html#section-3.9)
to gNMI; the client re-subscribes under the current policy.

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

For Get and Subscribe, apply the #1269 identity rule. For a permitted entry whose key
leaves all have a data class that allows cleartext (DataClass::allows_cleartext), encode
the real key in the canonical gNMI path through explicit inner-value access, as #1269
requires, and render a selected key leaf with that same value, as NETCONF does. A key
whose class forbids cleartext (security-secret, lawful-intercept, or the security-secret
class assigned to a secret-like name) never enters a gNMI path, real, masked or hashed:
when its keys are allowed, a selected non-empty list keeps today's fixed, schema-only
refusal; when a key is denied, the list is omitted like any other. NETCONF keeps
rendering such a key masked, because an XML key element can carry a masked value and a
gNMI path cannot. Non-key payload values keep their data-class masking.

Refuse a requested key-value match when the key's reply value is masked: its class
forbids cleartext, its name assigns the security-secret class, or no data class is
recorded. Otherwise a reply only for the correct guess reveals the masked key.
Decide this from the schema before authorization, provider access or stored-row
access, and return the same fixed, value-free refusal for every such request,
independent of the supplied value, permissions and whether any instance exists.
Apply this to every composite and ancestor-list key in gNMI Get and Subscribe
prefixes and paths and NETCONF get and operational get-data subtree content
matches. An omitted key, including a gNMI wildcard treated as omission, is not a
key-value match. Unconstrained reads retain the identity and masking rules above.

The baseline gNMI operational path passes provider JSON through unmasked. In Get, every
snapshot and every event, mask each accepted operational payload, key leaves included,
whose schema data class does not allow cleartext, with the redaction the generated gNMI
renderer applies to configuration leaves.

For NETCONF, preserve the existing data-class masking of key-leaf payloads. Group and
merge by the complete authorized identity before redaction, never by masked key text. A
denied key omits the dependent operational entry in exact and expanded reads; no
incomplete identity or invented row is rendered. This does not authorize unmasking XML
payloads or changing unrelated configuration-renderer missing-key behavior.
Generated/custom binding hooks must honor concrete selections and the same payload
contract.

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

Before server-side parsing/projection or allocating per-entry indexes, reject a provider
response with more than N = `max_paths_per_request` reported values. Then, before
parsing any entry, reject a reported canonical path or encoded JSON value longer than V
= `max_value_bytes` bytes. Apply the count check to both servers and every Subscribe
snapshot. Overflow fails the whole read or ends the subscription with the existing
protocol limit classification and fixed detail without counts or lengths; it never
truncates. One accepted read or
snapshot therefore holds at most N paths and N values of at most V bytes each (2 GiB at
the defaults N = 1024, V = 1 MiB), and server copies, escaping and rendering stay linear
in that. `OperationalRequest` carries N; the `OperationalStateProvider` documentation
states that an omitted key asks for every instance, that each instance is reported once
even when requested paths overlap, and that a provider stops after N + 1 values. A
provider that ignores this is still refused; what it allocates before returning is the
application's responsibility. gNMI queues keep their object-count bound,
clamp(floor(`max_subscriber_queue_bytes` / 4096), 1, 1024), and await capacity on send;
charging actual message bytes against `max_subscriber_queue_bytes` remains an existing
gap outside this change.

For operational events, apply the #1269 schema-path and dependency authorization
gate before event validation, JSON validation and size limits. Drop a denied event
silently, even if its path or value exceeds the byte limit; that event must not end
the stream or wait on per-event audit work. Apply the path and value limits to
events that pass this gate, before instance/JSON parsing and projection; their
overflow ends the subscription with the fixed protocol-limit status. This event
ordering does not relax whole-response rejection of invalid or oversized provider
responses to a read or snapshot.

## Failing tests first

Give the regressions explicit names and exact outcomes. Required test contracts:

- `operational_response_matches_key_subsets`: no/partial/all keys, nested composite
  lists, literal asterisk, overlap and unchanged exact lookup.
- `operational_response_rejects_invalid_members_atomically`: wrong
  key/module/node/depth, malformed/duplicate predicates, duplicate values, unsolicited
  origin and valid-plus-invalid mixtures.
- `operational_paths_round_trip_canonical_literals` and
  `operational_instances_require_complete_declared_keys`: all parser/encoder consumers,
  literal/trailing backslashes, delimiters, configuration and provider keys with
  backslashes or apostrophes read without keys, strict concrete paths, canonical
  ordering, non-canonical integer and boolean keys, one key in two encodings, a key-leaf
  value that differs from its path key and unchanged complete-key write rejection.
- `gnmi_operational_get_expands_instances`: real root/prefix/collection/leaf requests
  return exactly zero/one/many selected instances, a `[key=*]` request returns exactly
  the omitted-key result in Get and Subscribe, without fabrication.
- `operational_reads_use_one_policy_context`,
  `operational_denied_key_prunes_allowed_child`,
  `operational_denial_diagnostics_do_not_count_instances` and
  `operational_expansion_preserves_filters`: one context including effective groups and
  all keys, pre-provider pruning, unchanged allowed siblings, model/type/origin/branch
  constraints and no instance-dependent diagnostics.
- `gnmi_keyed_subscribe_snapshots_and_events` and
  `gnmi_keyed_subscribe_revocation_and_hidden_changes`: every snapshot mode, ON_CHANGE
  update/delete, updates_only, partial-key planning, Read versus Subscribe, policy
  failure/revocation, a provider that reorders unchanged instances without causing an
  update, and controlled hidden-change observations.
  Include #1269's `idle_on_change_revocation_terminates_on_context_change` with an
  expanded selector through an authenticated server: receive a permitted entry on an
  operational-only ON_CHANGE stream without SAMPLE or heartbeat, then revoke its
  identifying key in separate access-policy and resolved-principal-context variants.
  At the change-completion acknowledgement, require fixed, value-free termination
  without another data event or keyed delete. With controlled notification and
  scheduler barriers, hold the control notification after revocation, inject hidden
  events and verify silent drops without termination; release it and require the same
  termination boundary with zero, one and continuously queued hidden events. Hidden
  events must not initiate, accelerate or delay termination. Use no sleeps or visible
  data event to drive the assertion. Assert one policy call for the complete requested
  and previously permitted schema/dependency batch on control-triggered reevaluation.
  Apply #1269's `authorization_change_delivery_fails_closed` cases to expanded selectors:
  registration races, consecutive revoke/restore revisions, channel closure/loss,
  revision gaps, principal invalidation and policy-source failure. Require the
  acknowledgement boundary and no further output; blocked provider work, per-event
  audit work or output backpressure must not prevent server-side termination.
- `netconf_keyed_get_preserves_instance_tree` and
  `netconf_keyed_xpath_and_operational_get_data`: subtree key subsets and branch
  correlation, supported XPath expansion and predicate rejection, operational get-data
  filters, nested/sibling identities, config/state merge, namespaces, escaped keys,
  content-match text at and over the XML limits, including text split across parser
  events, no defaults/placeholders for absent instances and no widening.
- `netconf_keyed_content_match_text_is_bounded`: accumulated content-match text and node
  counts at and over the XML limits, including text split across parser events; overflow
  rejects before provider access with no partial result.
- `operational_expansion_limits_are_checked_before_projection`: N and V boundaries for
  values and paths in gNMI Get, Subscribe snapshots and authorized events and NETCONF
  get and get-data, overflow from one broad selector, a provider that stops at N + 1,
  no renderer call or partial success after overflow, and fixed diagnostics.
- `operational_hidden_event_overflow_does_not_end_stream`: with no policy change, an
  already-denied event with valid JSON and an oversized path or value leaves an
  otherwise visible stream open with no new output or activity diagnostics. Cover path
  and value overflow separately; an oversized authorized event produces the fixed
  protocol-limit failure.
- `operational_non_cleartext_key_class_is_refused`: security-secret, lawful-intercept
  and secret-like-name keys under a full grant give a fixed gNMI refusal and masked
  NETCONF keys; denied keys omit the entry.
- `operational_masked_key_match_is_refused_before_access`: masked-class,
  secret-like-name and unclassified key matches give the same fixed refusal for
  correct and incorrect guesses, absent and populated instances, and allowed and
  denied readers. Cover composite and ancestor keys, gNMI Get and Subscribe
  prefixes and paths, and NETCONF get and operational get-data. Assert zero policy,
  provider and stored-row accesses and no supplied value in diagnostics; omitting
  the match retains the existing read behavior. Removing this schema-only refusal
  must fail the test independently of later authorization and identity guards.
- `operational_opaque_aggregate_cannot_bypass_selection` and
  `operational_expansion_preserves_sensitive_encoding_and_debug`: child access inside
  aggregates, permitted sensitive identities, operational payloads of non-cleartext
  classes masked in gNMI Get, snapshots and events as in NETCONF and #435
  Debug/Display/serialization protection.

Record each test's exact command and candidate revision. Demonstrate separate failing
changes for exact-only matching/result lookup, missing strict path validation, literal
comparison of integer or boolean keys, a literal gNMI `*` key, one backslash-escaping
producer or consumer, dropping predicates/branch constraints, bypassing leaf or identity
authorization, reloading policy between dependencies, skipping event enforcement,
checking event limits before authorization, removing the independent policy/context
notification trigger or making it depend on data events, removing the opaque-aggregate
guard, timestamp- or order-sensitive change detection,
per-event denial records, unmasked gNMI operational payloads, bypassing response or
filter-text limits, permitting masked-key matches and removing diagnostic redaction.
Existing exact-read, denied-leaf,
duplicate/origin, unsupported-filter and Debug tests are preservation controls: they may
already pass at baseline and must fail when their own guard is removed, not necessarily
when expansion alone is absent. Inspect complete decoded paths/payloads, error
detail/Debug, logs, audit and metric observations, including counts. Renderer-only
fixtures cannot prove authenticated server behavior. Record intentional test
replacements in the required inventory.

Run the focused contract/server/codegen regressions, then the repository's
required final gates on the implementation candidate. This note changes no stored
format, provider lifecycle, or deployment procedure. Existing origin and NMDA
capability restrictions stay in force.
