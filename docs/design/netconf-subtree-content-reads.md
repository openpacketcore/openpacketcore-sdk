# NETCONF subtree content reads

Subtree content matching is supported by `<get-config>`, `<get>` and the
binding's supported NMDA `<get-data>` variants. It selects scalar key and
non-key leaves in configuration and operational data, following RFC 6241
sections 6.2.5 and 6.3. XPath and attribute matching retain their existing
support and refusal behavior.

## Matching and output

The XML parser retains namespace-qualified elements, their child scopes and
decoded text. Empty elements and elements containing only XML whitespace
(space, tab, carriage return and line feed) remain selections. Text, CDATA,
predefined entities and legal character references accumulate before outer XML
whitespace is trimmed once. Interior characters and other Unicode spaces are
preserved. Mixed text and child elements are invalid; DTDs, external and
undeclared entities, and references to non-XML characters remain forbidden.
Numeric references require decimal digits or `x` followed by hexadecimal
digits; neither form accepts a sign. Value limits count accumulated decoded
UTF-8 bytes, while encoded references remain subject to request and work limits.

Element names match by namespace URI and local name. Prefix aliases do not
change matching. An absent namespace, including `xmlns=""`, is a wildcard
over supported namespaces, as specified by RFC 6241 section 6.2.1.

All content predicates in a sibling set must hold on the same data instance.
Root elements in the same namespace share a sibling set. Repeated containment
or list branches are alternatives with independent nested constraints.
Successful matches include their match leaves and explicitly selected or
contained siblings. With no selection or containment siblings, they select
the sibling subtree. Overlapping results are emitted once in existing list
order, with complete ancestor identity keys in schema order. No match produces
empty data without inventing a row.

Following RFC 6243 section 4.5.1, matching sees only values that the same read
would report after default processing. An unset default can match under
report-all or report-all-tagged. A value omitted by trim or explicit cannot
match. Defaults never create list instances, keys or operational values.
Generated configuration defaults use `LeafPresence::Defaulted`; an explicitly
absent field stays absent in both ordinary and content-filtered reads.

## Scalar comparison

The shared codec resolves schema types before authorization or data access.

| Leaf type | Content comparison |
| --- | --- |
| Boolean | `true` and `false` |
| uint16, uint32, int64 | Numeric normalization within the declared width and range; `+007` can match 7 |
| String, enumeration | Exact decoded characters or enumeration name after outer XML whitespace handling |
| Empty | No text-match value |
| Leafref | Bounded target-type resolution without reading referenced instances |
| Non-key identityref, decimal64, Custom | Fixed `operation-not-supported`, including leafrefs ending in these types |

Invalid literals for supported types are unsatisfiable. They do not disappear
from the plan or fall back to strings. Text on a leaf-list is unsupported;
text on a container or list is invalid input. In a configuration-only read,
a predicate on an operational leaf matches nothing and requests no provider.

Key predicates retain canonical key handling: numeric and boolean keys are
normalized; other supported key representations compare their stored text.
In particular, identityref and decimal64 keys retain their existing lexical
identity, without claiming namespace-resolved identity or lossless decimal
comparison. Neither non-key matching nor key matching changes stored formats.

## Authorization and masking

Before accessing data, one captured Read policy/principal context decides the
union of output leaves, predicate leaves and every identifying key at every
ancestor list. Separate registries reuse that context. A denied or unknown
predicate or identity dependency makes its dependent branch unsatisfiable.
An output-only denial omits that output individually. A structural selection
or predicate permission grants no child permission.

Pruned branches perform no row enumeration, presence checks, value decoding,
predicate trials, projection validation or provider requests. Populated,
absent and malformed hidden branches produce the same omission, work charges
and diagnostics while an independent allowed branch remains available. This
is a pre-access control-flow guarantee; it makes no constant-time claim or
claim about arbitrary provider internals.

Content matching on a security-secret, lawful-intercept, secret-like-name or
unclassified leaf is refused from the schema for every reader, including key
leaves. Comparing a masked value would disclose whether a guess was correct.
Selecting these leaves still uses normal masking, including masked NETCONF
key elements. Masked configuration payloads enter the captured tree as the
fixed placeholder before encoding, copying or charging payload bytes. Default
omission compares against the schema default without encoding hidden values;
its work depends on that schema default. Masked leaf-list members retain only
their capture position to preserve distinct members and deduplicate overlaps.
Masked list keys enter the captured tree as fixed-width SHA-256 identities,
computed identically by configuration and state capture and retained only for
this request. Joins, copies, deduplication and ordering checks charge those
identities, never the hidden key lengths. Configuration and provider captures
remain uncoalesced until one checked envelope covers the initial join, every
dependent predicate and copy, scope unions and final ordering. Sizing retains
only schema paths, node/key counts and captured lengths. It pools all possible
instances of each schema parent, including children that separate capture
fragments could contribute to the same row. Sibling comparison products use
these original groups; no intermediate joined or selected tree sizes a charge.
Discovery fragment appending follows the same rule: before evaluation, a checked
bound counts every original node and stored key, captured scalar lengths, XML
escaping, qualified names, namespace declarations and default attributes. Its
metadata work and complete byte-copy allowance are admitted together; neither
selected nodes nor rendered fragment lengths determine a later charge.

Sizing normalizes its metadata order without changing data order. Its bounded
local allowance prevents partial sizing progress from becoming a shared-budget
observation when masked keys change provider sort order. Metadata work and the
complete dependent envelope are admitted together before the first identity
join. Overflow or insufficient admission leaves the input and shared allowance
unchanged. All tuple components, candidate pairs, scalar comparisons, descendant
searches, copies and vector moves are covered. Equal prefixes, earlier matches,
coalesced rows and predicate short-circuits cannot reduce the reservation.
Predicate instrumentation records all admitted trial slots, including unused
slots; it does not expose which joined rows reached a later conjunct. No unused
work is refunded. Hashing itself has a fixed admission charge; it makes no
timing claim. Raw provider keys remain available only for
mandatory canonical-path and key/payload consistency validation, under the
independent provider byte caps. That validation charges public path bytes and
fixed units for masked keys, without retaining raw keys for matching. Predicate
text is redacted from Debug output and never appears in error replies, logs,
audits or metric labels.

## Captured inputs and binding contract

`ReadSelection` carries the authorized plan through the read handler and
`NetconfConfigBinding`. Generated `NetconfXmlRenderer` implementations use
`SubtreeProjection` before typed field access. They capture the authorized
values once, after default handling, without serializing the complete model.
The evaluator uses those same captured inputs for predicates and output.
Candidate reads share an immutable model snapshot, including fallback to
running; capturing a candidate never clones the complete configuration.
The public `handle_get_config` and `handle_get_data` content paths borrow the
candidate or startup snapshots in their contexts after the same budget gate;
they do not copy the caller's model or denied rows.

A startup read loads the binding's stored startup configuration in full through
`StartupDatastore`, as ordinary startup reads do. That interface returns a
complete configuration and has no selective decoding operation, so loading
may decode denied rows. The pre-access guarantee begins at projection, as it
does for provider internals. The binding must bound stored bytes, decoded
collections and allocations before loading or decoding its snapshot; these
datastore limits are separate from the NETCONF subtree work budget. The server
loads it once, only after an authorized configuration branch survives pruning,
then applies the shared projection budget. It does not claim that the matching
budget bounds storage I/O or decoding inside a startup implementation.

Authorized operational match leaves become provider dependencies. A complete
provider response is validated before any predicate evaluation: duplicate,
unsolicited, malformed, noncanonical, out-of-request or inconsistent values
fail the entire read even if they would not match. Only scalar JSON values
are accepted. Configuration and state correlate through complete canonical
ancestor-key tuples; missing state does not create configuration rows.
Provider paths require qualified keys in schema order. Single quotes are
preferred, double quotes represent a key containing an apostrophe, and
backslashes remain literal. A key requiring both quote delimiters is refused.
After complete validation, state instances are ordered by raw canonical path.
The shared budget precharges the sort's worst-case comparison and move count
using the fixed-width captured identities, so hidden key lengths and raw sort
order cannot affect the allowance. Merging retains configuration order for
existing instances. Provider duplicate-path, selector and key searches also
reserve their complete candidate comparisons before an early match or refusal.
`OperationalValue` validates JSON at construction and retains its shape with
the immutable payload. Masked non-key state selections check this proof before
capturing only the fixed placeholder. Complete provider byte and count limits
still apply, and identifying key payloads still undergo identity validation.

A binding must opt into `supports_subtree_content` and honor
`project_subtree_content`. Regenerated renderers supply both. A binding that
cannot evaluate the plan refuses it explicitly. Legacy schema-only or opaque
XML rendering is never a fallback for constrained reads. A custom binding
whose ordinary rendering uses different default processing must report the
same mode through `subtree_default_report`; the default hooks use trim.
Explicit `with-defaults` modes still require advertised support.

## Resource bounds

`MgmtLimits::max_subtree_filter_nodes` (default 1024) independently bounds the
raw tree and expanded plan/dependencies. `max_subtree_filter_work_units`
(default 16777216) covers parsing, compilation and execution. Both limits
must be positive. Visits, predicate trials, joins, index insertions and
matching bytes are charged before the corresponding operation, including
failed matches and overlapping alternatives. Denied rows and values are never
enumerated and add no work charges. Every projector `enter` check, including one that
rejects a node, consumes work before checking selection. Authorization builds
one bounded, sorted set of structural prefixes; subsequent exact and structural
lookups charge every binary-search probe instead of scanning all plan paths.

Every phase after capture derives its charges from the original uncoalesced
node, key and child counts and retained lengths from each source, together with
fixed schema and request metadata. Each bound uses checked arithmetic and is
reserved and admitted before the corresponding work. Never measure a joined,
merged, selected or rendered result to decide a charge. Coalescing may leave
reserved work unused; it cannot reduce the charge or change authorized output.

Identity merging and final ordering share one complete evaluation reservation.
Sizing visits are charged before reading capture metadata. Bounds use original
node/key totals, the largest captured tuples and values, and schema cardinality
within each parent row. A scalar or container path can occur at most once per
joined parent; list and leaf-list bounds retain every original occurrence.
These bounds are established from schema and capture metadata before any join.
Custom captures must have the declared key structure for these bounds to apply.
Captured masked identities have a fixed width.

The initial join stable-sorts an index of each sibling batch by schema path,
captured keys, masked ordinal and leaf-list value. Equal runs coalesce in one
recursive batch, preserving scalar/default conflict checks and restoring the
first occurrence's position. This also normalizes singleton capture subtrees.
Selection then carries the original parent-local key or child position through
copies and unions. Subsequent merges and output ordering sort these integer
positions, so they do not repeatedly search or compare captured key tuples.
Keys keep their schema slots, and lists and leaf-lists retain source order.

A sort of a row of width N has at most N comparisons and N position moves per
merge-sort level. Reservations multiply original node totals by the logarithmic
row-width bound and the largest compared tuple/value lengths, then add linear
visit, predicate, copy and conflict-check terms. They do not square pooled list
sizes or charge vector-removal shifts. Metadata normalization, provider duplicate
checks and provider ordering also use bounded index sorts. Metadata normalization
charges each merge level by the batch's summed metadata. Provider ordering
still uses validated canonical paths; its prepaid byte bound uses captured path
identities, including fixed-width masked components.

All additions and products are checked. Metadata sizing and the full executor
bound are admitted together before the initial configuration/state join. Refusal leaves
the input, shared allowance and predicate admissions unchanged; early exits do
not refund work. Test-only counters record visits, byte comparisons, copies and
moves at their operation sites. Separate checks cover capture and scope sizing,
row bounds, both metadata normalizations, provider identity and ordering sorts,
provider output moves, and the executor portion of the reservation. Unused sizing
allowance cannot cushion an executor overrun. Paired-byte comparisons count each
position once. Canonical ordering of masked provider keys retains its fixed
logical comparison cost; the counters do not bound raw secret-byte CPU time.

Local admission checks also measure the actual budget deduction around
the charged operation, then observe visits, comparison byte positions and
retained elements or bytes at that operation. Opaque bounded text operations
record their input bytes. Selector sizing and correlation have separate checks,
as do schema lookup, compilation, projection and provider validation. A missing
deduction cannot borrow spare allowance from a different operation. The schema
crate's `testkit` feature enables these checks when linked by server unit tests
and the authenticated generated-service harness; ordinary builds keep empty
tokens and no counters.

`ci/subtree-charge-mutations.py` inventories production charge calls across the
schema, server and generator source trees, including generated projection code.
It removes one deduction at a time while preserving argument evaluation, runs
the complete server unit and authenticated suites, and restores the source.
Every mutation needs a failing test; compiler errors, timeouts and incomplete
test runs are invalid results. Its evidence records the source, patch, commands
and logs separately from the reusable development build cache.

Existing request, XML depth, namespace, attribute and content-node limits
remain in force. Each accumulated decoded value is bounded by
`max_value_bytes`, and aggregate decoded text is bounded by
`max_request_bytes`. Complete provider response count, path and JSON value
limits remain independent of the matching budget. An overrun returns fixed
`too-big`, discards buffered output and never truncates into success or
no-match. Custom projectors must use the shared budget before retaining or
comparing values and before accessing rows. They must capture list identities
through `SubtreeProjection::key`, and propagate budget failures from `selected`
and `subtree_selected` as well as `enter`. Callers of `merge_bounded` must submit
the complete sibling batch, rather than repeatedly merge a growing prefix.

The authenticated generated-service fixture covers the content contracts
in `crates/opc-yanggen/tests/fixtures/subtree_content_test.rs`; parser, codec,
tree and path unit tests supplement it. Existing structural, XPath, masking,
ordering and default-report controls remain in place.
