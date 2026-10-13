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
Raw identity values can correlate authorized instances without
becoming unmasked XML payloads. Predicate text is redacted from Debug output
and never appears in error replies, logs, audits or metric labels.

## Captured inputs and binding contract

`ReadSelection` carries the authorized plan through the read handler and
`NetconfConfigBinding`. Generated `NetconfXmlRenderer` implementations use
`SubtreeProjection` before typed field access. They capture the authorized
values once, after default handling, without serializing the complete model.
The evaluator uses those same captured inputs for predicates and output.
Candidate reads share an immutable model snapshot, including fallback to
running; capturing a candidate never clones the complete configuration.

Authorized operational match leaves become provider dependencies. A complete
provider response is validated before any predicate evaluation: duplicate,
unsolicited, malformed, noncanonical, out-of-request or inconsistent values
fail the entire read even if they would not match. Only scalar JSON values
are accepted. Configuration and state correlate through complete canonical
ancestor-key tuples; missing state does not create configuration rows.
Provider paths require qualified keys in schema order. Single quotes are
preferred, double quotes represent a key containing an apostrophe, and
backslashes remain literal. A key requiring both quote delimiters is refused.
After complete validation, state instances are ordered by canonical path under
the shared budget. Merging retains configuration order for existing instances.
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
failed matches and overlapping alternatives. Denied data branches are neither
enumerated nor charged.

Existing request, XML depth, namespace, attribute and content-node limits
remain in force. Each accumulated decoded value is bounded by
`max_value_bytes`, and aggregate decoded text is bounded by
`max_request_bytes`. Complete provider response count, path and JSON value
limits remain independent of the matching budget. An overrun returns fixed
`too-big`, discards buffered output and never truncates into success or
no-match. Custom projectors must use the shared budget before retaining or
comparing values and before accessing rows.

The authenticated generated-service fixture covers the content contracts
in `crates/opc-yanggen/tests/fixtures/subtree_content_test.rs`; parser, codec,
tree and path unit tests supplement it. Existing structural, XPath, masking,
ordering and default-report controls remain in place.
