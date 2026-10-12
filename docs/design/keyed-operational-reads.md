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

Put the canonical path parser/comparator in `opc-mgmt-path`, shared with the
opstate contract and server selections. Compare parsed keys, never string prefixes
or stripped predicates. Preserve the canonical builder's literal-value grammar,
including backslashes; do not introduce XPath or a new escaping convention.
Malformed paths and duplicate predicates fail closed. The opstate contract stays
protocol-neutral; servers additionally resolve each reported path against their
registry, checking declared keys, canonical ordering, node kind, and complete key
tuples for concrete instances. Unknown keys/nodes, missing instance keys, keys on
non-list nodes, and non-canonical aliases cannot become expanded entries.

## Server integration

**gNMI.** Add an explicit read-selection mode to `opc-mgmt-path` that permits a
subset of declared list keys. Keep the existing complete-key resolver for writes
and concrete provider paths. `opc-gnmi-server::get` uses that read mode for request
and prefix resolution. Replace `state_entries_with_values`' exact filtering with
concrete `ReadSelectionEntry` values carrying both the resolved schema path and
the provider's full instance path. Preserve these through rendering and wire-path
conversion. Shared initial/sample reads use the same selection rules; this does
not change event queues or subscription delivery semantics.

**NETCONF.** Carry instance constraints through `filter`, `ReadSelection`, `get`,
and operational `get-data`; schema paths alone cannot represent this selection.
Unkeyed subtree filters select all instances. For partial/exact keys, admit only
schema-declared list-key leaf content matches in these read operations. Preserve
which predicates belong to each list and each sibling filter branch. Bound text
and node collection with the existing XML input limits. This is a narrow addition;
general content matching and XPath predicates remain unsupported. Preserve
`get-config`'s current supported filter subset.

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

Keep authorization before provider access. After validating the complete provider
response, authorize its actual schema paths in one batch under the current policy,
then apply each decision to each concrete entry. Reapply the original key, model,
data-type, and protocol filter constraints before rendering. A matching key is
never permission to read another leaf. The current NACM policy is schema-node
scoped; this change does not invent per-instance policy rules.

Identifiers returned in gNMI paths and XML key leaves are disclosures too. Include
required key leaves in authorization and redaction decisions. If a required key
cannot be disclosed, omit that instance; never emit a masked or incomplete
identity. Denied data leaves are omitted normally. Preserve exact reads' error
mapping, audit behavior, and policy-unavailable failure; do not leak raw keys or
provider diagnostics through rejection messages. Renderer hooks must honor the
concrete selection and existing payload/redaction contract.

Apply existing path-count and value-size limits to the expanded response before
projection, not merely to the request's schema paths. Overflow fails the read,
without truncated success. Existing transport/XML bounds still apply. The
synchronous provider returns a vector, so this bounds server acceptance and
rendering, not allocations performed inside the provider.

## Failing tests first

| Boundary | Required cases |
| --- | --- |
| Shared contract | No, partial, and complete keys; nested two-key lists; overlapping selectors; literal delimiter/backslash values; unchanged exact lookup. |
| Rejections | Different key/module/node/depth; malformed or duplicate predicates; undeclared/missing instance keys; duplicate response path; unsolicited origin; one invalid value among valid values. |
| Both server read paths | Actual requests selecting zero, one, and several instances through root/subtree and leaf reads; requested key subsets preserved end to end; absent state stays absent. |
| Authorization and filters | Allowed and denied leaves on expanded instances; required key denied/redacted; policy change/failure; original model/data-type/filter restrictions and redacted audit/error output. |
| NETCONF projection | Two sibling and nested list instances with distinct state; matching configuration/state merged once; namespaces and escaped key values; no placeholders or selection widening. |
| Limits and compatibility | Expanded count/value overflow fails wholly; strict writes and unsupported filter/shape cases retain rejection; exact reads and operational `get-data` restrictions remain. |

Run the focused contract/server/codegen regressions, then the repository's
required final gates on the implementation candidate. This note changes no stored
format, provider lifecycle, or deployment procedure. Existing origin and NMDA
capability restrictions stay in force.
