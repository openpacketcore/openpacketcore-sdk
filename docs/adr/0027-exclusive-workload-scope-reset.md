# ADR 0027: Reset of an exclusively owned workload scope

## Status

Accepted.

## Context

A stopped workload must be able to discard its own predecessor's incompatible
maps, retained records and hooks, then attach normally without manual cleanup.
A scope can contain several interface leaves or outlive an interface rename or
change of tc priority. Per-interface exact-slot cleanup cannot settle all of
those states.

## Decision

`reset_exclusive_workload_graph` is an explicit opt-in beside the unchanged
conservative `reset_workload_graph`. As in ADR 0026, deployment ownership is the
authority. The caller owns the whole scope, stops the previous writer, invalidates
old forwarding and isolates ingress on its interfaces. It does not combine reset
with externally authorized retained-graph recovery.

Inventory covers the named interface and all root leaves that resolve in the
current network namespace. On each, reset removes the configured clsact slots,
all SDK filters matched by the ordinary attach predicate, and every filter whose
program references a scope map, at any priority, handle, chain or protocol.
Map references also identify filters on renamed interfaces in this namespace.
Declared names resolve to kernel indices before discovery, including alternative
names. Other interfaces are inspected only for unaccounted map references;
failed, oversized or unparseable discovery dumps and non-UTF-8 names are skipped.
The reference guard still refuses unresolved programs. Filters outside these
rules remain. Direct tc deletion stays in the calling namespace.

Every root entry is inventoried with descriptor-relative traversal under writer
and operation locks. Program and link pins are removed before maps; deleting an
owned link pin releases its attachment wherever it is, including another
namespace or hook type, when the final reference ends. Ownership of every object
pinned in the root covers that effect. Reset waits at most 250 ms for retired
program IDs and scope-map references, including references left by a prior call.
Busy locks return `RetryRequired`; references that survive the wait return
`StateIndeterminate` with separate detached-program and external-program labels.
A live external holder must retire; another call does not force it away. Maps
remain pinned while referenced.

Callers reset every intended interface before the first attachment; missing pins
cannot identify unnamed interfaces, and a managed device prevents further reset.
Existing SDK generations do not leave a non-SDK filter in a nonzero chain at the
configured priority/handle, or an exclusion-marker-named directory in a writer
or operation lock. These foreign-only layouts can survive reset and prevent the
following ordinary attachment; they require correction by their writer.

A scope ever bound to a selector namespace cannot use this operation. Authority,
decommission and legacy selector-terminal markers refuse before destructive
effects, preserving that separate permanent history. Pending terminal admissions
also refuse. Required capabilities are `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` for
global program inspection; `CAP_BPF` alone is insufficient. Denied inspection,
symlinks, nested mounts and invalid retained lock metadata fail closed.

Writer-lock inodes and every exclusion marker survive. Each inventoried name's
exclusion is finished so the next ordinary attach can proceed. Newly created
exclusions publish their marker atomically. Existing lock names recover an
unfinished exclusion for a present interface even after its graph is gone. Lock
directories may be created before inspection; after interruption, another
exclusive reset must finish them before conservative reset or ordinary attach.
No new tc program or cleanup journal is required.

## Verification

The exclusive cleanup-port test exercises the new driver: complete inventory,
each interface detach, link/program unpins, the release wait, map/directory unpins,
and finish. It injects an error after every driver boundary and repeats to
absence. It does not inject crashes inside the real kernel adapter.

Privileged tests cover multiple and renamed interfaces, predecessor priorities
with and without pins, incompatible layouts, pinned programs and TCX links when
supported, an unfinished exclusion after another leaf's graph is gone,
unrelated ingress filters, alternative names without pins, delayed external
program release, subsequent ordinary attachment and uplink forwarding, plus writer,
selector, neighboring-scope and map-reference guards. The native and EL9 full
CI datapath lanes discover these tests and check the source-derived count.
