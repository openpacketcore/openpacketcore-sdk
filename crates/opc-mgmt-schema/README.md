# opc-mgmt-schema

The runtime YANG **schema-registry contract** for the OpenPacketCore management
plane (gNMI and NETCONF servers).

`opc-yanggen` emits compile-time path constants and a data-class map, but the
gNMI/NETCONF servers need a single queryable runtime view of the *same* canonical
schema — served modules (name/revision/namespace/prefix), the valid path tree,
config-vs-state classification, list key names **in order**, leaf type metadata,
redaction data classes, NACM action mapping, gNMI origins, and YANG defaults.

This crate is a **leaf** crate that ships only:

- the value types (`ModelData`, `NodeMeta`, `LeafType`, `NodeKind`, `NacmAction`,
  `DataClass` re-use, `OriginEntry`, `DefaultReport`), and
- the object-safe [`SchemaRegistry`] trait, whose query methods (path lookup,
  normalization, NACM derivation, with-defaults, integrity self-check) are
  **default implementations** over four data accessors.

It contains **no schema knowledge of its own**. A consuming CNF gets a concrete
`&'static dyn SchemaRegistry` from its `opc-yanggen`-generated crate (the
generated `schema_registry::registry()` accessor), so the registry is always a
projection of the single canonical source — never a hand-maintained side schema.
The crate intentionally does not depend on `opc-nacm` (it mirrors the five
datastore `NacmAction` variants locally so generated code stays crypto-free); the
server maps to `opc_nacm::NacmAction` at its own boundary.
