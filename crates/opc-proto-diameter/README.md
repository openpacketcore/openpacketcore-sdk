# opc-proto-diameter

Experimental Diameter protocol scaffold for OpenPacketCore.

This crate is the first SDK-owned Diameter mechanism surface from ADR 0018. It
currently provides:

- RFC 6733 Diameter header framing and raw AVP framing with checked 24-bit
  length/command fields;
- raw-preserving message and AVP storage for future byte-exact fixtures;
- AVP-region validation for per-message/per-group AVP count limits, duplicate
  AVP-key rejection policy, zero padding in strict mode, and dictionary-marked
  grouped AVP recursion bounded by `DecodeContext::max_depth`;
- dictionary metadata types for applications, commands, AVPs, flag rules, and
  layered lookup; and
- feature-gated RFC 6733 base procedure helpers for CER/CEA, DWR/DWA, and
  DPR/DPA, including optional `Origin-State-Id`, answer diagnostics
  (`Error-Message`/raw `Failed-AVP` values), protocol-error E-bit derivation,
  and transport-neutral peer capability/result-code helpers; and
- feature-gated skeleton dictionaries for selected 3GPP application work.

It intentionally does **not** provide realm routing, AAA/HSS/CDF behavior,
watchdog threshold policy, peer transport operation, charging decisions, or any
claim that a downstream EPC/ePDG product is carrier-ready.

## Features

| Feature | Default | Scope |
| --- | --- | --- |
| `base` | yes | RFC 6733 common application, peer command names, and base AVP metadata scaffold. |
| `peer` | no | Transport-neutral CER/CEA, DWR/DWA, DPR/DPA builders/parsers, diagnostics preservation, and peer capability/result-code helpers over the base command set. |
| `app-gx` | no | Initial 3GPP Gx application dictionary slot. |
| `app-rf` | no | Initial 3GPP Rf accounting application dictionary slot. |
| `app-s6a` | no | Initial 3GPP S6a/S6d application dictionary slot. |
| `app-s6b` | no | Initial 3GPP S6b application dictionary slot. |
| `app-swm` | no | Initial 3GPP SWm application dictionary slot. |
| `app-swx` | no | Initial 3GPP SWx application dictionary slot. |
| `all-apps` | no | Enables every `app-*` skeleton feature. |

The crate is `publish = false` until the follow-up Diameter tasks add the
fixture provenance, conformance coverage, fuzz targets, and broader typed
application support required by ADR 0015.

## Boundary

This crate owns reusable protocol mechanisms only: wire framing, parser limits,
raw preservation, dictionary metadata, base peer procedure message construction,
capability intersection/result-code selection, and test helper building blocks.
Products that consume it remain responsible for peer selection, realm policy,
transport lifecycle, subscriber behavior, charging policy, watchdog thresholds,
and deployment readiness.
