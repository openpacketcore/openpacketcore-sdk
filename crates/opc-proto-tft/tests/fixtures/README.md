# TFT fixture provenance

The byte constants in `tests/tft_codec.rs` are hand-authored from these
normative layouts, not emitted by `opc-proto-tft`:

- 3GPP TS 24.008 V18.8.0 clause 10.5.6.12, figures 10.5.144 through
  10.5.144c and table 10.5.162: operation octet, full-filter and
  identifier-only lists, all twenty Release-18 component identifiers and
  fixed widths, and parameter TLVs.
- 3GPP TS 23.060 V18.0.0 clause 15.3.2 table 12: valid IP packet-filter
  attribute combination types.
- 3GPP TS 24.302 V17.9.0 clause 8.2.9.11: TFT Notify carries this exact
  TS 24.008 value part without the type-4 IEI or outer length octet.
- 3GPP TS 29.274 V18.8.0 clause 8.19: Bearer TFT carries the same exact
  TS 24.008 value part beginning with octet 3.

Each fixture has octet-level comments at its declaration. Round-trip tests
prove decode then encode reproduces those independently authored bytes.
