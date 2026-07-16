# TFT fuzz corpus

`spec_ignore` is the single-octet `Ignore this IE` value (`00`) and
`spec_delete_existing` is the single-octet `Delete existing TFT` value (`40`),
both authored from TS 24.008 V18.8.0 table 10.5.162. They are duplicated under
each target-specific directory because `cargo-fuzz` selects one corpus per
target.

The named mutation seeds are deliberately non-conforming ASCII inputs. They
give libFuzzer varied operation/filter/parameter vocabulary to mutate while
the specification-authored valid corpus and full valid fixtures remain plainly
distinguishable. Fuzzer-generated hash-named working entries are not committed
without separate minimization and provenance review.
