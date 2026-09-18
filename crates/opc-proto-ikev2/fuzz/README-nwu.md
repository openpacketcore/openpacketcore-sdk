# NWu seeds

The 15 files named for `opc-n3iwf-fixtures/fixtures/nwu-ike/wire/*.hex`
are exact binary decodings of those independently published synthetic vectors.
Their JSON manifests retain source releases, clauses, provenance, outcomes and
SHA-256 digests. They prove payload shape only, not authentication or live mobility.
The fuzz target also exercises complete opened configuration/create/modify/delete
profiles. Mutated corpora belong in a temporary directory, not in this seed set.
