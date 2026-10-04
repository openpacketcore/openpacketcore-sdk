# N2 SCTP fixture subset

Non-DTLS N2 profile: PPID 60 and port 38412. Ordinary SCTP metadata is
not cryptographic protection. PPID 66 is reserved for `n2-dtls`.

Correction (2026-09-17): metadata tuples now encode the claimed default port
as `96 0c` (38412). Their previous `96 1c` encoded 38428. Independent numeric
port and PPID checks cover both metadata orders and every duplicated tuple;
DATA checks also compare the claimed user-data length. This correction changes
four wire files and their digests without promoting any runtime claim. The
65535 negative remains a caller-selected bound test, not an invalid port claim.
