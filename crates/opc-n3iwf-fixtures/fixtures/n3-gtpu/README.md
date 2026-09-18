# N3 GTP-U fixture subset

Reuses issue 341 typed Echo/Recovery/PSC vectors by digest. Downlink and
uplink PDU Session Containers are direction-specific. Twenty-two additional
packets are copied unchanged from the independently authored, digest-pinned
N3 reference corpus: QFI 9 covers both RQI values and all absent/present PPI
values, with QFI 0/63 in both directions. A separate gate binds each manifest,
field claim and wire back to its source case. The existing codec executes every
packet; no forwarding installation or backend capability is claimed. Received Recovery is
ignored and canonicalized to zero. Issue 644 checksum-offload behavior is
dataplane runtime and is not duplicated here.
