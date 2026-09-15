# N3 GTP-U fixture subset

Reuses issue 341 typed Echo/Recovery/PSC vectors by digest. Downlink and
uplink PDU Session Containers are direction-specific. Received Recovery is
ignored and canonicalized to zero. Issue 644 checksum-offload behavior is
dataplane runtime and is not duplicated here.
