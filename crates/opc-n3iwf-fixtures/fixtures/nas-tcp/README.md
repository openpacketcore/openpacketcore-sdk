# NAS-over-TCP fixture subset

Two-octet length precedes an opaque NAS PDU. A partial prefix remains
need-more-data until a complete frame, EOF/loss, or bounded finalization.
A complete first frame plus a trailing partial or complete frame is valid
buffered input.

