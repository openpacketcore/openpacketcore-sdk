# NAS-over-TCP fixture subset

Two-octet length precedes an opaque NAS PDU. A partial prefix remains
need-more-data while the stream is open. EOF/loss of an incomplete frame or
a bounded-length overflow finalizes as reject. A complete first frame plus
a trailing partial or complete frame is valid buffered input.
