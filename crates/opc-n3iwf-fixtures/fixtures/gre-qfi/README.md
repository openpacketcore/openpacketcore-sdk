# NWu GRE QFI fixture subset

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `20` | C=0 K=1 S=0 |
| 1 | `00` | Reserved/Ver 0 |
| 2..3 | `00 00` | Protocol Type 0 on send |
| 4 | `09` | QFI 9 |
| 5..6 | `00 00` | Spare |
| 7 | `80` or `00` | RQI downlink-only |
| 8 | `00` | One opaque synthetic user payload octet |

Received nonzero Protocol Type is ignored. The payload is opaque; no next-header
or terminator is defined here. The duplicate-key-header case contains one GRE
header followed by eight opaque payload octets. The bounded-QFI case is the
construction argument 64, not a packet with malformed spare bits.
