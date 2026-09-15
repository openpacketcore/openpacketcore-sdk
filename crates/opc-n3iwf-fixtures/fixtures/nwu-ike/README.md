# NWu IKE fixture subset

Wire notifies and Delete/MOBIKE payloads only. Backend overlap, SPI
provenance, rekey, and roster relocation belong to `xfrm-roster`.

| Notify | Type | Synthetic value |
| --- | --- | --- |
| NAS_IP4_ADDRESS | 55502 | 192.0.2.10 |
| NAS_TCP_PORT | 55506 | 20000 |
| 5G_QOS_INFO | 55501 | PDU session 5, QFI 9 |
| UP_IP4_ADDRESS | 55508 | 192.0.2.11 |
| ADDITIONAL_IP4_ADDRESS | 16397 | 192.0.2.10 |
| Delete ESP | RFC 7296 §3.11 | one synthetic SPI |

