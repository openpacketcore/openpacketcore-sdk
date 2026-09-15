# NWu IKE fixture subset

Wire notifies and Delete/MOBIKE payloads only. Backend overlap, SPI
provenance, rekey, and roster relocation belong to `xfrm-roster`.

| Notify | Type | Synthetic value |
| --- | --- | --- |
| NAS_IP4_ADDRESS | 55502 | 192.0.2.10 |
| NAS_TCP_PORT | 55506 | 20000 |
| 5G_QOS_INFO | 55501 | PDU session 5, QFI 9 |
| UP_SA_INFO | 55508 | SPI label 0x0a0b0c0d |

