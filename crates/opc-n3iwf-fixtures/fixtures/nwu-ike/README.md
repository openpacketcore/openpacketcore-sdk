# NWu IKE fixture subset

Wire notifies plus create/modify/delete/mobility payloads only. Backend
overlap, SPI provenance, rekey, and roster relocation belong to `xfrm-roster`.

| Notify | Type | Synthetic value |
| --- | --- | --- |
| NAS_IP4_ADDRESS | 55502 | 192.0.2.10 |
| NAS_TCP_PORT | 55506 | 20000 |
| 5G_QOS_INFO | 55501 | PDU session 5, QFI 9 or 10 |
| UP_IP4_ADDRESS | 55504 | 192.0.2.11 |
| UP_SA_INFO | 55508 | ESP SPI Size 4, synthetic SPI |
| ADDITIONAL_IP4_ADDRESS | 16397 | 192.0.2.10 |
| CREATE_CHILD_SA chain | TS 24.502 7.5.2 | 55501 then 55504 |
| MODIFY_CHILD_SA | TS 24.502 7.6.2 | 55508 then 55501 |
| Delete ESP | RFC 7296 §3.11 | one synthetic SPI |

