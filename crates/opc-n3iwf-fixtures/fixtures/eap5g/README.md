# EAP-5G fixture subset

Hand-authored from TS 24.502 V18.8.0 clauses 7.3–7.7 and 9.3.2.

| Offset | Octets | Field |
| --- | --- | --- |
| 0 | `01` | EAP Code Request (RFC 3748 §4.1) |
| 1 | `01` | Synthetic identifier |
| 2..3 | `00 0e` | EAP Length 14 |
| 4 | `fe` | Expanded Type 254 |
| 5..7 | `00 28 af` | Vendor-Id 10415 |
| 8..11 | `00 00 00 03` | Vendor-Type EAP-5G |
| 12 | `01` | 5G-Start-Id |
| 13 | `00` | Spare |

Unknown spare AN-parameters and AN-parameter reordering are permitted on
receive. Duplicate selected-PLMN is a caller duplicate-singleton policy, not
the spare-parameter ignore rule. Notification (Message-Id 3) and Stop
(Message-Id 4) are published. NAS remains opaque. `runtime_claim=false`.

