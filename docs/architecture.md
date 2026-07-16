# Architecture

Layered view of the SDK. Arrows point in the dependency direction (inward).

```mermaid
flowchart TB
  subgraph L1["Layer 1 — pure codecs & types (no async, no I/O)"]
    types[opc-types]
    codecs["opc-proto-* (pfcp, gtpu, gtpv2c, ngap, nas, diameter, ikev2)"]
    protocol[opc-protocol]
  end
  subgraph L2["Layer 2 — models & ports"]
    cfgmodel[opc-config-model]
    ports["opc-mgmt-* ports (schema, path, errors, principal, limits, audit, authz, opstate, transport)"]
    nacm[opc-nacm]
  end
  subgraph L3["Layer 3 — app orchestrator"]
    bus["opc-config-bus (validate → authorize → persist → publish; commit-confirmed expiry rollback; recovery fence)"]
  end
  subgraph L4["Layer 4 — adapters (async)"]
    netconf["opc-netconf-server (SSH/russh)"]
    gnmi["opc-gnmi-server (tonic, mTLS)"]
    cfgconsensus["opc-config-bus-consensus (sealed config adapter)"]
    persist[opc-persist]
    tls["opc-tls / opc-identity (SPIFFE)"]
  end
  subgraph L5["Layer 5 — runtime & operators"]
    runtime[opc-runtime]
    oplc["operator-lifecycle / operator-controller (Rust)"]
    gosdk["operators/operator-sdk-go + sdk-reference-operator (Go)"]
  end
  facade["opc-sdk (facade / prelude)"]

  netconf --> bus
  gnmi --> bus
  bus --> ports
  bus --> cfgmodel
  bus --> cfgconsensus
  cfgconsensus --> persist
  persist --> ports
  ports --> types
  cfgmodel --> types
  codecs --> protocol
  nacm --> ports
  tls --> ports
  runtime --> ports
  oplc --> runtime
  gosdk -. bridge CLI contract .-> oplc
  facade --> netconf
  facade --> gnmi
  facade --> bus
  facade --> codecs
  facade --> runtime
```

Legend: solid arrows are Cargo dependencies (direction = "depends on"); the dashed
edge is the Go↔Rust policy-CLI process boundary (JSON contract, versioned by
`scripts/check-downstream-import.sh` on the Go side).
