# OPC-SDK-RFC-014: Interactive Operational Console and Command Framework

**Status**: Draft for Implementation

**Version**: 0.1.0

**Date**: 2026-07-09

**Audience**: SDK implementers, CNF teams, SREs, platform IAM teams, security reviewers, TUI engineers

## 1. Abstract

This RFC defines a first-class interactive operational console for
OpenPacketCore CNFs. The console restores the discoverable, persistent
network-element shell experience familiar to mobile-core operators while
preserving the SDK's declarative management invariant:

> Infrastructure as Code owns desired configuration; the operational console
> observes state and invokes explicitly modeled operational actions.

The RFC standardizes:

- a transport-neutral command catalog that CNFs use to describe their
  operational vocabulary;
- an SDK registration API for mapping commands to YANG operational state,
  subscriptions, and typed actions;
- catalog discovery over the existing authenticated gNMI and NETCONF
  management plane;
- configurable human login through OIDC, OpenShift OAuth, SSH credentials, or
  workload identity;
- persistent, identity-bound console sessions;
- a responsive terminal user interface with contextual help, completion,
  streaming output, cancellation, paging, filtering, and safe history;
- authorization, auditing, redaction, resource limits, versioning, and
  conformance requirements.

The TUI is not an optional wrapper around a client library. It is the primary
human interface and an implementation acceptance boundary for this RFC.

## 2. Decision and Invariants

OpenPacketCore will provide an SDK-owned operational console framework and a
reference Rust TUI application. A consuming CNF declares the commands that are
meaningful for that network function and supplies operational state or typed
action implementations. The SDK owns parsing, discovery, help, completion,
transport selection, authentication integration, authorization hooks, audit,
limits, presentation, and terminal behavior.

The following invariants are normative:

1. The console MUST NOT expose configuration mutation through gNMI `Set`,
   NETCONF `<edit-config>`, candidate/running datastore mutation, or an
   equivalent escape hatch.
2. A user MUST be able to discover ordinary operational commands without
   knowing a YANG path, XPath, protobuf service name, or transport protocol.
3. CNFs MUST describe commands as bounded declarative data. A target MUST NOT
   send executable client code, scripts, terminal escape sequences, or native
   plugins to the console.
4. The console MUST translate parsed commands into typed management
   operations. It MUST NOT send an arbitrary shell command string for remote
   execution.
5. Every target operation MUST be authenticated, authorized, and audited at
   execution time. Help visibility is not an authorization decision.
6. Trusted management-environment configuration supplies identity authorities,
   trust anchors, broker policy, and tenant-assignment policy; validated IdP
   claims supply human identity; broker policy and issued credentials bind the
   allowed tenant. A target or catalog MUST NOT supply or override any login,
   issuer, token, JWKS, callback, broker, or redirect endpoint, signed or
   unsigned.
7. The interactive event loop MUST remain responsive while authentication,
   discovery, reads, subscriptions, actions, rendering, or reconnection are in
   progress.
8. Remote text and values MUST be treated as untrusted input and rendered
   without allowing terminal control-sequence injection.
9. One-shot and automation modes MAY reuse the same parser and execution
   engine, but they MUST NOT weaken or displace the interactive experience.

## 3. Scope

### 3.1 In Scope

- Interactive login, connection, reconnection, logout, and identity display.
- Persistent operator sessions against one selected CNF target.
- Contextual `?` help and tab completion at every grammar position.
- Hierarchical operational command registration and discovery.
- Read, monitor, bounded diagnostic, and authorized operational-action
  command classes.
- gNMI `Capabilities`, `Get`, and `Subscribe` client adapters.
- NETCONF capability discovery, `<get>`, `<get-data>`, and modeled RPC/action
  client adapters.
- Future protocol adapters, including gNOI-style operational services.
- Structured table, tree, detail, JSON, and streaming presentation.
- Local paging, filtering, counting, and export of authorized results.
- Human authentication provider integration and short-lived management
  credentials.
- NACM read/subscribe/exec authorization and management audit integration.
- CNF and TUI conformance testkits.

### 3.2 Out of Scope

- A configuration shell or replacement for IaC workflows.
- An arbitrary remote POSIX shell.
- An SSH daemon that executes commands inside the CNF container.
- Owning user passwords, MFA enrollment, or a general-purpose identity
  provider.
- Treating every YANG node as a well-designed human command automatically.
- Replacing OSS/BSS, fleet automation, or Kubernetes operators.
- A browser-based management console. Such a console may consume the same
  catalog in a later RFC.
- High-volume telemetry storage or analytics.

## 4. Terminology

| Term | Meaning |
| :--- | :--- |
| **Console** | The complete human operational interface, including login, persistent target session, command engine, and terminal presentation. |
| **TUI** | The interactive terminal application. It includes the line-oriented network-element shell, help/pager overlays, and optional full-screen views. |
| **Command catalog** | A bounded declarative description of the commands available from one authenticated target. |
| **Command specification** | One stable command identity, grammar, help, operation plan, authorization metadata, and presentation specification. |
| **Operation plan** | A transport-neutral read, subscribe, or action plan produced after a command is parsed. |
| **Management context** | Trusted configuration describing targets, server trust, login provider, access broker, tenant policy, and client defaults for an environment. |
| **Access broker** | A management-domain service that exchanges an authenticated human session for short-lived protocol credentials. |
| **CNF command module** | CNF-supplied registration code that adds validated command specifications and action implementations to the SDK framework. |

## 5. Operator Experience

### 5.1 Primary Interaction

The expected primary flow is:

```console
$ opc connect epdg-prod-1
Authentication required for context "production"
Opening the configured identity provider in your browser...

Logged in as alice@example.com
Tenant: mobile-prod
Connected to epdg-prod-1 (ePDG 2.4.1)
Management: gNMI + NETCONF

epdg-prod-1> ?
  show         Display operational state
  monitor      Stream changing operational state
  diagnose     Run bounded diagnostic operations
  clear        Clear explicitly modeled operational state
  describe     Explain a command, object, or capability
  whoami       Display the authenticated management identity
  exit         Close this console session

epdg-prod-1> show ?
  alarms                   Active alarms
  health                   Component health
  ike                      IKE operational state
  ipsec                    Child SA and tunnel state
  peers                    AAA and packet-core peers
  system                   Runtime and system information

epdg-prod-1> show ike security-associations peer 192.0.2.20
SPI              PEER          STATE        AGE       CHILD-SAS
0x7a94b23f       192.0.2.20    established  00:14:38  2

epdg-prod-1> monitor alarms severity major
Monitoring alarms. Press Ctrl-C to stop.
...

epdg-prod-1> diagnose ping 198.51.100.10 source-interface s2b
PING 198.51.100.10 from s2b
5 transmitted, 5 received, 0% loss, avg 8.3 ms
```

The user is not expected to know that these commands map to gNMI paths,
NETCONF subtree filters, or YANG actions.

### 5.2 Interaction Requirements

The TUI MUST provide:

- `?` help after any complete or partial token;
- tab completion after any complete or partial token;
- unambiguous abbreviations in interactive mode only;
- exact grammar in one-shot or script mode;
- inline indication of required and optional arguments;
- human-readable validation errors with the invalid token identified;
- command examples and longer help through `describe`;
- `Ctrl-C` to cancel the active operation without closing the console;
- `Ctrl-C` at an idle prompt to clear the edit buffer;
- `Ctrl-D` on an empty buffer or `exit` to close the console when no operation
  is active;
- asynchronous progress indication for operations that do not return
  promptly;
- terminal resize handling without losing the current command line;
- pagination and horizontal handling for output larger than the viewport;
- a no-color mode and usable output when color is unavailable;
- stable machine-readable output when explicitly requested;
- visible target, connection, and degraded/reconnecting state in the prompt.

Unknown commands MUST provide bounded suggestions. Ambiguous abbreviations MUST
list the conflicting continuations instead of choosing one. Before confirming
an abbreviated `operate` command, the TUI MUST expand and display its canonical
syntax and target summary.

`help [<command-prefix>]` displays the command tree, `help search <terms>`
searches bounded summaries/descriptions, and `describe command <canonical
command>` displays grammar, arguments, effect, examples, availability, and
output shape. Empty, locally filtered, permission-denied, unsupported, and
temporarily unavailable results MUST use distinct messages and status values.

The console SHOULD support interactive-only local output pipelines such as:

```console
epdg-prod-1> show alarms | include certificate
epdg-prod-1> show ike security-associations | count
epdg-prod-1> show peers | json
```

These are bounded local transformations over structured results. They are not
shell pipelines and MUST NOT invoke local or remote programs.

### 5.3 Responsiveness Requirements

The TUI MUST use a non-blocking event loop separated from network and rendering
workers by bounded channels. Under the console test profile:

- keystroke echo and local cursor movement SHOULD complete within 32 ms at
  p95;
- cached help and completion SHOULD appear within 100 ms at p95;
- a progress indicator SHOULD appear within 150 ms when a remote operation has
  not produced output;
- catalog validation and command-tree construction SHOULD complete within 100
  ms for the maximum accepted catalog on the reference test host;
- large results MUST stream or page within bounded memory rather than freezing
  input until the complete result is buffered;
- cancellation MUST be observed by the local execution engine promptly and
  propagated to the active protocol adapter; the reducer SHOULD acknowledge
  local cancellation within 100 ms at p95 even when output is saturated.

Network handshake and remote processing latency are measured separately from
local interaction latency. A slow target MUST NOT make typing, help, resize, or
cancel handling unresponsive.

The conformance report defines the reference host, terminal emulator, catalog
size, stream rate, resize load, sample window, and exact measurement points.
Interaction latency MUST also be measured while the maximum supported output
stream is active. The 150 ms progress threshold is a default subject to
usability validation and is disabled in append-only accessibility mode.

### 5.4 Accessibility and Terminal Compatibility

The console MUST:

- be fully keyboard operable;
- not rely on color alone to communicate state or severity;
- support plain output suitable for screen readers and log capture;
- sanitize control characters and ANSI/OSC sequences in target-supplied text;
- calculate display width safely for Unicode and malformed input;
- degrade to a line-oriented interface when full-screen terminal capabilities
  are unavailable;
- respect an explicit no-color configuration and the conventional `NO_COLOR`
  environment setting.

An append-only accessibility mode MUST avoid cursor addressing, animated
spinners, overwritten progress lines, and asynchronous insertion into the
current edit line. Severity and state are always expressed in text. `TERM=dumb`
and non-TTY output use this mode or a documented machine-output mode rather
than attempting full-screen behavior.

Full-screen dashboards and detail panes MAY be added, but the hierarchical
shell MUST remain complete and usable by itself.

## 6. Architecture

```text
                         Trusted management context
                      (targets, issuer, broker, trust)
                                      |
                                      v
+----------------------+      +----------------------+      +------------------+
| Rust operational TUI |----->| Management clients   |----->| CNF management   |
|                      |      |                      |      | endpoints         |
| command tree         |      | gNMI adapter         |      |                  |
| help/completion      |      | NETCONF adapter      |      | capabilities     |
| session state        |      | future adapters      |      | opstate          |
| safe rendering       |      +----------------------+      | subscriptions    |
+----------+-----------+                                    | modeled actions  |
           |                                                +---------+--------+
           |                                                          |
           | catalog                                                  |
           v                                                          v
+----------------------+                                  +---------------------+
| Command engine       |<---------------------------------| CNF command module  |
|                      |        declarative catalog       |                     |
| parse -> plan        |                                  | typed paths         |
| authorize -> execute |                                  | action providers    |
| render events        |                                  | presentation hints  |
+----------------------+                                  +---------------------+

Human login:

TUI -> configured IdP/OpenShift OAuth -> access broker -> short-lived
management credentials -> authenticated CNF connections
```

### 6.1 Separation of Responsibilities

| Responsibility | SDK/framework | CNF | Platform/IAM |
| :--- | :---: | :---: | :---: |
| Command grammar model and validation | Yes | Supplies entries | No |
| Help, completion, parsing, and TUI | Yes | Supplies descriptions/data | No |
| Operational state implementation | Defines contract | Yes | No |
| Typed action implementation | Defines contract | Yes | No |
| gNMI/NETCONF client and server adapters | Yes | Binds server | No |
| Login provider framework | Yes | No | Configures provider |
| Login page, password, and MFA | No | No | Identity provider |
| Access-broker policy and trust | Defines contract/reference | Verifies credential | Operates/configures |
| NACM policy | Defines/enforces | Integrates | Provisions through IaC |
| Command-specific presentation | Validates/renders | Declares hints | No |
| Console conformance tests | Yes | Must pass | May gate deployment |

### 6.2 Dependency and Runtime Rules

The command model and execution semantics form the domain core. They MUST NOT
depend on tonic, SSH/XML libraries, terminal libraries, OAuth clients, or other
adapter wire types. Reader, subscriber, action, login, clock, and audit ports
are owned by the domain/application layer; gNMI, NETCONF, identity-provider,
broker, and terminal adapters implement those ports at the edges.

The Rust implementation uses Tokio for asynchronous composition. It MUST NOT
perform blocking identity, network, filesystem, terminal, or rendering work on
an async worker, and it MUST NOT hold a synchronous mutex across `.await`.
Dynamic dispatch is appropriate at configurable provider/adapter boundaries;
hot parsing and rendering paths SHOULD prefer static dispatch where practical.

Library errors use bounded, typed, payload-safe error enums. The binary may add
operator context at its composition root, but adapter errors, XML/protobuf
objects, tokens, and server payloads MUST NOT leak into domain errors. Library
code MUST NOT panic on catalog, command, authentication, protocol, or terminal
input.

Rust library crates use typed `thiserror` errors; the `opc-console` binary may
use `anyhow` only at the outer composition/reporting boundary. Production code
does not use `unwrap`, `expect`, or `panic` on externally influenced paths.

## 7. Command Model

### 7.1 Command Classes

Every command MUST declare one effect class:

| Class | Examples | Expected behavior |
| :--- | :--- | :--- |
| `observe` | show health, show sessions, show peers | Read-only, bounded result |
| `monitor` | monitor alarms, watch peer state | Long-lived authorized subscription |
| `probe` | ping, traceroute, peer reachability test | Bounded active diagnostic with rate and destination limits |
| `operate` | clear SA, reset peer, drain instance | Operational mutation with exec authorization and explicit confirmation policy |
| `configure` | set address, change policy, edit datastore | Prohibited by this RFC |

The registry MUST reject the `configure` class and any operation plan containing
a management configuration mutation. Calling an operation "operational" does
not make it safe; `probe` and `operate` commands require explicit limits and
authorization.

The classification test is based on the effect, not the command name or
transport:

- an operation is prohibited when it changes candidate, running, startup,
  rollback, or shadow-security configuration; invokes the config bus; changes
  a generated config-model value; establishes durable desired behavior that
  should survive reconciliation; or provides another path to accomplish those
  effects;
- an `operate` action may change runtime/session state or an operational record
  only through a separately modeled action with an observable lifecycle,
  authorization path, bounded effect, and audit contract;
- an operational action MUST NOT create hidden desired state or fight the
  Kubernetes operator/IaC reconciler;
- when an effect could reasonably be represented as desired configuration, it
  is configuration unless the model and CNF owner document why it is a
  transient incident-response operation.

Accepted examples include clearing one IKE SA, acknowledging an alarm, running
a bounded ping, or temporarily draining an instance with explicit expiry and
observable status. Rejected examples include changing a peer address, setting
a persistent drain flag, changing routing policy, installing a certificate,
or writing a runtime override that survives reconciliation. Ambiguous actions
fail registry review closed until their ownership is resolved.

Catalog metadata is descriptive and is not the enforcement boundary. Every CNF
MUST maintain an independent server-side allowlist of operational action IDs
and effect policies that applies to NETCONF, registered gRPC services, and any
future adapter even when the caller does not use the console. The server denies
unknown or configuration-capable actions before invoking CNF code. The
allowlist is compiled or provisioned through trusted CNF composition/IaC and
cannot be widened by the catalog or an action request.

SDK action handlers receive a restricted `OperationalActionContext` containing
only the declared operational capabilities, deadline/cancellation, principal,
audit, and bounded result sink. It does not expose `ConfigBus`, config-store
writers, operator reconciliation inputs, or unrestricted service locators.
The action-module dependency policy rejects direct dependencies on config-bus,
config-store writer, and operator-reconciliation crates. Composition tests run
every registered action against instrumented config/reconciliation fakes and
fail on any attempted write. Catalog validation, dependency checks, restricted
handler capabilities, server admission, and datastore/reconciliation evidence
are all required; no one layer is sufficient by itself. These controls verify
the supported composition boundary, not malicious code compiled deliberately
outside it.

### 7.2 Command Specification

The transport-neutral model is conceptually:

```rust
pub struct CommandSpec {
    pub id: CommandId,
    pub version: CommandVersion,
    pub grammar: CommandGrammar,
    pub summary: HelpText,
    pub description: HelpText,
    pub examples: Vec<CommandExample>,
    pub effect: EffectClass,
    pub availability: CapabilityRequirement,
    pub authorization: AuthorizationSpec,
    pub operation: OperationPlan,
    pub presentation: PresentationSpec,
    pub limits: CommandLimits,
    pub deprecation: Option<Deprecation>,
}
```

All strings and collections MUST have explicit size limits. The wire catalog
MUST use stable enums and versioned schemas rather than serializing Rust trait
objects or closures.

`CommandId` is the stable API identity. Human syntax may gain aliases or be
reorganized while the identity remains stable for audit, telemetry, and
compatibility.

### 7.3 Grammar

A grammar is a bounded tree of:

```rust
pub enum GrammarNode {
    Literal {
        token: CommandToken,
        aliases: Vec<CommandToken>,
        help: HelpText,
    },
    Argument {
        name: ArgumentName,
        value: ValueSpec,
        sensitive: bool,
        completion: CompletionSpec,
    },
    Optional(Vec<GrammarNode>),
    Choice(Vec<Vec<GrammarNode>>),
}
```

Unbounded recursion, arbitrary regular expressions, executable validators, and
target-supplied parser code are prohibited. Grammar depth, branch count, token
length, and total nodes MUST be bounded by `opc-mgmt-limits`.

Arguments SHOULD use generated YANG-derived types or SDK value types:

- IP address and prefix;
- interface or peer identifier;
- duration and bounded integer;
- enum and boolean;
- timestamp;
- tenant-safe session key;
- explicitly classified subscriber identifier;
- generated action input object.

### 7.4 Operation Plans

```rust
pub enum OperationPlan {
    Get(ReadPlan),
    Subscribe(SubscribePlan),
    Invoke(ActionPlan),
    Composite(CompositeReadPlan),
}
```

A `ReadPlan` or `SubscribePlan` references schema-validated generated paths and
binds parsed arguments only into declared list keys or query fields. It MUST
NOT build an XPath or query by concatenating untrusted text.

`CompositeReadPlan` may combine a bounded number of independent read
operations for presentation. Arbitrary client-side programs, loops, branches,
or scripts are prohibited. Complex domain behavior belongs in a typed
server-side action.

An `ActionPlan` references a modeled YANG RPC/action or a registered typed
operational service. It includes input bindings, deadline, output limits,
idempotency semantics, and cancellation behavior.

### 7.5 Presentation Specification

Presentation is declarative and operates over typed results:

```rust
pub enum PresentationSpec {
    Table(TableSpec),
    Detail(DetailSpec),
    Tree(TreeSpec),
    EventStream(EventStreamSpec),
    Scalar(ScalarSpec),
}
```

Table columns reference validated response fields and may declare headings,
width policy, alignment, units, and redaction classification. Presentation
specifications MUST NOT contain general template languages, code, terminal
control sequences, filesystem paths, or network URLs.

JSON and other machine-readable output are generated from the authorized typed
result, not by scraping the rendered table.

Data classification is anchored in trusted generated schema metadata and local
governance policy, not in the target-supplied catalog. A catalog may increase
sensitivity but cannot lower that minimum; unknown fields default to
sensitive. One governance projection applies consistently to table, detail,
tree, JSON/NDJSON, history, export, errors, completion, and audit so a different
renderer cannot bypass redaction.

### 7.6 Completion

Completion sources are:

- static literals and aliases;
- schema enums and bounded numeric/value hints;
- generated identifiers from already authorized, low-cardinality operational
  state;
- an explicitly registered bounded completion provider.

Remote completion is an authenticated management read and MUST pass the same
authorization and audit boundary as explicit commands. High-cardinality or
sensitive values, including subscriber identifiers, MUST NOT be enumerable by
default. Completion results MUST be capped, cancellable, cache-bounded, and
safe to render.

Phase 1 completion is limited to literals, aliases, types, and schema enums.
Remote completion is opt-in after the local editor and authorization boundary
pass conformance; every command must remain discoverable and usable without
remote completion.

## 8. CNF Registration API

### 8.1 Registration Contract

A CNF registers commands during management-plane composition:

```rust
pub trait OperationalCommandModule: Send + Sync {
    fn register(
        &self,
        registry: &mut CommandRegistry,
    ) -> Result<(), CommandRegistrationError>;
}
```

Illustrative ePDG registration:

```rust
registry
    .command(EpdgCommandId::ShowIkeSecurityAssociations)
    .syntax("show ike security-associations [peer <address>]")
    .summary("Display active IKE security associations")
    .effect(EffectClass::Observe)
    .get(EpdgPaths::ike_security_associations())
    .table([
        column("SPI", EpdgFields::initiator_spi()),
        column("Peer", EpdgFields::peer_address()),
        column("State", EpdgFields::state()),
        column("Age", EpdgFields::age()),
        column("Child SAs", EpdgFields::child_sa_count()),
    ])?;

registry
    .command(EpdgCommandId::DiagnosePing)
    .syntax("diagnose ping <destination> [source-interface <interface>]")
    .summary("Test reachability from an ePDG interface")
    .effect(EffectClass::Probe)
    .limits(CommandLimits::probe_defaults())
    .invoke(EpdgActions::ping())?;
```

The concrete API MAY use builders, macros, or generated modules. It MUST retain
typed path/action references so schema drift fails at generation, compilation,
or startup validation instead of during an operator session.

### 8.2 Registry Freeze and Publication

After registration, the CNF composition root freezes the registry against the
active schema registry:

```rust
let catalog = command_registry.freeze(schema_registry)?;
let provider = ConsoleCatalogProvider::new(catalog, authorizer, capabilities);
management_binding.with_console_catalog(provider);
```

`freeze` returns an immutable `ValidatedCommandCatalog`; it does not serialize
transport data. `ConsoleCatalogProvider` applies current capability and
principal visibility, then the gNMI and NETCONF bindings project the same
result through the well-known console YANG model. Transport bindings MUST NOT
reinterpret command grammar or operation semantics.

The final API shape may differ, but registration, validation/freeze,
principal-visible projection, and transport serialization MUST remain separate
steps with separately testable errors.

### 8.3 Registry Validation

Startup validation MUST reject:

- duplicate command IDs;
- ambiguous grammar paths;
- alias collisions;
- unknown schema paths or action identities;
- unauthorized use of reserved SDK top-level words;
- presentation fields not present in the result schema;
- missing effect, authorization, deadline, or limit metadata;
- a `configure` operation or any config mutation primitive;
- unbounded result, subscription, input, or completion declarations;
- unsafe help or display text;
- command/catalog versions incompatible with the SDK server binding.

Failure MUST be visible during CNF startup admission. Production profiles MUST
fail closed rather than silently omit an invalid command module.

### 8.4 Standard and CNF-Specific Commands

The SDK supplies a standard base vocabulary for common models, including:

- `show system`;
- `show health`;
- `show alarms`;
- `show config-application-status`;
- `monitor alarms`;
- `describe`, `whoami`, `capabilities`, and session-local commands.

CNFs augment this vocabulary with domain commands such as ePDG IKE/IPsec state,
SMF PDU sessions, AMF UE context summaries, and UPF forwarding state.

SDK command words and IDs occupy a reserved namespace. CNF extensions MUST use
stable product/module namespaces internally even when the visible grammar is
natural and concise.

The SDK MUST publish a command-language style guide covering top-level verbs,
singular/plural nouns, filter ordering, identifiers, units, time display,
empty-result language, destructive verbs, and common aliases. New CNF modules
receive an operator-experience review against this vocabulary so `show peers`,
for example, does not mean materially different things across CNFs without
explicit qualification.

### 8.5 Test and Preview Support

The SDK MUST provide a command-module testkit that can:

- validate a registry without starting a CNF;
- render a complete command tree;
- snapshot `?`, completion, and `describe` output;
- execute commands against fake operational providers;
- exercise denied, empty, large, slow, and malformed responses;
- preview tables at common terminal widths;
- assert that no config mutation is reachable;
- emit catalog compatibility evidence.

CNF owners are responsible for the human command experience, not only for
making their operation plan compile.

## 9. Catalog Discovery

### 9.1 Well-Known Model

The SDK will define an `openpacketcore-console` YANG module with an operational
catalog rooted at a well-known path:

```text
/openpacketcore-console:console/catalog
```

The model exposes:

- catalog schema version;
- catalog content ID/digest;
- target product and command-module identities;
- minimum and maximum compatible console protocol versions;
- authenticated principal visibility revision;
- command specifications;
- supported output and action capabilities.

The catalog is available through authenticated gNMI `Get` and NETCONF `<get>`
or `<get-data>`. The same semantic content MUST be produced regardless of the
transport used to retrieve it.

### 9.2 Discovery Sequence

The console performs:

1. select the management context explicitly, from a context-qualified target,
   or from the user's active context;
2. load and validate that context's target-discovery, issuer, broker, and trust
   configuration;
3. acquire authentication according to the configured mode: OIDC/OpenShift
   establishes a human and broker session, SSH loads/proves an approved agent
   identity and optionally exchanges it with a broker, and SPIFFE automation
   obtains a workload identity without a human login;
4. resolve the target through static context data or the context's
   authenticated discovery service;
5. acquire target-scoped protocol credentials from the mode's credential
   source: broker-issued mTLS/SSH credentials, an approved SSH agent/certificate,
   or the SPIFFE Workload API;
6. establish the catalog transport, mutually authenticating the client and
   verifying the target server identity;
7. request protocol and model capabilities;
8. retrieve the principal-visible catalog;
9. validate catalog size, syntax, schema references, and compatibility;
10. build the local command trie and initialize presentation state;
11. display the ready prompt;
12. connect additional transports eagerly or lazily according to the trusted
    transport policy.

For human modes the TUI prints "Logged in" only after step 3; automation modes
print the redaction-safe workload identity state instead. It prints
"Connected" only after step 6 and the ordinary target prompt only after step
11. When an existing session or credential is reused, the same states occur
without an unnecessary browser round trip. A failure leaves the console in the
corresponding visible local state with `status`, `reauthenticate`,
`disconnect`, and `exit` available.

Catalog bootstrap has an explicit trusted order because full capability
selection is not yet available. The management context supplies the allowed
bootstrap transports and order; the authenticated target-discovery record
supplies matching endpoints. For each candidate, the client completes the
authenticated handshake, then gNMI `Capabilities` or the NETCONF hello/YANG
library exchange, and accepts it only if the well-known console model/catalog
is supported. It may try the next candidate only for pre-dispatch
`Unavailable` or `Unimplemented`; authentication, target-identity, policy, or
malformed-capability failures stop bootstrap. The resulting capability set
then drives the general adapter-selection algorithm in Section 12.2.

The console MAY load a memory-cached catalog optimistically after target and
principal identity are established, but it MUST validate the advertised
content ID before executing target commands. The cache key includes verified
target identity, stable principal key, tenant, authentication
strength/credential profile, visibility revision, schema/model set,
capabilities, and allowed adapter set. It is purged on logout, principal or
tenant change, assurance downgrade, policy/visibility change, and target
identity change. Lost refresh signals are covered by bounded TTL and
revalidation. The content digest covers the canonical principal-visible
catalog. A persistent role-filtered cache requires a separate encrypted-cache
threat review and is not part of the MVP.

### 9.3 Principal-Visible Catalog

Command inventory is confidential management metadata by default. Reading the
catalog root requires a deny-by-default `discover` authorization decision, and
the server MUST filter command entries unavailable to the authenticated
principal. Static visibility evaluates the command's declared paths/actions
against the set of execution adapters both allowed by trusted policy and
available on the target; it does not depend on which transport retrieved the
catalog. Composite commands are visible only under their declared all-path or
partial-result policy. Input-dependent and instance authorization remains an
execution-time decision and is not disclosed by catalog filtering.

Catalog filtering improves usability but never grants authority. The server
MUST reauthorize every operation because policy, tenant, target state, and
instance keys can change after catalog retrieval.

The catalog includes a visibility revision. A policy or capability change MUST
advance that revision and signal catalog refresh on transports that support it;
clients still revalidate on bounded TTL because signals can be lost. The TUI
MUST preserve the current line when refreshing the command tree where possible.

### 9.4 Untrusted Catalog Handling

An authenticated target may still be faulty or compromised. The client MUST:

- cap encoded and decoded catalog size;
- cap command count, grammar depth, branches, arguments, help length, examples,
  presentation fields, and completion declarations;
- reject duplicate fields and unknown mandatory semantics;
- reject control characters and terminal escape sequences;
- parse without panics on malformed input;
- avoid loading target-provided code, fonts, themes, URLs, or files;
- fail closed for the target-specific catalog while retaining safe local
  commands such as `disconnect`, `status`, and `exit`.

## 10. Login and Management Identity

### 10.1 Ownership

OpenPacketCore owns the login integration framework, native-client behavior,
access-broker contract, and terminal session lifecycle. It does not own the
customer's password page, MFA policy, users, or identity database.

The page opened by `opc login` is selected by the trusted management context:

- Keycloak or another OIDC provider opens its configured authorization page;
- OpenShift integrated OAuth opens the cluster OAuth authorization page;
- an enterprise provider may federate to Entra ID, Okta, Ping, or another IdP;
- SSH-agent and workload profiles do not open a browser.

The only browser content served by the native CLI is a minimal loopback
callback success/error page telling the user to return to the terminal.

### 10.2 Management Context

Illustrative configuration:

```yaml
apiVersion: management.openpacketcore.io/v1alpha1
kind: ManagementContext
metadata:
  name: production
spec:
  targets:
    discovery: https://management.example.com/targets
  trust:
    serverBundle: /etc/openpacketcore/production-targets.pem
    brokerBundle: /etc/openpacketcore/production-broker.pem
  authentication:
    provider: oidc
    issuer: https://sso.example.com/realms/packet-core
    clientId: opc-cli
    audience: opc-management
    scopes: [openid, profile, email]
    flow: authorization-code-pkce
  accessBroker:
    endpoint: https://access.management.example.com
```

OpenShift example:

```yaml
spec:
  authentication:
    provider: openshift-oauth
    issuer: https://oauth-openshift.apps.cluster.example.com
    clientId: opc-cli
    scopes: [user:info]
    flow: authorization-code-pkce
```

The IaC invariant in this RFC applies directly to CNF desired state. Management
security configuration is a separate bootstrap trust boundary, but production
contexts MUST also be versioned and installed through IaC or a signed
environment bundle with configured signer trust, expiry, anti-rollback, atomic
update, and owner-only local storage. Unsigned manual contexts are limited to
an explicit development/compatibility profile.

CLI flags, environment variables, target discovery, and CNF command catalogs
MUST NOT override issuer, authorization/token/JWKS endpoints, broker, callback
policy, requested scopes, target identity, or trust roots in a production
context.

Target discovery records MUST be authenticated and freshness-bound. Each
record binds the logical target name to expected cryptographic server identity,
tenant and NF-kind constraints, endpoints, and allowed transports. The client
verifies that identity atomically during the actual mTLS or SSH handshake; a
broadly trusted CA certificate without the expected target binding is not
sufficient.

Context selection is deterministic. An explicit `--context` wins, followed by
a context-qualified target name, followed by the locally selected active
context. If none exists, or a short target name is ambiguous across contexts,
the CLI MUST ask the user to select from locally trusted contexts and MUST NOT
guess. `opc login <context>` establishes or refreshes that environment's login
session; `opc connect` invokes the same flow implicitly when required.

### 10.3 Authentication and Credential Interfaces

Identity-provider login, broker exchange, and protocol credential possession
are separate ports:

```rust
pub trait HumanAuthenticator: Send + Sync {
    async fn authenticate(
        &self,
        context: &ManagementContext,
        interaction: &dyn LoginInteraction,
    ) -> Result<HumanAuthSession, LoginError>;
}

pub trait CredentialBroker: Send + Sync {
    async fn exchange(
        &self,
        session: &HumanAuthSession,
        keys: &ClientPublicKeys,
    ) -> Result<ManagementCredentialSet, BrokerError>;
}

pub trait ProtocolCredentialSource: Send + Sync {
    async fn credentials(
        &self,
        target: &VerifiedTarget,
    ) -> Result<ManagementCredentialSet, CredentialError>;
}
```

The interfaces also define refresh and logout/revocation operations omitted
from the illustrative async signatures. The concrete Rust form may use
object-safe boxed futures or an equivalent adapter; implementations selected at
composition boundaries MUST be object-safe when runtime provider selection
requires it.

| Mode | Human login | Broker | Protocol credentials | Intended use |
| :--- | :--- | :---: | :--- | :--- |
| `oidc` | Keycloak or enterprise OIDC | Yes | Broker-issued mTLS/SSH | Production human access |
| `openshift-oauth` | OpenShift integrated OAuth | Yes | Broker-issued mTLS/SSH | Production OpenShift human access |
| `ssh-agent` | Existing SSH identity | Optional | Agent key or broker-issued SSH certificate | Disconnected/compatibility human access |
| `spiffe-workload` | None | No | Workload API X.509-SVID | Non-human automation only |

Provider-specific differences remain behind these ports. OIDC discovery and
OpenShift OAuth authorization-server discovery are not assumed to be
interchangeable, and workload identity is not described as human login.

### 10.4 Native Interactive Flow

For OIDC-capable providers, the CLI uses an external browser, authorization
code, PKCE S256, state, nonce where applicable, an exact loopback redirect, and
a public client registration without an embedded client secret. Device
authorization MAY be enabled for headless environments only when explicitly
configured and advertised by the provider.

A production context that claims jump-host support MUST configure and test a
headless login path. `opc login --no-browser` uses device authorization when
the provider advertises it, or an approved SSH-agent/workload profile. The TUI
MUST display the exact verified HTTPS origin and user code, distinguish pending
authorization from denial or expiry, support cancellation and bounded retry,
and never infer a device endpoint from an untrusted target.

Normative standards include:

- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252);
- [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636);
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414);
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628);
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

The CLI MUST NOT collect the user's IdP password or use a resource-owner
password grant.

Production provider profiles additionally require exact issuer comparison,
HTTPS endpoint validation against context-approved trust, bounded metadata and
JWKS caches, an algorithm allowlist, controlled key refresh, and no
cross-origin metadata redirects outside explicit context policy. The loopback
listener binds only loopback addresses on an ephemeral port, accepts one
state-matching callback, has a short deadline, and closes after success or
failure. OpenShift OAuth uses its explicit authorization-server metadata and
identity-validation adapter rather than pretending its tokens are OIDC ID
tokens.

### 10.5 Access Broker and Protocol Credentials

The production human-login profile uses a management access broker so every
CNF does not integrate independently with every identity provider.

The flow is:

1. the CLI authenticates the human with the configured provider;
2. the CLI sends a broker-audience OAuth access token only to the configured
   broker; an OIDC ID token is never accepted as the broker bearer credential;
3. the broker validates issuer, audience, signature, time claims, session
   state, and provider-specific identity resolution;
4. trusted broker policy maps the identity to an allowed tenant and management
   credential profile;
5. the CLI generates ephemeral client key material or uses an approved agent,
   obtains a broker nonce, and proves possession of the corresponding key in
   the exchange;
6. the broker issues short-lived gNMI/mTLS and NETCONF/SSH credentials bound to
   one management login session and proof of possession;
7. each CNF authenticates the broker-issued credential and creates the same
   stable management-user principal;
8. CNF-side signed policy supplies roles and NACM groups.

The broker MUST NOT accept a tenant selected solely by the CLI. Roles and NACM
groups MUST NOT be trusted from unsigned client metadata or ordinary command
arguments.

The broker profile defines the required token audience/resource, accepted
access-token type, issuer allowlist, maximum token age, replay cache, nonce/key
proof, and sender-constrained-token policy. Opaque OpenShift access tokens are
validated through the configured authoritative OpenShift integration. A token
that cannot be audience-bound and replay-controlled for the broker is rejected
in the production profile.

The SDK will separate stable authorization identity from rotating
authentication state:

```rust
pub struct ManagementPrincipalKey {
    pub issuer: IssuerId,
    pub subject: SubjectId,
    pub tenant: TenantId,
}

pub struct AuthenticationContext {
    pub login_session: LoginSessionId,
    pub credential_id: CredentialId,
    pub expires_at: Timestamp,
    pub auth_strength: AuthStrength,
    pub credential_profile: CredentialProfileId,
}
```

The precise X.509 and SSH certificate wire profiles require security review
before implementation. Both profiles MUST cryptographically bind the stable
principal and authentication context, use client-generated or agent-held
private keys, exclude roles/groups, and map to one stable authorization key.
Roles and authorization caches key on `ManagementPrincipalKey`; audit and
session enforcement additionally bind `AuthenticationContext`. A session,
credential, assurance, or profile change invalidates authentication-dependent
caches without changing the stable user grant key.

This is an explicit extension to RFC 003, whose current gRPC profile only
defines SPIFFE workload principals. Phase 2 is blocked until an RFC 003
amendment is accepted and implemented defining
`PrincipalIdentity::{Workload, ManagementUser}`, the canonical management-user
certificate identity, issuing trust and bundle distribution to CNFs, tenant
validation, X.509 and SSH mappings, service/method authorization, rotation,
expiry, and cross-transport conformance tests.

### 10.6 Session and Credential Handling

`AuthSession` and protocol credentials MUST be opaque secret-bearing types:

- no secret-bearing `Debug` or display output;
- no access, refresh, device, or broker tokens in logs, traces, audit payloads,
  panic text, command history, process arguments, or environment dumps;
- ephemeral private keys remain in memory or an approved agent and are zeroed
  when feasible;
- persistent refresh credentials require an OS credential store or approved
  agent and explicit policy;
- credentials have configurable short lifetimes with a hard production cap;
- refresh occurs before expiry without freezing the TUI;
- target connections are rotated or re-established after credential renewal;
- `logout` closes target sessions, removes local credentials, and requests
  broker/provider revocation where supported;
- the TUI warns before expiry and provides `reauthenticate` without discarding
  the current command line.

The prompt and `whoami` show redaction-safe identity, tenant, authentication
strength, and expiry. They never show tokens, certificate material, or raw
authorization policy.

CNFs enforce credential expiry and a maximum connection/stream age server-side;
the TUI is not the enforcement point. The production credential profile sets
the numeric maximum lifetime before Phase 2. Logout closes local connections
and revokes broker/provider refresh state, but an offline certificate may
remain usable until its short expiry unless the deployment provides a
target-consumed revocation feed. The CLI reports that residual validity
honestly. Renewal of a subscription or accepted action reconnects observation
by stable operation/stream semantics and never replays the action.

## 11. Authorization and Audit

### 11.1 Authorization Mapping

Commands map to existing SDK authorization classes:

| Command effect | Authorization |
| :--- | :--- |
| catalog discovery | deny-by-default management `discover` plus static command visibility |
| remote completion | explicit `enumerate` plus per-instance read filtering and completion policy |
| `observe` | NACM `read` for every selected schema path |
| `monitor` | NACM `subscribe` for every selected schema path |
| `probe` | NACM `exec` for the static modeled action path, plus action policy |
| `operate` | NACM `exec` for the static modeled action path, plus action policy and confirmation |

A composite read is allowed only when every required path is allowed, unless
the command explicitly defines a schema-safe partial-result policy. Partial
results MUST identify omitted sections without revealing denied values.

An authorization failure MUST NOT cause the console to retry through another
protocol in an attempt to obtain a different decision.

`discover` and `enumerate` are explicit extensions to the shared authorization
facade. `enumerate` is never implied by ordinary read access. A remote
completion plan requires data-classification approval, per-instance filtering,
minimum-prefix policy where appropriate, per-principal rate/query budgets, no
pagination, and a principal-scoped short-lived cache purged on logout or policy
change.

### 11.2 Confirmation

Confirmation is a usability safeguard, not authorization. An `operate` command
declares:

- whether confirmation is required;
- a redaction-safe target summary;
- whether a reason/ticket is required;
- whether the action supports dry-run;
- idempotency and retry behavior;
- cancellation semantics.

The TUI MUST require an explicit response for destructive actions. One-shot
mode requires an explicit non-interactive confirmation flag and MUST NOT infer
consent from standard input being non-terminal.

### 11.3 Audit Events

Every target-observed catalog retrieval, completion query, read, subscription
start/stop, action, denial, and cancellation emits an authoritative target
enforcement audit event. A client-side stop/cancel attempt that cannot reach
the target emits only a local intent event and remains explicitly unconfirmed.
Authentication and connection transitions emit the applicable broker/target
event.

Before executing a mutating operational action, the target durably appends its
intent/authorization audit event. If that append fails, execution fails closed.
It appends outcome afterward. If the side effect may have occurred but outcome
append fails, the server and TUI report a potentially completed action, enter a
security-degraded state, and block further mutations until audit health is
restored; they do not claim the side effect was rolled back. Non-mutating
operations follow RFC 003 audit availability policy.

The console also emits a supplemental local intent event containing command ID
and UX metadata. It is not authoritative evidence of target authorization.
Target and console events share a request/correlation ID where the protocol
permits, but the server never trusts client-supplied command metadata for an
authorization decision.

The combined audit model includes:

- stable command ID and version;
- effect class;
- authenticated principal and login session ID;
- target identity and selected transport;
- authorized schema/action identities;
- request/correlation ID;
- start time, duration, result class, and cancellation state;
- redaction marker and bounded argument classification;
- confirmation and reason metadata for operational mutations.

Raw tokens, secrets, unrestricted command text, subscriber identifiers, and
unredacted payloads MUST NOT enter audit records.

## 12. Execution and Protocol Mapping

### 12.1 Transport-Neutral Client Traits

The console engine depends on narrow capabilities:

```rust
pub trait OperationalReader {
    async fn get(&self, request: ReadRequest) -> Result<ReadResult, MgmtError>;
}

pub trait OperationalSubscriber {
    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<OperationalStream, MgmtError>;
}

pub trait OperationalActionInvoker {
    async fn invoke(
        &self,
        request: ActionRequest,
    ) -> Result<ActionExecution, MgmtError>;
}
```

A single oversized `ManagementClient` trait is discouraged because transports
and CNFs support different capability sets.

### 12.2 Adapter Selection

The session negotiates capabilities and selects an adapter per operation:

| Semantic operation | Preferred adapter | Alternatives |
| :--- | :--- | :--- |
| capabilities/catalog | gNMI capabilities + Get | NETCONF hello + get/get-data |
| bounded state read | gNMI Get | NETCONF get/get-data |
| state monitor | gNMI Subscribe | NETCONF notification when modeled |
| YANG RPC/action | NETCONF RPC/action | registered typed service |
| standard operational service | registered gRPC/gNOI-style adapter | modeled NETCONF action |

The TUI hides protocol selection, but `status` and diagnostic logs expose the
selected adapter without leaking credentials or payloads.

The trusted management context contains a `TransportPolicy` with allowed
adapters, deterministic preference order, optional per-operation overrides,
and eager/lazy connection policy. Adapter selection is:

1. start with adapters allowed by the trusted context;
2. retain only adapters whose authenticated capability set implements the
   semantic operation;
3. order candidates by the per-operation override or the default table above,
   then by the context preference order;
4. reuse a healthy authenticated connection or lazily establish one;
5. select the first successful candidate and record the choice in local status
   and audit.

Fallback has two explicit cases:

- when the adapter proves the operation was not dispatched and the failure is
  `Unavailable` or `Unimplemented`, the engine may select the next adapter;
  this is an initial dispatch, not a replay;
- when dispatch may have occurred, any retry of an action class, including
  `probe`, requires declared idempotency plus a protocol-independent
  idempotency key and target-enforced deduplication shared across eligible
  adapters; otherwise the outcome is ambiguous and no retry occurs.

Syntax, authentication, authorization, policy, validation, malformed response,
resource exhaustion, and security failures are never fallback triggers. All
attempts preserve one deadline, principal, authorization target,
request/correlation ID, validation/limit policy, and result schema.

Protocol fallback is permitted only for transport unavailability or an
unimplemented capability according to policy. It MUST NOT bypass an
authentication, authorization, validation, or resource-limit failure.

### 12.3 Action Lifecycles

Actions may be:

- immediate: one structured result;
- streaming: bounded result events until completion or cancellation;
- accepted: a stable operation ID followed through operational state or a
  subscription.

Long-running operations SHOULD use the accepted model so reconnecting the TUI
does not lose server-side operation identity. The command catalog declares
whether disconnect or cancellation terminates the server-side action.

The MVP permits one foreground remote operation per console. An accepted
server-side operation may be detached only by stable operation ID and later
queried or reattached through a modeled status path. General concurrent
background jobs are deferred.

Retries require declared idempotency. The client MUST NOT automatically retry a
non-idempotent `operate` command after an ambiguous transport failure.

### 12.4 Stream Integrity and Backpressure

Control events for cancellation, authentication expiry, connection state,
catalog invalidation, and terminal shutdown use a bounded priority path that
bulk output cannot starve. Data-event channels are bounded and declare one of
these policies:

- `lossless`: apply bounded backpressure; if the limit/deadline is exceeded,
  terminate the view with an explicit truncation/gap event;
- `coalescing`: replace older updates only for the same schema key when the
  command explicitly declares state-coalescing semantics, and display the
  number and interval of coalesced updates.

Silent event drops are prohibited. Every stream exposes receive timestamps,
target timestamps and sequence information when supplied by the protocol,
initial-snapshot/synchronization markers, reconnect boundaries, and known gap
or drop counts.

On transport loss, a monitor does not silently continue. It either:

- resumes from a proven replay/resume point supported by the adapter;
- restarts with a visible reconnect marker and new initial snapshot while
  marking the intervening interval unknown; or
- terminates and returns to the prompt.

The catalog and adapter capability select the behavior. A local pause pauses
viewing, not the remote source; if its bounded buffer fills, the console emits
an explicit gap/truncation result rather than hiding loss.

### 12.5 Cancellation and Deadlines

Every local execution carries a deadline and cancellation handle. The adapter
propagates protocol cancellation when the selected transport supports it;
otherwise it closes/detaches the stream or session according to the declared
lifecycle and reports an ambiguous outcome when remote completion is unknown.
`Ctrl-C`:

1. returns control to the TUI event loop immediately;
2. marks the local execution cancelled;
3. sends protocol cancellation when supported;
4. continues bounded background cleanup;
5. records the final known state in audit and local status.

The TUI must distinguish "cancel requested" from "remote action confirmed
cancelled." It MUST NOT claim that a side effect did not occur after an
ambiguous failure.

## 13. TUI Design

### 13.1 Session State Model

Authentication, transport, catalog, foreground operation, and active view are
orthogonal state axes rather than one linear enum:

```rust
pub struct ConsoleState {
    pub lifecycle: LifecycleState,
    pub authentication: AuthenticationState,
    pub transports: TransportSetState,
    pub catalog: CatalogState,
    pub foreground: ForegroundState,
    pub view: ViewState,
}
```

The reducer derives `Ready` only when lifecycle, authentication, at least one
required transport, and catalog validity permit execution. Transitions are
visible but unobtrusive. The prompt MUST distinguish a ready target from a
disconnected, degraded, expired, stale-catalog, or reconnecting target.

Typing and safe local help remain available during recoverable transitions,
but target commands entered while not ready are rejected with the blocking
state; they are never queued for later automatic execution. `?` and tab may use
only a currently validated catalog and must visibly mark stale offline help.
`logout` closes target connections before discarding or revoking credentials.

### 13.2 Event Model

The UI consumes structured events:

```rust
pub enum ConsoleEvent {
    Connection(ConnectionEvent),
    Authentication(AuthenticationEvent),
    Catalog(CatalogEvent),
    Command(CommandEvent),
    Output(OutputEvent),
    Progress(ProgressEvent),
    Warning(ConsoleWarning),
    Error(ConsoleError),
}
```

Network tasks MUST NOT write directly to the terminal. They send bounded events
to the UI, which owns terminal state and sanitization.

### 13.3 Input and Command Editing

The interactive editor MUST provide:

- history navigation;
- beginning/end and word movement;
- token-aware completion;
- multiline editing only when an argument format explicitly requires it;
- safe paste handling;
- search over history that the history policy allowed to persist;
- clear indication of incomplete grammar;
- preservation of the current line across asynchronous notifications.

The baseline key contract includes arrow and Home/End navigation, Ctrl-A/E,
Ctrl-W and word movement/deletion, Backspace/Delete, history search, completion
cycling, quoting/escaping rules, and Unicode grapheme-aware cursor movement.
Literal `?` in an argument uses quoting or escaping; unquoted `?` requests
contextual help. The implementation MUST publish the complete keymap through a
local `help keys` view.

Bracketed paste MUST NOT cause pasted newlines to execute multiple commands
without an explicit review/confirmation policy.

Asynchronous notifications are batched according to a bounded display policy,
rendered above the edit line, and followed by deterministic restoration of the
prompt, buffer, cursor, and completion state. Progress updates replace only
their own progress region. Bulk notifications MUST NOT continuously steal the
cursor; the console summarizes them and offers a dedicated view.

### 13.4 History

Argument specifications carry sensitivity and data-classification metadata.
History policy may:

- persist the complete command when all arguments are safe;
- persist a redacted command form;
- persist only the stable command ID;
- omit the entry entirely.

Tokens, passwords, private material, authentication codes, sensitive
subscriber identifiers, and action secrets MUST never be persisted. History
files require owner-only permissions and bounded retention.

The default production policy persists safe commands, stores a visibly
redacted non-replayable entry when only selected arguments are classified, and
omits secret-bearing commands. Selecting a non-replayable history entry shows
why it cannot execute until the missing value is re-entered.

### 13.5 Rendering and Pager

The renderer MUST:

- consume typed rows/events incrementally;
- cap buffered rows and bytes;
- preserve column identity across terminal resize;
- provide a detail view when columns cannot fit safely;
- clearly label truncation, omission, redaction, stale data, and partial
  results;
- never interpret remote ANSI, OSC, hyperlink, clipboard, or title sequences;
- allow the user to stop rendering without falsely cancelling a server-side
  action;
- separate local rendering failure from remote operation failure.

The built-in pager remains inside the console process. Invoking an external
pager is disabled by default in production profiles because environment,
history, temporary-file, and terminal-control behavior cross additional trust
boundaries.

The pager owns navigation keys only while active: arrows and PageUp/PageDown
move, `/` searches rendered safe text, `n` advances a match, `w` toggles
wrap/horizontal handling, Enter opens a structured detail view, and `q` closes
the view. Closing the pager means "stop viewing" only. For a live source, the
TUI separately offers `pause`, `follow`, `detach` where supported, and `stop`;
only `stop` requests remote cancellation. Ctrl-C follows the currently
displayed ownership hint and never silently conflates those actions.

Machine output has a versioned envelope and stable schema identity. One-shot
bounded results use JSON; streams use NDJSON by default. Structured results go
to stdout, while progress and redaction-safe diagnostics go to stderr. An
interactive `| json` view remains inside the pager unless the user explicitly
requests a classified file export.

File export uses owner-only permissions, an atomic create/write/rename flow,
and no overwrite without explicit confirmation. The exporter preserves data
classification and redaction metadata, reports partial writes without printing
payloads, and never routes classified output through a temporary world-readable
file.

### 13.6 Errors

Errors use the shared management status taxonomy and a stable console category:

- syntax or local validation;
- authentication required/expired;
- permission denied;
- target unavailable/reconnecting;
- capability unavailable;
- remote deadline/cancellation;
- malformed target response;
- output truncated by policy;
- ambiguous action outcome;
- internal console defect.

The TUI gives a concise operator message and an optional redaction-safe detail
view. It does not print raw server errors, XML, protobuf debug output, tokens,
paths containing sensitive values, or backtraces by default.

### 13.7 Terminal Lifecycle

The TUI owns raw mode, alternate-screen use, cursor visibility, mouse mode, and
signal handling through one terminal guard. It MUST restore the terminal on
normal exit, startup failure, handled panic, SIGINT/SIGTERM, broken pipe, and
other supported termination paths. Ctrl-Z suspends only after restoring the
terminal and resume re-enters and redraws from reducer state.

The line-oriented shell SHOULD preserve normal scrollback. Views that use the
alternate screen MUST document entry/exit and restore the previous screen.
Pseudo-terminal tests deliberately crash and signal the process to prove that
the terminal is not left in raw mode, with a hidden cursor, or with paste/mouse
modes enabled.

## 14. Security and Threat Model

### 14.1 Threats

The design assumes an attacker may:

- operate a malicious or compromised CNF endpoint;
- return a hostile catalog or operational value;
- inject terminal control sequences into remote data;
- attempt catalog or response memory exhaustion;
- cause high-cardinality completion queries;
- replay action requests or login callbacks;
- substitute an identity-provider or broker URL;
- steal local history or configuration files;
- observe process arguments, logs, audit, or terminal scrollback;
- interrupt transport after an action is accepted but before its result;
- exploit protocol fallback to seek a weaker authorization path.

Authorization and target-data confidentiality guarantees assume the CNF's RFC
003 enforcement boundary remains intact. A fully compromised target can ignore
NACM or falsify state. Against that target, the console still guarantees local
grammar/operation allowlisting, resource bounds, governance projection,
credential non-disclosure, and terminal safety; it cannot prove correctness or
confidentiality of target-owned behavior.

### 14.2 Required Controls

- Trusted contexts pin or validate target, issuer, and broker trust.
- Login redirects are derived only from validated provider metadata for the
  configured issuer.
- OAuth state, PKCE, nonce where applicable, exact redirects, issuer, audience,
  signature, and time claims are validated fail closed.
- Catalogs, responses, help, completion, and rendering are size bounded.
- All remote strings are terminal sanitized.
- Commands bind arguments through typed fields rather than string-built
  queries.
- Roles/groups come from signed policy, not unsigned transport metadata.
- Completion, help filtering, reads, subscriptions, and actions respect tenant
  and authorization boundaries.
- Action retries obey declared idempotency.
- Secrets and classified values are excluded or redacted from history, logs,
  metrics, error messages, and audit.
- Protocol fallback cannot downgrade security decisions.
- Parser and catalog decoders are fuzzed and contain no untrusted-input panic
  paths.

### 14.3 Terminal Output Is a Security Boundary

Operational fields may contain peer names, alarm text, interface labels, error
text, or identifiers influenced by external systems. Before width calculation
or display, the renderer MUST neutralize:

- C0/C1 controls except the console's own intentional line handling;
- ANSI CSI sequences;
- OSC title, hyperlink, and clipboard sequences;
- bidirectional text controls according to policy;
- invalid or excessively combining Unicode;
- embedded newlines in fields not declared multiline.

Raw export, when authorized, MUST write through an explicit file-output path
with classification checks. `--raw` does not mean "write untrusted bytes to the
terminal."

## 15. Failure and Recovery

### 15.1 Connection Loss

On connection loss the TUI:

- marks the prompt disconnected;
- retains the current edit buffer;
- cancels or detaches operations according to their declared lifecycle;
- reconnects with bounded exponential backoff and jitter when policy allows;
- reauthenticates if credentials expired;
- revalidates target identity and catalog content ID;
- does not replay non-idempotent actions automatically.

### 15.2 Catalog Failure

If catalog validation fails, target commands are unavailable. The console
retains safe local commands:

- `status`;
- `show connection`;
- `reauthenticate`;
- `disconnect`;
- `diagnostics console`;
- `exit`.

It MUST NOT fall back to executing unknown raw paths or arbitrary RPC names as
a convenience.

### 15.3 Authentication Failure

Unknown issuer, invalid metadata, TLS failure, callback mismatch, token
validation failure, broker denial, credential expiry, tenant mismatch, or
grant-source failure all fail closed. The operator receives a stable error
category and correlation ID without token contents or internal policy details.

## 16. Versioning and Compatibility

The system versions independently:

- catalog wire schema;
- command ID/version;
- visible syntax and aliases;
- operation/result schema;
- presentation schema;
- login-provider profile;
- management credential profile;
- console binary.

The catalog declares its compatible console protocol range. Unknown optional
fields may be ignored only when the wire schema marks them optional. Unknown
effect classes, operation primitives, required presentation semantics, or
security requirements cause that command or catalog to fail closed according
to compatibility policy.

Command deprecation includes replacement command ID, message, and earliest
removal version. Interactive aliases may preserve familiar legacy syntax, but
audit always records the stable command ID.

## 17. Proposed Crate and Component Boundaries

| Component | Purpose |
| :--- | :--- |
| `opc-mgmt-command` | Catalog types, grammar, operation plans, presentation specs, validation, and CNF registry |
| `opc-mgmt-action` | Typed action provider, action lifecycle, cancellation, idempotency, and result contracts |
| `opc-mgmt-client` | Transport-neutral reader, subscriber, invoker, capability, and session contracts |
| `opc-gnmi-client` | Production gNMI capabilities/Get/Subscribe client adapter |
| `opc-netconf-client` | Production NETCONF hello/get/get-data/RPC/action client adapter |
| `opc-auth-client` | Management contexts, login providers, native OAuth behavior, credential handles, refresh/logout |
| `opc-access-broker` | Reference broker service and management-user credential issuance contract |
| `opc-console` | Rust binary containing the interactive shell/TUI and optional one-shot mode |
| `opc-console-testkit` | Catalog, pseudo-terminal, rendering, auth, protocol, and CNF experience conformance tools |

Exact crate consolidation may change during implementation. The architectural
boundaries must remain narrow even if several are initially delivered in one
crate.

Existing crates are reused:

- `opc-mgmt-opstate` for reads and subscriptions;
- `opc-mgmt-schema` and `opc-yanggen` for generated paths and projections;
- `opc-mgmt-path` for normalized schema identity;
- `opc-mgmt-authz` and `opc-nacm` for read/subscribe/exec authorization;
- `opc-mgmt-principal` for trusted principal construction and signed grants;
- `opc-mgmt-audit` for operation audit;
- `opc-mgmt-errors` and `opc-mgmt-limits` for shared status and bounds;
- `opc-mgmt-transport`, `opc-tls`, and `opc-identity` for transport trust;
- `opc-redaction` and `opc-data-governance` for output classification;
- `opc-gnmi-server` and `opc-netconf-server` for server exposure.

The existing gNMI smoke client is test-oriented and MUST NOT silently become
the production client without a boundary, API, security, and lifecycle review.

## 18. Observability

Metrics use bounded labels and MUST NOT include raw users, targets with high
cardinality, command arguments, YANG instance paths, subscriber IDs, or login
session IDs.

Suggested metrics:

- `opc_console_sessions_total{outcome,auth_provider}`;
- `opc_console_active_sessions`;
- `opc_console_command_total{command_id,effect,outcome}` with an allowlisted
  bounded command ID set;
- `opc_console_command_duration_seconds{command_id,transport}`;
- `opc_console_catalog_load_total{outcome}`;
- `opc_console_catalog_size_bytes`;
- `opc_console_reconnect_total{reason}`;
- `opc_console_auth_refresh_total{outcome}`;
- `opc_console_output_truncated_total{reason}`;
- `opc_console_ui_event_lag_seconds`.

Local diagnostic logs are structured, redaction-safe, and disabled or bounded
according to profile. A user may export a console diagnostic report that
contains versions, state transitions, capability summaries, and correlation
IDs, but not command payloads or credentials.

## 19. Testing and Evidence

### 19.1 Unit and Property Tests

- grammar ambiguity and collision detection;
- typed argument validation and binding;
- prohibition of configuration mutations;
- catalog and presentation compatibility;
- terminal sanitization and Unicode width behavior;
- history classification and redaction;
- action idempotency and ambiguous outcomes;
- pure console-state reducer transitions with fake time and replayable event
  traces;
- queue overflow, priority-event, stream gap, and reconnect policies;
- authorization mapping and partial-result rules.

### 19.2 Fuzzing and Adversarial Tests

- malformed/oversized catalog documents;
- deeply nested grammar and choice bombs;
- hostile ANSI/OSC/bidirectional/Unicode output;
- malformed gNMI/NETCONF results;
- rapid resize, paste, completion, and cancel sequences;
- response floods, slow streams, queue saturation, coalescing, and gap
  reporting;
- login callback replay, state mismatch, issuer substitution, and token-like
  error payloads;
- transport downgrade/fallback attempts;
- disconnect at every action lifecycle boundary.

### 19.3 Pseudo-Terminal Conformance

The reference TUI MUST be tested through a pseudo-terminal at multiple sizes
and capability profiles. The evidence declares a supported matrix covering at
least a modern xterm-compatible terminal, a common Linux jump-host terminal,
`TERM=dumb`, non-TTY output, no-color, and append-only accessibility mode.
Tests verify:

- prompt and line preservation during asynchronous events;
- `?` and tab behavior for every example command;
- paging, filtering, no-color, resize, and cancellation;
- editor/pager key ownership and async notification redraw;
- secret-free history and scrollback fixtures;
- disconnected, expired, denied, slow, empty, and large-result UX;
- stream reconnect, gap, initial-snapshot, and truncation markers;
- append-only accessibility and `TERM=dumb` behavior;
- raw-mode/cursor/paste/mouse restoration after exit, signals, suspend/resume,
  broken pipe, startup failure, and a deliberate crash;
- stable plain-text snapshots for accessibility and support use;
- no terminal-control injection from target data.

Replayable interaction transcripts cover successful operation plus slow login,
denial, reconnect, empty output, catalog refresh, output truncation, stream
gap, credential expiry, and ambiguous action outcome. Tests assert semantic
reducer state and structured render events in addition to terminal-byte
snapshots.

### 19.4 CNF Experience Conformance

A CNF command module is conformant only when:

1. every visible command has summary, contextual help, typed arguments, effect,
   limits, and presentation;
2. a new operator can discover the command from the root `?` tree;
3. ordinary use requires no YANG/XPath knowledge;
4. empty, denied, partial, slow, and oversized results remain understandable;
5. the module passes authorization, audit, redaction, and terminal tests;
6. no config mutation is reachable;
7. examples execute against the CNF test fixture;
8. command output remains useful at 80, 120, and 160 columns.

### 19.5 Reader and Usability Tests

Before declaring the Phase 3 operational-actions gate complete,
representative packet-core operators who
did not implement the commands MUST be asked to perform tasks using only
login, `?`, tab completion, and `describe`. At minimum:

- identify whether an ePDG is healthy;
- find active major alarms;
- locate an IKE SA for a known peer;
- monitor a state transition;
- run a bounded ping;
- recognize and safely handle an authorization denial;
- exit without leaving credentials or a remote action ambiguous.

Observed confusion becomes a catalog/TUI defect, not operator-training debt by
default.

Each phase defines its task subset and a completion/error threshold before the
study begins. Failure blocks that phase's exit unless the RFC evidence records
an explicitly accepted known gap. At least one usability pass MUST cover the
append-only accessibility mode and one MUST cover the configured headless
login path. Accessibility evidence includes a screen-reader user or qualified
accessibility review rather than relying on snapshots alone.

### 19.6 Release Evidence

RFC 006 evidence includes:

- catalog schema and compatibility report;
- command-module conformance report per reference CNF;
- authentication-provider and broker security tests;
- terminal injection corpus results;
- parser/catalog fuzz summaries;
- pseudo-terminal UX snapshots;
- authorization/audit/redaction matrix;
- performance budgets for UI responsiveness and bounded memory;
- known gaps and unsupported terminal/provider profiles.

## 20. Delivery Plan

### Phase 1: Developer Preview and First-Class Read Console

- `opc-mgmt-command` model, validator, registry, and testkit;
- well-known console YANG catalog;
- production gNMI read client and authenticated catalog discovery;
- trusted management contexts;
- OIDC and OpenShift OAuth login-provider interfaces with a fake broker;
- the interactive Rust TUI delivered in the same phase;
- root help, tab completion, editing, safe history, tables, pager, JSON, status,
  `whoami`, reconnect, and cancellation;
- SDK-standard health, alarm, runtime, and config-application-status commands;
- ePDG read-only vertical slice.

Phase 1 is not complete if only the catalog or client crates exist. The TUI,
its conformance tests, and operator usability tasks for login, discovery,
health, alarms, denial, and exit are required deliverables. This phase is a
developer preview because the broker credential profile is not yet production.

### Phase 2: Production Read and Monitor MVP

- accepted and implemented RFC 003 management-user identity amendment;
- gNMI Subscribe and streaming renderer;
- NETCONF read fallback;
- production access broker and management-user credential profiles;
- credential refresh/rotation and logout;
- role-visible catalog refresh;
- `monitor alarms` and ePDG state-monitoring commands;
- terminal and authentication fault campaigns;
- operator usability tasks for headless login, stream gaps, reconnect, and
  accessible monitoring.

### Phase 3: Typed Diagnostics and Operational-Actions Gate

- `opc-mgmt-action` contracts;
- NETCONF action/RPC and registered operational-service adapters;
- bounded ping as the first probe action;
- confirmation and ambiguous-outcome UX;
- accepted/streaming action lifecycles;
- selected ePDG operational actions after security review;
- operator usability tasks for confirmation, cancellation, ambiguous outcome,
  and reattachment.

### Phase 4: Broader CNF and TUI Experience

- AMF, SMF, UPF, and additional ePDG command modules;
- optional full-screen dashboards and detail panes over the same catalog;
- signed environment distribution and approved credential-store adapters;
- one-shot automation using the exact command IDs and engine;
- broader cross-CNF vocabulary and usability refinement.

## 21. Alternatives Considered

### 21.1 Raw gNMI/NETCONF Tools

Rejected as the operator experience. They require paths, schemas, protocol
knowledge, and separate tools, and do not recreate a discoverable persistent
network-element session. They remain valuable engineering diagnostics.

### 21.2 Generate the Entire CLI from YANG

Rejected as the only command-design mechanism. YANG supplies types, paths, and
actions but does not by itself create concise task-oriented grammar, useful
tables, domain grouping, examples, or operator workflows. Generated fallback
inspection may be added for developers, but curated CNF commands are required.

### 21.3 CNF-Specific CLI Binaries

Rejected. They duplicate authentication, protocol, safety, terminal, and
authorization work and produce inconsistent operator experiences.

### 21.4 Remote Shell over SSH

Rejected. It creates arbitrary-code and container-access boundaries, weakens
schema validation and audit, and couples operational workflows to CNF process
internals.

### 21.5 Send Command Strings to a Generic Execute RPC

Rejected. It makes the remote parser an undocumented API, obscures typed
authorization paths, encourages shell-like injection, and prevents standard
gNMI/NETCONF interoperability.

### 21.6 Browser UI First

Rejected for this feature. Operators explicitly require the persistent terminal
workflow, discoverable command tree, low-friction keyboard navigation, and
jump-host compatibility. A browser UI may reuse the framework later.

### 21.7 OpenPacketCore-Owned Identity Store and Login Page

Rejected. The SDK integrates with the deployment's identity system. It does
not become another password, MFA, recovery, and user-lifecycle authority.

## 22. Open Design Decisions

The following decisions must be closed before their implementation phase:

| Decision | Owner/review | Must close before |
| :--- | :--- | :--- |
| Final binary and package name (`opc`, `opc-console`, or another unambiguous name) | SDK maintainers | Phase 1 packaging |
| Catalog wire encoding and maximum production limits | Management/schema and security reviewers | Phase 1 catalog implementation |
| Initial full-screen views beyond the required shell, pager, help, and streaming presentation | TUI owner and operator UX reviewers | Phase 4 full-screen implementation; not an MVP blocker |
| Exact management-user X.509 and SSH credential profiles and RFC 003 amendment | Security and identity maintainers | Phase 2 production credentials |
| Standalone production broker, existing-platform adapter, or both | Platform architecture and security | Phase 2 broker implementation |
| Approved persistent credential stores by OS and disconnected profile | Platform security | Any phase enabling persistent refresh credentials |

These decisions do not change the central architecture: trusted configurable
login, a declarative CNF command catalog, typed protocol operations, and a
first-class interactive TUI.

## 23. Acceptance Criteria

RFC 014 reaches full operational-actions implementation status when:

1. A reference ePDG publishes a validated catalog through the well-known model.
2. An operator can authenticate through at least one configurable human
   provider and reach a persistent authenticated prompt.
3. The operator can discover and run ePDG health, alarm, IKE SA, and peer-state
   reads without entering a YANG/XPath path.
4. `?`, tab completion, `describe`, paging, resize, cancellation, safe history,
   structured output, reconnect, and `whoami` pass pseudo-terminal tests.
5. The TUI remains responsive during slow login, catalog retrieval, reads,
   subscriptions, and connection loss.
6. Catalogs and outputs cannot inject terminal controls or exceed configured
   resource bounds.
7. All target operations pass authentication, NACM authorization, audit, and
   redaction checks.
8. No console command or raw escape hatch can mutate configuration.
9. A bounded ping action demonstrates typed probe execution without arbitrary
   remote command strings.
10. RFC 006 evidence records authentication, catalog, CNF experience, TUI,
    security, fuzzing, and performance results.

## 24. Summary

OpenPacketCore will provide operators with a modern version of the persistent
network-element shell: immediate, discoverable, keyboard-driven, and useful
without knowledge of management protocol paths. CNFs define their operational
vocabulary through typed declarative command modules. The SDK turns that
vocabulary into consistent help, completion, authorization, protocol requests,
safe presentation, and audit.

The design restores operational immediacy without restoring configuration
drift, arbitrary shell access, bespoke authentication, or per-CNF UI
fragmentation. The TUI is where these guarantees become a coherent operator
experience, so it is designed, tested, and shipped as a first-class component
from the first implementation phase.
