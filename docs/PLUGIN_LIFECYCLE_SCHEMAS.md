# Plugin lifecycle and compatibility receipts (frozen)

Task 6 freezes host-owned schemas for install inventory, trust, activation,
logical defaults, session pins, descriptor identity, host barriers, provision
gates, cohort holds, purge plan/arming/intent/fence/entry completion, rollback,
and GC. Implementation lives under
`crates/codegen/xai-grok-pager/src/plugin_host/{receipts,lifecycle,canonical}.rs`
with fixtures in `plugin_host/fixtures/`.

## Canonical digests

- Preimage is sorted-key compact JSON (no whitespace).
- Self-digest fields (`*Digest`) are omitted from their own preimage.
- Digest is lowercase SHA-256 hex (64 chars).

## Install / registry

| Type | Role |
| --- | --- |
| `InstallReceiptV1` | Immutable version+archive inventory + trust |
| `ActivationPointerV1` | New-session activation (no mutable `current`) |
| `LogicalDefaultV1` | `{backendId, versionPolicy:"followActivation"}` only |
| `RegistryDocumentV2` | Side-by-side receipts + activation + defaults |
| `RegistryV1MigrationPreview` | Preview-only v1 content import; never fabricates native receipts |

Same `pluginId@version` with different `archiveSha256` is a typed conflict.

## Session pins

`SessionPinV1` is a closed discriminator:

- `NativeV1` — `backendId="native"`, host/native session identities only. Plugin
  fields are forbidden.
- `ExternalV1` — `Creating|Active` with creation key, request digest, receipt,
  cohort, extension schema, renderer contract, nullable-then-final ACP session ID.

## Host barrier

`HostBarrierV1.writer` is always `Host`. The host is the sole external barrier
writer. States: `Absent`, `Provisioning`, `ProvisionFailed`, `Open` (concrete
identities required), `PreparedStartupGate`, `CommitArmed`,
`DestructivePurgeFence`, `Completed`.

## Purge algebra

1. Members sorted ascending by `cohortKey`.
2. Entries canonical bottom-up (deeper first, path ascending, files before dirs);
   unique depth-zero root is last.
3. Deleting journal: `Ready → IntentCommitted` (intent before unlink) →
   `DeletionObserved` → completion durable → cursor advance.
4. Completion must precede cursor advance; absence without matching intent fails closed.

## Rollback / GC

- `RollbackReceiptV1` changes new-session activation only; never moves pins.
- `GcPlanV1` lists unreferenced payloads / completed staging only.

## Fixtures

See `src/plugin_host/fixtures/` for canonical transition and negative samples.
