# Orca fork delta

Orca is an independent Git root. Upstream GrokBuild history is recorded only as
a pin (`SOURCE_REV` and the source-sync pin commit/tree), never as a gitlink or
submodule edge.

## Ownership

| Surface | Owner |
| --- | --- |
| Public CLI/TUI (`orca`) | Orca |
| Host update / R5 archives | Orca (Task 16 + Task 55) |
| Host doctor renderer | Orca (Task 55) |
| Plugin runtime / private routes | Go-Orca (separate root) |
| Released contracts | Byte-identical copies under each root (Task 7) |

## Delta policy

1. Replay ordered patches with `SourceSyncReportV1` (see `GROK_SOURCE_SYNC.md`).
2. Root `Cargo.toml` is never modified by source-sync.
3. Generated `Cargo.toml` drift fails closed.
4. Conflicts produce a deterministic report; they never auto-merge or promote.
5. Host packaging binds the live Orca source commit/tree and empty Orca shard aggregate only.

## Non-goals

- No Go-Orca source, artifacts, or Task-53 outputs in host results.
- No combined `ArtifactVerificationResultV1` from the host packager.
- No OMO upstream queries from host release.
