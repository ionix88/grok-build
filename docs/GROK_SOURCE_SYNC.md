# Grok source synchronization

Deterministic, fail-closed replay of ordered patches against a pinned upstream
revision. Implemented as `SourceSyncReportV1` in the host release packager.

## Pin

- `SOURCE_REV` at the Orca root records the monorepo commit SHA used as provenance.
- Live packaging also binds `git rev-parse HEAD` and `HEAD^{tree}` of the Orca root.

## Replay algorithm

1. Load pin commit + tree.
2. Apply patches in order against an in-memory path → bytes map.
3. Each patch may declare `expectedBaseSha256`; mismatch → conflict row.
4. `REPLACE\n` bodies fully replace the path; other bodies append a replay marker.
5. Any patch targeting root `Cargo.toml` aborts with root-Cargo mutation.
6. Paths containing both `Cargo.toml` and `generated` set `generatedCargoDrift`.
7. Emit `SourceSyncReportV1` with self-omitted `reportDigest` (SHA-256 of the report without that field).

## Status

| Status | Meaning | Promotion |
| --- | --- | --- |
| `clean` | All patches applied; root Cargo unchanged | Allowed for local packaging |
| `conflict` | One or more base mismatches / missing bases | Fail closed |
| `generatedCargoDrift` | Generated Cargo touched | Fail closed |

## Conflict report

Conflicts are retained as evidence. Rollback of host artifacts never deletes
conflict reports. Operators resolve conflicts with a new ordered patch set and
re-run packaging.

## Isolation

Source-sync runs only on Orca paths. Go-Orca roots, plugin archives, and Task-53
outputs are denied inputs.
