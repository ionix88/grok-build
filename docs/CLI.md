# Orca CLI

The sole public command is **`orca`**.

## Identity

| Surface | Value |
|---------|-------|
| Public binary | `orca` |
| Clap product name | `orca` |
| Built-in backend ID | `native` (reserved; selection is a later task) |
| Internal crates | `xai-grok-*` (unchanged provenance) |

## Common invocations

```sh
orca --help
orca --version
orca                      # native interactive TUI
orca -p "summarize README.md"   # headless single-turn
orca --agent explore      # persona/agent selector (unchanged)
orca completions zsh      # shell completions
```

## Flags that stay stable

- **`--agent <NAME>`** — agent/persona selector or definition file path. Not a backend selector.
- **`-p` / `--single` / `--print`** — headless single-turn prompt.
- Bare `orca` with no subcommand — native TUI launch path.

## Forbidden public names

These must never appear as the public CLI product:

- `grok` (legacy public header)
- `orca-grok`
- `go-orca` / `go-orcad` (private plugin runtimes; receipt-bound absolute paths only)
- wrappers or PATH shims that re-export a second public command
