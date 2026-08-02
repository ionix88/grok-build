<div align="center">

# Orca (`orca`)

**Orca** is the terminal-based AI coding host. It runs as a full-screen TUI that
understands your codebase, edits files, executes shell commands, searches the
web, and manages long-running tasks — interactively, headlessly for scripting/CI,
or embedded in editors via the Agent Client Protocol (ACP).

[Installing](#installing) ·
[Building from source](#building-from-source) ·
[Documentation](#documentation) ·
[Repository layout](#repository-layout) ·
[Development](#development) ·
[Contributing](#contributing) ·
[License](#license)

</div>

---

## Installing

When release artifacts are published:

```sh
# see docs/INSTALL.md — installers place the public `orca` binary on PATH
orca --version
```

From a local build:

```sh
./scripts/install.sh          # macOS / Linux
# pwsh ./scripts/install.ps1  # Windows (best-effort; not an advertised target)
orca --version
```

The **only** public command is `orca`. There is no public `grok`, `orca-grok`,
or private-runtime command on PATH.

## Building from source

Requirements:

- **Rust** — pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (`1.92.0`).
- **[DotSlash](https://dotslash-cli.com)** — hermetic tools under [`bin/`](bin/)
  (notably [`bin/protoc`](bin/protoc)).
- **protoc** — via DotSlash, or `protoc` / `$PROTOC` on `PATH`.
- macOS and Linux are supported build hosts for this delivery.

```sh
cargo run -p xai-grok-pager-bin --locked              # build + launch TUI
cargo build -p xai-grok-pager-bin --release --locked  # target/release/orca
cargo check -p xai-grok-pager-bin --locked
```

The Cargo package remains `xai-grok-pager-bin` for provenance; the **public
binary artifact is `orca`**.

## Quick usage

```sh
orca --help
orca --version
orca                            # native interactive TUI
orca -p "explain this repo"     # headless single-turn
orca --agent explore            # persona selector (unchanged)
orca completions zsh
```

Built-in backend ID **`native`** is reserved. Backend selection flags arrive in
later tasks; `--agent` stays the persona selector.

## Documentation

| Doc | Path |
|-----|------|
| CLI | [`docs/CLI.md`](docs/CLI.md) |
| Install | [`docs/INSTALL.md`](docs/INSTALL.md) |
| Update | [`docs/UPDATE.md`](docs/UPDATE.md) |
| Completions | [`docs/COMPLETIONS.md`](docs/COMPLETIONS.md) |
| User guide (in-tree) | [`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/) |

## Repository layout

| Path | Role |
|------|------|
| `crates/codegen/xai-grok-pager-bin` | Composition root; builds public `orca` |
| `crates/codegen/xai-grok-pager` | TUI + clap CLI (`PUBLIC_CLI_NAME=orca`) |
| `crates/codegen/xai-grok-*` | Internal libraries (names retained) |
| `scripts/ci/todo-verify.sh` | `ORCA_QA` entry |
| `test/todo/*.json` | Frozen task QA records |
| `packaging/` | Homebrew / Scoop skeletons |

A small `SOURCE_REV` file at the root records the monorepo commit SHA for the
synced tree.

## Development

```sh
cargo test --locked -p xai-grok-pager -p xai-grok-pager-bin
cargo fmt --all -- --check
cargo clippy --locked -p xai-grok-pager -p xai-grok-pager-bin --all-targets -- -D warnings
```

Task QA:

```sh
export CARGO_EXE="$(command -v cargo)"
bash --noprofile --norc ./scripts/ci/todo-verify.sh --todo 2 --mode happy --out /tmp/orca-qa-happy
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). External PRs are not accepted.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
