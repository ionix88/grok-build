# Installing Orca

## Released binary (when published)

```sh
curl -fsSL https://example.invalid/orca/install.sh | bash   # macOS / Linux
# Windows PowerShell (when published):
# irm https://example.invalid/orca/install.ps1 | iex
orca --version
```

Installers place the `orca` binary on your `PATH`. No second public command is installed.

## Build from source

Requirements: Rust toolchain from [`rust-toolchain.toml`](../rust-toolchain.toml) (1.92.0), DotSlash for hermetic `bin/protoc`, and a C toolchain.

```sh
cargo build -p xai-grok-pager-bin --release --locked
# artifact: target/release/orca
./target/release/orca --version
```

## Supported hosts (this delivery)

Advertised targets: `darwin-aarch64` and `linux-amd64`. Windows schemas may compile; no Windows support claim is made here.
