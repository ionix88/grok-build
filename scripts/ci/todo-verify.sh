#!/usr/bin/env bash
# ORCA_QA entrypoint. Invoke only as:
#   $BASH_EXE --noprofile --norc "$ORCA_ROOT/scripts/ci/todo-verify.sh" \
#     --todo N --mode happy|failure --out DIR
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ORCA_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"

if [[ -z "${CARGO_EXE:-}" ]]; then
  printf 'setup: CARGO_EXE must be set to an absolute cargo executable\n' >&2
  exit 3
fi
if [[ ! -x "${CARGO_EXE}" ]]; then
  printf 'setup: CARGO_EXE is not executable: %s\n' "${CARGO_EXE}" >&2
  exit 3
fi

BIN_DEBUG="${ORCA_ROOT}/target/debug/orca-todo-verify"
BIN_RELEASE="${ORCA_ROOT}/target/release/orca-todo-verify"

if [[ -x "${BIN_DEBUG}" ]]; then
  exec "${BIN_DEBUG}" "$@"
fi
if [[ -x "${BIN_RELEASE}" ]]; then
  exec "${BIN_RELEASE}" "$@"
fi

exec "${CARGO_EXE}" run --locked \
  --manifest-path "${ORCA_ROOT}/Cargo.toml" \
  -p xai-grok-pager-bin \
  --bin orca-todo-verify \
  -- "$@"
