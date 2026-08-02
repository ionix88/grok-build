#!/usr/bin/env bash
# Local/dev installer skeleton for the public `orca` binary.
# Production CDN URLs are release-owned; this script installs a built artifact.
set -euo pipefail

ORCA_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BIN_DIR="${ORCA_BIN_DIR:-${HOME}/.orca/bin}"
mkdir -p "${BIN_DIR}"

CANDIDATES=(
  "${ORCA_ROOT}/target/release/orca"
  "${ORCA_ROOT}/target/debug/orca"
)

SRC=""
for c in "${CANDIDATES[@]}"; do
  if [[ -x "${c}" ]]; then
    SRC="${c}"
    break
  fi
done

if [[ -z "${SRC}" ]]; then
  printf 'error: build orca first: cargo build -p xai-grok-pager-bin --release --locked\n' >&2
  exit 1
fi

install -m 0755 "${SRC}" "${BIN_DIR}/orca"
printf 'Installed %s -> %s/orca\n' "${SRC}" "${BIN_DIR}"
printf 'Ensure %s is on PATH, then run: orca --version\n' "${BIN_DIR}"
