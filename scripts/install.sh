#!/usr/bin/env bash
# Local/dev installer for the public `orca` binary into an independent host bin root.
set -euo pipefail
ORCA_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BIN_DIR="${ORCA_BIN_DIR:-${HOME}/.orca/bin}"
mkdir -p "${BIN_DIR}"
CANDIDATES=("${ORCA_ROOT}/target/release/orca" "${ORCA_ROOT}/target/debug/orca")
SRC=""
for c in "${CANDIDATES[@]}"; do
  if [[ -x "${c}" ]]; then SRC="${c}"; break; fi
done
if [[ -z "${SRC}" ]]; then
  printf 'error: build orca first: cargo build -p xai-grok-pager-bin --release --locked\n' >&2
  exit 1
fi
tmp="${BIN_DIR}/.orca.tmp.$$"
install -m 0755 "${SRC}" "${tmp}"
mv -f "${tmp}" "${BIN_DIR}/orca"
printf 'Installed %s -> %s/orca\n' "${SRC}" "${BIN_DIR}"
printf 'Host update: orca update --check | orca update --to <archive.tar.gz>\n'
printf 'Ensure %s is on PATH\n' "${BIN_DIR}"
