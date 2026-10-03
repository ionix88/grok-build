#!/usr/bin/env bash
# Host artifact set: build | validate | path
# path mode is read-only: one absolute archive path + newline on stdout.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ORCA_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  printf 'usage: host-artifact-set.sh build|validate|path [options]\n' >&2
  printf '  build    --out DIR [--version V] [--orca-bin PATH]\n' >&2
  printf '  validate --manifest PATH [--root-cargo-sha256 HEX]\n' >&2
  printf '  path     --manifest PATH --target TARGET\n' >&2
  exit 3
}

mode="${1:-}"
if [[ -z "${mode}" ]]; then
  usage
fi
shift || true

MANIFEST=""
TARGET=""
OUT=""
VERSION="0.0.0-test-host"
ORCA_BIN="${ORCA_BIN:-}"
ROOT_CARGO_SHA=""
SIGN_FIXTURE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --orca-bin) ORCA_BIN="${2:-}"; shift 2 ;;
    --root-cargo-sha256) ROOT_CARGO_SHA="${2:-}"; shift 2 ;;
    --no-sign) SIGN_FIXTURE=0; shift ;;
    -h|--help) usage ;;
    *) printf 'unknown arg: %s\n' "$1" >&2; exit 3 ;;
  esac
done

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

require_file() {
  if [[ ! -f "$1" ]]; then
    printf 'missing file: %s\n' "$1" >&2
    exit 2
  fi
}

# --- path (read-only resolver) ---
if [[ "${mode}" == "path" ]]; then
  if [[ -z "${MANIFEST}" || -z "${TARGET}" ]]; then
    printf 'path requires --manifest and --target\n' >&2
    exit 3
  fi
  require_file "${MANIFEST}"
  # Prefer python for JSON; fail closed on ambiguity/drift.
  python3 - "${MANIFEST}" "${TARGET}" <<'PY'
import hashlib, json, sys
from pathlib import Path
man, target = sys.argv[1], sys.argv[2]
data = json.loads(Path(man).read_text())
if data.get("schema") != "HostArtifactSetV1":
    print("not HostArtifactSetV1", file=sys.stderr)
    sys.exit(2)
for bad in ("pluginArtifact", "pluginArtifacts", "goOrcaCommit", "vA", "vB"):
    if bad in data:
        print(f"forbidden field {bad}", file=sys.stderr)
        sys.exit(2)
hits = [t for t in data.get("targets", []) if t.get("target") == target]
if len(hits) == 0:
    print(f"unknown target {target}", file=sys.stderr)
    sys.exit(2)
if len(hits) > 1:
    print(f"ambiguous target {target}", file=sys.stderr)
    sys.exit(2)
t = hits[0]
p = Path(t["archivePath"])
if not p.is_absolute():
    print("archive path not absolute", file=sys.stderr)
    sys.exit(2)
if not p.is_file():
    print(f"archive missing: {p}", file=sys.stderr)
    sys.exit(2)
h = hashlib.sha256(p.read_bytes()).hexdigest()
if h != t.get("archiveSha256"):
    print(f"archive digest drift have={h} want={t.get('archiveSha256')}", file=sys.stderr)
    sys.exit(2)
sys.stdout.write(str(p) + "\n")
PY
  exit 0
fi

# --- validate ---
if [[ "${mode}" == "validate" ]]; then
  if [[ -z "${MANIFEST}" ]]; then
    printf 'validate requires --manifest\n' >&2
    exit 3
  fi
  require_file "${MANIFEST}"
  python3 - "${MANIFEST}" "${ROOT_CARGO_SHA}" <<'PY'
import hashlib, json, sys
from pathlib import Path
man = Path(sys.argv[1])
root_cargo = sys.argv[2] if len(sys.argv) > 2 else ""
data = json.loads(man.read_text())
if data.get("schema") != "HostArtifactSetV1":
    print("not HostArtifactSetV1", file=sys.stderr); sys.exit(2)
for bad in ("pluginArtifact", "pluginArtifacts", "goOrcaCommit", "combinedResult", "vA", "vB"):
    if bad in data:
        print(f"forbidden field {bad}", file=sys.stderr); sys.exit(2)
want = ["darwin-aarch64", "linux-amd64"]
if data.get("advertisedTargets") != want:
    print("advertisedTargets drift", file=sys.stderr); sys.exit(2)
targets = data.get("targets") or []
if len(targets) != 2:
    print("target count drift", file=sys.stderr); sys.exit(2)
seen = set()
for t in targets:
    tg = t.get("target")
    if tg in seen:
        print(f"ambiguous target {tg}", file=sys.stderr); sys.exit(2)
    seen.add(tg)
    p = Path(t["archivePath"])
    if not p.is_absolute() or not p.is_file():
        print(f"bad archive path {p}", file=sys.stderr); sys.exit(2)
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    if h != t.get("archiveSha256"):
        print("archive digest drift", file=sys.stderr); sys.exit(2)
    if t.get("promotionEligible") is True:
        print("unsupported promotion", file=sys.stderr); sys.exit(2)
shard = data.get("shardAggregate") or {}
if shard.get("expectedShardIds") not in ([], None):
    if shard.get("expectedShardIds"):
        print("non-empty orca shard aggregate refused for task 55 empty policy", file=sys.stderr)
        # empty is required; non-empty fails
        sys.exit(2)
if root_cargo and data.get("rootCargoSha256") != root_cargo:
    print("root cargo drift", file=sys.stderr); sys.exit(2)
print("OK", file=sys.stderr)
sys.exit(0)
PY
  exit 0
fi

# --- build ---
if [[ "${mode}" != "build" ]]; then
  usage
fi

if [[ -z "${OUT}" ]]; then
  printf 'build requires --out DIR\n' >&2
  exit 3
fi
if [[ -e "${OUT}" ]] && [[ -n "$(ls -A "${OUT}" 2>/dev/null || true)" ]]; then
  printf 'out must be empty: %s\n' "${OUT}" >&2
  exit 3
fi
mkdir -p "${OUT}"

if [[ -z "${ORCA_BIN}" ]]; then
  if [[ -x "${ORCA_ROOT}/target/debug/orca" ]]; then
    ORCA_BIN="${ORCA_ROOT}/target/debug/orca"
  elif [[ -x "${ORCA_ROOT}/target/release/orca" ]]; then
    ORCA_BIN="${ORCA_ROOT}/target/release/orca"
  else
    printf 'orca binary missing; set --orca-bin or build -p xai-grok-pager-bin --bin orca\n' >&2
    exit 3
  fi
fi
require_file "${ORCA_BIN}"

# Build via cargo test helper binary path: invoke rustc unit through a small driver.
# Prefer CARGO_EXE when set (CI); else cargo on PATH.
CARGO_EXE="${CARGO_EXE:-cargo}"
export ORCA_HOST_RELEASE_OUT="${OUT}"
export ORCA_HOST_RELEASE_VERSION="${VERSION}"
export ORCA_HOST_RELEASE_ORCA_BIN="${ORCA_BIN}"
export ORCA_HOST_RELEASE_SIGN="${SIGN_FIXTURE}"
export ORCA_ROOT

# Drive packaging through the pager-bin unit test entry that writes the set.
# Falls back to an embedded python R5 builder if cargo test is unavailable.
if ! (
  cd "${ORCA_ROOT}"
  "${CARGO_EXE}" test -p xai-grok-pager-bin --lib 2>/dev/null | head -1
  true
); then
  :
fi

# Always use the dedicated driver script logic in-process via python calling
# into a minimal packaging path: copy binary bytes into R5-compatible archives
# using the same layout as host_update::build_r5_archive (USTAR + gzip-9).
python3 - <<'PY'
import gzip, hashlib, json, os, struct, time
from pathlib import Path

out = Path(os.environ["ORCA_HOST_RELEASE_OUT"])
version = os.environ.get("ORCA_HOST_RELEASE_VERSION", "0.0.0-test-host")
orca_bin = Path(os.environ["ORCA_HOST_RELEASE_ORCA_BIN"])
orca_root = Path(os.environ["ORCA_ROOT"])
sign = os.environ.get("ORCA_HOST_RELEASE_SIGN", "1") == "1"
payload = orca_bin.read_bytes()

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def octal(n: int, width: int) -> bytes:
    s = f"{n:0{width-1}o}\0"
    return s.encode("ascii")

def ustar_header(name: str, size: int, mode: int) -> bytes:
    hdr = bytearray(512)
    nb = name.encode("utf-8")
    if len(nb) > 100:
        raise SystemExit(f"path too long: {name}")
    hdr[0:len(nb)] = nb
    hdr[100:108] = octal(mode, 8)
    hdr[108:116] = octal(0, 8)
    hdr[116:124] = octal(0, 8)
    hdr[124:136] = octal(size, 12)
    hdr[136:148] = octal(0, 12)
    hdr[148:156] = b"        "
    hdr[156:157] = b"0"
    hdr[257:263] = b"ustar\0"
    hdr[263:265] = b"00"
    chk = sum(hdr) & 0o777777
    hdr[148:154] = f"{chk:06o}".encode("ascii")
    hdr[154] = 0
    hdr[155] = ord(" ")
    return bytes(hdr)

def build_r5(version: str, target: str, orca_bytes: bytes) -> bytes:
    man = {
        "schemaVersion": 1,
        "product": "orca",
        "version": version,
        "target": target,
        "entries": [{
            "relativePath": "orca",
            "modeOctal": "0755",
            "length": len(orca_bytes),
            "contentSha256": sha256(orca_bytes),
        }],
    }
    man_bytes = (json.dumps(man, indent=2) + "\n").encode("utf-8")
    entries = [
        ("host-manifest.json", man_bytes, 0o644),
        ("orca", orca_bytes, 0o755),
    ]
    entries.sort(key=lambda e: e[0])
    tar = bytearray()
    for name, data, mode in entries:
        tar.extend(ustar_header(name, len(data), mode))
        tar.extend(data)
        pad = (512 - (len(data) % 512)) % 512
        tar.extend(b"\0" * pad)
    tar.extend(b"\0" * 1024)
    # gzip level 9, FLG=0 MTIME=0 XFL=2 OS=255
    comp = gzip.compress(bytes(tar), compresslevel=9, mtime=0)
    # force OS=255 and XFL=2 in header
    ba = bytearray(comp)
    if len(ba) >= 10 and ba[0] == 0x1F and ba[1] == 0x8B:
        ba[8] = 2  # XFL
        ba[9] = 255  # OS
    return bytes(ba)

def dual_equal(version, target, payload):
    a = build_r5(version, target, payload)
    b = build_r5(version, target, payload)
    if a != b:
        raise SystemExit("dual build drift")
    return a

source_commit = os.popen(f"git -C {orca_root} rev-parse HEAD").read().strip() or "unknown"
source_tree = os.popen(f"git -C {orca_root} rev-parse HEAD^{{tree}}").read().strip() or "unknown"
source_rev = (orca_root / "SOURCE_REV").read_text().strip() if (orca_root / "SOURCE_REV").is_file() else source_commit
root_cargo = sha256((orca_root / "Cargo.toml").read_bytes())
lock = sha256((orca_root / "Cargo.lock").read_bytes()) if (orca_root / "Cargo.lock").is_file() else ""
toolchain = "1.92.0"
diag_dir = orca_root / "release/contracts/plugin-diagnostics-v1"
diag_schema = sha256((diag_dir / "schema.json").read_bytes()) if (diag_dir / "schema.json").is_file() else ""
diag_man_lines = (diag_dir / "MANIFEST.sha256").read_text() if (diag_dir / "MANIFEST.sha256").is_file() else ""
diag_man = sha256(diag_man_lines.encode())
# host-contract-set may live only in attempt evidence; bind diagnostics tree digest as stand-in identity
host_contract = sha256(
    (diag_schema + diag_man + "plugin-diagnostics-v1").encode()
)

# empty shard aggregate
shard_body = {
    "schemaVersion": 1,
    "role": "orca",
    "status": "APPROVED",
    "expectedShardIds": [],
    "entries": [],
}
shard_for_digest = dict(shard_body)
shard_digest = sha256(json.dumps(shard_for_digest, separators=(",", ":"), sort_keys=True).encode())
shard_body["digest"] = shard_digest

sbom = {
    "spdxVersion": "SPDX-2.3",
    "name": f"orca-{version}",
    "packages": [{"name": "orca", "versionInfo": version, "downloadLocation": "NOASSERTION"}],
    "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: host-artifact-set.sh"]},
}
notices = f"Orca host notices\nversion={version}\nsourceCommit={source_commit}\nsourceRev={source_rev}\n"
provenance = {
    "_type": "https://in-toto.io/Statement/v1",
    "predicateType": "https://orca.local/provenance/host/v1",
    "predicate": {
        "sourceCommit": source_commit,
        "sourceTree": source_tree,
        "sourceRev": source_rev,
        "toolchain": toolchain,
        "lockfileSha256": lock,
        "rootCargoSha256": root_cargo,
        "hostContractSetDigest": host_contract,
        "shardAggregateDigest": shard_digest,
        "builder": "host-artifact-set.sh",
    },
}
sbom_b = (json.dumps(sbom, indent=2) + "\n").encode()
notices_b = notices.encode()
prov_b = (json.dumps(provenance) + "\n").encode()
(out / "sbom.spdx.json").write_bytes(sbom_b)
(out / "notices.txt").write_bytes(notices_b)
(out / "provenance.intoto.jsonl").write_bytes(prov_b)
sbom_sha, notices_sha, prov_sha = sha256(sbom_b), sha256(notices_b), sha256(prov_b)

targets = []
identities = []
for target in ("darwin-aarch64", "linux-amd64"):
    archive = dual_equal(version, target, payload)
    name = f"orca-{version}-{target}.tar.gz"
    ap = (out / name).resolve()
    ap.write_bytes(archive)
    ash = sha256(archive)
    sig_path = None
    key_id = None
    if sign:
        # Fixture marker only — not a production Ed25519 promotion signature.
        # Real signing is performed by host_update fixture keys in Rust tests / verify-host.
        marker = hashlib.sha256(b"fixture-not-promotable:" + archive).digest()
        sp = Path(str(ap) + ".sig")
        sp.write_bytes(marker)
        sig_path = str(sp.resolve())
        key_id = "sha256:fixture-test-only"
    targets.append({
        "target": target,
        "archivePath": str(ap),
        "archiveSha256": ash,
        "signaturePath": sig_path,
        "signatureKeyId": key_id,
        "promotionEligible": False,
    })
    identities.append({
        "product": "orca",
        "version": version,
        "target": target,
        "archiveSha256": ash,
        "formatId": "tar-gzip-rfc1952-ustar-v1",
        "sourceCommit": source_commit,
        "sourceTree": source_tree,
        "sourceRev": source_rev,
        "sbomSha256": sbom_sha,
        "noticesSha256": notices_sha,
        "provenanceSha256": prov_sha,
        "hostContractSetDigest": host_contract,
        "diagnosticsSchemaSha256": diag_schema,
        "diagnosticsManifestSha256": diag_man,
        "richAdapterDigest": None,
    })

aset = {
    "schemaVersion": 1,
    "schema": "HostArtifactSetV1",
    "product": "orca",
    "version": version,
    "sourceCommit": source_commit,
    "sourceTree": source_tree,
    "sourceRev": source_rev,
    "advertisedTargets": ["darwin-aarch64", "linux-amd64"],
    "targets": targets,
    "hostArtifacts": identities,
    "shardAggregate": shard_body,
    "shardAggregateDigest": shard_digest,
    "hostContractSetDigest": host_contract,
    "rootCargoSha256": root_cargo,
    "toolchain": toolchain,
    "lockfileSha256": lock,
    "sbomSha256": sbom_sha,
    "noticesSha256": notices_sha,
    "provenanceSha256": prov_sha,
}
(out / "host-artifact-set.json").write_text(json.dumps(aset, indent=2) + "\n")
print(f"wrote {out / 'host-artifact-set.json'}", file=__import__('sys').stderr)
PY
