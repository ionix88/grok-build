import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "@playwright/test";
import { loadFixture, writeSemanticOnly } from "../src/capture.ts";
import type { ReadinessEvent, SemanticSnapshot } from "../src/protocol.ts";
import { snapshotsEqual } from "../src/semantic_regions.ts";

const here = dirname(fileURLToPath(import.meta.url));
const visualRoot = join(here, "..");
const fixturePath = join(visualRoot, "fixtures/native-startup.json");

test("duplicate semantic captures are equal", () => {
  const fixture = loadFixture(fixturePath);
  const readiness: ReadinessEvent[] = [
    "xterm-write",
    "webfont-ready",
    "browser-lifecycle",
    "stable-frame",
  ];
  const aDir = mkdtempSync(join(tmpdir(), "orca-vis-a-"));
  const bDir = mkdtempSync(join(tmpdir(), "orca-vis-b-"));
  try {
    const a = writeSemanticOnly(aDir, fixture, readiness);
    const b = writeSemanticOnly(bDir, fixture, readiness);
    expect(snapshotsEqual(a, b)).toBe(true);
    const da = createHash("sha256").update(JSON.stringify(a)).digest("hex");
    const db = createHash("sha256").update(JSON.stringify(b)).digest("hex");
    expect(da).toBe(db);
  } finally {
    rmSync(aDir, { recursive: true, force: true });
    rmSync(bDir, { recursive: true, force: true });
  }
});

test("manifest forbids fixed sleep readiness", () => {
  const m = JSON.parse(
    readFileSync(join(visualRoot, "harness-manifest.lock.json"), "utf8"),
  ) as { readiness: { allow_fixed_sleep: boolean } };
  expect(m.readiness.allow_fixed_sleep).toBe(false);
});

test("fixture regions are stable", () => {
  const fixture = loadFixture(fixturePath);
  expect(fixture.id).toBe("native-startup");
  expect(fixture.expected_regions.map((r) => r.id)).toEqual([
    "title",
    "status",
    "backend",
  ]);
  const semantic: SemanticSnapshot = {
    fixture_id: fixture.id,
    cols: fixture.cols,
    rows: fixture.rows,
    regions: fixture.expected_regions.map((r) => [r.id, r.text]),
    raw_pty_sha256: createHash("sha256").update(fixture.pty_bytes).digest("hex"),
    readiness: ["xterm-write", "webfont-ready", "browser-lifecycle", "stable-frame"],
  };
  expect(semantic.regions.length).toBe(3);
});
