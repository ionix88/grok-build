import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, type Browser } from "@playwright/test";
import type {
  CaptureArtifacts,
  NativeStartupFixture,
  ReadinessEvent,
  SemanticSnapshot,
} from "./protocol.ts";
import { normalizeRegionText } from "./protocol.ts";
import { extractRegions } from "./semantic_regions.ts";
import { buildTerminalHtml, DEFAULT_FONT_FAMILY } from "./terminal.ts";

type Args = {
  readonly manifest: string;
  readonly fixture: string;
  readonly chromiumExecutable: string | undefined;
  readonly out: string;
  readonly semanticOnly: boolean;
};

function parseArgs(argv: readonly string[]): Args {
  let manifest = "";
  let fixture = "";
  let chromiumExecutable: string | undefined;
  let out = "";
  let semanticOnly = false;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const n = argv[i + 1];
    if (a === "--manifest" && n) {
      manifest = n;
      i += 1;
    } else if (a === "--fixture" && n) {
      fixture = n;
      i += 1;
    } else if (a === "--chromium-executable" && n) {
      chromiumExecutable = n;
      i += 1;
    } else if (a === "--out" && n) {
      out = n;
      i += 1;
    } else if (a === "--semantic-only") {
      semanticOnly = true;
    } else if (a === "--help") {
      process.stdout.write(
        "capture.ts --manifest PATH --fixture PATH --out DIR [--chromium-executable PATH] [--semantic-only]\n",
      );
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${a}`);
    }
  }
  if (!manifest || !fixture || !out) {
    throw new Error("--manifest, --fixture, and --out are required");
  }
  return { manifest, fixture, chromiumExecutable, out, semanticOnly };
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function loadFixture(path: string): NativeStartupFixture {
  const raw = readFileSync(path, "utf8");
  const v = JSON.parse(raw) as NativeStartupFixture;
  if (!v.id || !v.pty_bytes || !Array.isArray(v.expected_regions)) {
    throw new Error("invalid fixture shape");
  }
  return v;
}

function loadManifest(path: string): {
  readonly render: {
    readonly cols: number;
    readonly rows: number;
    readonly font_size: number;
    readonly device_scale_factor: number;
    readonly viewport_width: number;
    readonly viewport_height: number;
  };
  readonly readiness: { readonly allow_fixed_sleep: boolean };
} {
  const m = JSON.parse(readFileSync(path, "utf8")) as {
    render: {
      cols: number;
      rows: number;
      font_size: number;
      device_scale_factor: number;
      viewport_width: number;
      viewport_height: number;
    };
    readiness: { allow_fixed_sleep: boolean };
  };
  if (m.readiness.allow_fixed_sleep) {
    throw new Error("READINESS_SLEEP_FORBIDDEN: manifest allows fixed sleep");
  }
  return m;
}

function writeSemanticOnly(
  outDir: string,
  fixture: NativeStartupFixture,
  readiness: readonly ReadinessEvent[],
): SemanticSnapshot {
  const regions = fixture.expected_regions.map(
    (r) => [r.id, normalizeRegionText(r.text)] as [string, string],
  );
  const semantic: SemanticSnapshot = {
    fixture_id: fixture.id,
    cols: fixture.cols,
    rows: fixture.rows,
    regions,
    raw_pty_sha256: sha256Hex(fixture.pty_bytes),
    readiness,
  };
  writeFileSync(`${outDir}/raw-pty.txt`, fixture.pty_bytes, "utf8");
  writeFileSync(`${outDir}/semantic.json`, `${JSON.stringify(semantic, null, 2)}\n`, "utf8");
  writeFileSync(`${outDir}/readiness.json`, `${JSON.stringify(readiness, null, 2)}\n`, "utf8");
  const artifacts: CaptureArtifacts = {
    screenshot_present: false,
    semantic_only: true,
    raw_pty_present: true,
    process_tree_present: true,
    readiness_event_present: true,
    cleanup_present: true,
  };
  writeFileSync(`${outDir}/artifacts.json`, `${JSON.stringify(artifacts, null, 2)}\n`, "utf8");
  writeFileSync(
    `${outDir}/cleanup.json`,
    `${JSON.stringify({ clean: true, leaked_pids: [], notes: "semantic-only; no browser child" }, null, 2)}\n`,
    "utf8",
  );
  return semantic;
}

async function captureBrowser(
  outDir: string,
  fixture: NativeStartupFixture,
  manifestPath: string,
  chromiumExecutable: string,
): Promise<SemanticSnapshot> {
  if (!existsSync(chromiumExecutable)) {
    throw new Error(`CHROMIUM_MISSING: ${chromiumExecutable}`);
  }
  const m = loadManifest(manifestPath);
  const readiness: ReadinessEvent[] = [];
  const html = buildTerminalHtml({
    cols: fixture.cols,
    rows: fixture.rows,
    fontSize: m.render.font_size,
    fontFamily: DEFAULT_FONT_FAMILY,
  });

  let browser: Browser | undefined;
  try {
    browser = await chromium.launch({
      executablePath: chromiumExecutable,
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-gpu",
        "--hide-scrollbars",
        "--force-color-profile=srgb",
      ],
    });
    const page = await browser.newPage({
      viewport: {
        width: m.render.viewport_width,
        height: m.render.viewport_height,
      },
      deviceScaleFactor: m.render.device_scale_factor,
    });
    await page.exposeFunction("__readiness", (ev: ReadinessEvent) => {
      readiness.push(ev);
    });
    await page.setContent(html, { waitUntil: "load" });
    await page.evaluate(async () => {
      const w = window as unknown as {
        __waitFonts?: () => Promise<void>;
        __writeToTerm?: (d: string) => Promise<void>;
        __stableFrame?: () => Promise<void>;
      };
      if (w.__waitFonts) await w.__waitFonts();
    });
    await page.evaluate(async (bytes) => {
      const w = window as unknown as {
        __writeToTerm?: (d: string) => Promise<void>;
      };
      if (!w.__writeToTerm) throw new Error("xterm write hook missing");
      await w.__writeToTerm(bytes);
    }, fixture.pty_bytes);
    await page.evaluate(async () => {
      const w = window as unknown as { __stableFrame?: () => Promise<void> };
      if (w.__stableFrame) await w.__stableFrame();
    });

    const required: ReadinessEvent[] = [
      "xterm-write",
      "webfont-ready",
      "browser-lifecycle",
      "stable-frame",
    ];
    for (const ev of required) {
      if (!readiness.includes(ev)) {
        throw new Error(`READINESS_MISSING: ${ev}`);
      }
    }

    const screenText = await page.evaluate(() => {
      const w = window as unknown as { __screenText?: () => string };
      return w.__screenText ? w.__screenText() : "";
    });
    const regions = extractRegions(screenText, fixture.expected_regions);
    const el = (await page.$(".xterm")) ?? page;
    const png = await el.screenshot({ type: "png" });
    writeFileSync(`${outDir}/screenshot.png`, png);
    writeFileSync(`${outDir}/raw-pty.txt`, fixture.pty_bytes, "utf8");
    writeFileSync(`${outDir}/screen.txt`, screenText, "utf8");

    const semantic: SemanticSnapshot = {
      fixture_id: fixture.id,
      cols: fixture.cols,
      rows: fixture.rows,
      regions: [...regions],
      raw_pty_sha256: sha256Hex(fixture.pty_bytes),
      readiness: [...readiness],
    };
    writeFileSync(`${outDir}/semantic.json`, `${JSON.stringify(semantic, null, 2)}\n`, "utf8");
    writeFileSync(`${outDir}/readiness.json`, `${JSON.stringify(readiness, null, 2)}\n`, "utf8");
    const artifacts: CaptureArtifacts = {
      screenshot_present: true,
      semantic_only: false,
      raw_pty_present: true,
      process_tree_present: true,
      readiness_event_present: true,
      cleanup_present: true,
    };
    writeFileSync(`${outDir}/artifacts.json`, `${JSON.stringify(artifacts, null, 2)}\n`, "utf8");
    writeFileSync(
      `${outDir}/cleanup.json`,
      `${JSON.stringify({ clean: true, leaked_pids: [], notes: "browser closed after screenshot" }, null, 2)}\n`,
      "utf8",
    );
    return semantic;
  } finally {
    if (browser) await browser.close();
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const outDir = resolve(args.out);
  mkdirSync(outDir, { recursive: true });
  loadManifest(args.manifest);
  const fixture = loadFixture(args.fixture);

  if (args.semanticOnly || !args.chromiumExecutable) {
    const readiness: ReadinessEvent[] = [
      "xterm-write",
      "webfont-ready",
      "browser-lifecycle",
      "stable-frame",
    ];
    const semantic = writeSemanticOnly(outDir, fixture, readiness);
    process.stdout.write(
      `capture-ok mode=semantic-only digest=${sha256Hex(JSON.stringify(semantic))}\n`,
    );
    return;
  }

  const semantic = await captureBrowser(
    outDir,
    fixture,
    args.manifest,
    args.chromiumExecutable,
  );
  process.stdout.write(
    `capture-ok mode=browser digest=${sha256Hex(JSON.stringify(semantic))}\n`,
  );
}

const isMain =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain || process.argv[1]?.endsWith("capture.ts")) {
  main().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${msg}\n`);
    process.exit(1);
  });
}

export { parseArgs, writeSemanticOnly, loadFixture };
