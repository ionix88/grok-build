export type ReadinessEvent =
  | "xterm-write"
  | "webfont-ready"
  | "browser-lifecycle"
  | "stable-frame";

export type ExpectedRegion = {
  readonly id: string;
  readonly text: string;
};

export type NativeStartupFixture = {
  readonly id: string;
  readonly cols: number;
  readonly rows: number;
  readonly pty_bytes: string;
  readonly expected_regions: readonly ExpectedRegion[];
};

export type SemanticSnapshot = {
  readonly fixture_id: string;
  readonly cols: number;
  readonly rows: number;
  readonly regions: readonly [string, string][];
  readonly raw_pty_sha256: string;
  readonly readiness: readonly ReadinessEvent[];
};

export type CaptureArtifacts = {
  readonly screenshot_present: boolean;
  readonly semantic_only: boolean;
  readonly raw_pty_present: boolean;
  readonly process_tree_present: boolean;
  readonly readiness_event_present: boolean;
  readonly cleanup_present: boolean;
};

export function assertNever(x: never): never {
  throw new Error(`unexpected variant: ${String(x)}`);
}

export function normalizeRegionText(s: string): string {
  return s
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "")
    .split(/\s+/)
    .filter(Boolean)
    .join(" ");
}
