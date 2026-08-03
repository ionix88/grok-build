import type { ExpectedRegion, SemanticSnapshot } from "./protocol.ts";
import { normalizeRegionText } from "./protocol.ts";

export function extractRegions(
  screenText: string,
  expected: readonly ExpectedRegion[],
): readonly [string, string][] {
  const normalizedScreen = normalizeRegionText(screenText);
  const out: [string, string][] = [];
  for (const region of expected) {
    const needle = normalizeRegionText(region.text);
    if (!normalizedScreen.includes(needle)) {
      throw new Error(`SEMANTIC_REGION_MISSING: ${region.id} (${needle})`);
    }
    out.push([region.id, needle]);
  }
  return out;
}

export function snapshotsEqual(a: SemanticSnapshot, b: SemanticSnapshot): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
