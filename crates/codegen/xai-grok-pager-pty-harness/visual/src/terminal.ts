import type { ReadinessEvent } from "./protocol.ts";

export type TerminalRenderConfig = {
  readonly cols: number;
  readonly rows: number;
  readonly fontSize: number;
  readonly fontFamily: string;
};

export type TerminalPageHooks = {
  readonly onReadiness: (event: ReadinessEvent) => void;
};

export function buildTerminalHtml(cfg: TerminalRenderConfig): string {
  const { cols, rows, fontSize, fontFamily } = cfg;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>orca-visual-harness</title>
<link rel="stylesheet" href="./terminal.css"/>
<style>
  @font-face {
    font-family: 'JetBrains Mono Harness';
    src: local('JetBrains Mono'), local('Menlo');
    font-display: block;
  }
  html, body { margin: 0; padding: 0; background: #0b0e14; }
  #t { padding: 8px; }
</style>
</head>
<body>
<div id="t"></div>
<script type="module">
import { Terminal } from '@xterm/xterm';
const term = new Terminal({
  cols: ${cols},
  rows: ${rows},
  fontSize: ${fontSize},
  fontFamily: ${JSON.stringify(fontFamily)},
  allowProposedApi: true,
  convertEol: false,
  scrollback: 0,
  theme: { background: '#0b0e14', foreground: '#d7dae0' },
});
term.open(document.getElementById('t'));
window.__term = term;
window.__writeToTerm = (d) => new Promise((resolve) => {
  term.write(d, () => {
    window.__readiness && window.__readiness('xterm-write');
    resolve();
  });
});
window.__screenText = () => {
  const b = term.buffer.active;
  const lines = [];
  for (let i = 0; i < b.length; i++) {
    const ln = b.getLine(i);
    lines.push(ln ? ln.translateToString(true) : '');
  }
  return lines.join('\\n').replace(/\\n+$/, '\\n');
};
window.__waitFonts = async () => {
  if (document.fonts && document.fonts.ready) await document.fonts.ready;
  window.__readiness && window.__readiness('webfont-ready');
};
window.__stableFrame = () => new Promise((resolve) => {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    window.__readiness && window.__readiness('stable-frame');
    resolve();
  }));
});
term.focus();
window.__readiness && window.__readiness('browser-lifecycle');
</script>
</body>
</html>`;
}

export const DEFAULT_FONT_FAMILY =
  '"JetBrains Mono Harness", "JetBrains Mono", Menlo, "DejaVu Sans Mono", monospace';
