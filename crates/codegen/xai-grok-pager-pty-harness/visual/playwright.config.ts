import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const chromiumExe = process.env.CHROMIUM_EXE ?? process.env.ORCA_CHROMIUM_EXECUTABLE;

if (process.env.ORCA_VISUAL_REQUIRE_BROWSER === "1") {
  if (!chromiumExe || !existsSync(chromiumExe)) {
    throw new Error(
      "CHROMIUM_EXE must be an absolute sealed Chromium path (no channel/PATH lookup)",
    );
  }
}

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["line"]],
  use: {
    headless: true,
    // Never use channel: 'chrome' — only explicit executablePath when provided.
    ...(chromiumExe
      ? {
          launchOptions: {
            executablePath: chromiumExe,
            args: [
              "--no-sandbox",
              "--disable-gpu",
              "--hide-scrollbars",
              "--force-color-profile=srgb",
            ],
          },
        }
      : {}),
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "dark",
    viewport: { width: 1240, height: 680 },
    deviceScaleFactor: 2,
  },
  projects: [
    {
      name: "chromium-pinned",
      use: {},
    },
  ],
});
