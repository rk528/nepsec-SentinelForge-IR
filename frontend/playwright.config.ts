import { defineConfig } from "@playwright/test";

// End-to-end tests run against a running frontend (BASE_URL) whose backend has the
// synthetic demo seeded with DEMO_MODE=true. Locally they use the installed Chrome;
// CI sets PW_CHANNEL="" to use Playwright's bundled Chromium.
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.BASE_URL ?? "http://127.0.0.1:3000",
    channel: process.env.PW_CHANNEL ?? "chrome",
    viewport: { width: 1440, height: 900 },
    colorScheme: "dark",
    trace: "retain-on-failure",
  },
});
