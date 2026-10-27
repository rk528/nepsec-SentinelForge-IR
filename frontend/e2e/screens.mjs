// Ad-hoc screenshot helper for local visual review (not part of CI).
// Usage: node e2e/screens.mjs <outDir> <path> [<path> ...]
import { chromium } from "@playwright/test";

const [, , outDir, ...paths] = process.argv;
const base = process.env.BASE_URL ?? "http://127.0.0.1:3000";
const role = process.env.DEMO_ROLE ?? "lead";
const width = Number(process.env.VW ?? 1440);
const height = Number(process.env.VH ?? 900);

const browser = await chromium.launch({ channel: "chrome" });
const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1, colorScheme: "dark" });
const page = await context.newPage();
await page.goto(`${base}/login`);
await page.getByRole("button", { name: new RegExp(`^${role}$`, "i") }).click();
await page.waitForURL(/dashboard/);
for (const p of paths) {
  await page.goto(`${base}${p}`);
  await page.waitForLoadState("load");
  await page.waitForTimeout(Number(process.env.WAIT ?? 2500));
  const name = p.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "") || "root";
  await page.screenshot({ path: `${outDir}/${name}.png`, fullPage: process.env.FULL === "1" });
  console.log("saved", name);
}
await browser.close();
