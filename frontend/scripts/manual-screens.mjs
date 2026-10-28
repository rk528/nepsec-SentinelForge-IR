// Capture the screenshots used by docs/manual/endpoint-connection-manual.html.
//
// Run against a local stack seeded with synthetic data (never production):
//   BASE_URL=http://127.0.0.1:3005 SF_EMAIL=... SF_PASSWORD=... node scripts/manual-screens.mjs
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, "../../docs/manual/assets");
mkdirSync(out, { recursive: true });

const base = process.env.BASE_URL ?? "http://127.0.0.1:3005";
const email = process.env.SF_EMAIL;
const password = process.env.SF_PASSWORD;
const authAlert = process.env.SF_ALERT_ID; // the alert to show in detail
if (!email || !password) throw new Error("Set SF_EMAIL and SF_PASSWORD");
if (!/^http:\/\/(127\.0\.0\.1|localhost)/.test(base)) throw new Error("Screenshots are taken from a local, synthetic workspace only");

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
const context = await browser.newContext({ viewport: { width: 1680, height: 1000 }, deviceScaleFactor: 2, colorScheme: "light" });
await context.addInitScript(() => localStorage.setItem("sf.theme", "light"));
const page = await context.newPage();

async function shot(name, locator) {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(400);
  const path = resolve(out, `${name}.png`);
  // Whole pages are captured as the window, scrolled to the top, so the sticky header never covers content.
  if (locator) await locator.screenshot({ path, animations: "disabled" });
  else {
    // The content column only (no sidebar), from the top bar down to the end of the page content.
    await page.evaluate(() => window.scrollTo(0, 0));
    const box = await page.evaluate(() => {
      const main = document.querySelector("main");
      const column = main.parentElement.getBoundingClientRect();
      const last = [...main.querySelectorAll(":scope > *")].reduce((b, el) => Math.max(b, el.getBoundingClientRect().bottom), 0);
      return { x: column.left, width: column.width, height: Math.min(last + 32, window.innerHeight) };
    });
    await page.screenshot({ path, animations: "disabled", clip: { x: box.x, y: 0, width: box.width, height: box.height } });
  }
  console.log("saved", name);
}

await page.goto(`${base}/login`);
await page.getByLabel("Email").fill(email);
await page.getByLabel("Password").fill(password);
await page.getByRole("button", { name: "Sign in" }).click();
await page.waitForURL(/dashboard/);

// Data sources, as they look once machines report.
await page.goto(`${base}/settings`);
const sources = page.getByRole("region", { name: "Data sources" });
await sources.scrollIntoViewIfNeeded();
await shot("endpoint-sources", sources);

// Add a source for a new Ubuntu machine.
await sources.getByRole("button", { name: "Add source" }).click();
const dialog = page.getByRole("dialog");
await dialog.getByLabel("Name").fill("ubuntu-srv-02");
await dialog.getByLabel("Type").selectOption("linux");
await shot("endpoint-add-source", dialog);

// The one-time key dialog. The key is masked: even a throwaway local key never goes in a document.
await dialog.getByRole("button", { name: "Create and show key" }).click();
const keyDialog = page.getByRole("dialog", { name: "Ingest key created" });
await keyDialog.waitFor();
await keyDialog.getByLabel("Ingest key").evaluate((el) => {
  el.value = `${el.value.slice(0, 10)}••••••••••••••••••••••••••••••••`;
});
await shot("endpoint-key", keyDialog);
await keyDialog.getByRole("button", { name: "I have stored it" }).click();

// Events arriving from each kind of machine.
for (const [name, host] of [["endpoint-events-server", "ubuntu-srv-01"], ["endpoint-events-desktop", "ubuntu-desk-07"], ["endpoint-events-windows", "fin-ws-014"]]) {
  await page.goto(`${base}/events?host=${host}&hours=24`);
  await page.getByRole("table").first().waitFor();
  await shot(name);
}

// Alerts raised by the detections.
await page.goto(`${base}/alerts`);
await page.getByRole("table").first().waitFor();
await shot("endpoint-alerts");

if (authAlert) {
  await page.goto(`${base}/alerts/${authAlert}`);
  await page.getByRole("heading", { level: 1 }).first().waitFor();
  await shot("endpoint-alert-detail");
}

await browser.close();
