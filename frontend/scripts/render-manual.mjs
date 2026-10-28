// Render a manual in docs/manual from HTML to an A4 PDF with page numbers.
//   node scripts/render-manual.mjs endpoint-connection-manual.html SentinelForge-IR-Endpoint-Connection-Manual.pdf
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { chromium } from "@playwright/test";

const [source, target] = process.argv.slice(2);
if (!source || !target) throw new Error("Usage: render-manual.mjs <html in docs/manual> <pdf name>");
const dir = resolve(dirname(fileURLToPath(import.meta.url)), "../../docs/manual");

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
const page = await browser.newPage();
await page.goto(pathToFileURL(resolve(dir, source)).href, { waitUntil: "networkidle" });
const title = await page.title();
await page.pdf({
  path: resolve(dir, target),
  format: "A4",
  preferCSSPageSize: true,
  printBackground: true,
  displayHeaderFooter: true,
  headerTemplate: "<span></span>",
  footerTemplate: `<div style="width:100%;font:8px 'Segoe UI',Arial,sans-serif;color:#71717a;padding:0 16mm;display:flex;justify-content:space-between"><span>${title.replace(/</g, "&lt;")}</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
});
await browser.close();
console.log("wrote", target);
