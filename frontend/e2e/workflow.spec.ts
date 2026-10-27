import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

async function demoLogin(page: Page, role: "Analyst" | "Lead" | "Viewer") {
  await page.goto("/login");
  await page.getByRole("button", { name: role, exact: true }).click();
  await page.waitForURL(/\/dashboard/);
}

test("unauthenticated visitors are sent to login", async ({ page }) => {
  await page.goto("/incidents");
  await expect(page).toHaveURL(/\/login\?next=%2Fincidents/);
});

test("analyst works an incident: note, status change, timeline", async ({ page }) => {
  await demoLogin(page, "Analyst");
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();

  await page.getByRole("link", { name: "Incidents", exact: true }).click();
  await page.getByRole("link", { name: /Macro document led to encoded PowerShell/ }).click();
  await expect(page.getByRole("heading", { name: /INC-\d{4}/ })).toBeVisible();

  // Evidence is linked and explorable.
  await page.getByRole("tab", { name: "Evidence" }).click();
  await expect(page.getByText("Supporting events")).toBeVisible();

  // Add an analyst note.
  const note = `E2E note ${Date.now()}`;
  await page.getByRole("tab", { name: "Notes" }).click();
  await page.getByLabel("New note").fill(note);
  await page.getByRole("button", { name: "Add note" }).click();
  await expect(page.getByText(note)).toBeVisible();

  // Move the incident forward if it is still new.
  const start = page.getByRole("button", { name: "Start investigating" });
  if (await start.isVisible()) {
    await start.click();
    await page.getByRole("dialog").getByRole("button", { name: "Start investigating" }).click();
    await expect(page.getByText("Investigating").first()).toBeVisible();
  }

  await page.getByRole("tab", { name: "Timeline" }).click();
  await expect(page.getByText("Note added").first()).toBeVisible();
});

test("viewer cannot change incidents", async ({ page }) => {
  await demoLogin(page, "Viewer");
  await page.goto("/incidents");
  await expect(page.getByRole("button", { name: "New incident" })).toHaveCount(0);
});

test("alert explains its rule and evidence", async ({ page }) => {
  await demoLogin(page, "Analyst");
  await page.goto("/alerts");
  await page.locator("tbody tr a").first().click();
  await expect(page.getByText("Why this alert fired")).toBeVisible();
  await expect(page.getByText("Known false positives")).toBeVisible();
  await expect(page.getByText("Matching events")).toBeVisible();
});

for (const path of ["/dashboard", "/incidents", "/alerts", "/threat-intel", "/attack-coverage", "/settings"]) {
  test(`no serious accessibility violations on ${path}`, async ({ page }) => {
    await demoLogin(page, "Lead");
    await page.goto(path);
    await page.waitForLoadState("load");
    await page.waitForTimeout(1500);
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    const serious = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
    expect(serious.map((v) => `${v.id}: ${v.help} (${v.nodes.length})`)).toEqual([]);
  });
}
