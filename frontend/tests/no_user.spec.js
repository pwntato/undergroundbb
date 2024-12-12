import { test, expect } from "@playwright/test";

test("homepage has title", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveTitle(/UndergroundBB/);
});

test("login page", async ({ page }) => {
  await page.goto("/login");
  await page.fill('input[name="username"]', "invaliduser");
  await page.fill('input[name="password"]', "wrongpassword");
  await page.click('button[type="submit"]');
  await expect(page.locator("text=Invalid username or password")).toBeVisible();
});
