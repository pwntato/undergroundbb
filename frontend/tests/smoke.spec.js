import { test, expect } from "@playwright/test";
const { signUp, login, logout, generateRandomString } = require("./helpers");

test("main smoke test", async ({ page }) => {
  const currentTime = new Date().toLocaleTimeString();

  const { username, password } = await signUp(page);

  await login(page, username, password);

  // Create a new group
  await page.goto("/create-group");
  const groupName = `Test Group ${generateRandomString(8)}  ${currentTime}`;
  const groupDescription = "This is a test group";
  await page.fill('input[name="name"]', groupName);
  await page.fill('textarea[name="description"]', groupDescription);
  await page.click('button[type="submit"]');

  // Verify that the group has been created and is selected
  await expect(page).toHaveURL(/\/group\/[a-f0-9-]+/);
  await expect(page.locator("h1")).toHaveText(groupName);
  await expect(page.locator(`text="${groupDescription}"`)).toBeVisible();

  await logout(page);
});
