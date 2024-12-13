import { test, expect } from "@playwright/test";
const {
  signUp,
  login,
  logout,
  generateRandomString,
  createGroup,
} = require("./helpers");

test("main smoke test", async ({ page }) => {
  const currentTime = new Date().toLocaleTimeString();

  const { username, password } = await signUp(page);

  await login(page, username, password);

  const groupName = `Test Group ${generateRandomString(8)}  ${currentTime}`;
  const groupDescription = "This is a test group";
  await createGroup(page, groupName, groupDescription);

  // Admin buttons are visible
  await expect(page.locator('text="Create Post"')).toBeVisible();
  await expect(page.locator('text="Invite User"')).toBeVisible();
  await expect(page.locator('text="Edit Group"')).toBeVisible();

  await logout(page);
});
