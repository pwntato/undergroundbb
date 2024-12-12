import { test, expect } from "@playwright/test";

function generateRandomString(length) {
  const characters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  result += characters.charAt(Math.floor(Math.random() * 26));
  result += characters.charAt(Math.floor(Math.random() * 26) + 26);
  result += characters.charAt(Math.floor(Math.random() * 10) + 52);
  for (let i = 3; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

test("signup and login", async ({ page }) => {
  const randomUsername = generateRandomString(8);
  const randomPassword = generateRandomString(12);

  // Navigate to signup page
  await page.goto("/signup");
  await page.fill('input[name="username"]', randomUsername);
  await page.fill('input[name="password"]', randomPassword);
  await page.fill('input[name="confirmPassword"]', randomPassword);
  await page.click('button[type="submit"]');

  // Verify redirection to login page
  await expect(page).toHaveURL("/login");

  // Login with new username and password
  await page.fill('input[name="username"]', randomUsername);
  await page.fill('input[name="password"]', randomPassword);
  await page.click('button[type="submit"]');

  // Verify login was successful
  await expect(page.locator("text=Logout")).toBeVisible();
});

/*
// TODO: make this create a new user each time first, then try to create the same user again
test("signup with existing username", async ({ page }) => {
  const existingUsername = "testuser";
  const randomPassword = generateRandomString(12);

  // Navigate to signup page
  await page.goto("/signup");
  await page.fill('input[name="username"]', existingUsername);
  await page.fill('input[name="password"]', randomPassword);
  await page.fill('input[name="confirmPassword"]', randomPassword);
  await page.click('button[type="submit"]');

  // Verify error message for existing username
  await expect(page.locator("text=Username is not available")).toBeVisible();
});
*/
