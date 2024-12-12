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

async function signUp(page, username = generateRandomString(8), password = generateRandomString(12)) {
  // Navigate to signup page
  await page.goto("/signup");
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.fill('input[name="confirmPassword"]', password);
  await page.click('button[type="submit"]');

  // Verify redirection to login page
  await expect(page).toHaveURL("/login");

  return { username, password };
}

test("signup and login", async ({ page }) => {
  const { username, password } = await signUp(page);

  // Login with new username and password
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');

  // Verify login was successful
  await expect(page.locator("text=Logout")).toBeVisible();
});
