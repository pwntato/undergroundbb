import { expect } from "@playwright/test";

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

async function signUp(
  page,
  username = generateRandomString(8),
  password = generateRandomString(12)
) {
  await page.goto("/signup");
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.fill('input[name="confirmPassword"]', password);
  await page.click('button[type="submit"]');

  await expect(page).toHaveURL("/login");

  return { username, password };
}

async function login(page, username, password) {
  await page.goto("/login");
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');

  await expect(page.locator("text=Logout")).toBeVisible();
}

async function logout(page) {
  await page.click('button:text("Logout")');
  await expect(page.locator("text=Login")).toBeVisible();
}

module.exports = { generateRandomString, signUp, login, logout };
