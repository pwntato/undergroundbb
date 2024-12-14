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

async function createGroup(page, groupName, groupDescription) {
  await page.goto("/create-group");
  await page.goto("/create-group");
  await page.fill('input[name="name"]', groupName);
  await page.fill('textarea[name="description"]', groupDescription);
  await page.click('button[type="submit"]');

  // Verify that the group has been created and is selected
  await expect(page).toHaveURL(/\/group\/[a-f0-9-]+/);
  const url = page.url();
  const groupUuidMatch = url.match(/\/group\/([a-f0-9-]+)/);
  const groupUuid = groupUuidMatch ? groupUuidMatch[1] : null;
  await expect(page.locator("h1")).toHaveText(groupName);
  await expect(page.locator(`text="${groupDescription}"`)).toBeVisible();

  return { groupUuid };
}

async function createPost(page, postTitle, postBody) {
  await page.click('text="Create Post"');
  await page.fill('input[name="title"]', postTitle);
  await page.fill('textarea[name="body"]', postBody);
  await page.click('button:has-text("Create Post")');

  // Verify the post was created
  await expect(page.locator(`text="${postTitle}"`)).toBeVisible();
}

module.exports = {
  generateRandomString,
  signUp,
  login,
  logout,
  createGroup,
  createPost,
};
