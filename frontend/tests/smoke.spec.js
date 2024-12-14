import { test, expect } from "@playwright/test";
const {
  signUp,
  login,
  logout,
  generateRandomString,
  createGroup,
  createPost,
} = require("./helpers");

test("main smoke test", async ({ page }) => {
  const currentTime = new Date().toLocaleTimeString();

  // create a member user to interact with the group
  const { username: memberUsername, password: memberPassword } = await signUp(
    page
  );
  await login(page, memberUsername, memberPassword);
  await logout(page);

  // create an admin user to create the group
  const { username: adminUsername, password: adminPassword } = await signUp(
    page
  );

  await login(page, adminUsername, adminPassword);

  const groupName = `Test Group ${generateRandomString(8)}  ${currentTime}`;
  const groupDescription = "This is a test group";
  const { groupUuid } = await createGroup(page, groupName, groupDescription);

  // Admin buttons are visible
  await expect(page.locator('text="Create Post"')).toBeVisible();
  await expect(page.locator('text="Invite User"')).toBeVisible();
  await expect(page.locator('text="Edit Group"')).toBeVisible();

  // Create a post
  const postTitle = "Test Post Title";
  const postBody = "This is the body of the test post.";
  await createPost(page, postTitle, postBody);

  // Go to the post page
  await page.click(`text="${postTitle}"`);
  await expect(page.locator(`text="${postTitle}"`)).toBeVisible();
  await expect(page.locator(`text="${postBody}"`)).toBeVisible();

  // invite user
  await page.goto(`/group/${groupUuid}`);
  await page.click('text="Invite User"');
  await page.fill('input[name="username"]', memberUsername);
  await page.click('text="Invite"');

  // Verify member user is in group
  await page.goto(`/group/${groupUuid}`);
  await page.click('text="Edit Group"');
  await expect(page.locator(`text="${memberUsername}"`)).toBeVisible();
  
  await logout(page);
});
