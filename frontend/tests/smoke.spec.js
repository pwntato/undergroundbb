import { test, expect } from "@playwright/test";
const {
  signUp,
  login,
  logout,
  generateRandomString,
  createGroup,
  createPost,
  inviteUserToGroup,
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

  const postTitle = "Test Post Title";
  const postBody = "This is the body of the test post.";
  await createPost(page, postTitle, postBody);

  // Go to the post page and verify the post is visible
  await page.click(`text="${postTitle}"`);
  await expect(page.locator(`text="${postTitle}"`)).toBeVisible();
  await expect(page.locator(`text="${postBody}"`)).toBeVisible();

  await inviteUserToGroup(page, groupUuid, memberUsername);
  
  await logout(page);

  await login(page, memberUsername, memberPassword);

  // Go to the group page
  await page.goto(`/group/${groupUuid}`);

  // Verify the group name
  await expect(page.locator("h1")).toHaveText(groupName);

  // Only member buttons are visible
  await expect(page.locator('text="Create Post"')).toBeVisible();
  await expect(page.locator('text="Invite User"')).toBeHidden();
  await expect(page.locator('text="Edit Group"')).toBeHidden();

  // Verify the post is visible
  await expect(page.locator(`text="${postTitle}"`)).toBeVisible();

  // Go to the post page and verify the post is visible
  await page.click(`text="${postTitle}"`);
  await expect(page.locator(`text="${postTitle}"`)).toBeVisible();
  await expect(page.locator(`text="${postBody}"`)).toBeVisible();
});
