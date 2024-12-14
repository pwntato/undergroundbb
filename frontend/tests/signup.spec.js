import { test } from "@playwright/test";
const { signUp, login, logout } = require("./helpers");

test("signup and login", async ({ page }) => {
  const { username, password } = await signUp(page);

  await login(page, username, password);

  await logout(page);
});