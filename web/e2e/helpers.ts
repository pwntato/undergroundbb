import { randomBytes } from 'node:crypto'

import { expect, type Page } from '@playwright/test'

export interface TestUser {
  readonly username: string
  readonly password: string
}

// A fresh account per run, never stored anywhere. The reserved prefix is what lets the
// server accept it as a test account and the purge find it (3-32 chars: [A-Za-z0-9_-]).
export function newTestUser(): TestUser {
  return {
    username: `zz-delete-test-${randomBytes(5).toString('hex')}`,
    password: randomBytes(18).toString('base64url'),
  }
}

/** Signs up through the real UI and leaves the page on the signed-in Home screen. */
export async function signUp(page: Page, user: TestUser): Promise<string> {
  await page.goto('/signup')
  await page.getByLabel('Username').fill(user.username)
  await page.getByLabel('Password', { exact: true }).fill(user.password)
  await page.getByLabel('Confirm password').fill(user.password)
  await page.getByRole('button', { name: 'Continue' }).click()

  // Key generation and the post-signup login happen before the recovery code appears.
  const code = page.getByRole('textbox', { name: 'Your recovery code' })
  await expect(code).toBeVisible()
  const recoveryCode = (await code.textContent())?.trim() ?? ''
  expect(recoveryCode).not.toBe('')

  await page.getByLabel("I've saved this recovery code somewhere safe.").check()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Skip for now' }).click()
  return recoveryCode
}

/**
 * Logs out from Home and waits until the app shows the signed-out state. Navigating away before
 * the logout request finishes aborts it, leaves the session alive, and makes /login bounce back
 * to Home, so every logout has to be waited out.
 */
export async function logOut(page: Page): Promise<void> {
  await page.goto('/')
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page.getByRole('link', { name: 'Log in' })).toBeVisible()
}

export async function logIn(page: Page, user: TestUser): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Username').fill(user.username)
  await page.getByLabel('Password').fill(user.password)
  await page.getByRole('button', { name: 'Log in' }).click()
}

/**
 * Navigates inside the running app without a page load. A full load (page.goto) drops the
 * in-memory keys, and an invite link's fragment carries the key that authenticates it, so the
 * invite screens must be reached this way once signed in.
 */
export async function spaNavigate(page: Page, pathAndHash: string): Promise<void> {
  await page.evaluate((target) => {
    history.pushState(null, '', target)
    dispatchEvent(new PopStateEvent('popstate'))
  }, pathAndHash)
}
