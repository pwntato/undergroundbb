import { randomBytes } from 'node:crypto'

import { expect, request, test, type BrowserContext, type Page } from '@playwright/test'

import { BASE_URL, TEST_ACCOUNT_HEADERS } from './env.ts'
import { logIn, logOut, newTestUser, signUp, spaNavigate, type TestUser } from './helpers.ts'

// The account-lifecycle flows, in the order a real account meets them: a cold-key tab, a password
// change, recovery with the code the change issued, then account deletion. One account walks all
// of it, so the specs are serial and share a page. If a step fails the later ones fail too, which
// is the honest signal; the account (and anything it still owns) is left for the scheduled purge.
test.describe.configure({ mode: 'serial' })

const original = newTestUser()
const changed: TestUser = {
  username: original.username,
  password: randomBytes(18).toString('base64url'),
}
const recovered: TestUser = {
  username: original.username,
  password: randomBytes(18).toString('base64url'),
}
const groupName = `zz-account-${original.username.slice(-10)}`

let context: BrowserContext
let page: Page
let recoveryCode = ''

/** Finishes the "Save your recovery code" step and returns the code it showed. */
async function acknowledgeRecoveryCode(p: Page): Promise<string> {
  const code = p.getByRole('textbox', { name: 'Your recovery code' })
  await expect(code).toBeVisible()
  const shown = (await code.textContent())?.trim() ?? ''
  expect(shown).not.toBe('')
  await p.getByLabel("I've saved this recovery code somewhere safe.").check()
  await p.getByRole('button', { name: 'Continue' }).click()
  return shown
}

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: TEST_ACCOUNT_HEADERS,
  })
  page = await context.newPage()
})

test.afterAll(async () => {
  await context.close()
})

test('signs up', async () => {
  recoveryCode = await signUp(page, original)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
})

test('after a page load the keys are cold: it asks for the password, then creates the group', async () => {
  // The session cookie outlives a page load but the keys live in the tab's worker and do not, so a
  // signed-in visitor with cold keys is asked for the password before anything that signs. A fresh
  // tab of the same context is one way to get there (a reload in the first tab is another).
  const tab = await context.newPage()
  await tab.goto('/groups/new')
  await expect(tab.getByRole('heading', { name: 'Confirm your password' })).toBeVisible()
  await tab.getByLabel('Username').fill(original.username)
  await tab.getByLabel('Password').fill(original.password)
  await tab.getByRole('button', { name: 'Continue' }).click()
  await expect(tab.getByRole('heading', { name: 'Create a group' })).toBeVisible()
  await tab.getByLabel('Name').fill(groupName)
  await tab.getByRole('button', { name: 'Create group' }).click()
  await expect(tab.getByText(groupName)).toBeVisible()
  await tab.close()
})

test('changes the password and is issued a new recovery code', async () => {
  // A copy of the session cookie, as an attacker holding a stolen session would have it.
  const stolen = (await context.cookies()).find((c) => c.name === 'ubb_session')
  expect(stolen).toBeDefined()
  await page.goto('/account/password')
  await page.getByLabel('Current password').fill(original.password)
  await page.getByLabel('New password', { exact: true }).fill(changed.password)
  await page.getByLabel('Confirm new password').fill(changed.password)
  await page.getByRole('button', { name: 'Continue' }).click()
  const issued = await acknowledgeRecoveryCode(page)
  expect(issued).not.toBe(recoveryCode)
  recoveryCode = issued
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()

  // The change ended every session that existed before it, so the copy is dead...
  const attacker = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { ...TEST_ACCOUNT_HEADERS, Cookie: `ubb_session=${stolen?.value ?? ''}` },
  })
  const copied = (await (await attacker.get('/api/auth/session')).json()) as {
    authenticated: boolean
  }
  expect(copied.authenticated).toBe(false)
  await attacker.dispose()
  // ...while the tab that made the change was reissued a working one.
  const own = (await (await context.request.get('/api/auth/session')).json()) as {
    authenticated: boolean
  }
  expect(own.authenticated).toBe(true)
})

test('the old password stops working and the new one logs in', async () => {
  await logOut(page)
  await logIn(page, original)
  await expect(page.getByText('Incorrect username or password.')).toBeVisible()
  await logIn(page, changed)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
  await expect(page.getByText(groupName)).toBeVisible()
})

test('recovers the account with the recovery code and sets a new password', async () => {
  await logOut(page)
  await page.goto('/recovery')
  await page.getByLabel('Username').fill(recovered.username)
  await page.getByLabel('Recovery code').fill(recoveryCode)
  await page.getByLabel('New password', { exact: true }).fill(recovered.password)
  await page.getByLabel('Confirm new password').fill(recovered.password)
  await page.getByRole('button', { name: 'Continue' }).click()
  recoveryCode = await acknowledgeRecoveryCode(page)
  await expect(page).toHaveURL(/\/login\?recoveryComplete=1$/)
  await logIn(page, recovered)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
  await expect(page.getByText(groupName)).toBeVisible()
})

test('deletes the account together with the group it alone owned', async () => {
  // In-app navigation keeps the keys warm; a page load would ask for the password first.
  await spaNavigate(page, '/account/delete')
  // The innermost block holding the heading is the panel that lists the groups to be deleted.
  const deleting = page
    .locator('div')
    .filter({ has: page.getByText('These groups will be deleted') })
    .last()
  await expect(deleting.getByRole('listitem')).toHaveText(groupName)
  await page.getByRole('button', { name: 'Delete my account' }).click()
  await page.getByRole('button', { name: 'Yes, delete my account' }).click()
  // Signed out lands on Home or, if a request races the logout, on /login; either is signed out.
  await expect(
    page.getByRole('link', { name: 'Log in' }).or(page.getByRole('heading', { name: 'Log in' })),
  ).toBeVisible()
  await logIn(page, recovered)
  await expect(page.getByText('Incorrect username or password.')).toBeVisible()
})
