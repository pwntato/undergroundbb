import { expect, test, type BrowserContext, type Page } from '@playwright/test'

import { BASE_URL, TEST_ACCOUNT_HEADERS } from './env.ts'
import { logIn, newTestUser, signUp, spaNavigate } from './helpers.ts'

// One account walks the main flows in order, so the specs are serial and share a page. The
// account is left for the scheduled purge (cmd/purge) to delete.
test.describe.configure({ mode: 'serial' })

const user = newTestUser()
const invitee = newTestUser()
const groupName = `zz-smoke-${user.username.slice(-10)}`

let context: BrowserContext
let page: Page
let inviteeContext: BrowserContext
let inviteePage: Page
let inviteLink = ''

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: TEST_ACCOUNT_HEADERS,
  })
  page = await context.newPage()
  // A second browser context is a second user: its own cookie jar and its own key worker.
  inviteeContext = await browser.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: TEST_ACCOUNT_HEADERS,
  })
  inviteePage = await inviteeContext.newPage()
})

test.afterAll(async () => {
  await context.close()
  await inviteeContext.close()
})

test('the API rejects an unauthenticated user lookup', async ({ request }) => {
  const res = await request.post('/api/users:batch', { data: { ids: [] } })
  expect(res.status()).toBe(401)
})

test('signs up and lands signed in', async () => {
  await signUp(page, user)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Create a group' })).toBeVisible()
})

test('creates a group and lists it', async () => {
  await page.getByRole('link', { name: 'Create a group' }).click()
  await page.getByLabel('Name').fill(groupName)
  await page.getByRole('button', { name: 'Create group' }).click()
  await expect(page.getByText(groupName)).toBeVisible()
})

test('the members page asks users:batch for the roster and gets real usernames back', async () => {
  const lookup = page.waitForResponse(
    (r) => r.url().endsWith('/api/users:batch') && r.request().method() === 'POST',
  )
  await page.getByRole('link', { name: 'Members' }).click()
  const res = await lookup
  expect(res.status()).toBe(200)
  const body = (await res.json()) as { users: { username: string }[] }
  expect(body.users.map((u) => u.username)).toContain(user.username)
})

test('the members page shows the username, not the short id', async () => {
  // #204: the roster once showed the short id (8e227a44) although users:batch had resolved the name.
  await expect(page.getByRole('listitem').getByText(user.username)).toBeVisible()
})

test('logs out, logs back in, and still has the group', async () => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page.getByRole('link', { name: 'Log in' })).toBeVisible()

  await logIn(page, user)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
  await expect(page.getByText(groupName)).toBeVisible()
  await expect(page.getByText('admin', { exact: true })).toBeVisible()
})

test('creates an invite link for the group', async () => {
  await page.getByRole('link', { name: 'Invite', exact: true }).click()
  await page.getByRole('button', { name: 'Create invite' }).click()
  const link = page.getByLabel('Invite link')
  await expect(link).toBeVisible()
  inviteLink = await link.inputValue()
  expect(new URL(inviteLink).pathname).toMatch(/^\/invites\/[0-9a-f-]{36}$/)
  expect(new URL(inviteLink).hash).not.toBe('')
})

test('a second user signs up and accepts the invite', async () => {
  await signUp(inviteePage, invitee)
  const target = new URL(inviteLink)
  await spaNavigate(inviteePage, target.pathname + target.hash)
  await expect(inviteePage.getByRole('heading', { name: "You've been invited" })).toBeVisible()
  await inviteePage.getByRole('button', { name: 'Accept invite' }).click()
  await expect(inviteePage.getByRole('heading', { name: "You're in" })).toBeVisible()
})

test('the inviter logs in again and the new member is on the roster', async () => {
  // The group key reaches the invitee the next time the inviter logs in.
  await page.goto('/')
  await page.getByRole('button', { name: 'Log out' }).click()
  await logIn(page, user)
  await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible()
  await page.getByRole('link', { name: 'Members' }).click()
  const row = page.getByRole('listitem').filter({ hasText: invitee.username })
  await expect(row).toBeVisible()
  await expect(row).toContainText('Member')
})

test('the invitee sees the group after logging in', async () => {
  await inviteePage.goto('/')
  await inviteePage.getByRole('button', { name: 'Log out' }).click()
  await logIn(inviteePage, invitee)
  await expect(inviteePage.getByRole('button', { name: 'Log out' })).toBeVisible()
  await expect(inviteePage.getByText(groupName)).toBeVisible()
  await expect(inviteePage.getByText('member', { exact: true })).toBeVisible()
})
