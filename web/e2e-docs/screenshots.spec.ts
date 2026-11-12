import { mkdirSync } from 'node:fs'
import { resolve } from 'node:path'

import { expect, test, type Page } from '@playwright/test'

import { signUpPerson, spaGo, type Person } from './docsHelpers.ts'

// Regenerates the screenshots in docs/images/ for docs/USER_GUIDE.md from a LOCAL app on an empty
// database. See docs/images/README.md for the exact steps. It is not part of CI and never runs
// against a deployment: it makes accounts with fixed names.

const OUT = resolve(process.cwd(), process.env['DOCS_IMAGES'] ?? '../docs/images')
mkdirSync(OUT, { recursive: true })

const alice: Person = { username: 'alice', password: 'correct horse battery staple 42' }
const bob: Person = { username: 'bob', password: 'another long passphrase 77' }

async function shot(page: Page, name: string): Promise<void> {
  // Let the layout settle and focus rings clear so the same screen always looks the same.
  await page.waitForTimeout(1200)
  await page.screenshot({ path: resolve(OUT, `${name}.png`) })
}

test('user guide screenshots', async ({ browser }) => {
  test.setTimeout(420_000)
  const size = { viewport: { width: 1100, height: 760 } }
  const a = await (await browser.newContext(size)).newPage()
  const b = await (await browser.newContext(size)).newPage()

  // Signing up.
  await a.goto('/signup')
  await a.getByLabel('Username').fill(alice.username)
  await a.getByLabel('Password', { exact: true }).fill(alice.password)
  await a.getByLabel('Confirm password').fill(alice.password)
  await shot(a, 'signup')
  await a.getByRole('button', { name: 'Continue' }).click()
  await expect(a.getByRole('textbox', { name: 'Your recovery code' })).toBeVisible()
  await shot(a, 'recovery-code')
  await a.getByLabel("I've saved this recovery code somewhere safe.").check()
  await a.getByRole('button', { name: 'Continue' }).click()
  await expect(a.getByRole('heading', { name: 'Pick a look' })).toBeVisible()
  await shot(a, 'pick-a-look')
  await a.getByRole('button', { name: 'Continue' }).click()
  await expect(a.getByText("You're not in any groups yet")).toBeVisible()
  await shot(a, 'home-empty')

  // A group, a post and a comment.
  await a.getByRole('link', { name: 'Create a group' }).first().click()
  await a.getByLabel('Name').fill('Book Club')
  await a.getByLabel('Description (optional)').fill('Monthly picks and arguments about them.')
  await shot(a, 'create-group')
  await a.getByRole('button', { name: 'Create group' }).click()
  await expect(a.getByRole('link', { name: 'Write a post' })).toBeVisible()
  await shot(a, 'home-group')

  await a.getByRole('link', { name: 'Write a post' }).click()
  await a.getByLabel('Title').fill('November pick: The Dispossessed')
  await a
    .getByLabel('Post', { exact: true })
    .fill('Ursula K. Le Guin, 1974. Chapters 1 to 4 for next time. Bring opinions about the wall.')
  await shot(a, 'new-post')
  await a.getByRole('button', { name: 'Post', exact: true }).click()
  await expect(a.getByText('Posted.')).toBeVisible()
  await a.getByRole('link', { name: 'Back to your groups' }).click()
  await a.getByRole('link', { name: 'Posts', exact: true }).first().click()
  await a.getByRole('link', { name: 'Comments' }).first().click()
  await a
    .getByLabel('Write the first comment')
    .fill('Chapter 1 had me at the wall. Who is it keeping out?')
  await a.getByRole('button', { name: 'Send' }).click()
  await expect(a.getByText('Comment sent.')).toBeVisible()
  await shot(a, 'post-thread')

  // An invite, accepted by a second person.
  await spaGo(a, '/')
  await a.getByRole('link', { name: 'Invite', exact: true }).click()
  await shot(a, 'invite-create')
  await a.getByRole('button', { name: 'Create invite' }).click()
  await expect(a.getByText('Invite created')).toBeVisible()
  await shot(a, 'invite-created')
  const link = new URL(await a.getByLabel('Invite link').inputValue())

  await signUpPerson(b, bob)
  await spaGo(b, link.pathname + link.hash)
  await expect(b.getByRole('button', { name: 'Accept invite' })).toBeVisible()
  await shot(b, 'invite-accept')
  await b.getByRole('button', { name: 'Accept invite' }).click()
  await expect(b.getByText("You're in")).toBeVisible()
  await shot(b, 'invite-accepted')

  // The inviter completes the invite the next time they log in.
  await a.getByRole('button', { name: 'Log out' }).click()
  await a.waitForURL('**/login')
  await shot(a, 'login')
  await a.getByLabel('Username').fill(alice.username)
  await a.getByLabel('Password').fill(alice.password)
  await a.getByRole('button', { name: 'Log in' }).click()
  await expect(a.getByRole('link', { name: 'Members', exact: true })).toBeVisible()
  await a.getByRole('link', { name: 'Members', exact: true }).first().click()
  await expect(a.getByText('Check fingerprint')).toBeVisible()
  await shot(a, 'members')
  await spaGo(a, '/')
  await a.getByRole('link', { name: 'Settings', exact: true }).first().click()
  await expect(a.getByRole('heading', { name: 'Edit settings' })).toBeVisible()
  await shot(a, 'group-settings')

  // The member's view, and the picker.
  await spaGo(b, '/')
  await expect(b.getByRole('link', { name: 'Posts', exact: true })).toBeVisible()
  await shot(b, 'home-member')
  await spaGo(a, '/appearance')
  await expect(a.getByRole('heading', { name: 'Appearance' })).toBeVisible()
  await shot(a, 'appearance')
})
