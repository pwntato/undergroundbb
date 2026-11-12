import { expect, type Page } from '@playwright/test'

export interface Person {
  readonly username: string
  readonly password: string
}

/** Signs up through the real UI (a local app, so no test-account header) and lands on Home. */
export async function signUpPerson(page: Page, who: Person): Promise<string> {
  await page.goto('/signup')
  await page.getByLabel('Username').fill(who.username)
  await page.getByLabel('Password', { exact: true }).fill(who.password)
  await page.getByLabel('Confirm password').fill(who.password)
  await page.getByRole('button', { name: 'Continue' }).click()
  const code = page.getByRole('textbox', { name: 'Your recovery code' })
  await expect(code).toBeVisible()
  const recoveryCode = (await code.textContent())?.trim() ?? ''
  await page.getByLabel("I've saved this recovery code somewhere safe.").check()
  await page.getByRole('button', { name: 'Continue' }).click()
  await expect(page.getByRole('heading', { name: 'Pick a look' })).toBeVisible()
  await page.getByRole('button', { name: 'Continue' }).click()
  return recoveryCode
}

export async function spaGo(page: Page, target: string): Promise<void> {
  await page.evaluate((t) => {
    history.pushState(null, '', t)
    dispatchEvent(new PopStateEvent('popstate'))
  }, target)
}
