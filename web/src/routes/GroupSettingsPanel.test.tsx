// Markup tests for GroupSettingsPanel (renderToStaticMarkup, per
// GroupList.test.tsx's reasoning) and validateSettingsForm.

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { GroupDetail } from '@/lib/api/groups'
import { GroupSettingsPanel } from './GroupSettingsPanel'
import { REVOCATION_TEXT, validateSettingsForm } from './groupSettingsForm'
import type { SettingsView } from './runGroupSettings'

function detail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: 'g1',
    visibility: 'public',
    role: 'member',
    generation: 0,
    nameGeneration: 0,
    namePlaintext: 'Book Club',
    descriptionPlaintext: 'We read books',
    revocationMode: 'rotating',
    expirationDays: 30,
    version: 1,
    ...overrides,
  }
}

function render(view: SettingsView): string {
  return renderToStaticMarkup(
    createElement(GroupSettingsPanel, {
      view,
      onSave: () => undefined,
      saving: false,
      message: null,
      error: null,
    }),
  )
}

const publicView = (d: GroupDetail): SettingsView => ({
  detail: d,
  name: 'Book Club',
  description: 'We read books',
  nameStatus: 'plaintext',
})

describe('GroupSettingsPanel', () => {
  it('shows name, expiration and revocation mode to a plain member, with no edit form', () => {
    const html = render(publicView(detail()))
    expect(html).toContain('Book Club')
    expect(html).toContain('Messages expire after 30 days.')
    expect(html).toContain('Rotating: removing a member re-keys the group.')
    expect(html).not.toContain('Edit settings')
  })

  it('always spells out what Open means', () => {
    const html = render(publicView(detail({ revocationMode: 'open', role: 'admin' })))
    expect(html).toContain('Open: removing a member only revokes their access.')
    expect(html).toContain('keeps the group key')
  })

  it('shows the edit form to an admin, but never a control for revocation mode', () => {
    const html = render(publicView(detail({ role: 'admin' })))
    expect(html).toContain('Edit settings')
    expect(html).toContain('id="settings-name"')
    expect(html).not.toMatch(/type="radio"/)
    expect(html).not.toMatch(/name="revocationMode"/)
  })

  it('shows no form to a non-member viewing a public group', () => {
    expect(render(publicView(detail({ role: '' })))).not.toContain('Edit settings')
  })

  it('shows "never expire" and a login hint for a cold-keys private admin, with no form', () => {
    const html = render({
      detail: detail({ visibility: 'private', role: 'admin', expirationDays: 0 }),
      name: null,
      description: null,
      nameStatus: 'coldKeys',
    })
    expect(html).toContain('Messages never expire.')
    expect(html).toContain('Log in again')
    expect(html).not.toContain('Edit settings')
  })

  it('contains no em dashes in its copy', () => {
    expect(render(publicView(detail({ role: 'admin' })))).not.toContain('—')
    expect(Object.values(REVOCATION_TEXT).join('')).not.toContain('—')
  })
})

describe('validateSettingsForm', () => {
  const ok = { name: 'A', description: '', expirationDays: 30 }
  it('accepts a normal form and never-expire (0)', () => {
    expect(validateSettingsForm(ok)).toBeNull()
    expect(validateSettingsForm({ ...ok, expirationDays: 0 })).toBeNull()
  })
  it.each([
    [{ name: '   ' }],
    [{ name: 'x'.repeat(201) }],
    [{ description: 'x'.repeat(2001) }],
    [{ expirationDays: -1 }],
    [{ expirationDays: 3651 }],
    [{ expirationDays: 1.5 }],
    [{ expirationDays: Number.NaN }],
  ])('rejects %j', (bad) => {
    expect(validateSettingsForm({ ...ok, ...bad })).not.toBeNull()
  })
})
