// Markup tests for GroupSettingsPanel (renderToStaticMarkup, per
// GroupList.test.tsx's reasoning) and validateSettingsForm.

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { GroupDetail } from '@/lib/api/groups'
import { GroupSettingsPanel } from './GroupSettingsPanel'
import {
  CONVERT_OPEN_WARNING,
  convertConfirmed,
  revocationText,
  validateSettingsForm,
} from './groupSettingsForm'
import type { SettingsView } from './runGroupSettings'

function detail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: 'g1',
    visibility: 'public',
    role: 'member',
    generation: 0,
    noRotation: true,
    nameGeneration: 0,
    namePlaintext: 'Book Club',
    descriptionPlaintext: 'We read books',
    revocationMode: 'rotating',
    memberCap: 1000,
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
      onReauthenticate: () => undefined,
      onConvert: () => undefined,
      converting: false,
      convertError: null,
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

  it('shows "never expire" and a way to re-enter the password for a cold-keys private admin, with no form', () => {
    const html = render({
      detail: detail({ visibility: 'private', role: 'admin', expirationDays: 0 }),
      name: null,
      description: null,
      nameStatus: 'coldKeys',
    })
    expect(html).toContain('Messages never expire.')
    expect(html).toContain('needs your password again')
    expect(html).toContain('Enter your password')
    // /login bounces a signed-in user, so the notice must not point there (#217).
    expect(html).not.toContain('Log in again')
    expect(html).not.toContain('Edit settings')
  })

  it('offers the password button only for the cold-keys notice', () => {
    const base = detail({ visibility: 'private', role: 'admin' })
    expect(
      render({ detail: base, name: null, description: null, nameStatus: 'unreadable' }),
    ).not.toContain('Enter your password')
    expect(
      render({ detail: base, name: 'Book Club', description: '', nameStatus: 'decrypted' }),
    ).not.toContain('Enter your password')
  })

  it('contains no em dashes in its copy', () => {
    expect(render(publicView(detail({ role: 'admin' })))).not.toContain('—')
    expect(revocationText('rotating', 1000) + revocationText('open', 0)).not.toContain('—')
  })
})

describe('revocationText', () => {
  it('states the deployment cap for a Rotating group, not a fixed number', () => {
    expect(revocationText('rotating', 1000)).toContain('Capped at 1,000 members.')
    expect(revocationText('rotating', 250)).toContain('Capped at 250 members.')
    expect(revocationText('rotating', 250)).not.toContain('1,000')
  })

  it('says nothing about a cap when the server reports none', () => {
    expect(revocationText('rotating', 0)).not.toContain('Capped')
  })

  it('says an Open group has no cap, whatever the number', () => {
    expect(revocationText('open', 0)).toContain('There is no member cap.')
    expect(revocationText('open', 500)).not.toContain('500')
  })
})

describe('validateSettingsForm', () => {
  const ok = { name: 'A', description: '', expirationDays: 30 }
  it('accepts a normal form and never-expire (0)', () => {
    expect(validateSettingsForm(ok)).toBeNull()
    expect(validateSettingsForm({ ...ok, expirationDays: 0 })).toBeNull()
  })
  it('accepts a name at exactly the byte limit', () => {
    expect(validateSettingsForm({ ...ok, name: 'é'.repeat(100) })).toBeNull()
    expect(validateSettingsForm({ ...ok, name: 'a'.repeat(200) })).toBeNull()
  })
  it.each([
    [{ name: '   ' }],
    [{ name: 'x'.repeat(201) }],
    [{ description: 'x'.repeat(2001) }],
    [{ expirationDays: -1 }],
    [{ expirationDays: 3651 }],
    [{ expirationDays: 1.5 }],
    [{ expirationDays: Number.NaN }],
    // 101 two-byte characters: 101 UTF-16 units but 202 UTF-8 bytes.
    [{ name: 'é'.repeat(101) }],
    [{ description: 'é'.repeat(1001) }],
  ])('rejects %j', (bad) => {
    expect(validateSettingsForm({ ...ok, ...bad })).not.toBeNull()
  })
})

describe('converting to Open (#61)', () => {
  const adminView = (d: Partial<GroupDetail> = {}): SettingsView =>
    publicView(detail({ role: 'admin', revocationMode: 'rotating', ...d }))

  it('offers the conversion to an admin of a Rotating group, and only the first step', () => {
    const html = render(adminView())
    expect(html).toContain('Convert to Open')
    // The warning and the typed confirmation appear only after the first click.
    expect(html).not.toContain('Type the group name')
  })

  it.each([
    ['an Open group', adminView({ revocationMode: 'open' })],
    ['a plain member', adminView({ role: 'member' })],
    ['an ambassador', adminView({ role: 'ambassador' })],
    [
      'an admin whose tab cannot read the name',
      {
        detail: detail({ visibility: 'private', role: 'admin', revocationMode: 'rotating' }),
        name: null,
        description: null,
        nameStatus: 'coldKeys' as const,
      },
    ],
  ])('does not offer it to %s', (_who, view) => {
    expect(render(view)).not.toContain('Convert to Open')
  })

  it('spells out what is lost and that it is permanent, without em dashes', () => {
    const text = CONVERT_OPEN_WARNING.join(' ')
    expect(text).toContain('never be re-keyed')
    expect(text).toContain('cannot be undone')
    expect(text).toContain('member cap')
    expect(text).not.toContain('—')
  })

  it('needs the exact group name typed, ignoring surrounding spaces and nothing else', () => {
    expect(convertConfirmed('Book Club', 'Book Club')).toBe(true)
    expect(convertConfirmed('  Book Club ', 'Book Club')).toBe(true)
    expect(convertConfirmed('book club', 'Book Club')).toBe(false)
    expect(convertConfirmed('Book', 'Book Club')).toBe(false)
    expect(convertConfirmed('', 'Book Club')).toBe(false)
    expect(convertConfirmed('', '')).toBe(false)
    expect(convertConfirmed('anything', null)).toBe(false)
  })
})
