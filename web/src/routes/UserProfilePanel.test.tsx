import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import { elementsOf } from './elementTree.testkit'
import { profileView, type ProfileView } from './profileView'
import type { MemberVerifications } from './runMemberVerification'
import { UserProfilePanel, type BioEditProps } from './UserProfilePanel'

const view = (over: Partial<ProfileView> = {}): ProfileView => ({
  userId: 'u1',
  deleted: false,
  username: 'alice',
  memberSince: '8 November 2026',
  bio: 'I like maps.',
  fingerprint: '12345-12345-12345-12345-12345-12345-12345-12345-12345-12345-12345-12345',
  ...over,
})

const edit = (over: Partial<BioEditProps> = {}): BioEditProps => ({
  draft: 'I like maps.',
  onDraftChange: () => undefined,
  onSave: () => undefined,
  saving: false,
  message: null,
  error: null,
  ...over,
})

const render = (props: Parameters<typeof UserProfilePanel>[0]) =>
  renderToStaticMarkup(createElement(MemoryRouter, null, createElement(UserProfilePanel, props)))

describe('UserProfilePanel', () => {
  it("shows another user's username, member-since, bio and fingerprint, with no editor", () => {
    const html = render({ view: view(), isSelf: false, verification: null })
    expect(html).toContain('alice')
    expect(html).toContain('Member since 8 November 2026')
    expect(html).toContain('I like maps.')
    expect(html).toContain('12345-12345-12345-12345')
    expect(html).not.toContain('profile-bio')
    expect(html).not.toContain('>Save<')
  })

  it('omits member-since for an account that predates the field, and says when there is no bio', () => {
    const html = render({
      view: view({ memberSince: null, bio: '' }),
      isSelf: false,
      verification: null,
    })
    expect(html).not.toContain('Member since')
    expect(html).toContain('No bio.')
  })

  it('says a fingerprint could not be read instead of showing nothing', () => {
    const html = render({ view: view({ fingerprint: null }), isSelf: false, verification: null })
    expect(html).toContain('could not be read')
  })

  it('shows the viewer’s own verification state for someone else', () => {
    const verification: MemberVerifications = {
      state: 'ready',
      byUser: new Map([['u1', { fingerprint: 'x', verdict: 'verified' as const }]]),
    }
    expect(render({ view: view(), isSelf: false, verification })).toContain(
      'fingerprint checked by you',
    )
    expect(render({ view: view(), isSelf: true, verification, bioEdit: edit() })).not.toContain(
      'fingerprint checked by you',
    )
  })

  it('shows a deleted account as deleted and nothing else', () => {
    const html = render({
      view: profileView({
        userId: 'u1',
        username: '',
        deleted: true,
        bio: 'leftover',
        createdDay: '2026-11-08',
        signingPublicKey: 'AAAA',
        wrappingPublicKey: 'AAAA',
        supersededSigningKeys: [],
        keyEpoch: 0,
      }),
      isSelf: false,
      verification: null,
    })
    expect(html).toContain('Deleted user')
    expect(html).not.toContain('leftover')
    expect(html).not.toContain('Member since')
  })

  it('gives the owner an editor that says who can read the bio', () => {
    const html = render({ view: view(), isSelf: true, verification: null, bioEdit: edit() })
    expect(html).toContain('id="profile-bio"')
    expect(html).toContain('Anyone signed in can read your bio')
    expect(html).toContain('12 / 280')
  })

  it("never shows the editor on someone else's page, even if given edit props", () => {
    const html = render({ view: view(), isSelf: false, verification: null, bioEdit: edit() })
    expect(html).not.toContain('profile-bio')
  })

  it('disables Save while saving or over the cap, and shows an error and a message', () => {
    const saveDisabled = (bioEdit: BioEditProps) => {
      const el = UserProfilePanel({ view: view(), isSelf: true, verification: null, bioEdit })
      const save = elementsOf(el).find((n) => (n.type as { name?: string }).name === 'Button')
      return save?.props['disabled']
    }
    expect(saveDisabled(edit())).toBe(false)
    expect(saveDisabled(edit({ saving: true }))).toBe(true)
    expect(saveDisabled(edit({ draft: 'a'.repeat(281) }))).toBe(true)
    expect(saveDisabled(edit({ draft: 'a'.repeat(280) }))).toBe(false)
    // 280 emoji is within the character cap but 1,120 bytes, which the server refuses.
    expect(saveDisabled(edit({ draft: '😀'.repeat(280) }))).toBe(true)

    expect(
      render({ view: view(), isSelf: true, verification: null, bioEdit: edit({ saving: true }) }),
    ).toContain('Saving…')
    const tooLong = render({
      view: view(),
      isSelf: true,
      verification: null,
      bioEdit: edit({ draft: 'a'.repeat(281), error: 'Nope.' }),
    })
    expect(tooLong).toContain('Nope.')
    expect(
      render({
        view: view(),
        isSelf: true,
        verification: null,
        bioEdit: edit({ message: 'Saved.' }),
      }),
    ).toContain('Saved.')
  })

  it('passes the typed text and the Save click to the screen', () => {
    const onDraftChange = vi.fn()
    const onSave = vi.fn()
    const el = UserProfilePanel({
      view: view(),
      isSelf: true,
      verification: null,
      bioEdit: edit({ onDraftChange, onSave }),
    })
    const nodes = elementsOf(el)
    const box = nodes.find((n) => n.props['id'] === 'profile-bio')
    const onChange = box?.props['onChange'] as (e: { target: { value: string } }) => void
    onChange({ target: { value: 'new bio' } })
    expect(onDraftChange).toHaveBeenCalledExactlyOnceWith('new bio')
    const save = nodes.find((n) => (n.type as { name?: string }).name === 'Button')
    const onClick = save?.props['onClick'] as () => void
    onClick()
    expect(onSave).toHaveBeenCalledOnce()
  })
})
