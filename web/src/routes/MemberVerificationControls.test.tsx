// Markup tests for the roster's fingerprint verification controls (#65), via
// renderToStaticMarkup like GroupMembersPanel.test.tsx.

import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { MemberEntry } from '@/lib/api/groups'
import { FingerprintBlock } from './FingerprintBlock'
import { GroupMembersPanel } from './GroupMembersPanel'
import {
  MemberVerificationBadge,
  MemberVerificationControls,
  type MemberVerificationProps,
  type VerifyPrompt,
} from './MemberVerificationControls'
import type { MemberVerifications } from './runMemberVerification'
import type { MembersView } from './runGroupMembers'

const ME = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const FP = '11111-22222-33333-44444-55555-66666-77777-88888-99999-00000-12345-67890'

const ready = (
  verdict: 'none' | 'verified' | 'changed' | 'bad-signature',
  fp: string | null = FP,
) =>
  ({
    state: 'ready',
    byUser: new Map([[BOB, { fingerprint: fp, verdict }]]),
  }) as MemberVerifications

function props(
  state: MemberVerifications | null,
  prompt: VerifyPrompt | null = null,
): MemberVerificationProps {
  return {
    state,
    prompt,
    onStart: () => undefined,
    onCancel: () => undefined,
    onConfirm: () => undefined,
    onRemove: () => undefined,
    onReauthenticate: () => undefined,
  }
}

function controls(p: MemberVerificationProps, disabled = false): string {
  return renderToStaticMarkup(
    createElement(MemberVerificationControls, { props: p, userId: BOB, label: 'bob', disabled }),
  )
}

describe('FingerprintBlock', () => {
  it('lays twelve groups out four to a row, keeping the hyphens', () => {
    const html = renderToStaticMarkup(createElement(FingerprintBlock, { value: FP }))
    expect(html).toContain('11111-22222-33333-44444')
    expect(html).toContain('55555-66666-77777-88888')
    expect(html).toContain('99999-00000-12345-67890')
    expect(html.match(/<span/g)).toHaveLength(3)
  })
})

describe('MemberVerificationBadge', () => {
  const badge = (state: MemberVerifications | null) =>
    renderToStaticMarkup(createElement(MemberVerificationBadge, { state, userId: BOB }))

  it('shows nothing while loading, when unavailable, and for an unverified member', () => {
    expect(badge(null)).toBe('')
    expect(badge({ state: 'unavailable' })).toBe('')
    expect(badge(ready('none'))).toBe('')
  })

  it('says the person checked it for a verified member, without the role mark wording', () => {
    const html = badge(ready('verified'))
    expect(html).toContain('fingerprint checked by you')
    expect(html).not.toContain('✓ verified')
  })

  it('warns when the keys changed or the saved check failed', () => {
    expect(badge(ready('changed'))).toContain('Keys changed since you checked')
    expect(badge(ready('bad-signature'))).toContain('Saved check failed')
  })
})

describe('MemberVerificationControls', () => {
  it('offers Check fingerprint for an unverified member', () => {
    expect(controls(props(ready('none')))).toContain('Check fingerprint')
    expect(controls(props(ready('none')))).not.toContain('again')
  })

  it('offers checking again after a change, and removal when verified', () => {
    expect(controls(props(ready('changed')))).toContain('Check fingerprint again')
    expect(controls(props(ready('verified')))).toContain('Remove check')
  })

  it('lets a changed or failed record be withdrawn without re-checking the person', () => {
    for (const verdict of ['changed', 'bad-signature'] as const) {
      const html = controls(props(ready(verdict)))
      expect(html).toContain('Check fingerprint again')
      expect(html).toContain('Remove check')
    }
    expect(controls(props(ready('none')))).not.toContain('Remove check')
    // Even with no readable fingerprint, a stale record can still be withdrawn.
    const noFp = controls(props(ready('changed', null)))
    expect(noFp).toContain('Remove check')
    expect(noFp).not.toContain('Check fingerprint')
  })

  it('offers nothing while loading, when unavailable, or when the member has no fingerprint', () => {
    expect(controls(props(null))).toBe('')
    expect(controls(props({ state: 'unavailable' }))).toBe('')
    expect(controls(props(ready('none', null)))).toBe('')
  })

  it('shows the whole fingerprint and out-of-band instructions in the prompt', () => {
    const html = controls(props(ready('none'), { userId: BOB, fingerprint: FP }))
    expect(html).toContain('11111-22222-33333-44444')
    expect(html).toContain('99999-00000-12345-67890')
    expect(html).toContain('Every group matches')
    expect(html).toContain('in person or on a call')
    expect(html).toContain('Do not take it from the group or from a message')
    expect(html).not.toContain('Check fingerprint')
  })

  it('adds a warning to the prompt when the keys changed since the last check', () => {
    const html = controls(props(ready('changed'), { userId: BOB, fingerprint: FP }))
    expect(html).toContain('real key change or a substituted key')
    expect(controls(props(ready('none'), { userId: BOB, fingerprint: FP }))).not.toContain(
      'substituted key',
    )
  })

  it('disables its buttons while another action runs', () => {
    expect(controls(props(ready('none')), true)).toContain('disabled=""')
    expect(controls(props(ready('none')), false)).not.toContain('disabled=""')
  })
})

describe('GroupMembersPanel verification wiring', () => {
  const member = (userId: string, role: MemberEntry['role']): MemberEntry => ({
    userId,
    role,
    generation: 0,
  })
  const view: MembersView = {
    groupId: 'g1',
    members: [member(ME, 'admin'), member(BOB, 'member')],
    myRole: 'admin',
    myGrantSortKey: 'GRANT#x',
    revocationMode: 'open',
    myGeneration: 0,
  }
  function panel(
    verification: MemberVerificationProps | undefined,
    usernames = new Map<string, string>(),
  ): string {
    return renderToStaticMarkup(
      createElement(GroupMembersPanel, {
        view,
        userId: ME,
        busyUserId: null,
        onChangeRole: () => undefined,
        confirmRemoveUserId: null,
        onStartRemove: () => undefined,
        onCancelRemove: () => undefined,
        onConfirmRemove: () => undefined,
        usernames,
        ...(verification !== undefined && { verification }),
      }),
    )
  }

  it('shows the control on other members only, never on the caller', () => {
    const html = panel(props(ready('none')))
    expect(html.match(/Check fingerprint/g)).toHaveLength(1)
  })

  it('shows no verification controls when the prop is absent', () => {
    expect(panel(undefined)).not.toContain('Check fingerprint')
  })

  it('shows the badge next to a verified member', () => {
    expect(panel(props(ready('verified')))).toContain('fingerprint checked by you')
  })

  it('offers nothing and warns of nothing for a deleted account, even with a changed record', () => {
    for (const verdict of ['none', 'changed', 'verified'] as const) {
      const html = panel(props(ready(verdict)), new Map([[BOB, '']]))
      expect(html).not.toContain('Check fingerprint')
      expect(html).not.toContain('Keys changed')
      expect(html).not.toContain('checked by you')
    }
  })

  it('says why no checks are shown when they could not be loaded, and offers the password step', () => {
    const html = panel(props({ state: 'unavailable' }))
    expect(html).toContain('Couldn&#x27;t load your fingerprint checks')
    expect(html).toContain('Enter your password')
    expect(panel(props(ready('none')))).not.toContain('Enter your password')
    expect(panel(props(null))).not.toContain('Enter your password')
  })
})
