import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import type { DesignationRecord, GrantRecord } from '@/lib/crypto/grant-chain'
import { SuccessorPanel, type DesignationChoice } from './SuccessorPanel'
import type { SuccessorView } from './runSuccessor'

const ADMIN = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const CAT = 'cccccccc-3333-4333-8333-333333333333'
const RAND = '0123456789abcdef'
const at = (iso: string) => Date.parse(`${iso}T12:00:00Z`)

const USERNAMES = new Map([
  [ADMIN, 'alice_admin'],
  [BOB, 'bob_member'],
  [CAT, ''],
])

const designation = (successor: string | undefined, iso = '2026-06-01'): DesignationRecord => ({
  sortKey: `DESIGNATION#${ADMIN}#${iso}#${RAND}`,
  adminUserId: ADMIN,
  ...(successor !== undefined && { successorUserId: successor }),
  periodDays: 90,
  adminGrantRef: `GRANT#${ADMIN}#2026-01-01#${RAND}`,
  signature: 's',
})

function view(
  role: 'admin' | 'member',
  designations: DesignationRecord[] = [],
  grants: GrantRecord[] = [],
): SuccessorView {
  return {
    groupId: 'g1',
    myRole: role,
    myGrantSortKey: `GRANT#x#2026-01-01#${RAND}`,
    members: [
      { userId: ADMIN, role: 'admin', generation: 0 },
      { userId: BOB, role: role === 'admin' ? 'member' : role, generation: 0 },
      { userId: CAT, role: 'member', generation: 0 },
    ],
    designations,
    grants,
  }
}

function render(
  v: SuccessorView,
  userId: string,
  nowIso: string,
  extra: { confirmingClaim?: string | null; busy?: boolean; choice?: DesignationChoice } = {},
): string {
  return renderToStaticMarkup(
    createElement(SuccessorPanel, {
      view: v,
      userId,
      usernames: USERNAMES,
      nowMs: at(nowIso),
      busy: extra.busy ?? false,
      choice: extra.choice ?? { successorUserId: '', periodDays: '90' },
      onChoice: () => undefined,
      onDesignate: () => undefined,
      onRevoke: () => undefined,
      confirmingClaim: extra.confirmingClaim ?? null,
      onStartClaim: () => undefined,
      onCancelClaim: () => undefined,
      onConfirmClaim: () => undefined,
    }),
  )
}

describe('SuccessorPanel, admin', () => {
  it('says plainly that there is no designation, and offers the suggested 90 days within 30 to 365', () => {
    const html = render(view('admin'), ADMIN, '2026-09-01')
    expect(html).toContain('You have not named a successor')
    expect(html).toContain('value="90"')
    expect(html).toContain('min="30"')
    expect(html).toContain('max="365"')
    expect(html).toContain('Designate successor')
    expect(html).not.toContain('Revoke')
  })

  it('lists other live members as candidates, not yourself or a deleted account', () => {
    const html = render(view('admin'), ADMIN, '2026-09-01')
    expect(html).toContain('bob_member')
    expect(html).not.toContain('alice_admin')
    expect(html).not.toContain(CAT.split('-')[0])
    expect(html).not.toContain('deleted user')
  })

  it('shows the standing designation with the day it can fire, and offers replace and revoke', () => {
    const html = render(view('admin', [designation(BOB)]), ADMIN, '2026-09-01')
    expect(html).toContain('bob_member is your successor')
    expect(html).toContain('2026-08-30')
    expect(html).toContain('Replace successor')
    expect(html).toContain('Revoke')
  })

  it('says when the designation lapsed because the admin role changed', () => {
    const lapse: GrantRecord = {
      sortKey: `GRANT#${ADMIN}#2026-07-10#${RAND}`,
      subjectUserId: ADMIN,
      grantedRole: 'admin',
      grantorUserId: CAT,
      signature: 's',
    }
    const html = render(view('admin', [designation(BOB)], [lapse]), ADMIN, '2026-09-01')
    expect(html).toContain('lapsed')
    expect(html).toContain('2026-07-10')
    expect(html).toContain('You have no successor now')
    // Nothing standing to revoke.
    expect(html).not.toContain('Revoke')
    expect(html).toContain('Designate successor')
  })

  it('says after a revocation that there is no successor', () => {
    const html = render(
      view('admin', [designation(BOB), designation(undefined, '2026-07-01')]),
      ADMIN,
      '2026-09-01',
    )
    expect(html).toContain('You revoked your successor')
    expect(html).not.toContain('Revoke')
  })

  it('disables Designate until someone is chosen, and every control while busy', () => {
    const idle = render(view('admin'), ADMIN, '2026-09-01')
    expect(idle).toMatch(/<button[^>]* disabled=""[^>]*>Designate successor/)
    const chosen = render(view('admin'), ADMIN, '2026-09-01', {
      choice: { successorUserId: BOB, periodDays: '90' },
    })
    expect(chosen).not.toMatch(/<button[^>]* disabled=""[^>]*>Designate successor/)
    const busy = render(view('admin', [designation(BOB)]), ADMIN, '2026-09-01', {
      busy: true,
      choice: { successorUserId: BOB, periodDays: '90' },
    })
    expect(busy).toMatch(/<button[^>]* disabled=""[^>]*>Replace successor/)
    expect(busy).toMatch(/<button[^>]* disabled=""[^>]*>Revoke/)
  })
})

describe('SuccessorPanel, designated member', () => {
  it('tells someone nobody named that nobody did', () => {
    expect(render(view('member'), BOB, '2026-09-01')).toContain('Nobody has named you')
    expect(render(view('member', [designation(CAT)]), BOB, '2026-09-01')).toContain(
      'Nobody has named you',
    )
  })

  it('before the period elapses, says from when they can claim and offers no claim button', () => {
    const html = render(view('member', [designation(BOB)]), BOB, '2026-08-29')
    expect(html).toContain('alice_admin named you')
    expect(html).toContain('2026-08-30')
    expect(html).not.toContain('Claim admin role')
  })

  it('once the period has elapsed, offers the claim as a two-step action', () => {
    const first = render(view('member', [designation(BOB)]), BOB, '2026-09-01')
    expect(first).toContain('Claim admin role')
    expect(first).not.toContain('Confirm claim')
    const key = designation(BOB).sortKey
    const second = render(view('member', [designation(BOB)]), BOB, '2026-09-01', {
      confirmingClaim: key,
    })
    expect(second).toContain('Confirm claim')
    expect(second).toContain('Cancel')
    // Says when they can grant roles: the server refuses earlier (grantor_granted_today).
    expect(second).toContain('from the day after you claim')
  })

  it('offers nothing for a designation that has lapsed', () => {
    const lapse: GrantRecord = {
      sortKey: `GRANT#${ADMIN}#2026-07-10#${RAND}`,
      subjectUserId: ADMIN,
      grantedRole: 'admin',
      grantorUserId: CAT,
      signature: 's',
    }
    const html = render(view('member', [designation(BOB)], [lapse]), BOB, '2026-09-01')
    expect(html).toContain('Nobody has named you')
    expect(html).not.toContain('Claim admin role')
  })
})
