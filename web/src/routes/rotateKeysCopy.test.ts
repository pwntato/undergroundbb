import { describe, expect, it } from 'vitest'
import {
  failureMessage,
  MIN_PASSWORD_LENGTH,
  stepText,
  validateNewPassword,
} from './rotateKeysCopy'
import type { KeyRotationFailure, KeyRotationStep } from './runKeyRotation'

const label = (id: string) => `Group ${id}`

describe('validateNewPassword', () => {
  it('accepts a long enough matching password', () => {
    expect(
      validateNewPassword('x'.repeat(MIN_PASSWORD_LENGTH), 'x'.repeat(MIN_PASSWORD_LENGTH)),
    ).toBeNull()
  })
  it('refuses a short one before it checks the match', () => {
    expect(validateNewPassword('short', 'different')).toContain('at least')
  })
  it('refuses a mismatch', () => {
    expect(validateNewPassword('longenough1', 'longenough2')).toBe('Passwords do not match.')
  })
})

describe('failureMessage', () => {
  const kinds: KeyRotationFailure[] = [
    { kind: 'needsLogin' },
    { kind: 'authRequired' },
    { kind: 'cooldown' },
    { kind: 'handoffPending', groups: ['a', 'b'] },
    { kind: 'groupBusy', groups: [] },
    { kind: 'changedElsewhere' },
    { kind: 'rejected', message: 'bad signature.' },
    { kind: 'unreachable' },
    { kind: 'unconfirmed', recoveryCode: 'ABCD' },
  ]

  it('has a message for every failure, and none of them uses a dash as punctuation', () => {
    for (const f of kinds) {
      const msg = failureMessage(f, label)
      expect(msg.length).toBeGreaterThan(20)
      expect(msg).not.toMatch(/—|--/)
    }
  })

  it('names the groups a conflict is about, by label', () => {
    expect(failureMessage({ kind: 'handoffPending', groups: ['a', 'b'] }, label)).toContain(
      'Group a, Group b',
    )
    expect(failureMessage({ kind: 'groupBusy', groups: [] }, label)).toContain('a group')
  })

  it('never tells the user their keys are unchanged when the request was sent and the answer is unknown', () => {
    const msg = failureMessage({ kind: 'unconfirmed', recoveryCode: 'ABCD' }, label)
    expect(msg).toContain("couldn't confirm")
    expect(msg).not.toMatch(/not changed|Nothing was rotated/)
    expect(msg).toContain('never rotates twice')
    // The code is the one thing that cannot be recovered if the rotation did land.
    expect(msg).toContain('write the code down')
    expect(msg).toContain('new password')
  })

  it('says nothing was rotated for the failures that mean it, and that keys are unchanged when unreachable', () => {
    expect(failureMessage({ kind: 'changedElsewhere' }, label)).toContain('Nothing was rotated')
    expect(failureMessage({ kind: 'rejected', message: 'x.' }, label)).toContain(
      'Nothing was rotated',
    )
    expect(failureMessage({ kind: 'unreachable' }, label)).toContain('have not changed')
  })
})

describe('stepText', () => {
  it('reports handoff progress as it happens', () => {
    const s: KeyRotationStep = { name: 'handoffs', done: 2, total: 5 }
    expect(stepText(s)).toContain('2 of 5')
    expect(stepText({ name: 'handoffs', done: 0, total: 0 })).toBe('Checking your groups…')
  })
  it('has a line for every other step', () => {
    for (const name of ['preparing', 'signing', 'committing'] as const) {
      expect(stepText({ name })).toMatch(/…$/)
    }
  })
})
