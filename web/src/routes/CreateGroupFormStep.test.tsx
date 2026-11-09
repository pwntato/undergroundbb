// Pins PR #142 round 3's non-blocking finding: CreateGroupScreen's
// ReauthenticateStep branch unmounts CreateGroupFormStep entirely, so its
// own useState fields are lost on Cancel or a failed resubmit after
// re-auth unless the parent re-seeds them via initialValues. No jsdom/RTL
// needed -- renderToStaticMarkup is enough to read each controlled input's
// `value`/`checked` attribute in the initial render.

import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { createElement } from 'react'
import { CreateGroupFormStep, type GroupFormValues } from './CreateGroupFormStep'
import { buildGroupValues, revocationModeFor } from './groupFormValues'

const ALLOW_NEVER = { known: true, allowNeverExpire: true, defaultDays: 30 } as const

const VALUES: GroupFormValues = {
  visibility: 'public',
  name: 'Book Club',
  description: 'We read books',
  revocationMode: 'open',
  expirationDays: 0,
}

describe('CreateGroupFormStep initialValues', () => {
  it('seeds every field from initialValues on first render', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: ALLOW_NEVER,
        initialValues: VALUES,
      }),
    )

    expect(html).toContain('value="Book Club"')
    expect(html).toContain('We read books')
    // Public visibility (the SECOND visibility radio) and open revocation
    // (the SECOND revocationMode radio) should both be checked; the first
    // radio in each pair (private/rotating) should not be.
    expect(html).toMatch(/name="visibility"\/>Private[\s\S]*?checked=""\/>Public/)
    expect(html).toMatch(/name="revocationMode"\/>Rotating[\s\S]*?checked=""\/>Open/)
    // expirationDays: 0 means "never expire" -- the checkbox should be checked.
    expect(html).toMatch(/type="checkbox" checked=""/)
  })

  it('offers only Open for a public group, even if the saved choice was Rotating', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: ALLOW_NEVER,
        initialValues: { ...VALUES, visibility: 'public', revocationMode: 'rotating' },
      }),
    )
    expect(html).toMatch(/disabled="" name="revocationMode"\/>Rotating/)
    expect(html).toMatch(/name="revocationMode" checked=""\/>Open/)
    expect(html).toContain('A public group is always Open.')
  })

  it("submits Open for every public group and keeps a private group's choice", () => {
    expect(revocationModeFor('public', 'rotating')).toBe('open')
    expect(revocationModeFor('public', 'open')).toBe('open')
    expect(revocationModeFor('private', 'rotating')).toBe('rotating')
    expect(revocationModeFor('private', 'open')).toBe('open')
  })

  it('hands up Open for a public group whatever Rotating was picked, and the rest unchanged', () => {
    const f = {
      visibility: 'public',
      name: 'N',
      description: 'D',
      revocationMode: 'rotating',
      neverExpires: true,
      policy: ALLOW_NEVER,
    } as const
    expect(buildGroupValues(f)).toEqual({
      visibility: 'public',
      name: 'N',
      description: 'D',
      revocationMode: 'open',
      expirationDays: 0,
    })
    expect(
      buildGroupValues({ ...f, visibility: 'private', neverExpires: false, policy: ALLOW_NEVER }),
    ).toMatchObject({
      revocationMode: 'rotating',
      expirationDays: 30,
    })
  })

  it('uses the deployment default days, and 0 only where never-expire is allowed', () => {
    const f = {
      visibility: 'private',
      name: 'N',
      description: '',
      revocationMode: 'open',
      neverExpires: true,
    } as const
    expect(
      buildGroupValues({ ...f, policy: { known: true, allowNeverExpire: true, defaultDays: 14 } })
        .expirationDays,
    ).toBe(0)
    expect(
      buildGroupValues({ ...f, policy: { known: true, allowNeverExpire: false, defaultDays: 14 } })
        .expirationDays,
    ).toBe(14)
    expect(
      buildGroupValues({
        ...f,
        neverExpires: false,
        policy: { known: true, allowNeverExpire: true, defaultDays: 14 },
      }).expirationDays,
    ).toBe(14)
  })

  it('does not offer never-expire where the deployment forbids it, and says how long messages last', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: { known: true, allowNeverExpire: false, defaultDays: 14 },
      }),
    )
    expect(html).not.toContain('type="checkbox"')
    expect(html).not.toContain('Never expire')
    expect(html).toContain('Messages expire after 14 days.')
  })

  it('offers never-expire, naming the default days, where it is allowed', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: { known: true, allowNeverExpire: true, defaultDays: 14 },
      }),
    )
    expect(html).toContain('type="checkbox"')
    expect(html).toContain('Never expire messages (default: 14 days)')
  })

  it('leaves Rotating available for a private group', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: ALLOW_NEVER,
        initialValues: { ...VALUES, visibility: 'private', revocationMode: 'rotating' },
      }),
    )
    expect(html).toMatch(/name="revocationMode" checked=""\/>Rotating/)
    expect(html).not.toContain('disabled=""')
    expect(html).not.toContain('A public group is always Open.')
  })

  it('falls back to the original defaults when initialValues is omitted', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
        policy: ALLOW_NEVER,
      }),
    )

    expect(html).toContain('value=""')
    // Private (first radio) and rotating (first radio) should be checked by
    // default; their public/open counterparts should not be.
    expect(html).toMatch(/name="visibility" checked=""\/>Private/)
    expect(html).toMatch(/name="revocationMode" checked=""\/>Rotating/)
    expect(html).not.toContain('type="checkbox" checked=""')
  })
})
