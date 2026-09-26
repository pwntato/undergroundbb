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

  it('falls back to the original defaults when initialValues is omitted', () => {
    const html = renderToStaticMarkup(
      createElement(CreateGroupFormStep, {
        onSubmit: () => {
          /* not exercised by a static render */
        },
        error: null,
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
