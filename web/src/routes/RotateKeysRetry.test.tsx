import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { RotateKeysRetry } from './RotateKeysRetry'

const html = renderToStaticMarkup(
  createElement(RotateKeysRetry, {
    message: "We couldn't confirm whether your keys were rotated.",
    recoveryCode: 'ZW5G4-7PAVS-W2ERX',
    onRetry: () => undefined,
  }),
)

describe('RotateKeysRetry', () => {
  it('shows the new recovery code, because it is the only copy if the rotation landed', () => {
    expect(html).toContain('ZW5G4-7PAVS-W2ERX')
    expect(html).toContain('Your new recovery code')
  })

  it('offers only Try again: no password to retype, since the request keeps the first one', () => {
    expect(html).toContain('Try again')
    expect(html).not.toContain('type="password"')
    expect(html.match(/<button/g)).toHaveLength(1)
  })

  it('carries the explanation', () => {
    expect(html).toContain('couldn&#x27;t confirm')
  })
})
