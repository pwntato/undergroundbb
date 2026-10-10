import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { OwnFingerprintPanel } from './OwnFingerprintPanel'

describe('OwnFingerprintPanel', () => {
  it('shows the fingerprint once loaded', () => {
    const html = renderToStaticMarkup(
      <OwnFingerprintPanel state={{ status: 'ready', fingerprint: '12345-67890' }} />,
    )
    expect(html).toContain('Your key fingerprint')
    expect(html).toContain('12345-67890')
  })

  it('shows a placeholder while loading, with no fingerprint', () => {
    const html = renderToStaticMarkup(<OwnFingerprintPanel state={{ status: 'loading' }} />)
    expect(html).toContain('Loading')
  })

  it('asks for a fresh login when the keys are not cached', () => {
    const html = renderToStaticMarkup(<OwnFingerprintPanel state={{ status: 'unavailable' }} />)
    expect(html).toContain('Log in again')
  })
})
