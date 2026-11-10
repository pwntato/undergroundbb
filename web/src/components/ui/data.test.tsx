import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { Data } from './data'

describe('Data', () => {
  it('is monospace with aligned figures, and keeps the caller classes', () => {
    const html = renderToStaticMarkup(<Data className="text-xs">alice</Data>)
    expect(html).toContain('font-mono')
    expect(html).toContain('tabular-nums')
    expect(html).toContain('text-xs')
    expect(html).toContain('>alice<')
  })
})
