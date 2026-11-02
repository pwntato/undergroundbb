import { describe, expect, it } from 'vitest'
import { seekForm } from './formSeek'

const base = {
  formKey: 'P9',
  settled: true,
  shown: ['P1', 'P2'],
  cursor: 'c1',
  lastAsked: undefined,
}

describe('seekForm', () => {
  it("asks for the next page while the form's item is not on screen and pages remain", () => {
    expect(seekForm(base)).toEqual({ kind: 'loadMore', cursor: 'c1' })
  })

  it('does nothing without a form, while a page is loading or failed, or once the item shows', () => {
    expect(seekForm({ ...base, formKey: undefined })).toEqual({ kind: 'none' })
    expect(seekForm({ ...base, settled: false })).toEqual({ kind: 'none' })
    expect(seekForm({ ...base, shown: ['P9'] })).toEqual({ kind: 'none' })
  })

  it('says the item is gone only when the last page is loaded without it', () => {
    expect(seekForm({ ...base, cursor: undefined })).toEqual({ kind: 'gone' })
    expect(seekForm({ ...base, cursor: undefined, shown: ['P9'] })).toEqual({ kind: 'none' })
  })

  it('never asks for the same cursor twice in a row, so a server repeating a cursor cannot loop', () => {
    expect(seekForm({ ...base, lastAsked: 'c1' })).toEqual({ kind: 'none' })
    expect(seekForm({ ...base, cursor: 'c2', lastAsked: 'c1' })).toEqual({
      kind: 'loadMore',
      cursor: 'c2',
    })
  })
})
