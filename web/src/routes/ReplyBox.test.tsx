import { describe, expect, it, vi } from 'vitest'
import { elementsOf } from './elementTree.testkit'
import { ReplyBox } from './ReplyBox'

function box(over: { unchanged?: boolean; value?: string; onSubmit?: () => void } = {}) {
  return ReplyBox({
    id: 'x',
    label: 'l',
    value: over.value ?? 'text',
    maxBytes: 100,
    sending: false,
    error: null,
    unchanged: over.unchanged,
    onChange: () => {},
    onSubmit: over.onSubmit ?? (() => {}),
  })
}
const submit = (tree: ReturnType<typeof box>) =>
  (elementsOf(tree).find((e) => e.type === 'form')!.props['onSubmit'] as (e: unknown) => void)({
    preventDefault: () => {},
  })

describe('ReplyBox submit', () => {
  it('submits text that is valid', () => {
    const onSubmit = vi.fn()
    submit(box({ onSubmit }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })
  it('does not submit an unchanged edit, even by Enter in the form', () => {
    const onSubmit = vi.fn()
    submit(box({ unchanged: true, onSubmit }))
    expect(onSubmit).not.toHaveBeenCalled()
  })
  it('does not submit empty text', () => {
    const onSubmit = vi.fn()
    submit(box({ value: '  ', onSubmit }))
    expect(onSubmit).not.toHaveBeenCalled()
  })
  it('labels the button Save for an edit and disables it while unchanged', () => {
    const btn = (t: ReturnType<typeof box>) =>
      elementsOf(t).find((e) => e.props['type'] === 'submit')!.props
    const tree = ReplyBox({
      id: 'x',
      label: 'l',
      value: 'v',
      maxBytes: 100,
      sending: false,
      error: null,
      submitLabel: 'Save',
      unchanged: true,
      onChange: () => {},
      onSubmit: () => {},
    })
    expect(btn(tree)['children']).toBe('Save')
    expect(btn(tree)['disabled']).toBe(true)
  })
})
