import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import { DirectoryPanel } from './DirectoryPanel'
import { directoryRows, type DirectoryRow } from './directoryRows'
import { elementsOf } from './elementTree.testkit'

function call(
  el: { props: Record<string, unknown> } | undefined,
  prop: string,
  ...args: unknown[]
): void {
  if (el === undefined) throw new Error('element not found')
  ;(el.props[prop] as (...a: unknown[]) => void)(...args)
}

const html = (el: React.ReactElement) => renderToStaticMarkup(createElement(MemoryRouter, null, el))

const rows = (): DirectoryRow[] =>
  directoryRows(
    [
      { groupId: '11111111-aaaa', name: 'Book Club', description: 'We read novels' },
      { groupId: '22222222-bbbb', name: 'Book Club', description: 'We read comics' },
      { groupId: '33333333-cccc', name: 'Chess' },
    ],
    new Set(['33333333-cccc']),
    [],
  )

const props = {
  query: '',
  rows: rows(),
  searched: '',
  hasMore: false,
  busy: false,
  onQueryChange: () => undefined,
  onSearch: () => undefined,
  onLoadMore: () => undefined,
}

describe('DirectoryPanel', () => {
  it('lists two groups with one name as two rows, told apart by id and description', () => {
    const out = html(createElement(DirectoryPanel, props))
    expect(out.match(/Book Club/g)).toHaveLength(2)
    expect(out).toContain('#11111111')
    expect(out).toContain('#22222222')
    expect(out).toContain('We read novels')
    expect(out).toContain('We read comics')
  })

  it('links a free group to its request screen and shows a member their own status instead', () => {
    const out = html(createElement(DirectoryPanel, props))
    expect(out).toContain('/groups/11111111-aaaa/join')
    expect(out).not.toContain('/groups/33333333-cccc/join')
    expect(out).toContain('You are a member')
  })

  it('says what an empty search looked for, and that browsing found nothing', () => {
    expect(html(createElement(DirectoryPanel, { ...props, rows: [], searched: 'Zed' }))).toContain(
      'starting with &quot;Zed&quot;',
    )
    expect(html(createElement(DirectoryPanel, { ...props, rows: [] }))).toContain(
      'No public groups yet.',
    )
  })

  it('says the search is case-sensitive and that posts and members stay private', () => {
    const out = html(createElement(DirectoryPanel, props))
    expect(out).toContain('capital letters')
    expect(out).toContain('posts and members stay private')
  })

  it('submits the search through the form without reloading the page, and passes typing on', () => {
    const onSearch = vi.fn()
    const onQueryChange = vi.fn()
    const el = DirectoryPanel({ ...props, onSearch, onQueryChange })
    const form = elementsOf(el).find((n) => n.type === 'form')
    const preventDefault = vi.fn()
    call(form, 'onSubmit', { preventDefault })
    expect(preventDefault).toHaveBeenCalledOnce()
    expect(onSearch).toHaveBeenCalledOnce()
    const input = elementsOf(el).find((n) => typeof n.props['onChange'] === 'function')
    call(input, 'onChange', { target: { value: 'Bo' } })
    expect(onQueryChange).toHaveBeenCalledWith('Bo')
  })

  it('offers Show more only when there is more, and locks Search while busy', () => {
    expect(html(createElement(DirectoryPanel, props))).not.toContain('Show more')
    const more = html(createElement(DirectoryPanel, { ...props, hasMore: true }))
    expect(more).toContain('Show more')
    const onLoadMore = vi.fn()
    const el = DirectoryPanel({ ...props, hasMore: true, busy: true, onLoadMore })
    const buttons = elementsOf(el).filter((n) => (n.type as { name?: string }).name === 'Button')
    expect(buttons.length).toBe(2)
    expect(buttons.every((b) => b.props['disabled'] === true)).toBe(true)
  })

  it('calls onLoadMore from the real Show more button', () => {
    const onLoadMore = vi.fn()
    const el = DirectoryPanel({ ...props, hasMore: true, onLoadMore })
    const more = elementsOf(el).find(
      (n) => (n.type as { name?: string }).name === 'Button' && n.props['variant'] === 'outline',
    )
    call(more, 'onClick')
    expect(onLoadMore).toHaveBeenCalledOnce()
  })
})
