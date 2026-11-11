import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { validateCustomTheme, type CustomTheme } from '@/theme/customTheme'
import { CustomThemesPanel, type CustomThemesPanelProps } from './CustomThemesPanel'
import { ThemePicker } from './ThemePicker'
import { elementsOf } from './elementTree.testkit'

function mine(name = 'Mine'): CustomTheme {
  const r = validateCustomTheme(JSON.stringify({ name, mode: 'dark', tokens: {} }))
  if (!r.ok) throw new Error('bad fixture')
  return r.theme
}

function props(o: Partial<CustomThemesPanelProps> = {}): CustomThemesPanelProps {
  return {
    customs: [],
    importText: '',
    errors: [],
    invalid: [],
    notice: null,
    exportText: null,
    onImportText: () => undefined,
    onImport: () => undefined,
    onRemove: () => undefined,
    onDiscard: () => undefined,
    onExport: () => undefined,
    ...o,
  }
}

const byText = (p: CustomThemesPanelProps, text: string) =>
  elementsOf(CustomThemesPanel(p)).find(
    (e) =>
      (e.type as { name?: string }).name === 'Button' &&
      JSON.stringify(e.props['children']).includes(text),
  )
const press = (el: { props: Record<string, unknown> } | undefined) => {
  if (el === undefined) throw new Error('not found')
  ;(el.props['onClick'] as () => void)()
}

describe('CustomThemesPanel', () => {
  it('Import is disabled for an empty box and its click calls onImport', () => {
    expect(byText(props(), 'Import and use')?.props['disabled']).toBe(true)
    const onImport = vi.fn()
    const p = props({ importText: '{}', onImport })
    expect(byText(p, 'Import and use')?.props['disabled']).toBe(false)
    press(byText(p, 'Import and use'))
    expect(onImport).toHaveBeenCalledOnce()
  })

  it('typing in the box calls onImportText with the text', () => {
    const onImportText = vi.fn()
    const box = elementsOf(CustomThemesPanel(props({ onImportText }))).find(
      (e) => e.props['id'] === 'theme-json',
    )
    expect(box).toBeDefined()
    ;(box!.props['onChange'] as (e: { target: { value: string } }) => void)({
      target: { value: 'abc' },
    })
    expect(onImportText).toHaveBeenCalledExactlyOnceWith('abc')
  })

  it('lists each refusal reason in an alert and marks the box invalid', () => {
    const html = renderToStaticMarkup(
      createElement(
        CustomThemesPanel,
        props({ errors: ['The value of "primary" is not allowed.'] }),
      ),
    )
    expect(html).toContain('role="alert"')
    expect(html).toContain('The value of &quot;primary&quot; is not allowed.')
    expect(html).toContain('aria-invalid="true"')
    expect(renderToStaticMarkup(createElement(CustomThemesPanel, props()))).not.toContain(
      'role="alert"',
    )
  })

  it('Remove names its theme and calls onRemove with that id', () => {
    const onRemove = vi.fn()
    const a = mine('Alpha')
    const b = mine('Beta')
    const p = props({ customs: [a, b], onRemove })
    expect(renderToStaticMarkup(createElement(CustomThemesPanel, p))).toContain(' Beta')
    const removes = elementsOf(CustomThemesPanel(p)).filter(
      (e) =>
        (e.type as { name?: string }).name === 'Button' &&
        JSON.stringify(e.props['children']).includes('Remove'),
    )
    expect(removes).toHaveLength(2)
    press(removes[1])
    expect(onRemove).toHaveBeenCalledExactlyOnceWith(b.id)
  })

  it('the export button calls onExport, and the JSON shows in a read-only box only once asked for', () => {
    const onExport = vi.fn()
    press(byText(props({ onExport }), 'Show this theme as JSON'))
    expect(onExport).toHaveBeenCalledOnce()
    const before = renderToStaticMarkup(createElement(CustomThemesPanel, props()))
    expect(before).not.toContain('theme-json-export')
    const after = renderToStaticMarkup(
      createElement(CustomThemesPanel, props({ exportText: '{"a":1}' })),
    )
    expect(after).toContain('theme-json-export')
    expect(after).toContain('readOnly')
  })
})

describe('saved themes that no longer pass, and the replaced notice', () => {
  const invalid = {
    id: 'invalid-abc',
    name: 'Old',
    errors: ['The value of "border-width" is not allowed.'],
    json: '{"name":"Old"}',
  }
  it('shows each one with its reasons and its JSON, and Discard calls onDiscard with its id', () => {
    const onDiscard = vi.fn()
    const p = props({ invalid: [invalid], onDiscard })
    const html = renderToStaticMarkup(createElement(CustomThemesPanel, p))
    expect(html).toContain('No longer valid')
    expect(html).toContain('The value of &quot;border-width&quot; is not allowed.')
    expect(html).toContain('{&quot;name&quot;:&quot;Old&quot;}')
    expect(html).toContain(' Old')
    press(byText(p, 'Discard'))
    expect(onDiscard).toHaveBeenCalledExactlyOnceWith('invalid-abc')
    expect(renderToStaticMarkup(createElement(CustomThemesPanel, props()))).not.toContain(
      'No longer valid',
    )
  })

  it('says when an import replaced a saved theme, and says nothing otherwise', () => {
    const html = renderToStaticMarkup(
      createElement(CustomThemesPanel, props({ notice: 'Replaced your saved theme "Moss".' })),
    )
    expect(html).toContain('role="status"')
    expect(html).toContain('Replaced your saved theme')
    expect(renderToStaticMarkup(createElement(CustomThemesPanel, props()))).not.toContain(
      'role="status"',
    )
  })
})

describe('ThemePicker with custom themes', () => {
  it('lists the built-ins then the custom ones, marks them Custom, and a press selects by id', () => {
    const c = mine('Alpha')
    const onSelect = vi.fn()
    const tree = elementsOf(ThemePicker({ currentId: 'zine', onSelect, customThemes: [c] }))
    const cards = tree.filter((e) => e.props['data-theme-id'] !== undefined)
    expect(cards.map((e) => e.props['data-theme-id'])).toEqual([
      'refined-terminal',
      'bbs-revival',
      'zine',
      c.id,
    ])
    const html = renderToStaticMarkup(
      ThemePicker({ currentId: 'zine', onSelect, customThemes: [c] }),
    )
    expect(html).toContain('>Custom<')
    expect(html.match(/>Selected</g)).toHaveLength(1)
    ;(cards[3]!.props['onClick'] as () => void)()
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(c.id)
  })
})
