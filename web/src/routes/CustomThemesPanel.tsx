// Custom themes on the Appearance screen (#74): paste a theme as JSON, see exactly why one is refused,
// remove one, and copy the theme on the page out as JSON to edit. Hook-free, so a test presses the
// real buttons. What it accepts is decided in theme/customTheme.ts, never here.

import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { MAX_CUSTOM_THEMES, type CustomTheme } from '@/theme/customTheme'
import type { InvalidSavedTheme } from '@/theme/customThemes'

export interface CustomThemesPanelProps {
  readonly customs: readonly CustomTheme[]
  readonly importText: string
  readonly errors: readonly string[]
  /** Saved entries that no longer pass the rules. */
  readonly invalid: readonly InvalidSavedTheme[]
  /** What the last import did beyond adding (it replaced a saved theme), or null. */
  readonly notice: string | null
  readonly exportText: string | null
  readonly onImportText: (text: string) => void
  readonly onImport: () => void
  readonly onRemove: (id: string) => void
  readonly onDiscard: (id: string) => void
  readonly onExport: () => void
}

const BOX =
  'w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30'

export function CustomThemesPanel(p: CustomThemesPanelProps) {
  return (
    <section aria-labelledby="custom-themes" className="flex flex-col gap-3">
      <h2 id="custom-themes" className="text-lg font-medium">
        Custom themes
      </h2>
      <p className="text-sm text-muted-foreground">
        A theme is a small JSON object of colors, fonts and sizes. It is checked before it is used,
        can never contain CSS, and must keep text readable. Anything you leave out comes from
        Refined Terminal (mode dark) or Zine (mode light). You can keep {MAX_CUSTOM_THEMES}.
      </p>

      {p.customs.length > 0 && (
        <ul className="flex flex-col gap-2">
          {p.customs.map((t) => (
            <li key={t.id} className="flex items-center justify-between gap-2 text-sm">
              <span className="min-w-0 [overflow-wrap:anywhere]">{t.name}</span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  p.onRemove(t.id)
                }}
              >
                Remove
                <span className="sr-only">{` ${t.name}`}</span>
              </Button>
            </li>
          ))}
        </ul>
      )}

      {p.invalid.length > 0 && (
        <section aria-labelledby="invalid-themes" className="flex flex-col gap-2">
          <h3 id="invalid-themes" className="text-sm font-medium">
            No longer valid
          </h3>
          <p className="text-xs text-muted-foreground">
            These saved themes do not pass the current rules, so they are not listed above. They are
            kept until you discard them: copy the JSON, fix what is listed and import it again.
          </p>
          {p.invalid.map((i) => (
            <div key={i.id} className="flex flex-col gap-1.5 rounded-md border border-border p-2">
              <div className="flex items-center justify-between gap-2 text-sm">
                <span className="min-w-0 [overflow-wrap:anywhere]">{i.name}</span>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    p.onDiscard(i.id)
                  }}
                >
                  Discard
                  <span className="sr-only">{` ${i.name}`}</span>
                </Button>
              </div>
              <ul className="flex flex-col gap-0.5 text-xs text-destructive">
                {i.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
              <textarea
                aria-label={`The saved JSON of ${i.name}`}
                value={i.json}
                readOnly
                rows={5}
                spellCheck={false}
                className={BOX}
              />
            </div>
          ))}
        </section>
      )}

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="theme-json">Theme JSON</Label>
        <textarea
          id="theme-json"
          value={p.importText}
          onChange={(e) => {
            p.onImportText(e.target.value)
          }}
          rows={8}
          spellCheck={false}
          aria-invalid={p.errors.length > 0}
          aria-describedby={p.errors.length > 0 ? 'theme-json-errors' : undefined}
          placeholder='{"name": "My theme", "mode": "dark", "tokens": {"primary": "oklch(0.8 0.12 150)"}}'
          className={BOX}
        />
        {p.errors.length > 0 && (
          <ul
            id="theme-json-errors"
            role="alert"
            className="flex flex-col gap-1 text-sm text-destructive"
          >
            {p.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {p.notice !== null && (
          <p role="status" className="text-sm text-muted-foreground">
            {p.notice}
          </p>
        )}
        <Button
          type="button"
          className="self-start"
          disabled={p.importText.trim() === ''}
          onClick={p.onImport}
        >
          Import and use
        </Button>
      </div>

      <div className="flex flex-col gap-1.5">
        <Button type="button" variant="outline" className="self-start" onClick={p.onExport}>
          Show this theme as JSON
        </Button>
        {p.exportText !== null && (
          <>
            <Label htmlFor="theme-json-export">The theme on this page</Label>
            <textarea
              id="theme-json-export"
              value={p.exportText}
              readOnly
              rows={10}
              spellCheck={false}
              className={BOX}
            />
          </>
        )}
      </div>
    </section>
  )
}
