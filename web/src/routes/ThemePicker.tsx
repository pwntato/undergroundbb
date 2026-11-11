// The theme picker (#53): one card per built-in theme with a live sample drawn in that theme, and the
// chosen one marked. Choosing applies it at once (the caller's onSelect). No hooks, so a test can call
// it as a function and press the real buttons. Used by the Appearance screen and the signup finish step.

import { BUILT_IN_THEMES } from '@/theme/themes'
import { cn } from '@/lib/utils'
import { themePreviewStyles } from './themePreview'

export interface ThemePickerProps {
  /** The id of the theme on the page now. */
  readonly currentId: string
  readonly onSelect: (id: string) => void
}

export function ThemePicker({ currentId, onSelect }: ThemePickerProps) {
  return (
    <div role="group" aria-label="Theme" className="flex w-full flex-col gap-3">
      {BUILT_IN_THEMES.map((theme) => {
        const selected = theme.id === currentId
        const sample = themePreviewStyles(theme)
        return (
          <button
            key={theme.id}
            type="button"
            aria-pressed={selected}
            data-theme-id={theme.id}
            onClick={() => {
              onSelect(theme.id)
            }}
            className={cn(
              'flex flex-col gap-2 rounded-lg border border-input bg-card p-3 text-left text-card-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50',
              selected && 'ring-2 ring-primary',
            )}
          >
            <span className="flex items-center justify-between text-sm font-medium">
              {theme.name}
              <span className="text-xs text-muted-foreground">{selected ? 'Selected' : 'Use'}</span>
            </span>
            <span aria-hidden="true" style={sample.frame}>
              <span style={sample.heading}>Sample heading</span>
              <span style={sample.body}>A line of a thread, the way it will read.</span>
              <span style={sample.button}>Reply</span>
            </span>
          </button>
        )
      })}
    </div>
  )
}
