// Signup's finish step (#33), now the real picker (#53): the same ThemePicker as Settings > Appearance.
// Choosing applies the theme at once, so Continue simply moves on with whatever is showing, and doing
// nothing keeps the default. The view has no hooks (a test calls it and presses the real buttons); the
// screen below it only holds the current id.

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { appliedThemeId, browserStore, pickTheme } from '@/theme/applyTheme'
import { loadCustomThemes } from '@/theme/customThemes'
import type { BuiltInTheme } from '@/theme/themes'
import { ThemePicker } from './ThemePicker'

export interface ThemePickerStepViewProps {
  readonly currentId: string
  /** Themes the person imported before signing up (#74): listed, and a selected one is marked. */
  readonly customThemes?: readonly BuiltInTheme[]
  readonly onSelect: (id: string) => void
  readonly onDone: () => void
}

export function ThemePickerStepView({
  currentId,
  customThemes = [],
  onSelect,
  onDone,
}: ThemePickerStepViewProps) {
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Pick a look</h1>
        <p className="text-sm text-muted-foreground">You can change this later under Appearance.</p>
      </div>
      <ThemePicker currentId={currentId} onSelect={onSelect} customThemes={customThemes} />
      <Button onClick={onDone}>Continue</Button>
    </div>
  )
}

export function ThemePickerStep({ onDone }: { onDone: () => void }) {
  // Imported on /appearance before signing up, so they may be on the page already.
  const [customThemes] = useState(() => loadCustomThemes(browserStore()))
  const [currentId, setCurrentId] = useState(() =>
    appliedThemeId(document.documentElement, customThemes),
  )
  return (
    <ThemePickerStepView
      currentId={currentId}
      customThemes={customThemes}
      onSelect={(id) => {
        setCurrentId(pickTheme(id, currentId, document.documentElement, browserStore()))
      }}
      onDone={onDone}
    />
  )
}
