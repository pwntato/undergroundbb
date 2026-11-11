// Signup's finish step (#33), now the real picker (#53): the same ThemePicker as Settings > Appearance.
// Choosing applies the theme at once, so Continue simply moves on with whatever is showing, and doing
// nothing keeps the default.

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { switchTheme, browserStore, storedTheme } from '@/theme/applyTheme'
import { ThemePicker } from './ThemePicker'

export function ThemePickerStep({ onDone }: { onDone: () => void }) {
  const [currentId, setCurrentId] = useState(() => storedTheme(browserStore()).id)
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Pick a look</h1>
        <p className="text-sm text-muted-foreground">You can change this later under Appearance.</p>
      </div>
      <ThemePicker
        currentId={currentId}
        onSelect={(id) => {
          if (switchTheme(id, document.documentElement, browserStore())) setCurrentId(id)
        }}
      />
      <Button onClick={onDone}>Continue</Button>
    </div>
  )
}
