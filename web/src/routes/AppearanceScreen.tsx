// #53: Settings > Appearance at /appearance. Choosing a theme switches the page at once and keeps the
// choice in this browser (switchTheme). Needs no session: a theme is a local look, and the picker works
// before login too. Syncing the choice across devices is #366.

import { useState } from 'react'
import { Link } from 'react-router'
import { switchTheme, browserStore, storedTheme } from '@/theme/applyTheme'
import { ThemePicker } from './ThemePicker'

export function AppearanceScreen() {
  const [currentId, setCurrentId] = useState(() => storedTheme(browserStore()).id)
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Appearance</h1>
        <p className="text-sm text-muted-foreground">
          Pick a look. It changes right away and is kept in this browser.
        </p>
      </div>
      <ThemePicker
        currentId={currentId}
        onSelect={(id) => {
          if (switchTheme(id, document.documentElement, browserStore())) setCurrentId(id)
        }}
      />
      <Link to="/" className="text-center text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </div>
  )
}
