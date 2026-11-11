// #53: Settings > Appearance at /appearance. Choosing a theme switches the page at once and keeps the
// choice in this browser (switchTheme). Needs no session: a theme is a local look, and the picker works
// before login too. Syncing the choice across devices is #366. The view has no hooks (a test calls it);
// the screen below it only holds the current id, read from the page so it is right even when storage is
// blocked.

import { useState } from 'react'
import { Link } from 'react-router'
import { appliedThemeId, browserStore, pickTheme } from '@/theme/applyTheme'
import { ThemePicker } from './ThemePicker'

export interface AppearanceViewProps {
  readonly currentId: string
  readonly onSelect: (id: string) => void
}

export function AppearanceView({ currentId, onSelect }: AppearanceViewProps) {
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Appearance</h1>
        <p className="text-sm text-muted-foreground">
          Pick a look. It changes right away and is kept in this browser.
        </p>
      </div>
      <ThemePicker currentId={currentId} onSelect={onSelect} />
      <Link
        to="/"
        className="inline-flex min-h-[1.5rem] items-center justify-center text-center text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to your groups
      </Link>
    </div>
  )
}

export function AppearanceScreen() {
  const [currentId, setCurrentId] = useState(() => appliedThemeId(document.documentElement))
  return (
    <AppearanceView
      currentId={currentId}
      onSelect={(id) => {
        setCurrentId(pickTheme(id, currentId, document.documentElement, browserStore()))
      }}
    />
  )
}
