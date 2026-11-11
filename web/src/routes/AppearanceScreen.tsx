// #53: Settings > Appearance at /appearance. Choosing a theme switches the page at once and keeps the
// choice in this browser (switchTheme). Needs no session: a theme is a local look, and the picker works
// before login too; while signed in each change is also sent to the encrypted preferences blob (#366). Custom themes (#74) are imported here as
// JSON (CustomThemesPanel). The view has no hooks (a test calls it); the screen below it only holds the
// state that appearanceState.ts changes, read from the page so it is right even when storage is blocked.

import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { notifyThemeChanged, onThemeSynced } from '@/lib/session/themeSyncSession'
import { browserStore } from '@/theme/applyTheme'
import {
  initialAppearance,
  runDiscard,
  runExport,
  runImport,
  runRemove,
  runSelect,
  typeImport,
  type AppearanceEnv,
  type AppearanceState,
} from './appearanceState'
import { CustomThemesPanel } from './CustomThemesPanel'
import { ThemePicker } from './ThemePicker'

export interface AppearanceViewProps {
  readonly state: AppearanceState
  readonly onSelect: (id: string) => void
  readonly onImportText: (text: string) => void
  readonly onImport: () => void
  readonly onRemove: (id: string) => void
  readonly onDiscard: (id: string) => void
  readonly onExport: () => void
}

export function AppearanceView({ state, onSelect, ...custom }: AppearanceViewProps) {
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Appearance</h1>
        <p className="text-sm text-muted-foreground">
          Pick a look. It changes right away and is kept in this browser; signed in, it follows you
          to your other devices.
        </p>
      </div>
      <ThemePicker currentId={state.currentId} onSelect={onSelect} customThemes={state.customs} />
      <CustomThemesPanel
        customs={state.customs}
        importText={state.importText}
        errors={state.errors}
        invalid={state.invalid}
        notice={state.notice}
        exportText={state.exportText}
        {...custom}
      />
      <Link
        to="/"
        className="inline-flex min-h-[1.5rem] items-center justify-center text-center text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to your groups
      </Link>
    </div>
  )
}

function pageEnv(): AppearanceEnv {
  return { target: document.documentElement, store: browserStore(), onChange: notifyThemeChanged }
}

export function AppearanceScreen() {
  const [state, setState] = useState(() => initialAppearance(pageEnv()))
  // A login sync (#366) can change the page while this screen is open: read it again.
  useEffect(
    () =>
      onThemeSynced(() => {
        setState(initialAppearance(pageEnv()))
      }),
    [],
  )
  return (
    <AppearanceView
      state={state}
      onSelect={(id) => {
        setState((s) => runSelect(s, id, pageEnv()))
      }}
      onImportText={(text) => {
        setState((s) => typeImport(s, text))
      }}
      onImport={() => {
        setState((s) => runImport(s, pageEnv()))
      }}
      onRemove={(id) => {
        setState((s) => runRemove(s, id, pageEnv()))
      }}
      onDiscard={(id) => {
        setState((s) => runDiscard(s, id, pageEnv()))
      }}
      onExport={() => {
        setState((s) => runExport(s))
      }}
    />
  )
}
