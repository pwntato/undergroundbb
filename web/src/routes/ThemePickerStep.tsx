// Signup's finish step -- #33: "theme picker as a light, skippable finish."
//
// Stub, not the real M5 theming work: none of the three named themes exist
// yet (index.css is still an explicit placeholder; #48's token vocabulary
// and #49-51's actual themes are separate work). One real option (today's
// placeholder/default styling) plus two visibly-disabled "coming soon"
// entries for BBS Revival and Zine, so the screen's shape matches what #33
// asks for without pulling M5 forward. Selection is saved to localStorage
// only -- there is no server-side preferences store yet (#52,
// encrypted-profile persistence, is what would carry this across devices).
// Superseded once #48/#49-51/#52 land.

import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

const THEME_STORAGE_KEY = 'ubb.theme-picker.selection'

interface ThemeOption {
  readonly id: string
  readonly name: string
  readonly description: string
  readonly available: boolean
}

const THEME_OPTIONS: readonly ThemeOption[] = [
  { id: 'default', name: 'Refined Terminal', description: 'The default look.', available: true },
  { id: 'bbs-revival', name: 'BBS Revival', description: 'Coming soon.', available: false },
  { id: 'zine', name: 'Zine', description: 'Coming soon.', available: false },
]

function saveSelection(themeId: string): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, themeId)
  } catch {
    // Best-effort only -- see SessionContext.tsx's neighbor reasoning:
    // a private window or blocked storage must not break signup completion.
  }
}

export function ThemePickerStep({ onDone }: { onDone: () => void }) {
  return (
    <div className="flex w-full max-w-md flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Pick a look</h1>
        <p className="text-sm text-muted-foreground">You can change this later.</p>
      </div>
      <div className="flex flex-col gap-3">
        {THEME_OPTIONS.map((theme) => (
          <Card key={theme.id} className={theme.available ? '' : 'opacity-50'}>
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-base">
                {theme.name}
                {theme.available ? (
                  <Button
                    size="sm"
                    onClick={() => {
                      saveSelection(theme.id)
                      onDone()
                    }}
                  >
                    Select
                  </Button>
                ) : (
                  <span className="text-xs text-muted-foreground">Coming soon</span>
                )}
              </CardTitle>
              <CardDescription>{theme.description}</CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>
      <Button variant="outline" onClick={onDone}>
        Skip for now
      </Button>
    </div>
  )
}
