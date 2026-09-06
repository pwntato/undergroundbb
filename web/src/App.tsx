import { Button } from '@/components/ui/button'

/**
 * Application shell.
 *
 * Deliberately minimal: this milestone is a building frontend, not a product.
 * Routing, the crypto worker and real screens arrive with the features that
 * need them. The button exists only to prove the shadcn/ui pipeline and the
 * theme tokens resolve.
 */
function App() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
      <h1 className="font-mono text-2xl font-bold tracking-tight text-primary">UndergroundBB</h1>
      <p className="text-sm text-muted-foreground">Frontend scaffold. Nothing to see yet.</p>
      <Button variant="outline">Placeholder</Button>
    </main>
  )
}

export default App
