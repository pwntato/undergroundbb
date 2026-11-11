import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from '@/App.tsx'
import '@/index.css'
import { applyTheme, browserStore, storedTheme } from '@/theme/applyTheme'

// Before the first render, so a saved theme is on the page as soon as the bundle runs. (The CSP
// forbids an inline script, so this cannot run any earlier than the bundle.)
applyTheme(storedTheme(browserStore()), document.documentElement)

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('root element not found')
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
