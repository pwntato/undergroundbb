# UndergroundBB — web

React + TypeScript + Vite SPA. All cryptography happens here: the browser holds
the private keys, and the server only ever sees ciphertext and public keys.

## Requirements

Node 24 (pinned in `.node-version`; `fnm use` picks it up).

## Commands

```sh
npm install
npm run dev          # dev server on :5173, proxying /api to localhost:3000
npm run typecheck    # tsc, no emit
npm run lint         # oxlint
npm run format       # prettier --write
npm run build        # typecheck + production build to dist/
```

Run the Go API alongside it with `go run ./cmd/local` from the repository root.

## Layout

- `src/components/ui/` — shadcn/ui components, vendored into the repo rather
  than imported from a dependency, so they can be restyled freely
- `src/lib/` — shared helpers
- `src/index.css` — Tailwind entry point and the theme tokens

## Theming

Tailwind reads every color, font, radius and shadow from CSS custom properties
declared in `src/index.css`, not from a hardcoded palette. A theme is therefore
a set of custom property overrides and needs no changes to component markup.
The values currently in place are a neutral placeholder; the real design system
(Refined Terminal, BBS Revival and Zine) lands in the design milestone.

## TypeScript

Strict mode plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.
This is deliberate: the type system is load-bearing here, because handing a
`Uint8Array` containing the wrong key to the wrong function is precisely the
mistake that types can catch and tests often will not.
