# Theming guide

A theme is a JSON object of design token values. It is never a stylesheet. This guide covers the built-in themes, every token and its allowed range, how to write and import a custom theme, the accessibility floor a theme must clear, and how your choice follows you between devices.

Themes are the lowest-barrier way to contribute to the project: a theme touches no application logic.

The design rationale lives in [DESIGN.md](DESIGN.md) ("Theming", "Custom themes (#74)", "The choice follows the user (#366)"). The reason themes are JSON and not CSS is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Built-in themes

| Theme | Mode | Character |
| --- | --- | --- |
| Refined Terminal (default) | dark | Cool dark blues, teal accent, soft shadows, small radii. |
| BBS Revival | dark | Box-drawing look: `double` borders at 3px, dense spacing, square corners, flat. |
| Zine | light | Bone paper, photocopy black, one red. Hard offset shadows, zero radius, thick borders, uppercase tracked headings. |

Pick one at `/appearance`. The page works without signing in, and it is also the last step of signup. The sources are in `web/src/theme/themes/`.

## Tokens

Every token is a CSS custom property named `--ubb-<token>`. A theme sets values only; components read them through ordinary Tailwind utilities. The list is `web/src/theme/tokens.ts`, and `web/src/index.css` must default every entry (a test fails if the two drift).

A theme may omit any token. An omitted token comes from the built-in theme of the same mode: Refined Terminal for `dark`, Zine for `light`.

### Colors (19)

Written as `oklch(L C H)`: lightness `L` from 0 to 1, chroma `C` from 0 to 0.5, hue `H` from 0 to 360. Nothing else is accepted (no hex, `rgb()`, `hsl()`, named colors or alpha).

| Token | Used for |
| --- | --- |
| `background` | The page. |
| `foreground` | Body text. |
| `muted`, `muted-foreground` | Quiet blocks and secondary text. |
| `surface`, `surface-foreground` | Panels. |
| `card`, `card-foreground` | Cards. |
| `border` | The quiet divider line. |
| `input` | The edge of a form control. |
| `ring` | The keyboard focus ring. |
| `primary`, `primary-foreground` | Buttons, links and accent text. |
| `accent`, `accent-foreground` | Hovered items. |
| `secondary`, `secondary-foreground` | Secondary buttons and blocks. |
| `destructive`, `destructive-foreground` | Errors and destructive actions. |

### Fonts (3)

`font-sans`, `font-mono`, `font-heading`. A comma-separated list of up to ten names, 300 characters at most. Each name must be a generic family (`serif`, `sans-serif`, `monospace`, `system-ui`, `ui-serif`, `ui-sans-serif`, `ui-monospace`, `ui-rounded`) or a family on the allowlist. The allowlist is the curated list in `web/src/theme/customTheme.ts` (`CURATED_FONTS`: Arial, Helvetica, Verdana, Georgia, Menlo, Consolas, Roboto, Inter, JetBrains Mono, Impact and others) plus every family the built-in themes use. Names are matched without regard to case and written back quoted.

It is an allowlist because an installed symbol font such as Wingdings would turn every label into pictures, and no color check can see that. No web fonts load: the Content-Security-Policy has no `font-src`, so a font only shows if the reader's system has it. List fallbacks.

`font-heading` alone may also be exactly `var(--ubb-font-sans)` (headings follow the body font). That is the only `var()` allowed.

### Lengths

Written as a number with `px`, `rem` or `em` (a bare `0` is allowed). No negative numbers, `calc()` or percentages. 1rem = 1em = 16px.

| Token | Allowed range |
| --- | --- |
| `radius-sm`, `radius-md`, `radius-lg`, `radius-xl` | 0 to 32px |
| `border-width` | 1 to 4px (it draws every form control's edge, so it cannot be 0) |
| `border-width-strong` | 0 to 12px (cards and alerts) |
| `spacing` | 0.15 to 0.375rem (the unit every `p-*`, `m-*` and `gap-*` multiplies; the built-ins use 0.25rem) |
| `tracking-heading`, `tracking-body` | 0 to 0.3em (letter-spacing) |

### Border style

`border-style`: one of `solid`, `dashed`, `dotted`, `double`. A `double` rule only draws from 3px, so pair it with a `border-width-strong` of 3px or more (1px control borders stay single lines).

### Shadows (4)

`shadow-xs`, `shadow-sm`, `shadow-md`, `shadow-lg`. A comma-separated list of up to three terms, 300 characters at most. Each term is `x y blur [spread] color`:

- `x` and `y`: -40 to 40px
- `blur`: 0 to 60px
- `spread` (optional): -40 to 40px
- all in `px` only (no `rem` or `em`)
- `color`: `oklch(L C H)`, `oklch(L C H / alpha)` with alpha 0 to 1, or `transparent`
- no `inset`

For "no shadow" write `0 0 0 0 transparent`, never `none`. The focus ring shares one box-shadow list with these tokens, and `none` voids the whole list.

### Heading text (3)

- `case-heading`: `none`, `uppercase`, `lowercase` or `capitalize`.
- `tracking-heading` and `tracking-body`: see Lengths.

`case-heading: uppercase` requires a `tracking-heading` above zero, such as `0.08em`. Uppercase with no letter-spacing is hard to read, so a theme that does that is refused.

## Writing a custom theme

A custom theme is `{ "name", "mode", "tokens" }`:

```json
{
  "name": "Moss",
  "mode": "dark",
  "tokens": {
    "primary": "oklch(0.78 0.12 140)",
    "ring": "oklch(0.82 0.1 140)",
    "radius-md": "0.25rem"
  }
}
```

- `name`: 1 to 40 characters, starting with a letter or number; letters, numbers, spaces and `. _ ' -` after that. The same name in any case replaces the saved theme of that name (the screen says so).
- `mode`: `dark` or `light`. It sets `<html data-theme>`, which the vendored components' `dark:` styles key off, and chooses which built-in fills in omitted tokens.
- `tokens`: an object of token values. Unknown tokens, unknown top-level fields and anything outside the grammar above are refused.
- The whole JSON is at most 8192 characters (a full theme is about 2 KB).

The easiest start is to open `/appearance`, press "Show this theme as JSON" on a built-in, copy it, and edit. Then paste your JSON into the box and press "Import and use". A refused theme lists every reason, not just the first.

Each value is parsed into parts and the string given to the page is rebuilt from those parts, so what is applied is never your text. No `url()`, `calc()`, other `var()`, quote, `;`, brace or comment can get through.

Up to five custom themes are kept per browser.

## The accessibility floor

The theme you import is merged with the base for its mode, and the merged result must pass the same check the built-ins pass (`themeProblems` in `web/src/theme/themeChecks.ts`). A failing theme is refused, because unreadable text could also hide a warning or a key fingerprint.

- Text pairs hold WCAG AA at 4.5:1. The list is `TEXT_PAIRS` in `themeChecks.ts`: each foreground on every fill it can land on (page, card, surface, muted, accent, secondary, and `primary` and `destructive` text on those fills).
- The edge of a form control, `input`, holds 3:1 on the page and on a card. The quiet `border` divider is exempt.
- The focus ring holds 3:1 on the page and on a card, both solid and at the 50% halo the components draw.
- The heading pair rule above.

The app itself also keeps these for every theme: `prefers-reduced-motion: reduce` makes transitions effectively instant, and standalone links and checkbox or radio labels are at least 24px tall.

If a later release narrows a range, renames a token or adds a contrast pair, a saved theme that stops validating is kept, not deleted. `/appearance` lists it under "No longer valid" with the reasons and its JSON until you discard it.

## How the choice syncs

Before login the choice is a theme id in `localStorage` under `ubb.theme`. After login it follows you through the encrypted preferences blob. The server stores only ciphertext and never opens it. The blob holds `{"v":1,"theme":"<id>","customThemes":[...]}`, sealed in your browser under a key derived from your account key.

**The blob wins, and local seeds it.**

- At login, a blob that opens wins: its choice goes on the page and into `localStorage`. Custom themes are joined (the blob's first, capped at five).
- No blob, or one that does not open: this browser's choice seeds a new blob, so you keep your look and do not fall back to the default.
- After login every change is sent as you make it, last writer wins.
- A change that could not be sent (network, a stale key epoch after a rotation, no live keys after a reload) is flagged, and at the next login that browser's choice wins.
- A theme deleted on another device can come back from a browser that still holds it, until you remove it there too, because the saved lists are joined.
- A shared browser is safe: when a different account logs in, the previous account's themes and choice are wiped first, so custom theme names never cross accounts.
- At logout the saved custom themes are trimmed to the one in use, so user-written names do not stay in plaintext `localStorage`. They return from the blob at the next login.

## Contributing a built-in theme

A custom theme is personal. To propose one for everyone:

1. Start from an existing file in `web/src/theme/themes/` (`zine.ts` is the fullest example). A built-in must give a value for every token, with no extras.
2. Register it in `web/src/theme/themes/index.ts` (`BUILT_IN_THEMES`: `id`, `name`, `mode`, `tokens`).
3. Add a test like the neighbors (for example `zine.test.ts`) and run the web tests. `themeProblems` is the same check described above, and the neighbors' tests also pin their character (for example, Zine's light ground).
4. Open a pull request. Screenshots of the picker card and a busy screen help review.

Rules for built-ins beyond the custom grammar: no web fonts, and keep the destructive color distinguishable from the primary one.
