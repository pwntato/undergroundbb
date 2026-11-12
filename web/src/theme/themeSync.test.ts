import { describe, expect, it } from 'vitest'
import { THEME_ID_ATTRIBUTE, THEME_STORAGE_KEY } from './applyTheme'
import {
  CUSTOM_THEMES_KEY,
  addCustomTheme,
  loadCustomThemes,
  readSavedThemes,
} from './customThemes'
import { exportThemeJson as exportJson, validateCustomTheme, type CustomTheme } from './customTheme'
import { encodePreferences, type Preferences } from './preferences'
import {
  PREFS_OWNER_KEY,
  markPrefsDirty,
  prefsDirtyKey,
  localPreferences,
  pushLocal,
  syncAtLogin,
  type ThemeSyncDeps,
  type WireBlob,
} from './themeSync'

function make(name: string, over: Record<string, string> = {}): CustomTheme {
  const r = validateCustomTheme(JSON.stringify({ name, mode: 'dark', tokens: over }))
  if (!r.ok) throw new Error(r.errors.join())
  return r.theme
}

/** The server and the worker in one: a blob is "sealed" as its text, and OPEN_FAILS makes it not open. */
const ME = 'user-me'
const DIRTY = prefsDirtyKey(ME)

function world(
  opts: { blob?: string | null; epoch?: number; local?: Record<string, string> } = {},
) {
  const data = new Map(Object.entries(opts.local ?? {}))
  const attrs = new Map<string, string>()
  const style = new Map<string, string>()
  const s = {
    blob: opts.blob === undefined || opts.blob === null ? null : opts.blob,
    epoch: opts.epoch ?? 0,
    writes: [] as { epoch: number; text: string }[],
    liveKeys: true,
    readFails: false,
    writeFails: false,
    opens: true,
  }
  const deps: ThemeSyncDeps = {
    userId: ME,
    target: {
      style: { setProperty: (n, v) => void style.set(n, v) },
      setAttribute: (n, v) => void attrs.set(n, v),
    },
    store: { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v) },
    read: () => {
      if (s.readFails) return Promise.reject(new Error('offline'))
      return Promise.resolve({
        keyEpoch: s.epoch,
        ...(s.blob === null ? {} : { preferencesBlob: { nonce: 'n', ciphertext: s.blob } }),
      })
    },
    write: (epoch, blob: WireBlob) => {
      if (s.writeFails) return Promise.reject(new Error('409'))
      s.writes.push({ epoch, text: blob.ciphertext })
      s.blob = blob.ciphertext
      return Promise.resolve()
    },
    seal: (text) =>
      s.liveKeys
        ? Promise.resolve({ nonce: 'n', ciphertext: text })
        : Promise.reject(new Error('no keys')),
    open: (blob) =>
      !s.liveKeys
        ? Promise.reject(new Error('no keys'))
        : Promise.resolve(s.opens ? blob.ciphertext : null),
  }
  return { s, data, attrs, style, deps }
}

const doc = (p: Preferences) => encodePreferences(p)

describe('syncAtLogin: the blob wins, this browser seeds it', () => {
  it("puts the blob's theme on the page and in storage, replacing the browser's own choice", async () => {
    const w = world({
      blob: doc({ themeId: 'bbs-revival', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine' },
    })
    expect(await syncAtLogin(w.deps)).toBe('applied')
    expect(w.attrs.get(THEME_ID_ATTRIBUTE)).toBe('bbs-revival')
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('bbs-revival')
    expect(w.s.writes).toHaveLength(0)
  })

  it('brings a custom theme from the blob and applies it when it is the choice', async () => {
    const mine = make('Mine', { primary: 'oklch(0.8 0.1 150)' })
    const w = world({ blob: doc({ themeId: mine.id, customs: [mine] }) })
    expect(await syncAtLogin(w.deps)).toBe('applied')
    expect(loadCustomThemes(w.deps.store).map((t) => t.name)).toEqual(['Mine'])
    expect(w.attrs.get(THEME_ID_ATTRIBUTE)).toBe(mine.id)
    expect(w.style.get('--ubb-primary')).toBe(mine.tokens['primary'])
  })

  it('keeps a custom theme made here, joins it into the blob and sends the join', async () => {
    const here = make('Here')
    const there = make('There')
    const w = world({ blob: doc({ themeId: 'zine', customs: [there] }) })
    addCustomTheme(here, w.deps.store)
    expect(await syncAtLogin(w.deps)).toBe('applied')
    expect(loadCustomThemes(w.deps.store).map((t) => t.name)).toEqual(['There', 'Here'])
    expect(w.s.writes).toHaveLength(1)
    expect(JSON.parse(w.s.writes[0]!.text).customThemes).toHaveLength(2)
  })

  it("keeps a saved theme that no longer validates, which is the person's to fix", async () => {
    const stale = { name: 'Old', mode: 'dark', tokens: { primary: 'not a colour' } }
    const w = world({
      blob: doc({ themeId: 'zine', customs: [make('There')] }),
      local: { [CUSTOM_THEMES_KEY]: JSON.stringify([stale]) },
    })
    await syncAtLogin(w.deps)
    expect(readSavedThemes(w.deps.store).invalid.map((i) => i.name)).toEqual(['Old'])
    expect(loadCustomThemes(w.deps.store).map((t) => t.name)).toEqual(['There'])
  })

  it('seeds a missing blob from this browser, naming the key epoch it read', async () => {
    const w = world({ epoch: 3, local: { [THEME_STORAGE_KEY]: 'zine' } })
    expect(await syncAtLogin(w.deps)).toBe('pushed')
    expect(w.s.writes).toHaveLength(1)
    expect(w.s.writes[0]!.epoch).toBe(3)
    expect(JSON.parse(w.s.writes[0]!.text)).toMatchObject({ v: 1, theme: 'zine' })
  })

  it('sends nothing for a browser with no choice and no blob', async () => {
    const w = world()
    expect(await syncAtLogin(w.deps)).toBe('unchanged')
    expect(w.s.writes).toHaveLength(0)
  })

  it('a blob that does not open (a keypair change) falls back to the LOCAL choice, not the default, and rewrites it', async () => {
    const w = world({ blob: 'sealed under an old key', local: { [THEME_STORAGE_KEY]: 'zine' } })
    w.s.opens = false
    expect(await syncAtLogin(w.deps)).toBe('pushed')
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('zine')
    expect(JSON.parse(w.s.blob!)).toMatchObject({ v: 1, theme: 'zine' })
  })

  it("a damaged document is replaced by this browser's choice", async () => {
    const w = world({ blob: 'not json', local: { [THEME_STORAGE_KEY]: 'zine' } })
    expect(await syncAtLogin(w.deps)).toBe('pushed')
    expect(JSON.parse(w.s.blob!)).toMatchObject({ theme: 'zine' })
  })

  it('leaves a blob from a newer release alone', async () => {
    const newer = '{"v":2,"theme":"future"}'
    const w = world({ blob: newer, local: { [THEME_STORAGE_KEY]: 'zine' } })
    expect(await syncAtLogin(w.deps)).toBe('left-alone')
    expect(w.s.blob).toBe(newer)
    expect(w.s.writes).toHaveLength(0)
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('never lets blob text reach the page unvalidated: a theme with CSS in it is dropped', async () => {
    const evil = JSON.stringify({
      v: 1,
      theme: 'custom-evil',
      customThemes: [
        {
          name: 'Evil',
          mode: 'dark',
          tokens: { primary: 'red; background: url(https://evil.example/x)' },
        },
      ],
    })
    const w = world({ blob: evil, local: { [THEME_STORAGE_KEY]: 'zine' } })
    await syncAtLogin(w.deps)
    expect(loadCustomThemes(w.deps.store)).toEqual([])
    expect(w.data.get(CUSTOM_THEMES_KEY) ?? '').not.toContain('evil.example')
    for (const v of w.style.values()) expect(v).not.toContain('evil.example')
    expect(w.attrs.get(THEME_ID_ATTRIBUTE)).not.toBe('custom-evil')
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('failures never throw and leave this browser as it was', async () => {
    const down = world({ local: { [THEME_STORAGE_KEY]: 'zine' } })
    down.s.readFails = true
    expect(await syncAtLogin(down.deps)).toBe('failed')
    const cold = world({
      blob: doc({ themeId: 'bbs-revival', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine' },
    })
    cold.s.liveKeys = false
    expect(await syncAtLogin(cold.deps)).toBe('failed')
    expect(cold.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })
})

describe('changes while signed in', () => {
  it('a change is sent whole (last writer wins, so a removal propagates)', async () => {
    const w = world({ epoch: 1, blob: doc({ themeId: 'zine', customs: [make('Gone')] }) })
    expect(await pushLocal(w.deps)).toBe('pushed')
    expect(JSON.parse(w.s.writes[0]!.text).customThemes).toEqual([])
    expect(w.s.writes[0]!.epoch).toBe(1)
  })

  it('a change that cannot be sent is flagged, and at the next login THIS browser wins', async () => {
    const w = world({
      blob: doc({ themeId: 'bbs-revival', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine' },
    })
    w.s.liveKeys = false // signed in after a reload: the worker has no keys
    expect(await pushLocal(w.deps)).toBe('failed')
    expect(w.data.get(DIRTY)).toBe('1')

    w.s.liveKeys = true // the next login
    expect(await syncAtLogin(w.deps)).toBe('pushed')
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('zine')
    expect(JSON.parse(w.s.blob!)).toMatchObject({ theme: 'zine' })
    expect(w.data.get(DIRTY)).toBe('0')
  })

  it('a change made while the server cannot be reached is flagged too', async () => {
    const w = world({ local: { [THEME_STORAGE_KEY]: 'zine' } })
    w.s.readFails = true
    expect(await pushLocal(w.deps)).toBe('failed')
    expect(w.data.get(DIRTY)).toBe('1')
  })

  it('a send refused for a stale key epoch is flagged, not lost', async () => {
    const w = world({ local: { [THEME_STORAGE_KEY]: 'zine' } })
    w.s.writeFails = true
    expect(await pushLocal(w.deps)).toBe('failed')
    expect(w.data.get(DIRTY)).toBe('1')
  })

  it('a clean login does not leave the flag set', async () => {
    const w = world({
      blob: doc({ themeId: 'zine', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine' },
    })
    expect(await syncAtLogin(w.deps)).toBe('unchanged')
    expect(w.data.get(DIRTY)).toBeUndefined()
  })
})

describe('localPreferences', () => {
  it('ignores a stored id that names no theme', () => {
    const w = world({ local: { [THEME_STORAGE_KEY]: 'gone' } })
    expect(localPreferences(w.deps.store).themeId).toBeNull()
  })
})

describe("a shared browser: another account's state is never this account's (#366 review)", () => {
  const ALICE = 'user-alice'
  const alice = make('Alice Secret')
  const aliceState = (extra: Record<string, string> = {}) => ({
    [PREFS_OWNER_KEY]: ALICE,
    [THEME_STORAGE_KEY]: alice.id,
    [CUSTOM_THEMES_KEY]: JSON.stringify([JSON.parse(exportJson(alice))]),
    ...extra,
  })
  const everythingSent = (w: ReturnType<typeof world>) => w.s.writes.map((x) => x.text).join('\n')

  it("Alice's dirty flag does not make her choice win over the new account's blob, and nothing of hers is sent", async () => {
    const w = world({
      blob: doc({ themeId: 'zine', customs: [] }),
      local: aliceState({ [prefsDirtyKey(ALICE)]: '1' }),
    })
    await syncAtLogin(w.deps)
    expect(w.attrs.get(THEME_ID_ATTRIBUTE)).toBe('zine')
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('zine')
    expect(everythingSent(w)).not.toContain('Alice Secret')
    expect(loadCustomThemes(w.deps.store)).toEqual([])
    expect(w.data.get(PREFS_OWNER_KEY)).toBe(ME)
  })

  it("without a flag, Alice's custom themes are not joined into the new account's blob", async () => {
    const w = world({ blob: doc({ themeId: 'zine', customs: [] }), local: aliceState() })
    await syncAtLogin(w.deps)
    expect(everythingSent(w)).not.toContain('Alice Secret')
    expect(JSON.parse(w.s.blob!).customThemes).toEqual([])
    expect(loadCustomThemes(w.deps.store)).toEqual([])
  })

  it("an account with no blob yet is not seeded from Alice's state, and her look leaves the page", async () => {
    const w = world({ local: aliceState() })
    w.attrs.set(THEME_ID_ATTRIBUTE, alice.id)
    expect(await syncAtLogin(w.deps)).toBe('unchanged')
    expect(w.s.writes).toHaveLength(0)
    expect(w.attrs.get(THEME_ID_ATTRIBUTE)).toBe('refined-terminal')
    expect(localPreferences(w.deps.store)).toEqual({ themeId: null, customs: [] })
    expect(w.data.get(CUSTOM_THEMES_KEY)).toBe('[]')
  })

  it("Alice's saved themes that no longer validate are wiped too", async () => {
    const stale = { name: 'Old Alice', mode: 'dark', tokens: { primary: 'not a colour' } }
    const w = world({ local: aliceState({ [CUSTOM_THEMES_KEY]: JSON.stringify([stale]) }) })
    await syncAtLogin(w.deps)
    expect(readSavedThemes(w.deps.store).invalid).toEqual([])
  })

  it('wipes even when the server cannot be reached', async () => {
    const w = world({ local: aliceState() })
    w.s.readFails = true
    expect(await syncAtLogin(w.deps)).toBe('failed')
    expect(loadCustomThemes(w.deps.store)).toEqual([])
  })

  it('a later change by the new account is sent without her themes', async () => {
    const w = world({ blob: doc({ themeId: 'zine', customs: [] }), local: aliceState() })
    await syncAtLogin(w.deps)
    expect(await pushLocal(w.deps)).toBe('pushed')
    expect(everythingSent(w)).not.toContain('Alice Secret')
  })

  it('a send while the browser still belongs to another account is refused', async () => {
    const w = world({ local: aliceState() })
    expect(await pushLocal(w.deps)).toBe('failed')
    expect(w.s.writes).toHaveLength(0)
    expect(w.data.get(CUSTOM_THEMES_KEY)).toContain('Alice Secret')
  })

  it('the same account keeps joining (an unset owner is a browser that never synced, the same owner is itself)', async () => {
    for (const owner of [{}, { [PREFS_OWNER_KEY]: ME }]) {
      const here = make('Here')
      const w = world({ blob: doc({ themeId: 'zine', customs: [make('There')] }), local: owner })
      addCustomTheme(here, w.deps.store)
      await syncAtLogin(w.deps)
      expect(loadCustomThemes(w.deps.store).map((t) => t.name)).toEqual(['There', 'Here'])
      expect(w.data.get(PREFS_OWNER_KEY)).toBe(ME)
    }
  })

  it("another account's dirty flag is not this account's", async () => {
    const w = world({
      blob: doc({ themeId: 'bbs-revival', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine', [prefsDirtyKey(ALICE)]: '1' },
    })
    await syncAtLogin(w.deps)
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('bbs-revival')
  })
})

describe('a change made while the login sync is still running (#366 review)', () => {
  it("is kept by the merge instead of being put back to the blob's choice, then sent", async () => {
    const w = world({
      blob: doc({ themeId: 'bbs-revival', customs: [] }),
      local: { [THEME_STORAGE_KEY]: 'zine' },
    })
    const realOpen = w.deps.open
    // The person picks Refined Terminal while the blob is being opened.
    const deps: ThemeSyncDeps = {
      ...w.deps,
      open: async (blob) => {
        w.data.set(THEME_STORAGE_KEY, 'refined-terminal')
        markPrefsDirty(w.deps.store, ME)
        return realOpen(blob)
      },
    }
    await syncAtLogin(deps)
    expect(w.data.get(THEME_STORAGE_KEY)).toBe('refined-terminal')
    expect(JSON.parse(w.s.blob!)).toMatchObject({ theme: 'refined-terminal' })
  })
})
