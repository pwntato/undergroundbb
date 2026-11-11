import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const getPreferences = vi.fn()
const putPreferences = vi.fn()
const seal = vi.fn()
const open = vi.fn()

vi.mock('@/lib/api/preferences', () => ({ getPreferences, putPreferences }))
vi.mock('@/lib/crypto/worker-client', () => ({
  sealPreferencesText: seal,
  openPreferencesBlob: open,
}))

const { attachThemeSync, notifyThemeChanged, onThemeSynced, startThemeSync, stopThemeSync } =
  await import('./themeSyncSession')

const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve()
}

beforeEach(() => {
  const data = new Map<string, string>([['ubb.theme', 'zine']])
  vi.stubGlobal('document', { documentElement: { style: { setProperty() {} }, setAttribute() {} } })
  vi.stubGlobal('window', {
    localStorage: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
    },
  })
  getPreferences.mockReset().mockResolvedValue({ keyEpoch: 4 })
  putPreferences.mockReset().mockResolvedValue(undefined)
  seal
    .mockReset()
    .mockImplementation((_id: string, text: string) =>
      Promise.resolve({ nonce: 'n', ciphertext: text }),
    )
  open.mockReset()
})
afterEach(() => {
  stopThemeSync()
  vi.unstubAllGlobals()
})

describe('theme sync for the session', () => {
  it('sends nothing before login or after logout', async () => {
    notifyThemeChanged()
    await flush()
    expect(putPreferences).not.toHaveBeenCalled()
    await startThemeSync('user-1')
    stopThemeSync()
    putPreferences.mockClear()
    notifyThemeChanged()
    await flush()
    expect(putPreferences).not.toHaveBeenCalled()
  })

  it('a session restored with cold keys flags a change for the next login instead of dropping it', async () => {
    attachThemeSync('user-1')
    seal.mockRejectedValue(new Error('no live keys'))
    notifyThemeChanged()
    await flush()
    expect(putPreferences).not.toHaveBeenCalled()
    expect(window.localStorage.getItem('ubb.prefsDirty')).toBe('1')
  })

  it('after login a change seals for the signed-in account and names the key epoch', async () => {
    await startThemeSync('user-1')
    putPreferences.mockClear()
    notifyThemeChanged()
    await flush()
    expect(seal).toHaveBeenLastCalledWith('user-1', expect.stringContaining('"theme":"zine"'))
    expect(putPreferences).toHaveBeenCalledWith(4, expect.objectContaining({ nonce: 'n' }))
  })

  it('a burst of changes is sent one at a time and coalesced into one more send', async () => {
    await startThemeSync('user-1')
    putPreferences.mockClear()
    let release: () => void = () => undefined
    putPreferences.mockImplementationOnce(() => new Promise<void>((r) => (release = r)))
    notifyThemeChanged()
    await flush()
    notifyThemeChanged()
    notifyThemeChanged()
    await flush()
    expect(putPreferences).toHaveBeenCalledTimes(1) // the second and third wait for the first
    release()
    await flush()
    expect(putPreferences).toHaveBeenCalledTimes(2) // coalesced into one more
  })

  it('tells a listening screen when a login sync pushed or applied, and not after it unsubscribes', async () => {
    const heard = vi.fn()
    const off = onThemeSynced(heard)
    await startThemeSync('user-1') // no blob, a local choice: seeds it
    expect(heard).toHaveBeenCalledTimes(1)
    off()
    await startThemeSync('user-1')
    expect(heard).toHaveBeenCalledTimes(1)
  })
})
