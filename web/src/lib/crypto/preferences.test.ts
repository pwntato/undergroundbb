import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64'
import { bytesToHex } from './hex'
import {
  EMPTY_PREFERENCES_TEXT,
  MAX_PREFERENCES_BYTES,
  PreferencesTooLargeError,
  openPreferencesUnder,
  preferencesKey,
  resealPreferences,
  sealPreferencesUnder,
} from './preferences'
import type { LiveKeys } from './credential-material'

const key = (n: number) => new Uint8Array(32).fill(n)
const USER = '11111111-1111-4111-8111-111111111111'
const OTHER = '22222222-2222-4222-8222-222222222222'

describe('preferences sealing (#366)', () => {
  it('opens under the key it was sealed under and returns the exact text', async () => {
    const blob = await sealPreferencesUnder(key(1), USER, '{"v":1,"theme":"zine"}')
    expect(await openPreferencesUnder(key(1), USER, blob)).toBe('{"v":1,"theme":"zine"}')
  })

  it('does not open under another private key, another owner, or a damaged blob (null, never a throw)', async () => {
    const blob = await sealPreferencesUnder(key(1), USER, 'hello')
    expect(await openPreferencesUnder(key(2), USER, blob)).toBeNull()
    expect(await openPreferencesUnder(key(1), OTHER, blob)).toBeNull()
    const bytes = Uint8Array.from(atob(blob.ciphertext), (c) => c.charCodeAt(0))
    bytes[0] = bytes[0]! ^ 1
    expect(
      await openPreferencesUnder(key(1), USER, { ...blob, ciphertext: bytesToBase64(bytes) }),
    ).toBeNull()
  })

  it('derives a key that is neither the private key nor the same for two keys', () => {
    expect(preferencesKey(key(1))).not.toEqual(key(1))
    expect(preferencesKey(key(1))).not.toEqual(preferencesKey(key(2)))
    expect(preferencesKey(key(1))).toHaveLength(32)
  })

  it('derives exactly this key (a known answer: changing it makes every sealed blob unreadable)', () => {
    expect(bytesToHex(preferencesKey(new Uint8Array(32).fill(1)))).toBe(
      'f2a0e1725a99b7d98feeb0e3222aac04122c09dbda6cff5718101b0f47f9162f',
    )
  })

  it('uses a fresh nonce every time', async () => {
    const a = await sealPreferencesUnder(key(1), USER, 'x')
    const b = await sealPreferencesUnder(key(1), USER, 'x')
    expect(a.nonce).not.toBe(b.nonce)
  })

  it('refuses more plaintext than the server will take, and takes exactly the limit', async () => {
    await expect(
      sealPreferencesUnder(key(1), USER, 'a'.repeat(MAX_PREFERENCES_BYTES + 1)),
    ).rejects.toBeInstanceOf(PreferencesTooLargeError)
    const blob = await sealPreferencesUnder(key(1), USER, 'a'.repeat(MAX_PREFERENCES_BYTES))
    // 16-byte tag; the server's cap is 32 KiB of ciphertext.
    expect(atob(blob.ciphertext).length).toBeLessThanOrEqual(32 * 1024)
  })
})

describe('resealPreferences (key rotation)', () => {
  const keys = (n: number): LiveKeys =>
    ({ userId: USER, signingKey: {}, wrappingKey: { privateKey: key(n) } }) as unknown as LiveKeys

  it('moves the same text from the old key to the new one', async () => {
    const old = await sealPreferencesUnder(key(1), USER, '{"v":1,"theme":"zine"}')
    const next = await resealPreferences(keys(1), key(9), old)
    expect(await openPreferencesUnder(key(9), USER, next)).toBe('{"v":1,"theme":"zine"}')
    expect(await openPreferencesUnder(key(1), USER, next)).toBeNull()
  })

  it('replaces a blob that no longer opens with an empty document instead of failing the rotation', async () => {
    const lost = await sealPreferencesUnder(key(5), USER, 'unreadable')
    const next = await resealPreferences(keys(1), key(9), lost)
    expect(await openPreferencesUnder(key(9), USER, next)).toBe(EMPTY_PREFERENCES_TEXT)
  })
})
