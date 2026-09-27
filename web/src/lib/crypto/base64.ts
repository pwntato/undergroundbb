// Standard, padded base64 -- the wire encoding every binary field in
// internal/handlers/register.go's decodeBase64Field expects
// (base64.StdEncoding, not URL-safe, padding required).

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i)
  }
  return out
}

/**
 * Base64url (RFC 4648 §5), unpadded -- used only for values embedded
 * directly in a URL fragment (currently just invite.ts's per-invite MAC
 * key), where standard base64's `+`, `/` and `=` would otherwise need
 * percent-encoding. Every OTHER binary field in this app still uses the
 * standard, padded alphabet above, matching
 * internal/handlers/*.go's decodeBase64Field.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const padLen = (4 - (padded.length % 4)) % 4
  return base64ToBytes(padded + '='.repeat(padLen))
}
