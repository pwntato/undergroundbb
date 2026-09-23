// User uuid generation, matching internal/idgen/idgen.go's UUID/ValidUUID
// shape exactly: lowercase RFC 4122 version 4.
//
// Issue #123 made the user uuid client-generated (POST /api/auth/register's
// UserID field is sent as-is, not assigned by the server) specifically so it
// exists before signup wraps the private keys under it via
// credentialWrapAAD -- see worker.ts's generateSignupMaterial.

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/**
 * Generates a fresh user uuid via the platform CSPRNG (crypto.randomUUID,
 * available in every environment this app runs in -- main thread and Web
 * Worker alike -- and already RFC 4122 v4 lowercase by spec, the same shape
 * idgen.UUID() produces). Validated against UUID_PATTERN before returning
 * rather than trusted blindly, matching this codebase's general preference
 * for pinning a wire shape with a check rather than assuming a platform API
 * behaves as documented forever.
 */
export function generateUserID(): string {
  const id = crypto.randomUUID()
  if (!isValidUserID(id)) {
    throw new Error('crypto: crypto.randomUUID() produced an unexpected shape')
  }
  return id
}

/** Reports whether s is a well-formed, lowercase RFC 4122 v4 uuid. */
export function isValidUserID(s: string): boolean {
  return UUID_PATTERN.test(s)
}
