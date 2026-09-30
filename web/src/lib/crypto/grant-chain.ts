// Client-side verification of a group's role-grant chain (#55, #56), against
// the data GET /api/groups/{id}/grants and GET /api/users/{id} serve. Pure:
// no fetching, no clock. The server is the party this protects against, so
// nothing here trusts a field just because the server wrote it.
//
// Rules (docs/DESIGN.md, "Roles and the chain of trust"):
//   - The anchor's own signature (TrustAnchor context) must verify, and the
//     root grant must be self-signed by the anchor's key, by the creator,
//     for admin, with no grantorGrantRef.
//   - Every other grant must be signed (RoleGrant context) by a key that
//     belonged to the grantor on the grant's UTC day, resolved from the
//     grantor's key history. The row's grantorSigningPublicKey is ignored:
//     nothing in the signed payload binds it, so it is server-chosen.
//   - The grantor must have held admin on that day: grantorGrantRef must be
//     the grantor's own grant that was current on the day, it must be admin,
//     and it must itself verify (recursively, to the root).
//   - STRICT same-day rule: if the grantor has any grant dated the same UTC
//     day as the signature, the role may have changed that day and the order
//     within a day is unknowable (the sort key's suffix is random), so the
//     signature is rejected. This fails safe and may flag a legitimate grant.
//   - Revocation is a later grant to a lower role (append-only history), so
//     walking the history covers #56 with no separate row.
//   - A member with no GRANT# row (added by invite) is baseline `member`.
//
// Known limit: leaving a group appends no grant, so a departed admin's last
// grant still says admin. Grants alone cannot show that they left.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { roleGrantPayload, trustAnchorPayload } from './group.js'

export type GrantRole = 'admin' | 'ambassador' | 'member'

/** A grant as served by GET /api/groups/{id}/grants. */
export interface GrantRecord {
  readonly sortKey: string
  readonly subjectUserId: string
  readonly grantedRole: string
  readonly grantorUserId: string
  /** Server-written hint; never used for verification. */
  readonly grantorSigningPublicKey?: string
  readonly grantorGrantRef?: string
  readonly signature: string
}

/** The anchor as served on every page of the grants response. */
export interface GrantAnchor {
  readonly creatorUserId: string
  readonly creatorSigningPublicKey: string
  readonly trustAnchorSignature: string
  readonly rootGrantSortKey: string
}

/** A user's signing keys as served by GET /api/users/{id}. */
export interface UserKeyHistory {
  readonly signingPublicKey: string
  readonly supersededSigningKeys: readonly {
    readonly publicKey: string
    readonly from: string
    readonly until?: string
  }[]
}

export interface GrantVerdict {
  readonly valid: boolean
  /** Why the grant was rejected; absent when valid. */
  readonly reason?: string
}

export interface GrantChainInput {
  readonly groupId: string
  readonly anchor: GrantAnchor
  readonly grants: readonly GrantRecord[]
  /** Key history per user id. A grantor missing here fails closed. */
  readonly keyHistories: ReadonlyMap<string, UserKeyHistory>
}

export interface GrantChainResult {
  readonly anchorValid: boolean
  readonly verdicts: ReadonlyMap<string, GrantVerdict>
  readonly grantsBySubject: ReadonlyMap<string, readonly GrantRecord[]>
}

export type RoleStatus =
  { readonly status: 'verified' } | { readonly status: 'unverified'; readonly reason: string }

const SORT_KEY = /^GRANT#([0-9a-f-]{36})#(\d{4}-\d{2}-\d{2})#[0-9a-f]{16}$/
const DAY_MS = 24 * 60 * 60 * 1000
const ROLES: readonly string[] = ['admin', 'ambassador', 'member']

interface ParsedKey {
  readonly subject: string
  readonly day: number
}

function parseSortKey(sortKey: string): ParsedKey | null {
  const m = SORT_KEY.exec(sortKey)
  if (!m) return null
  const day = Date.parse(`${m[2]}T00:00:00.000Z`)
  if (Number.isNaN(day)) return null
  return { subject: m[1]!, day }
}

function decode(b64: string | undefined): Uint8Array | null {
  if (!b64) return null
  try {
    return base64ToBytes(b64)
  } catch {
    return null
  }
}

/**
 * The keys a user held on the UTC day starting at dayStart. A superseded key
 * covers [from, until]; the current key covers everything after the latest
 * superseded key's until. A superseded key with a missing or unparseable
 * bound is dropped rather than guessed at (fails safe). A rotation on the
 * day itself yields two candidates, and a signature under either is accepted.
 */
function keysOnDay(history: UserKeyHistory, dayStart: number): Uint8Array[] {
  const dayEnd = dayStart + DAY_MS
  const out: Uint8Array[] = []
  let currentFrom = -Infinity
  for (const k of history.supersededSigningKeys) {
    const from = Date.parse(k.from)
    const until = k.until ? Date.parse(k.until) : NaN
    if (Number.isNaN(from) || Number.isNaN(until)) continue
    currentFrom = Math.max(currentFrom, until)
    if (from < dayEnd && until >= dayStart) {
      const key = decode(k.publicKey)
      if (key) out.push(key)
    }
  }
  if (currentFrom < dayEnd) {
    const key = decode(history.signingPublicKey)
    if (key) out.push(key)
  }
  return out
}

/** Verifies every grant in the history. Never throws on malformed input. */
export function verifyGrantChain(input: GrantChainInput): GrantChainResult {
  const { groupId, anchor, keyHistories } = input

  const anchorKey = decode(anchor.creatorSigningPublicKey)
  const anchorSig = decode(anchor.trustAnchorSignature)
  const anchorValid =
    anchorKey !== null &&
    anchorSig !== null &&
    verify(
      anchorKey,
      SigningContext.TrustAnchor,
      trustAnchorPayload(anchor.creatorUserId, anchorKey, groupId),
      anchorSig,
    )

  // A duplicate sort key is server misbehaviour; poison it rather than pick.
  const bySortKey = new Map<string, GrantRecord>()
  const duplicated = new Set<string>()
  const grantsBySubject = new Map<string, GrantRecord[]>()
  for (const g of input.grants) {
    if (bySortKey.has(g.sortKey)) duplicated.add(g.sortKey)
    bySortKey.set(g.sortKey, g)
    const list = grantsBySubject.get(g.subjectUserId) ?? []
    list.push(g)
    grantsBySubject.set(g.subjectUserId, list)
  }

  const verdicts = new Map<string, GrantVerdict>()

  const reject = (reason: string): GrantVerdict => ({ valid: false, reason })

  // Recursion terminates without a cycle guard: each hop moves to a grant on
  // a strictly earlier UTC day (the same-day rule rejects anything else), so
  // a chain can never revisit a grant.
  function verifyOne(g: GrantRecord): GrantVerdict {
    const cached = verdicts.get(g.sortKey)
    if (cached) return cached
    const verdict = compute(g)
    verdicts.set(g.sortKey, verdict)
    return verdict
  }

  function compute(g: GrantRecord): GrantVerdict {
    if (duplicated.has(g.sortKey)) return reject('duplicate grant sort key')
    const parsed = parseSortKey(g.sortKey)
    if (!parsed) return reject('malformed sort key')
    if (parsed.subject !== g.subjectUserId) return reject('sort key does not match subject')
    if (!ROLES.includes(g.grantedRole)) return reject('unknown role')
    const sig = decode(g.signature)
    if (!sig) return reject('malformed signature')
    const ref = g.grantorGrantRef ?? ''
    const payload = roleGrantPayload(groupId, g.subjectUserId, g.grantedRole, g.sortKey, ref)

    if (g.sortKey === anchor.rootGrantSortKey) {
      if (!anchorValid || anchorKey === null) return reject('trust anchor does not verify')
      if (g.subjectUserId !== anchor.creatorUserId || g.grantorUserId !== anchor.creatorUserId) {
        return reject('root grant is not self-signed by the creator')
      }
      if (g.grantedRole !== 'admin') return reject('root grant is not admin')
      if (ref !== '') return reject('root grant has a predecessor')
      if (!verify(anchorKey, SigningContext.RoleGrant, payload, sig)) {
        return reject('root signature does not verify under the anchor key')
      }
      return { valid: true }
    }

    // Non-root.
    if (g.grantorUserId === g.subjectUserId) return reject('non-root self-grant')
    if (ref === '') return reject('missing grantorGrantRef')
    const grantorGrants = grantsBySubject.get(g.grantorUserId) ?? []

    // The strict same-day rule, then "current on the day" = latest strictly
    // earlier day.
    let latestDay = -Infinity
    let latest: GrantRecord[] = []
    for (const other of grantorGrants) {
      const p = parseSortKey(other.sortKey)
      if (!p) continue
      if (p.day === parsed.day) return reject("grantor's role changed on the same UTC day")
      if (p.day > parsed.day) continue
      if (p.day > latestDay) {
        latestDay = p.day
        latest = [other]
      } else if (p.day === latestDay) {
        latest.push(other)
      }
    }
    if (latest.length === 0) return reject('grantor held no grant on the signing day')
    if (latest.length > 1) return reject("grantor's current grant is ambiguous (same-day tie)")
    const current = latest[0]!
    if (ref !== current.sortKey) return reject("grantorGrantRef is not the grantor's current grant")
    if (current.grantedRole !== 'admin') return reject('grantor was not admin on the signing day')
    if (!verifyOne(current).valid) return reject("grantor's own grant does not verify")

    const history = keyHistories.get(g.grantorUserId)
    if (!history) return reject('no key history for grantor')
    for (const key of keysOnDay(history, parsed.day)) {
      if (verify(key, SigningContext.RoleGrant, payload, sig)) return { valid: true }
    }
    return reject('signature does not verify under any key the grantor held on that day')
  }

  for (const g of input.grants) verifyOne(g)
  return { anchorValid, verdicts, grantsBySubject }
}

/**
 * Whether claimedRole (what the roster shows for userId) is backed by the
 * verified chain. No grant rows means baseline member (invite-added); with
 * grants, the subject's latest grant must verify and carry the claimed role.
 */
export function checkMemberRole(
  result: GrantChainResult,
  userId: string,
  claimedRole: string,
): RoleStatus {
  const grants = result.grantsBySubject.get(userId) ?? []
  if (grants.length === 0) {
    return claimedRole === 'member'
      ? { status: 'verified' }
      : { status: 'unverified', reason: `no grant backs role ${claimedRole}` }
  }
  let latestDay = -Infinity
  let latest: GrantRecord[] = []
  for (const g of grants) {
    const p = parseSortKey(g.sortKey)
    if (!p) return { status: 'unverified', reason: 'malformed sort key' }
    if (p.day > latestDay) {
      latestDay = p.day
      latest = [g]
    } else if (p.day === latestDay) {
      latest.push(g)
    }
  }
  if (latest.length > 1) return { status: 'unverified', reason: 'latest grant is ambiguous' }
  const g = latest[0]!
  const verdict = result.verdicts.get(g.sortKey)
  if (!verdict?.valid) {
    return { status: 'unverified', reason: verdict?.reason ?? 'grant not verified' }
  }
  if (g.grantedRole !== claimedRole) {
    return {
      status: 'unverified',
      reason: `latest grant says ${g.grantedRole}, not ${claimedRole}`,
    }
  }
  return { status: 'verified' }
}
