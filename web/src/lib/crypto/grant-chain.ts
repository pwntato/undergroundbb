// Client-side verification of a group's role-grant chain (#55, #56), against
// the data GET /api/groups/{id}/grants and GET /api/users/{id} serve. Pure:
// no fetching, no clock. The server is the party this protects against, and
// this module checks GRANTS, not the inputs it is handed: the anchor and the
// key histories are taken as given. A history the server substituted is
// indistinguishable here from a real one, so this module is only as good as
// the checks the caller ran on those inputs first (see "Caller obligations").
//
// Rules (docs/DESIGN.md, "Roles and the chain of trust"):
//   - The anchor's own signature (TrustAnchor context) must verify, and the
//     root grant must be self-signed by the anchor's key, by the creator,
//     for admin, with no grantorGrantRef.
//   - The anchor key must be a key the creator held on the root grant's day,
//     per the creator's key history. The anchor signature alone proves only
//     possession of SOME key (it is a self-signature), so without this any
//     invented keypair would verify.
//   - If the caller supplies pinnedAnchor (creator uuid + key remembered from
//     an earlier, trusted moment such as joining), the served anchor must
//     match it exactly.
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
//   - A row with `viaDesignation` is a designated successor's claim of the
//     admin role (#161, docs/DESIGN.md, "Inactivity"), not an ordinary grant,
//     and is judged by verifyClaim below instead: the designation must verify
//     like any admin-signed row, name this subject, and be cited by no other
//     row; the SUCCESSOR's claim signature must verify under a key they held on
//     the claim day; the role must be admin; the claim must fall at least
//     periodDays after the designation; and the designating admin must have
//     no other designation and no grant TO them dated on or after the
//     designation's day up to the claim day. The server cannot choose the
//     successor or claim early; a successor who colludes with it can postdate
//     the claim, which the admin undoes by revoking first, and which a caller
//     passing `now` flags when the claim is dated beyond the skew tolerance.
//
// Caller obligations. "verified" here means "consistent with the anchor and
// key histories supplied", and is proof against the server only if BOTH held:
//   1. pinnedAnchor was supplied and matched (result.anchorPinned), and
//   2. every entry in keyHistories was already checked against the caller's
//      signed PIN# rows for that user (docs/DESIGN.md, "Key pinning and
//      verification"; TOFU for a user seen for the first time, with the usual
//      first-contact limit).
// Otherwise a server can invent a creator, a keypair, an anchor and that
// user's history, or substitute any grantor's history with a key it holds
// (e.g. Alice's history = key E, E signs "Alice -> Mallory admin" citing
// Alice's real admin grant) and the chain verifies.
//
// Known limits:
//   - Leaving as an admin or ambassador appends a self-signed demotion to
//     member (issue #55), so a departed admin's last grant no longer says
//     admin and a rejoin by invite (baseline member) matches the chain. Two
//     gaps remain: a group left before this shipped has no demotion, so its
//     old leavers still show as unverified on rejoin; and an admin promoted
//     and leaving on the SAME UTC day has an unverifiable demotion (order
//     within a day is unknowable), so that rejoin shows as unverified too.
//   - Removing an admin appends a demotion signed by the REMOVER (issue #58).
//     It verifies like any admin grant, but the same-day exemption above is
//     for self-demotion only, so every grant the removed admin signed on the
//     removal's own UTC day is flagged, honest ones included, and the member
//     they promoted shows as unverified until a later grant re-establishes
//     them. Deliberate: order within a day is unknowable, and exempting a
//     demotion by someone else would let a server colluding with the removed
//     admin store a grant signed after the removal and have it verify. Pinned
//     in grant-chain.test.ts; do not widen the exemption without a way to
//     order within a day. The mirror case (promoted and removed the same day)
//     leaves an ambiguous latest grant on rejoin, as for leaving. Worse: if the
//     REMOVER's own grant is dated the removal's day OR LATER (reachable by
//     honest clients near 00:00 UTC), the remover's grant, the removal and
//     everything the remover signs later are all flagged, and with nobody left
//     to re-grant them it is permanent. The server refuses that write
//     (remover_granted_today) rather than store it; pinned in the tests. A role
//     change gets the same refusal (grantor_granted_today, #167).
//   - A self-demotion is the only self-grant accepted. It takes effect the
//     day after it is dated, so the leaver's promotion of a successor the same
//     day still verifies.
//   - The grant's day is chosen by its signer, so a superseded key that
//     later leaks can sign grants backdated into its old interval forever.
//     Inherent to the day in the sort key; latent until key rotation exists.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import {
  roleGrantPayload,
  successorClaimPayload,
  successorDesignationPayload,
  trustAnchorPayload,
} from './group.js'

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
  /**
   * Set only on a designated successor's claim (#161): the DESIGNATION# sort
   * key it relies on. A row that has it is judged by the claim rule, never as
   * an ordinary grant.
   */
  readonly viaDesignation?: string
  readonly signature: string
}

/** A successor designation as served by GET /api/groups/{id}/designations. */
export interface DesignationRecord {
  readonly sortKey: string
  readonly adminUserId: string
  /** Absent on a revocation. */
  readonly successorUserId?: string
  readonly periodDays: number
  readonly adminGrantRef: string
  readonly signature: string
}

/**
 * How far past `now` a claim's signed day may be before it is flagged. The
 * server accepts a client-dated grant up to two hours ahead of its own clock
 * (grantDaySkewTolerance), so an honest claim from a fast clock is not flagged.
 */
export const CLAIM_DAY_SKEW_TOLERANCE_MS = 2 * 60 * 60 * 1000

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

/** The part of the anchor a caller remembers from a trusted moment. */
export interface PinnedAnchor {
  readonly creatorUserId: string
  readonly creatorSigningPublicKey: string
}

export interface GrantChainInput {
  readonly groupId: string
  readonly anchor: GrantAnchor
  /** When set, the served anchor must match it exactly (compared as bytes). */
  readonly pinnedAnchor?: PinnedAnchor
  readonly grants: readonly GrantRecord[]
  /**
   * Key history per user id. A grantor missing here fails closed. These are
   * TRUSTED AS GIVEN: the caller must already have checked each against the
   * user's signed PIN# rows, because the verifier cannot tell a substituted
   * history from a real one.
   */
  readonly keyHistories: ReadonlyMap<string, UserKeyHistory>
  /**
   * Every designation the server serves (all pages). A claim row whose
   * designation is not here is rejected, so a caller that cannot fetch them
   * must not pass an empty list as if it had.
   */
  readonly designations?: readonly DesignationRecord[]
  /**
   * The viewer's clock, ms since the epoch. When set, a claim row dated more
   * than CLAIM_DAY_SKEW_TOLERANCE_MS ahead of it is rejected: the verifier has
   * no clock of its own, so this is the only check that catches a postdated
   * claim (docs/DESIGN.md, "Inactivity").
   */
  readonly now?: number
}

export interface GrantChainResult {
  /**
   * The anchor's own signature verifies and, if a pin was supplied, the
   * anchor matches it. A pin mismatch makes this false.
   */
  readonly anchorValid: boolean
  /**
   * A pin was supplied AND the anchor matched it. This says nothing about
   * key histories: pinned + verified is proof against the server only if the
   * caller also pin-checked keyHistories (see "Caller obligations").
   */
  readonly anchorPinned: boolean
  readonly verdicts: ReadonlyMap<string, GrantVerdict>
  readonly grantsBySubject: ReadonlyMap<string, readonly GrantRecord[]>
}

export type RoleStatus =
  { readonly status: 'verified' } | { readonly status: 'unverified'; readonly reason: string }

const SORT_KEY = /^GRANT#([0-9a-f-]{36})#(\d{4}-\d{2}-\d{2})#[0-9a-f]{16}$/
const DESIGNATION_KEY = /^DESIGNATION#([0-9a-f-]{36})#(\d{4}-\d{2}-\d{2})#[0-9a-f]{16}$/
const MIN_PERIOD_DAYS = 30
const MAX_PERIOD_DAYS = 365
export const DAY_MS = 24 * 60 * 60 * 1000
const ROLES: readonly string[] = ['admin', 'ambassador', 'member']

export interface ParsedKey {
  readonly subject: string
  readonly day: number
}

/** The subject and UTC day (ms) a GRANT# sort key addresses, or null if malformed. */
export function parseSortKey(sortKey: string): ParsedKey | null {
  const m = SORT_KEY.exec(sortKey)
  if (!m) return null
  const day = Date.parse(`${m[2]}T00:00:00.000Z`)
  if (Number.isNaN(day)) return null
  return { subject: m[1]!, day }
}

function parseDesignationKey(sortKey: string): ParsedKey | null {
  const m = DESIGNATION_KEY.exec(sortKey)
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
export function keysOnDay(history: UserKeyHistory, dayStart: number): Uint8Array[] {
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/** Verifies every grant in the history. Never throws on malformed input. */
export function verifyGrantChain(input: GrantChainInput): GrantChainResult {
  const { groupId, anchor, keyHistories } = input

  const anchorKey = decode(anchor.creatorSigningPublicKey)
  const anchorSig = decode(anchor.trustAnchorSignature)
  const pin = input.pinnedAnchor
  const pinKey = pin ? decode(pin.creatorSigningPublicKey) : null
  const pinMatched =
    pin !== undefined &&
    pinKey !== null &&
    anchorKey !== null &&
    pin.creatorUserId === anchor.creatorUserId &&
    bytesEqual(pinKey, anchorKey)
  const pinMismatch = pin !== undefined && !pinMatched
  const anchorValid =
    !pinMismatch &&
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

  // Designations by sort key (a duplicate poisons it), and which grants rely on each.
  const designationByKey = new Map<string, DesignationRecord>()
  const duplicatedDesignations = new Set<string>()
  const designationsByAdmin = new Map<string, DesignationRecord[]>()
  for (const d of input.designations ?? []) {
    if (designationByKey.has(d.sortKey)) duplicatedDesignations.add(d.sortKey)
    designationByKey.set(d.sortKey, d)
    const list = designationsByAdmin.get(d.adminUserId) ?? []
    list.push(d)
    designationsByAdmin.set(d.adminUserId, list)
  }
  const citing = new Map<string, number>()
  for (const g of input.grants) {
    if (g.viaDesignation) citing.set(g.viaDesignation, (citing.get(g.viaDesignation) ?? 0) + 1)
  }

  const verdicts = new Map<string, GrantVerdict>()
  const designationVerdicts = new Map<string, GrantVerdict>()

  const reject = (reason: string): GrantVerdict => ({ valid: false, reason })

  // Recursion terminates without a cycle guard: each hop moves to a grant on
  // a strictly earlier UTC day (the same-day rule rejects anything else), so
  // a chain can never revisit a grant. The one same-day hop is a grantor's
  // self-demotion, which only ever looks at its own subject's strictly earlier
  // grants, so it cannot lead back.
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
    if (g.viaDesignation) return verifyClaim(g, parsed, sig)
    const ref = g.grantorGrantRef ?? ''
    const payload = roleGrantPayload(groupId, g.subjectUserId, g.grantedRole, g.sortKey, ref)

    if (g.sortKey === anchor.rootGrantSortKey) {
      if (pinMismatch) return reject('anchor does not match the pinned anchor')
      if (!anchorValid || anchorKey === null) return reject('trust anchor does not verify')
      if (g.subjectUserId !== anchor.creatorUserId || g.grantorUserId !== anchor.creatorUserId) {
        return reject('root grant is not self-signed by the creator')
      }
      if (g.grantedRole !== 'admin') return reject('root grant is not admin')
      if (ref !== '') return reject('root grant has a predecessor')
      const creatorHistory = keyHistories.get(anchor.creatorUserId)
      if (!creatorHistory) return reject('no key history for creator')
      if (!keysOnDay(creatorHistory, parsed.day).some((k) => bytesEqual(k, anchorKey))) {
        return reject('anchor key is not a key the creator held on the root day')
      }
      if (!verify(anchorKey, SigningContext.RoleGrant, payload, sig)) {
        return reject('root signature does not verify under the anchor key')
      }
      return { valid: true }
    }

    // Non-root.
    if (ref === '') return reject('missing grantorGrantRef')
    if (g.grantorUserId === g.subjectUserId) {
      // The only self-grant is a demotion to member, written when an admin or
      // ambassador leaves. It needs no one else's authority and raises no
      // one's standing, so it asks only that the signer held an elevated
      // role the day before and signed with a key they held that day.
      if (g.grantedRole !== 'member') return reject('non-root self-grant')
      return verifySelfDemotion(g, parsed.day, ref, payload, sig)
    }
    const grantorGrants = grantsBySubject.get(g.grantorUserId) ?? []

    // The strict same-day rule, then "current on the day" = latest strictly
    // earlier day.
    let latestDay = -Infinity
    let latest: GrantRecord[] = []
    for (const other of grantorGrants) {
      const p = parseSortKey(other.sortKey)
      if (!p) continue
      if (p.day === parsed.day) {
        // A verified self-demotion the same day is not a change of role
        // BEFORE this signature: the server only accepts grants from a
        // current admin, and the demotion is what the grantor does on the
        // way out, usually right after promoting a successor. It takes
        // effect the next day (the strictly-earlier rule below already
        // ignores it for today).
        if (isSelfDemotion(other) && verifyOne(other).valid) continue
        return reject("grantor's role changed on the same UTC day")
      }
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

  function verifyDesignation(d: DesignationRecord): GrantVerdict {
    const cached = designationVerdicts.get(d.sortKey)
    if (cached) return cached
    const verdict = computeDesignation(d)
    designationVerdicts.set(d.sortKey, verdict)
    return verdict
  }

  /**
   * A designation verifies like a grant the admin signed: under a key they
   * held on its day, while holding admin that day by a verifying grant that
   * is strictly earlier, with no other grant to them on the day itself (order
   * within a day is unknowable, so a same-day change fails safe).
   */
  function computeDesignation(d: DesignationRecord): GrantVerdict {
    if (duplicatedDesignations.has(d.sortKey)) return reject('duplicate designation sort key')
    const parsed = parseDesignationKey(d.sortKey)
    if (!parsed) return reject('malformed designation sort key')
    if (parsed.subject !== d.adminUserId) return reject('designation sort key does not match admin')
    if (
      !Number.isSafeInteger(d.periodDays) ||
      d.periodDays < MIN_PERIOD_DAYS ||
      d.periodDays > MAX_PERIOD_DAYS
    ) {
      return reject('designation period is out of range')
    }
    const sig = decode(d.signature)
    if (!sig) return reject('malformed designation signature')
    if (d.adminGrantRef === '') return reject('designation has no admin grant reference')

    let latestDay = -Infinity
    let latest: GrantRecord[] = []
    for (const other of grantsBySubject.get(d.adminUserId) ?? []) {
      const p = parseSortKey(other.sortKey)
      if (!p) continue
      if (p.day === parsed.day) return reject("admin's role changed on the designation's day")
      if (p.day > parsed.day) continue
      if (p.day > latestDay) {
        latestDay = p.day
        latest = [other]
      } else if (p.day === latestDay) {
        latest.push(other)
      }
    }
    if (latest.length === 0) return reject('admin held no grant on the designation day')
    if (latest.length > 1) return reject("admin's current grant is ambiguous (same-day tie)")
    const current = latest[0]!
    if (d.adminGrantRef !== current.sortKey) {
      return reject("adminGrantRef is not the admin's current grant")
    }
    if (current.grantedRole !== 'admin') return reject('designating admin was not admin that day')
    if (!verifyOne(current).valid) return reject("admin's own grant does not verify")

    const history = keyHistories.get(d.adminUserId)
    if (!history) return reject('no key history for the designating admin')
    const payload = successorDesignationPayload(
      groupId,
      d.adminUserId,
      d.successorUserId ?? '',
      d.periodDays,
      d.sortKey,
      d.adminGrantRef,
    )
    for (const key of keysOnDay(history, parsed.day)) {
      if (verify(key, SigningContext.SuccessorDesignation, payload, sig)) return { valid: true }
    }
    return reject('designation signature does not verify under any key the admin held that day')
  }

  /**
   * The successor-claim rule (docs/DESIGN.md, "Inactivity: the admin pre-signs
   * a successor"). Every check here is made from signed rows; none relies on
   * the server's login record or clock.
   */
  function verifyClaim(g: GrantRecord, parsed: ParsedKey, sig: Uint8Array): GrantVerdict {
    const designationKey = g.viaDesignation!
    // The claim payload does not sign a role, and a designation can only confer admin.
    if (g.grantedRole !== 'admin') return reject('a successor claim can only confer admin')
    if ((citing.get(designationKey) ?? 0) > 1) {
      return reject('more than one grant relies on this designation')
    }
    const d = designationByKey.get(designationKey)
    if (!d) return reject('the designation this claim relies on was not served')
    const designation = verifyDesignation(d)
    if (!designation.valid) return reject(`designation does not verify (${designation.reason})`)
    if (d.successorUserId !== g.subjectUserId) return reject('the designation names someone else')
    if (g.grantorUserId !== d.adminUserId) return reject('claim names a different admin')
    if ((g.grantorGrantRef ?? '') !== d.adminGrantRef) {
      return reject('claim does not cite the grant the designation was signed against')
    }
    const dParsed = parseDesignationKey(d.sortKey)!

    // The floor: signing the designation shows the admin was active that day,
    // so periodDays must have passed before anyone may claim.
    if (parsed.day - dParsed.day < d.periodDays * DAY_MS) {
      return reject('the claim is dated before the designation period elapsed')
    }
    if (input.now !== undefined && parsed.day - input.now > CLAIM_DAY_SKEW_TOLERANCE_MS) {
      return reject('the claim is dated in the future')
    }

    // The lapse: anything of the admin's own from the designation's day up to
    // the claim's. "On or after" is deliberate: a same-day revocation or
    // self-demotion cannot be ordered against the designation, so it cancels it.
    for (const other of designationsByAdmin.get(d.adminUserId) ?? []) {
      if (other.sortKey === d.sortKey) continue
      const p = parseDesignationKey(other.sortKey)
      if (p && p.day >= dParsed.day && p.day <= parsed.day) {
        return reject('the admin signed another designation since, which cancels this one')
      }
    }
    for (const other of grantsBySubject.get(d.adminUserId) ?? []) {
      const p = parseSortKey(other.sortKey)
      if (p && p.day >= dParsed.day && p.day <= parsed.day) {
        return reject("the admin's own role changed since the designation")
      }
    }

    const history = keyHistories.get(g.subjectUserId)
    if (!history) return reject('no key history for the successor')
    const payload = successorClaimPayload(groupId, g.subjectUserId, designationKey, g.sortKey)
    for (const key of keysOnDay(history, parsed.day)) {
      if (verify(key, SigningContext.SuccessorClaim, payload, sig)) return { valid: true }
    }
    return reject('claim signature does not verify under any key the successor held that day')
  }

  function isSelfDemotion(g: GrantRecord): boolean {
    return g.grantorUserId === g.subjectUserId && g.grantedRole === 'member'
  }

  function verifySelfDemotion(
    g: GrantRecord,
    day: number,
    ref: string,
    payload: Uint8Array,
    sig: Uint8Array,
  ): GrantVerdict {
    // The subject's grants other than this one. Any other grant the same day
    // leaves the order unknowable, so it fails safe, as for any grantor.
    let latestDay = -Infinity
    let latest: GrantRecord[] = []
    for (const other of grantsBySubject.get(g.subjectUserId) ?? []) {
      if (other.sortKey === g.sortKey) continue
      const p = parseSortKey(other.sortKey)
      if (!p) continue
      if (p.day === day) return reject("signer's role changed on the same UTC day")
      if (p.day > day) continue
      if (p.day > latestDay) {
        latestDay = p.day
        latest = [other]
      } else if (p.day === latestDay) {
        latest.push(other)
      }
    }
    if (latest.length === 0) return reject('signer held no grant before the demotion')
    if (latest.length > 1) return reject("signer's current grant is ambiguous (same-day tie)")
    const current = latest[0]!
    if (ref !== current.sortKey) return reject("grantorGrantRef is not the signer's current grant")
    if (current.grantedRole !== 'admin' && current.grantedRole !== 'ambassador') {
      return reject('signer held no elevated role to give up')
    }
    if (!verifyOne(current).valid) return reject("signer's own grant does not verify")

    const history = keyHistories.get(g.subjectUserId)
    if (!history) return reject('no key history for signer')
    for (const key of keysOnDay(history, day)) {
      if (verify(key, SigningContext.RoleGrant, payload, sig)) return { valid: true }
    }
    return reject('signature does not verify under any key the signer held on that day')
  }

  for (const g of input.grants) verifyOne(g)
  return { anchorValid, anchorPinned: pinMatched, verdicts, grantsBySubject }
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
