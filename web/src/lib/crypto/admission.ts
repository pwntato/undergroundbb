// Client-side check of one member's admission record (#178), against the
// verified grant chain. Pure: no fetching, no clock. A rotating admin runs it
// before wrapping a new group key to anyone, because the member list is
// whatever the server reports and nothing else signed says who is a member (the
// invite rows are deleted at completion and a plain member has no grant).
//
// A record admits a member if ALL of these hold:
//   - it is the invitee's own: its keys are the ones the server now serves for
//     them (the Ed25519 key among their served signing keys, the X25519 key
//     equal to the served wrapping key). A record for other keys admits
//     nobody at the address the server is offering;
//   - the inviter's signature (Admission context) over admissionPayload
//     verifies under a key the inviter held on the record's day, from their
//     key history. The history is TRUSTED AS GIVEN: the caller must have
//     pin-checked it, exactly as for verifyGrantChain (see its "Caller
//     obligations");
//   - inviterGrantRef names a grant TO the inviter that verified in the chain
//     and conferred admin or ambassador, and nothing could have changed that
//     role before the admission: the inviter has no other grant dated from the
//     ref's day through the record's day. The order within a day is unknowable
//     (the sort key's suffix is random), so a same-day change fails closed, as
//     in grant-chain.ts. A grant dated AFTER the record's day (a later
//     demotion, removal) does not matter: that member was admitted properly.
//
// The group's creator is the one member with no admission; the caller exempts
// them, and only against an anchor it trusts.
//
// Known limits, the same as the grant chain's: the record's day is the
// inviter's own claim (the server holds it to its clock at write time, but a
// verifier has no clock), so a server colluding with an inviter who has since
// been demoted can store a backdated admission; and nothing binds the SET of
// records, so the server can withhold one, which only ever shrinks who is
// wrapped to.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import {
  keysOnDay,
  parseSortKey,
  type GrantChainResult,
  type GrantRecord,
  type UserKeyHistory,
} from './grant-chain.js'
import { admissionPayload } from './group.js'

/** An admission as served by GET /api/groups/{id}/admissions. */
export interface AdmissionRecord {
  readonly inviteeUserId: string
  readonly inviterUserId: string
  readonly inviteId: string
  readonly inviteeEd25519PublicKey: string
  readonly inviteeX25519PublicKey: string
  readonly inviterGrantRef: string
  /** UTC date, YYYY-MM-DD. */
  readonly day: string
  readonly signature: string
}

export type AdmissionVerdict =
  { readonly ok: true } | { readonly ok: false; readonly reason: string }

export interface VerifyAdmissionInput {
  readonly groupId: string
  readonly record: AdmissionRecord
  /** Every signing key now served for the invitee (current and superseded). */
  readonly inviteeSigningKeys: readonly Uint8Array[]
  /** The invitee's served X25519 wrapping key, base64. */
  readonly inviteeWrappingKey: string
  readonly chain: GrantChainResult
  /** The inviter's key history; missing fails closed. Must be pin-checked. */
  readonly inviterHistory: UserKeyHistory | undefined
}

const DAY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/

function reject(reason: string): AdmissionVerdict {
  return { ok: false, reason }
}

function decode(b64: string, length: number): Uint8Array | null {
  try {
    const bytes = base64ToBytes(b64)
    return bytes.length === length ? bytes : null
  } catch {
    return null
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/** Midnight UTC of a YYYY-MM-DD date in ms, or null if it is not a real date. */
function dayStart(day: string): number | null {
  if (!DAY_PATTERN.test(day)) return null
  const ms = Date.parse(`${day}T00:00:00.000Z`)
  if (Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== day) return null
  return ms
}

/** Never throws on malformed input. */
export function verifyAdmission(input: VerifyAdmissionInput): AdmissionVerdict {
  const { groupId, record, chain } = input

  const ed = decode(record.inviteeEd25519PublicKey, 32)
  const x = decode(record.inviteeX25519PublicKey, 32)
  const sig = decode(record.signature, 64)
  if (ed === null || x === null || sig === null) return reject('the admission record is malformed')
  const day = dayStart(record.day)
  if (day === null) return reject('the admission record has a malformed date')

  // The record must be about the keys the server is offering for this member.
  if (!input.inviteeSigningKeys.some((k) => sameBytes(k, ed))) {
    return reject('the admitted signing key is not one the server serves for this member')
  }
  const served = decode(input.inviteeWrappingKey, 32)
  if (served === null || !sameBytes(served, x)) {
    return reject('the admitted wrapping key is not the one the server serves for this member')
  }

  // The inviter's grant: named, verified, elevated, and not superseded by day.
  const inviterGrants: readonly GrantRecord[] =
    chain.grantsBySubject.get(record.inviterUserId) ?? []
  const ref = inviterGrants.find((g) => g.sortKey === record.inviterGrantRef)
  if (ref === undefined)
    return reject("the inviter's grant named by the admission is not on record")
  if (ref.grantedRole !== 'admin' && ref.grantedRole !== 'ambassador') {
    return reject('the inviter held no role that can invite')
  }
  if (chain.verdicts.get(ref.sortKey)?.valid !== true) {
    return reject("the inviter's grant does not verify")
  }
  const refKey = parseSortKey(ref.sortKey)
  if (refKey === null) return reject("the inviter's grant has a malformed address")
  if (refKey.day > day) return reject("the inviter's grant is dated after the admission")
  for (const g of inviterGrants) {
    if (g.sortKey === ref.sortKey) continue
    const k = parseSortKey(g.sortKey)
    if (k === null) return reject("one of the inviter's grants has a malformed address")
    if (k.day >= refKey.day && k.day <= day) {
      return reject("the inviter's role changed on or before the day of the admission")
    }
  }

  if (input.inviterHistory === undefined) return reject("the inviter's keys are not available")
  const payload = admissionPayload(
    groupId,
    record.inviterUserId,
    record.inviteeUserId,
    ed,
    x,
    record.inviteId,
    record.inviterGrantRef,
    record.day,
  )
  for (const key of keysOnDay(input.inviterHistory, day)) {
    if (verify(key, SigningContext.Admission, payload, sig)) return { ok: true }
  }
  return reject('the admission signature does not verify under any key the inviter held that day')
}
