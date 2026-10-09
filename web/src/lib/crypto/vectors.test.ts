// Verifies this package against the SAME fixed vectors the Go
// implementation checks itself against (internal/crypto/testdata/vectors.json,
// #20). This is the #24 half that didn't exist yet: proving the TypeScript
// side agrees with Go's, not just with its own round-trips.
//
// Reads the vectors file directly from the Go package rather than a copy —
// there must be exactly one vectors.json in the repo, or the two
// implementations could silently drift against different "shared" files.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { decrypt, DecryptionFailedError, encryptWithNonce } from './aesgcm.js'
import { deriveKey } from './argon2.js'
import { credentialWrapAAD, type CredentialCopy } from './credential.js'
import * as ed25519 from './ed25519.js'
import { fingerprint } from './fingerprint.js'
import {
  admissionPayload,
  genKeyAAD,
  groupNameAAD,
  memberWrapAAD,
  roleGrantPayload,
  successorClaimPayload,
  rotationStartPayload,
  successorDesignationPayload,
  trustAnchorPayload,
  type GroupTextField,
} from './group.js'
import { bytesToHex, hexToBytes } from './hex.js'
import {
  computeInviteMAC,
  deriveInviteMACKey,
  inviteAcceptancePayload,
  inviteCreationPayload,
  verifyInviteMAC,
} from './invite.js'
import { decodeKeyBundle, encodeKeyBundle } from './keybundle.js'
import { signedPayload } from './payload.js'
import { pinPayload } from './pin.js'
import { unwrap, wrapWithEphemeralAndNonce } from './x25519.js'

const VECTORS_PATH = fileURLToPath(
  new URL('../../../../internal/crypto/testdata/vectors.json', import.meta.url),
)

interface VectorFile {
  version: number
  kdf: {
    password: string
    salt_hex: string
    m_kib: number
    t: number
    p: number
    key_hex: string
  }[]
  aead: {
    name: string
    key_hex: string
    nonce_hex: string
    plaintext_hex: string
    aad_hex: string
    ciphertext_hex: string
  }[]
  aead_negative: {
    name: string
    key_hex: string
    nonce_hex: string
    ciphertext_hex: string
    aad_hex: string
    wrong_aad_hex: string
  }[]
  signing: {
    name: string
    private_key_hex: string
    public_key_hex: string
    context: string
    message_hex: string
    signature_hex: string
  }[]
  signed_payload: {
    name: string
    private_key_hex: string
    public_key_hex: string
    context: string
    author_uuid: string
    group_id: string
    sort_key: string
    generation: number
    utc_day: string
    ciphertext_hex: string
    payload_hex: string
    signature_hex: string
  }[]
  wrapping: {
    name: string
    recipient_private_key_hex: string
    recipient_public_key_hex: string
    ephemeral_private_key_hex: string
    ephemeral_public_key_hex: string
    plaintext_hex: string
    aad_hex: string
    wrapped_nonce_hex: string
    wrapped_ciphertext_hex: string
  }[]
  genkey_chain: {
    name: string
    group_id: string
    generation: number
    gen_n_key_hex: string
    gen_n_plus_1_key_hex: string
    aad_hex: string
    link_nonce_hex: string
    link_ciphertext_hex: string
    forward_must_fail: boolean
  }[]
  fingerprint: {
    name: string
    signing_public_key_hex: string
    wrapping_public_key_hex: string
    fingerprint: string
  }[]
  credential_wrap: {
    name: string
    user_id: string
    copy: string
    aad_hex: string
    key_hex: string
    plaintext_hex: string
    nonce_hex: string
    ciphertext_hex: string
  }[]
  key_bundle: {
    name: string
    signing_seed_hex: string
    wrapping_private_key_hex: string
    encoded_hex: string
  }[]
  trust_anchor: {
    name: string
    private_key_hex: string
    public_key_hex: string
    creator_uuid: string
    group_id: string
    payload_hex: string
    signature_hex: string
  }[]
  role_grant: {
    name: string
    private_key_hex: string
    public_key_hex: string
    group_id: string
    subject_uuid: string
    role: string
    grant_sort_key: string
    grantor_grant_ref: string
    payload_hex: string
    signature_hex: string
  }[]
  successor_designation: {
    name: string
    private_key_hex: string
    public_key_hex: string
    group_id: string
    admin_uuid: string
    successor_uuid: string
    period_days: number
    designation_sort_key: string
    admin_grant_ref: string
    payload_hex: string
    signature_hex: string
  }[]
  successor_claim: {
    name: string
    private_key_hex: string
    public_key_hex: string
    group_id: string
    successor_uuid: string
    designation_sort_key: string
    claim_sort_key: string
    payload_hex: string
    signature_hex: string
  }[]
  rotation_start: {
    name: string
    private_key_hex: string
    public_key_hex: string
    group_id: string
    remover_uuid: string
    subject_uuid: string
    generation: number
    payload_hex: string
    signature_hex: string
  }[]
  admission: {
    name: string
    private_key_hex: string
    public_key_hex: string
    group_id: string
    inviter_uuid: string
    invitee_uuid: string
    invitee_ed25519_hex: string
    invitee_x25519_hex: string
    invite_id: string
    inviter_grant_ref: string
    day: string
    generation: number
    payload_hex: string
    signature_hex: string
  }[]
  pin: {
    name: string
    private_key_hex: string
    public_key_hex: string
    pinner_uuid: string
    pinned_uuid: string
    wrapping_public_key_hex: string
    signing_keys_hex: string[]
    payload_hex: string
    signature_hex: string
  }[]
  member_wrap_aad: {
    name: string
    group_id: string
    member_uuid: string
    generation: number
    aad_hex: string
    key_hex: string
    plaintext_hex: string
    nonce_hex: string
    ciphertext_hex: string
  }[]
  group_name_aad: {
    name: string
    group_id: string
    field: string
    generation: number
    aad_hex: string
    key_hex: string
    plaintext_hex: string
    nonce_hex: string
    ciphertext_hex: string
  }[]
  invite_creation: {
    name: string
    private_key_hex: string
    public_key_hex: string
    invite_id: string
    group_id: string
    expires_at: string
    payload_hex: string
    signature_hex: string
  }[]
  invite_acceptance: {
    name: string
    private_key_hex: string
    public_key_hex: string
    invite_id: string
    invited_ed25519_pub_hex: string
    invited_x25519_pub_hex: string
    payload_hex: string
    signature_hex: string
  }[]
  invite_mac: {
    name: string
    inviter_seed_hex: string
    invite_id: string
    invited_ed25519_pub_hex: string
    invited_x25519_pub_hex: string
    mac_key_hex: string
    payload_hex: string
    mac_hex: string
  }[]
}

const vectors: VectorFile = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'))

describe('kdf vectors', () => {
  for (const tc of vectors.kdf) {
    it(`m=${tc.m_kib}KiB t=${tc.t} p=${tc.p}`, async () => {
      const salt = hexToBytes(tc.salt_hex)
      const want = hexToBytes(tc.key_hex)
      const got = await deriveKey(
        tc.password,
        salt,
        { memoryKiB: tc.m_kib, iterations: tc.t, parallelism: tc.p },
        want.length,
      )
      expect(bytesToHex(got)).toBe(tc.key_hex)
    })
  }
})

describe('aead vectors', () => {
  for (const tc of vectors.aead) {
    it(tc.name, async () => {
      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)
      const aad = hexToBytes(tc.aad_hex)

      const ciphertext = await encryptWithNonce(key, nonce, plaintext, aad)
      expect(bytesToHex(ciphertext)).toBe(tc.ciphertext_hex)

      const decrypted = await decrypt(key, nonce, ciphertext, aad)
      expect(bytesToHex(decrypted)).toBe(tc.plaintext_hex)
    })
  }
})

describe('aead negative vectors', () => {
  for (const tc of vectors.aead_negative) {
    it(tc.name, async () => {
      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const ciphertext = hexToBytes(tc.ciphertext_hex)
      const wrongAad = hexToBytes(tc.wrong_aad_hex)

      await expect(decrypt(key, nonce, ciphertext, wrongAad)).rejects.toThrow(DecryptionFailedError)
    })
  }
})

describe('signing vectors', () => {
  for (const tc of vectors.signing) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const message = hexToBytes(tc.message_hex)
      const signature = ed25519.sign(key, tc.context as ed25519.SigningContext, message)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)

      expect(
        ed25519.verify(key.publicKey, tc.context as ed25519.SigningContext, message, signature),
      ).toBe(true)
    })
  }
})

describe('signed payload vectors', () => {
  for (const tc of vectors.signed_payload) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      const ciphertext = hexToBytes(tc.ciphertext_hex)

      const payload = signedPayload(
        tc.author_uuid,
        tc.group_id,
        tc.sort_key,
        tc.generation,
        tc.utc_day,
        ciphertext,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, tc.context as ed25519.SigningContext, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

describe('wrapping vectors', () => {
  for (const tc of vectors.wrapping) {
    it(tc.name, async () => {
      const recipientPriv = hexToBytes(tc.recipient_private_key_hex)
      const recipientPub = hexToBytes(tc.recipient_public_key_hex)
      const ephemeralPriv = hexToBytes(tc.ephemeral_private_key_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)
      const aad = hexToBytes(tc.aad_hex)
      const nonce = hexToBytes(tc.wrapped_nonce_hex)

      const wrapped = await wrapWithEphemeralAndNonce(
        recipientPub,
        ephemeralPriv,
        nonce,
        plaintext,
        aad,
      )
      expect(bytesToHex(wrapped.ephemeralPub)).toBe(tc.ephemeral_public_key_hex)
      expect(bytesToHex(wrapped.ciphertext)).toBe(tc.wrapped_ciphertext_hex)

      const unwrapped = await unwrap(recipientPriv, wrapped, aad)
      expect(bytesToHex(unwrapped)).toBe(tc.plaintext_hex)
    })
  }
})

// The negative vector issue #20 (and #24 now) calls out by name: GENKEY#<n>
// holds generation n encrypted under generation n+1's key. A holder of
// generation n+1 decrypts backward to generation n; a holder of only
// generation n has no key material that decrypts a link encrypted under
// generation n+1. This exercises the plain AES-GCM primitives, not X25519 —
// see internal/crypto/vectors_test.go's TestVectorGenkeyChain for why using
// two unrelated asymmetric keys here would test the wrong construction.
describe('genkey chain vectors', () => {
  for (const tc of vectors.genkey_chain) {
    it(tc.name, async () => {
      const genN = hexToBytes(tc.gen_n_key_hex)
      const genNPlus1 = hexToBytes(tc.gen_n_plus_1_key_hex)
      const aad = hexToBytes(tc.aad_hex)
      expect(bytesToHex(genKeyAAD(tc.group_id, tc.generation))).toBe(tc.aad_hex)
      const nonce = hexToBytes(tc.link_nonce_hex)

      const ciphertext = await encryptWithNonce(genNPlus1, nonce, genN, aad)
      expect(bytesToHex(ciphertext)).toBe(tc.link_ciphertext_hex)

      const decrypted = await decrypt(genNPlus1, nonce, ciphertext, aad)
      expect(bytesToHex(decrypted)).toBe(tc.gen_n_key_hex)

      if (tc.forward_must_fail) {
        await expect(decrypt(genN, nonce, ciphertext, aad)).rejects.toThrow(DecryptionFailedError)
      }
    })
  }
})

describe('fingerprint vectors', () => {
  for (const tc of vectors.fingerprint) {
    it(tc.name, () => {
      const signingPub = hexToBytes(tc.signing_public_key_hex)
      const wrappingPub = hexToBytes(tc.wrapping_public_key_hex)
      expect(fingerprint(signingPub, wrappingPub)).toBe(tc.fingerprint)
    })
  }
})

// Pins credentialWrapAAD's exact encoding — see that function's own doc
// comment for why this specific AAD, unlike every other one in this
// codebase, had no code fixing its byte format before #30 needed one.
// Proves both the encoding itself and, by running the AES-256-GCM round
// trip through it, that a client unwrapping under the wrong copy's AAD
// (PROFILE's AAD against RECOVERY's ciphertext or vice versa) fails the way
// any other address-relocation attempt does.
describe('credential wrap vectors', () => {
  for (const tc of vectors.credential_wrap) {
    it(tc.name, async () => {
      const wantAad = hexToBytes(tc.aad_hex)
      const gotAad = credentialWrapAAD(tc.user_id, tc.copy as CredentialCopy)
      expect(bytesToHex(gotAad)).toBe(bytesToHex(wantAad))

      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)

      const ciphertext = await encryptWithNonce(key, nonce, plaintext, gotAad)
      expect(bytesToHex(ciphertext)).toBe(tc.ciphertext_hex)

      const decrypted = await decrypt(key, nonce, ciphertext, gotAad)
      expect(bytesToHex(decrypted)).toBe(tc.plaintext_hex)
    })
  }

  it('cross-copy AAD must fail (PROFILE ciphertext under RECOVERY AAD)', async () => {
    const profile = vectors.credential_wrap.find((v) => v.copy === 'PROFILE')
    const recovery = vectors.credential_wrap.find((v) => v.copy === 'RECOVERY')
    if (!profile || !recovery) throw new Error('expected both PROFILE and RECOVERY vectors')

    const key = hexToBytes(profile.key_hex)
    const nonce = hexToBytes(profile.nonce_hex)
    const profileCiphertext = hexToBytes(profile.ciphertext_hex)
    const recoveryAad = hexToBytes(recovery.aad_hex)

    await expect(decrypt(key, nonce, profileCiphertext, recoveryAad)).rejects.toThrow(
      DecryptionFailedError,
    )
  })
})

// Pins encodeKeyBundle's exact plaintext layout — see that function's own
// doc comment for why this, like the credential-wrap AAD before it, needed
// a fixed cross-implementation vector rather than being left to whatever
// each side happened to guess.
describe('key bundle vectors', () => {
  for (const tc of vectors.key_bundle) {
    it(tc.name, () => {
      const bundle = {
        signingSeed: hexToBytes(tc.signing_seed_hex),
        wrappingPrivateKey: hexToBytes(tc.wrapping_private_key_hex),
      }

      const encoded = encodeKeyBundle(bundle)
      expect(bytesToHex(encoded)).toBe(tc.encoded_hex)

      const decoded = decodeKeyBundle(hexToBytes(tc.encoded_hex))
      expect(bytesToHex(decoded.signingSeed)).toBe(tc.signing_seed_hex)
      expect(bytesToHex(decoded.wrappingPrivateKey)).toBe(tc.wrapping_private_key_hex)
    })
  }
})

// Pins trustAnchorPayload's exact encoding -- issue #34, the same reasoning
// as "signed payload vectors": a group's root of trust is verified by every
// future member's client, so this payload must be byte-identical to Go's
// before any real group exists under it.
describe('trust anchor vectors', () => {
  for (const tc of vectors.trust_anchor) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = trustAnchorPayload(tc.creator_uuid, key.publicKey, tc.group_id)
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.TrustAnchor, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins roleGrantPayload's exact encoding, for both the root-grant shape
// (empty grantorGrantRef) and a non-root grant referencing a real
// predecessor.
describe('role grant vectors', () => {
  for (const tc of vectors.role_grant) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = roleGrantPayload(
        tc.group_id,
        tc.subject_uuid,
        tc.role,
        tc.grant_sort_key,
        tc.grantor_grant_ref,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.RoleGrant, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins successorDesignationPayload's exact encoding (#161), for a named
// successor and for the revocation form (empty successor).
describe('successor designation vectors', () => {
  for (const tc of vectors.successor_designation) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = successorDesignationPayload(
        tc.group_id,
        tc.admin_uuid,
        tc.successor_uuid,
        tc.period_days,
        tc.designation_sort_key,
        tc.admin_grant_ref,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.SuccessorDesignation, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins successorClaimPayload's exact encoding (#161).
describe('successor claim vectors', () => {
  for (const tc of vectors.successor_claim) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = successorClaimPayload(
        tc.group_id,
        tc.successor_uuid,
        tc.designation_sort_key,
        tc.claim_sort_key,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.SuccessorClaim, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins rotationStartPayload's exact encoding (#178).
describe('rotation start vectors', () => {
  for (const tc of vectors.rotation_start) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = rotationStartPayload(
        tc.group_id,
        tc.remover_uuid,
        tc.subject_uuid,
        tc.generation,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.RotationStart, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins admissionPayload's exact encoding (#178).
describe('admission vectors', () => {
  for (const tc of vectors.admission) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = admissionPayload(
        tc.group_id,
        tc.inviter_uuid,
        tc.invitee_uuid,
        hexToBytes(tc.invitee_ed25519_hex),
        hexToBytes(tc.invitee_x25519_hex),
        tc.invite_id,
        tc.inviter_grant_ref,
        tc.day,
        tc.generation,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.Admission, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins pinPayload's exact encoding (#63), including that the signing key set
// is order-independent: two vectors list the same keys in different orders.
describe('pin vectors', () => {
  for (const tc of vectors.pin) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = pinPayload(
        tc.pinner_uuid,
        tc.pinned_uuid,
        key.publicKey,
        hexToBytes(tc.wrapping_public_key_hex),
        tc.signing_keys_hex.map(hexToBytes),
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.Pin, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins inviteCreationPayload's exact encoding -- issue #38, the invite
// handshake's step-1 signed payload. Every future invitee's client verifies
// this signature before trusting the invite, so the encoding must be
// byte-identical to Go's before any real invite exists under it. No
// ephemeral_pubkey field -- see docs/DESIGN.md's now-resolved open question.
describe('invite creation vectors', () => {
  for (const tc of vectors.invite_creation) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const payload = inviteCreationPayload(tc.invite_id, tc.group_id, key.publicKey, tc.expires_at)
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.Invite, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins inviteAcceptancePayload's exact encoding -- issue #39, the invite
// handshake's step-2 signed payload. Step 3 (the inviter's client) verifies
// this signature before ever wrapping the group key to the keys it names.
describe('invite acceptance vectors', () => {
  for (const tc of vectors.invite_acceptance) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const invitedEd25519Pub = hexToBytes(tc.invited_ed25519_pub_hex)
      const invitedX25519Pub = hexToBytes(tc.invited_x25519_pub_hex)
      const payload = inviteAcceptancePayload(tc.invite_id, invitedEd25519Pub, invitedX25519Pub)
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, ed25519.SigningContext.Invite, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

// Pins deriveInviteMACKey/computeInviteMAC's exact encoding -- PR #146
// round-1 review's blocking finding #1, the per-invite MAC that closes the
// gap plain signature verification leaves open (a malicious server can
// mint its own keypair, self-sign, and pass that check with no real
// invitee involved). Must be byte-identical to Go's before any real
// invite MAC exists under it.
describe('invite MAC vectors', () => {
  for (const tc of vectors.invite_mac) {
    it(tc.name, () => {
      const inviterSeed = hexToBytes(tc.inviter_seed_hex)
      const invitedEd25519Pub = hexToBytes(tc.invited_ed25519_pub_hex)
      const invitedX25519Pub = hexToBytes(tc.invited_x25519_pub_hex)

      const macKey = deriveInviteMACKey(inviterSeed, tc.invite_id)
      expect(bytesToHex(macKey)).toBe(tc.mac_key_hex)

      const payload = inviteAcceptancePayload(tc.invite_id, invitedEd25519Pub, invitedX25519Pub)
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const mac = computeInviteMAC(macKey, payload)
      expect(bytesToHex(mac)).toBe(tc.mac_hex)
      expect(verifyInviteMAC(macKey, payload, hexToBytes(tc.mac_hex))).toBe(true)

      // A MAC key derived under a DIFFERENT invite id must not verify --
      // proves the key is actually bound to this invite via HKDF's info
      // parameter, not merely present.
      const wrongIDKey = deriveInviteMACKey(inviterSeed, 'a-different-invite-id')
      expect(verifyInviteMAC(wrongIDKey, payload, hexToBytes(tc.mac_hex))).toBe(false)
    })
  }
})

// Pins memberWrapAAD's exact encoding -- the same reasoning as "credential
// wrap vectors" applied to a different AAD.
describe('member wrap AAD vectors', () => {
  for (const tc of vectors.member_wrap_aad) {
    it(tc.name, async () => {
      const wantAad = hexToBytes(tc.aad_hex)
      const gotAad = memberWrapAAD(tc.group_id, tc.member_uuid, tc.generation)
      expect(bytesToHex(gotAad)).toBe(bytesToHex(wantAad))

      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)

      const ciphertext = await encryptWithNonce(key, nonce, plaintext, gotAad)
      expect(bytesToHex(ciphertext)).toBe(tc.ciphertext_hex)

      const decrypted = await decrypt(key, nonce, ciphertext, gotAad)
      expect(bytesToHex(decrypted)).toBe(tc.plaintext_hex)
    })
  }
})

// Pins groupNameAAD's exact encoding, for both the name and description
// fields -- the same reasoning as "member wrap AAD vectors" applied to a
// different AAD.
describe('group name AAD vectors', () => {
  for (const tc of vectors.group_name_aad) {
    it(tc.name, async () => {
      const wantAad = hexToBytes(tc.aad_hex)
      const gotAad = groupNameAAD(tc.group_id, tc.field as GroupTextField, tc.generation)
      expect(bytesToHex(gotAad)).toBe(bytesToHex(wantAad))

      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)

      const ciphertext = await encryptWithNonce(key, nonce, plaintext, gotAad)
      expect(bytesToHex(ciphertext)).toBe(tc.ciphertext_hex)

      const decrypted = await decrypt(key, nonce, ciphertext, gotAad)
      expect(bytesToHex(decrypted)).toBe(tc.plaintext_hex)
    })
  }

  it('cross-field AAD must fail (name ciphertext under description AAD)', async () => {
    const nameVec = vectors.group_name_aad.find((v) => v.field === 'NAME')
    const descVec = vectors.group_name_aad.find((v) => v.field === 'DESC')
    if (!nameVec || !descVec) throw new Error('expected both NAME and DESC vectors')

    const key = hexToBytes(nameVec.key_hex)
    const nonce = hexToBytes(nameVec.nonce_hex)
    const nameCiphertext = hexToBytes(nameVec.ciphertext_hex)
    const descAad = hexToBytes(descVec.aad_hex)

    await expect(decrypt(key, nonce, nameCiphertext, descAad)).rejects.toThrow(
      DecryptionFailedError,
    )
  })
})
