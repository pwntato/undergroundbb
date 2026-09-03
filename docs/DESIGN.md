# UndergroundBB — Design

This document explains how UndergroundBB works and why it is built the way it is. For what an
attacker can and cannot do, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Overview

UndergroundBB is an end-to-end encrypted message board. Users join groups; groups contain posts;
posts contain threaded comments. Everything a user writes is encrypted in their browser before it
reaches the server, and the server never holds the keys to read any of it.

The stack is a Go binary on AWS Lambda behind CloudFront, a single DynamoDB table, and a React SPA
served as static files. There is no application server holding state, no session store, and no
plaintext content anywhere in the backend.

## The cryptographic core

Each user has two keypairs:

| Key | Algorithm | Purpose |
|---|---|---|
| Signing key | Ed25519 | Login challenge-response, signing posts and role grants |
| Wrapping key | X25519 | Wrapping and unwrapping group keys (ECIES with HKDF) |

Both private keys are encrypted with AES-256-GCM under a key derived from the user's password via
**Argon2id**, and the resulting blob is stored on the server. The password itself is never
transmitted, and neither is anything derived from it.

Groups have a symmetric **group key** (AES-256-GCM) that encrypts every post, comment, and — for
private groups — the group's name and description. Each member holds a copy of the group key wrapped
to their X25519 public key.

### Login

1. Client sends a username to `POST /api/auth/challenge`.
2. Server returns the user's salt, their wrapped private keys, and a random nonce.
3. Client derives the key from the password with Argon2id, unwraps the private keys, and signs the
   nonce with the Ed25519 key.
4. Server verifies the signature against the stored public key and issues a session cookie.

The server learns only that someone holding the private key was present. Decryption of the private
key happens entirely in the browser, and GCM's authentication tag failing *is* the wrong-password
signal — no separate password verifier is stored.

### Multi-device

There is no device pairing, key sync protocol, or device registry. Any device can log in with the
username and password: it downloads the same encrypted key blob and derives the same key. The
password is the portable credential, and the encrypted blob is safe to store centrally precisely
because it is encrypted.

### Recovery

At signup, a high-entropy recovery code is generated and a **second copy** of the private keys is
wrapped under it. A user who forgets their password can recover with the code. A user who loses both
has permanently lost access — the server has nothing to reset, by design.

Changing a password does **not** change keys. It unwraps the private keys with the old password and
re-wraps them under the new one. Nothing else in the system is affected.

## Groups

### Invites — the signed handshake

An invite is a three-step handshake that prevents the server from substituting its own key for the
invitee's:

1. **Inviter creates.** Signs `{invite_id, group_id, inviter_pubkey, ephemeral_pubkey, expires_at}`
   with their Ed25519 key. This payload contains **no secrets** and is safe at rest.
2. **Invitee accepts.** Verifies the inviter's signature, then signs
   `{invite_id, ed25519_pub, x25519_pub}` with their own key.
3. **Inviter completes.** Their client verifies the acceptance signature and wraps the group key to
   the X25519 key **that was signed in step 2** — never to a key the server offers unilaterally.

For the server to insert itself it would have to forge an Ed25519 signature, which it cannot.
Step 3 happens automatically the next time the inviter's client is online; the group key exists in
plaintext only inside a member's browser, so no server-side process can complete it.

Invite links carry the inviter's key fingerprint in the **URL fragment**, which browsers never
transmit. An invitee's client can therefore verify the inviter's key against a value the server
never saw.

### Roles and the chain of trust

| Role | Can invite | Can remove / change roles |
|---|---|---|
| Admin | yes | yes |
| Ambassador | yes | no |
| Member | no | no |

Role changes are **signed by the granting admin**, so a client can verify a chain of grants back to
the group's creator without trusting the server. A server that fabricates a role cannot produce the
signature to back it.

Note the limit: signed grants prevent the *server* from lying about roles. They do not prevent a
legitimately-privileged member from misusing their authority. Once someone holds the group key and
the right to share it, they are trusted. The chain records who extended trust to whom.

### Revocation mode

Removing a member cannot retroactively revoke what they have already seen — they hold the group key.
Each group therefore chooses a mode **at creation**:

- **Rotating** — removal mints a new key generation, wrapped to every remaining member. The removed
  member keeps history but is cut off from new posts. Capped at 1,000 members, because rotation cost
  is linear in membership.
- **Open** — removal is access control only. No cap, no rotation, and the limitation is stated
  permanently in the group's UI.

A group can be converted Rotating → Open deliberately. The reverse is not offered: everyone who was
ever a member already holds the old keys, so "upgrading" would imply a guarantee it cannot deliver.

This is an explicit choice rather than an automatic threshold. A security property should never
change as a side effect of someone adding one more member.

### Key generations

Each rotation creates a generation. Generations are **parallel, not nested** — a post records its
generation, and the client performs exactly one unwrap to read it regardless of how many generations
exist.

Each generation's key is wrapped under the previous generation's key, so members hold only their
newest generation directly and walk the chain backward to read older content. Storage is
`O(members + generations)` rather than `O(members × generations)`.

### Message expiration

Every group has an expiration policy, defaulting to **30 days**. Expired posts are deleted by
DynamoDB TTL.

Expiration does more work than it appears to. It bounds key-generation growth, since generations with
nothing left to decrypt can be dropped. And it is the only forward-secrecy mechanism that works at
any group size — rotation protects future posts and costs `O(members)`, while expiration limits past
exposure at `O(1)` per item.

Because TTL deletion is eventual (typically within 48 hours), clients also filter expired items on
read rather than trusting deletion to have occurred.

## Data model

One DynamoDB table, one GSI. Every access pattern is a single `Query` or `GetItem`; nothing scans.

| Item | PK | SK | GSI1PK | GSI1SK |
|---|---|---|---|---|
| User | `USER#<uuid>` | `PROFILE` | | |
| Username claim | `USERNAME#<lower>` | `CLAIM` | | |
| Group | `GROUP#<gid>` | `META` | | |
| Membership | `GROUP#<gid>` | `MEMBER#<uuid>` | `USER#<uuid>` | `GROUP#<gid>` |
| Role grant | `GROUP#<gid>` | `GRANT#<uuid>` | | |
| Post | `GROUP#<gid>` | `POST#<day>#<ulid>` | | |
| Comment | `POST#<pid>` | `CMT#<path>` | | |
| Reaction | `POST#<pid>` | `RXN#<path>#<uuid>` | | |
| Invite | `INVITE#<iid>` | `META` | `USER#<invitee>` | `INVITE#<ts>` |
| Key pin | `USER#<uuid>` | `PIN#<other>` | | |
| Notification | `USER#<uuid>` | `NOTIF#<ulid>` | | |

**Membership items do double duty**, holding both the wrapped group key and the role, so the check
that gates every group operation is a single `GetItem`.

**Comments use a materialized path.** Because lexicographic ordering of `CMT#0003.0001.0002` *is*
depth-first traversal order, one query returns an entire thread already in display order. Depth is
capped at 8.

**Sort keys carry a day and a ULID.** ULIDs sort by creation time and need no coordinating counter;
the day gives a dump only day-level granularity while the precise timestamp rides inside the
encrypted payload. DynamoDB pagination is cursor-based natively, so infinite scroll needs no offsets.

## Frontend

React, TypeScript, Vite, Tailwind, shadcn/ui — a pure SPA on S3 behind CloudFront. Server-side
rendering would be pointless: the server holds only ciphertext.

TypeScript is load-bearing here rather than a preference. Passing the wrong `Uint8Array` into a
crypto function is exactly the bug class the type system catches.

Argon2id runs in WebAssembly, and all crypto runs in a Web Worker so decrypting a page of posts does
not block the UI.

### Theming

Every color, font, radius, border width, shadow, and text-transform is a CSS custom property. Three
themes ship: **Refined Terminal** (default), **BBS Revival**, and **Zine**.

The token vocabulary was designed against Zine first, deliberately — it is the most demanding
(hard offset shadows, zero radius, thick borders, uppercase headings), and a vocabulary that can
express it can express the others trivially.

Users may write custom themes. A theme is a **JSON object of token values, never a stylesheet**.
Every value is validated against an allowlist and applied through the CSSOM. No user-supplied string
ever reaches the page as CSS syntax — see the threat model for why this matters more here than in an
ordinary app.

## Infrastructure

```
CloudFront  (+ AWS WAF)
├── /*        → S3 (static SPA)          [origin access control]
└── /api/*    → Lambda Function URL (Go) [caching disabled]
                    └── DynamoDB (single table)
```

Same origin for app and API, so there is no CORS configuration. The Lambda holds no state between
requests and never possesses key material.

Rate limiting is enforced by WAF rate-based rules. This is a **cost** control as much as a security
one: login runs Argon2id at ~64MB and hundreds of milliseconds, so an attacker hammering the login
endpoint burns compute budget.

Environments are Terraform workspaces (`dev`, `prod`) in one AWS account, with resource names derived
from the workspace so a mistyped variable cannot cross-wire them.

Site name, domain, registration policy, and whether "no expiration" is a permitted group setting are
all runtime configuration, served to the SPA from an unauthenticated `/api/config`. Nothing about a
particular deployment is baked into the bundle.

## Testing

Beyond ordinary unit and integration tests, CI verifies the crypto against **fixed test vectors** —
known inputs with known expected outputs, checked in.

This is not optional. A round-trip test ("encrypt, then decrypt, expect the original") passes even
when both directions are wrong in the same way. If a refactor silently changes key derivation, every
existing user is locked out permanently and no recovery is possible, because the server cannot
re-derive anything. Fixed vectors are the only thing that catches it.
