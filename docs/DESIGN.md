# UndergroundBB — Design

This document explains how UndergroundBB works and why it is built the way it is. For what an
attacker can and cannot do, see [THREAT_MODEL.md](THREAT_MODEL.md).

## Overview

UndergroundBB is an end-to-end encrypted message board. Users join groups; groups contain posts;
posts contain threaded comments. Everything a user writes is encrypted in their browser before it
reaches the server, and the server never holds the keys to read any of it.

The stack is a Go binary on AWS Lambda behind CloudFront, a single DynamoDB table, and a React SPA
served as static files. There is no application server holding state, no session store, and no
plaintext content anywhere in the backend. (The one exception is the short-lived login challenge
item described below, which holds a random number and no key material.)

**This document describes the complete design, not the current state of the code.** The whole
design is settled and nothing here is speculative, but it is built in milestones: private groups,
invites, posts and comments come first, while public groups, join requests, notifications and
custom themes are deliberately sequenced later. Where something is not yet built, it is because of
ordering, not doubt. Progress is tracked in the repository's issues and milestones.

## The cryptographic core

Each user has two keypairs:

| Key | Algorithm | Purpose |
|---|---|---|
| Signing key | Ed25519 | Login challenge-response, signing posts and role grants |
| Wrapping key | X25519 | Wrapping and unwrapping group keys (ECIES with HKDF) |

Both private keys are encrypted with AES-256-GCM under a key derived from the user's password via
**Argon2id**, and the resulting blob is stored on the server. The password itself is never
transmitted, and neither is anything derived from it.

Groups have a symmetric **group key** (AES-256-GCM) that encrypts every post, comment, and reaction,
and — for private groups — the group's name and description. Each member holds a copy of the group
key wrapped to their X25519 public key.

### Login

1. Client sends a username to `POST /api/auth/challenge`.
2. Server generates a random nonce, **stores it** as the `USER#<uuid>` / `CHALLENGE` item with
   a short TTL, and returns it along with the user's salt and their wrapped private keys.
3. Client derives the key from the password with Argon2id, unwraps the private keys, and signs the
   nonce with the Ed25519 key.
4. Server **deletes the challenge item with a conditional write** and, only if that delete succeeds,
   verifies the signature against the stored public key and issues a session cookie.

The server learns only that someone holding the private key was present. Decryption of the private
key happens entirely in the browser, and GCM's authentication tag failing *is* the wrong-password
signal — no separate password verifier is stored.

**The challenge item is deliberate state, and the conditional delete is what makes the ceremony
sound.** A signed challenge response is a bearer credential until something marks it spent: the
tempting implementation — a timestamp or an HMAC over a server key, validated on return but never
recorded — verifies signatures correctly and **does not prevent replay**, so anyone who captures one
valid response can trade it for a fresh session repeatedly for as long as the window lasts. Making
the delete a condition of the verification, rather than a cleanup after it, is what spends the
nonce: two requests carrying the same nonce race for one delete and exactly one wins. A single-use
nonce is a requirement here, not an optimization.

This is the one piece of cross-request state in the system, and the statelessness claims elsewhere
mean **no session store and no key material** — never "no items with a short life." The challenge
item holds a random number and nothing else: no key material, nothing derived from the password,
and nothing that helps an attacker who steals it, since using it still requires a signature from a
private key the server does not have.

Note that step 2 is an **unauthenticated write** — anyone can request a challenge for any username,
and usernames are enumerable — so it is a write-amplification target and is rate-limited on those
terms, not merely on the harvesting terms discussed under Infrastructure below. The TTL
is short (a minute or two, enough for a slow Argon2id derivation on a phone) so abandoned challenges
expire quickly rather than accumulating.

**The challenge is a single slot per user — `CHALLENGE`, not `CHALLENGE#<nonce>` — and that is a
bound, not a tidiness preference.** Putting the nonce in the sort key makes every request a distinct
item, so an attacker who picks an enumerable username can inflate that user's partition without
limit, and the only thing removing the items is a TTL. TTL deletion is eventual — typically within
48 hours, as the cost section says — so a short TTL promises only that items become *eligible*, and
the steady-state count for a targeted user can far exceed what the rate limit implies per window.
It also lands in `USER#<uuid>`, the same partition as `PROFILE`, which is the hottest item that user
has and the one every login must read, so this is contention against the legitimate login path and
not merely storage. Every other unauthenticated write in the system is bounded this way already: the
failure counter is an attribute update on one existing item, so hammering it costs contention but
not cardinality. Overwriting one slot gives the challenge the same property, and a new challenge
invalidates any outstanding one. Single use is unaffected — the conditional delete still spends the
nonce and two racing requests still resolve to one winner. The cost is that a user with two tabs
mid-login has the first tab's challenge replaced, which fails closed: that tab retries.

**The session cookie authenticates; it decrypts nothing.** It is a short-lived signed token —
there is no session store, so the server holds nothing to look up — carried in an `HttpOnly`,
`Secure`, `SameSite=Lax` cookie. It names the user to the API and nothing more. The private keys
stay in the browser's memory for the life of the tab and are never sent anywhere, so a stolen cookie
yields ciphertext, group membership and metadata, but no plaintext and no key. Nor can it write
convincingly: every post carries an Ed25519 signature the cookie cannot produce, so forged content
from a stolen session fails verification in every reader's client. Session theft here is a genuinely
smaller event than in an ordinary application.

The cost of statelessness is the other half, and it is a real one: **a stateless session cannot be
revoked.** A stolen cookie stays valid until it expires. Neither a password change nor the
five-minute lockout ends a live session — which matters most for the user the password-change flow
is designed for, someone who believes they are compromised and reasonably expects that changing
their password logs the attacker out. It does not. Keeping sessions short is the only control here,
and it is a bounded one; a revocation list is the standard fix and is deferred rather than
dismissed, since it reintroduces exactly the server-side state this architecture does without.

**This means the server cannot count wrong passwords.** A mistyped password fails at step 3, inside
the browser, and never reaches the server at all. What the server can count is **failed signature
verifications at step 4**, which a normal user with a wrong password never reaches. The
five-attempts-in-five-minutes lockout therefore counts signature failures, and the attack it bounds
is credential stuffing rather than password guessing — someone guessing a password is limited by
Argon2id and by the challenge endpoint's rate limit, not by the lockout. **Replay is bounded by the
single-use nonce, not by this lockout**, which is worth separating because a replayed valid
signature never fails verification and so never increments a counter that only counts failures.

The counter and a lock-until timestamp live as attributes on the user's `PROFILE` item, incremented
on a failed step 4 and cleared on a successful one. **That increment is an unauthenticated write** —
step 4 takes a username and a signature, and the signature does not need to be valid to cause it —
so it needs a rate limit of its own; see Infrastructure. The lock-until value is the one short-lived
thing in an item class that never expires, so it is a timestamp compared on read rather than a TTL:
the item must outlive the lock.

### Multi-device

**There is no device identity.** No device is registered, distinguishable from another, or
separately revocable, and there is no pairing step or key sync protocol. Any device can log in with
the username and password: it downloads the same encrypted key blob and derives the same key. The
password is the portable credential, and the encrypted blob is safe to store centrally precisely
because it is encrypted.

What that does *not* mean is that everything is per-device local state. Per-user state that is not a
private key **follows the user across devices**, because it is stored server-side and protected by a
key the password reproduces: the preferences blob is sealed to a user-derived key, and key pins are
**signed** with the user's Ed25519 key and stored under their own partition — deliberately, so a new
device inherits what an existing one verified rather than re-TOFUing every counterparty from
scratch. The distinction is that the server holds this state without being trusted with it.

### Recovery

At signup, a high-entropy recovery code is generated and a **second copy** of the private keys is
wrapped under it, stored as its own `USER#<uuid>` / `RECOVERY` item and served by no read path. A
user who forgets their password can recover with the code. A user who loses both has permanently
lost access — the server has nothing to reset, by design. The code is a **second full credential**,
with the exposure that implies — see
[the threat model](THREAT_MODEL.md#the-recovery-code).

Changing a password does **not** change keys. It unwraps the private keys with the old password and
re-wraps them under the new one — the keypairs, group memberships, and everything signed by them are
untouched.

It does, however, **issue a new recovery code and re-wrap the recovery copy under it**, invalidating
the old code. This is deliberate. The recovery copy decrypts to the same private keys, so leaving it
alone would mean a user who changes their password because they believe they are compromised gains
nothing at all if the attacker also holds their recovery code — they would have done the one thing
the interface offers and still be exposed. Because a password change therefore always produces a new
code, the flow has to make the user store it before completing.

**Recovering with the code is the mirror flow, and it behaves symmetrically.** A user who has
forgotten their password authenticates by proving possession of the recovery code — the one flow in
the system that proves possession of something other than the password, which works because the
recovery copy has its own salt and no dependence on the password at all. The client unwraps the
private keys with the code, sets a new password, and re-wraps the `PROFILE` copy under it. **It
also issues a new recovery code and re-wraps the `RECOVERY` copy under that**, for the same reason
a password change does: a user recovering because they lost control of their password should not
remain reachable through a code that may well have leaked alongside it. Neither flow leaves the
other credential untouched, so neither leaves a user who has acted on a compromise still exposed
through the credential they did not think about.

Both copies are therefore rewritten together, and — like signup — **that is one
`TransactWriteItems`**. It writes `PROFILE` and `RECOVERY`, and this time both live in the same
partition, but the partial-write exposure is the same one: a `PROFILE` re-wrapped under the new
password with a `RECOVERY` item still holding the old code leaves exactly the stale credential the
flow exists to invalidate, and the reverse leaves an account whose recovery code no longer matches
the password that works.

Neither operation is a **key rotation**, which is the subject of the next section: a much heavier
operation, and the only one that invalidates existing wrapped group keys.

### Key rotation

Three operations get conflated under "changing my keys," and only the third one actually changes
them. A password change (above) and a recovery-code reset both re-wrap **the same private keys**
under a new wrapper. **Key rotation replaces the keypairs themselves**, and it happens in exactly
two cases:

1. The user has lost **both** their password and their recovery code. The private keys still exist
   in the database but nothing can unwrap them, so they are permanently useless and the account
   needs new ones to keep participating.
2. Deliberate invalidation after suspected compromise — a stolen laptop, malware.

Naming both cases is what makes "rare but heavyweight" a fact rather than an assertion: it takes a
double loss or a security incident, so it should happen a handful of times in a deployment's life.

The consequence is the reason it is heavy. **Every group key the user holds was wrapped to the old
X25519 key**, which they can no longer unwrap, so they are locked out of all group content while
still appearing in every member list. The design's answer is **dormant memberships plus a
re-invitation per group**: the membership rows survive — the user stays in the member list and their
post history stays attributed to them — but they cannot read until an admin or ambassador in each
group re-wraps the current group key to their new public key. That concentrates the work into one
deliberate action per group, taken by someone who already has the authority, rather than spreading
confusion across every co-member. It is the same re-invitation event the pinning section describes,
and this is its cause.

**The Ed25519 half of a rotation is the harder half, and it is why the user item keeps a key
history.** Replacing a signing key does not merely affect what the user signs next — it invalidates
every signature they have ever made, because the only public key a reader could fetch would be the
new one. Two of those signatures are claimed as permanent properties: every post and comment carries
one, and `GRANT#` items must stay verifiable back to the group creator *forever*, which is why they
never expire. A rotating creator would otherwise strand the root of every role chain in their group.
There is no re-signing path either, since case 1 is a user who no longer holds the old private key
and cannot reproduce anything with it.

So **superseded Ed25519 public keys are retained on the `PROFILE`, each with the interval it was
current for, and a signature is verified against the key that was current when the item was
written** — the day in the sort key gives that to the resolution required. A rotation appends to
this history rather than replacing an entry, the `GET /api/users/:id` projection serves the whole
set, and `PIN#` accordingly pins a key *set* rather than a single key. Without the history a client
has only bad options: reject unverifiable posts and the user's history vanishes, contradicting the
attribution this section promises; show them unverified and "forged" becomes indistinguishable from
"signed with a superseded key"; or stop verifying old items and the property is gone altogether.

Retention is why this is affordable: the history holds public keys only, it grows by one entry per
rotation, and rotations are rare by construction. The X25519 half needs no equivalent — group keys
are re-wrapped to the new key, so nothing verifies against an old one.

Two further properties are easy to get wrong when implementing it:

- **A rotating user re-enters the chain at the current generation, and keeps their history.** Their
  new entry point is a wrap of the *current* group key, and the older `GENKEY#` links are reachable
  backward from it. Rotation therefore costs no history — the backward chain rescues this case for
  free, which is worth knowing before someone builds an expensive re-wrap that is not needed.
- **A dormant membership is not a removal, and must not mint a generation.** In a `Rotating` group
  a removal triggers a re-key; if dormancy were implemented as remove-then-re-invite, every user
  keypair rotation would burn a generation in every group that user belongs to and drag the entire
  membership through a re-wrap. The distinction is invisible unless stated, and the cost of missing
  it scales with how many groups the rotating user is in.

**The interface must clearly distinguish "change password" from "rotate keys."** They sound alike
and differ enormously: one is trivial and keeps everything, the other invalidates every wrapped
group key the user holds and requires an admin in every one of their groups to act. A user who
conflates them picks the destructive one believing it is the cheap one.

**Group governance rules — who may leave, what happens to the last admin of a group, how a
successor is chosen — are decided in the issues rather than here.** They are membership policy
rather than cryptography, and they do not change any key or item in this document.

### Key pinning and verification

The invite handshake stops the server substituting a key for someone you are *already* connected to,
because the invitee signs their own keys. It cannot help on **first contact**: the first time you
are handed a public key for a username you have never seen, you have nothing to compare it against.

The answer is trust on first use. A client **pins** a user's public keys the first time it sees
them, storing them under `PIN#<other-uuid>` — **keyed by the pinned user's uuid, not their
username**, so that a name displayed as typed can never split one person across two pin rows and
silently re-TOFU them. If a pinned key later changes, the client **hard-blocks**
rather than warning — it refuses to encrypt to the new key or to accept content signed by it until a
person resolves it. The reasoning is that a key change is genuinely rare, so it can afford real
friction, while the operation it protects is common and must not train people to click through
warnings.

**Every pin is signed with the pinning user's own Ed25519 key, and an unsigned or badly-signed pin
is not a pin.** This is the property the whole mechanism rests on, and it is not optional. `PIN#`
is a row in the same table as everything else, so without a signature the hard-block compares a key
the server just served against a pin the server also just served: an operator substituting a key
does not have to defeat the comparison, it rewrites the pin to match, and the client compares two
attacker-chosen values and sees nothing wrong. No mismatch, no hard-block, no re-invitation
ceremony. The signature is what makes the record trustworthy to the only party who cares about it —
the client that wrote it — and a client that stores a pin and reads it back without verifying has
implemented something that passes every test and protects against nothing.

**Pins live server-side deliberately, under the pinning user's own partition, so a new device
inherits what an existing one verified.** The alternative — pins as local browser state — means
every new login re-TOFUs every counterparty, and warnings that fire constantly are warnings nobody
reads. This is state that follows the user rather than the browser, which is possible precisely
because the signature makes server storage safe. One consequence follows and is worth stating here
rather than rediscovering later: since a pin is signed by the pinning user's Ed25519 key, **rotating
that keypair invalidates that user's entire pin set**, exactly as it resets the preferences blob.

**Rotation must therefore re-sign every pin row under the new key, and must do it before the old key
is discarded.** The superseded-key retention above rescues posts and grants because those carry a
day in the sort key, which says which key interval to verify against; `PIN#<other-uuid>` carries no
day and no timestamp, so that rule cannot be applied to it at all. A client loading its own pins
after a rotation would hold the superseded key set with no way to know which interval any pin
belongs to, and would be left with the three bad options this section already rejects: drop the
unverifiable pins and every counterparty silently returns to first contact — reproducing, across the
whole pin set at once, the deletion attack the threat model marks *Possible*; trust them unverified,
which is the unsigned pin the section calls protection against nothing; or prompt on all of them,
which is the warning fatigue the re-invitation flow exists to avoid. The material for the re-sign is
all local — the client already holds its pins — and it is one `BatchWriteItem` loop of the same
shape as the rotation and mark-read loops, interruptible in the same way. **The ordering is the part
most likely to be got wrong: re-sign, then discard the old private key.** Because that loop can be
interrupted, the pin row also carries the **interval of the pinning key it was signed under**, so a
half-re-signed set can be finished on the next login instead of being ambiguous forever. Rebuilding
a pin set from scratch remains one more thing a re-invitation event has to do, but a rotation alone
no longer requires it.

**A signature authenticates a pin's contents, not its existence, and that gap is not closed in v1.**
The operator cannot rewrite a pin, but it can withhold or delete one. If the server serves a
substituted key for Bob *and* omits Alice's `PIN#` row for him, Alice's client finds no pin, concludes
this is a first sighting, and pins the substituted key — no signature is forged and no check fails,
because there is no record left to check. The hard-block is conditional on a pin being present, and
**absence is indistinguishable from genuine first contact**. So pinning protects a connection the
client can still see; it does not protect the client's knowledge that a connection existed.

Closing it needs a signed record of the pin *set* rather than of each pin — a counter or a digest
over the pinned usernames, held on the user's own `PROFILE` and checked on load, so a missing row
becomes a detectable mismatch. That is deferred rather than dismissed, for two reasons worth
stating: it puts a read-modify-write on the profile item back into every new pin, and it has to
survive the keypair rotation described above, which invalidates the whole pin set and would
therefore have to reset the manifest in the same operation without that reset being forgeable.
Until it exists, **fingerprint verification is the only control that detects a deleted pin**, which
is the same answer the design already gives for first contact — and that is the honest way to read
this: pin deletion returns a counterparty to the first-contact case, silently.

Resolving a mismatch is deliberately not a dismissable dialog. A legitimate key change is a
**re-invitation event**: the user's group memberships go dormant, and an admin or ambassador
re-invites them through the same signed handshake, which forces exactly one deliberate check by
someone with authority rather than N warnings across N members.

The re-invitation flow is therefore the one path that **clears a stale pin rather than blocking on
it**. The authorizing admin's own client also sees the mismatch, and a blanket "hard-block on
mismatch" check would block the very operation that resolves it, making a key change unrecoverable.
Approving the re-invite *is* the trust decision, and it replaces that admin's pin explicitly. Other
members' pins update once that has happened. This delegates verification to whoever re-invited — a
real trust decision, and the honest limit of what pinning gives you.

Verification stays **available rather than mandatory**: fingerprints are shown on profiles, there is
an explicit verify affordance, and a badge appears when two users have verified each other. Invite
links additionally carry the inviter's fingerprint in the URL fragment, which the browser never
transmits, so the invitee's client can check it against a value the server never saw.

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

**Two storage details make the ceremony work, and both are easy to get wrong.**

*An invite has no invitee until step 2.* The step 1 payload deliberately contains no invitee
identity — an invite is a link, handed to someone who may not have an account yet, and
`GET /api/invites/:id` is unauthenticated for exactly that reason. So the invite item is **written
without a GSI1 entry**, and DynamoDB simply omits it from the index; the `USER#<invitee>` /
`INVITE#<YYYY-MM-DD, UTC>#<rand>` entry is **added at acceptance**, once there is a uuid to point
at. Reading the table
row as though GSI1PK were populated at creation makes accountless invites impossible, which would
take the link flow with it.

*Step 3 needs an inviter-keyed lookup, and the invitee index cannot serve it.* "The next time the
inviter's client is online" means that client must find **its own invites that have been accepted
and are awaiting completion** — a query keyed on the inviter, which neither `INVITE#<iid>` (it needs
the id you are trying to discover) nor a GSI keyed to the invitee can answer. Hence the second row:
the inviter's client lists `USER#<inviter>` / `SENT#` and completes anything accepted, **deleting
each row as it completes** so the query returns pending work rather than a history. Without it
the only implementations available are a `Scan` or a fan-out across the inviter's groups, and this
design permits neither. **Completion is driven by that query on login**, not by the notification
path — notifications carry no content a client can act on, and step 3 must work for an inviter who
never opens the notification.

> **Open question — `ephemeral_pubkey`.** It is signed into the step 1 payload and then plays no
> part in steps 2 or 3, which wrap using the inviter's own X25519 key. Either it is vestigial and
> should be dropped, or it is meant to give the wrap forward secrecy — in which case step 3 must
> wrap with the ephemeral *private* key and this document must say where that key lives between
> steps 1 and 3, which for a browser-held key is the hard part. It is called out rather than
> quietly removed because signing a field with no defined semantics reliably produces
> implementations that generate it, sign it, and discard it — the ceremony without the property.
> This is resolved before the invite handshake is built.

Invite links carry the inviter's key fingerprint in the **URL fragment**, which browsers never
transmit. An invitee's client can therefore verify the inviter's key against a value the server
never saw.

### Visibility — private and public groups

A group is **private** or **public**, chosen at creation.

**Private** groups encrypt their name and description under the group key, so they are invisible to
non-members, and the only way in is an invite.

**Public** groups keep name and description in plaintext so they can be listed in a directory and
searched. **That directory is a sparse GSI1 entry written only on public groups**: `PUBLIC#<shard>`
as the partition, `NAME#<name>#<gid>` as the sort key, so browsing is a `Query` and prefix search is
a `begins_with` on it.

**Group names are deliberately not unique, and the gid suffix on that sort key is what makes
non-uniqueness safe.** Two clubs both calling themselves "Book Club" is normal, and forbidding it
would be a worse product — so unlike usernames, group names get no claim item and no conditional
write. But a GSI key is not a primary key: DynamoDB does not reject a duplicate, it keeps one entry
per distinct index key, so two public groups sharing a name **and** a shard would project the same
key and the second would silently overwrite the first. The older group would vanish from the
directory while its `GROUP#<gid>` / `META` row sat in the table intact, reachable only by someone who
already had the gid — no error to either party, and a name-squatting primitive available to any
account, since the shard fan-out is small by design and a handful of attempts covers it. Appending
the gid makes the key unique by construction. `begins_with(GSI1SK, "NAME#" + prefix)` is the only
read this index serves, and the suffix does not disturb it. A directory listing is therefore
expected to show duplicate names, and the interface must not assume otherwise. Private groups write no entry at all and are therefore absent from the index
rather than filtered out of it — the strongest form of "invisible to non-members", and the reason
this costs nothing for the groups that want privacy. The shard exists only to keep one directory
partition from becoming a write hotspot as the deployment grows; a small fixed fan-out is enough,
and a browse reads all shards and merges.

This shares GSI1 with the three user reverse-lookups rather than adding a second index, which works
because those all partition on `USER#<uuid>` and this partitions on `PUBLIC#<shard>` — the key
spaces cannot collide. Without it a directory would need a `Scan`, which is the one thing this
schema does not do. **Posts are still encrypted under the group key** — public means *discoverable*, not
*readable*. Someone browsing the directory sees that a group exists and what it calls itself; they
see none of its content.

In both cases the **member list is visible to members only**. There is no setting that changes this.

Public groups are joined by **request**, which is the invite handshake run in the opposite
direction: the requester signs a request carrying their public keys, and an admin or ambassador
approves it by wrapping the group key to the keys that were signed. The server can no more
substitute a key here than it can during an invite — same machinery, same guarantee.

### Direct messages

A DM is **a group with `type: "dm"`**: exactly two members, no further invites, and no name (the UI
renders the other member's username). Group key, key wrapping, signed posts and encryption are
all identical.

`type` is a **plaintext attribute on the group's `META` item**, not a separate row — a DM occupies
the same `GROUP#<gid>` partition as any other group, which is what lets one codepath serve both. It
is the only attribute in this design that changes an item's validation rules, and it needs a stated
home for that reason: the three invariants above — two members, no invites, no name — are enforced
against it, and nothing else records them. It is also one of the few constraints the **server** can
usefully check in a design that pushes almost everything client-side, since membership count and
invite creation are both server-mediated operations.

A DM appears in a user's group list like any other group, through the same `USER#<uuid>` GSI1 entry
on its membership item. That is deliberate — one listing query, no special case — and it means a
database dump shows who direct-messages whom exactly as clearly as it shows group membership. See
[the social graph](THREAT_MODEL.md#the-social-graph).

This is deliberate. A separate one-to-one message path would be a second implementation of the same
cryptography, and the second implementation is where the bug lives. There is one codepath.

Three group-level settings still need answers, because "identical" would otherwise answer them by
omission:

- **A DM is `Open`, with the mode picker hidden.** Rotating would be meaningless: removing the other
  member leaves a group of one, so there is nothing to re-key to. Saying a DM *is* `Open` rather than
  that it has no mode keeps the design at two revocation modes instead of three, and gives blocking a
  correspondent a defined meaning — it is a UI state with no key consequence, exactly as removal is
  in any other `Open` group. A DM therefore has one generation for its whole life: the chain, its
  truncation rule and the `META` chain floor exist but never advance.
- **Expiration behaves exactly as in any other group**, defaulting to 30 days. DMs are not the one
  place in the system with permanent retention, which is the right outcome given they hold the
  content with the smallest anonymity set.
- **A first DM to someone you have never contacted is the TOFU case**, and the handshake does not
  help: there is no inviter and invitee here, the sender picks the recipient, so the server supplies
  the recipient's key with nothing to check it against. The key is pinned at that moment and any
  later change hard-blocks, but the first contact itself is trust-on-first-use. This is the row the
  threat model's attack table marks **Possible**, and fingerprint verification is the only thing that
  closes it.

### Roles and the chain of trust

| Role | Can invite | Can remove / change roles |
|---|---|---|
| Admin | yes | yes |
| Ambassador | yes | no |
| Member | no | no |

Role changes are **signed by the granting admin**, so a client can verify a chain of grants back to
the group's creator without trusting the server. A server that fabricates a role cannot produce the
signature to back it.

**Grants are append-only, and that is what makes the chain walkable.** A chain is
`creator → Alice → Bob`: verifying Bob's grant means checking it was signed by Alice *while Alice
held admin*, which means reading Alice's grant, and so on back to the creator. One row per subject
cannot express that — demoting Alice would overwrite the very row Bob's grant is verified against,
and Bob's legitimately-granted role would become unverifiable in exactly the way a forgery looks.
So the sort key is `GRANT#<uuid>#<YYYY-MM-DD, UTC>#<rand>`: a subject's history is
`begins_with(SK, "GRANT#" + uuid)`, and verifying a grant signed on day D means finding the
grantor's grant that was current on D. That is the same point-in-time reasoning the superseded-key
retention uses, at the same day resolution, applied to roles instead of keys. **Revocation is an
appended row, never a delete** — a deleted grant is indistinguishable from one that never existed.
The hot path is untouched: the current role lives on the membership item and gates writes with a
`GetItem`, so this history is read only by the chain walk, which is already the slow path.

Note the limit: signed grants prevent the *server* from lying about roles. They do not prevent a
legitimately-privileged member from misusing their authority. Once someone holds the group key and
the right to share it, they are trusted. The chain records who extended trust to whom.

### Revocation mode

Removing a member cannot retroactively revoke what they have already seen — they hold the group key.
Each group therefore chooses a mode **at creation**:

- **Rotating** — removal mints a new key generation, wrapped to every remaining member. The removed
  member keeps history but is cut off from new posts. Capped at 1,000 members (matching Signal's
  Sender Keys limit). Adding member 1,001 **fails with an explicit error** explaining that the group
  re-keys on removal and that this is what bounds it. It never silently becomes an `Open` group.
- **Open** — removal is access control only. No cap, no rotation, and the limitation is stated
  permanently in the group's UI.

The cap is set by the write burst, not the CPU. A rotation writes one `GENKEY` chain link for the
whole group, and then re-wraps **every remaining member's entry point** — and it is that second,
per-member set of writes the cap is sized against. The wraps themselves are cheap; the writes are
not, and they are issued **from a browser**. `BatchWriteItem` takes 25 items at a time, so a rotation
at the 1,000-member cap is about 40 batched round trips, on the order of a few seconds.

**The chain link must be committed before any membership item points at the new generation.** A
member who fetches a re-wrapped entry point for generation N while `GENKEY#<N−1>` does not yet exist
holds a key into a chain with a missing link, and cannot read history at all. A resumed rotation
must therefore re-use the generation key the interrupted one minted rather than issuing a fresh one,
and the batch cursor in the marker is a position in the **membership** list, not in anything
group-wide.

That is the sizing the cap is chosen to hold. It is worth seeing what the same arithmetic does
without one: a 10,000-member group would need roughly 400 round trips over tens of seconds, and the
dangerous property there is not that it is slow but that **it can fail halfway** — a closed tab or a
dropped connection at member 5,000 leaves the group split across two generations, some members
holding the new key and some not. The cap keeps that window small; it does not remove it, because
even 40 round trips can be interrupted.

Rotation is therefore specified as a **resumable job**, not a single operation. The server tracks a
rotation-in-progress marker, the client posts wrapped keys in batches and can resume where it left
off, and **new posts continue to use the previous generation until the rotation completes**. Any
implementation that treats rotation as one atomic client-side loop is wrong, and will corrupt groups
at the top of the supported range.

Something must also **act on that marker**, because rotation is client-driven and the group key
exists in plaintext only inside a member's browser — so a rotation whose client never comes back has
no other actor that can finish it. Left alone, the removed member goes on reading every new post
indefinitely, and nothing in the group indicates anything is wrong. The marker therefore carries a
staleness deadline, and a rotation past it is **surfaced to every remaining admin** so that someone
else can resume it. Without that, a closed tab silently converts a removal into no removal at all.

A group can be converted Rotating → Open deliberately. The reverse is not offered: everyone who was
ever a member already holds the old keys, so "upgrading" would imply a guarantee it cannot deliver.

This is an explicit choice rather than an automatic threshold. A security property should never
change as a side effect of someone adding one more member.

### Key generations

Each rotation creates a generation, and a post records the generation it was encrypted under.

**Each generation's key is wrapped under its successor**: generation N is encrypted under
generation N+1, never the reverse. A member holds only the newest generation directly and unwraps
backward from it — gen(N) yields gen(N−1), which yields gen(N−2), and so on.

The direction is the whole security property, so it is worth stating what it buys and what the
opposite would cost. Because wrapping runs newest-to-oldest, a member cut off at generation N holds
nothing that derives generation N+1: rotation actually revokes. Chaining the other way — each new
generation encrypted under the *previous* one — would let anyone who ever held a generation derive
every generation that followed it, so removal would cut off nobody and the guarantee in Limitation 3
of the threat model would be void. **An implementation that gets this backwards still passes a
round-trip test.**

Storage is `O(members + generations)` rather than `O(members × generations)`, which removes the
400KB item ceiling a per-member-per-generation layout would hit.

The cost is that reading old content takes one unwrap per generation crossed, rather than a constant
one. This is paid only when reading back past a rotation, and the unwrapped generation keys are
cacheable client-side, so a session walks any given stretch of the chain once.

### Message expiration

Every group has an expiration policy, defaulting to **30 days**. Expired items are deleted by
DynamoDB TTL.

**Comments and reactions carry their own TTL attribute**, set from the parent post's expiry when
they are written. DynamoDB deletes items individually and does not cascade, and comments live in a
different partition from their post (`POST#<pid>` rather than `GROUP#<gid>`), so a TTL on the post
alone would delete the post and leave its entire thread in the table indefinitely. They cannot
inherit the expiry lazily either — once the post is gone there is nothing left to inherit from. This
matters because comments are encrypted under the same group key as posts and are usually the larger
share of a thread's text: without their own TTL, the forward-secrecy property below would hold for
post bodies and quietly fail for everything hanging off them.

Expiration is the only forward-secrecy mechanism that works at any group size — rotation protects
future posts and costs `O(members)`, while expiration limits past exposure at `O(1)` per item.
**It is also optional**, where a deployment permits it: a group set to never expire keeps that
mechanism switched off permanently, and the consequences below and in the threat model apply to it
in full.

It also lets the generation chain be truncated, but **only from the old end, and only contiguously**.
Because generation *n* is reachable solely by unwrapping generation *n+1*, every generation is a
load-bearing link regardless of whether any of its own posts survive: dropping an empty generation
from the middle of the chain destroys access to every older generation behind it, including content
that has not expired. Truncation therefore starts at generation 1 and stops at the first generation
with surviving content. **A middle generation is never droppable, however empty it is.**

**`GENKEY#<nnnnnn>` items therefore carry no TTL attribute, ever.** Posts do expire by DynamoDB TTL,
which is per-item and unconditional — it deletes on a schedule without consulting anything else. The
truncation rule here is global: a link may go only once every older link has already gone. TTL cannot
express that precondition, so a TTL on a `GENKEY` item would eventually delete a middle link and
destroy access to everything behind it, silently and irreversibly, with nothing in the table
recording that the link was load-bearing. Truncation is a deliberate operation that walks forward
from the oldest surviving generation and stops at the first one with content.

The group's `META` item records the **oldest surviving generation**, so a member walking backward
knows where the chain floor is and stops there rather than treating an absent `GENKEY` as a
corrupted chain.

**Truncation must re-encrypt a private group's name and description before it advances past their
generation, or it destroys them permanently.** The name is not content: it is an attribute on `META`,
it has no TTL, and `META` never expires because it records the floor. So a private group created at
generation 1, whose early posts have all aged out, truncates generation 1 away — and the name, still
sitting on `META` and still claiming generation 1, becomes undecryptable to **every member,
forever**. Not a stale-history edge case: the group's own name. The truncation walk is defined over
posts, and surviving content is the only thing that pins the floor, which is exactly what the name is
not. The fix belongs here rather than where the name is described, because here is where an
implementer is standing when they get it wrong: **when truncation would advance the floor past the
generation the name and description were encrypted under, re-encrypt them under the current
generation first.** That is one write, on an item the truncation already updates to move the floor,
and it leaves the "rotation does not re-encrypt the name" sizing untouched — the cost is paid at
truncation, not at rotation. Treating the name's generation as content instead, so the floor may
never pass it, would pin the chain at generation 1 for every group forever and defeat truncation
entirely. Public groups need none of this; their names are plaintext.

That is a weaker bound than it first appears, and worth being honest about: a single long-lived post
under an early generation pins the whole chain from that point forward. **In a group with expiration
disabled there is no truncation at all** — nothing ever ages out, so "the chain accumulates without
bound under churn" stops being a worst case and becomes the certain one. That is an operational cost
of `no expiration`, not only a security one, and it is the reason the setting is a deployment
decision rather than something every group is offered by default. `Rotating` groups rotate on
every removal, so generation count tracks membership churn rather than time, while truncation only
ever bites at the old end. A group with steady churn and any pinned early content accumulates
generations without bound, and the per-read cost of walking the chain grows with it. Client-side
caching of unwrapped generation keys is what keeps that tolerable in practice; if it ever stops
being tolerable, the fix is re-wrapping a member's entry point deeper into the chain, not dropping
links out of the middle.

Because TTL deletion is eventual (typically within 48 hours), clients also filter expired items on
read rather than trusting deletion to have occurred. That filter is a **display convenience, not the
deletion mechanism** — it hides items that are still in the table, so it will happily mask ciphertext
that was never given a TTL at all. Do not treat a clean-looking UI as evidence that expiry is
working; check the table.

## Data model

One DynamoDB table, one GSI. **Nothing scans: every read is a `Query` or a `GetItem`.** That is the
property worth claiming, and it holds everywhere. Several operations take more than one such read —
grant-chain verification, walking the generation chain to read older content, and rendering a
notification each need a small bounded sequence — but none of them scans, and none is unbounded in
the size of the table. The one read whose cost is not bounded by what it returns is the **unread
notification count**, a filtered `Query` over a range that grows with retained history; it is still
a `Query`, and it is discussed with the notification item below.

| Item | PK | SK | GSI1PK | GSI1SK | TTL |
|---|---|---|---|---|---|
| User | `USER#<uuid>` | `PROFILE` | | | never |
| Recovery blob | `USER#<uuid>` | `RECOVERY` | | | never |
| Login challenge | `USER#<uuid>` | `CHALLENGE` | | | ~2 min |
| Username claim | `USERNAME#<lower>` | `CLAIM` | | | never |
| Group | `GROUP#<gid>` | `META` | `PUBLIC#<shard>` (public only) | `NAME#<name>#<gid>` | never |
| Membership | `GROUP#<gid>` | `MEMBER#<uuid>` | `USER#<uuid>` | `GROUP#<gid>` | never |
| Generation key | `GROUP#<gid>` | `GENKEY#<nnnnnn>` | | | never |
| Rotation marker | `GROUP#<gid>` | `ROTATION` | | | never |
| Role grant | `GROUP#<gid>` | `GRANT#<uuid>#<YYYY-MM-DD, UTC>#<rand>` | | | never |
| Post | `GROUP#<gid>` | `POST#<YYYY-MM-DD, UTC>#<rand>` | | | group policy |
| Comment | `POST#<pid>` | `CMT#<path>` | | | group policy |
| Reaction | `POST#<pid>` | `RXN#<cmtpath>#<reactor>` | | | group policy |
| Invite | `INVITE#<iid>` | `META` | `USER#<invitee>` | `INVITE#<YYYY-MM-DD, UTC>#<rand>` | signed `expires_at`, cleared at acceptance |
| Invite (inviter's copy) | `USER#<inviter>` | `SENT#<YYYY-MM-DD, UTC>#<rand>#<iid>` | | | signed `expires_at`, cleared at acceptance |
| Join request | `GROUP#<gid>` | `REQ#<uuid>` | `USER#<requester>` | `REQ#<YYYY-MM-DD, UTC>#<rand>` | never (pending) / cool-off (denied) |
| Key pin | `USER#<uuid>` | `PIN#<other-uuid>` | | | never |
| Notification | `USER#<uuid>` | `NOTIF#<YYYY-MM-DD, UTC>#<rand>` | | | group policy |

**The TTL column is part of the table on purpose.** This assignment was prose for several revisions
and drifted every time a row was added — a new row would arrive and the separate list would not be
updated, which is a defect the list's own claim to be exhaustive actively hides. Answering the
question in the row makes it impossible to add an item without deciding, and the paragraphs below
explain the reasoning rather than carrying the assignment.

**The user item is mixed, not wholly encrypted.** `USER#<uuid>` / `PROFILE` necessarily holds
plaintext the system reads: the username, the Ed25519 and X25519 **public** keys other members need
— including **superseded Ed25519 public keys with the intervals they were current for**, without
which no signature written before a rotation could ever be verified — the Argon2id salt, and the
wrapped private keys. It also holds an **encrypted preferences blob** —
theme and font choices — sealed under a key **derived by HKDF from the user's X25519 private key**,
so they do not become another identifying signal in a dump. That derivation is deliberate: the
recovery code restores the same private keys, so preferences survive a password change and a
recovery alike, with no second wrapped copy to keep in step. Deriving the key from the password
instead would leave a recovered account's preferences permanently unreadable — and it would fail
silently, looking like a theme that reset itself rather than a key that was lost. The email, when
present, is encrypted separately under a **server-held** key, because the server has to read it to
send mail. Three different protections in one item, and the distinction is the point: only the
preferences blob is beyond the operator's reach.

That derivation does have one case it does not survive, and it is worth naming rather than leaving
to be discovered: a **keypair change resets preferences**. A pinned key change is a re-invitation
event, and the new X25519 key is a new HKDF input, so the old blob will not open. This is acceptable
only because of what the blob holds — a theme and a font, both re-choosable in a few seconds — and
it would not be acceptable for anything the user could not trivially reconstruct. Nothing else in
the design should be keyed this way.

**Three writes in this schema are contested, and all three are conditional.** The comment ordinal
above is one. The second is the login challenge delete, where two requests carrying the same nonce
race for one delete and exactly one wins — that race is the replay guarantee, not an incidental
detail. The third is the username claim below. Nothing else in the table has two writers competing
for one key — which is a separate question from whether a write is *atomic*: signup is not
contested beyond its claim, but it spans three items and is a transaction for that reason.

**Usernames are unique case-insensitively, and displayed as typed.** The `USERNAME#<lower>` claim
item decides the first half: `Alice` and `alice` cannot both exist, and **every lookup lowercases**,
including `POST /api/auth/challenge` — a user who signed up as `Alice` logs in as `alice`. The
`PROFILE` item keeps the username as typed, and that is what is projected, displayed and shown
beside a fingerprint, because a name the user chose the capitalization of is theirs to present.
**The claim item holds the uuid its username resolves to**, which is what makes it a lookup and not
merely a lock: every other user row is keyed `USER#<uuid>`, and a login arrives with a username, so
this row is the only thing that bridges the two.

**The claim is only a claim because the write is conditional on `attribute_not_exists(PK)`.**
Without that, two concurrent signups for `alice` both read the name as available and both write:
two `PROFILE` items believing they own it, one claim row pointing at one of them, and the loser's
account reachable by no login at all, since `/auth/challenge` lowercases and resolves through the
claim. The account would exist, hold keys, and be unreachable — a worse outcome than a lost
comment, and silent in the same way.

**That condition is necessary and not sufficient: signup writes three items across two partitions,
so it is one `TransactWriteItems`.** The claim, the `PROFILE` and the `RECOVERY` item cannot be a
single conditional `PutItem`, and issuing them as separate writes leaves two failure states that an
interruption — a timeout, a throttle, a client disconnect — reaches without any concurrency at all:

- **Claim written, profile not.** The username is burned permanently. It is held by a `PROFILE`
  that does not exist, `attribute_not_exists(PK)` rejects every later attempt including the same
  user retrying, and nothing short of manual table surgery releases it.
- **Profile written, claim not.** Identical in outcome to the concurrent-signup bug above, reached
  by a different route: the keys exist and `/auth/challenge` resolves through a claim that is not
  there.

A transaction subsumes the conditional write rather than replacing it — the same
`attribute_not_exists(PK)` still does the concurrency work, and atomicity closes the partial-write
routes to the same unreachable account. It costs double the write capacity for the one operation in
the system that happens once per account, which is a fair trade. **A `PROFILE` without its
`RECOVERY` item is the quietest failure of the three**, since nothing is wrong until the recovery
code is needed, which is exactly when nothing can be done about it.
Since the claim is case-folded, no two accounts can differ by case alone, so displaying the typed
form costs nothing in impersonation terms. **Homoglyphs across scripts are a harder version of this
problem and are not solved here** — fingerprint verification, not the username, is what ultimately
identifies a counterparty.

**The recovery copy is a separate item, not an attribute of the profile.** `USER#<uuid>` /
`RECOVERY` holds a **second copy of the private keys wrapped under a key derived from the recovery
code**, with its own salt — derived from the recovery code alone, with **no dependence on the
password**. That independence is the whole point of the item: it is what a user who has forgotten
their password has left. Wrapping this copy under the password-derived key instead would be
self-defeating in the exact situation it exists for, and it is a plausible enough mistake to be
worth foreclosing here.

Reads of another user go through a **projection exposing only the username and public keys —
current and superseded, since verifying an older signature needs the key that was current then** —
never the salt or the wrapped private keys, which leave the server only via the rate-limited
challenge endpoint. **The `RECOVERY` item is served by no read path at all.** It is
offline-cracking material exactly as the password-wrapped blob is — against a higher-entropy secret,
but with the same consequence if it leaks — and unlike the login blob it has no reason to leave the
server, since recovery is a write path: the client submits proof it can use the code rather than
asking for the blob to try codes against.

**There is no separate display name.** Users are identified everywhere by their username, which is
plaintext by necessity — login requires looking a user up by name. A display name sealed under a key
only its owner holds would be unreadable by the people meant to read it, and one readable by other
members would have to be either plaintext or group-scoped, neither of which buys anything a username
does not. Preferences in this blob are therefore strictly **self-directed**: they change what their
owner sees, never what anyone else sees.

**Membership items do double duty**, holding both the wrapped group key and the role, so the check
that gates every group operation is a single `GetItem`. The key it holds is **one** key: the member's
copy of the group's *current* generation, wrapped to their X25519 key, and the item records which
generation number that is. It is the member's **entry point** into the chain, not the chain itself.
Rotation replaces it; it never accumulates.

**Generation key items are the chain.** `GENKEY#<nnnnnn>` holds generation *n* wrapped under generation
*n+1*, written **once per rotation for the whole group** rather than once per member per rotation.
This is what makes storage `O(members + generations)`: the `members` term is the one current key in
each membership item, and the `generations` term is this set of group-wide links. Storing history in
the membership items instead — a wrapped key per member per generation — is the
`O(members × generations)` layout that this design rejects, and it walks into the 400KB item ceiling.
A member reads old content by unwrapping their current generation and then walking `GENKEY#<n−1>`,
`GENKEY#<n−2>`, and so on, stopping at the oldest surviving generation recorded on the group's `META`
item. The **walk is cryptographic, not a sequence of round trips**: every `GENKEY#` shares the
`GROUP#<gid>` partition, so a client fetches the range it needs in **one `Query`** with an SK prefix
of `GENKEY#` and then unwraps locally, generation by generation. Only the unwrapping is sequential —
each link decrypts the one below it — and its cost is CPU, not latency.

**The generation number is zero-padded to six digits — `GENKEY#000008`, not `GENKEY#8`.** Sort keys
compare as UTF-8 bytes, so an unpadded integer sorts `GENKEY#10` before `GENKEY#2`, and the two reads
above both depend on the ordering: the range fetch is a `BETWEEN` on the sort key, and lexically
`GENKEY#8` through `GENKEY#20` contains `GENKEY#9` but not `GENKEY#10` through `GENKEY#19`, so it
returns a chain with a hole and the client cannot decrypt anything below the top — a failure that
looks like corruption rather than a bad query. The chain-floor comparison below breaks the same way.
Six digits is a million generations, past anything the 1,000-member rotation cap and truncation can
produce. This is the third place the rule bites, after the comment path and the day format, so state
it once as a rule: **every numeric component of a sort key in this schema is zero-padded to a fixed
width.**

**Why each item expires or does not.** The assignment itself is the TTL column above; what follows
is the reasoning behind it, not a second copy of it.

**Expiring:** `POST#`, `CMT#`, `RXN#` and `NOTIF#` — content and the pointers to it — plus
`CHALLENGE`, which carries the shortest TTL in the system (a minute or two) and is normally deleted
by the conditional write that spends it, the TTL existing only to collect challenges nobody ever
answers — plus the invite pair, `INVITE#` and `SENT#`, whose TTL is **set from the `expires_at` the
inviter signed** so that the stored lifetime and the signed one cannot drift. An invite is the one
item here whose expiry is part of a signed payload, and the storage layer must honour it rather than
leave a year-old invite acceptable. Clients still verify `expires_at` against the signature when
accepting, because TTL deletion is eventual and an expired-but-not-yet-deleted invite must be
refused: for invites that check is a
**security control, not a display convenience**, and it runs only after the inviter's signature has
been verified, since an unverified `expires_at` is a value the server could have altered.

**Both copies of an invite take their TTL from the same signed value, and the inviter's copy is
deleted when step 3 completes.** `SENT#` is a pointer to `INVITE#`, so deriving both lifetimes from
the one signed `expires_at` keeps them in step by construction rather than by discipline. Deletion
at completion is what keeps the step-3 query honest: it returns **invites still awaiting
completion**, not a history of everything the user ever sent. Without it the query grows without
bound and the client re-wraps the group key for already-completed invites on every login —
idempotent, but permanently accumulating. The TTL is therefore only a backstop, covering invites
nobody ever accepts, and it means the inviter's partition never becomes a durable log of who they
approached. A `SENT#` row whose `INVITE#` is already gone is filtered on read, as a notification
whose target was deleted is.

**Acceptance clears the TTL on both rows, and skipping that loses invites silently.** Step 3 runs on
the inviter's *next login*, so the gap between acceptance and completion is however long the inviter
stays away. Leave the signed `expires_at` in place across that gap and an invite accepted on day 6
of a 7-day window expires on day 7 with both rows: the `SENT#` row the inviter's client would have
found is deleted, so nothing completes, and the invitee — who signed their keys, completed their
half, and was told it succeeded — never receives a group key and is never told why. The read-time
check does not catch this; that check correctly refuses an *expired* invite at step 2, and here
acceptance happened while the invite was valid. So at step 2, in the same write that adds the
`USER#<invitee>` GSI entry, **the TTL attribute is removed from both rows** (or replaced with a
completion deadline measured from acceptance). The signed `expires_at` keeps its real job of
bounding how long an *unaccepted* link stays usable, which is the property the signature protects
and is unaffected. What a dump yields is unchanged in kind — a completed step 3 deletes the `SENT#`
row regardless, so the residue is still work genuinely outstanding.

**Never expiring:** the rest. Each has a reason: `META` records the chain floor, `MEMBER#` is a
member's entry point into it, `GENKEY#` is the chain, `ROTATION` would abandon a rotation in
progress, `GRANT#` must stay verifiable back to the group creator, and `PIN#` is the signed record a
key change is checked against. `REQ#` is durable **unlike an invite** because a join request carries
no signed lifetime — it is resolved by an admin approving or denying it, and a request left pending
stays visible to its requester rather than silently vanishing. **Denial is a status on the row with
a cool-off TTL, not a delete and not a permanent slot.** The sort key is `REQ#<uuid>` on the
requester's uuid, so there is exactly one slot per user per group, and the three obvious readings
are all wrong: deleting the row makes the request vanish from the requester's list, which is what
this sentence rules out, and lets them immediately re-request with no record that an admin already
said no; keeping it forever with `attribute_not_exists(SK)` as the write condition turns one admin
decision into a permanent silent ban, a moderation power no role in the table grants; and keeping it
with no expiry at all leaves denied rows in the group partition where the admin's pending-request
`Query` must filter them, a filtered read whose cost grows with total denial history. A cool-off
TTL — days, not forever — gets all three: the requester sees "declined" rather than a vanishing row,
the admin queue keys on status, and the slot frees itself. **`REQ#` is the one item with a
conditional TTL**, which is why its row above reads `never (pending) / cool-off (denied)`. The
pending-request `Query` is a filtered read for as long as denied rows share the partition, bounded
by the cool-off window rather than by history. `RECOVERY` never expires for the
plainest reason of all: it is used precisely when a user has been away long enough to forget their
password, so any lifetime short enough to limit exposure is short enough to destroy the account it
exists to save.

**A default-TTL-on-write rule with exceptions is the wrong shape here** — most of this partition
does not expire.

**Join requests mirror invites in the opposite direction.** A request lives in the group partition,
so an admin loading a public group reads its pending requests with one `Query`, and GSI1 carries the
reverse lookup — a requester listing their own outstanding requests. That is the same pair of access
patterns the `Invite` item serves, keyed the other way round, because the approving party is the
group rather than the individual. Public groups and join requests are M7; the row is here because
this table describes the complete design, and an item missing from it is otherwise indistinguishable
from an oversight.

**The rotation marker is the one item with a liveness requirement.** `ROTATION` records the
in-progress generation, how far the batched writes have got, and when the job started. Nothing on
the server acts on it: **admin clients compare its timestamp against the staleness deadline when
they load the group**, and surface a stalled rotation for resumption. This is deliberate — no
server-side process can complete a rotation anyway, because the group key exists in plaintext only
inside a member's browser, so a scheduled Lambda could detect staleness but could do nothing about
it. Detection therefore lives where the remedy lives.

**Editing is in place; deletion is a tombstone.** An edit overwrites the ciphertext and bumps an
`edited_at` field, leaving no earlier plaintext anywhere — there is no revision history, which is
the point rather than a shortcut. A delete replaces the content with a tombstone rather than
removing the item, because comments hang off posts and replies hang off comments: removing the row
outright would orphan or reorder everything beneath it, and the materialized path a thread is
rendered from would break.

Three consequences the rest of this document constrains:

- **An edit re-signs, and it re-encrypts under the generation the item already records.** A post
  records the generation it was encrypted under, and an edit must keep that field and the ciphertext
  agreeing — re-encrypting under the *current* generation while the item still claims an older one
  produces content nobody can read, and the reverse strands a reader walking the chain. The
  signature is regenerated with the author's current key, which is also the only mechanism in the
  design by which a user re-signs their own content: it does not rescue history after a rotation,
  because it requires the author to still be able to read and re-encrypt the item.
- **A tombstone inherits `group policy`**, like the content it replaces, since it is an item state
  and not a new row. In a group with expiration disabled that makes it permanent, and a permanent
  tombstone is a durable record that a post existed, by whom, and on what day it was removed.
- **Deletion is advisory.** It removes the copy the server holds; it cannot remove what any member
  already decrypted and kept. This is the same limit removal has, and it is stated in the threat
  model beside it.

**`<pid>` is a post's full address, not just its random half:** `<gid>#<YYYY-MM-DD>#<rand>`, the
group and day and random id joined. Comments and reactions are the only rows keyed under something
other than `GROUP#<gid>`, and defining `<pid>` this way is what keeps them reachable — three
separate mechanisms need the group and the day, and neither is recoverable from the random id
alone:

- **The membership check.** The `GetItem` that gates every group operation is `GROUP#<gid>` /
  `MEMBER#<uuid>`, and a `POST /api/posts/:pid/comments` request carries only a pid and a session
  cookie. If the pid did not contain the gid, the server would have to take the group from the
  client — which is asking the caller to assert the thing being authorized. With it, the server
  parses the gid out of the address it was given and checks membership against that.
- **The comment's TTL.** A comment inherits its expiry from the parent post, which means addressing
  the post, which needs its full sort key.
- **Notification rendering.** A notification stores a `post_id`; resolving it must be one `GetItem`,
  and that needs the day as well as the group.

The cost is a longer partition key and a pid that is not opaque — it reveals the group and the day
to anyone holding a link, both of which that person can see anyway if they can read the post.

**Comments use a materialized path.** Because lexicographic ordering of `CMT#0003.0001.0002` *is*
depth-first traversal order, one query returns an entire thread already in display order. Depth is
capped at 8 — **past the cap a reply attaches at the cap level** rather than being refused, so a
conversation never dead-ends on a structural limit — and each segment is **four digits,
zero-padded** — the padding is what makes the
ordering property hold, since unpadded segments would sort sibling `10` before sibling `2` and
scramble the thread. That fixes the schema's bounds: at most 9,999 replies to any one comment, and a
comment sort key no longer than 39 characters — eight four-digit segments plus the seven separators
between them — or 43 with the `CMT#` prefix.

**Comments are the one place this design accepts a sequential id, and it is a deliberate exception
to the rule posts follow.** A sibling ordinal buys the property the whole materialized path exists
for: lexicographic order *is* depth-first display order, so one query returns a thread ready to
render. A random segment would destroy exactly that and leave the client reconstructing the tree,
which is why posts and comments land on opposite answers — a random id costs a post only intra-day
sorting, and would cost a comment the entire structure.

It is paid for twice, and both costs belong here rather than being discovered later:

- **It needs write-time coordination**, which the post ids specifically avoid. Writing the fourth
  reply means first learning that three exist, so two clients replying to the same parent can both
  read three siblings and both write `…0004`, with the second silently overwriting the first —
  a lost comment and no error anywhere. **The write is therefore conditional on
  `attribute_not_exists(SK)`, retrying with the next ordinal on failure.** It is the only conditional
  write whose *retry changes the value written* — the other two, below, are ordinary compare-and-set.
- **It discloses sequence in plaintext.** `CMT#0003.0001.0002` says third top-level comment, first
  reply beneath it, second beneath that. That is exact intra-thread order, in the clear — not
  wall-clock time, which stays encrypted like any other content, but enough to bound how a
  conversation interleaved when read alongside day prefixes. The trade is judged worth it for the
  structure it buys, and it is worth noting that the same trade is *not* worth it for posts, which
  would gain no traversal property in exchange.

A reaction's `<cmtpath>` is the path of the comment it attaches to, and is empty for a reaction on
the post itself, so reactions sort alongside the thread they belong to.

**A reaction is keyed by its reactor, not by a fresh id**, which is what makes it removable. Every
reaction UI toggles — click to react, click again to undo — and undoing needs an addressable
target. With a random id in the key a client would have to query the whole `RXN#<cmtpath>#` range
and decrypt each row to find its own, and the server could not authorize the delete at all without
being told whose it was. Keyed on the reactor, un-reacting is a `DeleteItem` on a key the client
constructs from what it already knows, and the server authorizes it by comparing the key against
the session. It also makes a repeat reaction idempotent: a double-fired click, a retried request or
a second open tab overwrites the same row rather than inflating a count that is tallied client-side
from a set nothing deduplicates.

The consequence is **one reaction per user per target** — react again with a different emoji and it
replaces the first, as it does on most platforms. If several emoji per user per target are ever
wanted, the key extends to `RXN#<cmtpath>#<reactor>#<emoji-hash>`, which keeps addressability while
allowing a set; that is a schema change and is not in v1. Note that the reactor's uuid is therefore
plaintext in the sort key, which is what the threat model already states — a dump shows who reacted
to what, and only the emoji is unreadable.

**A reaction's target is plaintext; the reaction itself is not.** The comment path sits in the sort
key so the server can order reactions with their thread, but which emoji was chosen is encrypted
under the group key like any other content. The server therefore knows that a user reacted to a
particular comment, and not what they said by it. The cost is that reaction counts are computed
client-side after decryption rather than aggregated by the server.

**Reactions carry no time at all**, which is a smaller disclosure than posts make and is deliberate.
Their sort key holds the target path and the reactor's id — no day prefix — and the item records
no creation timestamp, encrypted or otherwise. Nothing needs one: reactions are read as a set with
their thread and counted after decryption, never ordered or filtered by time. So a reaction is the
one item in this schema that discloses an association without a date, and adding a timestamp later
would be adding a disclosure, not filling a gap.

**Notification items hold identifiers, not text.** The server knows thread structure and author
ids — those are metadata — so it can tell that someone replied to your post without being able to
read either. But it cannot compose a human-readable notification: a private group's name is
encrypted under the group key, so the server cannot name the group a notification refers to.

A notification item therefore stores `{kind, actor_uuid, group_id, post_id, cmt_path, read}` and
**no content of any kind**. **The client renders the text**: "alice replied to your post in Roof
Group" is what the user sees, not what the table contains, and no notification is ever a
ready-to-display message.

`cmt_path` is what makes a reaction notification land where the reaction is: `kind` distinguishes a
reply from a reaction, but `post_id` alone resolves to the post, and a reaction to a comment must
link to that comment rather than to the top of a thread. `read` is the flag the unread badge and
the mark-read operation act on, and it carries two costs worth stating here rather than discovering
in M7:

- **Unread count is the one read in this design whose cost grows with retained history.** A flag is
  an attribute, not a key component, so counting unread items is a `Query` over the user's whole
  `NOTIF#` range with a filter, and DynamoDB bills every item the filter examines rather than the
  ones it returns. Nothing scans, so the data model's claim holds, but a user with a long retained
  history pays for all of it on every count. A counter attribute on `PROFILE` is the standard fix
  and would make a **fourth** contested write, alongside the three named above.
- **Marking read in bulk is a write per item.** DynamoDB has no bulk attribute update, so it is
  `BatchWriteItem` at 25 per call, issued from the browser — the same batched client-side shape as
  the rotation loop, and it should be built with the same expectation that it is interruptible.

Both halves of that rendering need a mechanism, and neither is free:

- **The group name.** In a **private** group the name and description are encrypted under the group
  key, so — like a post — the `META` item **records the generation they were encrypted under**, and a
  client that has walked the chain can read a name written before it joined. Rotation does *not*
  re-encrypt the name: that would add a write the rotation sizing does not account for, and it is
  unnecessary, since the name is reachable through the same backward walk as any older content. **A
  public group's name is plaintext** — it is the `GSI1SK` the directory does `begins_with` on — so
  there is no generation to record and nothing to walk; a client rendering the notification just
  reads the attribute.
- **The actor's username.** Usernames are read through `GET /api/users/:id`, a **projection over the
user item exposing only the username and the public keys, current and superseded**. The full
`PROFILE` item also holds
  the Argon2id salt and the wrapped private keys, which is offline-cracking material, and no ordinary
  read path may hand those out — that blob is available only from `POST /api/auth/challenge`, which
  is rate-limited precisely because it does. The key-pinning flow reads the same projection.

**Email notifications are the exception, and they are strictly poorer for it.** The server composes
those itself — it decrypts the address to send them — so it can use only what it can read. An email
says there is activity and links to it; it names neither the group nor the actor. Anything richer
would mean handing the group name to the server, which is the property this design exists to keep.
**A notification inherits the expiration policy of the group that generated it**, so it never
outlives the content it points at. Notifications live in the user's partition rather than a group's,
so a single user's list mixes policies from every group they belong to — and one from a group with
expiration disabled does not expire either. A notification whose target has already been deleted is
filtered on read like any other expired item, since the client renders from identifiers and an
unresolvable `post_id` would otherwise show as a reply linking to nothing.

**Sort keys carry a day and a random id — deliberately not a ULID.** A ULID would be the obvious
choice here and it is the wrong one: a ULID *is* a timestamp. Its leading 48 bits are the Unix time
in **milliseconds**, sitting in plaintext in the first 10 characters of the id, so a sort key built
on one carries millisecond timing regardless of what the day prefix says and regardless of what the
encrypted payload holds. The day prefix would coarsen nothing, because the precise time it was
meant to withhold would be sitting beside it. **The id is therefore 128 random bits**, and the day
is the only time component in the key.

**One id convention, used everywhere the table writes `<rand>` or `<uuid>`:** 128 bits from a
cryptographic RNG, rendered as **32 lowercase hex characters**. Fixed-width and byte-ordered, so
prefix comparisons and `begins_with` behave. The encoding is worth pinning because the obvious
alternatives are not interchangeable — base64url is unsafe here, since its alphabet contains `-`
and does not sort in byte order, and `uuidv4()` yields 122 random bits rather than 128, with version
and variant nibbles pinned in fixed positions. Neither is a security problem at these sizes; both
are avoidable surprises in sort keys. The two placeholders name the same construct and are not a
distinction.

**Do not substitute UUIDv7 anywhere in this table.** It is time-ordered by design — the same
timestamp-in-the-id trap as a ULID, wearing a more standard-looking name, and it would reintroduce
the millisecond leak in rows that were never part of the fix. The same goes for any other sortable
id format: if an id in this schema orders by time, that is a defect, not a feature.

That makes the claim honest: the exact timestamp exists **only** inside the encrypted payload, so a
dump yields the day a post was written and nothing finer. The cost is paid in ordering, and it is
worth stating plainly: posts are **ordered by day in the table and by decrypted timestamp within a
day**. The server can sort no finer than a day, so a day's page is fetched and ordered client-side
after decryption. That is cheap here — the client decrypts every post it renders anyway — but it
means intra-day ordering is a client responsibility, and a client that skips the sort will render a
day in arbitrary order. Random ids keep the property that made ULIDs attractive in the first place:
no coordinating counter, no serializing every write to a group through one item.

**The day is `YYYY-MM-DD` in UTC, and both halves of that matter.** UTC because a client stamping
its *local* day would leak the author's timezone — a disclosure the threat model does not account
for, and one that measurably shrinks the anonymity set it relies on, since "pseudonyms to
pseudonyms" is weaker when a pseudonym carries a UTC offset. Local stamping also makes two clients
in different zones write different prefixes for the same instant, so a group stops sorting
consistently across readers. Zero-padded `YYYY-MM-DD` because the ordering is lexicographic:
`2026-9-4` sorts after `2026-10-01`. That is the same padding bug the comment path already guards
against, and it applies here for the same reason.

DynamoDB pagination is cursor-based natively, so infinite scroll needs no offsets. **A day boundary
is a hard pagination seam, though, and that is a real cost of this design**: "the newest 20 posts"
spans days, so a client walks day partitions backward without knowing in advance how many it must
cross to fill a screen, and a quiet group can need several empty-day queries to render one page.
Anything needing sub-day server-side time filtering or server-side intra-day ordering would require
a schema migration, so this is a deliberate and hard-to-reverse choice, not an incidental one.

**`NOTIF#` uses the same random id, and for a sharper reason.** Notifications live in the *user's*
partition, so a time-ordered id there is a millisecond-resolution activity log for one named person
spanning every group they belong to — a worse disclosure per item than posts, which are at least
scoped to a group. It carries a day prefix for the same reason posts do.

**`INVITE#`, `SENT#` and `REQ#` use the same day-plus-random construct, and there is no `<ts>`
anywhere in this schema.** A field named `ts` invites `Date.now()`, an ISO-8601 instant, or a Unix
epoch, every one of which puts millisecond or second resolution back into a plaintext sort key —
the leak the random id exists to remove. Two of these three sit in the *user's* partition, which is
the sharper case named just above: `INVITE#` is a precise timeline of when a named person was
invited to things, and `SENT#` is the same for who they approached, which the threat model treats as
the more sensitive half because it is intent rather than association. The `<rand>` suffix closes a
collision too — two invites to the same invitee on the same day would otherwise project the same
GSI1 key and one would silently overwrite the other, the same failure as the directory collision
above. What this costs is sub-day ordering on the two listings a user reads, `INVITE#` and `REQ#`,
which is the trade posts already accept. `SENT#` is queried as pending work rather than in time
order, so it loses nothing.

**Role grants are keyed by group, not by subject, and are append-only.** Verifying a grant chain
therefore queries the group partition and filters client-side; it is a `Query`, never a `Scan`, but
the read returns role *history* rather than current roles, so it grows with total role churn in the
group rather than with membership or with the length of the chain being checked, and DynamoDB bills
the filtered-out items. Acceptable at the group sizes this design targets. A group with heavy
role churn would want a GSI keyed by subject, which is additive and needs no migration of existing
items.

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

Same origin for app and API, so there is no CORS configuration. The Lambda holds no state in
**memory** between requests and never possesses key material. The single piece of cross-request
state it writes is the login challenge item, which lives in DynamoDB with a short TTL and is spent
by a conditional delete.

Rate limiting is enforced by WAF rate-based rules. Note what it is and is not protecting: Argon2id
runs in the **client's** browser, so a login costs the server only a DynamoDB read and, on the second
leg, one Ed25519 verification. An attacker hammering the endpoint burns their own CPU, not the
operator's.

The first thing worth bounding is **bulk harvesting**, not compute. `POST /api/auth/challenge`
hands out a salt and wrapped private keys to anyone who names a username, which is offline-cracking
material; the rate limit exists to make collecting it at scale slow. Size those limits against
harvesting rate, not against a server cost that this design does not have.

**The second is writes on unauthenticated paths, which have the opposite cost model and need their
own limits.** Two endpoints let an anonymous caller cause a write against a named user's partition:
`POST /api/auth/challenge` creates the challenge item, and the verify leg increments the failure
counter on that user's `PROFILE` — failing is what triggers it, so no valid signature is required.
Both target items in a single partition, `PROFILE` being the hottest item that user has and the one
every login must read, so sustained hammering is the classic hot-partition case. Unlike harvesting,
**this cost falls on the operator**, in write capacity and in contention against legitimate logins,
and it is precisely the cost the paragraph above says the design does not have — that claim is true
of Argon2id and the challenge leg, and not of these writes. A limit sized only against harvesting
rate will not necessarily catch it, so bound the verify endpoint on its own terms.

Environments are Terraform workspaces (`dev`, `prod`) in one AWS account, with resource names derived
from the workspace so a mistyped variable cannot cross-wire them.

Whether `no expiration` is permitted deserves particular care: enabling it lets a group turn off the
mitigation that Limitation 3 of the threat model, the forward-secrecy argument above, and generation
chain truncation all depend on. There are real reasons to want a permanent group, so the setting
exists — but a deployment that enables it should expect those three properties to be absent from any
group that uses it.

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
