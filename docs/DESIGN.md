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

**This document describes the complete design, not the current state of the code.** The design is
settled, with no open questions remaining. The work is built in milestones: private groups, invites,
posts and comments come first, while public groups, join requests, notifications and custom themes
are deliberately sequenced later. Where something is not yet built, it is because of ordering, not
doubt. Progress is tracked in the repository's issues and milestones.

## The cryptographic core

Each user has two keypairs:

| Key | Algorithm | Purpose |
|---|---|---|
| Signing key | Ed25519 | Login challenge-response, signing posts and role grants |
| Wrapping key | X25519 | Wrapping and unwrapping group keys (ECIES with HKDF) |

Both private keys are encrypted with AES-256-GCM under a key derived from the user's password via
**Argon2id**, and the resulting blob is stored on the server. The password itself is never
transmitted, and neither is anything derived from it. The plaintext inside that blob is a versioned,
length-prefixed encoding of the two private scalars only — see `internal/crypto/keybundle.go`
(mirrored in `web/src/lib/crypto/keybundle.ts`) and the `key_bundle` test vector; the public keys are
excluded since they already travel and are stored in plaintext elsewhere.

Groups have a symmetric **group key** (AES-256-GCM) that encrypts every post, comment, and reaction,
and — for private groups — the group's name and description. Each member holds a copy of the group
key wrapped to their X25519 public key.

**Every GCM encryption uses a fresh random 96-bit IV from a CSPRNG, stored alongside the ciphertext.
Never a counter, and never derived from the item's identity.** This is not a stylistic preference:
GCM does not degrade gracefully under IV reuse, it fails completely and in both directions. Two
messages encrypted under one key and IV give up the XOR of their plaintexts, and — worse — the GHASH
subkey `H` becomes recoverable, which hands out **forgery**: arbitrary ciphertext bearing a valid tag
under a key the attacker still does not hold. That is precisely the capability the signature layer
exists to deny, so a reused IV silently undoes it.

Three things in this design walk into that, and the appealing implementation is wrong in all three:

- **Edit-in-place re-encrypts the same item under the same key.** Deriving the IV from the item's
  address — deterministic, testable, and the natural partner to the AAD binding below — means an
  edit reuses the IV with different plaintext. That is a **one-item, one-edit** break, not a
  statistical one, and it happens the first time anyone edits a post.
- **The group key is shared by every member**, so no counter scheme can work: two browsers issue
  counter 1 for two different posts under one key, and this architecture has no coordination that
  could prevent it. Random IVs are effectively the only safe choice, with the birthday bound
  (~2³² messages per key) noted so nobody later "optimizes" this into a counter.
- **Every key wrap is a GCM encryption too** — group keys to X25519, private keys under the
  Argon2id key, the recovery copy, and the `GENKEY#` chain links. The chain links are the worst
  case, being written once and read forever by everyone in the group.

The rotation and truncation flows re-encrypt existing plaintext under existing keys — the group
name at truncation, an edited post under the generation it already records — which is the classic
setup for accidental reuse. Each of those writes takes a new IV.

**Every ciphertext is additionally bound to its address with AES-GCM's associated data (AAD).**
Without it, GCM authenticates only that *someone holding the key* produced the ciphertext — and
every member of a group holds that key, as does anyone who ever did. An attacker with write access
to the table could then **relocate valid ciphertext between records with every tag still
verifying**: move a comment under a different parent post and the reply is re-parented; copy a post
into a different day's sort key and it is redated; swap two `GENKEY#` links and the chain silently
yields the wrong generation key. The AAD is the item's full address, and it is what makes a
relocated ciphertext fail loudly:

| Item | AAD binds |
|---|---|
| Post | `PK` + `SK` (group, day, rand) + generation number |
| Comment | `POST#<pid>` + `CMT#<path>` + generation number — `CommentAAD` in `internal/crypto/group.go` |
| Reaction | `POST#<pid>` + `RXN#<cmtpath>#<reactor>` + generation |
| Generation key | group id + generation number |
| Wrapped private keys | user uuid + which copy (`PROFILE` or `RECOVERY`) — `CredentialWrapAAD` in `internal/crypto/credential.go`. The user uuid is client-generated at registration (not server-assigned) specifically so it exists before the client wraps under it; `POST /api/auth/register` validates the client-supplied id's shape and the schema's `attribute_not_exists(PK)` condition on the `PROFILE` write guards against a collision. That guard only holds while `PROFILE` exists for every uuid ever used, though — user uuids are never reused, so account deletion (`DELETE /api/account`, below) tombstones `PROFILE` rather than deleting it, or a re-registration on a stale uuid could inherit another user's still-live memberships, invites, and other items keyed on it. |
| Group name/description | group id + which field (name vs. description) + generation number — `GroupNameAAD` in `internal/crypto/group.go`. The field distinguishes the two ciphertexts sharing the same group id and generation, since without it an attacker with write access could swap a group's name and description with both tags still verifying. |
| Rotation handoff wrap | user uuid + group id + generation number + the new X25519 public key it is wrapped to — `HandoffWrapAAD`. Like `MemberWrapAAD` it is row-specific: the plaintext is a group key, so without the group id an operator could swap two of the user's `HANDOFF#` rows and the self re-key would write group A's key into group B's `GENKEY#` chain, readable by every member of B. The new public key keeps a row written for one rotation from opening under another. |
| Member's wrapped group key | group id + member uuid + generation number — `MemberWrapAAD` in `internal/crypto/group.go`. Unlike the generation key row above, this wrap is **member-specific** (each member holds their own ECIES-wrapped copy on their own `MEMBER#` item, per docs/DESIGN.md's key-generations discussion), so the member uuid has to be part of the binding: without it, an attacker with write access could swap two members' wrapped entries at the same generation and both tags would still verify, silently handing each member the other's copy — harmless only when the two copies happen to unwrap to the same plaintext, which is true within one generation but not the property this table is trying to guarantee. |

**Posts and comments are signed over their address as well as their content**, for the same reason
and as the second half of the same binding. The signed payload is the **author uuid, group id, the
item's own sort key, the generation number, the UTC signing day, and a hash of the ciphertext** —
so a signature that is genuinely the author's cannot be replayed into a different location either.
The signing day is redundant for a post, whose sort key already carries it, and **load-bearing for a
comment, whose sort key does not**: it is what tells a verifier which key interval to check a
comment's signature against, and covering it by the signature keeps the server from choosing. A signature covering
only the plaintext body would survive relocation: real author, real content, rewritten context.

### Posts

`POST /api/groups/{gid}/posts` (#42) stores one item, `GROUP#<gid>` / `POST#<YYYY-MM-DD, UTC>#<16 hex>`,
with the author's id, the generation, the IV, the ciphertext and the signature. The client chooses the
sort key, because the signature covers it; the day in it is the only time the server holds.

**The plaintext is binary, not JSON.** `0x01`, then the title, the body and the exact write time (RFC 3339 UTC
with milliseconds, 24 bytes), each with a 4-byte big-endian length. The overhead is 37 bytes plus the 16-byte
GCM tag. JSON would escape a byte into as many as six, and the server can only see ciphertext, so its size
limit would have to be that much looser to be safe; with this layout the limit is the two field caps plus a
64-byte allowance (`handlers.postEnvelopeOverhead`), and the cap means what it says. The layout is pinned
by `web/src/lib/crypto/post.test.ts` and must not change once real posts exist.

**Size caps are bytes, and configurable.** `MAX_POST_TITLE_BYTES` (default 200) and `MAX_POST_BODY_BYTES`
(default 10,000) are served in `GET /api/config`; the compose form enforces each exactly, the server
enforces their sum as a ciphertext limit. 10,000 bytes is about 7.5 KB of binary whatever the alphabet. A cap
bounds what a post can hold; it cannot inspect it, since the server never sees plaintext. The other half of
the protection is structural: posts are plain text, the client never renders a body as markup or loads
anything from it, and there are no attachments.

**What the server checks.** The caller is a current member, not dormant, whose entry is at or above the post's
generation (a member ahead of it opens the older key through the chain); the generation is the one new posts
use, which is the group's settled generation, one below a running rotation's; the sort key is well formed and
its day is within the usual clock tolerance of today; the nonce is 12 bytes and the ciphertext is within the
limit; and the signature verifies under the author's **current** signing key over
`crypto.SignedPayload(author, group, sort key, generation, day, ciphertext)`. The membership, the entry's
generation and `WrapEpoch`, the account's `KeyEpoch` **and the group's rotation marker** are re-checked in the
write's own transaction: without the marker, a post sealed for the generation a running rotation is leaving could
commit after that rotation completed, on the key the removed member holds. A marker that appears, vanishes or
moves in the window fails the write (409 `generation_stale`) and the client reseals. The TTL
is the group's `ExpirationDays` from now, rounded up to the end of its UTC day (none for a group that never
expires). The same bytes sent twice are one post (a lost response is resent as is), and a resend is answered
by what was written **before** the generation and day checks: the first send may have committed, and a rotation
may have completed or the day passed since, so refusing the resend would make the client seal a second post. The
same address with anything different is 409 `post_exists`, and a different post at an aged address is still
refused.

**What it cannot check.** That the ciphertext opens, or that it holds what the form said: a patched client can
store garbage under a valid signature, which readers must treat as an unreadable post, not as a failure of the
group. `AAD` is `GROUP#<gid>:<sort key>:GEN#<nnnnnn>` (`crypto.PostAAD`, vectors `post_aad`).

**For the reader (#43).** Two things the signature does not give it. (1) The author signs whatever `at` they
like: a reader must check that the decrypted `at` falls on the sort key's day and show a post that does not as
suspect, not trust the time. (2) `SignedPayload` covers the ciphertext hash but not the nonce, so someone with
write access to the table can swap a post's nonce and make a validly signed post fail to open. Changing
`SignedPayload` is not worth it for this, but the reader must show a post that does not open as **unreadable**,
in wording that does not blame its author.

**Listing (#43).** `GET /api/groups/{gid}/posts?limit=&cursor=` serves the stored rows (author, generation, nonce,
ciphertext, signature) newest sort key first, to any member, and verifies nothing. The cursor is a post sort key and
can only move inside the group's own partition; `limit` is 1 to 50 (default 20). A post past its TTL is skipped even
though DynamoDB has not deleted it yet, and one request makes at most `db.ListPostsMaxPasses` (10) queries doing so,
so over a long run of such posts a page may be short or even empty while still carrying `nextCursor`: the cursor is
the last key read, and an empty page with a cursor means "keep going", not "no posts". The sort key orders by day,
then by a random suffix, so **within a day the server's order means nothing**: each page is re-sorted within each day
by the decrypted time, newest first, with unreadable posts last. A day that runs over a page boundary is ordered
within each page only; the screen does not re-sort across pages. The reader (`routes/runListPosts.ts`) does the
following for every post:

- **Opens it under the key of its own generation** (the caller's entry, walked down the `GENKEY#` chain), in the
  crypto worker (`openPosts`). A post that does not open is shown as unreadable ("could not be opened") with no word
  about its author, because the nonce is not signed. A chain that could not be read is a page error, not a row of
  unreadable posts.
- **Verifies the signature** under the author's signing keys for the sort key's day (`lib/crypto/post-check.ts`:
  the current key from the day it was introduced, each superseded key up to the rotation that ended it, both on a
  rotation day). The author's served keys are anchored first, by the same trust-on-first-use rule as the roster's
  grant check: your own key from the worker; anyone else's against your signed pin. A match is `pinned`; no pin yet is
  saved and shown once as `first-seen`; a pin that mismatches, rolled back or does not verify is never re-pinned over
  and the post says it **could not be checked**, with the reason. A failed read is likewise `could not check`, never
  `signature failed`.
- **Checks that the decrypted `at` is on the sort key's UTC day.** A post whose time is not is flagged as suspect and
  its time is not shown (the filed day is).
- **Renders as text.** Title and body are React text nodes, with the author's line breaks kept by CSS. Nothing in a
  post is a link, an image or markup, and `GroupPostsPanel.test.tsx` pins that with a hostile body.

**Comments (#44).** `POST /api/posts/{pid}/comments` stores `POST#<pid>` / `CMT#<path>`; the `#` in a post id travels as
`%23`. The server takes the group from the post id and checks the caller's membership against it, so a request cannot
name a group it is not in. Its checks are the post's: a current, non-dormant member at the settled generation, a signing
day within the usual tolerance, a nonce of 12 bytes, a ciphertext within `MAX_COMMENT_BYTES` plus the envelope
(`handlers.commentEnvelopeOverhead`), and a signature that verifies under the author's **current** key over
`crypto.SignedPayload(author, group, "CMT#<path>", generation, signed day, ciphertext)` with `ContextComment`. The post's
address is bound by the ciphertext's AAD, `crypto.CommentAAD`, not by the signature. The plaintext is binary, like a
post's: `0x01`, then the text and the exact write time (RFC 3339 UTC, 24 bytes), each with a 4-byte big-endian length (33
bytes of envelope plus the 16-byte tag). The row stores the **signed day**, because a comment's sort key has none and a
verifier needs it to pick the key interval. In one transaction the post must still exist and be unexpired, the parent
comment must exist (for a reply), and the member, key epoch and rotation marker are re-checked as for a post. The TTL is
copied from the post, so the row says when the post expires and nothing about when the comment was made.

**The client chooses the path, not the server.** The signature and the AAD both cover the path, so the server cannot
renumber a comment after the client has sealed it. Two people replying to the same comment can pick the same next number;
the write is conditional on the path being free, and the loser gets 409 `comment_path_taken` with `nextPath`, the first
free number under that parent, and seals again. `nextPath` is one past the highest direct child, read with one
descending query of one item (the highest key under a parent is its last child or a descendant of it, and its next
segments name that child). **A path may be at most one past that number**, checked before the write (409
`comment_path_skips`, with `nextPath`). Without the rule one request could write `9999` first, leaving nobody room to
reply under that parent for as long as the post lives, and a member could choose where their comment sorts; with it,
sibling order is write order and filling a parent takes 9,999 writes. The check cannot go stale: the highest sibling only
grows, so a path no more than one past it when checked is still no more than one past it when written, and two writers
at the same number meet the write's own condition (409 `comment_path_taken`). A parent whose 9,999 numbers are used is
409 `replies_full`. The depth cap is 8 and enforced by the path's shape; a reply to a comment at the cap is sent by
the client as a sibling of it ("attaches at the cap level"). A resend of the same bytes is answered by what was
written, before the freshness checks.

**A thread is read in pages, two small queries each.** `GET /api/posts/{pid}/thread?cursor=&limit=` (default 50, at most
100) serves a page of comments in display order, the cursor being the last comment's path, and **the reactions that
belong to exactly those comments**. A reaction's key is `RXN#<cmtpath>#<reactor>` and the cmtpath order is the thread's
order, so a page's comments are a contiguous slice of the reaction block: one range query from the first comment's path
to `RXN#<last>$` reads it (`$` sorts after the `#` that follows a path and before the `.` that begins a reply's path, so
the last comment's reactions are in and its replies' are out). The first page also carries the post's own reactions
(target `0000`). This replaces the single query the issue described: a long thread never loads in one response, and
there is no cap on comments per post. A page can be shorter than `limit` and still carry a cursor, because one DynamoDB
query returns at most 1 MB; a cursor means "keep going", never "this page was full". **A page is also bounded by response
size.** The reaction read itself is not capped (a page's reactions are at most the page size times the group's members,
one per user per target), and sizing the default page against the member cap would not help, since an Open or public
group has no cap. Instead the handler weighs the page (a base64-and-key estimate of each comment and reaction, checked
by a test never to undercount the real JSON) against `defaultThreadBudget`, 4 MB under a Lambda's 6 MB response limit,
and cuts the comments from the first one that no longer fits. The cursor moves back to the last comment kept, and the
reactions of the comments cut are not sent: the next page reads them with their comments, so none is lost or sent
twice. The first comment is always kept, so every page makes progress, and the post's own reactions always go out with
the first page, so one target's reactions are never split. The limit this leaves is a single target with so many
reactors (about 20,000 at roughly 200 bytes each) that its reactions alone pass the budget (the response itself fails
at about 30,000); that would take an Open group of that many members all reacting to one comment. The read still fetches the whole range before cutting, which
costs reads, not response size. Truncating the reaction read to stay under a limit is the wrong fix, because it would
drop reactions silently, the way an unflagged short page would drop comments. Members only, 404 otherwise (a
dormant member can read what their keys open).

**For the comment reader (#44).** `/groups/:gid/posts/:pid` (the `#`s of the post id as `%23`) reads a thread with the
rules of the post list, in `web/src/routes/runLoadThread.ts`. A comment opens under `commentAAD` (post, path,
generation) or is shown as one that could not be opened, which blames no one: the nonce is not signed. Its signature is
checked under the author's keys for the **signed day stored on the row** (a comment's sort key has no day), after
anchoring those keys the way the post list does (your own key, your signed pin, or first sight saved); a failed read of
the keys is "could not check", never "invalid". A decrypted time that is not on the signed day is flagged and not shown.
A path that is not well formed is shown unreadable and unnested. Pages keep the server's order and are appended; a
comment already shown is dropped, and a cursor, even on an empty page, keeps "Load more comments" on screen. Text is a
plain text node. The post's title comes from the list's navigation state for display only, so a thread opened in a new
tab has none; nothing is trusted from it.

**Writing a reaction (#46).** `PUT /api/posts/{pid}/reactions/{target}` (target `0000` for the post, else a comment path)
takes `{generation, nonce, ciphertext}` and sets the caller's reaction there, replacing any earlier one, so a resend or a
second click is harmless and answers 204. The reactor is the session's user, never a field, and there is no signature
(see "Reactions are not signed" below: nothing but the server ties a reaction to its reactor). The plaintext is **one
byte**, an index into a fixed emoji table kept by the client, so every reaction seals to exactly
`crypto.ReactionCiphertextSize` (17) bytes and the server refuses any other length: the ciphertext's size cannot say
which emoji it is (UTF-8 emoji vary from 3 to 8+ bytes), and a client cannot park other data in these rows. The same
freshness rules as a comment apply (non-dormant member, the generation new items use, the rotation marker pinned in the
transaction), and the comment must still exist (409 `parent_gone`). `DELETE` on the same path removes the caller's own
reaction, answers 204 whether or not one existed, and needs membership and a live post but no key, so a dormant member
can still take one back. Two requests that write the same item at the same moment can make DynamoDB cancel one of them
with a transaction conflict, which answers 409 `conflict_retry`; a client retries on it, so a double click is harmless
once retried (this comes from the AWS documentation; DynamoDB Local does not model the conflict, so it is untested).
The AAD is `crypto.ReactionAAD` (`POST#<pid>:RXN#<target>#<reactor>:GEN#<nnnnnn>`).

**For the reply box (#44).** `web/src/routes/runCreateComment.ts`. The client picks the path: one past the highest
direct child it has loaded under the parent, which can be wrong when the thread is paged or someone replied meanwhile.
On 409 `comment_path_taken` or `comment_path_skips` it seals again at `nextPath`, at most four seals per send, and
accepts a `nextPath` only if it is well formed, under the same parent and not already tried (otherwise the send is
refused rather than looped or misplaced). A reply to a comment at depth 8 is written as its sibling, and the box says
so. A resend after a lost answer sends the **same sealed bytes**, never a new seal, so the server's "identical bytes
are one comment" rule makes it safe; a changed draft or a different target drops the kept seal. `replies_full` and
`parent_gone` have their own messages (a gone parent reloads the thread). There is one draft: moving the box to
another comment keeps it, and it survives the password step. The counter counts UTF-8 bytes, the unit of
`MAX_COMMENT_BYTES` (served by `GET /api/config`). After a send the thread restarts from its first page, since the new
comment may sit on any page.

### Login

1. Client sends a username to `POST /api/auth/challenge`.
2. Server generates a random nonce, **stores it** as the `USER#<uuid>` / `CHALLENGE` item with
   a short TTL, and returns it along with the user's uuid, salt, and wrapped private keys. The uuid
   is included because the client needs it to build `CredentialWrapAAD` before it can unwrap the
   keys (see the AAD table above) — for a fresh device with no prior session, this is the only
   response that hands it one. An unknown username gets a freshly random decoy uuid alongside the
   rest of the placeholder response, so the response has the same shape either way (not a claim
   that the account's existence stays hidden; see THREAT_MODEL.md, Usernames).
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
nonce and two racing requests still resolve to one winner.

**The trade this makes is a cardinality problem for a login-availability one, and that is the
honest way to state it.** The benign cost is small: a user with two tabs mid-login has the first
tab's challenge replaced, which fails closed — that tab retries, and nothing is racing to overwrite
it again. The adversarial cost is not small, and it did not exist before this change. **The slot is
one per user and any unauthenticated caller who knows the username can overwrite it**, so an
attacker requesting challenges for a named account in a loop invalidates that user's outstanding
nonce continuously: every time she finishes an Argon2id derivation — deliberately slow, and slowest
on exactly the phone the TTL is sized for — and returns her signature, the conditional delete finds
a different nonce and fails. **She cannot complete a login for as long as the flood continues, and
retrying is what loses**, because each retry re-derives Argon2id and races again. The slower the
client, the more reliably it loses.

Two things make that worth stating rather than filing under "rate limits handle it". It **never
touches the lockout**: no signature failure is recorded, so the counter stays at zero and the
account is never locked — an operator checking the control the threat model names for account
denial-of-service finds nothing wrong. And with the nonce in the sort key this attack was
impossible: the flood cost unbounded storage but could not invalidate anyone's outstanding
challenge. **Nothing in this design actually bounds it** — the lockout is not that control, and the
WAF rate rules that would be are keyed on source IP while the attack is keyed on username. See the
rate-limiting discussion under Infrastructure, which works the arithmetic.

**The mechanism can be closed rather than documented, and is deliberately not in v1.** Accepting the
write only when the existing challenge is absent or already past its TTL — one conditional write —
keeps the single-item cardinality bound and makes the flood fail against the attacker instead of
against the user. It is deferred because it is not free: the slot then belongs to whoever asked
first for the length of the TTL, so the two-tab case reverses (the second tab is the one that
waits), and a user whose own abandoned challenge is still live is briefly blocked by it. Both are
tolerable, and neither is a reason to leave the attack undocumented in the meantime.

**The session cookie authenticates; it decrypts nothing.** It is a short-lived signed token —
there is no session store, so the server holds nothing to look up — carried in an `HttpOnly`,
`Secure`, `SameSite=Lax` cookie. It names the user to the API and nothing more. The private keys
stay in the browser's memory for the life of the tab and are never sent anywhere, so a stolen cookie
yields ciphertext, group membership and metadata, but no plaintext and no key. Nor can it write
convincingly: every post carries an Ed25519 signature the cookie cannot produce, so forged content
from a stolen session fails verification in every reader's client. Session theft here is a genuinely
smaller event than in an ordinary application.

**Logout, a password change and a recovery reset revoke sessions (#224).** The token carries the user's session
generation, a counter on the PROFILE item, and every authenticated request (and
`GET /api/auth/session`) compares it with the stored value in one strongly consistent read. Logout
bumps the counter, so a cookie copied before it stops working immediately rather than at expiry, and
every other session of that user ends with it ("log out everywhere"; there is no per-device
logout). The bump is conditional on the generation the logging-out token carries, so replaying an
already-revoked token cannot sign out a newer login. The server still keeps no record of individual
tokens and no session table: one integer on an item that already exists. If that read fails, the
request is a 500, never a 401, so a store outage does not look like a logout to the web client.
Tokens issued before this change have no generation and do not verify, so the deploy logs everyone out once.

A password change and a recovery reset bump the same counter, inside the transaction that re-wraps the
credentials (`db.RewrapCredentials`), so there is no moment when the new password is live and an old
session still is. That is the point for the user those flows are designed for, someone who believes
they are compromised and expects changing their password to log the attacker out. The change handler
reads the new generation back and reissues the caller a token, so the person who changed it stays
signed in. The session is one cookie in the browser's jar, so the reissued cookie replaces it for every
tab of that browser, and those tabs stay signed in; every other browser and device, and anyone holding
a copy of the old cookie, is signed out. If that read fails the change has
already committed, so the answer is still 200 and the cookie is cleared (a 500 there would tell the
client its password did not change); the user logs in again with the new password. A recovery reset
issues no session at all, since the user logs in with the new password afterwards. A change that
conflicts (a stale credential version) commits nothing and revokes nothing. What still does **not**
revoke a session is the five-minute lockout, which leaves a live session valid until it expires;
keeping sessions short remains the control for that.

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

**The lock is enforced at step 4 only, and step 2 does not consult it.** That needs saying, because
the counter's definition does not imply an enforcement point and the two candidates behave
differently. Checking at step 4 means a locked account can still be issued challenges: `/auth/challenge`
goes on serving the salt and wrapped keys to anyone naming that username for the whole five minutes.
That is deliberate and costs nothing the design was relying on — **the lockout and offline harvesting
are orthogonal controls.** The threat model already says so: challenge material is available on
request, that is unavoidable because a client needs it to attempt a login, and what makes offline
guessing expensive is Argon2id rather than any lock. Gating step 2 on the lock would not close
harvesting either, since an attacker who wants blobs collects them before provoking a lock, or from
usernames they never attack.

**Checking at step 2 would also make the two unauthenticated legs coordinate through the hottest
item in the partition**, which is the interaction the single-slot challenge decision was reasoning
about: the challenge leg would *read* lock state that the verify leg *writes*, both unauthenticated,
both on `PROFILE`, adding contention on exactly the item every login must already read. And it would
hand an attacker a third denial path — five bad signatures would suppress challenge issuance as well
as verification — which the threat model's account of how many independent ways there are to deny
one named account would then have to grow to include. Enforcing at step 4 keeps that accounting at
two.

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
wrapped under it, stored as its own `USER#<uuid>` / `RECOVERY` item and served only by a code-gated
release endpoint. The release response includes the uuid alongside the salt and wrapped keys, for
the same reason login's challenge response does — the client needs it to build `CredentialWrapAAD`
before unwrapping. Unlike challenge, there is no decoy branch to match: every failure mode here
already collapses to one uniform error rather than a fabricated success body, so the uuid is only
ever returned once the code has actually verified. A
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
operation, and the only one that invalidates existing wrapped group keys. Rotation does not rescue a
user who has lost both the password and the recovery code: it needs the current keys unwrapped to
authorise it, so that account stays permanently lost.

**The `RECOVERY` item carries its own guessing-bound lockout**, a counter and lock-until timestamp
distinct from login's — the same rolling-window mechanism as login's (the lock-until value itself
acting as the window marker) but scoped to failed recovery-verifier checks rather than failed step-4
signatures, and never touching login's counter or vice versa. Reusing login's counter would corrupt
its meaning — a wrong recovery code is not the signature failure it counts — and would let a
recovery-guessing attacker lock a user out of logging in entirely, the wrong failure mode to hand an
attacker. A locked `RECOVERY` item fails with the same uniform error as a wrong code, for the same
enumeration-resistance reason every other failure mode here already collapses to one response.

**The numbers are deliberately not login's five-in-five-minutes.** Login's lock earns its cost
because a password is comparatively low-entropy and the lock is what makes guessing expensive
against it. The recovery code is 128 bits of CSPRNG output — a tight lock buys it essentially no
brute-force resistance it doesn't already have, while creating a real griefing vector: anyone who
knows a username can keep their `RECOVERY` item locked indefinitely at a handful of requests every
few minutes, and the uniform response means the victim only ever sees "invalid code," with no way
to tell their code is fine and the account is merely locked. Recovery's threshold is 20 attempts per
hour rather than 5 per 5 minutes — the counter still delivers the observability and doc-accuracy
this section exists for, while making that griefing path take meaningfully more sustained effort, at
no real security cost given the code's actual entropy.

### Key rotation

Three operations get conflated under "changing my keys," and only the third one actually changes
them. A password change (above) and a recovery-code reset both re-wrap **the same private keys**
under a new wrapper. **Key rotation replaces the keypairs themselves**, and it exists for one
reason: **the user believes their private keys, or the means to reach them, are in someone else's
hands** (a stolen laptop, malware, a leaked password together with a copied key blob). It takes a
security incident, so it should happen a handful of times in a deployment's life.

**It is not a way out of losing both credentials, and an earlier draft of this section said it
was.** A user who has lost the password *and* the recovery code has nothing that proves they are the
owner of the uuid, and rotation changes the keys of an existing uuid, so an endpoint that accepted
that user would accept anyone: any visitor could replace the keys of any username. The
[Recovery](#recovery) section's answer stands: that account is permanently lost, and the person
registers a new one and is invited back. What rotation requires instead is **live proof**: the
request is signed by the user's *current* Ed25519 key, so the client must already hold the private
keys unwrapped. That is true after a password login, after a recovery-code reset, and in a tab that
is still signed in with a warm worker; it is not true after a page reload with no password (the keys
live only in the worker), which is the "forgot the password, tab still open" case, and the answer
there is the recovery code, not a new keypair.

Live proof also removes a case this section used to describe: rotating because the old private
keys *cannot* be unwrapped. Every rotation is by someone who can unwrap them, so there is a single
mode, and it assumes exposure (below).

#### What a rotation writes

`POST /api/account/rotate-keys` needs a session **and** two signatures over one payload
(`underground-bb:key-rotation:v1`: uuid, the current signing and wrapping public keys, the new
ones, the UTC day, the current `KeyEpoch`, and a digest of the caller's pin and verification rows,
see "What a key change looks like to others"): one by the **old** Ed25519 key, one by the **new**
one. The first proves the caller holds the keys being replaced. The second proves the caller holds
the new private key, so nobody can register a public key they cannot use (or one lifted from
another user). The server checks both, that the day is within the usual skew of its own clock, and
that `KeyEpoch` is the value it holds, which is also what makes the request single-use. Then, in
**one `TransactWriteItems`** of five items (`PROFILE`, `RECOVERY`, `KEYCHANGE#`, the cooldown, and a
condition check on `HANDOFFSEQ`, below), so the
number of groups the user is in never meets the 100-item limit. `PROFILE` is conditioned on
`KeyEpoch`, `CredentialVersion` and the old keys being what the request was signed against and on
the account not being deleted, and the `KEYCHANGE#` put on the row not existing. The roster behind the
digest is capped at 8192 entries (16 bytes each, which keeps the item well inside DynamoDB's 400 KiB):

- `PROFILE`: the new public keys, the private keys re-wrapped under a **new password** the user
  sets in the same flow, a fresh salt, the **old Ed25519 key appended to `SupersededSigningKeys`**
  with its interval (it ends on the signed day: both bounds are day-start instants, so nothing
  stores when in the day the rotation happened, and the day of the rotation itself has both keys as
  candidates; the first retired key starts at the Unix epoch, since a user's creation time is not
  stored, and each later one starts where the one before it ended), `KeyEpoch + 1`, `SessionGeneration + 1` (every other session,
  and any copied cookie, is signed out, exactly as a password change does), and the preferences
  blob **re-sealed under the new X25519 key**. The sealing key is derived from the X25519 private
  key, so the old blob would otherwise become unreadable; the client holds the old key and can do
  this. A rotation that did not would look like a theme that reset itself.
- `RECOVERY`: the new keys wrapped under a **new recovery code**, which the flow makes the user
  store before it completes. The old code unwraps the old keys, which are now worth nothing, but
  leaving it live would leave a second credential nobody is tracking.
- `KEYCHANGE#<epoch>` under the user's partition (the epoch zero-padded to six digits, so the chain
  sorts, as `GENKEY#` does): the payload, the roster list behind its digest, and both signatures,
  written once and never edited. The rows form a chain, each new signing key
  introduced by the one before it. `GET /api/users/:id` serves each row's payload (with the digest)
  and signatures **but strips the list**, since its length would tell anyone how many people this
  user has pinned or verified; `GET /api/pins` serves the list to its owner (on its first page). The
  chain is on the single-user read only, always present and empty for a user who never rotated; the
  batch read, which a roster uses a hundred users at a time, does not carry it. Account deletion
  removes the handoff and cooldown rows and leaves the `KEYCHANGE#` chain with the tombstone, which
  keeps the public keys for the same reason. See "What a key change
  looks like to others."

`KeyEpoch` is a counter on `PROFILE`, 0 for every account that has never rotated (an absent
attribute reads as 0), and it is plaintext and served. It orders states: a client that has seen
epoch 2 can recognise a server that now serves epoch 1.

Two limits keep a rotation from being a tool against other people. **Rotations are rate-limited to
one per 24 hours per account** (a deployment setting, `KEY_ROTATION_COOLDOWN_HOURS`; the limit is a
`ROTCOOLDOWN` item in the user's partition whose TTL is rounded up to the end of its UTC day like
every stored TTL, so it runs up to a day longer than the setting and no permanent timestamp of when
someone rotated sits next to their keys), because each one obliges an admin in every
group the user belongs to to act, and a user, or someone holding their session and keys, could
otherwise keep every one of those groups busy indefinitely. And a rotation does not touch any group
or any other user's rows; everything else follows from state, below.

#### Dormant memberships, and why a re-wrap is not enough

Every group key the user holds was wrapped to the old X25519 key. The user can unwrap them (that is
what live proof means), but **they do not**, and the reason is the point of the mode: if the keys
are exposed, whoever holds the old private key holds the same wrapped copies and can unwrap the same
generation. Wrapping the current key to the new public key would hand the user a copy and leave the
attacker with theirs. So a rotation does not re-wrap anything. The membership rows survive, the
user stays in the member list and keeps their attributed history, and they cannot read new content
until an admin or ambassador acts in each group. That concentrates the work into one deliberate
action per group by someone who already has the authority, rather than spreading warnings across
every co-member. It is the same key-change event the pinning section describes, resolved by approval.

**Dormancy is derived, not stored.** Each `MEMBER#` row records `WrapEpoch`, the recipient's
`KeyEpoch` when that wrap was made (an absent attribute reads as 0). A membership is dormant
exactly when `WrapEpoch` is behind the user's served `KeyEpoch`. Nothing marks it and nothing has
to be cleared, a half-finished re-wrap resumes by the same query that finds the stragglers of an
interrupted generation rotation. Both `KeyEpoch` and `WrapEpoch` are **server-held and unsigned**, and
`MEMBER#` wraps carry no admin signature, so dormancy is only as trustworthy as the server: an
operator that also holds the old keys can serve the old key set with the old `KeyEpoch` (or raise
`WrapEpoch`) and a dormant member looks current. What detects it is the pin's epoch, and only for an
admin who has already seen the newer epoch; an admin whose only memory is the pre-rotation pin gets
`match` and would wrap new generations to the old key. That is the whole-old-state replay under "What
this does not close", and until the pin-set manifest exists rotation does not hold against an
operator with the old keys. Every path that writes a `MEMBER#` wrap (group creation, invite completion, the rotation re-wrap,
and a removal's or takeover's own entry; readmit writes an admission, not a wrap) sets `WrapEpoch`
from the recipient's `KeyEpoch` and checks it in the same transaction, so a wrap to a key that has
just been replaced is refused rather than stored. Where the recipient is the caller, or the invitee,
the server takes the epoch from the recipient's own `PROFILE`; invite completion also refuses (409
`invitee_keys_changed`, clearing the invite) when the invitee's current keys are no longer the ones
they signed at acceptance, since the wrap and the admission would name keys they no longer hold. The
rotation re-wrap, where the recipient is another member, takes it from the client
(`wrapEpoch` on each wrap, the `keyEpoch` it read from `GET /api/users`), and the member's condition
requires their existing entry to be at that same epoch, so a dormant member is refused (409
`member_dormant`) and a wrap to a replaced key is refused (409 `wrap_epoch_stale`). A start by a
dormant admin sets their own `WrapEpoch` to their current epoch, which is how their self re-key brings
their entry current.

**An ordinary rotation never wraps to a dormant member.** A removal, a leave or any other
generation job leaves a dormant member (`WrapEpoch < KeyEpoch`) out of its recipient set, out of
the job's "behind" set, and out of the server's `members_behind` check that decides whether the
marker may clear (the server reads `KeyEpoch` only for the members it finds behind, which is few).
Two failures follow from the alternative, and both were in the first draft of this section. A job
that tried to wrap to the rotated member's new key would stall on the pin check, since the new key
fails the admin's saved pin (`runRotation.ts` fails closed and the server refuses to clear the
marker), so one rotation, or anyone holding the keys, could block every removal in the user's
groups. And a job run by an admin who has **no pin** of that member would take the first-sight path
(`runRotation.ts` pins a first-sight recipient and wraps to it), so a thief's rotation, whose
`KEYCHANGE#` chain is valid, would be handed the new generation with no prompt. Dormant members
reach a new key only through the explicit approval below.

A side effect is a benefit: once any generation is minted after the user rotated, the old keys no
longer hold the current key, with no admin action aimed at them.

**Approval: what the admin does, and when it mints.** The roster shows the dormant member with the
`KEYCHANGE#` evidence and their fingerprint. Approving replaces the admin's pin deliberately (see the
pinning section), after the admin has compared the fingerprint with the user out of band, and wraps
to the new key. This is the step that stops a rotation being an account takeover **in groups where the rotated
user is not an admin**: someone who rotated a victim's keys gets a new key set and no content
there, because no admin will wrap to a fingerprint the real person did not give them. Where the
victim is an admin it does not hold; see self-approval below. Whether it also mints a generation is decided by
state: **it mints exactly when the member's own entry is still at the group's current
generation**, because then the old keys hold the current key.

- **`Rotating`, member's entry behind the current generation** (a generation was minted since they
  rotated): a plain wrap of the **current** generation to the new key. Nothing is minted. An **admin
  or an ambassador** may do this, as #62 asked, since it is shaped like an invite.
- **`Rotating`, member's entry at the current generation:** the admin's client starts the ordinary
  rotation job (marker, new `GENKEY#` link, re-wrap of every member's entry point) with the
  approved member wrapped to their **new** key. The start signature names a reason, so a re-key is
  distinguishable from a removal. This is a re-key, shaped like a removal, so it is **admin only**;
  that departs from #62's "Admin or Ambassador" on purpose. It costs one generation and one full
  re-wrap per group per rotation, which is why rotations are rate-limited, and it is bounded by the
  same cap that bounds a removal.
- **`Open`:** the admin or an ambassador wraps the **current** key to the new key, and nothing
  else. An `Open` group has no way to re-key, by its own definition, so the holder of the old keys
  keeps reading it. The rotation flow says so, naming each `Open` group, before the user confirms:
  a rotation cannot make them safe, and they should assume that group's content is known to
  whoever holds the old keys.

The earlier draft of this section said a dormant membership must never mint a generation, to stop
every user rotation from burning one in every group. That is right for a membership that is merely
unreadable and wrong when the old identity still holds the current key. The rule above mints in the
second case only.

The history is not lost either way. The new entry point is a wrap of the *current* generation, and
older `GENKEY#` links are reachable backward from it, so rotation costs no history. The mirror is
also true: the holder of the old keys can read everything the user could read at rotation time and
that stays so.

**The rotating user can approve themselves in groups where they are an admin.** Live proof means
they hold the current group key at rotation time, and what approval protects against is a stranger
obtaining the key through the rotated identity. Here the approver is the person who just proved
possession of the old keys, and someone who stole those keys already held an admin's powers in
that group before rotating, so self-approval grants nothing new **at the moment of rotation**. It does change what they keep:
the server cannot tell the owner from a thief holding the same keys, so a thief who rotates can run
this too, and then holds the admin seat under keys only they have, including every future
generation, while the real owner has no way back in. Dropping self-approval from the flow would not
prevent that, because the thief can run the same steps from their own client. What recovers it is a
co-admin, who sees the key change, hears from the owner out of band, and removes that identity; in
a sole-admin group nobody can, which is the same end state as a sole admin who has lost their
keys. So right after `rotate-keys` the
client runs the re-key itself in each `Rotating` group where the user is an admin (the ordinary
rotation job, with every recipient's pin and admission checks, plus their own new key) and
self-wraps the current key in each `Open` group they belong to (see "The `Open` self-wrap" below). This is what keeps a
group whose only admin rotates, and a solo group, from becoming unreadable to anyone, and it cuts
the old keys off at once in those groups. Other members still see the admin's key change through
their pins, so it is not silent. Members and ambassadors of a `Rotating` group have no such path; they wait for an admin. In an `Open` group nobody needs to wait: every member self-wraps, whatever their role.

**The self re-key must survive a closed tab, so it does not depend on the old private key.** After
`rotate-keys` commits, `PROFILE` and `RECOVERY` hold only the new keys, and a re-key start needs the
current group key, which the client could otherwise only get by unwrapping its `MEMBER#` entry with
the old X25519 key, which now exists only in that tab. So before `rotate-keys` the client, holding
the old keys, writes one **handoff row** per group where it is an admin: `HANDOFF#<groupId>` in the
caller's own partition, holding that group's current key and generation wrapped (ECIES, with `HandoffWrapAAD`) to the
**new** X25519 public key, plus that public key. These are written with ordinary writes
(`PUT /api/account/rotation-handoff/{groupId}`, authenticated by the old session), not in the
`rotate-keys` transaction, so the number of admin groups is not capped by the 100-item transaction
limit. Every group counts, public ones included (a public group is always `Open`, and every member
needs the row for the `Open` self-wrap), so `GET /api/groups` and `GET /api/groups/{id}` serve the
caller's own wrapped group key for a public group as well as a private one. `rotate-keys` refuses
with 409 `handoff_required` unless every group where the caller is an admin, and every `Open` or public group
they belong to in any role, has a row naming the new
key at that group's current generation (one past its newest `GENKEY#`
link, which is written when the rotation to the next generation starts, or 0 for a group that has
never rotated), and the flow re-sends any it names. The 409 carries the group ids it is about. "Newest link" includes one a rotation in progress has already written, so the self re-key
resumes that job from the handed-off key like any other resume. If the user's own entry is behind
the newest link (another admin's job has not wrapped to them yet), no row can be written for it,
and `rotate-keys` answers 409 `rotation_in_progress` naming the group (and the PUT, for a generation
that is not the group's current one or one the caller's own entry is not at, answers 409
`handoff_stale`); the flow waits for that job to finish. Only an admin the job has already wrapped to (in practice the one who started it) can
resume it, so the user's rotation stays blocked on that group until then; it is not offered to
proceed with the group marked not handed off. After the commit, the self re-key (or the `Open` self-wrap) reads the row, unwraps it with the
new private key from any later session, runs, and deletes the row when the group's start (or
self-wrap) commits, so it resumes like any other rotation job. **A row has no TTL**: the
rows of a committed rotation are the only copy of a key that group's sole admin can still reach, so
nothing may delete them on a timer. Rows are cleaned up inside the user's own partition, which needs no
index and no purge job. An abandoned rotation leaves rows wrapped to a key that is not the account's
current one: `rotate-keys`, right after its transaction commits, runs a `Query` on `USER#<uuid>`
with `begins_with(SK, "HANDOFF#")` and deletes every row whose public key is not the one it just
committed, and also deletes rows for groups where the caller is no longer an admin or a member
(a co-admin's demotion in a `Rotating` group, which mints no generation, or removal from an `Open`
group, which is only the delete, would otherwise leave a row nothing can use and the account unable
to rotate), and account deletion sweeps the rest with the user's other own rows. The order is
enforced so a pending row is never overwritten: `PUT /api/account/rotation-handoff/{groupId}` answers 409 for
a row whose public key is the account's **current** key (only rows from attempts that never
committed can be replaced), `rotate-keys` refuses (409 `handoff_pending`, naming the groups) while any row naming the current key
**for a group where the caller still owes one** (an admin of it, or a member of an `Open` group) exists, and
the flow finishes pending self re-keys before it offers another rotation. A row whose start is refused because the generation moved, or because the user is no longer an
admin or a member, is deleted by the client with an ordinary delete
(`DELETE /api/account/rotation-handoff/{groupId}`), since nothing else would. The later session reads
rows with `GET /api/account/rotation-handoff` (the caller's own, ciphertext only). The delete on
success is not a separate call: the row is in the caller's partition at a known key, so the start's
(or self-wrap's) own transaction deletes it, and a crash cannot leave a used row behind to block
`rotate-keys`. (Built for the three starts that exist, a removal's, a leave takeover's and the self
re-key's below and the `Open` self-wrap's.) A thief gets nothing from these rows: only the holder of the new
private key can open them, and the old keys already open the same groups. One window remains: if
another admin advances a group's generation after the row is written, that row is stale until the
self re-key's start commits (the check at `rotate-keys` only covers the moment before). The start is
conditioned on the generation (the row's must equal the caller's entry, and the group's link for that
generation must not exist yet, which is how a dormant admin's row is caught: its generation still
equals their entry's), so a stale row fails the condition and is treated as not handed off;
the group then has another admin to approve, by construction. Other than that, no group the user administers depends on a tab staying open.

**The self re-key start.** `POST /api/groups/{gid}/rotation/rekey` is the start for an admin who
rotated their account keys: a rotation that removes no one, run from the group key the handoff row
holds. It is admin only and refused for an `Open` group and a direct message (400
`rotation_not_applicable`). The body is the next generation, the chain link, the caller's own wrap of
the new key and a signature. The signature is under its own context, `underground-bb:rotation-rekey:v1`,
over `RotationRekeyPayload` (group, admin, **member re-keyed**, generation rotated to, **reason**);
the server fixes the reason to `self` here, so a signature made for another reason or for a removal
(`rotation-start:v1`) does not verify. The transaction writes the marker and the `GENKEY#` link
(both carry `RekeyedUserID`, `RekeyReason` and the signature, and no `RemovedUserID`, so a resuming
admin or a takeover never reads a re-key as a removal), moves the caller's entry to the new key and
sets its `WrapEpoch`, checks the caller's `KeyEpoch`, and **deletes the handoff row, requiring that it
exist, name the account's current wrapping key and hold the generation the caller's entry is at, with the
group not yet past it (no `GENKEY#` link for that generation)**.
Otherwise 409 `handoff_stale` and nothing is written, which is the signal for the client to delete the
row. A rotation already in progress is 409 `rotation_in_progress`, as for any start. The record is
served on the group's `rotation` and on keychain links as `rekeyedUserId` and `rekeyReason`. The
client reads it: a resumer checks a re-key marker's signature under the rekey context (the signer is
`startedBy`, the reason `self`, the member re-keyed the signer, and no `removedUserId`; anything else
is refused) and excludes no one, and the removal-history check verifies a re-key link the same way and
records nobody as removed. It runs the start from the handoff row (`runSelfRekey`): the row is opened
with the new key, and is deleted by the client only when the server answers `handoff_stale` or the
caller's own entry has already moved past it, never for a failed read, a failed unwrap, a missing
list entry (an `Open` group runs the self-wrap below instead).
"Finish key changes" on the Rotate keys screen runs it for every pending group. The job that follows
the start checks the caller's own pins, records and removal links through their verified key history
(see "As built: the caller's verified key history" under Key rotation), so a rotated admin can re-wrap
the other members.

**The `Open` self-wrap.** An `Open` (or public) group has no re-key: nothing is minted, so the old keys keep
reading it whatever anyone does, and what a rotation changes is only which key the member's own entry is wrapped
to. `POST /api/groups/{gid}/rotation/selfwrap` brings the caller's own entry there from their handoff row. **Any
member may call it, for their own entry only**; `rewrap/{userId}` refuses the caller's own id on purpose, and an
admin or ambassador approving someone else is a different act (approve). The body is the generation and the group
key from the row, opened with the new key and wrapped to that same key under the entry's own AAD
(`memberWrapAAD`, at the row's generation). It is refused for a group that rotates (400 `rotation_not_applicable`).
One transaction sets the entry's wrap and `WrapEpoch` (the entry must be at the generation the request names),
checks the caller's `KeyEpoch`, and **deletes the handoff row, requiring that it exist, name the account's current
wrapping key and hold that generation**; otherwise 409 `handoff_stale` and nothing is written, which tells the
client to delete the row, and a replay is stale for the same reason. Because the row is how a member gets back in,
every member of an `Open` group writes one before `rotate-keys` (the PUT accepts any member of such a group, not
only an admin), `rotate-keys` counts those groups like administered ones for `handoff_required`,
`handoff_pending` and `rotation_in_progress`, and the sweep after a commit keeps a member's row for an `Open`
group while it deletes a plain member's row for a `Rotating` one, which nothing can use. `GET /api/groups` serves
`noRotation` on each entry so the client does not have to read every group to know which it owes. The client runs
it from the same "Finish key changes" step as the re-key (`runSelfRekey`, which takes the `Open` branch).

**A handoff change during a rotation.** `rotate-keys` checks the handoff rows before it commits, and
the commit alone cannot see them (a transaction of this size cannot condition on one row per group). A
`PUT` or `DELETE` landing between the check and the commit (a second tab, or a client retrying with
fresh keys while the first request is in flight) would leave a committed rotation whose handoff row is
gone or names another key, and the sweep after the commit deletes a row that names a key other than
the current one. A sole admin would be left with a group nobody can open, and `PUT` would refuse to
repair it (the key it needs to name is now the current one). So every `PUT` and `DELETE` of a handoff
row adds one to a counter, `USER#<uuid>` / `HANDOFFSEQ`, in the same transaction; `rotate-keys` reads
the counter (strongly consistent, absent as 0) **before** it lists the rows, and its commit carries a
condition check that the counter is still that value. Any write in the window fails the rotation with
409 `handoff_changed`, which the flow retries from the top. The counter is never reset and is swept
with the account.

**A rotate-keys whose response was lost.** The commit ends every session, so a client that sent the
request and never saw the answer cannot ask the server anything that needs one. It reads the
unauthenticated login challenge instead: if the served `wrappedPrivateKeys` are this request's, it
landed. That read is eventually consistent, so the old wraps prove nothing, and the client treats the
attempt as unknown and keeps the new keys and the recovery code. One answer can settle an unknown
send as "nothing happened", and only with a second step: 400 `signed_day_stale`, sent for a day that
has **passed** (a future day stays uncoded, it becomes valid later). That 400 says only that *this*
request is too old. An earlier send may have passed the day check just before the window closed and
still be between the check and its commit (the Lambda timeout is 10 s and the edge retries), so the
client waits longer than any send can stay in flight (60 s), then reads the account's credentials
(`GET /api/account/credentials`, a strongly consistent read of `PROFILE`). A session being valid
proves nothing, because the cookie jar may already hold one issued by the commit itself (the lost
response's `Set-Cookie`) or by a login with the new password in another tab. So the client settles
on what the account holds: the credentials it started from (same `credentialVersion`) mean nothing
committed and nothing still can, and the request's own wraps mean it landed. A failed read, or
credentials that are neither, leave the attempt unknown. Every other refusal stays unknown.

**Other admins after an approval.** Once admin X approves dormant member M, M is no longer
dormant, so an ordinary rotation by admin Y includes M, and if Y pinned M's old keys the check
fails and M lands in `blocked`: the server will not clear the marker while M is behind, so Y's
removal cannot finish until Y re-pins M. The same happens to every other admin who pinned a
self-approved rotating admin. The approval list only shows dormant members, so it would show Y
nothing. The rule is **fail-closed by default and one explicit action to resolve**: the roster
lists every member whose served keys fail the viewer's pin with the `changed` verdict and who is
not dormant, with an **"accept key change"** action. A `rollback` verdict is **not** offered it: no
legitimate flow produces one, and accepting it would re-pin keys the user rotated away from, so it
stays a hard-block with no accept action. The action is offered with evidence and never taken automatically:
the verified `KEYCHANGE#` chain from the pinned keys to the served ones (rotation by a holder of the
pinned key, or no link), the member's fingerprint to compare out of band, and whether the wrap was
made by another admin or was a self-approval. Accepting replaces that admin's pin, exactly as the
original approval did. `runRotation` reports such members in the `blocked` outcome's `changed` subset (only the
`mismatch` verdict, never `rollback` or `bad-signature`), and `describeRotation` says they "have new keys
that don't match the copy you saved earlier, possibly approved by another admin" and to "check the
fingerprint with them, then use Accept key change in the member list", instead of the plain
"don't match" line. A subset rather than a separate status, because one run can block a
changed member and a rolled-back one together and every existing consumer already handles
`blocked`. It still wraps to nobody until the admin accepts. A signed approval record by the first approver was considered, so
that Y could re-pin on X's word; it is not needed to close this stall and adds a delegation the
pinning section does not otherwise have, so each admin makes their own decision.

**Who wrapped a member's entry (#280).** The "accept key change" prompt tells the admin whether the
member's current wrap was made by another admin, by the member themself, or by nobody who signed for
it. The writes that bring an existing entry to a member's new keys therefore carry a **wrap record**:
`POST /api/groups/{gid}/rewrap/{uid}`, `rotation/approve/{uid}`, `rotation/rekey`,
`rotation/selfwrap`, and the two ways an admin brings their own entry current while starting a
rotation, a removal's start (`DELETE /api/groups/{gid}/members/{uid}` in a Rotating group, the
remover's own entry) and a leave takeover (`rotation/takeover`). Three writes set an entry's
`WrapEpoch` without one, and read as "no signed record": the creator's entry when a group is made,
an invitee's entry when an invite completes (the inviter's signed admission is that record), and the
ordinary re-wrap of members by the rotation job.
The record is the wrapper's Ed25519 signature, under its own context `underground-bb:wrap-record:v1`,
over `WrapRecordPayload(group, wrapper, member, generation, keyEpoch, reason, day)`: the generation
the entry was wrapped at, the member's `KeyEpoch` it was wrapped to (the value stored as `WrapEpoch`),
the reason and the UTC day. The server fixes the reason from the endpoint (`approval` for the two that
approve someone else, `self` for the other four), checks the signature under the caller's current
signing key and the day with the same window as a pin's, and writes `WrapperUserID`, `WrapReason`,
`WrapDay` and `WrapSignature` on the member's entry in the same transaction as the wrap. The roster
serves them as `wrapRecord` next to `wrapEpoch`. The fields are optional on the wire, all or none, so
a client from before this existed keeps working and its wraps read as "no signed record"; a signature
without a day, or the reverse, is 400. The client signs the epoch it read from the account's
projection, which can lag a just-committed rotation, so a record the server refuses as
`bad_signature` is dropped and the same wrap sent once more without it: a record is evidence, and
a refused one must not turn a wrap that would have succeeded into a failure.

A reader trusts a record only when it is **for the entry as it stands**: the signature verifies
under one of the wrapper's keys for the signed day, and the payload is rebuilt from the entry's
*own* served `generation` and `wrapEpoch`, so a record left over from an earlier wrap fails the
match and reads as no record. The writes that sign nothing do not clear the record (a removal's
re-wrap of the others, an invite): the binding does that work, because a later wrap moves the
generation or the epoch. The one exception is harmless: the rotation job's re-wrap (`#gen <= :gen`
while a marker exists) can rewrite an entry at the same generation and epoch, for instance one a
re-key approval just wrote. The record attests to the generation and the member key epoch the entry
is wrapped to, not to the wrapped bytes, and that rewrite leaves both true. What it does and does
not say: the server can withhold a
record, which shows as "no signed record", but cannot forge one, move one to another member, group,
generation or epoch, or turn a self wrap into an approval, provided the wrapper's keys are ones the
reader already trusts: the reader checks a record only under keys anchored to its own key (when it
wrapped the entry itself) or to its own pin of the wrapper (anyone else), and an unpinned or
changed wrapper reads as "could not check", never "wrapped by". Where the subject wrapped their own
entry, the keys are the very ones being questioned, so "self" only says whoever holds these new keys
wrapped them. A superseded key of the wrapper that leaked can still sign a record dated anywhere in
that key's interval, because nothing like the pin roster rules it out; that is accepted for
evidence. It does not prove the wrapper was an
admin or ambassador that day: the roster says so, unsigned, and proving it means walking the grant
chain at every prompt, which is left out. Like the chain evidence it informs the person deciding and
approves nothing.

**The window, stated plainly.** From the moment of rotation until an admin acts in a group, the old
keys keep reading that group's new content, `Rotating` included, because the generation in use is
still the one their entry holds. The only prompt an admin gets is the roster mismatch, so a group
whose admins do not open it has an unbounded window. The cooldown, the self-approval above for
admin groups, and a roster that lists dormant members first are the mitigations; there is no
server-side timer that acts for them, because the server cannot wrap keys.

`POST /api/groups/{id}/rewrap/{uid}` is the write for the plain-wrap cases, and **the server
enforces the mint rule itself rather than trusting the client**. The caller must be an admin or an
ambassador of the group. It is a conditional update of the member's wrap, its generation and
`WrapEpoch`, rejected unless `WrapEpoch < KeyEpoch`, `KeyEpoch` is the value the approver wrapped
to, and, in a `Rotating` group, the member's entry is **behind** the group's current generation.
Otherwise it answers 409 `rekey_required`, which sends the caller to the re-key: without that
condition a buggy or old client, or an ambassador, could "approve" with a plain wrap of the current
generation while the old keys still hold it, and the roster would then show the member as current. The self re-key is `POST rotation/rekey`; the minting
case has its own endpoint, below.

As built: the body is `{generation, wrappedKey, keyEpoch}`, with no signature, as for the rotation re-wrap.
`generation` must be the approver's own and, when a marker exists, the marker's; the approver's entry is
checked at it in the same transaction. A member whose `WrapEpoch` is not behind their `KeyEpoch`, including
every account that never rotated, answers 409 `member_not_dormant`. A stale `keyEpoch` answers 409
`wrap_epoch_stale`, a member past the approver's generation or gone answers 404, and a `Rotating` group
needs the member strictly behind. An `Open` group has no re-key, so there the member may sit at the
approver's generation and the wrap replaces the copy the old keys hold.
A retry after a lost 204 answers `member_not_dormant` too, since the first call set `WrapEpoch`; the approve
UI treats it as already approved and re-reads the roster.

The minting case is `POST /api/groups/{id}/rotation/approve/{uid}`, admin only, a `Rotating` group only
(400 `rotation_not_applicable` otherwise), no marker (409 `rotation_in_progress`). The body is the
self re-key's plus `memberWrappedKey` and `memberKeyEpoch`; the start signature is
`RotationRekeyPayload(group, admin, member, generation, "approval")` and the server fixes the reason. One
transaction writes the marker (`RekeyedUserID` = the member, no `RemovedUserID`), the `GENKEY#` link, the
admin's entry, and **the approved member's entry** at the new generation, because the ordinary re-wrap
refuses a dormant member and the job could never reach them. The member must be dormant and at exactly the
admin's generation; behind it, 409 `rekey_not_required` sends the admin to the plain wrap above (the
two endpoints partition the cases), and a caught-up or never-rotated member is 409 `member_not_dormant`.
`wrap_epoch_stale` is the member's keys, `key_epoch_stale` the admin's own.
A retry after a lost 204 does not answer `member_not_dormant` here: the start moved the admin's own entry
to the new generation, so a resent body fails the generation check with a code-less 400, whether the
rotation is still running or done (`rotation_in_progress` only comes back for a body rebuilt one generation
higher). The approve UI treats that 400 as "maybe it already landed" and re-reads the roster instead of
showing an error.

#### The Ed25519 half and the key history

Replacing a signing key does not merely affect what the user signs next. It would invalidate every
signature they have ever made, because the only public key a reader could fetch would be the new
one. Two of those signatures are claimed as permanent properties: every post and comment carries
one, and `GRANT#` items must stay verifiable back to the group creator *forever*, which is why they
never expire. A rotating creator would otherwise strand the root of every role chain in their group.
There is no re-signing path, and rotation does not need one.

So **superseded Ed25519 public keys are retained on the `PROFILE`, each with the interval it was
current for, and a signature is verified against the key that was current when the item was
written**. (The write side is `rotate-keys` above; the read side, `keysOnDay` and the projection,
already exists.) For posts and grants the day in the sort key gives that to the resolution required;
**comments carry no day in their key, so the signing day is part of the signed payload** and the
verifier reads it before selecting a key. A comment's parent post's day cannot stand in: threads
routinely outlive the day their post was written, so a comment written on day 20 of a post's life
would resolve to the interval current on day 1 and, if the author rotated in between, verify against
the **wrong** superseded key. That fails in the direction that looks like an attack — not
"unverifiable" but affirmatively invalid, which is the exact confusion the retention exists to
prevent. Putting the day in the comment sort key would fix it and is **rejected**: lexicographic
order there is depth-first traversal order, and that property is why the materialized path exists. A
rotation appends to this history rather than replacing an entry, the `GET /api/users/:id` projection
serves the whole set, and `PIN#` accordingly pins a key *set*. Without the history a client has only
bad options: reject unverifiable posts and the user's history vanishes; show them unverified and
"forged" becomes indistinguishable from "signed with a superseded key"; or stop verifying old items
and the property is gone altogether.

Retention is why this is affordable: the history holds public keys only, it grows by one entry per
rotation, and rotations are rare by construction. The X25519 half needs no equivalent, because
nothing is ever verified against an old wrapping key.

**A leaked superseded key must not be able to write.** The day in a signed item is chosen by its
signer, so the holder of an old private key can sign a grant or comment dated inside the old
interval, and a verifier that accepts any key current on that day will accept it. What stops it is
on the write path: the server refuses a day outside its skew tolerance of its own clock (it does
today for grants, claims, designations, admissions and readmits), and the rotation signs the
session out. **Posts and comments, the handlers must also check
the signature against the user's current key**; the post handler does (#42), and the comment handler,
not built yet, must. An attacker without the operator's database access then cannot land a backdated item. **An
operator can**, and for grants and comments that is the existing by-day retention design, which
this does not change; it is stated in the threat model rather than treated as the same boundary.
Pins and verification records are different, and are handled below. On the rotation day itself both
keys are candidates (day resolution), which is accepted.

**Every signer-key lookup has to use the served set.** `resolveSignerKeys` in
`web/src/routes/runRotation.ts` has a "current key only" shortcut for the caller, and it now also
covers every removal record the caller has ever signed, which are permanent. Once keys rotate, an
admin who ever removed anyone under an older key would have their own rotations stop on "does not
verify". The fix covers removal history, not only resuming a rotation.

**As built: the caller's verified key history.** The client builds it once per job from the
`KEYCHANGE#` chain on `GET /api/users/{self}` and the rosters on the first page of `GET /api/pins`
(`lib/crypto/own-history.ts`). It is trusted only if every link verifies under both keys it names
(the payload carries the epoch before the rotation), epochs run 1..n with none missing, each link's
old key is the previous link's new key, days do not go backwards, and the last link's new key is the
key the worker holds. Each roster is kept only if its entries hash to the digest the link signed.
A pin or verification record signed under a superseded key then counts only if that key is a link's
old key, the signed day is no later than that link's day and no earlier than the previous link's
(both keys are candidates on the rotation day), and the row's id is in that link's roster. The
interval comes from the signed link days, not from the served `SupersededSigningKeys` intervals,
which are unsigned. For grants the caller's own history is built from the chain (each
old key from the previous link's day to its own link's day), never from the served projection, which
must still agree with the chain (the same superseded keys, `KeyEpoch` equal to the chain length)
before it is used at all; otherwise a server holding a leaked old key could widen its served interval
past the rotation and have later-dated grants verify under it. Removal links carry no day, so any key
in the verified chain is accepted for them (a forged removal record can only exclude someone). When
the history cannot be built, only the current key is accepted, so a failed read blocks rather than
accepts.

#### What a key change looks like to others

A client that pinned a user sees a different key set, and the existing rule holds: **exact equality
or hard-block**. Rotation adds what a block could not say before. The served `KEYCHANGE#` chain
lets the client verify whether the new key was introduced by a holder of the pinned one (each link
is signed by the key before it and by the key after it). The block then reads either **"keys
rotated by the holder of the key you saved"** or **"keys changed with no link to the key you
saved"**, which is the operator-substitution signature, since the operator never holds the old
private key. Both block, and both resolve through approval ("Approval: what the admin does", and "Other admins after an approval"). The link informs the human
deciding whether to approve; it never approves anything. A link is also exactly what someone with
the stolen keys can produce, which is why it is evidence and not a trust path.

**A pin and a verification record carry the day, and rotation re-signs neither.**
Earlier drafts had the client re-sign every pin and verification under the new key before
discarding the old one, with an interval attribute to finish an interrupted run. That loop is the
most fragile thing in this feature: it needs the old private key to survive an interruption, and an
unfinished set leaves rows nobody can verify. It is unnecessary for ordinary use: **the payload
includes the UTC day it was signed on** (checked by the server against its clock), and the pinner's
own client verifies it against the key that was current that day, from the pinner's own served
history. Pins and verification records therefore move to payload version 2
(`underground-bb:pin:v2`, `underground-bb:verification:v2`). A verifier uses only the v2
signing context, so a row that claims v1 fails and a v2 row relabelled v1 by the server fails the same
way. **A pin or record that does not verify is `bad-signature`, never `first-sight`**, exactly as
`evaluatePin` already treats any pin that fails verification (the server must not be able to reset a pin by
corrupting it): it is withheld and named to the user and never re-pinned over. Existing v1 rows are
therefore wiped once, by a migration step in the v2 slice (`PIN#` and `VERIFIED#` for every user),
rather than left to fail; nothing is deployed with real users yet, and the accounts that exist are test
accounts and the maintainer's. Only the **pin** also
carries the pinned user's `KeyEpoch` that it saw (below). A verification record does not: it signs
the fingerprint, which already covers both current keys.

**But a day alone would let a leaked old key forge them, so a superseded key's pins are listed.**
Pins and records are the things the *operator* is the adversary for ("Malicious operator deletes a
pin, then substitutes that key"), and the server checks them only for hygiene. An operator who also
holds a leaked superseded key could write a pin dated inside the old interval that maps a
counterparty to keys of its choosing, and it would read as `match`; or a verification record that
reads as "verified". Both are worse than deletion, and they break the promise that a withheld
record "never makes anything look verified that was not". So the `key-rotation` payload also
carries a **roster digest**: the sorted list of `SHA-256(SK || signature)`, truncated to 16 bytes,
of every `PIN#` and `VERIFIED#` row the caller holds at rotation time, hashed into the payload
that both keys sign, and stored on the `KEYCHANGE#` row (the list itself is served only to its
owner, with `GET /api/pins`). A client accepts a pin or record signed under a **superseded** key
only if it appears in that key's link. Rows signed under the current key need no listing; anything
written after the rotation is signed under the current key. The client already holds its pins when
it builds the payload, so this stays one transaction with no loop. Two rules close the remaining
holes: the client requires the served chain to **end at the signing key it unwrapped itself** (an
operator holding a leaked key can sign a fork that ends at a key of its own, but cannot produce the
user's real keys), and **the flow holds this tab's pin and verification writes from building the digest until the
commit** (the commit signs every other session out, so after it only this tab can write). A row
that nonetheless lands in between, from another device, is not listed, so it reads as `bad-signature`
and is named to the user: the honest race fails loud, not silent.

**A `bad-signature` pin has one resolution, an explicit "reset saved key" action.** Without one, a
member whose pin fails verification would block every rotation that admin runs, with nothing to
resolve it. The roster and the `runRotation` outcome name the person and offer the action, which
shows their fingerprint to compare out of band and, on confirmation, signs a fresh v2 pin for the
keys now served and writes it with the existing `PUT /api/pins/{userId}`, which replaces the row (no
delete endpoint is needed). It is never taken automatically and never by a rotation job. It gives
the server no power it lacks, since the server can already delete a pin, and it makes the user's
decision visible. A `bad-signature` verification record is resolved the same way, by checking the
fingerprint again, which signs a new record over the old one.

With the epoch in the pin the verdicts become: served set equal and epoch equal → **match**; served
epoch lower → **rollback** (hard-block: the server is serving keys older than ones this account
already saw); served epoch higher or set different → **changed** (hard-block, with the link
evidence above). A verification record needs no new rule: after a rotation of the verified user it
reads "Keys changed since you checked", which is correct.

**What this does not close.** Replay of a *whole old state* to a client whose only memory is on the
server (the old pin, the old key set, the old epoch, all served together) still reads as `match`,
because nothing the client holds is newer. That is the manifest problem the pinning section
defers, and rotation does not make it worse than deleting the pin, but it is the reason the manifest
should follow. The epoch makes the replay detectable the moment the client has seen anything newer,
including in another session on the same device.

#### Everything else a rotation touches

- **Group `META` anchors** record the creator's signing key at creation and are verified against the
  creator's history, so they keep verifying.
- **Admissions** follow the `KEYCHANGE#` chain for the X25519 key (the admission check, below under
  "Roles and the chain of trust"); the Ed25519 rule already accepts superseded keys.
- **Pending invites** the user created stop working, because `k` comes from the old signing seed
  (see the invite section). The flow revokes them first.
- **`Open` groups** are the one place the user is told, at the point of rotation, that the old keys
  keep working as readers.
- **The interface must clearly distinguish "change password" from "rotate keys."** They sound alike
  and differ enormously: one is trivial and keeps everything, the other signs out every session,
  changes their fingerprint for everyone who pinned or verified them, and needs an admin in every
  group where they are not one to act. A user who
  conflates them picks the destructive one believing it is the cheap one. The flow lists the user's
  groups and which are `Open`, states what is lost and what is not, and requires the new password
  and the recovery code before it completes.

**Group governance rules — who may leave, what happens to the last admin of a group, how a
successor is chosen — are decided in the issues rather than here.** They are membership policy
rather than cryptography, and they do not change any key or item in this document. The one overlap:
a group whose only admin rotates is handled by the self-approval above, which resumes from the
handoff rows and so does not need the tab to stay open; if a row is stale (see above) and the group
has no other admin, nobody can act until another admin exists, which is the same
state as a sole admin who has lost their key, and the successor designation exists for it.

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
attacker-chosen values and sees nothing wrong. No mismatch, no hard-block, no approval
ceremony. The signature is what makes the record trustworthy to the only party who cares about it —
the client that wrote it — and a client that stores a pin and reads it back without verifying has
implemented something that passes every test and protects against nothing.

**Pins live server-side deliberately, under the pinning user's own partition, so a new device
inherits what an existing one verified.** The alternative — pins as local browser state — means
every new login re-TOFUs every counterparty, and warnings that fire constantly are warnings nobody
reads. This is state that follows the user rather than the browser, which is possible precisely
because the signature makes server storage safe. One consequence follows and is worth stating here
rather than rediscovering later: since a pin is signed by the pinning user's Ed25519 key, **rotating
that keypair must not orphan that user's pin set**, exactly as it must not orphan their posts.

**A pin carries the UTC day it was signed on, and is verified against the pinner's key for that day.**
It is the same mechanism comments use (the superseded-key retention above), and it is why rotation
re-signs nothing: the pinner's client loads its own pins after a rotation, reads each one's day, and
selects the key from the pinner's own served history. Earlier drafts re-signed every pin under the new
key before the old one was discarded, with an interval attribute to finish an interrupted run. That
loop needs the old private key to survive an interruption and leaves unverifiable rows when it
does not, and the day removes the need for it. The server checks the day against its own clock, as
it does for grants. Details, and what the pin also carries, are under "What a key change looks like
to others" in the Key rotation section.

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
survive the keypair rotation described above, where the pin set stays valid but the manifest's own
signature has to move to the new key without that move being forgeable.
Until it exists, **fingerprint verification is the only control that detects a deleted pin**, which
is the same answer the design already gives for first contact — and that is the honest way to read
this: pin deletion returns a counterparty to the first-contact case, silently.

**A superseded pin can be replayed, and that is worse than deletion.** Writing a pin replaces the previous row.
Once a user re-pins (after a key change), the server can keep the old row and serve it later, together with the old
key set: the client verifies its own signature, finds the served set equal to it, and reports `match` for keys the
user has already moved off, which is exactly when those keys may be compromised. Deletion only drops the client to
first contact, which the roster does not label "verified"; a replay passes as a genuine pin. Rotation makes this
reachable, so a pin now carries the pinned user's **`KeyEpoch`** under the signature, and a served epoch below the
pinned one is a hard-block of its own (`rollback`). That closes replay of a stale *pin* or *key set* against a client
that has seen anything newer. It does not close replay of a whole old state (pin, keys and epoch together) to a client
that has nothing newer to compare with; only the pin-set manifest above would, so rotation does not make deletion or
replay worse than they were, and does not fix them.

**What a pin covers, and what counts as a match.** A pin signs the pinned user's current X25519 wrapping key and
their Ed25519 signing keys as a *set* (current plus every superseded key, order not significant), together with
both uuids and the pinner's own signing key. A served key set matches only if it is **exactly equal** to the pinned
one. A set that merely *adds* a key is a mismatch, not an "extension": a server inventing a superseded key for
someone looks identical, and that key would then verify backdated grants. A legitimate rotation is a different
set with a higher `KeyEpoch`, so it hard-blocks and resolves through approval like any other change; the
`KEYCHANGE#` chain only tells the person deciding whether the new key was introduced by a holder of the pinned one. Implemented as `PUT /api/pins/{userId}`
(the server checks the signature under the caller's current key, for hygiene only) and `GET /api/pins` (the caller's
own pins, unverified by the server); the verdict logic is `evaluatePin` in `web/src/lib/crypto/pin.ts`.
The roster check (`runGrantCheck.ts`) pin-checks every grantor's served key set before the grant-chain verifier sees
it: a match passes, a first sighting is pinned and reported as first-seen, and a mismatch or bad signature is
**withheld** (the verifier then fails closed on that person) and named to the user, never re-pinned over. The roster
says "verified" only when the group anchor and every grantor's keys all matched something saved earlier. A pin covers
the key *set* and the pinned user's `KeyEpoch`, not the intervals of superseded keys; those are served and chained
(Key rotation, above), and a set that differs from the pinned one blocks regardless.

Resolving a mismatch is deliberately not a dismissable dialog. A legitimate key change is an
**approval event**: the user's group memberships go dormant, and an admin or ambassador approves
the new keys (the rewrap endpoint, or an admin's re-key), which forces exactly one deliberate check
by someone with authority rather than N warnings across N members. The invite handshake's point,
that the invitee signs their own keys, is carried here by the second signature on the `KEYCHANGE#`
link.

Approval is therefore the one path that **clears a stale pin rather than blocking on it**. The authorizing admin's own client also sees the mismatch, and a blanket "hard-block on
mismatch" check would block the very operation that resolves it, making a key change unrecoverable.
Approving the key change *is* the trust decision, and it replaces that admin's pin explicitly. Other
members' pins do **not** update by themselves; see "Other admins after an approval" in the Key
rotation section for how each of them resolves it. This delegates verification to whoever approved — a
real trust decision, and the honest limit of what pinning gives you.

**A fingerprint is SHA-256 over both of a user's current public keys — the Ed25519 signing key and
the X25519 wrapping key — with a domain-separation prefix and a fixed field order, displayed as 60
decimal digits in twelve groups of five.** Each of those choices closes a specific failure:

- **Both keys, not just the signing key.** The X25519 key is the one the substitution attacks
  actually target: group keys get wrapped to it, so a fingerprint covering only Ed25519 would let an
  operator swap the wrapping key while the value two users compared still matched. Verification
  would pass and the attack would succeed.
- **Current keys only — superseded Ed25519 keys are excluded.** Including them would change a
  fingerprint on every rotation and break every verification a counterparty had already done. The
  cost is that two different key *sets* can share a fingerprint if they share current keys, which is
  the correct trade: what a person verifies is who they are talking to now.
- **Decimal groups, not hex.** A 64-character hex string gets compared by eyeballing the first and
  last few characters, and grinding a key whose fingerprint matches at both ends is cheap. Digits in
  short groups are what make reading the whole value aloud realistic, which is the only comparison
  that is actually worth anything.
- **One-sided, not pairwise.** A user has one fingerprint that anyone can check, rather than a
  distinct safety number per pair. That keeps it displayable on a profile and embeddable in an
  invite link, at the cost of two comparisons instead of one when two people verify each other.

**What "I verified them" is.** A verification is a signed record in the verifier's own partition,
`USER#<verifier>` / `VERIFIED#<verified uuid>`, signed under the verifier's Ed25519 key
(`underground-bb:verification:v2`) over `{verifier uuid, verified uuid, verifier signing key,
fingerprint, UTC day signed}`. A reader checks it against the verifier's key **for that day**, from
their own served history, and a record signed under a superseded key counts only if the rotation's
roster digest lists it (Key rotation, above). **It signs the fingerprint string, not the keys**, for two reasons. The fingerprint is
exactly what the person compared out of band, so the record says what they actually checked. And it
already covers both of the other user's current keys, so the record stops applying the moment either
changes, with no separate staleness rule. The client computes the fingerprint locally from the keys
the server serves and never takes one from the server. Reading a record back has four outcomes:
*none* (no record, the normal case), *verified* (the record is valid and the served keys still give
that fingerprint), *changed* (valid, but the served keys now give a different fingerprint) and
*bad signature* (the record does not verify under the reader's key for its day, is signed by a
superseded key the rotation digest does not list, or is for another pair). **Changed is shown as a warning, never as "not verified"**: a real key change and a
substituted key are indistinguishable from here, and a substituted key after a verification is
precisely the case verification exists to catch. This also makes it the one signal that notices a
deleted pin on a user the reader had verified, because the substituted keys no longer give the
verified fingerprint. The server checks the signature, and that the fingerprint is the one it would
compute for the other user's keys right now (a clear 409 `fingerprint_stale` if they changed while
the person was comparing), as hygiene only: the party that must verify a record is the client that
reads it. Like a pin, a record can be withheld or deleted, which only costs the reader the
"verified" mark and never makes anything look verified that was not. Records are swept on account
deletion. A key rotation of the *verifier* leaves their records valid, since the record carries the day it was
signed on and is checked against the verifier's key for that day (the pin mechanism); a rotation of the *verified*
user changes the fingerprint, so the record reads "Keys changed since you checked", which is the correct outcome.

The roster shows each member's fingerprint on request, four groups to a row so that it is read and
compared whole, with a "check fingerprint" action that signs and stores a record once the person
confirms every group matched, a "✓ fingerprint checked by you" mark on verified members, and
"Keys changed since you checked" on a changed one. The wording is deliberately distinct from the
roster's role mark, which is about the grant chain. **One-sided by decision:** there is no "verified
each other" badge, because it would need the server to serve each side the other's record, which
tells a user who has checked them and builds a graph of who verified whom out of what is today
private to each verifier (#250, declined). The operator is not the audience that argument protects:
`VERIFIED#<verified uuid>` sits in the verifier's partition in plaintext, like `PIN#`, so a database
dump already shows who verified whom (docs/THREAT_MODEL.md names this). What is withheld is exposure
to the *other users*, and the detection value is untouched: a reader learns of a substituted key
from their own record ("Keys changed since you checked") whether or not the other side ever checked
them back.

Verification stays **available rather than mandatory**: fingerprints are shown on profiles and there
is an explicit verify affordance. Invite links additionally carry the inviter's fingerprint in the
URL fragment, which the browser never transmits, so the invitee's client can check it against a
value the server never saw.

## Groups

### Invites — the signed handshake

An invite is a three-step handshake that prevents the server from substituting its own key for the
invitee's:

1. **Inviter creates.** Signs `{invite_id, group_id, inviter_pubkey, expires_at}`
   with their Ed25519 key. This payload contains **no secrets** and is safe at rest. Also derives
   `k = HKDF-SHA256(inviter's own long-term Ed25519 seed, info = "underground-bb:invite-mac:v1" ||
   invite_id)` — nothing is stored, so `k` is re-derivable by the inviter's own client at step 3, on
   any future login, from `(seed, invite_id)` alone. `k` travels in the invite link's **URL
   fragment**, next to the fingerprint (see below) — browsers never transmit a URL fragment to any
   server, so `k` reaches exactly the party who was actually handed the link, and the server never
   sees it.
2. **Invitee accepts.** Verifies the inviter's signature, then signs
   `{invite_id, ed25519_pub, x25519_pub}` with their own key, and additionally computes
   `invite_mac = HMAC-SHA256(k, that same signed payload)` using the `k` carried in the link's
   fragment. `invite_mac` is submitted alongside the signature and stored (opaquely — the server
   cannot derive `k` and never checks it) so step 3 can read it back.
3. **Inviter completes.** Their client re-derives `k` from its own long-term seed and `invite_id`,
   verifies `invite_mac` against the acceptance payload, and — only if that verifies — wraps the
   group key to the X25519 key **that was signed in step 2** — never to a key the server offers
   unilaterally.

**Why step 2's signature alone is not enough, and what `invite_mac` actually closes.** Signing
`{invite_id, ed25519_pub, x25519_pub}` proves those two public keys are mutually consistent — that
whoever signed this payload controls the matching Ed25519 private key — but every value step 3
checks it against (`ed25519_pub`, `x25519_pub`, and the signature itself) arrives in the **same**
server response, which the server fully controls. A malicious or compromised server can mint its
own fresh keypair, sign this payload itself, and serve that as if a real invitee had accepted; the
signature verifies perfectly, because the forger did sign their own keys, and step 3 would wrap the
real group key straight to the server's own key with no real invitee involved anywhere. Plain
signature verification authenticates *a* keypair without binding it to *the link-holder specifically*
— the same "authenticates a key-holder without binding which one" shape the single-use discussion
below describes for a forwarded link, but here the attacker does not even need a forwarded link, just
network position. `invite_mac` closes this because `k` is a secret the server never sees: a server
that cannot compute `k` cannot produce a `invite_mac` that verifies, no matter what keypair it mints
or signs with. This binds the acceptance to whoever holds the actual invite link, which is exactly
the model the single-use rule already assumes but plain Ed25519 verification alone did not enforce.

**`k` is derived from the inviter's *current* signing seed, so key rotation between creation and
completion permanently breaks the invite.** If the inviter's Ed25519 identity key is rotated after
creating an invite but before it completes, step 3 re-derives `k` from the NEW seed, `invite_mac` no
longer verifies against a payload accepted under the OLD seed's `k`, and the invite fails permanently
— not transiently, and not distinguishable client-side from a real substitution attempt, since both
produce the identical `InviteMACError`. Key rotation (#62) accepts this rather than carrying invites
across: the old seed is the one thing a rotation is meant to stop relying on, and `k` cannot be
re-bound without the invitee's link. So the rotation flow **lists the user's pending invites and
revokes them before the keys change**, and says so; any that survive (a revoke that failed) fail
with the error above and have to be re-created.

**The MAC's guarantee also has a precondition worth stating explicitly: it protects the invite only
if the link itself reaches the invitee without passing through this server.** `k` travels in the URL
fragment specifically because browsers never transmit a fragment to any server — but that guarantee
only holds for the *literal* link. Posts are encrypted under the group key regardless of a group's
visibility, so pasting a link into one does not itself expose `k`; the real risk is a feature that
relays the link through a mechanism the server can read at all, such as a server-mediated
invite-by-email or notification feature. If a future feature ever does that, the operator would see
`k` in the relayed content and the substitution this section exists to block becomes possible again.
**Any future feature must never deliver an invite link through this server** — out-of-band delivery
(a message the inviter sends outside the app, or copy/pasting the link directly) is a load-bearing
part of this guarantee, not an implementation detail.

Step 3 happens automatically the next time the inviter's client is online; the group key exists in
plaintext only inside a member's browser, so no server-side process can complete it.

Step 3 also leaves the one durable, signed statement that this inviter admitted this invitee: an
**admission record** at `GROUP#<gid>` / `ADMISSION#<invitee uuid>`, written in the same transaction as
the membership (the invite rows are deleted by it, and a plain member has no grant, so nothing else
signed would say who is a member). The inviter signs `AdmissionPayload` (group, inviter, invitee,
the invitee's Ed25519 and X25519 keys as signed at step 2, invite id, the inviter's own current grant
address, UTC day) under `underground-bb:admission:v1`, in the worker, only after the invite MAC has
bound those keys to the real invitee. The server requires it (400 `admission_required` without; a
browser on an older bundle reloads), checks the grant address is the inviter's current one (409
`grantor_ref_stale`), the day is within the grant-day tolerance, and the signature verifies under
the inviter's current key (400 `bad_signature`), then stores it. A rejoin overwrites it. Members read
the records at `GET /api/groups/{gid}/admissions`. What checks them is the rotation job, below.

**Two storage details make the ceremony work, and both are easy to get wrong.**

**An invite is single-use, and the write at step 2 is conditional on the invitee field being
absent.** The `<iid>` is a bearer token — `GET /api/invites/:id` is unauthenticated by design, so
anyone holding the link can present it — and there is exactly one `INVITE#<iid>` / `META` row for
the acceptance to land in. Without the condition, last writer wins: a second person who obtained the
link (a forwarded message, a screenshot) accepts after the intended invitee, the row now names them,
and the inviter's step 3 wraps the group key to **their** signed X25519 key. The signature verifies
correctly, because they did sign their own keys — the handshake's guarantee is intact and
irrelevant, since nobody substituted anything. **The ceremony authenticates *a* key-holder without
binding *which* one**, and possession of the link is the entire authorization. The wrong person ends
up in the group while the intended invitee, who was told acceptance succeeded, is silently never
keyed. A later acceptance therefore fails with an explicit "already accepted" error. Multi-use join
links are a different object — they would need one row per acceptor — and are not this.

**An invite can also be revoked**, via `DELETE /api/invites/:id` (inviter only), which deletes the
`INVITE#` row and the inviter's own `SENT#` row: before acceptance that is the only remedy for a link
sent to the wrong address or known to have leaked, since the TTL is otherwise the only bound and
acceptance replaces it with a completion deadline. Conditional on `attribute_not_exists(InvitedUserID)`
on both rows — deleting them out from under an invitee who has already been told "you're in" (step 2
succeeded; the group key arrives via step 3, not this write) would silently strand them with no
membership and no remaining record anything was ever accepted, so revocation after acceptance is
refused rather than allowed.

**An invite names its group only when the group is public.** `GET /api/invites/:id` and
`GET /api/invites/received` carry `groupName`, the plaintext name, for a public group and omit the
field for a private one: a private group's name is ciphertext under the group key, which the invitee
does not hold until step 3, so the invitee's client shows "a group" there. The unauthenticated read
discloses nothing a public group has not already chosen to make discoverable: public names are
designed to be listed in the directory (#71). A member of the group still sees their
own decrypted label first.

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

**Resolved — `ephemeral_pubkey` is dropped.** It was signed into the step 1 payload in an earlier
draft of this design and never used in steps 2 or 3, which wrap using the inviter's own long-term
X25519 key. Forward secrecy for the group-key wrap is not a property this design states or promises
elsewhere — introducing it here would mean specifying where a browser persists an ephemeral private
key across a session boundary (invite creation to completion, on a future login), which is a real
storage problem with no other need driving it. Rather than carry a signed field with no defined
semantics, the field is removed from the step 1 payload entirely; the three payloads above already
reflect this.

Invite links carry the inviter's key fingerprint AND the per-invite MAC key `k` in the **URL
fragment** (`#<fingerprint>.<k>`, base64url), which browsers never transmit. An invitee's client can
therefore verify the inviter's key against a value the server never saw, and `k` is what the
inviter's own client later checks `invite_mac` against at step 3 — see this section's own three-step
description above for why that check, not the Ed25519 signature alone, is what actually proves step
2 was signed by the real link-holder.

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

**The recipient's membership row is written when they first open the conversation, not when the
sender starts it.** Every other route into a group requires the joiner to act — an invitee signs
their keys at step 2, a requester signs a join request — and a DM has neither, so writing the
recipient's row at send time would let any account manufacture a graph edge about any user it can
name, unsolicited. That matters because of what the threat model says a dump reveals: DM membership
is the pairwise case, the smallest anonymity set and the most to give away, and a dump cannot
distinguish "these two corresponded" from "a stranger opened a DM at this person who never replied".
Anyone reading it draws the first conclusion. It is also a caller-chosen write into another user's
partition, which is the shape the single-slot challenge argument rejects one section earlier.

Deferring the row costs nothing structurally: the group and the sender's own row exist immediately,
the message is stored, and delivery works — it is the same membership item written at a different
moment, so the one-codepath property is untouched. Until then the recipient sees the conversation
through their notifications rather than their group list. Note this matters more than blocking does,
because blocking is a UI state with no key consequence: a blocked correspondent's membership row and
its GSI1 entry would persist, so the graph edge would outlive the remedy.

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

**The chain's anchor is stored, not inferred.** `META` records the **creator's uuid and the Ed25519
public key that was current at group creation**, and a walk terminates by checking that the root
grant is self-signed by that key. Without a stored anchor the walk cannot terminate soundly, because
both available answers are wrong: "no predecessor means this is the creator" lets a malicious
operator invent a keypair, self-sign a grant making it Admin, and issue a grant to a confederate —
every signature real, the chain rooted at an identity the attacker chose — while "no predecessor
means reject" rejects the genuine creator too, since their own grant has no predecessor either.
Pinning the **key** as well as the uuid matters because of the superseded-key retention above: a
creator who later rotates has several keys, all served from a projection the server controls, so
anchoring on the uuid alone would still let the server choose which key was "current" at the root.

**The anchor is signed by the creator at group creation**, and clients verify that signature before
trusting it. `META` is a server-served item like any other, so an unsigned creator field would move
the operator's freedom rather than remove it — from nominating a root at verification time to
rewriting one attribute. That is a real improvement, since members can cache and compare `META`,
but it is not the property this section claims. A creator-signed anchor is, and it costs one
signature written once per group. This is the same reasoning `PIN#` gets: a record the server both
serves and could rewrite protects nothing unless the client checks a signature over it.

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

**Leaving appends a demotion.** An admin or ambassador who leaves a group that survives signs a
grant to `member` with themselves as both grantor and subject, and the server writes it in the same
transaction that deletes their membership. Without it a departed admin's last grant would still say
`admin`, and a later rejoin by invite (baseline `member`, no grant) would read as a forged demotion.
A self-grant is the one exception to "signed by an admin": lowering your own role needs no one's
authority and raises no one's standing, so the verifier accepts it only to `member`, only from a
signer whose current grant (strictly earlier day, verified) was elevated, and only under a key they
held that day. It takes effect the next day, so an admin who promotes a successor and leaves the
same day does not invalidate that promotion under the strict same-day rule. Two gaps stay: a group
left before this shipped has no demotion, and an admin promoted and leaving on the *same* day has an
unverifiable one (the order within a day is unknowable), so both show as unverified on rejoin. Both
fail safe: a flag, never a false "verified". Involuntary departure needs someone else's signature.

**Leaving a private Rotating group re-keys it (#178).** A leaver who kept the current key would go on
reading everything posted until the next removal, and a server colluding with them could re-list them so
that a later rotation wraps to them. So a leave in such a group (other members remaining; the only
member's leave deletes the group) also starts a rotation, in the same transaction as the delete and the
demotion. What it writes is **only the `ROTATION` marker**, carrying the same `RotationStartPayload`
signature a remover makes, naming the leaver **themselves** as the removed member.

**The leaver never mints, wraps or sends a key.** A key the leaver generated is a key a hostile leaver
keeps (a patched client logs it before wrapping it to anyone), and every later post would then be readable
by them: the rotation would cut off only an honest leaver. Anything the server accepted from a leaver to
put over an admin's entry would also be unverifiable, since the server cannot read wraps and a leaver is
the party we trust least at the moment they hand them over. So the leave carries none: no new key, no
`GENKEY#` link, no holder wraps, and no admin's entry is touched. The marker (`startedBy == removedUserId`,
which the start signature proves) blocks every other rotation, so nobody can be wrapped to a re-listed
leaver before the admin's link exists.

**An admin takes the marker over and mints the key, but only for a leaver whose key it has a reason to
trust.** The first admin whose entry is at the leaver's generation to load the group (`takeOverLeave`)
verifies the marker's start signature. That is not enough on its own: the leaver's key is whatever the
server serves, and the takeover is the one path where the admin's client turns a marker into **its own
new signature** naming that member as removed. A removal's marker is harmless on first sight (resuming
needs an entry at the marker's generation, which the server cannot forge, and signs nothing new). Here a
server could drop an unpinned member, serve a key it made under their id, write a marker signed with it,
and get an admin to sign that member into the verified removal history. So before taking over the admin
requires one of: the leaver's served keys match the admin's **pin** of them; the leaver is the group's
**creator** and the served key is the one the verified anchor names; or the leaver has an **admission**
that verifies against the grant chain for the keys served now (`isAdmitted`, the same check a rotation
applies to a recipient, so someone removed earlier and re-invited after the removal still counts; a
creator the removal history lists needs such an admission too). Otherwise it takes nothing over and says why. A server that withholds a member
can already stall a group, so failing closed costs nothing new. This is why a leave that starts a rotation
**keeps the leaver's `ADMISSION#` row** and the takeover deletes it in its transaction (a plain leave in
an Open group still deletes it at once). Having decided to take over, the admin does what a remover does: mints the next key, writes the `GENKEY#n` link under their **own** signature naming the
leaver, and moves their own entry point (`POST /rotation/takeover`, one transaction). It replaces the
marker (conditioned on it still being an unclaimed leaver's, at the next generation) and writes the link
(conditioned on it not existing: a generation is minted once). It then re-wraps everyone else through the
ordinary rotation path. Two admins racing settle on the marker condition: the loser is refused
(`rotation_not_active`), re-reads, and is re-wrapped by the winner like any member. The removal history
covers the leaver through the admin-signed link, as it already does after any removal, so a leaver
re-listed later with their old admission is refused exactly as a removed member is.

A leave is refused, changing nothing, when a rotation is already running (`rotation_in_progress`) or the
group cannot be read. Open groups, public groups and DMs hold no key to rotate and are unchanged. Posts
made between the leave and the takeover are still on generation n, which the leaver holds, exactly as
posts made between a removal and its re-wrap are; the rotation closes that window for everything after
it.

**Removal is signed by the remover.** `DELETE /api/groups/{gid}/members/{uid}` is Admin-only, and
for an admin or ambassador subject the request carries the remover's signed grant of `member` to
them, appended in the same transaction that deletes the membership. That is an ordinary admin
grant, so the demotion itself needs no new rule, and it needs nothing from the removed admin, which
is the property an involuntary departure cannot have otherwise. An admin cannot remove themselves,
so the admin who removes someone is always still there: removal never leaves a group without an
admin, and the successor problem (#161) is left only with account deletion (#77) and inactivity,
where no remaining admin is acting. In an **Open** group that is the whole of removal. In a
**Rotating** group the same transaction also starts the rotation: the request carries the new
generation (exactly one past the remover's own entry point), the `GENKEY#` link wrapping the old
generation's key under the new one, the new key wrapped for the remover, and the remover's signed
rotation start naming the removed member (see "The recipient set is taken from the server"). The transaction
writes the delete, the `ROTATION` marker, that link and the remover's re-wrap together, so no
membership can ever point at a generation whose chain link is missing, and the remover, whose
browser minted the key, durably holds the one copy a resumed rotation must re-use. Only one rotation
runs at a time: the marker and the link are both `attribute_not_exists` writes, so a removal while
one is in progress is refused (`rotation_in_progress`, 409) and changes nothing. Re-wrapping every
other member is the client's resumable job, not part of this request.

**Account deletion is a leave in every group, then a tombstone.** `DELETE /api/account` refuses with
409 `still_member` while the account holds any membership. The client leaves each group first, which
is the existing leave: an admin or ambassador signs their own demotion, and the last admin of a group
that survives is refused until they promote a successor. That answers "who signs the demotion" for
this case: the departing user does, so deletion needs no one else's signature and never chooses a
successor. Once no membership remains, one transaction tombstones `PROFILE` (`DeletedAt` set; username,
salt, wrapped private keys, preferences and lock state removed; the public keys stay so grants and
signatures the user made still verify), deletes the `USERNAME#` claim (the name is free again) and
deletes `RECOVERY`. Pins, the login challenge, invites they sent and invites addressed to them are
swept afterwards, and a repeated call finishes any leftovers. `PROFILE` is never deleted, so the uuid
cannot be re-registered (see the AAD table). `GET /api/users/{id}` serves a tombstone with `deleted:
true` and an empty username, which the web client shows as "deleted user" (id in the tooltip) in
rosters, invites and the leave panel. `CompleteInvite` refuses a deleted invitee. Two gaps, both fail safe: a
membership completed between the membership check and the tombstone survives, visible to the group
as a member whose profile is deleted, and an admin removes it with the ordinary removal flow (a role
change that would *elevate* such a member is refused, 410 `subject_deleted`, so a sole admin cannot
hand the group to a tombstone; demoting one is allowed, and the web client offers a deleted member
only Make member and Remove, and never as a successor). A deleted admin does not count as another
admin when an admin leaves: the server looks up the other admins' PROFILE rows, picks a live one, and
conditions the leave on that account still being live, otherwise `last_admin`; and a
session cookie issued earlier stays valid until it expires or its user logs out, though the handlers that check refuse it with 410 `account_deleted`. It cannot
create a membership, because `CreateGroup` and `CompleteInvite`, the only writers of a `MEMBER#`
row, both refuse a deleted account, and a password change from it fails because `RECOVERY` is gone;
anything else it writes, such as pins, lands on a partition nobody can sign in to. Content other members already decrypted cannot be recalled.

**Inactivity: the admin pre-signs a successor (#161, UI built).** An inactive admin who is
not the last admin needs nothing. An inactive *last* admin leaves a group nobody can govern, and no
remaining admin is acting, so the signature has to exist before the admin goes quiet. Co-signing by
the highest remaining role was rejected: it makes a non-admin signature create an admin, a second
root of authority beside the creator-rooted chain, and in a small group a quorum of one or two can
replace an admin who is only away.

- **The designation.** While active, an admin signs `SuccessorDesignation` (new signing context,
  length-prefixed like `RoleGrantPayload`): group id, admin uuid, successor uuid, `periodDays`, the
  row's own sort key `DESIGNATION#<admin uuid>#<YYYY-MM-DD>#<rand>`, and the admin's current grant
  ref. It is appended, never overwritten; the newest by day wins, and one naming no successor (empty
  uuid) revokes. Order within a day is unknowable, so two designations by one admin on one day cancel
  each other (the admin designates again the next day), and the server refuses a second designation
  from one admin on the same day, as it does `grantor_granted_today`. `periodDays` is the admin's
  choice within 30 to 365, and the UI suggests 90. It is signed under a key the admin held that day
  and needs the admin to hold admin that day, checked exactly as a grant is.
- **Activity** means the last successful login, kept as `PROFILE.LastLoginDay` (day resolution, one
  conditional write per day at login, so nothing on the request hot path). Sessions last 24 hours by
  default, so an active admin logs in at least daily and this tracks real use. The gate assumes
  sessions much shorter than the smallest period (30 days), so `SESSION_TTL_HOURS` is capped at 168
  hours (7 days, `config.MaxSessionTTL`): a larger value is lowered to the cap with a warning, and
  Terraform refuses one. Without a cap, an admin using the board daily on a month-long session would
  stamp only once a month and look inactive. It is a server attestation, used only by the server's
  own claim check below; a client never verifies it. A `PROFILE` with no `LastLoginDay` (every row
  from before this ships) simply loses to the designation's day in the rule below.
- **The successor signs the claim.** The successor's browser calls `POST
  /api/groups/{gid}/designation/claim`, signing a new `SuccessorClaim` payload (own signing context,
  length-prefixed, in the pattern of `RoleGrantPayload`): group id, successor uuid, the designation's
  sort key, and the claim row's own sort key `GRANT#<successor>#<YYYY-MM-DD>#<rand>`. The claim day
  is therefore signed by the honest party, not picked by the server, and a signature copied to another
  row or day does not verify.
- **The row.** The server appends an ordinary `GRANT#` row for the successor: role `admin`;
  `grantorUserId` the designating admin; `grantorGrantRef` the admin's grant ref as signed in the
  designation; `viaDesignation` the designation's sort key (the field that tells a verifier to use
  this section's rule instead of the ordinary grant rule); `signature` the successor's claim
  signature. Clients that do not know `viaDesignation` must not treat the row as an ordinary grant,
  so the claim endpoint ships with the verifier rule, never before it.
- **Server claim checks** (the server's own honest-path gate; the verifier does not rely on them
  except where stated below). All must hold: the designation is the admin's newest and not a
  revocation; the admin's *current* grant is exactly the ref the designation signed (one check that
  covers the admin leaving, being removed or demoted, and being re-promoted later: a re-promotion is
  a new grant, so the old designation does not return); the successor is a live member and the
  designation day is on or after their `MEMBER#` `CreatedAt` (so a removed successor who rejoins by
  invite does not inherit it); no earlier activation row cites this designation (each designation
  fires at most once, so an admin who returns and demotes the successor is not re-promoted by it);
  the admin has been inactive for `periodDays`, and no other admin has logged in within that period.
  The second condition makes it fire for an abandoned group, not because one of two admins is away.
  Inactivity is measured from the later of the admin's `LastLoginDay` and the designation's day, to
  the claim's signed day, for both conditions.
  - *Why from the later day.* A session lasts 24 hours, so the last login can fall the day before the
    designation. Measuring from the later day makes this gate imply the verifier's floor, so an
    honest claim is never rejected and, because it fires at most once, never stuck.
  - *Why to the signed day, not the server's today.* The server accepts a client-dated claim up to
    `grantDaySkewTolerance` behind its clock, as for every client-dated grant, so a slow clock or a
    request that crosses midnight can sign yesterday. A gate measured to the server's today would
    pass a claim the verifier's floor rejects, for good.
- **What the verifier checks.** The designation's signature and the admin's right to sign it, by the
  same chain walk as any grant; the successor's claim signature under a key they held on the claim
  day; that the row's role is `admin` (the claim payload does not sign a role, and a designation can
  only confer admin, so the verifier requires `grantedRole === 'admin'` on a `viaDesignation` row
  and `checkMemberRole` must not believe any other); that the designation names this subject; that
  no other `GRANT#` row cites the same `viaDesignation` (if more than one does, all of them are
  rejected, the way `compute()` poisons a duplicate sort key, so a returning admin's demotion cannot
  be undone by a second claim from a cooperating server and successor); the floor `claimDay -
  designationDay >= periodDays` (signing the designation shows the admin was active on that day, so
  an honest claim never trips it, and a server cannot fire early); and the lapse check: reject if
  the admin has any *other* designation, or any grant *to them* (a role change of theirs, not one
  they signed), dated **on or after** the designation's day and on or before the claim day. "On or
  after" is deliberate: a same-day revocation or self-demotion cannot be ordered against the
  designation, so it must cancel it rather than be skipped. That makes revocation, demotion, removal
  and replacement bind the server too, not only the honest path. The server's claim check uses the
  same rule.
- **Same-day behavior.** A grant takes effect the day after it is dated, so the successor can grant
  roles from the day after the claim; the server refuses earlier attempts (`grantor_granted_today`),
  as for any new admin, and the claim screen should say so.
- **What this trusts the server for, and what it does not.** The server alone cannot choose the
  successor, cannot claim before `periodDays` have passed since the designation, and cannot use a
  designation the admin revoked, replaced or lost admin under before the claim day. A successor who
  cooperates with the server can postdate the claim, because the verifier has no clock and checks
  the signed day; the admin undoes that by revoking or re-designating before that day, since the
  lapse window runs up to it, and a viewer's grant check, which does have a clock, rejects a claim
  row dated more than two hours ahead of the viewer's now (`CLAIM_DAY_SKEW_TOLERANCE_MS`, the same
  slack the server allows a fast clock, so an honest claim is not false-flagged; `checkGrants`
  passes `Date.now()`, and the verifier does nothing when given no clock). What is left is omission:
  a server that hides a revocation row from everyone can still serve a stale designation, which the
  existing grant history is equally exposed to. The login clock is the server's, but only the
  honest-path check uses it, so a lying clock alone can withhold a legitimate claim, not forge one.
  The claim screen should re-check eligibility against the day it is about to sign.
- **Lapses.** The designation stops applying without notice to the successor when any claim check
  above fails. Nothing re-nominates for the admin, so they have to maintain it; the group screen
  should say when an admin has none and when theirs has lapsed.
- **After activation** the original admin is still an admin if they return; nothing is revoked.
  Ordinary role changes and removal govern from there.
- **What exists** (step 1b): `PUT /api/groups/{gid}/designation` (admin only) appends a signed
  `DESIGNATION#` row, or a revocation when `successorUserId` is empty; `GET
  /api/groups/{gid}/designations` (members only, paged like grants) serves the rows and verifies
  nothing. The PUT refuses: a period outside 30 to 365; yourself, a non-member, or a deleted account
  as successor; a stale `adminGrantRef` (`grantor_ref_stale`); an admin grant dated the same day or
  later (`grantor_granted_today`, the verifier's strict rule); a second designation by the same
  admin the same day (`designation_today`, a read before the write, so two concurrent requests can
  both pass, which is harmless because the verifier cancels a same-day pair); a sort key not within
  the usual client-day tolerance; and a signature that does not verify under the admin's current key
  and `successor-designation:v1`. The row stores no signing key, since nothing signed binds one. A
  revocation still carries a `periodDays` in range, which is signed and stored but ignored. A
  successful login stamps `PROFILE.LastLoginDay` (one conditional write per day; a login fails if
  the stamp fails, because a missed stamp would make an active admin look inactive). Account
  deletion removes `LastLoginDay` with the rest of what a tombstone does not need.
- **What exists** (step 2): `POST /api/groups/{gid}/designation/claim`, called by the successor with
  `{designationSortKey, claimSortKey, signature}`. The caller must be a member and not already an
  admin (`already_admin`); the claim sort key must be a well-formed `GRANT#` key for the caller
  dated within the usual client-day tolerance, and the signature must verify under the caller's
  current key and `successor-claim:v1`. It then refuses, each with its own code: no such designation
  (404 `designation_not_found`); one that does not name the caller, which includes a revocation
  (`designation_not_yours`); another designation by the admin dated from this one's day through the
  claim day (`designation_superseded`); any grant to the admin in that window
  (`designation_lapsed`); an earlier row citing it (`already_claimed`); the admin no longer an admin
  or no longer on the grant it was signed against (`admin_changed`); a designation dated before the
  caller's `MEMBER#` `CreatedAt` (`designation_before_join`); and an admin, the designating one or
  any other, not inactive for `periodDays` (`not_inactive`). Inactivity is `claimDay -
  max(LastLoginDay, designationDay) >= periodDays`, with the claim day being the one in the signed
  sort key. One transaction then appends the `GRANT#` row (`ViaDesignation`, the successor's
  signature, `GrantorUserID` the admin) and sets the successor's `MEMBER#` role and `GrantSortKey`;
  it checks the admin is still an admin on the signed grant, the successor still holds the role the
  claim was checked against (which is what makes two concurrent claims safe: the second finds the
  role changed), and the successor's account is not deleted. The designation rows themselves are
  read before the transaction, so a revocation written in between does not stop the claim; the
  verifier's lapse rule is what still voids it. `GET /grants` serves `viaDesignation`. The web grant
  check fetches every designation page and the successor's key, and `verifyGrantChain` takes
  `designations` and `now`; a claim row whose designation is not served is unverified.
- **What exists** (step 3): the screen at `/groups/:groupId/successor`, linked from the members
  screen, which every member can open. An admin sees their standing designation or why they have
  none (never designated; revoked; two on one day cancelled; claimed already; the successor is no
  longer a member; lapsed because a grant to them is dated on or after the designation's day) and
  can designate a member (not themselves or a deleted account) with a period defaulting to 90
  inside 30 to 365, replace, or revoke; each signs `SuccessorDesignation` in the worker against
  the admin's own current grant and calls `PUT /designation`, re-signing once on
  `designation_key_taken`. A member a designation names sees when the period elapses and, from
  then, a two-step Claim: it reloads the group, checks eligibility against today's UTC day, signs
  `SuccessorClaim` in the worker, checks again against the day in the signed claim key (the worker
  dates it from its own clock, which may have crossed midnight), and only then calls `POST
  /designation/claim`. The confirm step says they can grant roles from the day after the claim
  (the server refuses earlier, `grantor_granted_today`). The client rules
  (`lib/groups/designation.ts`) mirror the verifier's: newest designation of the admin, no second
  one on its day, no grant to the admin from its day through the claim day, not already cited, the
  admin still an admin, `claimDay - designationDay >= periodDays`. They are advisory: they cannot
  see last-login days, so the server's `not_inactive` is shown as its own message, and nothing
  here verifies a signature.
- **Build order**: (1a) both payloads and contexts in Go and TS with vectors (pure builders, so
  shipping them early is harmless: nothing emits a claim row yet); (1b) `DESIGNATION#` rows, PUT/GET
  and `LastLoginDay`; (2) the claim endpoint and the verifier rule in `grant-chain.ts` together, in
  one PR, because a claim row reaching a client without the rule shows as unverified and so does
  every grant the successor signs after it (built, with the `SESSION_TTL_HOURS` cap); (3) the admin
  UI to designate, revoke and see status, and the successor claim screen (built).

**Finishing a rotation.** `GET /api/groups/{gid}` shows members the marker (`rotation`: generation,
`startedAt`, `startedBy`, and `removedUserId` with `startSignature`, below). `PUT /api/groups/{gid}/rotation/members` moves up to 25 members' entry
points to the marker's generation in one transaction, so there is no `UnprocessedItems` to chase: the
marker still names the generation, the caller is an admin whose own entry point is at it (the only
way to hold the key), and every member exists and is not already past it, or nothing is written
(`member_changed`, and the client re-lists and resends). During a rotation, a member already *at* the
generation is accepted, which makes a retry after a lost response safe. `POST /api/groups/{gid}/rotation/takeover`
is the admin's move for a rotation a leaver started (see "Leaving a private Rotating group").
`POST /api/groups/{gid}/rotation/complete`
deletes the marker only when no member is behind (`members_behind`), not counting dormant members
(`WrapEpoch < KeyEpoch`), which reach a new generation only through the explicit approval. The scan is a consistent read
but is not atomic with the delete, and an invite completed by an inviter who was re-wrapped
mid-request could land a member one generation behind (the `CompleteInvite` transaction conditions
on the inviter's generation, which closes that), so a behind member after completion is unlikely but
possible. They are moved by the same re-wrap call with **no marker present**, as a catch-up. The
server reads the marker first and picks the mode: with a marker, members at or behind its generation
are accepted (a retry of a member already moved is safe); with none, **only members strictly behind
the caller's generation are moved**, so no admin can replace the key of a member already at the
current generation in a group that never rotated, and a retry of a catch-up gets `member_changed`
once the member is no longer behind. The caller's own entry point pins the generation, so an admin
can only bring a member up to the admin's own current key, and nobody is moved backward. An admin
client compares members' generations to its own on load to find them. A client should
re-wrap only members who are **behind** (the retry allowance above is for a lost response, not a
way to refresh keys), because a wrong key written over an admin already at the generation would lock
out exactly the admins able to resume. A client
resuming a rotation should re-wrap the **other admins first**: only an admin already at the new
generation can resume, and only the initiator is until someone else is re-wrapped.

**The client job fails closed on pins.** Re-wrapping hands a member the new group key, so a
server-substituted X25519 key for that member would hand the server the key and defeat the rotation.
Before wrapping to anyone the job checks their served keys against the caller's signed pin: a match
is wrapped to; a first sighting is pinned (trust on first use, as the roster does) and wrapped to; a
mismatch or bad signature is skipped, reported, never wrapped to and never re-pinned over, and the
rotation is left unfinished (`members_behind`) until a person resolves it. A dormant member is the
exception that does not stall: it is excluded from the recipient set and from `members_behind` (see
"Dormant memberships"). A member whose keys changed with an approval by another admin is reported as
"approved elsewhere; accept to continue" and still waits for that admin to accept (see "Other admins
after an approval"), and a `bad-signature` pin waits for "reset saved key" (see "What a key change
looks like to others"). An unreadable pin set, or
keys that cannot be fetched, stops the run rather than wrapping unchecked. This differs from the
roster's grant check, which can show a mark while "unchecked": there the worst case is a missing
badge, here it is a leaked key. The job re-lists members each pass (state, not a cursor), re-wraps
only those behind, and runs the same way as a catch-up when no rotation is running.

**The recipient set is taken from the server, and only part of that is closed.** The pin check
covers each recipient's *key*, not *who* the recipients are: the list of members to re-wrap comes
from `listAllMembers`. Two attacks follow from a dishonest server, and they are different.

*Keeping a removed member listed* is closed for a rotation that a signed removal started. The
removal request carries a second signature, the remover's over `RotationStartPayload` (group,
remover, **removed subject**, generation rotated to, signed under its own
`underground-bb:rotation-start:v1` context), which the server verifies against the remover's key and
stores on the `ROTATION` marker as `removedUserId` and `startSignature`. A resuming admin verifies it
against the starter's keys (checked against the resumer's own pin of the starter), adds the named
member to the exclusion set whatever the member list says, and **stops, wrapping to no one,** if the
record is missing, malformed or does not verify. A marker written before this shipped has no record
and so cannot be resumed from the client; that is a deliberate fail-closed choice, not an oversight.
The signature can only *shrink* the recipient set, so a lying server gains nothing by forging one
and loses nothing by omitting a member it should have named: the worst it can make a client do is
refuse to finish. A rotation still cannot complete while the server insists the excluded member is
behind, which fails safe.

**Deploy note.** There is no client path to adopt or clear a marker that lacks the record, and no
abort endpoint: while a marker exists, removals and group edits are refused and new posts stay on the
old generation. Before deploying a build that requires the record, confirm no `ROTATION` item exists
in the table (`Scan` with `begins_with(SK, "ROTATION")`), or finish those rotations first with the old
client. A browser still on the old bundle sends a Rotating-group removal without `startSignature` and
gets 400 `bad_signature`; reloading fixes it. If a legacy marker is ever stranded, the remedy is
operator-side, because the remover cannot re-sign after the fact.

*Listing an account it made up* is closed by the admission record (see the invite ceremony above).
Before a recipient is pinned or wrapped to, the job checks that the inviter's signed admission of
them verifies (`verifyAdmission`, `lib/crypto/admission.ts`): the record's keys are the ones the
server serves for that member now; the signature verifies under a key the inviter held on the
record's day; the grant it names is the inviter's, verified in the chain, admin or ambassador; and
the inviter has **no other grant dated from that grant's day through the record's day**, the same
fail-closed treatment of same-day changes as the grant chain (a creator who makes a group and
invites on day one is fine, since their one grant is the one named; a demotion dated *after* the
admission does not undo it). The creator is the one member with no record, exempt only against an
anchor the caller trusts. The check runs *before* the pin check, so an account nobody admitted is
never pinned either. A recipient that fails is skipped and reported (`unadmitted`), never wrapped
to, and the rotation does not complete. A chain that cannot be read, a changed anchor or an
unverifiable root stops the run and wraps to no one. There is no legacy path: a member without a
record cannot receive a rotated key. This shipped while no members existed, so there are none
to vouch for; a group whose members predate it would need a re-admission flow first.

*Re-listing a removed member* is closed by the removal history. The marker's record is deleted when
its rotation finishes, so the same signed record (`removerUserId`, `removedUserId`, `startSignature`)
is also written on the durable `GENKEY#<n>` link the removal creates, in the same transaction, and
served by the keychain endpoint. Links are contiguous, one per generation, so a verifier that holds
generation G requires a verifying record for **every** n < G: a withheld, blanked, forged or replayed
one is a gap and **stops the run, wrapping to no one**, instead of passing as "nobody was ever
removed". The caller's own generation cannot be understated to hide the newest removals, because it
is authenticated by the AAD of its own wrapped key. That is what makes this different from
withholding an admission, which only ever shrinks who is wrapped to: omitting a removal would grow
it, so removals are bound to the chain and admissions are not.

The admission now signs the group-key generation the inviter held (the one the new member's key is
wrapped under; the server already requires it to equal the inviter's own). A member removed at
generation g is only a valid recipient again if their admission was signed at generation g or later:
generation g's key exists only after the removal, so such an admission is a fresh invitation. Their
old admission still verifies on everything else, which is exactly why it is rejected on this rule.
The creator is exempt only while nobody has removed them. The removers' keys come from the server and
are checked against the caller's pin like the marker's starter; a first sighting is accepted because a
forged record can only exclude someone.

*Re-admitting a member.* An admission can stop verifying through no fault of the member: the inviter's
keys can no longer be read, or another grant to the inviter is dated from the ref grant's day through the
admission's day (the verifier rejects the record then). That happens two ways: their role changed later on the
admission's own day, which breaks a record that was valid when stored, or, when it is signed, their current
grant already shares a day with an earlier one, which lasts until their role changes again and which the
server now refuses at signing time. Every rotation then
pauses on that member (`unadmitted`). `POST /api/groups/{gid}/members/{uid}/readmit` lets a current admin or
ambassador replace the record with a fresh one: the same `AdmissionPayload`, signed over the member's
**current** keys, with a client-chosen UUID in the invite slot (there is no invite; nothing looks it up).
The server checks what it can read: the caller holds the role, generation and grant they signed (the
transaction re-checks all three), the signature verifies over the keys the server stores for the member and
under the caller's current key, the day is held to a grant's clock tolerance and is not before the caller's own grant day, and no other grant to the caller
is dated from the ref grant's day through the admission's day (`grantor_role_changed_same_day`). Both are
the verifier's rules, and a record that fails them would replace a working one with one no client accepts;
`completeInvite` applies the same two checks, through one helper), the member still exists with
an account that is not deleted, and the caller is not re-admitting themselves. A running rotation does
**not** block it, because a rotation paused on an unadmitted member is exactly when it is needed. The
server cannot tell *who* is safe to re-admit: a member a removal named looks the same as one whose inviter
was lost, and re-admitting a removed member at the current generation would satisfy the generation rule and
re-list them. So that decision is the client's, which holds the verified removal history and never offers a
re-admission for anyone in it; those return only through a fresh invitation.

*The re-admission flow in the web app.* The Members page offers **Re-admit** on a member a rotation run
named `unadmitted` and the verified removal history does not name (the run reports these separately, as
`readmittable`). Offering is a convenience; every step re-reads and re-checks, so a stale roster decides
nothing. Starting it checks: the caller's role and grant; the member's served keys against the caller's
pin (a mismatch blocks; a pin that cannot be read stops it); the admission and removal history (one that
cannot be read or verified stops it, because carrying on would take the server's word that nobody was
removed); that the member is **not** in the removal history; and that their admission does not already
verify, because the server's overwrite is unconditional and a working record is never replaced. Only then
does it show the fingerprint of the keys the server serves for them now. The confirmation is required
every time, with no remembered answer: it is the control that stops an admin vouching for an account the
server invented, which also has no invitation behind it and so is also `readmittable`. On confirmation
everything is checked again, the signature is made only if freshly served keys still give the confirmed
fingerprint, a first-sight member's keys are pinned first (so the rotation that follows checks the same keys
the signature covers), the record is sent, and the paused rotation is re-run under the same lock. Any member can read their own
fingerprint under "Your key fingerprint" on the Members page (computed from their live keys in the worker,
not from anything the server serves), which is what the admin compares against, so the check does not
depend on the member being able to create an invite. Limits: the member must be logged in with live keys
to see it (after a page reload they log in again); and only an admin runs the rotation that names whom to
offer, so an ambassador would need a check of their own before the button could appear for them.

*What stays open.* (1) **Omission.** The server can withhold the marker, or a removal that never
started a rotation (an Open group has none, so there is no key to withhold and no chain link to
carry a record), and nothing binds the set of signed records, the same gap the grant history and
pins already accept; withholding an admission only ever shrinks who is wrapped to. Removals in a
Rotating group are the exception: see "Re-listing a removed member" above. (2) **A backdated admission.** The record's day is the inviter's own claim (the server
holds it to its clock when it writes, but a verifier has no clock), so a server colluding with an
inviter who has since been demoted can store an admission dated before the demotion, the same gap the
grant chain accepts for a postdated grant. (3) **A backdated generation.** The admission's generation is the inviter's own claim, like its day:
a server colluding with an inviter who still holds the key can store a record that claims a
generation above a removal it post-dates. It needs a live inviter's cooperation, the same gap as (2).
(4) **Trust on first use.** The creator is exempt only against an anchor the caller trusts, and a
first sighting counts as trusted, as in the roster: the anchor pin is per-browser localStorage, so on a
browser that has never seen this group the server can serve an invented creator, a chain that creator
signed, and matching admissions, and the check passes. Failing closed on first sight would not help,
because opening the members screen first takes the same pin. (5) **Key rotation (#62).** The
invitee's Ed25519 key is matched against current and superseded keys, but the X25519 key must equal the
current served wrapping key, so a member who rotates would be unadmitted in every group until
re-invited. With rotation the check **follows the `KEYCHANGE#` chain**: an admission naming keys
that a verified chain of rotations carries to the served ones is accepted. The chain proves the
served keys were introduced by a holder of the admitted ones, which is what an admission attests to
about the invitee; it does not make the member readable (that is the dormant re-wrap) or grant
anything the admission did not. **As built (slice 5):** the check fetches the invitee's chain
(`GET /api/users/{id}`) only when the admitted wrapping key is not the served one, and builds it
as the caller's own is built (`buildOwnKeyHistory`: every link signed by both keys it names,
epochs 1..n, each link's old signing and wrapping keys the previous link's new ones, ending at the
served signing key). The admitted signing and wrapping keys must be one link's old pair, the last
link must end at the served wrapping key, and the record's day must fall from the day the pair was
introduced to the day of the rotation that replaced it (both keys are candidates on that day). No
chain, or one that does not verify, reads as unadmitted; a failed read stops the run with its reason
(re-admit reports it unchecked) rather than offering Re-admit. A leaver's signed start is accepted
under the admitted key or any key the chain carried it to. The pin check still runs afterwards,
so a rotated member stays blocked until their key change is approved; what changes is that they no
longer show as unadmitted with a Re-admit button. (6) **Liveness.** An inviter whose keys can no longer be
read, or who has another grant dated from the ref grant's day through an admission's day (their role changed
later on that admission's own day, or their current grant shares a day with an earlier one), leaves their
invitees unadmitted until an
admin re-admits them (above). The server refuses to store an admission its own caller's grants would make
unverifiable, so an admin or ambassador in that state cannot re-admit anyone until their role changes again;
another admin can. A member removed earlier is not repaired this way and needs a fresh invitation.
(7) **A stalled leave rotation.** A leave's rotation is taken over and finished by an admin at the
leaver's generation, on their next load. If none returns, the group's new posts stay on the old generation
and the other members stay behind until one does, the same stall a removal has when its remover
disappears. Unlike a design where the leaver picks who can resume, any admin at the generation can, so a
leaver cannot stall the group by naming only an inactive one.

**Deploy note (leave rotation).** A browser still on an older bundle leaves a Rotating group without a
rotation and gets 400 `rotation_required`; reloading fixes it. No stored data changes.

**Deploy note (removal history).** A `GENKEY#` link written before this shipped has no record, so a
group that has already rotated can never pass the check and its rotations stop. Reset or recreate
any such group, together with the admission note below. A remover whose account was deleted, or whose
keys the server will not serve, also stops the check for as long as their link exists (the same
liveness cost the marker's own record has); there is no way around it that a lying server could not
use too. An admission signed before the generation was added does not verify, for the same reason.

**Deploy note (admission).** Reset or recreate any group whose members joined before this shipped;
they have no record and would be skipped at the next rotation.

**One cost, deliberate:** the same-day exemption above is for *self*-demotion only. A removed
admin's grants dated the **same UTC day as the removal** are therefore flagged unverified, honest
ones included, and so is the member they promoted, until a later grant re-establishes them. (A
no-op re-grant of the same role is refused, so that means demoting and re-promoting.) The order
within a day is unknowable, and exempting a demotion signed by someone else would let a server that
colludes with the removed admin store a grant signed *after* the removal and have it verify, which
is the one thing removal is for. It fails safe: a flag, never a false "verified". The mirror case,
an admin promoted and removed on the same day, leaves an ambiguous latest grant on rejoin, the same
gap leaving already has. Both are pinned in `grant-chain.test.ts`.

**The worse case is refused, not stored.** The verifier needs the *remover's own* grant to be dated
strictly earlier than the demotion they sign. If it is dated the same UTC day or later, the
remover's grant is flagged by the same rule, so the removal grant and everything the remover signs
afterwards fail with it. Honest admins reach this: a creator removing an admin on the day the group
was made, an admin promoted this morning removing someone this afternoon, or an admin promoted just
after 00:00 UTC whose slow client dates the removal for the day before (the grant-day tolerance is
now-26h to now+2h). When the removed admin was the creator, nobody is left who could re-grant the
remover, so the chain under them stays unverified permanently. The server already holds the
remover's current grant, so it answers 409 `remover_granted_today` ("try again after 00:00 UTC")
instead of storing a write that can never verify. This applies to removing an **admin or
ambassador** only, since removing a plain member signs nothing. Role changes get the same refusal
(`PUT /api/groups/{gid}/members/{uid}/role`, 409 `grantor_granted_today`, #167): a grant signed on
the day the grantor was granted, or before it, is stored but can never verify, and neither can
anything the grantee signs later. Leaving is exempt, since a self-demotion takes effect the next day.
The cost is a delay of up to a day on promoting, or removing, an elevated member for an admin whose
own grant is that new, including the creator of a group made today. One gap stays: the server checks only the grantor's *current* grant, while the verifier
rejects on *any* grant the grantor holds dated the signing day, so a grantor given grant A dated today
and then grant B dated yesterday (skewed clocks, inside the 26h tolerance) can sign a grant that the
server stores and the verifier flags. It needs two grants to one grantor within a day, so it is left
unless the server scans the grantor's grant rows. The verifier
cases that make it necessary are pinned in `grant-chain.test.ts`.

**The server also enforces the table above, as a first line and not a boundary.** The gates that
exist today, each judged from the caller's own `MEMBER#` row: creating an invite needs Admin or
Ambassador; completing one re-checks that the inviter still holds that role; editing group
settings needs Admin (and `UpdateGroupSettings` re-checks it inside its transaction, so a concurrent
demotion cannot slip through); changing a role needs Admin. The refusal shapes differ by endpoint
(invite creation answers a non-member and an under-privileged member both with 403, so it does not
reveal membership; role changes and private-group edits answer a non-member with 404). Removal
(`DELETE .../members/{uid}`) needs Admin too, by the same check. What this buys is catching bugs and casual misuse cheaply, and keeping
a stale or confused client from writing rows the chain would later flag. What it does not buy is
any protection against a malicious client: someone holding the group key can encrypt, sign and
write whatever they like, and the server cannot read a ciphertext to know otherwise. The `MEMBER#`
role is a server-side cache of what the signed chain says, not the chain, so a compromised server
can also hand out or withhold these checks at will. Never treat a passing gate as evidence about
who holds a role: that is the chain's job, verified client-side. `role_enforcement_test.go` pins
invite creation and settings edits per role, and a plain Member's role change; an Ambassador's role
change is pinned in `TestChangeRoleRejections`. Callers are real Members and Ambassadors, not only
non-members.

Note the limit: signed grants prevent the *server* from lying about roles. They do not prevent a
legitimately-privileged member from misusing their authority. Once someone holds the group key and
the right to share it, they are trusted. The chain records who extended trust to whom.

### Revocation mode

Removing a member cannot retroactively revoke what they have already seen — they hold the group key.
Each group therefore chooses a mode **at creation, and may later be converted `Rotating` → `Open`
once and only in that direction**:

- **Rotating** — removal mints a new key generation, wrapped to every remaining member. The removed
  member keeps history but is cut off from new posts. Capped at 1,000 members (matching Signal's
  Sender Keys limit; see below for a second, independent reason that number is the right order of
  magnitude). Adding member 1,001 **fails with an explicit error** explaining that the group
  re-keys on removal and that this is what bounds it. It never silently becomes an `Open` group.
  1,000 is the default of a deployment setting (`MAX_ROTATING_GROUP_MEMBERS`, 2 to 10,000), which the
  group detail reports to the client so the UI never states a number the server does not enforce.
  It is enforced when a member joins (`CompleteInvite`): the join counts the group's `MEMBER#` rows
  with a consistent count, and writes the new membership in a transaction that also bumps a
  `JoinSeq` attribute on the group's `META` item, conditioned on `JoinSeq` being the value it counted
  under. A join that committed in between moved `JoinSeq`, so the later write fails and recounts: the
  cap is exact, with no counter to keep in step across the other paths that delete a `MEMBER#` row
  (leave, removal, takeover). A departure needs no bump because it only lowers the count. Lowering
  the setting never removes anyone; it refuses further joins until the group is under it. Creating
  an invite for a full group is also refused up front, so an invitee does not accept something that
  cannot complete.
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
must therefore re-use the generation key the interrupted one minted rather than issuing a fresh one.

**`BatchWriteItem` is not atomic, and the rotation marker cannot track progress as a position.**
The call returns `UnprocessedItems` — an arbitrary **subset** of the batch, not a prefix — and the
caller must retry those with exponential backoff until it is empty. Partial success is the normal
case rather than an error case, and this design provokes it by construction: a rotation at the
1,000-member cap drives 1,000 writes into the single `GROUP#<gid>` partition, at the per-partition
write ceiling, so the highest-volume loop in the system is the one most likely to be throttled,
exactly when it is under load. A positional cursor encodes "everything before index *k* landed",
which is precisely what the API does not promise: a cursor at member 500 can sit above members in
1–499 whose writes silently failed. The rotation then **reports completion** while those members
still hold an entry point to the previous generation — their client cannot read new content, which
is indistinguishable from "not yet rotated" on their side and invisible on the admin's.

**So resume is driven by state, not by an index.** The membership item already records which
generation its wrapped key is for, so a resumed or verifying pass queries the group's members for
any whose recorded generation is behind the marker's and re-wraps those. That is the same
information the ordering rule above relies on, used to answer a question a cursor cannot.

The other two batched loops — pin re-signing and bulk mark-read — take the same retry rule. It
matters more for pins than it looks: an unprocessed write there leaves a pin signed under a key
about to be discarded, and the interval attribute that lets a later session finish the job only
helps if the loop knows it did not finish. For mark-read the cost is cosmetic; unread badges
reappear.

**A group is one partition key, and that is a second bound on its size.** `GROUP#<gid>` holds seven of
the seventeen item classes — `META`, `ROTATION`, every `MEMBER#`, every `GENKEY#`, every `GRANT#`, every
`DESIGNATION#`, and every `POST#` in the retention window — so essentially all of an active group's traffic lands on one
key, against DynamoDB's roughly 3,000 RCU and 1,000 WCU sustained per-partition-key ceilings. Those
apply per key regardless of table capacity, and adaptive capacity rebalances across partitions
without being able to split a single partition *key*.

This is not a claim the schema is wrong. Collocating a group's items is what makes the membership
gate one `GetItem` and a day's posts one `Query`, and those are bought deliberately. It is worth
stating because the cap is otherwise justified purely by the rotation write burst, which invites the
reading that the cap is removable once rotation moves server-side or becomes incremental. The
partition ceiling would still be there. If a mitigation is ever wanted, the standard one is sharding
the *post* partition (`GROUP#<gid>#<shard>` for `POST#` items only, merged on read) while leaving
`META`, `MEMBER#` and `GENKEY#` collocated — but that trades against the day-boundary pagination
seam, so recording the constraint is worth more for now than choosing a fix.

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

The deadline is one hour from the marker's `startedAt`, checked by the admin's client when it loads
the group (`web/src/routes/rotationStaleness.ts`). A rotation is a few batches of 25 re-wraps, so an
hour is far past a healthy run and short enough that a closed tab is noticed the same day. The load-
time check is a choice: a page left open while a fresh marker crosses the deadline shows nothing
until something reloads it. So is the clock: `startedAt` is stamped by the server but the age is
measured against the browser's clock, so a clock more than an hour slow hides the banner (it fails
quiet), while a fast one shows it early (it fails loud, which is fine). Past the deadline the admin
sees a banner naming who started the rotation and how long ago, but only once this tab's most recent
rotation job (the on-load attempt, or the one a removal runs) has ended, because the advice depends
on how it ended: an admin who does not hold the new key is told to ask one who does; an attempt that
stopped is told that reopening the group tries again; one paused on a pin mismatch is told, in the
banner itself, that a member's keys no longer match the saved copy; one whose own key is already
ahead of the marker is told to reload. The banner never says to keep the page open, since nothing is
running when it shows; the running status says that while a job is. A marker whose timestamp cannot
be parsed counts as stale.

A group can be converted Rotating → Open deliberately. The reverse is not offered: everyone who was
ever a member already holds the old keys, so "upgrading" would imply a guarantee it cannot deliver.

**Conversion lifts the 1,000-member cap, because the cap is a property of the current mode rather
than of the group.** The cap exists for the removal re-wrap burst, which an `Open` group never
performs, so a converted group is uncapped and correctly so — but any code enforcing the cap must
read the mode **at write time**, not at creation. That does not contradict "it never silently becomes
an `Open` group": becoming `Open` is a deliberate act, and it is the cap that follows the mode, not
the mode that follows the member count. Note the capacity argument then rests on the reverse
conversion being unavailable, and that refusal is made on cryptographic grounds rather than capacity
ones — worth knowing before anyone relaxes it.

**Conversion also freezes the generation chain.** No further rotations means no further generations,
while the existing chain stays load-bearing because older content still sits behind it, and
truncation still applies from the old end. So a converted group keeps a chain it can never extend.
That is coherent, but an implementer who assumes `Open` groups have exactly one generation will
write a chain walk that breaks on converted groups.

This is an explicit choice rather than an automatic threshold. A security property should never
change as a side effect of someone adding one more member.

**As built (#61).** `POST /api/groups/{gid}/convert-open`, no body, admin only (403 otherwise, 404 for
a non-member). One transaction: the caller is still an admin at the generation the server read, no
`ROTATION` marker exists, and `META` is still `Rotating`; it sets `RevocationMode` to `open` and bumps
`Version`, so a settings edit loaded before the conversion cannot land after it. Only a settled group
converts. A removal still running is 409 `rotation_in_progress` and a member whose entry is behind the
caller's generation is 409 `members_behind` (a dormant member does not count, as in `CompleteRotation`),
because Open never completes a marker and the removed member's cut-off would silently never happen. A
group already Open is 409 `already_open`; a direct message is 400. The mode is an unsigned flag, like the
mode chosen at creation (THREAT_MODEL row). The cap already reads the mode at write time (`memberCap`),
so nothing else changes for it, and the `GENKEY#` chain is left alone: its links are still served.
A member who rotated their keys but is still at the caller's generation does not block it either, so converting drops the re-key their approval would have needed (the warning says so). Members of a converted group owe handoff rows from then on, because `HasNoRotation` now covers them. The
settings panel offers the conversion to an admin of a Rotating group only, spells out the loss, and asks
for the group's name to be typed.

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

**Comments and reactions carry their own TTL attribute**, **copied from the parent post's expiry
value** — not recomputed as `now + policy` when they are written. The distinction looks like
pedantry and is not: a comment written three weeks into a 30-day post's life and given `now + 30d`
outlives its parent by three weeks, and a reaction given the same treatment carries a
second-resolution record of when it was made, which is precisely the disclosure reactions are
otherwise free of. **No test catches the wrong version**, because both values expire the item at a
plausible-looking time. Copy the parent's number; do not derive a new one. The day-rounding rule
above means a correctly copied value and a correctly recomputed one agree, which is a second reason
to have it — but the instruction is *copy*, because only copying also gets the lifetime right. DynamoDB deletes items individually and does not cascade, and comments live in a
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

**Reading the chain.** `GET /api/groups/{gid}/keychain?from=A&to=B` returns the `GENKEY#` links for
generations A through B inclusive, ascending, to members only (anyone else gets the roster's 404),
at most 200 per page with `nextFrom` when more remain. It returns links and nothing else: the server
cannot open them, and an absent generation is not an error, because the floor of a truncated chain
looks the same as a gap. The client decides which it is. The one reader today is the group name: a
member whose own generation is *g* and whose group's name was sealed at generation *n* < *g* fetches
links *n* through *g*-1 and walks back, opening link *k* with the key it just recovered and
`genKeyAAD(gid, k)` to get generation *k*'s key, so the remover's own name no longer reads blank
after a removal. The crypto worker does no network I/O, so the caller fetches the links
(`web/src/lib/groups/nameChain.ts`) and passes them in. A missing or unopenable link, or a name
newer than the member's own generation, makes that one name unreadable and is never cached, so the
next load retries. The oldest-surviving-generation floor on `META` is not served yet, because
truncation is not built.

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

**Rendering a user's group list is the one hot-path read that fans out**, and it belongs in this
accounting because it is the most frequent read in the product rather than a slow path like the
chain walk. It is one GSI1 `Query` returning the user's membership items, plus **one `GetItem` per
group** — membership items hold the wrapped key, the role and the generation, but not the group's
name, which lives on that group's `META` in a different partition. For a private group it can be
more than that: the name is ciphertext under the group key, `META` records the generation it was
encrypted under, and a member who joined after rotations may need a `GENKEY#` range read to decrypt
it. So the sidebar is `O(the user's groups)`, not `O(table)` — nothing scans, and the headline claim
holds — but the bound is the number that actually grows in use.

**Client-side caching of names and unwrapped generation keys is what makes that acceptable**, the
same answer the chain walk already gets. The tempting alternative is wrong here in a way worth
naming: denormalizing the name onto each membership item would mean N copies of a ciphertext that
truncation has to re-encrypt whenever the chain floor advances past its generation. One copy on
`META` is the right shape, and the fan-out is the price.

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
| Successor designation | `GROUP#<gid>` | `DESIGNATION#<admin uuid>#<YYYY-MM-DD, UTC>#<rand>` | | | never |
| Post | `GROUP#<gid>` | `POST#<YYYY-MM-DD, UTC>#<rand>` | | | group policy |
| Comment | `POST#<pid>` | `CMT#<path>` | | | group policy |
| Reaction | `POST#<pid>` | `RXN#<cmtpath>#<reactor>` | | | group policy |
| Invite | `INVITE#<iid>` | `META` | `USER#<invitee>` | `INVITE#<YYYY-MM-DD, UTC>#<rand>` | signed `expires_at`; once accepted, completion deadline plus a one-week grace window |
| Invite (inviter's copy) | `USER#<inviter>` | `SENT#<iid>` | | | signed `expires_at`; once accepted, completion deadline plus a one-week grace window |
| Join request | `GROUP#<gid>` | `REQ#<uuid>` | `USER#<requester>` | `REQ#<YYYY-MM-DD, UTC>#<rand>` | never (pending) / cool-off (denied) |
| Key pin | `USER#<uuid>` | `PIN#<other-uuid>` | | | never |
| Verification record | `USER#<uuid>` | `VERIFIED#<other-uuid>` | | | never |
| Key change | `USER#<uuid>` | `KEYCHANGE#<epoch>` | | | never |
| Rotation cooldown | `USER#<uuid>` | `ROTCOOLDOWN` | | | TTL, end of the UTC day after the cooldown setting |
| Rotation handoff | `USER#<uuid>` | `HANDOFF#<gid>` | | | never (deleted on use; by the client when its start is refused; by the next `rotate-keys` commit when it names another key or the caller is no longer an admin of that group; with the account) |
| Rotation handoff counter | `USER#<uuid>` | `HANDOFFSEQ` | | | never (absent reads as 0; deleted with the account) |
| Notification | `USER#<uuid>` | `NOTIF#<YYYY-MM-DD, UTC>#<rand>` | | | group policy |

**The TTL column is part of the table on purpose.** This assignment was prose for several revisions
and drifted every time a row was added — a new row would arrive and the separate list would not be
updated, which is a defect the list's own claim to be exhaustive actively hides. Answering the
question in the row makes it impossible to add an item without deciding, and the paragraphs below
explain the reasoning rather than carrying the assignment.

**Every stored TTL value is rounded up to the end of its UTC day, and that rule is not optional.**
A DynamoDB TTL is a **Unix epoch in seconds held as a plaintext numeric attribute** — it has to be,
because DynamoDB reads it itself — so an unrounded TTL is a second-resolution timestamp sitting
beside a sort key that was deliberately built to disclose only a day. The subtraction is trivial for
anyone holding a dump: a post's TTL minus the group's retention policy, which is an attribute on the
same group's `META` item in the same dump, is **the second the post was written**. That would undo
the entire reason ids in this schema are random rather than ULIDs, and it would do it in the adjacent
attribute rather than in the key.

Rounding to the end of the UTC day restores day granularity by construction, at the same resolution
the sort keys already commit to. It costs at most 24 hours of extra retention on items whose
lifetimes are measured in weeks, which is not a meaningful change to what expiration is for. It also
makes the copy-versus-compute question below stop mattering for comments and reactions: a value
copied from the parent and a value computed from the same day's policy round to the same number.

**This is the complementary rule to `GENKEY#`'s "no TTL attribute, ever."** That one exists because a
TTL on a chain link would delete something load-bearing; this one exists because a TTL on anything
else is a timestamp in the clear. Both belong next to the column that forces the expiry question to
be answered, because answering "does this item expire" without answering "at what resolution does
saying so leak" is only half the decision.

**The user item is mixed, not wholly encrypted.** `USER#<uuid>` / `PROFILE` necessarily holds
plaintext the system reads: the username, the Ed25519 and X25519 **public** keys other members need
— including **superseded Ed25519 public keys with the intervals they were current for**, without
which no signature written before a rotation could ever be verified — the Argon2id salt, **the
Argon2id parameters that salt was used with**, and the wrapped private keys. It also holds an **encrypted preferences blob** —
theme and font choices — sealed under a key **derived by HKDF from the user's X25519 private key**,
so they do not become another identifying signal in a dump. That derivation is deliberate: the
recovery code restores the same private keys, so preferences survive a password change and a
recovery alike, with no second wrapped copy to keep in step. Deriving the key from the password
instead would leave a recovered account's preferences permanently unreadable — and it would fail
silently, looking like a theme that reset itself rather than a key that was lost. The email, when
present, is encrypted separately under a **server-held** key, because the server has to read it to
send mail. Three different protections in one item, and the distinction is the point: only the
preferences blob is beyond the operator's reach.

**The Argon2id parameters are `m=64 MiB, t=3, p=1`, and they are stored on the item rather than
compiled into the client.** Naming the numbers matters because "Argon2id" without them is not a
security claim — Argon2id at `m=8 MiB, t=1` is weaker against GPU cracking than a well-tuned bcrypt,
and the entire offline-cracking argument in the threat model rests on the cost being high. Running
in WASM in a browser constrains the tuning from above (mobile Safari's memory ceiling is the real
limit), which is a reason to write the chosen numbers down, not a reason to leave them open.

**Storing them is the part that cannot be added later.** A client that derives with its own
constants can never change them: raising the cost as hardware improves would mean every existing
blob was wrapped under the old parameters while the new client derives a different key — locking out
every existing user permanently, with the recovery copy equally dead, and with nothing on the server
that could re-wrap anything. Deriving from **the stored values** makes an increase a lazy re-wrap on
next successful login, which is the one moment the client already holds the plaintext keys and the
re-wrap is free. This is why a bcrypt hash carries its cost factor inline. It is unaddable
retroactively because old blobs would have no field to read.

`RECOVERY` carries its own salt and its own parameters for the same reason, since its derivation is
independent of the password's.

**The recovery code is 128 bits of CSPRNG output, rendered as 26 characters of Crockford base32 in
five hyphen-separated groups.** The alphabet excludes `I`, `L`, `O` and `U`, so a transcribed code
has no ambiguous characters, and the grouping is what makes it copyable by hand. It is the one
credential the system generates rather than the user, so its entropy is fully within the design's
control and is stated rather than assumed.

That derivation does have one case it does not survive, and it is worth naming rather than leaving
to be discovered: a **keypair change resets preferences**. A pinned key change is an approval
event, and the new X25519 key is a new HKDF input, so the old blob will not open. This is acceptable
only because of what the blob holds — a theme and a font, both re-choosable in a few seconds — and
it would not be acceptable for anything the user could not trivially reconstruct. Nothing else in
the design should be keyed this way.

**Five writes in this schema are contested, and all five are conditional.** The comment ordinal
above is one. The second is the login challenge delete, where two requests carrying the same nonce
race for one delete and exactly one wins — that race is the replay guarantee, not an incidental
detail. The third is the username claim below.

**The fourth is the credential re-wrap** — a password change or a recovery-code reset, which both
rewrite `PROFILE` and `RECOVERY` together under a new wrapper. Each is a `TransactWriteItems`, and
it is worth being precise about what that does and does not buy: a transaction is atomic *within
itself*, but two transactions are not mutually exclusive with each other. Two credential re-wraps
running concurrently — two tabs, or a retried recovery that appeared to hang — are two writers on
one key, and last writer wins.

**The failure is quiet and lands on the user in the worst place.** Both flows must make the user
store the new code before completing, so the user can be shown a recovery code, write it down, and
have it silently superseded by the transaction that lands second. Nothing tells them; they find out
when they try to use it, which is the same too-late-to-fix moment that makes the partial-write case
above the quietest failure in the flow. **So the transaction is conditional on a credential-version
attribute** bumped by every re-wrap: the losing writer fails its condition, and the user is told
their code is stale rather than being left holding one that silently is.

**The fifth is invite acceptance**, and it is the only one contested by *untrusted* parties rather
than by one user's two tabs or two devices. The `<iid>` is a bearer token on an unauthenticated
endpoint, so any holder of the link can race any other; the write is conditional on the invitee
field being absent, so the first acceptance wins and later ones are refused explicitly.

Nothing else in the table has two writers competing for one key — which is a separate question from
whether a write is *atomic*: signup is not contested beyond its claim, but it spans three items and
is a transaction for that reason.

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
challenge endpoint. **The `RECOVERY` item is served only by a code-gated release endpoint**, and the gate is what
distinguishes it from the login blob. It is offline-cracking material exactly as the
password-wrapped blob is — against a higher-entropy secret, but with the same consequence if it
leaks — so it must not be available the way `/auth/challenge`'s material is, on request to anyone
naming a username.

**It cannot be withheld entirely, though, and an earlier draft of this document claimed it could.**
Recovery works by unwrapping the private keys with the code, and unwrapping is a read: the client
needs the blob *and* the recovery salt, and that salt exists nowhere else by construction. A user
recovering has no session and no password, so no authenticated route could hand it over either.
"Proving you can use the code" without receiving anything is not a protocol that exists here —
demonstrating a wrapping key means decrypting something wrapped under it.

So the release is gated on **presenting the code first**. The server holds a **verifier** — an
Argon2id hash of the recovery code under its own salt and parameters, derived separately from the
wrapping key so that holding the verifier does not yield the wrapper — checks it, and only then
returns the blob. That verifier is also what authorizes the recovery reset's write to `PROFILE` and
`RECOVERY`, which otherwise has nothing stated that permits it — **with one narrow exception**:
issue #130's retry fallback additionally authorizes a *reset's own retry* on a matching client-held
idempotency token, once the code alone can no longer prove it (the first, successful call already
rotated the verifier the retry still presents). That path never re-derives or trusts a new secret —
it only replays the exact same write the code itself already authorized once, confirmed by an
exact match on the stored token, the version it produced, and the credential material itself, all
under a strongly consistent read. See `internal/db/credentials.go`'s `IsOwnRewrap` for the full
check.

The result is weaker than "no read path" and meaningfully stronger than the login blob: it is not
available on request, it is rate-limitable per account against a high-entropy secret rather than a
user-chosen password, and a failed attempt is **observable server-side** in a way offline cracking
never is.

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
`GROUP#<gid>` partition, so a client fetches the range it needs in **one paginated `Query`** with an SK
prefix of `GENKEY#` and then unwraps locally, generation by generation. Paginated because a `Query`
returns at most 1MB per page — roughly four to five thousand `GENKEY#` items — and this document
sizes the sort key for a million generations and states that a churning group accumulates them
without bound. **A short page means "more to fetch", never "the chain ends here":** the client
follows `LastEvaluatedKey` until it reaches the floor recorded on `META`. Getting that wrong is the
bad kind of failure, because a truncated page looks exactly like reaching the floor, so the client
concludes the chain is corrupted and older content becomes unreadable when nothing is actually
wrong. Only the unwrapping is sequential —
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
acceptance happened while the invite was valid. So at step 2, **the signed `expires_at` stops
governing both rows and is replaced by a completion deadline measured from acceptance** — stored,
like every TTL here, rounded up to the end of its UTC day, so the attribute does not date the
acceptance to the second.

**That clearing is a `TransactWriteItems`, and it is why `SENT#` is keyed on the iid alone.** The
two rows are in different partitions — `INVITE#<iid>` and `USER#<inviter>` — so this is a
transaction, the same two-partition shape signup gets one for, and not the single `UpdateItem` that
adds the `USER#<invitee>` GSI entry. More importantly, step 2 is the **invitee's** action, and the
invitee must be able to address both rows: they hold `<iid>` because it is in the link they
followed, and `SENT#<iid>` is constructible from it. A `SENT#` key carrying the creation day and a
128-bit random component would not be — neither value is in the signed step-1 payload, neither is
derivable from `<iid>`, and a `begins_with` cannot help because those components would precede the
one component the invitee actually has. An implementer who found the row unaddressable would clear
only `INVITE#`'s TTL and reintroduce exactly the bug above. Keying on the iid costs nothing that
was not already conceded: `SENT#` is queried as pending work rather than in time order.

The write is still **server-mediated and server-authorized** — the invitee supplies `<iid>` and
nothing else, and the server composes the transaction after verifying the invite. A second party
never names a row in the inviter's partition directly, which matters because `USER#<inviter>` also
holds their `PROFILE`, `RECOVERY`, `CHALLENGE` and `PIN#` rows, and letting a caller choose what to
write there is the shape the single-slot challenge argument rejects.

The signed `expires_at` keeps its real job of
bounding how long an *unaccepted* link stays usable, which is the property the signature protects
and is unaffected.

**The completion deadline is a deadline and not a removal of the bound, and that distinction is the
whole point.** Simply clearing the TTL would make an accepted `SENT#` row permanent, because the
only other thing that deletes it is step 3 — which is client-driven and runs on the inviter's next
login. An inviter who never comes back would leave a durable record of every person they ever
approached, which is the disclosure the threat model calls the more sensitive half, and it would
outlive by an unbounded margin the short-lived invite it points at. Trading a lost-invite bug for a
permanent-record bug is not a fix.

**This is the same shape as the rotation marker, and it takes the same answer.** Both are work that
only a client can finish, with no server-side actor able to complete it, and both therefore need
something that notices when the client never returns. So the deadline is **surfaced, not silently
enforced**: an invite that passes it is shown to the inviter as an outstanding acceptance they still
owe, and — because the invitee has already completed their half and been told it succeeded —
deleting it silently at the deadline would reintroduce the round-22 bug on a longer timescale.
**The invitee must be able to see the state of their own acceptance**, so a pending completion is
visible to them rather than resolving into silence. Expiry after the deadline is therefore a
deliberate, surfaced abandonment rather than a TTL sweep, and the row's lifetime is bounded by the
deadline rather than by whether one particular person logs in again.

**How the surfacing is built.** The deadline and the TTL are two different attributes. At
acceptance both rows get `CompletionDeadline` (the deadline, rounded to the end of its UTC day) and a
`TTL` one week *after* it. Passing the deadline therefore deletes nothing: `GET /api/invites/sent`
and `GET /api/invites/received` keep returning the invite with `overdue: true` and a `removalDate`,
so the inviter sees an acceptance they still owe and the invitee sees "not completed, you have not
joined" for a week instead of silence. Rows accepted before the attribute existed carried the
deadline in `TTL` and are read that way. **This narrows the round-22 failure rather than removing
it:** once the grace window ends the TTL sweeps both rows and the acceptance does disappear, with no
tombstone, because a tombstone would be the permanent who-approached-whom record the paragraph above
rules out. The week is the price of the bound, and the point of it is that the invitee has had a
real chance to be told.

What a dump yields is therefore still **work genuinely outstanding**, bounded by the completion
deadline — not a history of every approach the user has ever made.

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
in-progress generation, who started it, and when. It does not record how far the batched writes have
got: resume is driven by member state, not a position (see the `BatchWriteItem` discussion above). Nothing on
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
depth-first traversal order, a query returns a thread already in display order (in pages; see "Comments (#44)"). Depth is
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

A reaction's `<cmtpath>` is the path of the comment it attaches to, and **`0000` for a reaction on
the post itself** — a sentinel, because a real comment path's segments are four-digit ordinals
starting at `0001`, so `0000` is a value no path can take and it sorts before all of them.

**The empty string was the obvious choice here and it is a trap.** `RXN##<reactor>` doubles the
delimiter, and splitting it on `#` yields an empty middle field — survivable only if every
implementation splits with a limit and never collapses empties. Several standard splits do collapse
them, and then a post-level reaction parses as two fields with the **reactor landing in the cmtpath
slot**: a silent misparse producing a reaction attributed to a comment path that happens to look
like a uuid. With the sentinel every `RXN#` key is exactly three non-empty `#`-delimited fields.
This is the same class as the zero-padding rule below — an unconstrained component in a delimited
key misbehaves — and it is worth stating as its own rule: **no component of a sort key in this
schema is ever the empty string.**

**What the `<cmtpath>` component buys is ordering among reactions, not interleaving with comments.**
Sort keys compare from the first byte, so the `CMT#` / `RXN#` prefix dominates: the partition holds
the entire comment thread in traversal order, and *then* the entire reaction block. A reaction never
sorts adjacent to the comment it targets. What it does do is put the reactions in the **same order
as the thread**, so a client that reads the partition in one `Query` walks the two blocks in step
and zips them together. Saying it "sorts alongside the thread" invites a single-pass renderer that
consumes the query in order — which works on a thread with no reactions and breaks on the first
one.

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
key so reactions order among themselves in thread order, but which emoji was chosen is encrypted
under the group key like any other content. The server therefore knows that a user reacted to a
particular comment, and not what they said by it. The cost is that reaction counts are computed
client-side after decryption rather than aggregated by the server.

**Reactions are not signed, so they are as trustworthy as the server.** The AAD stops a stored reaction from being moved
to another post, target, reactor or generation, but it proves nothing about who sealed it: it is public, and every
member holds the group key, so any key holder can seal a valid reaction under anyone's AAD. The only thing tying a
reaction to its reactor is the server writing the session's user into the sort key. Two things follow. The server alone
can bring back a reaction its reactor removed, or put back the emoji they replaced, by rewriting a copy of an old row:
the row has no time and no counter, so nothing about it is fresh. The server together with any group key (an operator
who is also a member, or a removed member who still has the key before a rotation) can make up reactions from any member
with any emoji. This was chosen over signing: a signature would close only the second, and it cannot carry a signing day
without dating the reaction, so it would have to be checked against the reactor's current key and an old reaction would
stop verifying after that member rotated keys. Reactions are low stakes, so they are left unsigned (#46). Signing them
later would mean migrating stored rows.

**Reactions carry no creation time**, which is a smaller disclosure than posts make and is
deliberate. Their sort key holds the target path and the reactor's id — no day prefix — and the item
records no creation timestamp, encrypted or otherwise. Nothing needs one: reactions are read as a
set with their thread and counted after decryption, never ordered or filtered by time.

**That property is conditional on the TTL being copied from the parent post rather than computed at
write time**, and it is worth stating here as well as where the copy rule is given. A reaction's TTL
is a plaintext epoch attribute like any other; if it is derived from the moment the reaction was
made, then the item does carry a creation time in the clear, and the claim below is simply false.
Copied from the parent, the attribute says when the *post* expires and reveals nothing about the
reaction. Given that, a reaction is the one item in this schema that discloses an association
without a date, and adding a timestamp later would be adding a disclosure, not filling a gap.

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
  and would make a **sixth** contested write, alongside the five named above — and it would put a
  second contested attribute on `PROFILE`, which the credential re-wrap already contests.
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
  `POST /api/users:batch` serves the same projection for up to 100 ids in one request (a
  `BatchGetItem`), so a large roster costs one call per hundred members rather than one per member;
  unknown and malformed ids come back in `notFound`, and keys DynamoDB leaves unprocessed after
  retries fail the request with a 503 rather than being reported as unknown users.

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

**There is no `<ts>` anywhere in this schema.** A field named `ts` invites `Date.now()`, an
ISO-8601 instant, or a Unix epoch, every one of which puts millisecond or second resolution back
into a plaintext sort key — the leak the random id exists to remove. `INVITE#` and `REQ#` therefore
use the day-plus-random construct, and `SENT#` carries **no time component at all**.

Both of the keys that keep a day sit in a *user's* partition, which is the sharper case named just
above: `INVITE#` is a precise timeline of when a named person was invited to things, and `REQ#` of
what they asked to join. The `<rand>` suffix closes a collision too — two invites to the same
invitee on the same day would otherwise project the same GSI1 key and one would silently overwrite
the other, the same failure as the directory collision above. What that costs is sub-day ordering on
those two listings, which is the trade posts already accept.

**`SENT#<iid>` is the exception, and drops the day for a reason beyond disclosure.** The invitee has
to address that row at acceptance to clear its TTL, and can construct the key only from the `<iid>`
in the link they followed — a day and a 128-bit random component would be unreachable to them. It
loses nothing by dropping them: `SENT#` is queried as pending work rather than in time order, and
`<iid>` is already unique so there is no collision to close. The disclosure benefit is narrower than
it first appears, though, and the earlier phrasing here overstated it: the *sort key* carries no
timing, but the row carries a TTL, and after acceptance that TTL is a completion deadline measured
from acceptance. Unrounded, that would date the acceptance to the second in the inviter's own
partition — a sharper disclosure than the day the invitee's side carries, which would invert the
asymmetry rather than strengthen it. **The day-rounding rule on stored TTLs is what actually makes
the inviter's side no worse than day-granular**, and the key shape is what makes it addressable.
The two do different jobs and only the pair gives the property.

**Role grants live in the group partition but are keyed by subject within it, and are append-only.**
Verifying a chain is therefore one `begins_with(SK, "GRANT#" + uuid)` per hop — a keyed range read
that returns only that subject's grant history, typically a row or two, with nothing fetched and
discarded. The cost of a full walk is bounded by the **depth of the chain**, not by how much role
churn the group has seen and not by its membership. That is what the round-22 key shape buys: with
`GRANT#<uuid>` alone the walk was a filtered scan of the whole group's role history, and DynamoDB
billed every row it discarded.

A **group-wide** role-history read — an audit view listing every grant in the group, rather than one
subject's — is the access pattern the table does not serve natively; it is a filtered `Query` over
the partition, and its cost does grow with total churn. That is the reason to add a GSI here if one
is ever wanted, and it is additive and needs no migration of existing items.

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

Rate limiting is enforced by WAF rate-based rules, which key on **source IP** over a five-minute
window. **That granularity is the right one for harvesting and the wrong one for the challenge
flood, and the difference is not cosmetic.** Harvesting is a per-source activity, so an IP-keyed
bound reaches it. The challenge flood is keyed on a *username* — an attacker overwriting one named
user's challenge slot — and nothing here counts challenge requests per username. This document
already supplies the refutation, in the threat model's argument for keying the lockout on the
account: a source-scoped counter is trivially defeated by rotating IPs.

**So the honest statement is that the challenge flood is bounded by nothing in this design**, and
the threat model says so rather than pointing at a rate limit that cannot reach it. A per-username
counter is not a WAF feature — it is application state, which on an unauthenticated path means
exactly the write the single-slot decision was trying not to add. That changes the calculus on the
deferred conditional write above: it is deferred against an alternative control that does not exist.

Note what rate limiting is and is not protecting: Argon2id
runs in the **client's** browser for login, so a login costs the server only a DynamoDB read and, on
the second leg, one Ed25519 verification. An attacker hammering the *login* endpoint burns their own
CPU, not the operator's.

**This stopped being true of every Argon2id derivation in the system once #31's recovery endpoints
shipped.** `crypto.CheckRecoveryVerifier` recomputes the recovery verifier's Argon2id hash
server-side, under parameters the registering client chose and the server only reads back, and
`POST /api/account/recovery-code/release` reaches it with no session and no valid code required —
the check runs, and fails, on the 401 path exactly as it does on the 200 path. This is the one
Argon2id derivation in the whole design the *operator* pays for rather than the caller, and it is
why `validateArgon2Params` (`internal/handlers/register.go`) enforces a ceiling as well as a floor
on every stored parameter set, not only a floor: a value with no ceiling here is compute the
registering client can force onto the server at recovery time, for the cost of registering one
throwaway account. `terraform/waf.tf`'s `rate-limit-auth` rule is the only per-source bound on that
compute, and — see its own comment — it is IP-keyed, so it does not bound the cost distributed
across many source IPs against a single named account.

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

The one deployed environment is the Terraform workspace `prod`, with resource names derived from the
workspace so a mistyped variable cannot cross-wire them. There is no dev environment (#13).

Whether `no expiration` is permitted deserves particular care: enabling it lets a group turn off the
mitigation that Limitation 3 of the threat model, the forward-secrecy argument above, and generation
chain truncation all depend on. There are real reasons to want a permanent group, so the setting
exists — but a deployment that enables it should expect those three properties to be absent from any
group that uses it.

Site name, domain, registration policy, and whether "no expiration" is a permitted group setting are
all runtime configuration, served to the SPA from an unauthenticated `/api/config`. Nothing about a
particular deployment is baked into the bundle.

**Registration policy takes one of two values, `open` or `closed`, and the choice retunes several
threat-model claims.** `open` means anyone may create an account, which is what the threat model
assumes throughout: usernames are confirmable one at a time through the signup availability check,
the lockout and challenge-flood denial paths are available to anyone, and the anonymity-set argument
depends on pseudonyms being freely mintable. `closed` means the signup endpoint is disabled and
accounts are provisioned out of band; a deployment choosing it should read the enumeration and
availability sections as describing a smaller attacker population than they assume.

**There is deliberately no `invite-only` value**, and it is worth saying why rather than leaving it
as an obvious gap: invites in this design are **group**-scoped objects, and `GET /api/invites/:id`
is unauthenticated precisely so someone with no account can follow a link. A deployment-level
registration gate is a different object with no schema item, and it would need a deployment-level
role, which the role table — entirely group-scoped — has no concept of. Adding it is a real feature,
not a config value.

**Test accounts are a reserved, opt-in namespace.** Usernames starting `zz-delete-test-`
(case-insensitive) are refused at signup unless the request carries `X-Test-Account: 1`, and that
header is refused on any other name, so the prefix and the `TestAccount` flag on `PROFILE` always
agree. The header is not a secret: it only keeps a real user from landing in a scheduled test-data
purge by accident, and a person who opts in has asked for the deletion. Test accounts get no other
treatment (no rate-limit exemption, no relaxed validation), so the flag is worth nothing to an
attacker. The purge requires both the prefix and the flag.

Test accounts are findable without a scan: registration also writes `GSI1PK = TESTACCOUNT`,
`GSI1SK = <CreatedAt>#<uuid>` on their `PROFILE` (and only theirs), so `PurgeTestAccounts`
(`internal/db/purge.go`, run by `cmd/purge`) is one GSI1 `Query` for accounts older than a cutoff.
It defaults to a dry run and caps accounts per run. A test in `internal/db` fails if a new partition
kind appears in the data layer that the purge has not been taught about.

**The purge tombstones `PROFILE`; it never deletes it.** The grant chain checks a grantor's signature
with the key `GET /api/users/{id}` serves from `PROFILE` and ignores the key stored on the grant row,
and grants are append-only, so a grant a test account signed in a real group, even one it has since
left, stops verifying for every member if `PROFILE` goes. User ids are also client-chosen, so a deleted
`PROFILE` would let anyone re-register the id and inherit its key history (see the AAD table). One small
tombstone per test account is the price.

Because anyone can mint a test account, a test account can create groups, become a group's last
admin, or sit in a group real users belong to. The purge therefore never touches a group that has a
real member, and never raw-deletes a membership (leaving needs the user's own signature, which the
server cannot produce). A group whose members are all test accounts is deleted whole, including the
comments and reactions in its posts' `POST#<pid>` partitions, which are deleted first because the
post rows are how a rerun finds them. A test account that is also in a group with a real member is
still removed, but that one membership row stays: the "member whose profile is deleted" state
described under account deletion, which an admin clears with the ordinary removal flow. A test
account cannot be given a role in a real group without a real admin's signature, so this should be
rare. Such a tombstone keeps its index keys, so every run looks at it again and deletes that group
once the last real member has left; with nothing left to wait on, the keys are removed and it is
never examined again. Waiting accounts count against the per-run cap. A test account younger than
the cutoff counts like a real member for this purpose, so an old account never deletes a group a
still-running test is using; it waits until the younger one is old enough too.

Deletion order: for each test-only group, its posts' comments and reactions first, then its other rows,
and the account's own `MEMBER#` row last (the post rows are how a rerun finds the comments, and the
`MEMBER#` row is how it finds the group, so a run that dies partway leaves no unreachable orphans,
including a public group's directory entry); then the user's other rows and invites, then
the username claim, then `PROFILE`, which is what the candidate query finds. Membership is read from
GSI1, which is eventually consistent, so the minimum-age cutoff (default 2 hours) is what keeps a
just-written membership from being missed.

## Testing

Beyond ordinary unit and integration tests, CI verifies the crypto against **fixed test vectors** —
known inputs with known expected outputs, checked in.

This is not optional. A round-trip test ("encrypt, then decrypt, expect the original") passes even
when both directions are wrong in the same way. If a refactor silently changes key derivation, every
existing user is locked out permanently and no recovery is possible, because the server cannot
re-derive anything. Fixed vectors are the only thing that catches it.

**What the vectors must pin**, because each is a parameter this document now states and a value a
refactor could silently change:

- **Key derivation** — `(password, salt, m, t, p) → key`, with the parameters read from the stored
  attributes rather than from client constants, so the vector fails if either the numbers or the
  read path changes.
- **Symmetric encryption** — `(key, IV, plaintext, AAD) → ciphertext + tag`, including a negative
  case where the AAD differs and the tag must fail. The negative case is the one that catches an
  implementation that quietly stops binding ciphertext to its address.
- **Signing** — `(private key, canonical payload) → signature` for a post and for a comment, since
  their payloads differ in whether the signing day is redundant or load-bearing.
- **Key wrapping** — `(X25519 keypair, group key) → wrapped`, and a `GENKEY#` chain link unwrapping
  to the generation below it.
- **Fingerprints** — `(Ed25519 pub, X25519 pub) → displayed string`, since the display encoding is
  what determines whether a human compares the whole value.

Writing these is what turns the parameters above from prose into numbers, and a vector that cannot
be written is a sign the parameter it needs is still undecided.
