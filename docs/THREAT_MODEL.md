# UndergroundBB — Threat Model

This document states plainly what UndergroundBB protects, what it does not, and where the
guarantees end. If you are deciding whether to trust it with something that matters, read the
[Limitations](#limitations) section first — it is the honest part.

For how the system works, see [DESIGN.md](DESIGN.md).

## What is protected

**Message content.** Post titles, post bodies, comments, and reactions are encrypted with AES-256-GCM
under a group key that the server never possesses. A complete copy of the database yields ciphertext.
Reactions are encrypted in their content but not in their existence: a dump shows that a given user
reacted to a given post or comment, and only the emoji itself is unreadable — the reactor's id is
in the sort key, because that is what makes a reaction removable. It does **not** show when: the key
carries the target and the reactor, with no day prefix and no timestamp, and reactions record no
creation time at all. They are the one item here that discloses an association without a date.

**Private keys.** Stored encrypted under an Argon2id-derived key. The password is never transmitted
and never stored in any form, including hashed.

**Private group names and descriptions.** Encrypted under the group key. Public groups, by
definition, have plaintext names and descriptions so they can be listed and searched — that is the
trade they make, and it is why the choice is per-group.

**Email addresses.** Optional, and encrypted at rest under a key **held by the server**, so a
stolen database *alone* does not yield them. Be precise about which attack that covers: the
protection is against a dump reaching someone who does not also hold the server's key, and a
compromise deep enough to read the server's key reads the addresses too. This is the one item in
this section the server can decrypt — it has to, in order to send mail. If you do not want the
operator to have your email address, do not provide one; in-app notifications work without it.

**Key substitution during invites.** The invite handshake requires the invitee to sign their own
public keys, so a server cannot swap in a key of its own without forging a signature.

**Role claims.** Role grants are signed by the granting admin, forming a verifiable chain back to
the group creator. A server cannot fabricate a role.

**User preferences.** Theme and font choices live in an encrypted blob inside the user item, sealed
under a key only that user holds, so they do not become another identifying signal in a database
dump. These are self-directed settings only — there is no display name, and users are named
everywhere by their plaintext username. The rest of that item — username, public keys, salt, wrapped
private keys — is necessarily readable, and the email is encrypted under a server key rather than a
user one. Only the preferences blob is beyond the operator's reach.

## What is not protected

These are deliberate design decisions, not oversights.

### The social graph

Membership records are stored in plaintext. **A database dump reveals exactly who is in which
groups.** For many users this matters more than message content — knowing that a particular set of
people share a private group is often the substance of the story.

This was chosen consciously: hiding it would require pseudonymous membership keyed by an HMAC of the
group key, which would break the ability to list a user's groups efficiently and would push that
listing into an encrypted blob requiring a read-modify-write on every join and leave.

**This includes direct messages.** A DM is a group like any other and its membership is recorded the
same way, so a dump reveals who direct-messages whom as plainly as it reveals group rosters — and
that is the pairwise case, the one with the smallest anonymity set and usually the most to give
away. The pairwise case gets no special treatment, and nobody should assume it does.

**It also includes invitations still outstanding, which is intent rather than association.** The
inviter's copy of an invite is stored under their own id and timestamped, so a dump shows that a
user invited someone to a group on a given day even though nobody joined — and the invitee may have
no account at all. This is deliberately bounded: that row is deleted when the invite completes and
expires with the invite otherwise, so what a dump yields is **invitations currently outstanding, not
a history of every approach the user has ever made.** A permanent record of attempted contact would
outlive the deliberately short-lived invite it points at, which would invert the whole point of
giving invites a lifetime.

The mitigating factor is that UndergroundBB performs **no identity verification**. Accounts are a
username and an optional encrypted email. The graph therefore links pseudonyms to pseudonyms.

### Public group names and descriptions

A public group's name and description are stored in plaintext, because a directory cannot list or
search what it cannot read. This is the entire trade a public group makes, and it is chosen per
group at creation. Its **posts remain encrypted** — public means discoverable, not readable — and
its member list, like every group's, is visible only to members. A private group writes no directory
entry at all, so it is **absent from the index rather than filtered out of it**: there is no listing
a bug or a permissive query could expose it through.

### Activity timing

Sort keys carry day-level granularity, so a dump reveals what day something was posted and by whom.
Precise timestamps exist only inside the encrypted payload, which is why the ids in sort keys are
**random rather than time-ordered** — a ULID or similar would have put a millisecond timestamp in
plaintext beside the day prefix and made the day meaningless.

**Comments are the exception, and they disclose sequence.** A comment's sort key is a materialized
path of sibling ordinals, so a dump shows the exact order of a thread — third top-level comment,
first reply beneath it — though not the wall-clock time of any of them. Read alongside day prefixes,
that bounds how a conversation interleaved within a day. The ordinals are what make one query return
a thread in display order, and that structure was judged worth the disclosure; it is named here
because it is genuinely more than the day-level granularity everything else exposes.

**This includes notifications**, which are `NOTIF#<YYYY-MM-DD, UTC>#<rand>` in the *user's* own
partition. That is a per-user timeline rather than a per-group one, and it spans every group the
user belongs to, so it is a distinct disclosure from "what day something was posted in this group" —
which is why it gets the same day-granular, randomly-ordered treatment.

What day-level timing still gives an observer is real: activity on a given date, per user, per
group, and a rough correlation of who was active on the same days, plus thread sequence where
comments are involved. What it withholds is the fine-grained analysis that a millisecond timeline
supports — inter-post intervals, session boundaries, and reply latency in wall-clock terms. That
last one matters most in the pairwise case named under [the social graph](#the-social-graph): in a
two-member DM, millisecond reply latency correlates two accounts far more strongly than membership
alone, and membership is the disclosure this document already treats as the serious one.

### Usernames

Usernames are stored in plaintext — login requires looking a user up by name — and are
**confirmable one at a time**: the signup availability check and `/auth/challenge` both reveal
whether a given name exists. There is no username search, and the design deliberately provides no
read path for one — matching partial names would need a `Scan` or a search index, and the schema
has neither — so an attacker can test names but cannot ask for a list of them. Both endpoints are
rate-limited; neither is private. Confirming names one at a time is still enough to enumerate a
deployment given time, which is what the lockout weakness below assumes.

### Volume and structure

The number of groups, their member counts, post counts, thread shapes, and ciphertext lengths are
all visible in a dump. Padding could obscure lengths; it is not currently implemented.

**A deleted post leaves a tombstone**, which keeps replies coherent but is itself a durable record
that something was posted there, by whom, and on what day it was removed. Tombstones expire with
the group's retention policy like any other item — so in a group that has disabled expiration, the
marker is permanent even though the content is gone.

### Login material

`POST /api/auth/challenge` returns the salt and the wrapped private keys for any username given to
it. This is unavoidable — a client needs both to attempt a login — but it means **material for an
offline password-cracking attack is available on request.**

This is precisely why Argon2id is used rather than a fast hash: it makes offline guessing expensive
rather than impossible. Weak passwords remain weak. The endpoint is rate-limited per IP, and
accounts lock for five minutes after five failed **signature verifications**, but neither prevents a
determined attacker from collecting blobs. The lockout counts signature failures rather than wrong
passwords because a wrong password fails inside the browser and never reaches the server — see the
login sequence in [DESIGN.md](DESIGN.md); it is a control on credential stuffing, not on guessing.
It is **not** what stops replay either — that is the single-use nonce, since a replayed valid
signature verifies successfully and so never increments a counter of failures.

It is unavoidable only for an *unauthenticated* endpoint, which is a choice rather than a law. A
proof-of-work or CAPTCHA in front of blob release would not change the cryptography, but it would
raise the cost of harvesting blobs in bulk — the exact gap named above. It is not in v1 because it
trades a real usability and accessibility cost on every login against an attacker who, at this
project's scale, can equally well collect blobs slowly. That trade is worth revisiting if the
deployment is large enough to be worth harvesting.

**The lockout is itself an availability weakness.** It is keyed on the account, not the source, and
usernames are enumerable — so anyone can lock any account by submitting five bad signatures against
its username, and keep it locked by repeating. This is a deliberate inheritance from the original
implementation. Its value is narrower than it first appears: since the challenge endpoint already
hands out crackable material, an attacker who wants to guess a password does it offline, where no
lockout reaches them. What the lockout still bounds is **online** abuse — credential stuffing
against a known account. A source-scoped counter would avoid the denial of service but is trivially
defeated by rotating IPs, which is the harder problem. Naming it plainly: an attacker who wants to
keep a specific user logged out can do so, and no design in this document prevents that. **There are
two independent ways to do it** — this one, and the challenge-slot flood described below, which
leaves no trace in the lockout counter at all.

**What that same attacker cannot do is inflate the victim's partition.** The lockout counter and the
login challenge are both **single items** in `USER#<uuid>` — the counter is an attribute update, and
the challenge is one slot per user, overwritten on each request rather than one item per nonce. So
repeated unauthenticated requests against a chosen username do not grow storage without bound and do
not accumulate items that a TTL then has to remove on an eventual schedule. Cardinality is closed.

**Rate is not, and after the single-slot change what the rate gap costs is no longer only the
operator's spend.** It is also **login availability for a chosen account**. Because the slot is one
per user and any unauthenticated caller who knows the username can overwrite it, a sustained flood
against that username replaces the victim's outstanding challenge faster than they can answer it —
their signature comes back matching a nonce that is no longer there, and the login fails. Argon2id
makes this easy for the attacker: the victim's leg is deliberately slow, so retrying loses the race
again. Usernames are enumerable, so the victim is chosen, exactly as in the paragraph above.

**This is a second and independent way to deny one named account, and it is invisible to the control
an operator would check first.** No signature failure is recorded, so the lockout counter stays at
zero and the account is never locked — an operator looking at an unlocked account and a user who
cannot log in is looking at the wrong mechanism. DESIGN.md states the trade where the single-slot
decision is made, along with the conditional write that would close it and why that is deferred.

### The recovery code

At signup every account is issued a **recovery code**, and a second copy of the private keys is
wrapped under it. It is therefore **a second full credential**: anyone holding it can unwrap the
same private keys, and through them every group key the user holds. It is equivalent to the
password, not a lesser factor.

Three things follow, and none of them is stated anywhere else:

- **Its strength is where the user put it.** The code is high-entropy and generated for the user, so
  unlike a password it cannot be guessed — the Argon2id stretching applied when wrapping under it is
  defence in depth rather than the primary control. What guards it is storage. A code in a password
  manager is strong; the same code on a sticky note or in a screenshot is the weakest thing in this
  document. Of every limitation listed here, this is the one an attacker is likeliest to reach
  without any skill at all.
- **It is not served by any endpoint.** Unlike the password-wrapped blob described in
  [Login material](#login-material), the recovery-wrapped copy leaves the server through no read
  path — recovery is a write path, where the client proves it can use the code rather than fetching
  the blob to try codes against. A database dump still exposes it, like everything else in the
  table, but it is not available on request the way login material is. That is a deliberate
  protection and the reason the two blobs are separate items.
- **A leaked code is neutralized only by changing the password.** There is no "revoke my recovery
  code" operation, because a password change already reissues the code and re-wraps the copy under
  the new one, invalidating the old. A user who believes their code has leaked should change their
  password — an instruction worth putting in front of them, since nothing about it is obvious.

The converse of the guarantee in the README — lose both password and code and the data is gone — is
that holding either one is total account access, indefinitely, until a password change.

## Limitations

The three things below are the real boundaries of what this software can promise.

### 1. A malicious operator can serve malicious JavaScript

**This is the fundamental limitation of end-to-end encryption in a web application, and it applies to
UndergroundBB exactly as it applies to every other browser-based E2E product.**

The server delivers the code that performs the encryption. An operator who is compromised, coerced,
or dishonest can ship a modified bundle that exfiltrates passwords or plaintext. No amount of
client-side cryptography prevents this, because the client-side cryptography is itself delivered by
the server.

What this design achieves is raising the cost: an attacker must push a detectable code change rather
than simply reading a database. Subresource integrity and reproducible builds narrow the gap further
but do not close it.

**If your threat model includes the operator of the server, use a native application with an
independently verified binary. This is not that.**

### 2. Roles are not a cryptographic boundary

Signed role grants prevent a *server* from fabricating roles. They do not prevent a member who
genuinely holds a role from abusing it, and they cannot: a member with the group key can encrypt
anything to that group, and an Ambassador can invite anyone they choose.

Roles coordinate behaviour among people who already share a key. They are not a containment
mechanism.

### 3. Removal cannot undo access

A removed member retains any group key they were given, and any content they already decrypted.
Rotation cuts them off from future posts; nothing recovers the past. In `Open` groups, without
rotation, a removed member could decrypt future posts too if they retain a copy of the data.

Rotation is not instantaneous. It is a resumable batched job, and new posts use the previous
generation until it finishes — well under a second in a small group, and a few seconds at the
1,000-member cap. The number that matters is not the normal case, though: if the client running the
rotation fails partway, the window stays open until someone resumes the job, which could be minutes
or longer. Anything posted before it closes is readable by the removed member. Removal is therefore
an eventual cryptographic boundary, not an immediate one.

Expiration is the mitigation that actually scales — content that no longer exists cannot be read.
**Where a deployment permits it, a group can disable expiration**, and such a group has none of this:
past content is retained indefinitely, and removal's boundary is bounded by rotation alone. That is a
deliberate option for groups that need a permanent record, and it should be chosen knowing it
switches off the only mechanism here that limits past exposure at any group size.

## Specific attack scenarios

| Attack | Outcome |
|---|---|
| Database dump stolen | Content safe. Social graph, usernames, day-level timing (no finer — sort-key ids are random, not time-ordered), volume, and **currently outstanding invitations** — who approached whom, even where nobody joined — exposed. Also exposed: **offline-cracking material for every account** — the salt and password-wrapped keys, and the recovery-wrapped copy, which a dump is the only way to reach since no endpoint serves it. Encrypted emails are not readable without the server's key. |
| Server compromised, database only | Same as above, **plus email addresses** if the compromise reaches the server-held email key, which a database-only dump does not. |
| Server compromised, attacker serves modified JS | **Total compromise.** See Limitation 1. |
| Malicious operator swaps a public key at invite time | Blocked — the invitee signs their own keys. |
| Malicious operator fabricates a role grant | Blocked — clients verify the signature chain, back to the group creator's key that was current when each grant was signed. |
| Malicious operator deletes a pin, then substitutes that key | **Possible.** A pin's signature authenticates its contents, not its existence, and nothing binds the pin *set* — so a withheld pin is indistinguishable from genuine first contact and the hard-block never fires. Fingerprint verification is the only control. See the pinning section in [DESIGN.md](DESIGN.md). |
| Malicious operator lies about a key on first contact | **Possible.** TOFU pins the key from that point on, and fingerprints are displayed for out-of-band verification, but a first sighting has nothing to compare against. |
| First DM to a user never contacted before | **Possible.** No handshake counterparty exists to sign their own keys — the sender picks the recipient — so the server supplies that key with nothing to check it against. TOFU pins it and later changes hard-block; fingerprint verification is the only control on the first message. This is a structural gap rather than an attack: it is present whether or not anyone is attacking. |
| Author deletes a post, expecting it to be gone | **Advisory only.** The stored copy is replaced with a tombstone, but any member who already read the post could have kept a copy, exactly as with removal (Limitation 3). Deletion removes what the server holds, not what has been seen. |
| Member forges a post as another member | Blocked — posts are signed with the author's Ed25519 key, and superseded public keys are retained so a rotation does not turn the author's own history into unverifiable content. |
| Attacker obtains a user's recovery code | **Total account compromise**, equivalent to learning the password. Neutralized only by a password change, which reissues the code. See [The recovery code](#the-recovery-code). |
| Login challenge response replayed | Blocked — the nonce is stored server-side and spent by a conditional delete, so a captured response is worthless the moment it is used once. Note the lockout does not help here: a replayed *valid* signature never fails verification, so nothing counts it. |
| Session cookie stolen | Reads ciphertext, membership and metadata; **no plaintext and no keys**, which stay in the browser. Cannot forge posts — those carry an Ed25519 signature the cookie cannot produce. Not revocable: valid until it expires, and unaffected by a password change or lockout. |
| Offline password cracking from a stolen database | Possible; cost is set by Argon2id parameters and the user's password strength. |
| Brute-force login over the network | Rate-limited per IP, plus a five-attempt lockout — but an attacker after a password guesses **offline** instead, where neither control reaches. See [Login material](#login-material). |
| Attacker keeps one named account locked out | **Possible.** The lockout is keyed on the account, not the source, and usernames are enumerable, so five bad signatures lock any account and repeating keeps it locked. Deliberate inheritance from the original implementation; a source-scoped counter is defeated by rotating IPs. See [Login material](#login-material). |
| Attacker floods `/auth/challenge` for one named account | **Possible, and distinct from the row above.** The challenge is a single slot per user that any unauthenticated caller can overwrite, so a sustained flood invalidates the victim's outstanding nonce faster than an Argon2id derivation completes and they cannot finish a login. **Records no signature failure, so the lockout counter stays at zero and the account never shows as locked** — the control an operator would check first says nothing is wrong. Only a rate limit bounds it. A conditional write that refuses to replace an unexpired challenge would close it; deferred in v1, see [DESIGN.md](DESIGN.md). |
| Malicious custom theme attempting exfiltration | Blocked — themes are validated JSON tokens, never CSS. See below. |
| Removed member reading future posts | **Eventually blocked** in `Rotating` groups — new posts use the old generation until rotation finishes, and a rotation abandoned by its client stays open until an admin notices the stale marker and resumes it. Possible indefinitely in `Open` groups. |

## Why custom themes are JSON, not CSS

In an application holding plaintext private keys in browser memory, **any script execution on the
page is a total compromise** — not defacement, but exfiltration of keys and every readable message.

A "custom CSS" feature would open several paths to that outcome:

- `url()` in a stylesheet issues network requests; combined with attribute selectors this can
  exfiltrate data character by character.
- `@import` loads remote CSS, bypassing any validation performed on the submitted text.
- `@font-face` with a remote `src` is the same exfiltration channel in another form.
- A theme able to set `position` and `z-index` can overlay the interface — covering a real button
  with a fake one, or **displaying a key fingerprint that is not the real fingerprint**, defeating
  the verification UI itself.

Sanitizing CSS means maintaining a denylist, and CSS denylists have a long history of being bypassed.

Instead, a theme is a JSON object of token values. Colors must match a color pattern; fonts must come
from a curated list or name a locally installed font; lengths must fall within bounded ranges.
Validated values are applied through the CSSOM as custom properties. **No user-supplied string ever
reaches the page as CSS syntax**, so the attacks above are structurally impossible rather than
filtered. A Content-Security-Policy of `style-src 'self'` without `unsafe-inline` backs this up.

## Reporting a vulnerability

Please report privately rather than in a public issue. Use the **Report a vulnerability** button
under this repository's **Security** tab, which opens a private advisory visible only to the
maintainers.

**What to expect, stated honestly because the alternative is silence:** this is a personal project,
not a funded one, and it has no on-call rotation. The best-effort target is an acknowledgement
within **one week**. There is no bounty. Fixes are made in the open and the advisory is published
once a fix is available, crediting the reporter unless they prefer otherwise. If a report goes
unacknowledged past that window, escalating publicly is a reasonable thing to do — a project that
cannot answer a security report in a week has no standing to ask for continued silence.
