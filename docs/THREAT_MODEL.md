# UndergroundBB — Threat Model

This document states plainly what UndergroundBB protects, what it does not, and where the
guarantees end. If you are deciding whether to trust it with something that matters, read the
[Limitations](#limitations) section first — it is the honest part.

For how the system works, see [DESIGN.md](DESIGN.md).

## What is protected

**Message content.** Post titles, post bodies, and comments are encrypted with AES-256-GCM under a
group key that the server never possesses. A complete copy of the database yields ciphertext.

**Private keys.** Stored encrypted under an Argon2id-derived key. The password is never transmitted
and never stored in any form, including hashed.

**Private group names and descriptions.** Encrypted under the group key. Public groups, by
definition, have plaintext names and descriptions so they can be listed and searched — that is the
trade they make, and it is why the choice is per-group.

**Email addresses.** Optional, and encrypted at rest under a key **held by the server**, so a
stolen database does not yield them. This is the one item in this section the server can decrypt —
it has to, in order to send mail. If you do not want the operator to have your email address, do
not provide one; in-app notifications work without it.

**Key substitution during invites.** The invite handshake requires the invitee to sign their own
public keys, so a server cannot swap in a key of its own without forging a signature.

**Role claims.** Role grants are signed by the granting admin, forming a verifiable chain back to
the group creator. A server cannot fabricate a role.

**User preferences.** Theme and font choices live inside the encrypted profile, so they do not
become another identifying signal in a database dump.

## What is not protected

These are deliberate design decisions, not oversights.

### The social graph

Membership records are stored in plaintext. **A database dump reveals exactly who is in which
groups.** For many users this matters more than message content — knowing that a particular set of
people share a private group is often the substance of the story.

This was chosen consciously: hiding it would require pseudonymous membership keyed by an HMAC of the
group key, which would break the ability to list a user's groups efficiently and would push that
listing into an encrypted blob requiring a read-modify-write on every join and leave.

The mitigating factor is that UndergroundBB performs **no identity verification**. Accounts are a
username and an optional encrypted email. The graph therefore links pseudonyms to pseudonyms.

### Public group names and descriptions

A public group's name and description are stored in plaintext, because a directory cannot list or
search what it cannot read. This is the entire trade a public group makes, and it is chosen per
group at creation. Its **posts remain encrypted** — public means discoverable, not readable — and
its member list, like every group's, is visible only to members.

### Activity timing

Sort keys carry day-level granularity, so a dump reveals what day something was posted and by whom.
Precise timestamps are encrypted, which blunts fine-grained traffic analysis but does not eliminate
it.

### Usernames

Usernames are stored in plaintext — login requires looking a user up by name — and are enumerable
through search and the signup availability check. Both endpoints are rate-limited; neither is
private.

### Volume and structure

The number of groups, their member counts, post counts, thread shapes, and ciphertext lengths are
all visible in a dump. Padding could obscure lengths; it is not currently implemented.

### Login material

`POST /api/auth/challenge` returns the salt and the wrapped private keys for any username given to
it. This is unavoidable — a client needs both to attempt a login — but it means **material for an
offline password-cracking attack is available on request.**

This is precisely why Argon2id is used rather than a fast hash: it makes offline guessing expensive
rather than impossible. Weak passwords remain weak. The endpoint is rate-limited per IP, and
accounts lock for five minutes after five failed attempts, but neither prevents a determined
attacker from collecting blobs.

It is unavoidable only for an *unauthenticated* endpoint, which is a choice rather than a law. A
proof-of-work or CAPTCHA in front of blob release would not change the cryptography, but it would
raise the cost of harvesting blobs in bulk — the exact gap named above. It is not in v1 because it
trades a real usability and accessibility cost on every login against an attacker who, at this
project's scale, can equally well collect blobs slowly. That trade is worth revisiting if the
deployment is large enough to be worth harvesting.

**The lockout is itself an availability weakness.** It is keyed on the account, not the source, and
usernames are enumerable — so anyone can lock any account by making five bad guesses, and keep it
locked by repeating. This is a deliberate inheritance from the original implementation, and it
protects the thing that matters more here: without it, an attacker gets unlimited online guesses
against a password whose only other defence is Argon2id. A source-scoped counter would avoid the
denial of service but is trivially defeated by rotating IPs, which is the harder problem. Naming it
plainly: an attacker who wants to keep a specific user logged out can do so, and no design in this
document prevents that.

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

## Specific attack scenarios

| Attack | Outcome |
|---|---|
| Database dump stolen | Content safe. Social graph, usernames, day-level timing, and volume exposed. |
| Server compromised, database only | Same as above. |
| Server compromised, attacker serves modified JS | **Total compromise.** See Limitation 1. |
| Malicious operator swaps a public key at invite time | Blocked — the invitee signs their own keys. |
| Malicious operator fabricates a role grant | Blocked — clients verify the signature chain. |
| Malicious operator lies about a key on first contact | **Possible.** TOFU pins the key from that point on, and fingerprints are displayed for out-of-band verification, but a first sighting has nothing to compare against. |
| Member forges a post as another member | Blocked — posts are signed with the author's Ed25519 key. |
| Offline password cracking from a stolen database | Possible; cost is set by Argon2id parameters and the user's password strength. |
| Brute-force login over the network | Rate-limited per IP, plus a five-attempt lockout. |
| Malicious custom theme attempting exfiltration | Blocked — themes are validated JSON tokens, never CSS. See below. |
| Removed member reading future posts | Blocked in `Rotating` groups **once rotation completes** — until then, new posts still use the generation they hold. Possible indefinitely in `Open` groups. |

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

Please report privately rather than in a public issue. If GitHub's private vulnerability reporting
is enabled on this repository, use it; otherwise open an issue asking for a private channel without
including details of the vulnerability.
