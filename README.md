# UndergroundBB

An end-to-end encrypted message board. Your posts are encrypted in your browser before they reach
the server, and the server never has the keys to read them.

> **Status: in development.** This is a ground-up rewrite of the
> [original implementation](https://github.com/pwntato/undergroundbb-legacy). It is not yet usable.

## What it does

Create a group, invite people you trust, and talk. Every post title, post body, and comment is
encrypted with a key that only group members hold. The server stores ciphertext, public keys, and
the metadata it needs to route requests — nothing else.

- **Your password is never sent to the server**, not even hashed. Login is a signed challenge.
  (The flip side: anyone can ask the server for a given username's salt and wrapped keys, because a
  client needs them to attempt a login. That makes offline password guessing possible, which is why
  Argon2id is used and why a weak password is still a weak password —
  [the threat model explains this](docs/THREAT_MODEL.md#login-material).)
- **Invites use a signed handshake**, so the server cannot substitute its own key to read along.
- **Posts are signed**, so members cannot forge messages as one another.
- **Groups expire content** on a schedule — 30 days by default.
- **Themes**, because you should be comfortable in a tool you spend hours in.

## How it works, briefly

Your password derives a key via Argon2id. That key unwraps your Ed25519 signing key and X25519
wrapping key, which live encrypted on the server and are useless without your password. Groups have
a symmetric key wrapped to each member's public key; it encrypts everything posted in that group.
Inviting someone means unwrapping the group key and re-wrapping it to them — all in your browser.

Because the password is the only credential, you can log in from any device with no pairing step.
For the same reason, **if you lose both your password and your recovery code, your data is gone.**
That is a design property, not a bug: there is nothing on the server that could restore it.

Full detail in [docs/DESIGN.md](docs/DESIGN.md).

## What this does not protect against

Worth stating up front, because "encrypted" gets used loosely:

- **A dishonest operator can serve modified JavaScript** that steals your password. This is true of
  every browser-based end-to-end encrypted product. If your threat model includes the person running
  the server, you want a native app with a verified binary.
- **A stolen database reveals who is in which groups.** Message content stays encrypted, but the
  social graph, usernames, and day-level activity timing do not.
- **Removing someone does not un-see what they saw.** Rotation cuts off future access; nothing
  recovers the past.

The complete accounting is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). It is meant to be read
before you trust this with anything serious.

## Stack

| Layer | Choice |
|---|---|
| Frontend | React + TypeScript + Vite + Tailwind, static on S3 |
| Edge | CloudFront + AWS WAF |
| Backend | Go on AWS Lambda (Function URL) |
| Storage | DynamoDB, single table |
| Crypto | Argon2id (WASM), AES-256-GCM, Ed25519, X25519 |
| IaC | Terraform, workspaces for dev and prod |
| CI/CD | GitHub Actions with OIDC |

## Self-hosting

UndergroundBB is meant to be run by whoever needs it. Site name, domain, registration policy, and
whether groups may disable message expiration are all runtime configuration — nothing about a
particular deployment is compiled into the build.

Setup instructions will land with the first deployable release.

## Contributing

Themes are the easiest place to start: a theme is a JSON file of design tokens, and adding one
touches no application logic. A theming guide is tracked in
[issue #80](https://github.com/pwntato/undergroundbb/issues/80).

All changes go through a pull request with passing CI.

## License

MIT
