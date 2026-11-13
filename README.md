# UndergroundBB

An end-to-end encrypted message board. Your posts are encrypted in your browser before they reach
the server, and the server never has the keys to read them.

> **Status: early release.** It runs at [undergroundbb.com](https://undergroundbb.com) and is open for
> signups, but it has not had an outside security review. This is a ground-up rewrite of the
> [original implementation](https://github.com/pwntato/undergroundbb-legacy).

## What it does

Create a group, invite people you trust, and talk. Every post title, post body, comment, and
reaction is encrypted with a key that only group members hold. The server stores ciphertext, public
keys, and the metadata it needs to route requests — nothing else.

- **Your password is never sent to the server**, not even hashed. Login is a signed challenge.
  (The flip side: anyone can ask the server for a given username's salt and wrapped keys, because a
  client needs them to attempt a login. That makes offline password guessing possible, which is why
  Argon2id is used and why a weak password is still a weak password —
  [the threat model explains this](docs/THREAT_MODEL.md#login-material).)
- **Invites use a signed handshake**, so the server cannot substitute its own key to read along.
- **Posts are signed**, so members cannot forge messages as one another.
- **Groups expire content** on a schedule — 30 days by default. A deployment may allow groups to turn
  expiration off, and a group that does gives up more than retention: expiry is the only
  forward-secrecy mechanism that works at every group size, so without it a database stolen later
  exposes everything ever posted, tombstones and notifications become permanent, and the key chain
  grows without bound. [The threat model covers what that costs](docs/THREAT_MODEL.md).
- **Themes**, because you should be comfortable in a tool you spend hours in.

## How it works, briefly

Your password derives a key via Argon2id. That key unwraps your Ed25519 signing key and X25519
wrapping key, which live encrypted on the server and are useless without your password. Groups have
a symmetric key wrapped to each member's public key; it encrypts everything posted in that group,
and in a Rotating group, removing a member mints a new one (an Open group, which a public group
always is, does not: see [removing a member](docs/GROUP_ADMIN_GUIDE.md#remove-a-member)). Inviting
someone means unwrapping the group key and re-wrapping it to them — all in your browser.

Because the password is the only credential, you can log in from any device with no pairing step.
For the same reason, **if you lose both your password and your recovery code, your data is gone.**
That is a design property, not a bug: there is nothing on the server that could restore it.

A plain-language walkthrough is in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) and the full detail in [docs/DESIGN.md](docs/DESIGN.md). To use the app, see the [user guide](docs/USER_GUIDE.md); to run a group, see the [group admin guide](docs/GROUP_ADMIN_GUIDE.md).

## What this does not protect against

Worth stating up front, because "encrypted" gets used loosely:

- **A dishonest operator can serve modified JavaScript** that steals your password. This is true of
  every browser-based end-to-end encrypted product. If your threat model includes the person running
  the server, you want a native app with a verified binary.
- **A stolen database reveals who is in which groups.** Message content stays encrypted, but the
  social graph, usernames, and day-level activity timing do not.
- **Removing someone does not un-see what they saw.** In a Rotating group, removal changes the key and
  so cuts off future access. In an Open group it only stops the server serving the group to them, so
  someone who kept a copy of the data could still read later posts. Either way, nothing recovers the
  past.
- **Your recovery code is a second full password.** Anyone holding it can unwrap your keys and read
  everything you can — it is not a lesser factor, and its strength is entirely wherever you stored
  it. Guard it like the password, and know that changing your password issues a new one and
  invalidates the old.

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
| IaC | Terraform, `prod` workspace |
| CI/CD | GitHub Actions with OIDC |

## Self-hosting

UndergroundBB is meant to be run by whoever needs it. Site name, domain, registration policy, whether
groups may turn message expiration off, and the size limits are runtime configuration: nothing about a
particular deployment is compiled into the build. The [self-hosting guide](docs/SELF_HOSTING.md) takes
you from an empty AWS account to your own deployment, and lists every setting with its default.

## Local development

Prerequisites: [Go](https://go.dev) (version pinned in `go.mod`), [Node](https://nodejs.org)
(version pinned in `web/.node-version` — `fnm use` or `nvm use` from `web/` picks it up
automatically), [Docker](https://www.docker.com) for DynamoDB Local, and the
[AWS CLI](https://aws.amazon.com/cli/) (`scripts/local-setup.sh` shells out to it to create the
local table — no real AWS account or credentials needed).

```sh
# 1. Start DynamoDB Local and create the table (schema matches docs/DESIGN.md
#    and the `dynamodb` service in .github/workflows/test.yml).
docker compose up -d
./scripts/local-setup.sh

# 2. Run the API server (in one terminal).
export AWS_ACCESS_KEY_ID=localuser AWS_SECRET_ACCESS_KEY=localpassword AWS_DEFAULT_REGION=us-west-2
export DYNAMODB_ENDPOINT=http://127.0.0.1:8000 TABLE_NAME=undergroundbb
export SESSION_SECRET=$(openssl rand -hex 32)
go run ./cmd/local

# 3. Run the frontend (in another terminal).
cd web && npm install && npm run dev
```

Open `http://localhost:5173` — Vite proxies `/api` to the Go server on `:3000`, so the app talks
to one origin exactly as it will in production behind CloudFront. `cmd/local` (`internal/db`,
`internal/handlers`) serves the identical handlers as `cmd/lambda`; only the transport differs.

`scripts/local-setup.sh` is idempotent — safe to re-run, it skips table creation if the table
already exists and matches the current schema. If you have a table from before a schema change
(GSI1 added or renamed), the script fails instead of accepting it — follow its message: `docker
compose down && docker compose up -d`, then re-run. The container runs `-inMemory`, so removing it
also clears all data if you want a clean slate for any other reason.


## Smoke tests

`web/e2e` is a Playwright suite that drives the real UI against a live deployment: it signs up a fresh
random `zz-delete-test-` account (sent with the `X-Test-Account` header, so the server treats it as a
test account and the scheduled purge deletes it later), creates a group, checks the roster lookup, then
runs the two-user invite flow: a second account, in its own browser context, accepts an invite, the
inviter logs out and back in (which completes the key handoff), and the invitee sees the group.
A second spec file walks one more account through the lifecycle: a new tab with cold keys asks for the
password before creating a group, a password change (the old password stops working), recovery with the
code the change issued, and account deletion together with the group it alone owned.
A third spec file checks what CloudFront adds in front of the app: the security headers on each route
and that every script and stylesheet carries a matching integrity hash, and, when `E2E_FUNCTION_URL`
is set, that the Lambda Function URL refuses calls that skip CloudFront. It skips itself against a
local stack, which has no CloudFront. The deploy workflow does not set `E2E_FUNCTION_URL` (the URL is
not public), so that last check is the one test the post-deploy run reports as skipped.
No credentials are stored anywhere.

```sh
cd web
npx playwright install chromium   # once
npm run e2e                       # against https://undergroundbb.com
E2E_BASE_URL=http://localhost:5173 npm run e2e
```

`.github/workflows/smoke.yml` runs it after every successful deploy of `main` (and on demand). It builds
the deployed commit and waits until the live site serves that build's assets before testing, so a
CloudFront invalidation that is still propagating does not test the previous release. One run spends
about 44 requests of the WAF's 100-per-5-minutes limit on `/api/auth/*` and `/api/account/recovery-code*`
(every full page load counts, via `GET /api/auth/session`), so two runs fit in a window and a third can
fail at signup with "Could not create your account"; wait for the window to clear instead of retrying.

## Contributing

Themes are the easiest place to start: a theme is a JSON file of design tokens, and adding one
touches no application logic. The [theming guide](docs/THEMING.md) covers the tokens and how to write one.

All changes go through a pull request with passing CI. CI includes a `govulncheck` step, and a weekly
run of it, that fails when the Go toolchain or a module has a known vulnerability our code reaches. It
can go red with no change of yours when Go publishes a fix; the cure is to raise the `go` line in
`go.mod` to the newest patch or, for a module, to update that module to the fixed version.

## License

MIT
