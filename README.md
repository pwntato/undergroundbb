# UndergroundBB

An end-to-end encrypted message board. Your posts are encrypted in your browser before they reach
the server, and the server never has the keys to read them.

> **Status: in development.** This is a ground-up rewrite of the
> [original implementation](https://github.com/pwntato/undergroundbb-legacy). It is not yet usable.

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
and removing a member mints a new one. Inviting someone means unwrapping the group key and
re-wrapping it to them — all in your browser.

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
| IaC | Terraform, workspaces for dev and prod |
| CI/CD | GitHub Actions with OIDC |

## Self-hosting

UndergroundBB is meant to be run by whoever needs it. Site name, domain, registration policy
(`open` or `closed`), and whether groups may disable message expiration are all runtime
configuration — nothing about a particular deployment is compiled into the build.

Setup instructions will land with the first deployable release.

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

## Deploying

Infrastructure is Terraform (`terraform/`), with remote state in S3 and locking via DynamoDB.
Bootstrapping that remote state is a one-time, per-AWS-account step — it has to exist before
`terraform/` has anywhere remote to put its own state, so it keeps its own local state rather than
depending on the thing it creates:

```sh
cd terraform/bootstrap
terraform init
terraform apply
```

This creates a versioned, encrypted, non-public S3 bucket (`undergroundbb-tfstate-<account-id>`)
and a `PAY_PER_REQUEST` DynamoDB table (`undergroundbb-tfstate-lock`) for state locking, both in
`us-west-2` by default (override with `-var aws_region=...`). The rest of the project's
infrastructure defaults to this same region — ACM (#9) is the one exception, since CloudFront
requires its certificate in `us-east-1` regardless.

**Already applied in account `350195739155`.** Because this module's state is local and gitignored,
it exists only on the machine that ran the first apply — running the command above from elsewhere
(a second maintainer, a new machine, CI) against the same account starts from empty state where the
resources already exist. `import` blocks in `main.tf` cover all five resources for exactly this
case: `terraform apply` (the plain command above) adopts them into the new local state instead of
trying to recreate them, so it's safe and idempotent to re-run from any machine, in any account whose
resources already exist.

The **first ever** bootstrap of an AWS account needs one extra flag. The import blocks are
unconditional — an import whose target doesn't exist is a hard plan-time error, not a fallback to
creating it — so by default this module assumes the state resources already exist in the account
you're authenticated to. On a brand-new account there's nothing yet to adopt, so pass
`-var create_new_state=true` to skip the imports and create fresh instead:

```sh
terraform apply -var create_new_state=true
```

Every run after that first one — including later runs in that same new account — uses the plain
`terraform apply` above; the flag is not sticky to the account, only to that one first run.

**The main `terraform/` configuration** (Lambda, CloudFront, dev/prod workspaces — #6-#11) lands as
those issues close. So far it has just the DynamoDB table (#5). Its state lives in the bucket and
lock table the bootstrap above creates, supplied at init time since their names include the account
id:

```sh
cd terraform
terraform init \
  -backend-config="bucket=$(terraform -chdir=bootstrap output -raw state_bucket)" \
  -backend-config="dynamodb_table=$(terraform -chdir=bootstrap output -raw state_lock_table)" \
  -backend-config="region=us-west-2"
terraform apply
```

Resource names derive from `terraform.workspace`, never a free-form variable (#11), so a mistyped
value can't point one environment's `apply` at another's table. There's no `dev`/`prod` split yet —
until #11 creates those workspaces, everything runs in Terraform's `default` workspace, so the table
is `undergroundbb-default`.

## Contributing

Themes are the easiest place to start: a theme is a JSON file of design tokens, and adding one
touches no application logic. A theming guide is tracked in
[issue #80](https://github.com/pwntato/undergroundbb/issues/80).

All changes go through a pull request with passing CI.

## License

MIT
