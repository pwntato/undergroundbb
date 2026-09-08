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
cd "$(git rev-parse --show-toplevel)/terraform"
STATE_BUCKET=$(terraform -chdir=bootstrap output -raw state_bucket 2>/dev/null)
LOCK_TABLE=$(terraform -chdir=bootstrap output -raw state_lock_table 2>/dev/null)
STATE_REGION=$(terraform -chdir=bootstrap output -raw aws_region 2>/dev/null)
[ -n "$STATE_BUCKET" ] && [ -n "$LOCK_TABLE" ] && [ -n "$STATE_REGION" ] || {
  echo "No bootstrap state on this machine. Run 'terraform apply' in terraform/bootstrap first (it adopts the existing resources via its import blocks)." >&2
  return 1 2>/dev/null || exit 1
}
terraform init \
  -backend-config="bucket=$STATE_BUCKET" \
  -backend-config="dynamodb_table=$LOCK_TABLE" \
  -backend-config="region=$STATE_REGION"
terraform apply -var state_bucket="$STATE_BUCKET"
```

`terraform -chdir=bootstrap output` exits `0` and prints nothing when bootstrap has no local state on
this machine (the state is local and gitignored, same as the note above) — without the check above,
that empty value flows silently into `-backend-config="bucket="` and Terraform fails on `main.tf`'s
`backend "s3"` block, which is not where the actual problem is.

The backend region is derived from the bootstrap's own output rather than hardcoded, since the
bootstrap region is itself overridable (`-var aws_region=...`, above). This `terraform/` config has
its own, independent `aws_region` variable (`terraform/variables.tf`, same `us-west-2` default) for
where its resources are created — the backend can't read a Terraform variable, which is why it's a
separate `-backend-config` flag in the first place, so a non-default region needs `-var
aws_region=...` on `terraform apply` here too, in addition to matching the bootstrap's region above.

Resource names derive from `terraform.workspace`, never a free-form variable (#11), so a mistyped
value can't point one environment's `apply` at another's table. There's no `dev`/`prod` split yet —
until #11 creates those workspaces, everything runs in Terraform's `default` workspace, so the table
is `undergroundbb-default`.

**The Lambda (#6)** needs a real deploy artifact — `terraform apply` reads `lambda.zip` at the
`terraform/` module's parent directory via `filebase64sha256`, so build it first:

```sh
GOOS=linux GOARCH=arm64 go build -o bootstrap ./cmd/lambda
zip lambda.zip bootstrap
```

`authorization_type = "NONE"` on the Function URL is intentional, not an oversight — CloudFront
(#8) is the access-control boundary once it lands, matching `docs/DESIGN.md`'s infrastructure
diagram. Until #8 exists, `terraform output function_url` is a temporary, unauthenticated way to
reach the deployed API directly.

**CI deploys on every push to `main`** (`.github/workflows/deploy.yml`): builds the binary, zips
it, assumes `AWS_DEPLOY_ROLE_ARN` via GitHub's OIDC provider (no long-lived AWS credentials stored
in the repo), and runs the same `terraform init`/`apply` as above against the `production`
environment. That role (`iam_deploy.tf`) is itself created by Terraform, scoped to exactly what
`terraform/` creates, plus read/write access to the state backend `terraform/bootstrap/`
provisions — bootstrap itself stays a manual, human-run step and is deliberately outside this
role's reach. Not a blanket policy, and not pre-granted access to #7-#11's future resources; each
of those gets its own policy statement added as it lands, same incremental approach
`iam_deploy.tf`'s comment describes.

That role has to exist before CI can use it, which means the **first** deploy is manual — apply the
commands above by hand once, then set the GitHub environment's `AWS_DEPLOY_ROLE_ARN` secret to the
`deploy_role_arn` output and `TF_STATE_BUCKET` var to the bootstrap's `state_bucket` output. Every
push to `main` after that deploys itself.

The GitHub Actions OIDC provider is per-AWS-account, not per-project — this account already has one
(created for `notoriousmcp`'s own deploy role), so `iam_deploy.tf` reads it via a data source rather
than declaring it as a resource, to avoid fighting over ownership of a provider shared with an
unrelated project's deploy pipeline.

**The AWS provider requires `>= 6.28.0`** (not `~> 5.0`, as it was through #4/#5). A Function URL's
`NONE` auth type needs two resource-policy statements, `lambda:InvokeFunctionUrl` and
`lambda:InvokeFunction` (the second gated on the `lambda:InvokedViaFunctionUrl` condition key, per
[AWS's own docs](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html), mandatory since
October 2025) — creating the URL via the console or SAM gets both automatically, but Terraform's
`aws_lambda_function_url` only manages the first, and the `invoked_via_function_url` attribute
needed to express the second on `aws_lambda_permission` didn't exist before provider `6.28.0`.
Without it, every request 403s (`AccessDeniedException`) regardless of `AuthType`, which is how this
was found — confirmed against a real deployment, not just read off the changelog.

## Contributing

Themes are the easiest place to start: a theme is a JSON file of design tokens, and adding one
touches no application logic. A theming guide is tracked in
[issue #80](https://github.com/pwntato/undergroundbb/issues/80).

All changes go through a pull request with passing CI.

## License

MIT
