# Self-hosting guide

UndergroundBB is built to be run by whoever needs it. This guide takes you from an empty AWS account to your own deployment at your own domain, and then lists every setting and every moving part.

**Read this first.** The project runs on AWS only (CloudFront, WAF, Lambda, DynamoDB, S3, Route 53) and is deployed with Terraform and GitHub Actions. It was built and deployed by its maintainer one piece at a time, so the steps below are taken from the Terraform and workflow files, not from a clean-room run in a fresh account. If a step does not work for you, please [open an issue](https://github.com/pwntato/undergroundbb/issues) with the error.

## What you need

- **An AWS account** and the [AWS CLI](https://aws.amazon.com/cli/) signed in with enough rights to create IAM roles, S3, CloudFront, WAF, Lambda, DynamoDB, ACM and Route 53 records. The one-off manual steps below need that. CI afterwards uses a narrower role that Terraform creates.
- **A domain with a Route 53 hosted zone in that same account.** The site is served at the *apex* of that zone (`example.com`, not `www.example.com`), and the TLS certificate is validated through that zone. To serve it at a subdomain such as `chat.example.com`, make `chat.example.com` its own hosted zone and delegate to it. There is no subdomain mode in the configuration.
- **GitHub's OIDC provider in the AWS account.** The Terraform *looks it up* and does not create it, because the provider is shared by every GitHub project in an account. A brand-new account does not have one yet, so see step 2.
- **Terraform 1.15 or newer**, **Go** (the version in `go.mod`, to build the Lambda zips) and **Node** (the version in `web/.node-version`; only needed if you build the site by hand).
- **A GitHub fork** of the repository, so that Actions can deploy it.

### What it costs

Almost everything is pay per use and is tiny for a small group: DynamoDB on demand, Lambda, S3, CloudFront. The fixed cost is **AWS WAF**: one web ACL plus two rate-limit rules (see `terraform/waf.tf`), which at AWS list prices is about $5 a month for the ACL and $1 for each rule, and a Route 53 hosted zone is about $0.50 a month. Check current [AWS pricing](https://aws.amazon.com/pricing/) before you rely on those numbers.

There is also a **cost guard** that switches the API off if spend spikes. Its monthly budget is **$20 for the whole AWS account**, not just this project, so if the account hosts other things, raise `cost_guard_budget_usd`. See [The cost guard](#the-cost-guard).

## Deploying, step by step

Each command block starts by going to the right directory, so you can run them from anywhere inside your clone.

### 1. Fork, then change the four things that are hard-coded to this project

Clone your fork. These values name the original project and have to be yours:

1. **Your domain.** In `terraform/variables.tf`, set the default of `root_domain` to your zone's name.
2. **Who may deploy.** In `terraform/iam_deploy.tf`, the deploy role trusts one GitHub subject, `repo:pwntato@844608/undergroundbb@1355495158:environment:production`. Replace it with yours. GitHub's newer repositories use the immutable-ID form `repo:<owner>@<owner id>/<repo>@<repo id>:environment:production`, and older ones the classic `repo:<owner>/<repo>:environment:production`. Ask GitHub which your repository issues, and for the IDs:

   ```sh
   gh api repos/OWNER/REPO/actions/oidc/customization/sub
   gh api users/OWNER --jq .id
   gh api repos/OWNER/REPO --jq .id
   ```

   The environment name `production` is part of the subject and must match the GitHub environment you create in step 6.
3. **Your region, if it is not `us-west-2`.** `.github/workflows/deploy.yml` names `us-west-2` twice (the AWS credentials step and `terraform init`). Change both, and pass `-var aws_region=...` wherever you run Terraform, including the bootstrap in step 3, whose region the state bucket and step 5's `init` then use. The workflow's `init` cannot read it from the bootstrap, which is why it is written out. The certificate always lives in `us-east-1`, whatever you choose, because CloudFront requires it.
4. **The smoke tests' address.** `.github/workflows/smoke.yml` sets `E2E_BASE_URL` to `https://undergroundbb.com`. Point it at your domain, or delete the workflow if you do not want post-deploy tests.

**Settings need to live in the repository, not on your laptop.** CI runs `terraform apply` on every push to `main`, and it only passes `state_bucket` and `alarm_email`. Any other setting you apply by hand (`site_name`, `registration_policy`, a limit) is **reverted by the next push**. Change the variable's default in `terraform/variables.tf`, or add a `TF_VAR_...` line to the `terraform plan` step in `deploy.yml`. See [Configuration](#configuration) for the settings.

### 2. Make sure the AWS account has GitHub's OIDC provider

```sh
aws iam list-open-id-connect-providers
```

If `token.actions.githubusercontent.com` is not in the list, create it:

```sh
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

Skip this step if the provider is already there. Creating a second one fails.

### 3. Bootstrap the Terraform state bucket (once per account)

```sh
cd "$(git rev-parse --show-toplevel)/terraform/bootstrap"
terraform init
terraform apply -var create_new_state=true
terraform output -raw state_bucket
```

This creates an encrypted, versioned, private S3 bucket named `undergroundbb-tfstate-<account id>`. Keep the `state_bucket` value; you need it twice more. The bootstrap keeps its own state **on your machine** (it cannot use the bucket it is creating), so run it from a machine you keep. `-var create_new_state=true` is for this very first run only: every later run in the same account uses plain `terraform apply`, which adopts the existing bucket instead of recreating it.

### 4. Build the Lambda zips

```sh
cd "$(git rev-parse --show-toplevel)"
./scripts/build-lambda-zips.sh
```

Terraform reads `lambda.zip`, `purge.zip` and `costguard.zip` from the repository root, so they must exist before you plan. Build with the Go version in `go.mod`: another toolchain gives a different binary and so a different hash.

### 5. The first apply, by hand

The deploy role that CI uses is created by this same Terraform, so the first apply cannot come from CI.

```sh
cd "$(git rev-parse --show-toplevel)/terraform"
STATE_BUCKET=$(terraform -chdir=bootstrap output -raw state_bucket)
STATE_REGION=$(terraform -chdir=bootstrap output -raw aws_region)
terraform init \
  -backend-config="bucket=$STATE_BUCKET" \
  -backend-config="region=$STATE_REGION"
terraform workspace new prod
terraform plan -out=tfplan -var state_bucket="$STATE_BUCKET"
```

Read the plan. The resource names should end in `-prod`. Then, as its own command:

```sh
terraform apply tfplan
```

The workspace has to be called `prod`, and it is the only one the configuration serves (`terraform/locals.tf`). If you skip `terraform workspace new prod`, the plan stops with `Invalid index` and `terraform.workspace is "default"`. The apply creates the DynamoDB table, the Lambdas, the S3 bucket, the certificate and its DNS validation records, the WAF, the CloudFront distribution, the DNS alias, and the deploy role. Certificate validation and CloudFront can take 15 minutes or more.

When it finishes, `terraform output` gives you what step 6 needs (`deploy_role_arn`, `frontend_bucket_name`, `cloudfront_distribution_id`).

### 6. Connect GitHub Actions

In your fork, open Settings, Environments, and create an environment named **`production`** (or open it, if an earlier deploy run already created it: GitHub creates an environment on its own when a job names one that does not exist). The name is not cosmetic: the deploy role only accepts a token issued to a job running under an environment with exactly that name.

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `AWS_DEPLOY_ROLE_ARN` | `terraform output -raw deploy_role_arn` |
| Variable | `TF_STATE_BUCKET` | the bootstrap's `state_bucket` |
| Secret (optional) | `ALARM_EMAIL` | an address for the purge and cost alarms |

`ALARM_EMAIL` is a secret because the repository is public and variables are not masked in logs. AWS emails the address a confirmation link, and the alarms reach you only once you confirm it.

### 7. Put the site live

The first apply made the infrastructure, but the web app itself is built and uploaded by the deploy workflow. GitHub leaves Actions off on a new fork, so open the Actions tab and turn them on first. Pushing to `main` starts the `deploy` workflow. If you had already enabled Actions, any push before step 6 ran a deploy that failed at the credentials step because `AWS_DEPLOY_ROLE_ARN` was still empty. That is expected. Now push any commit to `main`, or re-run the failed run from the Actions tab. The workflow builds the Lambdas, applies Terraform, builds the site, uploads it to S3 and invalidates CloudFront.

If you would rather do it by hand, the same steps are:

```sh
cd "$(git rev-parse --show-toplevel)"
cd web && npm ci && npm run build && cd ..
BUCKET=$(terraform -chdir=terraform output -raw frontend_bucket_name)
DIST=$(terraform -chdir=terraform output -raw cloudfront_distribution_id)
aws s3 sync web/dist "s3://$BUCKET" --exclude index.html
aws s3 cp web/dist/index.html "s3://$BUCKET/index.html"
aws cloudfront create-invalidation --distribution-id "$DIST" --paths '/*'
```

### 8. Check that it works

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://YOUR-DOMAIN/api/health
curl -sS https://YOUR-DOMAIN/api/config
```

The first should print `200`. The second shows your site name and the policy settings the app is running with. Then open the site in a browser and sign up. See the [user guide](USER_GUIDE.md) for what to expect. If you kept the smoke workflow, it runs after each successful deploy and signs up a throwaway `zz-delete-test-` account, which the hourly purge deletes.

From now on every push to `main` deploys itself.

## Choosing registration

`REGISTRATION_POLICY` is `open` (anyone may sign up) or `closed`. **`closed` turns signup off completely and there is no tool in this repository to create accounts afterwards**, so a `closed` deployment has no way to get its first user. There is also no "invite only" value: invites belong to groups, and a link works for someone with no account yet (see `docs/DESIGN.md`, "Registration policy"). Leave it `open` unless you have your own way to provision accounts.

## Running it day to day

- **Updating.** Merge to `main`. The deploy workflow builds and applies. The Lambda zips are reproducible, so a change that touches only `web/` or `docs/` plans no Lambda update.
- **Backups.** The DynamoDB table has point-in-time recovery turned on, and deletion protection. The server only ever holds ciphertext, so a restore does not need any key from you.
- **Alarms.** Two groups of alarms publish to SNS topics: the test-account purge and the cost guard. Set `ALARM_EMAIL` (step 6) to hear about them.
- **Tearing down.** `terraform destroy` stops at two things. The table has deletion protection: set `deletion_protection_enabled = false` in `terraform/dynamodb.tf` and apply. The frontend bucket is not empty and has no `force_destroy`, and it is versioned, so `aws s3 rm --recursive` is not enough: every object version and delete marker has to go (emptying the bucket in the S3 console does that), or set `force_destroy = true` on `aws_s3_bucket.frontend` in the same apply that turns off deletion protection. Then destroy. The state bucket and the Route 53 zone are not managed by the main configuration, and the bootstrap is destroyed separately. This path has not been exercised, so read the plan.
- **Migrations you do not need.** The one-time `cmd/wipe-v1-keyrows` and `cmd/rekey-reaction-notifs` programs fix rows written by older versions of the code. A new deployment never has those rows, so it never runs them.

## Configuration

Everything below is runtime configuration: nothing about a deployment is compiled into the build. The server reads environment variables (falling back to the defaults in the table) and serves the public subset, unauthenticated, from `GET /api/config`, which the app fetches when it starts. In a Terraform deployment you do not set the environment variables yourself. You set the matching Terraform variable (`terraform/variables.tf`) as described in step 1.

| Variable | Default | Meaning |
|---|---|---|
| `SITE_NAME` | `UndergroundBB` | Display name of this deployment. |
| `DOMAIN` | `localhost:3000` | Public domain this deployment is served from. |
| `ENVIRONMENT` | `dev` | Deployment environment (`dev` is the local-run label; `prod` when deployed, set by Terraform from the workspace). |
| `TABLE_NAME` | `undergroundbb` | DynamoDB table backing every record. |
| `REGISTRATION_POLICY` | `open` | `open` (anyone may sign up) or `closed` (signup disabled, accounts provisioned out of band) — see [docs/DESIGN.md](DESIGN.md). An invalid value fails closed. |
| `ALLOW_GROUP_EXPIRATION_OFF` | `true` | Whether a group in this deployment may turn off message expiration entirely. |
| `DEFAULT_EXPIRATION_DAYS` | `30` | Expiration policy assigned to a group that doesn't choose one explicitly. Must be positive. |
| `MAX_ROTATING_GROUP_MEMBERS` | `1000` | The most members a Rotating group may have (#60); Open groups have no cap. Values outside 2 to 10000 are clamped with a warning. Sized against the write burst of a key rotation, so check `docs/DESIGN.md` before raising it. Lowering it never removes existing members: it only refuses further joins. |
| `KEY_ROTATION_COOLDOWN_HOURS` | `24` | The shortest time between two key rotations of one account (#62), in hours. Values outside 1 to 720 are clamped with a warning. The limit is stored as a TTL rounded up to the end of its UTC day, like every stored TTL, so in practice it runs up to a day longer than the setting. Each rotation obliges an admin in every group the person belongs to to act, which is what the limit protects. |
| `MAX_POST_TITLE_BYTES` | `200` | The longest post title in UTF-8 bytes (#42). Values outside 1 to 2000 are clamped with a warning. Bytes, not characters, so a non-ASCII title fits fewer characters. The server sees only ciphertext, so it enforces the title and body caps together as a ciphertext size limit; the compose form enforces each exactly. Lowering it never touches existing posts. |
| `MAX_POST_BODY_BYTES` | `10000` | The longest post body in UTF-8 bytes (#42). Values outside 1 to 100000 are clamped with a warning. 10,000 bytes is about 7.5 KB of binary whatever the alphabet, so the cap bounds what can be stored per post but cannot inspect it: posts are end-to-end encrypted. |
| `MAX_COMMENT_BYTES` | `10000` | The longest comment in UTF-8 bytes (#44), its own setting separate from the post body's. Values outside 1 to 100000 are clamped with a warning. The server sees only ciphertext, so it enforces this as a ciphertext size limit; the reply form enforces it exactly. Lowering it never touches existing comments. |
| `SESSION_SECRET` | *(required, no default)* | Hex-encoded HMAC key for login session cookies — see [`internal/session`](../internal/session). There is no safe default; the process refuses to start without it. Generate one with `openssl rand -hex 32`. |
| `SESSION_TTL_HOURS` | `24` | How long an issued session cookie remains valid, in hours. Must be a positive whole number, at most `168` (7 days): a longer value is lowered to 168 with a warning, because the inactivity rule for a pre-signed successor measures activity by login day ([`docs/DESIGN.md`](DESIGN.md), "Inactivity"). |

All of these are wired into the Lambda's
Terraform config (`terraform/lambda.tf`) — `SITE_NAME`, `REGISTRATION_POLICY`,
`ALLOW_GROUP_EXPIRATION_OFF`, `DEFAULT_EXPIRATION_DAYS`, `MAX_ROTATING_GROUP_MEMBERS`, `KEY_ROTATION_COOLDOWN_HOURS`, `MAX_POST_TITLE_BYTES`, `MAX_POST_BODY_BYTES`, `MAX_COMMENT_BYTES`, and `SESSION_TTL_HOURS` as Terraform
variables (`terraform/variables.tf`, overridable with `-var` or a `.tfvars` file), `DOMAIN` from
`local.domain_name` so it can't drift from the domain CloudFront is actually configured for,
`TABLE_NAME`/`ENVIRONMENT` derived from the deployment itself, `ORIGIN_VERIFY_SECRET` generated by
`random_password.origin_verify` (see the CloudFront paragraph below), and `SESSION_SECRET` generated once
per workspace by Terraform itself (`random_id.session_secret`) rather than supplied.


The settings that are not Lambda environment variables are Terraform variables only: `aws_region` (default `us-west-2`), `root_domain`, `purge_dry_run`, `purge_schedule`, `alarm_email`, `web_max_concurrency`, `flood_invocations_per_5min` and `cost_guard_budget_usd` (see [The cost guard](#the-cost-guard) and [The test-account purge](#the-test-account-purge)). Each is documented in `terraform/variables.tf`.


## Reference: how the deployment fits together

The steps above are all most people need. This section explains the parts, for when you want to change or debug one.

Infrastructure is Terraform (`terraform/`), with remote state in S3, locked with an S3-native lock file.
Bootstrapping that remote state is a one-time, per-AWS-account step — it has to exist before
`terraform/` has anywhere remote to put its own state, so it keeps its own local state rather than
depending on the thing it creates:

```sh
cd terraform/bootstrap
terraform init
terraform apply
```

This creates a versioned, encrypted, non-public S3 bucket (`undergroundbb-tfstate-<account-id>`) in
`us-west-2` by default (override with `-var aws_region=...`). `terraform/` locks its state with an
S3-native lock file (`use_lockfile`, #94), so there is no lock table; the one the bootstrap used to
create was deleted. The rest of the project's infrastructure defaults to this same region — ACM
(#9) is the one exception, since CloudFront requires its certificate in `us-east-1` regardless.

The bootstrap's state is local and gitignored, so it exists only on the machine that ran the first apply. Run from elsewhere (a second maintainer, a new machine) against the same account, plain `terraform apply` adopts the four existing resources into the new local state through `import` blocks in `main.tf`, instead of trying to recreate them.

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

**The main `terraform/` configuration** holds the DynamoDB table, the Lambdas and their IAM roles, the deploy role, the S3 frontend bucket, CloudFront, WAF, the ACM certificate and its DNS records, and the `prod` workspace. Its state lives in the bucket the bootstrap creates, supplied at init time since its name includes the account id:

```sh
cd "$(git rev-parse --show-toplevel)/terraform"
STATE_BUCKET=$(terraform -chdir=bootstrap output -raw state_bucket 2>/dev/null)
STATE_REGION=$(terraform -chdir=bootstrap output -raw aws_region 2>/dev/null)
[ -n "$STATE_BUCKET" ] && [ -n "$STATE_REGION" ] || {
  echo "No bootstrap state on this machine. Run 'terraform apply' in terraform/bootstrap first (it adopts the existing resources via its import blocks)." >&2
  return 1 2>/dev/null || exit 1
}
terraform init \
  -backend-config="bucket=$STATE_BUCKET" \
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
value can't point one environment's `apply` at another's table. `prod` is the only workspace
in use; there is no dev environment (#13). Terraform's own built-in `default` workspace also still exists — the
CLI refuses to delete it outright — and is left empty rather than used for anything: everything that
had been applied there (from before this project had workspaces at all) was migrated to
`prod` and destroyed out of `default`, and it's kept empty going forward so an `apply` run with a
missing or typo'd `select` fails loudly (either "no such workspace" or an empty plan wanting to
create everything from scratch) instead of silently landing on a workspace that looks legitimate.
Select the one you mean before planning or applying:

```sh
terraform workspace select prod
```

**Before running any `apply` or `destroy` by hand** — confirm `terraform workspace show` prints the
workspace you mean, and once you have a plan, confirm the resource names/IDs in it carry the
expected suffix (`-prod`, not `-default`), rather than trusting the workspace you last
remember selecting. This project hit a real incident (#11's own PR) where a local
`terraform workspace show` gave inconsistent answers across consecutive commands in the same
session with no `select` in between, and an `apply` landed on the wrong workspace as a result —
re-checking immediately before every write, not just once at the start of a session, is what caught
and stopped it from recurring.

`deploy.yml` sets `TF_WORKSPACE: prod` at the job level rather than a `terraform workspace select`
step — every `terraform` invocation (`init`/`plan`/`apply`/`output`) reads it independently, so a
later step in the job can't drift onto a different workspace even if an earlier step's on-disk
selection were somehow wrong; it still fails loudly (`terraform init` errors if the named workspace
doesn't exist in the backend) rather than silently creating one or falling back to `default`. Setting
`TF_WORKSPACE` locally works the same way, and takes precedence over `workspace select` — a manual
`select` while `TF_WORKSPACE` is set to a different value fails, on purpose, rather than picking one
of the two silently.

The domain served depends on which workspace is selected: `local.domain_name`
(`terraform/locals.tf`) resolves to the bare apex of the Route 53 zone
`var.root_domain` names, for `prod`, the only workspace in use. Any other workspace fails plan at
that lookup — see `locals.tf`'s own comment for why it fails loudly rather than silently getting an
unplanned subdomain.

**The Lambda (#6)** needs a real deploy artifact — `terraform apply` reads `lambda.zip` at the
`terraform/` module's parent directory via `filebase64sha256`, so build it first:

```sh
./scripts/build-lambda-zips.sh
```

The script builds all three Lambda zips (the purge Lambda and the cost guard below read `purge.zip` and `costguard.zip` the same way)
reproducibly, so the hash only changes when the Go code does and a push that touches only
`web/` or `docs/` plans no Lambda update (#98). Build with the Go version in `go.mod`: a different
toolchain produces a different binary, and so a different hash.

### The cost guard

The cost guard (`cmd/costguard`, `terraform/costguard.tf`) bounds what a flood can cost. WAF's rate
rules limit one source IP and CloudFront bills every request, so nothing in front of the API caps a
distributed flood. The web Lambda has a reserved concurrency (`var.web_max_concurrency`, default 50),
which caps Lambda and DynamoDB spend. A CloudWatch alarm on its invocations
(`var.flood_invocations_per_5min`, default 20,000 in five minutes) and an AWS Budget on actual monthly
spend (`var.cost_guard_budget_usd`, default 20; whole account) publish to one SNS topic that invokes
`cmd/costguard`, which sets the web Lambda's reserved concurrency to 0. The static site stays up and the
API answers with errors until the switch is re-armed. A deploy re-arms it (terraform restores
`var.web_max_concurrency`), so do not deploy while an attack is still running. To re-arm by hand,
first check that the alarm is back to OK (CloudWatch runs an alarm's actions only on a state change, so
an alarm still in ALARM cannot trip again, and a flood that is still going keeps it there):
`aws cloudwatch describe-alarms --alarm-names undergroundbb-costguard-<workspace>-invocations --query 'MetricAlarms[0].StateValue'`;
then:
`aws lambda put-function-concurrency --function-name undergroundbb-<workspace> --reserved-concurrent-executions 50`.
The alarm is the fast trip (minutes); Budgets data lags by hours, so the budget is the backstop. The
budget notifies once per month after it crosses the limit, so after a trip and a mid-month re-arm only
the alarm can trip again until next month, and it counts the whole account's spend, not just this
project's. The trade-off is deliberate: a flood of about 20,000 requests in five minutes from 10 or more
IPs, each under the WAF's per-IP rate rule, takes the API down until a deploy or a manual re-arm. That
costs availability, not money, which is the right failure at this budget. Not
covered by the alarm: requests CloudFront or WAF answer without reaching the Lambda are billed but not
counted, and only the budget sees them. The trip emails `ALARM_EMAIL` if its subscription was confirmed.
The limits are Terraform variables; change one and deploy.

### The test-account purge

The purge is a second Lambda (`cmd/purge`, `terraform/purge.tf`) that deletes accounts
created by automated smoke tests (reserved `zz-delete-test-` username prefix) and everything they
own. It has its own minimal execution role and an EventBridge schedule (`var.purge_schedule`,
hourly by default), and `terraform apply` reads its `purge.zip` the same way; the script above
builds it too.

Deletion is on (`var.purge_dry_run` defaults to `false`; set it to `true` for a report-only run, and
every run logs a `purge report:` JSON line to CloudWatch, `/aws/lambda/undergroundbb-purge-<workspace>`).
Only accounts flagged as test accounts that also carry the reserved prefix are eligible. An invocation
payload can force a dry run (`{"dryRun": true}`) but can never turn deletion on. Three CloudWatch alarms
(`Errors`, `AsyncEventsDropped`, and `not_running` for fewer than one invocation in three hours)
publish to an SNS topic. Set the `ALARM_EMAIL` Actions secret (CI passes it as `var.alarm_email`; a secret
because the repo is public) to subscribe an address, and confirm the subscription from the email AWS
sends. Async retries are off, so a failed run waits for the next schedule. Accounts created before the
`TESTACCOUNT` GSI1 entry existed are invisible to it and need a one-off backfill.

### Migrations for older deployments

These two programs only matter for a deployment that ran code from before the change they follow. A new deployment never has the old rows.

**One-time migration for key rotation (#62).** Pins and verification records moved to payload v2 (they
carry a signed day, and a pin carries the pinned user's `KeyEpoch`), so every existing v1 `PIN#` and
`VERIFIED#` row can only read as `bad-signature`. Run `cmd/wipe-v1-keyrows` once per environment, after
the v2 code is deployed, from a shell with your own AWS credentials. It is not a Lambda and the Lambda
roles do not carry the `dynamodb:Scan` it needs. It defaults to a dry run and only the exact string
`WIPE_DRY_RUN=false` deletes; it only ever matches rows with no `SignedDay`, so it is safe to repeat:

```sh
AWS_REGION=us-west-2 TABLE_NAME=<table> go run ./cmd/wipe-v1-keyrows                      # report only
AWS_REGION=us-west-2 TABLE_NAME=<table> WIPE_DRY_RUN=false go run ./cmd/wipe-v1-keyrows   # delete
```

**One-time migration for reaction notifications (#69).** A reaction notification's sort key now carries
the day of the post it is on (`NOTIF#0000-00-00#<post day>#<hash>`), so the notification list is plain
key order. Rows written before that have no post day; run `cmd/rekey-reaction-notifs` once per
environment, after the code that writes the new key is deployed, from a shell with your own AWS
credentials. It is not a Lambda and the Lambda roles do not carry the `dynamodb:Scan` it needs. It
defaults to a dry run and only the exact string `REKEY_DRY_RUN=false` writes. It moves a row only if
the reaction it announces still exists (a row whose reaction was taken back is deleted, reported as
`orphaned`), and a move that was cancelled is reported as `retry` and left for the next run. Repeat
the write run until a dry run reports `moved`, `superseded`, `orphaned` and `retry` all 0:

```sh
AWS_REGION=us-west-2 TABLE_NAME=<table> go run ./cmd/rekey-reaction-notifs                        # report only
AWS_REGION=us-west-2 TABLE_NAME=<table> REKEY_DRY_RUN=false go run ./cmd/rekey-reaction-notifs    # write
```

### CloudFront, the origin secret and the pipeline

`authorization_type = "NONE"` on the Function URL is intentional, not an oversight — CloudFront
(#8) is the intended access-control boundary, matching `docs/DESIGN.md`'s infrastructure diagram.

**CloudFront (#8)** fronts both the SPA and the API from one distribution — `/*` to the S3 frontend
bucket via Origin Access Control, `/api/*` to the Lambda Function URL with caching disabled — so
there's no CORS to configure. SPA client-side routing (`/groups/abc` and the like) is handled by a
CloudFront Function on the default behavior that rewrites extensionless paths to `/index.html`
before origin selection, rather than via `custom_error_response`: an error-response rewrite is
distribution-wide, not per-behavior, and would silently intercept the API's own 403s/404s the same
way it once masked a `Host`-header bug in this project's own origin request policy (see
`terraform/cloudfront.tf`'s comments for both incidents).

The Function URL is still addressable (it has no authorizer), so it is not the access-control
boundary by itself: CloudFront adds a shared secret as `X-Origin-Verify` on every request to the `api`
origin (`random_password.origin_verify`), and `cmd/lambda` answers 403 to any request without it, before
a handler runs. That keeps a direct caller from reaching any handler, and so from getting around the
response headers policy and TLS policy (**#103**). It does not stop the invocations themselves, which
are billed, use Lambda concurrency, and are not WAF rate limited; a flood of direct calls gets fast 403s
but can still crowd out real traffic. A shared secret was chosen over CloudFront Origin Access Control
with `AWS_IAM` (which would reject before invocation) because OAC needs clients to send
`x-amz-content-sha256` on request bodies. Rotate by bumping `keepers.rotation`; requests can get a 403 for
a few minutes until CloudFront deploys the new header. The secret is in Terraform state and the
Lambda environment, like `SESSION_SECRET`.

**CI deploys on every push to `main`** (`.github/workflows/deploy.yml`): builds the binary, zips
it, assumes `AWS_DEPLOY_ROLE_ARN` via GitHub's OIDC provider (no long-lived AWS credentials stored
in the repo), and runs the same `terraform init`/`apply` as above against the `production`
environment. It then builds the frontend SPA (`npm ci` / `npm run build` in `web/`), syncs
`web/dist` to the frontend S3 bucket, and invalidates the CloudFront distribution's cache so the
new build is served immediately — bucket name and distribution ID come from `terraform output`,
not a separate configured value. That role (`iam_deploy.tf`) is itself created by Terraform, scoped to exactly what
`terraform/` creates, plus read/write access to the state backend `terraform/bootstrap/`
provisions — bootstrap itself stays a manual, human-run step and is deliberately outside this
role's reach. Not a blanket policy, and not pre-granted access to #7-#11's future resources; each
of those gets its own policy statement added as it lands, same incremental approach
`iam_deploy.tf`'s comment describes.

That role has to exist before CI can use it, so the first apply is manual: steps 5 and 6 above. The deploy role's trust policy only accepts a token whose `sub` claim names your repository and the `production` environment (see step 1); a job without that environment presents a `ref`-based `sub` instead and `sts:AssumeRoleWithWebIdentity` is denied.

The GitHub Actions OIDC provider is per AWS account, not per project, so `iam_deploy.tf` reads it through a data source rather than declaring it, to avoid fighting over a provider that other projects in the account may also use. That is why step 2 creates it by hand when the account has none.

**The AWS provider must be `>= 6.37.0` and `< 6.69.0`** (`terraform/main.tf`; the cap is there because 6.69.0 fails every Lambda code update, upstream issue hashicorp/terraform-provider-aws#50474, and CI does not commit a lock file). The floor is
`6.28.0` for the Function URL permission below, raised to `6.37.0` for the DynamoDB index's
`key_schema` block (#96), which had bugs before that release. A Function URL's
`NONE` auth type needs two resource-policy statements, `lambda:InvokeFunctionUrl` and
`lambda:InvokeFunction` (the second gated on the `lambda:InvokedViaFunctionUrl` condition key, per
[AWS's own docs](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html), mandatory since
October 2025) — creating the URL via the console or SAM gets both automatically, but Terraform's
`aws_lambda_function_url` only manages the first, and the `invoked_via_function_url` attribute
needed to express the second on `aws_lambda_permission` didn't exist before provider `6.28.0`.
Without it, every request 403s (`AccessDeniedException`) regardless of `AuthType`, which is how this
was found — confirmed against a real deployment, not just read off the changelog.
