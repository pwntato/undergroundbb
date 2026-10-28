# #11: per-workspace values that can't be plain variable defaults, since a
# Terraform variable's default is static and can't itself read
# terraform.workspace. Resource *names* already derive from
# terraform.workspace directly wherever they're set (dynamodb.tf, lambda.tf,
# iam_deploy.tf, s3_frontend.tf, cloudfront.tf) -- this file is for the one
# value that isn't a name but still depends on the workspace: the domain the
# app is actually served from. prod is the only workspace in use (#13: no dev
# environment).
locals {
  # prod gets the bare apex. Deliberately a map with no fallback default: a
  # workspace someone creates by typo (terraform workspace new prodd) fails
  # plan with a clear "no key" error instead of silently getting a
  # *.undergroundbb.com subdomain from an unplanned name -- matches this
  # project's existing preference for exact scoping over a permissive
  # catch-all (see iam_deploy.tf's own comments).
  domain_name = {
    prod = var.root_domain
  }[terraform.workspace]
}

# Round 2 PR review suggested a `check` block here to make an unlisted
# workspace's failure self-describing rather than a bare Terraform-internals
# "Invalid index" error. Tried it and reverted: `check` blocks run during
# `plan`, but this map is a `locals` value evaluated eagerly wherever it's
# referenced -- the raw index error already aborts before a `check` block
# would ever get a chance to run, so it would have been dead code, not an
# improvement. The plain map's own error is what a typo'd workspace name
# actually surfaces; this file's comment above is where the explanation
# lives instead.
