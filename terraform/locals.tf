# #11: per-workspace values that can't be plain variable defaults, since a
# Terraform variable's default is static and can't itself read
# terraform.workspace. Resource *names* already derive from
# terraform.workspace directly wherever they're set (dynamodb.tf, lambda.tf,
# iam_deploy.tf, s3_frontend.tf, cloudfront.tf) -- this file is for the one
# value that isn't a name but still needs to differ per workspace: the
# domain the app is actually served from.
locals {
  # prod gets the bare apex; every other workspace (today: dev) gets a
  # same-named subdomain of it -- both live in the one Route 53 zone
  # var.root_domain names, so acm.tf's zone lookup never varies by
  # workspace even though the record it creates does. Deliberately a map
  # with no fallback default: a third workspace someone creates by typo
  # (terraform workspace new prodd) fails plan with a clear "no key" error
  # instead of silently getting a *.undergroundbb.com subdomain from an
  # unplanned name -- matches this project's existing preference for exact
  # scoping over a permissive catch-all (see iam_deploy.tf's own comments).
  domain_name = {
    prod = var.root_domain
    dev  = "dev.${var.root_domain}"
  }[terraform.workspace]
}
