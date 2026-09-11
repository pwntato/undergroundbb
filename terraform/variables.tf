variable "aws_region" {
  type        = string
  default     = "us-west-2"
  description = "Region for this project's infrastructure. ACM (#9) is the one exception — CloudFront requires its certificate in us-east-1 regardless of this value."
}

variable "state_bucket" {
  type        = string
  description = "State bucket name, from terraform/bootstrap's state_bucket output. Needed as plan-time data (not just a -backend-config flag) because the deploy role's own policy scopes itself to this bucket."
}

# #9: undergroundbb.com, decided over undergroundbb.net specifically because
# it's already a Route 53-registered domain in this account (registered
# directly through the Registrar on 2026-09-02, outside Terraform -- see
# acm.tf's comment on why the hosted zone is looked up rather than created).
# undergroundbb.net sits at Cloudflare instead, which would need either
# manual DNS-validation records there or delegating that zone into Route 53
# first; undergroundbb.com needs neither, so validation can be end-to-end
# Terraform-managed.
#
# Always the bare apex, never workspace-derived (#11) -- there is exactly
# one Route 53 hosted zone in this account, and it is what acm.tf's
# data "aws_route53_zone" looks up regardless of which workspace is applying.
# local.domain_name below is the thing that varies per workspace; this is
# the zone the per-workspace record lives inside.
variable "root_domain" {
  type        = string
  default     = "undergroundbb.com"
  description = "The Route 53 hosted zone's own apex name -- always this, never a per-workspace value. See local.domain_name for the name actually served."
}

# #113: self-hosting runtime configuration (#15, internal/config), wired into
# the Lambda's environment so a deployment can actually override the
# compiled-in defaults instead of always getting them. Each default below
# matches internal/config.Config's own Default* constant, so an apply with no
# overrides produces the identical Config a plain `go run ./cmd/local` would.
# DOMAIN is deliberately not among these -- it's local.domain_name (locals.tf),
# not a variable, since that value already varies correctly per workspace and
# a second, independently-settable value here could drift from it.
variable "site_name" {
  type        = string
  default     = "UndergroundBB"
  description = "Display name of this deployment. See internal/config.DefaultSiteName."
}

variable "registration_policy" {
  type        = string
  default     = "open"
  description = "\"open\" or \"closed\" -- see internal/config.DefaultRegistrationPolicy and docs/DESIGN.md's registration policy section."

  validation {
    condition     = contains(["open", "closed"], var.registration_policy)
    error_message = "registration_policy must be \"open\" or \"closed\"."
  }
}

variable "allow_group_expiration_off" {
  type        = bool
  default     = true
  description = "Whether a group in this deployment may turn off message expiration entirely. See internal/config.DefaultAllowGroupExpirationOff."
}

variable "default_expiration_days" {
  type        = number
  default     = 30
  description = "Expiration policy assigned to a group that doesn't choose one explicitly. See internal/config.DefaultExpirationDays."

  validation {
    # type = number alone permits fractions (e.g. 30.5), which pass > 0 and
    # tostring() to "30.5" -- Int64EnvOrDefault's strconv.ParseInt then
    # rejects that and silently falls back to the default, so a fraction
    # must be caught here rather than left to the Go side's parse failure.
    condition     = var.default_expiration_days > 0 && floor(var.default_expiration_days) == var.default_expiration_days
    error_message = "default_expiration_days must be a positive whole number of days."
  }
}
