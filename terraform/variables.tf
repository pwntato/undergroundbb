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

variable "max_rotating_group_members" {
  type        = number
  default     = 1000
  description = "The most members a Rotating group may have (#60). Open groups have no cap. Sized against the write burst of a rotation (docs/DESIGN.md), so check that before raising it. See internal/config.DefaultMaxRotatingGroupMembers."

  validation {
    # The Go side clamps out-of-range values with a warning; catching them here
    # means a typo fails the plan instead of being quietly corrected at runtime.
    # A fraction would tostring() to "12.5", which the Go side cannot parse and
    # would silently replace with the default.
    condition     = var.max_rotating_group_members >= 2 && var.max_rotating_group_members <= 10000 && floor(var.max_rotating_group_members) == var.max_rotating_group_members
    error_message = "max_rotating_group_members must be a whole number from 2 to 10000."
  }
}

variable "max_post_title_bytes" {
  type        = number
  default     = 200
  description = "The longest post title, in UTF-8 bytes (#42). The server enforces it as part of a ciphertext size cap, the compose form exactly. See internal/config.DefaultMaxPostTitleBytes."

  validation {
    condition     = var.max_post_title_bytes >= 1 && var.max_post_title_bytes <= 2000 && floor(var.max_post_title_bytes) == var.max_post_title_bytes
    error_message = "max_post_title_bytes must be a whole number from 1 to 2000."
  }
}

variable "max_post_body_bytes" {
  type        = number
  default     = 10000
  description = "The longest post body, in UTF-8 bytes (#42); 10,000 bytes is about 7.5 KB of binary whatever the alphabet. See internal/config.DefaultMaxPostBodyBytes."

  validation {
    condition     = var.max_post_body_bytes >= 1 && var.max_post_body_bytes <= 100000 && floor(var.max_post_body_bytes) == var.max_post_body_bytes
    error_message = "max_post_body_bytes must be a whole number from 1 to 100000."
  }
}

variable "key_rotation_cooldown_hours" {
  type        = number
  default     = 24
  description = "The shortest time between two key rotations of one account (#62), in hours; the stored limit is rounded up to the end of its UTC day, so it can run up to a day longer. See internal/config.DefaultKeyRotationCooldown."

  validation {
    # The Go side clamps out-of-range values with a warning; a fraction would
    # tostring() to something it cannot parse and would silently replace with
    # the default. 720 hours is internal/config.MaxKeyRotationCooldown.
    condition     = var.key_rotation_cooldown_hours >= 1 && var.key_rotation_cooldown_hours <= 720 && floor(var.key_rotation_cooldown_hours) == var.key_rotation_cooldown_hours
    error_message = "key_rotation_cooldown_hours must be a whole number from 1 to 720."
  }
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

variable "session_ttl_hours" {
  type        = number
  default     = 24
  description = "How long an issued login session cookie remains valid, in hours. See internal/config.DefaultSessionTTL and internal/session's package doc -- docs/DESIGN.md pins no duration, only \"short-lived,\" so this is deployment policy with a documented default."

  validation {
    condition     = var.session_ttl_hours > 0 && var.session_ttl_hours <= 168 && floor(var.session_ttl_hours) == var.session_ttl_hours
    error_message = "session_ttl_hours must be a positive whole number of hours, at most 168 (7 days): the inactivity rule for a pre-signed successor measures activity by login day (docs/DESIGN.md, \"Inactivity\"), so sessions must stay far shorter than its 30-day minimum period (internal/config.MaxSessionTTL)."
  }
}

variable "purge_dry_run" {
  type        = bool
  default     = false
  description = "Whether the scheduled test-account purge (cmd/purge) only reports what it would delete. Deletion is on by default (set to true for a report-only run): only accounts flagged as test accounts, with the reserved zz-delete-test- prefix, are eligible, and the prod table holds no real data yet."
}

variable "alarm_email" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Email address subscribed to the purge alarm topic; CI sets it from the ALARM_EMAIL secret (deploy.yml). Empty creates the topic and alarms with no subscriber (the alarms are then only visible in the CloudWatch console). The subscription must be confirmed from the email AWS sends."
}

variable "purge_schedule" {
  type        = string
  default     = "rate(1 hour)"
  description = "EventBridge schedule expression for the test-account purge."
}

variable "web_max_concurrency" {
  type        = number
  default     = 50
  description = "Reserved concurrency of the web Lambda: the most requests it runs at once, which caps what a flood can cost (costguard.tf). Requests over it are throttled (429/5xx). The account's unreserved pool must stay at or above AWS's floor of 100."
  validation {
    condition     = var.web_max_concurrency >= 1 && var.web_max_concurrency <= 800
    error_message = "web_max_concurrency must be between 1 and 800."
  }
}

variable "flood_invocations_per_5min" {
  type        = number
  default     = 20000
  description = "Web Lambda invocations in five minutes (about 67 a second) above which the cost kill switch sets the API's concurrency to 0. Normal use here is a few thousand a day."
}

variable "cost_guard_budget_usd" {
  type        = number
  default     = 20
  description = "Monthly actual spend in USD for the whole account at which the cost kill switch sets the API's concurrency to 0. AWS Budgets data lags by hours, so this is the backstop; the invocation alarm is the fast trip."
}
