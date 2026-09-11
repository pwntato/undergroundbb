# #10: AWS WAF in front of the CloudFront distribution (#8). A WebACL
# scoped to CLOUDFRONT must be created in us-east-1 regardless of
# var.aws_region -- same constraint as acm.tf's certificate, and the same
# aws.use1 provider alias from main.tf.
#
# Two AWS managed rule groups (common exploit patterns + known-bad-inputs),
# plus a rate-based rule scoped to /api/auth/* stricter than the site
# default. The rate rule is a cost control as much as a security one:
# Argon2id login runs at roughly 64MB and several hundred ms per attempt
# (see docs/THREAT_MODEL.md), so an unthrottled login/challenge endpoint
# burns compute budget as fast as an attacker can send requests.
#
# Explicitly NOT a defense against the challenge-slot flood described in
# docs/THREAT_MODEL.md ("Attacker floods /auth/challenge for one named
# account") -- confirmed in #10's own issue comment (PR #1 review round 28).
# WAF rate-based rules key on source IP over a five-minute window; that
# attack keys on username, so no limit value closes it -- a single attacker
# IP can still overwrite one victim's challenge slot as fast as this rule's
# window allows, and rotating IPs defeats it for free regardless of how the
# limit is tuned. That threat model entry already says nothing in this
# design bounds it -- this file doesn't change that, and shouldn't be read
# as though it does. What this rule *does* bound is per-IP bulk harvesting
# of challenge material, which is the right granularity for that threat.
resource "aws_wafv2_web_acl" "main" {
  provider    = aws.use1
  name        = "undergroundbb-${terraform.workspace}"
  description = "WAF for the undergroundbb CloudFront distribution, issue 10."
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # AWS-managed core rule set: SQLi, XSS, and other common exploit patterns
  # targeting the request line, headers, and body.
  rule {
    name     = "aws-common-rule-set"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "undergroundbb-${terraform.workspace}-common"
      sampled_requests_enabled   = true
    }
  }

  # AWS-managed known-bad-inputs rule set: request patterns known to exploit
  # specific CVEs/vulnerable software, independent of the common rule set
  # above.
  rule {
    name     = "aws-known-bad-inputs"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "undergroundbb-${terraform.workspace}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Site-default rate limit: generous, exists mainly to bound abusive
  # scraping/scanning traffic across the whole distribution. 2000 is AWS's
  # own commonly-cited "reasonable default" starting point and this
  # project has no traffic data yet to tune it against -- revisit once
  # real usage exists.
  rule {
    name     = "rate-limit-default"
    priority = 3

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "undergroundbb-${terraform.workspace}-rate-default"
      sampled_requests_enabled   = true
    }
  }

  # /api/auth/* specifically: 30 req/5min per IP (~6/min) is a deliberate
  # choice, not a forced floor -- round 1 review corrected an earlier
  # version of this comment that claimed 100 was WAF's minimum;
  # rate_based_statement.limit's real minimum is 10 (confirmed live via
  # `aws wafv2 check-capacity`, which accepts Limit=10 and rejects Limit=0).
  # This value is generous for a human retrying a forgotten password a
  # handful of times, while still meaningfully bounding the Argon2id compute
  # a single IP can burn (see this file's header comment: ~64MB and several
  # hundred ms per attempt). See the header comment for why no value here
  # closes the username-keyed challenge-flood threat -- that's a property of
  # WAF keying on IP, not of this number.
  rule {
    name     = "rate-limit-auth"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 30
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string = "/api/auth/"
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            # Round 1 review, verified live: NONE (byte-for-byte match on
            # the raw URI) let /api/./auth/challenge bypass this rule
            # entirely and fall through to the 2000/5min default --
            # confirmed via /api/./health returning the same 200 as
            # /api/health, i.e. Go's http.ServeMux (and CloudFront's /api/*
            # behavior ahead of it) already treats the two as identical
            # requests, so WAF must too. URL_DECODE then NORMALIZE_PATH
            # (applied in priority order) closes the verified gap; LOWERCASE
            # is added defensively for the same reason even though
            # /API/auth/ doesn't reach the Lambda today (it misses the
            # /api/* cache behavior and lands on the SPA instead) -- it
            # costs nothing to include and removes a second place this rule
            # would need revisiting if that ever changes.
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "NORMALIZE_PATH"
            }
            text_transformation {
              priority = 2
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "undergroundbb-${terraform.workspace}-rate-auth"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "undergroundbb-${terraform.workspace}"
    sampled_requests_enabled   = true
  }
}

output "waf_web_acl_arn" {
  value       = aws_wafv2_web_acl.main.arn
  description = "The WebACL protecting the CloudFront distribution (#10)."
}
