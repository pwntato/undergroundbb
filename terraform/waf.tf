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
# attack keys on username, and WAF's own rate-limit floor (100 req/5min per
# IP) still permits an overwrite roughly every three seconds from a single
# IP, before any IP rotation. That threat model entry already says nothing
# in this design bounds it -- this file doesn't change that, and shouldn't
# be read as though it does. What this rule *does* bound is per-IP bulk
# harvesting of challenge material, which is the right granularity for that
# threat.
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

  # /api/auth/* specifically: 100 req/5min per IP is WAF's own minimum for
  # a rate-based rule (rate_based_statement.limit's documented floor), so
  # this is already the strictest this control can be made -- see this
  # file's header comment for why that floor still doesn't close the
  # username-keyed challenge-flood threat, and why a lower value isn't an
  # option to reach for instead.
  rule {
    name     = "rate-limit-auth"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string = "/api/auth/"
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            text_transformation {
              priority = 0
              type     = "NONE"
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
