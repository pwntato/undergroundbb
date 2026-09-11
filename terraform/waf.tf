# #10: AWS WAF in front of the CloudFront distribution (#8). A WebACL
# scoped to CLOUDFRONT must be created in us-east-1 regardless of
# var.aws_region -- same constraint as acm.tf's certificate, and the same
# aws.use1 provider alias from main.tf.
#
# Two AWS managed rule groups (common exploit patterns + known-bad-inputs),
# plus a rate-based rule scoped to /api/auth/* stricter than the site
# default. Round 2 review caught this comment previously justifying that
# rule as a "cost control" against Argon2id compute -- wrong on both halves:
# Argon2id runs exclusively in the browser (web/src/lib/crypto/argon2.ts),
# never on this project's servers, and docs/DESIGN.md says so explicitly
# ("An attacker hammering the endpoint burns their own CPU, not the
# operator's"), then names what to size against instead: bulk harvesting of
# the salt + wrapped private keys POST /api/auth/challenge hands out to
# anyone naming a username (offline-cracking material), and a second,
# genuinely operator-side cost -- both /auth/challenge and the verify leg's
# failure-counter increment are unauthenticated writes against a single
# user's hottest DynamoDB partition (DESIGN.md: "this cost falls on the
# operator, in write capacity and in contention against legitimate logins").
# This rule bounds both: the harvesting rate directly, and the
# hot-partition write rate as a side effect of the same per-IP limit
# covering both legs under one prefix.
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
  # Round 2 review caught the value's own justification as wrong too: it had
  # been picked to tighten "a single IP's compute burn," but there is no
  # server-side compute this rule bounds (see this file's header comment --
  # Argon2id never runs here). 30 is sized against this file's header
  # comment's actual two targets instead: generous enough for a human
  # retrying a forgotten password a handful of times, while still bounding
  # both per-IP harvesting of challenge material and the hot-partition write
  # rate against a single named user's PROFILE item. See the header comment
  # for why no value here closes the username-keyed challenge-flood threat
  # -- that's a property of WAF keying on IP, not of this number.
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
            # NONE (byte-for-byte match on the raw URI) was tried and
            # dropped in round 1 review over a suspected /api/./auth/...
            # bypass -- rounds 1 and 2 both recorded that as a live-verified
            # 200 identical to /api/health, but round 3 found that was
            # curl's own client-side path normalization (curl cleans "."
            # and ".." out of a URL before sending unless --path-as-is is
            # given), not the server's behavior. Reproduced properly with
            # --path-as-is: /api/./health is 307 from Go's http.ServeMux
            # (its own unclean-path redirect, to the clean /api/health --
            # not a handler hit), and /api/foo/../health is 403 from
            # CloudFront at the edge, never reaching the origin at all.
            # Neither is actually a bypass of a NONE-transformation rule;
            # the request that would do real work (the redirect target, or
            # a request CloudFront lets through) is a separate, clean
            # request that a literal match already catches.
            # Kept URL_DECODE + NORMALIZE_PATH anyway, as defense-in-depth
            # against CloudFront's or ServeMux's edge/redirect behavior ever
            # changing, not because a live bypass was ever confirmed --
            # NONE was never actually broken, this chain is simply more
            # robust than depending on those two components' current
            # behavior. LOWERCASE is kept for a confirmed reason, not a
            # hypothetical one -- docs/DESIGN.md: every username lookup
            # lowercases, including POST /api/auth/challenge, so this
            # endpoint really is case-insensitive even though /API/auth/
            # doesn't reach the Lambda today (it misses the /api/* cache
            # behavior and lands on the SPA instead).
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
