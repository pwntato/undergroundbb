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
            # The three transformations below don't share one rationale --
            # each closes a different, separately-verified gap, so each is
            # justified on its own rather than as one undifferentiated
            # "hardening" bundle:
            #
            # URL_DECODE is load-bearing, not precautionary -- round 4
            # review found a genuine live bypass NONE could not have caught.
            # WAF's uri_path with NONE matches the raw, still-encoded URI,
            # so /%61pi/auth/challenge (%61 = "a") does not match
            # STARTS_WITH "/api/auth/" and falls straight through to the
            # 2000/5min default -- confirmed live: /%61pi/health hits the
            # real Lambda (genuine x-amzn-trace-id/x-amzn-requestid, "Miss
            # from cloudfront", real {"status":"ok"} body, not a redirect or
            # an edge rejection). Unlike the ./.. forms below, nothing else
            # in the request path normalizes or rejects this first --
            # decoding it here is the only thing that closes it.
            #
            # NORMALIZE_PATH is defense-in-depth, not a fix for a confirmed
            # bypass -- round 1/2 recorded /api/./auth/... and
            # /api/foo/../auth/... as live-verified bypasses, but round 3
            # found that was an artifact of testing with plain curl, which
            # silently strips "." and ".." from a URL client-side unless
            # --path-as-is is given. Reproduced properly with
            # --path-as-is: /api/./health is actually 307 from Go's
            # http.ServeMux (its own unclean-path redirect to the clean
            # path, not a handler hit) and /api/foo/../health is actually
            # 403 from CloudFront at the edge, never reaching the origin.
            # Kept anyway against those two components' behavior ever
            # changing, not because either was ever a real bypass.
            #
            # LOWERCASE is kept for a confirmed reason, not a hypothetical
            # one -- docs/DESIGN.md: every username lookup lowercases,
            # including POST /api/auth/challenge, so this endpoint really is
            # case-insensitive even though /API/auth/ doesn't reach the
            # Lambda today (it misses the /api/* cache behavior and lands on
            # the SPA instead).
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
