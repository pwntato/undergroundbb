# Single distribution fronting both the SPA and the API from one origin, so
# there is no CORS to configure (#8). Two origins behind it:
#   /*      -> S3 frontend bucket (#7), via Origin Access Control
#   /api/*  -> the Lambda Function URL (#6), CachingDisabled
#
# The S3 bucket policy granting this distribution's OAC principal read
# access lives here rather than in s3_frontend.tf, per that file's own
# comment: it needs this distribution's ARN in its AWS:SourceArn condition,
# so it couldn't exist before #8.

resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "undergroundbb-frontend-${terraform.workspace}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_iam_policy_document" "frontend_bucket_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.frontend.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.main.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = data.aws_iam_policy_document.frontend_bucket_policy.json
}

# Long cache for hashed static assets (Vite's build emits content-hashed
# filenames under /assets/*, e.g. index-DrLDjz1_.css) -- a changed file gets
# a new URL, so caching it for a year is safe and an edge revalidation on
# every request is pure waste. Attached only to the /assets/* ordered
# behavior below, not the default one -- see that behavior's comment for why
# the long-TTL policy has to opt in rather than being the default.
resource "aws_cloudfront_cache_policy" "static_assets" {
  name        = "undergroundbb-static-assets-${terraform.workspace}"
  default_ttl = 31536000
  max_ttl     = 31536000
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

# index.html (and any other unhashed file served from bucket root, e.g.
# favicon.svg) must not get the same long TTL as /assets/* -- it's the one
# file whose content changes without a URL change on every deploy, and the
# SPA-rewrite CloudFront Function below routes every client-side route
# (/groups/abc, /settings, ...) to it as well. This is the *default* cache
# behavior's policy, not a narrower one scoped to /index.html specifically
# (round 1 review on #8 caught that /index.html as a path_pattern barely
# matches anything real: the SPA rewrite happens at viewer-request, before
# cache-behavior selection, so a rewritten request is evaluated against
# whichever behavior the *original* path matched -- almost always this
# default one, since client-side routes have no extension and don't match
# /assets/* or /api/*). Making short-TTL HTML the default and requiring
# /assets/* to opt into the long TTL means any future unhashed root file
# is safe by default rather than accidentally cached for a year.
resource "aws_cloudfront_cache_policy" "html" {
  name        = "undergroundbb-html-${terraform.workspace}"
  default_ttl = 60
  max_ttl     = 300
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    cookies_config {
      cookie_behavior = "none"
    }
    headers_config {
      header_behavior = "none"
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

# CachingDisabled (AWS's own managed policy, id below) for /api/* -- every
# request must reach the Lambda, since responses are per-session and
# per-user.
data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

# Critical (#8's own text): CloudFront strips cookies and most headers by
# default. The API's only credential is the session cookie DESIGN.md
# describes (HttpOnly/Secure/SameSite=Lax, issued by POST /auth/login) --
# without this policy forwarding it, every authenticated request would look
# logged-out at the origin, and silently: no error, just an API that always
# behaves as an anonymous caller. This is named in #8's own body as the
# likely cause of past trouble on a sibling project (see notoriousmcp's
# fix/cloudfront-* branches, none of which reached its main -- notoriousmcp
# fronts API Gateway directly rather than through CloudFront, so there was
# no working precedent to mirror here; this policy is this project's own).
#
# Host is explicitly excluded via allExcept rather than forwarded --
# confirmed live, not just reasoned about: "allViewer" DOES forward the
# viewer's Host (d1ofodh9sft65y.cloudfront.net) to the origin verbatim, and
# a Lambda Function URL validates Host against its own domain
# (*.lambda-url.<region>.on.aws). A mismatched Host 403s
# (AccessDeniedException) at the Function URL itself -- confirmed by
# replaying the exact request with the CloudFront distribution's Host
# header against the Function URL directly. Because 403 is on
# CustomErrorResponses' list below, that error was silently rewritten to
# /index.html and served from the *frontend* origin instead -- every /api/*
# request 403'd from S3, not the Lambda, with no indication in the response
# that Host was the cause. Excluding just Host (not narrowing further) still
# forwards everything else a real API needs -- Content-Type, Authorization
# if ever added, etc. -- without re-deriving a whitelist by hand.
resource "aws_cloudfront_origin_request_policy" "api" {
  name = "undergroundbb-api-${terraform.workspace}"

  cookies_config {
    cookie_behavior = "all"
  }

  headers_config {
    header_behavior = "allExcept"
    headers {
      items = ["Host"]
    }
  }

  query_strings_config {
    query_string_behavior = "all"
  }
}

# SPA fallback (#8), rewritten at viewer-request rather than via
# custom_error_response -- round 1 review found custom_error_response is
# distribution-wide, not per-behavior, so a 403/404 entry for the SPA
# fallback also intercepted the API's own 403s/404s and silently served
# them from the frontend/S3 origin instead of the Lambda (confirmed live:
# a real Lambda 404 on /api/nope came back as an S3 AccessDenied). That's
# the same silent-misdirection shape as the Host bug this PR already fixed,
# just at the error-response layer instead of the request layer.
#
# This function only ever touches request.uri, and is associated with the
# default cache behavior alone (not /api/* or /assets/*), so it can never
# affect the API *origin* regardless of what CloudFront does with error
# responses -- the fix removes the shared distribution-wide mechanism
# entirely rather than trying to carve API paths out of it. "Extensionless"
# (no "." in the final path segment) is the SPA-routing heuristic: every
# client-side route matches, every real static asset in this bucket doesn't
# (see functions/spa_index_rewrite.js for two known-and-accepted caveats).
#
# Being off /api/*'s behavior is not the same as being out of the API's
# *path space*, though -- round 2 review found the bare path /api (no
# trailing slash) doesn't match the "/api/*" pattern, falls through to this
# default behavior, and got rewritten to /index.html and served from S3.
# The function itself now guards this explicitly (see its own comment) --
# belt-and-braces with the behavior-association scoping here, deliberately,
# since the two controls fail independently and this bug is exactly what
# happens when only one of them is relied on.
resource "aws_cloudfront_function" "spa_index_rewrite" {
  name    = "undergroundbb-spa-index-rewrite-${terraform.workspace}"
  runtime = "cloudfront-js-2.0"
  publish = true
  comment = "Rewrites extensionless paths to /index.html for SPA client-side routing (#8)."
  code    = file("${path.module}/functions/spa_index_rewrite.js")
}

# CSP from #8's own issue comment (originally specified in #1 review round
# 28). Four directives are load-bearing for specific reasons the comment
# spells out -- see docs/THREAT_MODEL.md, "Why custom themes are JSON, not
# CSS" -- and none of the four should be widened even to fix a CSP error
# during implementation:
#   - script-src 'wasm-unsafe-eval', never 'unsafe-eval': Argon2id runs in
#     WebAssembly, and 'unsafe-eval' would silently remove the protection
#     the threat model calls total compromise if hit.
#   - connect-src 'self': bounds where a compromised/malicious bundle can
#     exfiltrate to; pairs with subresource integrity (limitation 1) rather
#     than substituting for it.
#   - base-uri 'none': closes <base> hijacking of relative script URLs,
#     which otherwise routes around script-src 'self'.
#   - frame-ancestors 'none': closes clickjacking, the other route to the
#     same false-fingerprint outcome the theme-as-JSON restriction defends
#     against for #65's fingerprint-verification UI.
# Served as a CloudFront response headers policy applied to every behavior
# (both origins), since a stolen-cookie or injected-script outcome is a risk
# on the API path too, not just the static SPA.
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "undergroundbb-security-headers-${terraform.workspace}"

  security_headers_config {
    content_security_policy {
      override = true
      content_security_policy = join("; ", [
        "default-src 'none'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ])
    }
  }
}

resource "aws_cloudfront_distribution" "main" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "undergroundbb-${terraform.workspace}"
  # Round 1 review, confirmed live (DistributionConfig.DefaultRootObject was
  # "" on the deployed distribution): without this, "/" asked S3 for the
  # empty key, 403'd, and only rendered the SPA via the custom_error_response
  # fallback that round 1 also asked to be removed. With it, "/" is a normal
  # cache hit on the default behavior instead of going through an error path.
  default_root_object = "index.html"

  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "frontend"
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  # Function URLs are plain HTTPS endpoints, not an S3/OAC-style origin --
  # custom_origin_config with HTTPS-only matches how every other CloudFront
  # custom origin (API Gateway, ALB, etc.) is configured.
  origin {
    domain_name = replace(replace(aws_lambda_function_url.main.function_url, "https://", ""), "/", "")
    origin_id   = "api"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # Default behavior serves the SPA shell -- short-TTL html cache policy,
  # and the only behavior the SPA-rewrite function is associated with. Any
  # request that doesn't match /assets/* or /api/* below lands here,
  # including every client-side route the function rewrites to /index.html.
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "frontend"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.html.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_index_rewrite.arn
    }
  }

  # Vite's hashed build output opts into the year-long cache explicitly --
  # everything else (index.html, favicon.svg, any future unhashed root
  # file) gets the default behavior's short TTL instead. Inverted from this
  # PR's original shape (long-TTL default + a near-unreachable /index.html
  # behavior) per round 1 review: path_pattern matches the request URI as
  # received, and the SPA rewrite happens before behavior selection, so a
  # behavior scoped to literally "/index.html" almost never actually fired.
  ordered_cache_behavior {
    path_pattern           = "/assets/*"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "frontend"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.static_assets.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # Two behaviors, not one, because CloudFront path patterns have no
  # alternation -- "/api/*" cannot also express the bare path "/api" (no
  # trailing slash) in a single pattern. Discovered in round 2 review: an
  # early-return guard was added to spa_index_rewrite.js for "/api", but
  # that fix alone turned out not to close the gap -- cache-behavior
  # selection happens *before* any associated function runs, keyed on the
  # original request path, so a request for the bare "/api" was already
  # dispatched to the default behavior (and the frontend/S3 origin) before
  # the function had any chance to act on it. The function guard stops the
  # request from being silently rewritten into a 200-with-SPA-content; this
  # second behavior is what actually routes it to the right origin. Both
  # are kept: the guard is still correct defense for anything that reaches
  # the function with an /api-prefixed uri, and this behavior is what
  # prevents /api from reaching the function at all.
  # Both API behaviors refuse plaintext (https-only) rather than redirecting
  # it the way the frontend behaviors above do (redirect-to-https) --
  # flagged as an undocumented inconsistency in round 3 review, deliberate
  # but worth writing down so a future reader doesn't "fix" it into
  # matching the frontend. A session-cookie-bearing request that somehow
  # ends up on http:// should error immediately rather than being
  # redirected -- a redirect is one more network hop where the cookie has
  # already been sent in the clear once. The frontend has no such
  # credential to protect, so a redirect there is pure convenience with no
  # cost.
  ordered_cache_behavior {
    path_pattern           = "/api"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"
    compress               = true

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.api.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  ordered_cache_behavior {
    path_pattern           = "/api/*"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"
    compress               = true

    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.api.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # No custom_error_response: SPA fallback is handled entirely by the
  # viewer-request function rewriting the path before origin selection (see
  # aws_cloudfront_function.spa_index_rewrite's comment), specifically so
  # that a distribution-wide error rewrite can never intercept /api/*'s own
  # 403s/404s the way it did before round 1 review. A genuine missing static
  # asset under /assets/* (a bad deploy, a stale reference) now surfaces its
  # real S3 403 instead of being masked as a 200 -- an accurate error rather
  # than a silently-wrong success.

  # #9: the custom domain, once acm.tf's certificate + apex alias records
  # land. Referencing the *_validation resource (not aws_acm_certificate.main
  # directly) so a plan/apply here can't attach a certificate ACM hasn't
  # actually finished validating yet.
  aliases = [var.domain_name]

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.main.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.main.domain_name
  description = "The distribution's own *.cloudfront.net domain. Still resolves and serves the app after #9 (acm.tf's apex alias records point var.domain_name at this same distribution) -- kept as an output since it's occasionally useful to hit directly, bypassing DNS."
}

output "cloudfront_distribution_id" {
  value       = aws_cloudfront_distribution.main.id
  description = "Needed for CI to invalidate the cache (e.g. /index.html, /*) after each frontend deploy."
}
