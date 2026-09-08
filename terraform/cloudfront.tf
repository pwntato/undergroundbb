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
# every request is pure waste.
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
# SPA-fallback behavior below serves it for arbitrary client-side routes.
# Short TTL rather than zero: still cacheable at the edge, just revalidated
# often enough that a deploy is visible quickly.
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

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "frontend"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.static_assets.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  ordered_cache_behavior {
    path_pattern           = "/index.html"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "frontend"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = aws_cloudfront_cache_policy.html.id
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

  # SPA fallback (#8): a client-side route like /groups/abc has no matching
  # S3 key, so S3 returns 403 (OAC callers get 403, not 404, for a missing
  # key) which CloudFront rewrites to /index.html with a 200 rather than
  # surfacing the origin's error to the browser. Both codes are handled
  # since a public/anonymous request path could plausibly hit either.
  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.main.domain_name
  description = "The *.cloudfront.net domain serving the app. Temporary until #9's ACM cert + #10's custom domain replace it."
}

output "cloudfront_distribution_id" {
  value       = aws_cloudfront_distribution.main.id
  description = "Needed for CI to invalidate the cache (e.g. /index.html, /*) after each frontend deploy."
}
