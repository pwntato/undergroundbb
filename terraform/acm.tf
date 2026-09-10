# #9: ACM certificate + DNS for the CloudFront distribution (#8), plus the
# apex alias record that actually points the domain at it.
#
# The hosted zone is looked up, not created: undergroundbb.com was
# registered directly through Route 53 Registrar on 2026-09-02, outside
# Terraform (unlike notoriousmcp's route53.tf, which registers its own
# domain via aws_route53domains_registered_domain -- that pattern doesn't
# apply here, this domain already exists in the account). Managing it as a
# data source rather than an aws_route53_zone resource means a `terraform
# destroy` here can never delete the zone or de-register the domain.
data "aws_route53_zone" "main" {
  name = var.domain_name
}

# us-east-1, via main.tf's aliased provider -- CloudFront requires its
# certificate there regardless of var.aws_region (see that provider's own
# comment, and the README's "Deploying" section).
resource "aws_acm_certificate" "main" {
  provider          = aws.use1
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = data.aws_route53_zone.main.zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
  # Certificate renewal can add new validation options for the same
  # domain_name key that already has a live record -- allow_overwrite avoids
  # a duplicate-record apply failure in that case, matching the risk
  # ACM's own docs call out for DNS validation via IaC.
  allow_overwrite = true
}

# certificate_validation's own resource (rather than referencing
# aws_acm_certificate.main directly in cloudfront.tf) blocks apply until ACM
# actually confirms the CNAME, so a first-ever apply here waits out
# propagation instead of racing CloudFront into referencing a still-pending
# certificate ARN.
resource "aws_acm_certificate_validation" "main" {
  provider                = aws.use1
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Points the apex domain at the distribution. www/other subdomains are out
# of scope for #9 -- only the apex is wired up; a "www" alias (or redirect)
# is a separate, later decision, not implied by this issue's text.
resource "aws_route53_record" "apex" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

# IPv6 counterpart -- the distribution already has is_ipv6_enabled = true
# (cloudfront.tf), so an AAAA alias is free to add and keeps IPv6-only
# resolvers from falling back to a missing record.
resource "aws_route53_record" "apex_ipv6" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}

output "domain_name" {
  value       = var.domain_name
  description = "The custom domain the app is served from, once this and cloudfront.tf's aliases/viewer_certificate land."
}
