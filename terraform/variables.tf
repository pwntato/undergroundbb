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
# Terraform-managed as this file's own #9 issue text originally asked for.
variable "domain_name" {
  type        = string
  default     = "undergroundbb.com"
  description = "Apex domain CloudFront is fronted by (#9). Single workspace today (#11 hasn't landed), so no per-workspace subdomain split yet."
}
