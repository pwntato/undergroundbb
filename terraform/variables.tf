variable "aws_region" {
  type        = string
  default     = "us-west-2"
  description = "Region for this project's infrastructure. ACM (#9) is the one exception — CloudFront requires its certificate in us-east-1 regardless of this value."
}

variable "state_bucket" {
  type        = string
  description = "State bucket name, from terraform/bootstrap's state_bucket output. Needed as plan-time data (not just a -backend-config flag) because the deploy role's own policy scopes itself to this bucket."
}
