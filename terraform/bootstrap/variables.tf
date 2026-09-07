variable "aws_region" {
  type        = string
  default     = "us-west-2"
  description = "Region for the state bucket and lock table, and the default region for the rest of the project's infrastructure. ACM (#9) is the one exception — CloudFront requires its certificate in us-east-1 regardless of this value."
}

variable "adopt_existing_state" {
  type        = bool
  default     = true
  description = "Adopt the pre-existing state bucket and lock table in account 350195739155 instead of creating them. Set to false when bootstrapping a different AWS account, where nothing exists yet to import — the default (true) would otherwise fail with \"Cannot import non-existent remote object\"."
}
