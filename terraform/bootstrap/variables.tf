variable "aws_region" {
  type        = string
  default     = "us-west-2"
  description = "Region for the state bucket and lock table, and the default region for the rest of the project's infrastructure. ACM (#9) is the one exception — CloudFront requires its certificate in us-east-1 regardless of this value."
}

variable "create_new_state" {
  type        = bool
  default     = false
  description = "Set to true only for the very first bootstrap of an AWS account, where the state bucket and lock table don't exist yet to import — the default (false) assumes they're already there in whichever account you're authenticated to, and fails with \"Cannot import non-existent remote object\" if they aren't. Every run after that first one, including later runs in that same account, uses the default."
}
