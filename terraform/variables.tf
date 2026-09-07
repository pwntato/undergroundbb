variable "aws_region" {
  type        = string
  default     = "us-west-2"
  description = "Region for this project's infrastructure. ACM (#9) is the one exception — CloudFront requires its certificate in us-east-1 regardless of this value."
}
