# Main infrastructure, split across this file and the resource-scoped files
# alongside it (dynamodb.tf, and more as #6-#11 land). State lives in the S3
# bucket + DynamoDB lock table terraform/bootstrap/ creates (#4) — bucket and
# table names include the AWS account id, so they're supplied at init time
# rather than hardcoded here:
#
#   terraform init \
#     -backend-config="bucket=<state bucket from bootstrap output>" \
#     -backend-config="dynamodb_table=<state lock table from bootstrap output>" \
#     -backend-config="region=us-west-2"
#
# See the README's "Deploying" section.

terraform {
  required_version = ">= 1.15"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    key = "undergroundbb/terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region
}
