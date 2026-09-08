# Main infrastructure, split across this file and the resource-scoped files
# alongside it (dynamodb.tf, and more as #6-#11 land). State lives in the S3
# bucket + DynamoDB lock table terraform/bootstrap/ creates (#4) — bucket,
# table, and region are supplied at init time rather than hardcoded here,
# since bucket/table names include the AWS account id and region is derived
# from the bootstrap's own (overridable) output. See the README's "Deploying"
# section for the init command.

terraform {
  required_version = ">= 1.15"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # >= 6.28.0 for aws_lambda_permission's invoked_via_function_url --
      # lambda.tf's Function URL policy needs the lambda:InvokedViaFunctionUrl
      # condition key, which the v5 provider line cannot express at all (the
      # attribute was added in 6.28.0). Confirmed the v5->v6 breaking changes
      # (OpsWorks removal, aws_eip's vpc -> domain, SimpleDB removal) don't
      # touch anything this module manages.
      version = ">= 6.28.0, < 7.0"
    }
  }

  backend "s3" {
    key = "undergroundbb/terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region
}
