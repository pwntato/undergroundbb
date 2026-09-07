# One-time bootstrap: creates the S3 bucket and DynamoDB lock table that hold
# Terraform remote state for the rest of this project (terraform/, once
# #5-#11 land). Run once per AWS account — see the README for the command.
#
# This module's own state is local (no backend block below): it has to exist
# before there's anywhere remote to put it. It's small and safe to keep local
# — bootstrapping the bootstrap would be its own kind of absurd.
#
# Pattern matches notoriousmcp's terraform/bootstrap/ (a sibling project in
# the same AWS account): same resource set, same account-id-suffixed naming
# so the bucket name is globally unique without a random suffix.

terraform {
  required_version = ">= 1.15"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# This module's state is local and gitignored (see the comment above), so it
# exists only on whichever machine ran the first apply -- never in the repo.
# Without these, a second maintainer, a new laptop, or CI starting from an
# empty state directory would plan to recreate resources that already exist
# in the account, and apply would fail on BucketAlreadyOwnedByYou /
# ResourceInUseException instead of converging. `terraform apply` adopts the
# existing resources into local state on first run instead; once adopted,
# Terraform drops each import automatically and subsequent applies are a
# normal no-op plan.
import {
  to = aws_s3_bucket.tf_state
  id = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"
}

import {
  to = aws_dynamodb_table.tf_state_lock
  id = "undergroundbb-tfstate-lock"
}

resource "aws_s3_bucket" "tf_state" {
  bucket = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"

  # Losing this bucket loses every environment's Terraform state. Terraform
  # itself must not be the thing that deletes it.
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket                  = aws_s3_bucket.tf_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "tf_state_lock" {
  name         = "undergroundbb-tfstate-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}

output "state_bucket" {
  value = aws_s3_bucket.tf_state.bucket
}

output "state_lock_table" {
  value = aws_dynamodb_table.tf_state_lock.name
}

output "aws_region" {
  value = var.aws_region
}
