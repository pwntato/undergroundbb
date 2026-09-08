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
      source = "hashicorp/aws"
      # Matches terraform/main.tf's constraint (see its comment) -- kept in
      # sync so this account isn't managed by two different provider majors.
      # This module's own resources (S3, DynamoDB) are unaffected either way.
      version = ">= 6.28.0, < 7.0"
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
# in the account, and apply would fail outright for the bucket and table
# (BucketAlreadyOwnedByYou / ResourceInUseException) or silently overwrite
# the three S3 sub-resource settings with byte-identical config that merely
# happens to match today -- if the live bucket ever drifted (someone enabled
# a KMS key, say), a fresh-clone apply would revert it with no `~` in the
# plan to show it, because Terraform would think it was creating, not
# correcting. All five resources need an import, not just the two that fail
# loudly without one.
#
# Once adopted, an import whose target is already in state is a silent
# no-op on later plans -- Terraform does not remove the block or edit this
# file. These stay here deliberately: the state is local and per-machine, so
# the next fresh clone needs the same imports again.
#
# An import block is unconditional -- if its id doesn't resolve to a real
# object, plan fails outright ("Cannot import non-existent remote object")
# rather than falling back to a create. The ids follow the caller's own
# account (four interpolate data.aws_caller_identity.current.account_id; the
# fifth, a DynamoDB table name, is account-scoped by definition), so these
# adopt correctly in any account where the resources already exist -- but
# the very first bootstrap of an account has nothing to import, and needs
# var.create_new_state=true to skip them and create fresh. Every run after
# that first one, including later runs in that same account, leaves it at
# the default. See the README's "Deploying" section.
import {
  for_each = var.create_new_state ? toset([]) : toset(["x"])
  to       = aws_s3_bucket.tf_state
  id       = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"
}

import {
  for_each = var.create_new_state ? toset([]) : toset(["x"])
  to       = aws_s3_bucket_versioning.tf_state
  id       = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"
}

import {
  for_each = var.create_new_state ? toset([]) : toset(["x"])
  to       = aws_s3_bucket_server_side_encryption_configuration.tf_state
  id       = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"
}

import {
  for_each = var.create_new_state ? toset([]) : toset(["x"])
  to       = aws_s3_bucket_public_access_block.tf_state
  id       = "undergroundbb-tfstate-${data.aws_caller_identity.current.account_id}"
}

import {
  for_each = var.create_new_state ? toset([]) : toset(["x"])
  to       = aws_dynamodb_table.tf_state_lock
  id       = "undergroundbb-tfstate-lock"
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
