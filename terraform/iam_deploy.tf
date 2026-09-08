data "aws_caller_identity" "current" {}

# GitHub's OIDC provider is per-AWS-account, not per-project, and one already
# exists in this account (created by notoriousmcp's own deploy role setup) --
# creating a second one for the same URL fails with EntityAlreadyExists.
# Referenced by ARN rather than declared as a resource for exactly that
# reason: nothing here should manage another project's provider or delete it
# out from under notoriousmcp's own deploy role.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_iam_policy_document" "deploy_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:pwntato/undergroundbb:environment:production"]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "undergroundbb-deploy-${terraform.workspace}"
  assume_role_policy = data.aws_iam_policy_document.deploy_assume_role.json
}

# Scoped to exactly what terraform/ creates today (#4-#7), plus read/write
# access to the state backend terraform/bootstrap/ provisions -- not a
# blanket policy, and not pre-granted access to #8-#11's future resources,
# which get their own statements added as each lands, same incremental
# approach as notoriousmcp's iam_deploy.tf grew resource by resource rather
# than pre-granting a wide policy up front. Bootstrap itself (creating the
# state bucket/lock table) stays a manual, human-run step and is
# deliberately outside this role's reach -- this policy grants none of
# s3:CreateBucket/PutBucketVersioning/PutEncryptionConfiguration/
# PutBucketPublicAccessBlock or dynamodb:CreateTable on the state bucket or
# lock table specifically (it does grant several of those same action names
# on the #7 frontend bucket below, which this role does manage).
data "aws_iam_policy_document" "deploy_policy" {
  statement {
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:ListTagsOfResource",
    ]
    resources = [aws_dynamodb_table.main.arn]
  }

  statement {
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:UpdateTable",
      "dynamodb:DeleteTable",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = [aws_dynamodb_table.main.arn]
  }

  statement {
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetOpenIDConnectProvider",
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
    ]
    resources = [aws_iam_role.deploy.arn, aws_iam_role.lambda.arn]
  }

  # lambda:CreateFunction and lambda:UpdateFunctionConfiguration both require
  # iam:PassRole on the execution role being attached -- assigning a role to
  # a function is a privilege delegation AWS gates separately from creating
  # the role itself. Scoped to the lambda execution role only, and further
  # restricted to the Lambda service so this role can never hand the
  # execution role to anything else.
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.lambda.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    actions   = ["logs:DescribeLogGroups", "logs:ListTagsForResource"]
    resources = ["*"]
  }

  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:PutRetentionPolicy",
      "logs:DeleteLogGroup",
      "logs:TagLogGroup",
      "logs:TagResource",
    ]
    resources = ["arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:*"]
  }

  statement {
    actions = [
      "lambda:GetFunction",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:GetPolicy",
      "lambda:ListVersionsByFunction",
      "lambda:CreateFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:DeleteFunction",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:GetFunctionUrlConfig",
      "lambda:CreateFunctionUrlConfig",
      "lambda:UpdateFunctionUrlConfig",
      "lambda:DeleteFunctionUrlConfig",
      "lambda:AddPermission",
      "lambda:RemovePermission",
    ]
    resources = [aws_lambda_function.main.arn]
  }

  # The frontend bucket itself (#7) -- separate from the state-backend
  # statements below, which are scoped to var.state_bucket. No object-level
  # actions here: uploading the built SPA is a separate CI step (#8), not
  # something this deploy role's own terraform apply does.
  #
  # s3:Get*/s3:List* rather than an enumerated read list: a refresh of
  # aws_s3_bucket alone calls eleven distinct Get/List/Head operations
  # (ACL, location, policy, website, CORS, logging, request payment,
  # acceleration, replication, object-lock config, plus ListBucket), and
  # enumerating them only buys the ability to miss one -- which is what an
  # earlier version of this statement did. notoriousmcp's iam_deploy.tf hit
  # the identical gap and settled on this same fix; matching it here rather
  # than re-deriving a narrower list this file mirrors deliberately anyway.
  # DeleteBucketEncryption/DeletePublicAccessBlock are for removing those
  # configs (e.g. on a destroy, or if a block is ever taken out of config),
  # not just adding them.
  statement {
    actions = [
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:Get*",
      "s3:List*",
      "s3:PutBucketPublicAccessBlock",
      "s3:DeletePublicAccessBlock",
      "s3:PutEncryptionConfiguration",
      "s3:DeleteBucketEncryption",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:DeleteLifecycleConfiguration",
      "s3:PutBucketTagging",
    ]
    resources = [aws_s3_bucket.frontend.arn]
  }

  # Terraform state backend (the bucket + lock table terraform/bootstrap/
  # creates). Lock table name is a fixed literal there, not
  # workspace-derived, so it's referenced the same way here.
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.state_bucket}"]
  }

  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["arn:aws:s3:::${var.state_bucket}/*"]
  }

  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:DeleteItem",
    ]
    resources = ["arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/undergroundbb-tfstate-lock"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "undergroundbb-deploy-policy"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy_policy.json
}

output "deploy_role_arn" {
  value       = aws_iam_role.deploy.arn
  description = "Set this as the AWS_DEPLOY_ROLE_ARN GitHub Actions environment secret (production)."
}
