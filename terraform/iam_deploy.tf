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

# Scoped to exactly the resources terraform/ and terraform/bootstrap/ create
# today (#4-#6) -- not the eventual #7-#11 surface (S3 frontend bucket,
# CloudFront, ACM, WAF), which get their own statements added as each lands,
# same incremental approach as notoriousmcp's iam_deploy.tf grew resource by
# resource rather than pre-granting a wide policy up front.
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

  # Terraform state backend (the bucket + lock table terraform/bootstrap/
  # creates). Lock table name is a fixed literal there, not
  # workspace-derived, so it's referenced the same way here.
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.state_bucket}",
      "arn:aws:s3:::${var.state_bucket}/*",
    ]
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
