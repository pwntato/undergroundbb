# The Go binary, built and zipped by CI (see .github/workflows/deploy.yml)
# before this file's terraform apply runs. See lambda.zip's local placeholder
# note below for why the file must exist even to `terraform validate`.
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "undergroundbb-lambda-${terraform.workspace}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

# Scoped to exactly the table this Lambda uses and its one GSI, per #6.
# cmd/lambda's handlers use this read/write surface (the single-table data
# model in DESIGN.md), plus DescribeTable: cmd/lambda's cold start pings the
# table (#86) so a wrong table name or missing grant fails init instead of
# reporting healthy and 500ing on the first real request. No Scan: the
# single-table design's access patterns are all PK/SK or GSI1 lookups: an
# unbounded Scan is never the right tool here, so it's deliberately absent
# rather than granted "in case."
data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      # Transactions are authorized per item action, so a ConditionCheck inside
      # TransactWriteItems needs this. DynamoDB Local does not enforce IAM, so
      # only prod showed the AccessDenied.
      "dynamodb:ConditionCheckItem",
      "dynamodb:Query",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:TransactGetItems",
      "dynamodb:TransactWriteItems",
      "dynamodb:DescribeTable",
    ]
    resources = [
      aws_dynamodb_table.main.arn,
      "${aws_dynamodb_table.main.arn}/index/GSI1",
    ]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "undergroundbb-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/undergroundbb-${terraform.workspace}"
  retention_in_days = 14
}

# SESSION_SECRET -- see internal/config.Config.SessionSecret and
# internal/session's own package doc. Generated once per workspace (any
# two workspaces would get independent, unrelated secrets, which is correct:
# a session issued by one must never verify against the other) and stored
# directly in the Lambda's environment, the same mechanism as every other
# config value in this file. That means it is visible in Terraform state and
# the Lambda console -- the standard tradeoff for an env-var secret, accepted
# here rather than adding Secrets Manager (a new resource, a new IAM grant,
# and a fetch-at-cold-start code path) for a single value with no rotation
# requirement beyond "generate a new one," which `terraform taint
# random_id.session_secret && terraform apply` already does.
#
# byte_length = 32 matches internal/session's HMAC-SHA256 key size
# expectations (any length works for HMAC, but 32 bytes is the natural
# choice alongside AES-256/Ed25519 elsewhere in this project). hex, not
# base64: internal/config.sessionSecretFromEnv decodes with
# encoding/hex specifically, so the two must agree.
resource "random_id" "session_secret" {
  byte_length = 32

  # Changing byte_length would force recreation regardless; keepers is
  # otherwise unused; here only so a future intentional rotation has an
  # obvious, discoverable lever (bump keepers.rotation to force a new value)
  # rather than needing `terraform taint` looked up separately.
  keepers = {
    rotation = "1"
  }
}

# Shared secret CloudFront sends as X-Origin-Verify and cmd/lambda requires (#103).
# random_password rather than random_id so it is marked sensitive in plan output.
# It is in Terraform state and the Lambda environment, the same accepted
# tradeoff as session_secret above. To rotate, bump keepers.rotation; the apply
# updates the Lambda and the distribution together, and requests can get a 403
# until CloudFront finishes deploying the new header (a few minutes).
resource "random_password" "origin_verify" {
  length  = 48
  special = false

  keepers = {
    rotation = "1"
  }
}

resource "aws_lambda_function" "main" {
  function_name    = "undergroundbb-${terraform.workspace}"
  role             = aws_iam_role.lambda.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  filename         = "${path.root}/../lambda.zip"
  source_code_hash = filebase64sha256("${path.root}/../lambda.zip")
  timeout          = 10
  memory_size      = 256

  # Caps how fast the API can run, and so what a flood can cost (costguard.tf).
  # cmd/costguard sets this to 0 to stop the API; a deploy restores it.
  reserved_concurrent_executions = var.web_max_concurrency

  # #113: SITE_NAME/DOMAIN/REGISTRATION_POLICY/ALLOW_GROUP_EXPIRATION_OFF/
  # DEFAULT_EXPIRATION_DAYS previously had no Terraform variable at all, so a
  # deployed Lambda could never actually be configured with them -- it always
  # got internal/config's compiled-in defaults regardless of what an operator
  # wanted. DOMAIN reads local.domain_name (locals.tf) rather than a variable
  # of its own, since that's already the per-workspace value CloudFront's own
  # alias records point at (acm.tf) -- a second, independently-settable DOMAIN
  # value here could silently disagree with it. The bool and number variables
  # need tostring(): Lambda environment variables are string-only: string,
  # true, and 30 all interpolate as their JSON literal here, which is
  # what internal/config's BoolEnvOrDefault/Int64EnvOrDefault (via
  # strconv.ParseBool/ParseInt) expect on the read side.
  environment {
    variables = {
      TABLE_NAME                  = aws_dynamodb_table.main.name
      ENVIRONMENT                 = terraform.workspace
      SITE_NAME                   = var.site_name
      DOMAIN                      = local.domain_name
      REGISTRATION_POLICY         = var.registration_policy
      ALLOW_GROUP_EXPIRATION_OFF  = tostring(var.allow_group_expiration_off)
      DEFAULT_EXPIRATION_DAYS     = tostring(var.default_expiration_days)
      MAX_ROTATING_GROUP_MEMBERS  = tostring(var.max_rotating_group_members)
      KEY_ROTATION_COOLDOWN_HOURS = tostring(var.key_rotation_cooldown_hours)
      MAX_POST_TITLE_BYTES        = tostring(var.max_post_title_bytes)
      MAX_POST_BODY_BYTES         = tostring(var.max_post_body_bytes)
      SESSION_SECRET              = random_id.session_secret.hex
      ORIGIN_VERIFY_SECRET        = random_password.origin_verify.result
      SESSION_TTL_HOURS           = tostring(var.session_ttl_hours)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# authorization_type = "NONE" per #6 -- CloudFront (#8) is the intended
# access control boundary, same split as DESIGN.md's infrastructure diagram
# (CloudFront + WAF in front, Function URL behind). The URL itself is still
# addressable, so cmd/lambda answers 403 to any request that lacks the
# X-Origin-Verify secret CloudFront adds (#103).
resource "aws_lambda_function_url" "main" {
  function_name      = aws_lambda_function.main.function_name
  authorization_type = "NONE"
}

# When you create a NONE-auth function URL through the console or SAM, AWS
# bundles both required resource-policy statements in for you. Terraform
# calls the raw API, which only gets the lambda:InvokeFunctionUrl half of
# that pair -- confirmed against a real deployment of this exact resource,
# which 403'd at the edge (AccessDeniedException) despite AuthType: NONE and
# a resource-based policy that looked complete. Since October 2025, AWS also
# requires this second statement, lambda:InvokeFunction, gated on the
# lambda:InvokedViaFunctionUrl condition key so it can't be used to invoke
# the function by any path other than the URL. Without it, every request
# 403s regardless of AuthType.
resource "aws_lambda_permission" "function_url_invoke" {
  statement_id             = "FunctionURLInvokeAllowPublicAccess"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.main.function_name
  principal                = "*"
  invoked_via_function_url = true
}

