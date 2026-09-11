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
# cmd/lambda's handlers don't yet call any DynamoDB operation (see
# internal/handlers -- only GET /api/health is registered today), so this is
# the full single-table read/write surface DESIGN.md's data model describes,
# not what's exercised yet. No Scan: the single-table design's access
# patterns are all PK/SK or GSI1 lookups: an unbounded Scan is never the
# right tool here, so it's deliberately absent rather than granted "in case."
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
      "dynamodb:Query",
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:TransactGetItems",
      "dynamodb:TransactWriteItems",
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
      TABLE_NAME                 = aws_dynamodb_table.main.name
      ENVIRONMENT                = terraform.workspace
      SITE_NAME                  = var.site_name
      DOMAIN                     = local.domain_name
      REGISTRATION_POLICY        = var.registration_policy
      ALLOW_GROUP_EXPIRATION_OFF = tostring(var.allow_group_expiration_off)
      DEFAULT_EXPIRATION_DAYS    = tostring(var.default_expiration_days)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# authorization_type = "NONE" per #6 -- CloudFront (#8) is the intended
# access control boundary, same split as DESIGN.md's infrastructure diagram
# (CloudFront + WAF in front, Function URL behind). Not yet enforced, though:
# #8 landed the distribution, but the Function URL itself remains directly
# reachable with none of CloudFront's response headers/TLS policy/future WAF
# applied -- tracked in #103 (shared-secret origin-verify header). Update
# this comment (or drop it) once #103 actually closes the gap.
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

