# The test-account purge (cmd/purge, internal/db.PurgeTestAccounts): a second
# Lambda, run on a schedule, that removes accounts created by the automated
# smoke tests and everything they own. It has its own execution role rather
# than sharing the web Lambda's, so it holds none of the web Lambda's
# permissions and the web Lambda holds none of its.
#
# Names are built from local.purge_name, not from the resources' own
# attributes, wherever iam_deploy.tf's deploy_purge policy needs to name them:
# that policy must exist before these resources do (see its comment), so it
# cannot reference them without a dependency cycle.
locals {
  purge_name = "undergroundbb-purge-${terraform.workspace}"
}

resource "aws_iam_role" "purge" {
  name               = local.purge_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  depends_on = [aws_iam_role_policy.deploy_purge]
}

# Exactly the DynamoDB actions cmd/purge uses and nothing else: no Put, no
# Transact*, and no Scan -- candidates come from the GSI1 TESTACCOUNT
# partition by Query. internal/db/purge_iam_test.go pins this list to the
# code in both directions. No DescribeTable: cmd/purge does not Ping.
data "aws_iam_policy_document" "purge_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.purge.arn}:*"]
  }

  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchWriteItem",
    ]
    resources = [
      aws_dynamodb_table.main.arn,
      "${aws_dynamodb_table.main.arn}/index/GSI1",
    ]
  }
}

resource "aws_iam_role_policy" "purge" {
  name   = "undergroundbb-purge-policy"
  role   = aws_iam_role.purge.id
  policy = data.aws_iam_policy_document.purge_policy.json
}

resource "aws_cloudwatch_log_group" "purge" {
  name              = "/aws/lambda/${local.purge_name}"
  retention_in_days = 14

  depends_on = [aws_iam_role_policy.deploy_purge]
}

resource "aws_lambda_function" "purge" {
  function_name    = local.purge_name
  role             = aws_iam_role.purge.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  filename         = "${path.root}/../purge.zip"
  source_code_hash = filebase64sha256("${path.root}/../purge.zip")
  # A run examines at most PURGE_MAX_ACCOUNTS accounts, each a handful of
  # queries and batched deletes; a minute is generous, and a run that hits it
  # fails loudly and resumes on the next schedule.
  timeout     = 60
  memory_size = 256

  # One run at a time. EventBridge invokes asynchronously and Lambda retries a
  # failed run, so a retry could otherwise overlap the next scheduled run and
  # two purges would plan and delete the same accounts at once.
  reserved_concurrent_executions = 1

  # cmd/purge fails safe: anything other than the exact string "false" is a dry
  # run, and an invocation payload can force a dry run but never turn deletion
  # on. tostring(true) is "true", so deletion needs var.purge_dry_run = false.
  environment {
    variables = {
      TABLE_NAME    = aws_dynamodb_table.main.name
      PURGE_DRY_RUN = tostring(var.purge_dry_run)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.purge,
    aws_iam_role_policy.purge,
    aws_iam_role_policy.deploy_purge,
  ]
}

resource "aws_cloudwatch_event_rule" "purge" {
  name                = local.purge_name
  description         = "Runs the test-account purge."
  schedule_expression = var.purge_schedule

  depends_on = [aws_iam_role_policy.deploy_purge]
}

resource "aws_cloudwatch_event_target" "purge" {
  rule = aws_cloudwatch_event_rule.purge.name
  arn  = aws_lambda_function.purge.arn

  depends_on = [aws_iam_role_policy.deploy_purge]
}

resource "aws_lambda_permission" "purge_schedule" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.purge.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.purge.arn
}

output "purge_function_name" {
  value       = aws_lambda_function.purge.function_name
  description = "The test-account purge Lambda, for a manual dry-run invocation."
}
