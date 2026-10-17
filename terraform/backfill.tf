# The one-off CreatedAt backfill (cmd/backfill, internal/backfill; issue #253):
# a Lambda that nothing schedules. It is invoked by hand to coarsen the
# full-resolution CreatedAt on rows written before #147, first as a dry run
# and then, once var.backfill_dry_run is false, for real. It has its own
# execution role so it holds none of the web Lambda's or the purge's
# permissions, and they hold none of its. Delete this file, the deploy_backfill
# policy in iam_deploy.tf and the cmd/backfill build steps once the run is done.
#
# Names are built from local.backfill_name, not from the resources' own
# attributes, wherever iam_deploy.tf's deploy_backfill policy needs to name
# them: that policy must exist before these resources do (see its comment).
locals {
  backfill_name = "undergroundbb-backfill-${terraform.workspace}"
}

resource "aws_iam_role" "backfill" {
  name               = local.backfill_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  depends_on = [aws_iam_role_policy.deploy_backfill]
}

# Exactly the DynamoDB actions internal/backfill uses and nothing else: a
# table Scan to find the rows, and UpdateItem to rewrite them. No Query, no
# Get, no Delete, no Put, and no index access. internal/backfill's
# iam_test.go pins this list to the code in both directions.
data "aws_iam_policy_document" "backfill_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.backfill.arn}:*"]
  }

  statement {
    actions = [
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]
    resources = [aws_dynamodb_table.main.arn]
  }
}

resource "aws_iam_role_policy" "backfill" {
  name   = "undergroundbb-backfill-policy"
  role   = aws_iam_role.backfill.id
  policy = data.aws_iam_policy_document.backfill_policy.json
}

resource "aws_cloudwatch_log_group" "backfill" {
  name              = "/aws/lambda/${local.backfill_name}"
  retention_in_days = 14

  depends_on = [aws_iam_role_policy.deploy_backfill]
}

resource "aws_lambda_function" "backfill" {
  function_name    = local.backfill_name
  role             = aws_iam_role.backfill.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  filename         = "${path.root}/../backfill.zip"
  source_code_hash = filebase64sha256("${path.root}/../backfill.zip")
  # One paginated Scan of the table. A run that hits the timeout fails loudly
  # and is safe to invoke again: every write is conditional and idempotent.
  timeout     = 300
  memory_size = 256

  # cmd/backfill fails safe: anything other than the exact string "false" is a
  # dry run, and an invocation payload can force a dry run but never turn
  # writing on. tostring(true) is "true", so writing needs
  # var.backfill_dry_run = false.
  environment {
    variables = {
      TABLE_NAME       = aws_dynamodb_table.main.name
      BACKFILL_DRY_RUN = tostring(var.backfill_dry_run)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.backfill,
    aws_iam_role_policy.backfill,
    aws_iam_role_policy.deploy_backfill,
  ]
}

output "backfill_function_name" {
  value       = aws_lambda_function.backfill.function_name
  description = "The CreatedAt backfill Lambda (#253), for a manual invocation. The report is the response and is also logged."
}
