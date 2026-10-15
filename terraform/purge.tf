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

  # One execution at a time: an overlapping run is throttled (and dropped, see
  # the event invoke config below) instead of running on top of the live one.
  # Needs the account's unreserved pool to stay at or above AWS's floor of 100,
  # which the 1000 limit allows.
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

# Keeps a failed run from being retried on top of the next scheduled one.
# Reserved concurrency (above) prevents overlap; this stops the re-queueing.
# EventBridge invokes asynchronously and Lambda would otherwise retry a
# failed run.
# maximum_retry_attempts = 0 stops retries after a function error;
# maximum_event_age_in_seconds = 60 (the minimum) drops an invoke that was
# throttled or hit a Lambda system error instead of re-queueing it for the
# default 6 hours. A failed or dropped run just waits for the next schedule.
# Async delivery is still at-least-once, so a duplicate can run right after the
# first; it cannot run alongside it (reserved concurrency), and the purge is
# idempotent.
resource "aws_lambda_function_event_invoke_config" "purge" {
  function_name                = aws_lambda_function.purge.function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 60

  # Stated directly, like the other purge resources, rather than relying on
  # the transitive edge through the function: this apply adds the
  # event-invoke-config actions to deploy_purge and creates this resource
  # together, and only a direct dependency orders them.
  depends_on = [aws_iam_role_policy.deploy_purge]
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

# Alarms, so a purge that is failing, dropped, or not running at all is noticed
# instead of only visible in CloudWatch. The schedule is hourly.
#   errors:      runs that threw (cmd/purge returns an error from a failed plan
#                or delete; timeouts count too).
#   dropped:     scheduled invokes Lambda gave up on: throttled past
#                maximum_event_age_in_seconds, or, because retries are off,
#                any function error. So one failed run trips both errors and
#                dropped and sends two notifications; that is accepted.
#   not_running: fewer than one invocation in three hours. Silence is the
#                failure here, so missing data is breaching; the alarm can
#                fire once right after the first deploy, until the first
#                scheduled run. Catches a disabled rule or a broken
#                lambda_permission, which produce no Errors at all.
# For the first two a one-hour period with a threshold of 1 fires on the first
# bad run, and missing data is "not breaching": no invocation is normal
# between schedules.
resource "aws_sns_topic" "purge_alarms" {
  name = "${local.purge_name}-alarms"

  depends_on = [aws_iam_role_policy.deploy_purge]
}

# The address comes from the ALARM_EMAIL secret (deploy.yml), not a local
# tfvars: every push to main applies, and would destroy a subscription that only
# a local apply created. A secret and a sensitive variable because the repo is
# public: logs and plan output show it masked.
resource "aws_sns_topic_subscription" "purge_alarms_email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.purge_alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "purge" {
  for_each = {
    errors = {
      metric     = "Errors"
      statistic  = "Sum"
      period     = 3600
      comparison = "GreaterThanOrEqualToThreshold"
      threshold  = 1
      missing    = "notBreaching"
    }
    dropped = {
      metric     = "AsyncEventsDropped"
      statistic  = "Sum"
      period     = 3600
      comparison = "GreaterThanOrEqualToThreshold"
      threshold  = 1
      missing    = "notBreaching"
    }
    not_running = {
      metric     = "Invocations"
      statistic  = "Sum"
      period     = 10800
      comparison = "LessThanThreshold"
      threshold  = 1
      missing    = "breaching"
    }
  }

  alarm_name          = "${local.purge_name}-${each.key}"
  alarm_description   = "Test-account purge: ${each.value.metric} on ${local.purge_name} (${each.key})."
  namespace           = "AWS/Lambda"
  metric_name         = each.value.metric
  dimensions          = { FunctionName = aws_lambda_function.purge.function_name }
  statistic           = each.value.statistic
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = each.value.comparison
  treat_missing_data  = each.value.missing
  alarm_actions       = [aws_sns_topic.purge_alarms.arn]

  depends_on = [aws_iam_role_policy.deploy_purge]
}
