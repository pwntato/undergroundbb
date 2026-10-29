# The cost guard: caps what a flood can cost and trips a kill switch when
# spend or traffic crosses a limit. WAF's rate rules limit one source IP and
# CloudFront bills every request it serves, so nothing in front of the API
# bounds a distributed flood. What bounds it here:
#
#   1. aws_lambda_function.main's reserved concurrency (var.web_max_concurrency)
#      caps how fast the API can run, which caps Lambda and DynamoDB spend.
#   2. A CloudWatch alarm on the web Lambda's Invocations (minutes of lag).
#   3. An AWS Budget on actual monthly spend (hours of lag: Budgets data
#      updates a few times a day), the backstop.
#
# Both 2 and 3 publish to one SNS topic, which invokes cmd/costguard, which
# sets the web Lambda's reserved concurrency to 0. The static site stays up;
# the API answers 5xx until the switch is re-armed. A deploy re-arms it
# (terraform restores var.web_max_concurrency), so do not deploy while an
# attack is still running. By hand:
#   aws lambda put-function-concurrency --function-name <web> --reserved-concurrent-executions <n>
#
# What it does not cover: requests CloudFront or WAF answer without reaching
# the Lambda (blocked or cached) are billed at CloudFront and WAF rates and
# are not counted by the alarm; the Budget catches those, late.
#
# Names are built from local.costguard_name wherever iam_deploy.tf's
# deploy_costguard policy needs them, for the same reason as purge.tf.
locals {
  costguard_name = "undergroundbb-costguard-${terraform.workspace}"
}

resource "aws_iam_role" "costguard" {
  name               = local.costguard_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  depends_on = [aws_iam_role_policy.deploy_costguard]
}

# Exactly the one call cmd/costguard makes, on the one function it guards.
data "aws_iam_policy_document" "costguard_policy" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.costguard.arn}:*"]
  }

  statement {
    actions   = ["lambda:PutFunctionConcurrency"]
    resources = [aws_lambda_function.main.arn]
  }
}

resource "aws_iam_role_policy" "costguard" {
  name   = "undergroundbb-costguard-policy"
  role   = aws_iam_role.costguard.id
  policy = data.aws_iam_policy_document.costguard_policy.json
}

resource "aws_cloudwatch_log_group" "costguard" {
  name              = "/aws/lambda/${local.costguard_name}"
  retention_in_days = 14

  depends_on = [aws_iam_role_policy.deploy_costguard]
}

resource "aws_lambda_function" "costguard" {
  function_name    = local.costguard_name
  role             = aws_iam_role.costguard.arn
  handler          = "bootstrap"
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  filename         = "${path.root}/../costguard.zip"
  source_code_hash = filebase64sha256("${path.root}/../costguard.zip")
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      TARGET_FUNCTION = aws_lambda_function.main.function_name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.costguard,
    aws_iam_role_policy.costguard,
    aws_iam_role_policy.deploy_costguard,
  ]
}

resource "aws_sns_topic" "costguard" {
  name = local.costguard_name

  depends_on = [aws_iam_role_policy.deploy_costguard]
}

# CloudWatch alarms publish under the topic's default policy; Budgets needs
# its own statement. The default statement is restated because setting a
# policy replaces it.
data "aws_iam_policy_document" "costguard_topic" {
  statement {
    sid       = "AccountOwner"
    actions   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic", "sns:SetTopicAttributes", "sns:DeleteTopic", "sns:AddPermission", "sns:RemovePermission", "sns:Receive"]
    resources = [aws_sns_topic.costguard.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "Budgets"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.costguard.arn]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "costguard" {
  arn    = aws_sns_topic.costguard.arn
  policy = data.aws_iam_policy_document.costguard_topic.json
}

resource "aws_sns_topic_subscription" "costguard_lambda" {
  topic_arn = aws_sns_topic.costguard.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.costguard.arn
}

resource "aws_lambda_permission" "costguard_sns" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.costguard.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.costguard.arn
}

# The same address as the purge alarms, so a trip emails you. Confirm the
# subscription from the email AWS sends.
resource "aws_sns_topic_subscription" "costguard_email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.costguard.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_metric_alarm" "costguard_invocations" {
  alarm_name          = "${local.costguard_name}-invocations"
  alarm_description   = "Web Lambda invocations in 5 minutes crossed var.flood_invocations_per_5min: trips the cost kill switch (concurrency 0)."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = aws_lambda_function.main.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.flood_invocations_per_5min
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.costguard.arn]

  depends_on = [aws_iam_role_policy.deploy_costguard]
}

resource "aws_budgets_budget" "costguard" {
  name         = local.costguard_name
  budget_type  = "COST"
  limit_amount = tostring(var.cost_guard_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.costguard.arn]
  }

  depends_on = [aws_iam_role_policy.deploy_costguard, aws_sns_topic_policy.costguard]
}

output "costguard_function_name" {
  value       = aws_lambda_function.costguard.function_name
  description = "The cost kill switch Lambda: any invocation sets the web Lambda's reserved concurrency to 0."
}
