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
      # GitHub switched new repos (created after 2026-07-15) to an
      # immutable-ID subject claim -- repo:<owner>@<owner_id>/<repo>@<repo_id>
      # instead of the classic repo:<owner>/<repo> notoriousmcp still gets
      # (it predates the change). undergroundbb was created after, so this
      # is the format its tokens actually carry -- confirmed via
      # `gh api repos/pwntato/undergroundbb/actions/oidc/customization/sub`
      # and cross-checked against `gh api users/pwntato --jq .id` (844608)
      # and `gh api repos/pwntato/undergroundbb --jq .id` (1355495158). Every
      # CI deploy since #97 failed AssumeRoleWithWebIdentity against the old
      # value -- see #105. Pinned to the real numeric IDs rather than a
      # wildcard, matching this file's existing preference for exact scoping.
      values = ["repo:pwntato@844608/undergroundbb@1355495158:environment:production"]
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
      # data.aws_iam_openid_connect_provider resolves the provider's URL to
      # an ARN via ListOpenIDConnectProviders before GetOpenIDConnectProvider
      # can even be called -- missing here, so terraform plan never got past
      # reading this data source on the first real CI run past #106's OIDC
      # trust-policy fix (see #105/#107). Like GetOpenIDConnectProvider, this
      # action has no resource-level permissions in IAM (confirmed by the
      # live AccessDenied naming "resource: .../oidc-provider/*"), so it's
      # necessarily on the same "*" statement.
      "iam:ListOpenIDConnectProviders",
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
      # #8's OAC bucket policy, added once the distribution ARN existed to
      # scope its AWS:SourceArn condition to. Flagged as a known gap in
      # #100's own review rather than caught here -- this statement's
      # absence would have first broken on #8's initial CI-driven apply,
      # the same class of gap iam:PassRole was in #97.
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
    ]
    resources = [aws_s3_bucket.frontend.arn]
  }

  # #102: object-level actions for CI's frontend deploy step (`aws s3 sync`
  # + `aws s3 cp` of index.html), deliberately separate from the
  # bucket-management statement above per that statement's own comment
  # ("uploading the built SPA is a separate CI step"). No ListBucket
  # statement here -- `aws s3 sync` needs it to compute its diff, but the
  # bucket-management statement above already grants it via its `s3:List*`
  # on this same bucket ARN, so a second one here would be a no-op that
  # just invites a comment claiming it's load-bearing when it isn't (round
  # 4 caught exactly that). DeleteObject is not used by the deploy itself
  # -- the sync deliberately runs without --delete -- but is retained for
  # the orphaned-asset cleanup pass deploy.yml's comment defers.
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.frontend.arn}/*"]
  }

  # #102: cache invalidation after each frontend deploy. Resource-level
  # permissions ARE supported for this action (unlike the distribution's
  # other actions above), so this is scoped to the one distribution rather
  # than "*".
  statement {
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.main.arn]
  }

  # CloudFront (#8). Distribution/OAC/cache-policy/origin-request-policy/
  # response-headers-policy actions are all account-scoped, not
  # resource-scoped -- CloudFront's IAM actions don't support resource-level
  # permissions for these types (confirmed via `aws iam simulate-principal-policy`
  # before opening this PR, same check #97/#100's reviews wished had happened
  # earlier), so "*" here is the actual achievable scope, not a shortcut.
  statement {
    actions = [
      "cloudfront:GetDistribution",
      "cloudfront:CreateDistribution",
      "cloudfront:UpdateDistribution",
      "cloudfront:DeleteDistribution",
      "cloudfront:TagResource",
      "cloudfront:UntagResource",
      "cloudfront:ListTagsForResource",
      "cloudfront:GetOriginAccessControl",
      "cloudfront:CreateOriginAccessControl",
      "cloudfront:UpdateOriginAccessControl",
      "cloudfront:DeleteOriginAccessControl",
      "cloudfront:GetCachePolicy",
      "cloudfront:CreateCachePolicy",
      "cloudfront:UpdateCachePolicy",
      "cloudfront:DeleteCachePolicy",
      "cloudfront:ListCachePolicies",
      "cloudfront:GetOriginRequestPolicy",
      "cloudfront:CreateOriginRequestPolicy",
      "cloudfront:UpdateOriginRequestPolicy",
      "cloudfront:DeleteOriginRequestPolicy",
      "cloudfront:GetResponseHeadersPolicy",
      "cloudfront:CreateResponseHeadersPolicy",
      "cloudfront:UpdateResponseHeadersPolicy",
      "cloudfront:DeleteResponseHeadersPolicy",
      # Added in round 2 review: aws_cloudfront_function.spa_index_rewrite
      # (added in round 1's fix commit) was never added to this statement,
      # so a CI-driven apply of this branch couldn't create it -- the same
      # gap shape as #97's iam:PassRole and #100's s3:PutBucketPolicy, all
      # three caught only because live testing exercises the deploy role
      # directly rather than trusting a clean plan under admin credentials.
      # publish = true means Terraform calls CreateFunction *and*
      # PublishFunction; refresh calls DescribeFunction/GetFunction -- all
      # six needed, not just create.
      "cloudfront:CreateFunction",
      "cloudfront:UpdateFunction",
      "cloudfront:PublishFunction",
      "cloudfront:DescribeFunction",
      "cloudfront:GetFunction",
      "cloudfront:DeleteFunction",
    ]
    resources = ["*"]
  }

  # #9: ACM certificate for CloudFront. Like the CloudFront statement above,
  # acm:* actions don't support resource-level permissions (confirmed via
  # `aws iam simulate-principal-policy` before opening this PR, same
  # pre-check as #97/#100/cloudfront's own statement) -- "*" is the real
  # achievable scope here too, not a shortcut. AddTagsToCertificate/
  # ListTagsForCertificate cover the provider's own tagging calls on
  # aws_acm_certificate; the Describe/Request/Delete set covers create,
  # validation polling (aws_acm_certificate_validation waits on
  # DescribeCertificate until the domain_validation_options resolve), and
  # destroy.
  statement {
    actions = [
      "acm:RequestCertificate",
      "acm:DescribeCertificate",
      "acm:DeleteCertificate",
      "acm:AddTagsToCertificate",
      "acm:ListTagsForCertificate",
    ]
    resources = ["*"]
  }

  # route53:ListHostedZones has no resource-level permissions -- it's an
  # account-level list, so it can't live on the zone-scoped statement below
  # no matter how that statement's resource is written. acm.tf's
  # data "aws_route53_zone" looks the zone up by `name`, not `zone_id` --
  # the provider does not call GetHostedZone to resolve that (names aren't
  # unique), it lists every zone in the account and filters client-side, so
  # this is the action the lookup itself actually depends on. Caught in
  # review, not by the pre-merge simulate pass: that pass only checked the
  # actions this policy already granted, which by construction can't surface
  # one nobody thought to grant -- same shape as #97/#100/#108. Confirmed
  # live: `simulate-principal-policy` for this action came back
  # `implicitDeny` with zero matched statements, unscoped and zone-scoped
  # alike, before this statement was added.
  statement {
    actions   = ["route53:ListHostedZones"]
    resources = ["*"]
  }

  # #9: the existing undergroundbb.com hosted zone (looked up, not created --
  # see acm.tf's own comment on why) -- DNS validation records for the
  # certificate above, plus the apex A/AAAA alias records pointing the
  # domain at the distribution. Route 53 record-set actions ARE
  # resource-scopable to one hosted zone, unlike ACM/CloudFront above, so
  # this is scoped to that zone rather than "*". GetHostedZone/ListTagsForResource
  # are called later in the data source's own read (name servers, tags) --
  # not for the by-name lookup itself, which is ListHostedZones above --
  # and List/ChangeResourceRecordSets cover the provider computing a diff
  # before writing and the write itself.
  statement {
    actions = [
      "route53:GetHostedZone",
      "route53:ListTagsForResource",
      "route53:ListResourceRecordSets",
      "route53:ChangeResourceRecordSets",
    ]
    resources = ["arn:aws:route53:::hostedzone/${data.aws_route53_zone.main.zone_id}"]
  }

  # route53:GetChange has no resource-level permissions either (its ARNs are
  # per in-flight change batch, not knowable before the change is submitted)
  # -- ChangeResourceRecordSets returns a change id the provider then polls
  # via GetChange to confirm the record propagated before apply returns.
  statement {
    actions   = ["route53:GetChange"]
    resources = ["*"]
  }

  # #10: the WAF WebACL protecting the CloudFront distribution.
  # Create/Get/Update/Delete/Tag/Untag/ListTags all support resource-level
  # scoping for the webacl resource type (confirmed via AWS's own IAM
  # service reference, same pre-check this file's other "*" statements
  # cite -- unlike CloudFront/ACM above, WAFv2 actually does support scoping
  # here, so this is scoped rather than defaulting to "*"). The web ACL
  # itself only ever exists in us-east-1 (waf.tf's aws.use1 provider), but
  # IAM actions aren't region-scoped by the resource ARN's own region
  # component the way the API call is -- the ARN below still names
  # us-east-1 explicitly since that's the resource's real location.
  statement {
    actions = [
      "wafv2:GetWebACL",
      "wafv2:CreateWebACL",
      "wafv2:UpdateWebACL",
      "wafv2:DeleteWebACL",
      "wafv2:TagResource",
      "wafv2:UntagResource",
      "wafv2:ListTagsForResource",
    ]
    resources = ["arn:aws:wafv2:us-east-1:${data.aws_caller_identity.current.account_id}:global/webacl/undergroundbb-${terraform.workspace}/*"]
  }

  # wafv2:ListWebACLs (used by nothing in this config directly, but AWS
  # provider calls it as part of some webacl data-source/import paths) and
  # wafv2:CheckCapacity/ListAvailableManagedRuleGroups have no
  # resource-level permissions -- confirmed via the same IAM service
  # reference used above (these actions have no listed resource types),
  # so "*" is the actual achievable scope, not a shortcut. Kept narrow to
  # only the read-only listing actions rather than a broader wafv2:* "*"
  # grant.
  statement {
    actions = [
      "wafv2:ListWebACLs",
      "wafv2:CheckCapacity",
      "wafv2:ListAvailableManagedRuleGroups",
    ]
    resources = ["*"]
  }

  # No wafv2:AssociateWebACL/DisassociateWebACL statement: AWS's own WAFv2
  # API rejects CloudFront distribution ARNs on that call entirely (see
  # cloudfront.tf's web_acl_id comment) -- CloudFront association/removal
  # goes through cloudfront:UpdateDistribution instead, already granted
  # "*" scope by the existing CloudFront statement above.

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
