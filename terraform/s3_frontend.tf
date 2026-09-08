# Private bucket for the built SPA (#7). No public access and no S3 static
# website hosting -- CloudFront (#8) is the only intended reader, reaching
# this bucket through Origin Access Control, not a public bucket policy.
#
# The bucket policy that actually grants CloudFront's OAC principal read
# access is deliberately not here: it needs the distribution's ARN in its
# AWS:SourceArn condition, and the distribution doesn't exist until #8.
# Adding it there (scoped to exactly that one distribution, per #7's own
# text) keeps this bucket policy-free and inert on its own, same incremental
# per-resource approach #6's iam_deploy.tf comment describes.
resource "aws_s3_bucket" "frontend" {
  bucket = "undergroundbb-frontend-${terraform.workspace}"
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioned so a bad deploy (CI overwrites every object on every push, same
# as the Lambda's #98 churn) can be rolled back from the bucket itself,
# without needing a redeploy of the previous frontend build.
resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Old versions are cheap to keep briefly for rollback but not worth keeping
# forever -- this is build output, not user data, and every push to main
# creates a new noncurrent version of every changed object.
resource "aws_s3_bucket_lifecycle_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

output "frontend_bucket_name" {
  value       = aws_s3_bucket.frontend.id
  description = "Set as the S3 deploy target for the built SPA (#8's CI frontend deploy step)."
}
