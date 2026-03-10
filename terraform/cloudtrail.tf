# cloudtrail.tf
# Configures CloudTrail and the S3 bucket that receives logs
# This is the foundational detection data source for the entire lab

# -------------------------------------------------------
# S3 BUCKET — stores all CloudTrail logs
# -------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  # Bucket names must be globally unique - we use account ID to ensure this
  bucket        = "${var.project_name}-cloudtrail-logs-${var.aws_account_id}"
  force_destroy = true   # allows terraform destroy to delete bucket with contents
                         # acceptable in a lab - never do this in production
}

# Block all public access - logs should never be public
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning - preserves logs even if an attacker deletes them
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encrypt all logs at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"   # SSE-S3 encryption
    }
  }
}

# Bucket policy - only CloudTrail service can write to this bucket
# This prevents other services or users from writing fake log entries
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

# The actual policy document
# Two statements: one to verify bucket exists, one to allow log delivery
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {

  # Statement 1: CloudTrail needs to check the bucket ACL before writing
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  # Statement 2: CloudTrail is allowed to write log files
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]

    # Logs land at this specific prefix path inside the bucket
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${var.aws_account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Statement 3: Deny deletion of log files - protects evidence
  statement {
    sid    = "DenyLogDeletion"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:DeleteObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/*"]
  }
}

# -------------------------------------------------------
# CLOUDTRAIL — the actual trail configuration
# -------------------------------------------------------

resource "aws_cloudtrail" "lab_trail" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  # Explicitly wait for bucket policy before creating trail
  # Terraform can't infer this dependency automatically
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_s3_bucket_public_access_block.cloudtrail_logs
  ]
}