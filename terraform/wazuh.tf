## Wazuh IAM Resources
# Wazuh needs permissions to read from CloudTrail Logs and S3

# TODO: access keys are managed outside Terraform (on Wazuh VM)
# Manual deletion required before terraform destroy

resource "aws_iam_user" "wazuh_cloudtrail_reader" {
  name = "wazuh-cloudtrail-reader"
}

resource "aws_iam_user_policy" "wazuh_s3_readonly" {
  name = "wazuh-s3-readonly"
  user = aws_iam_user.wazuh_cloudtrail_reader.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        ]
      },
            {
        Sid    = "AllowGuardDutyS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.guardduty_findings.arn,
          "${aws_s3_bucket.guardduty_findings.arn}/*"
        ]
      },
                  {
        Sid    = "AllowKMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = [
          "arn:aws:kms:us-east-1:${data.aws_caller_identity.current.account_id}:key/de8b158a-0602-4518-8800-60fec283a659"
        ]
      }
    ]
  })
}