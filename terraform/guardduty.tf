# guardduty.tf
# Enables AWS GuardDuty - managed threat detection service
# Analyzes CloudTrail, VPC Flow Logs, and DNS logs automatically
# Generates findings mapped to MITRE ATT&CK

# Enable GuardDuty detector - kept minimal, features configured separately
resource "aws_guardduty_detector" "lab" {
  enable = true
}

# S3 Protection - monitors S3 data events
# Catches exfiltration attempts like GetObject on sensitive buckets
# Note: aws_guardduty_detector datasources block is deprecated in
# AWS provider ~> 5.0. Features are now managed as separate
# aws_guardduty_detector_feature resources for independent control.
resource "aws_guardduty_detector_feature" "s3_protection" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# Malware Protection - scans EC2 EBS volumes when suspicious activity found
# Only triggers on findings so cost impact is minimal
resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# EKS Protection - disabled, not using Kubernetes in this lab
resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.lab.id
  name        = "EKS_AUDIT_LOGS"
  status      = "DISABLED"
}

# SNS Topic - GuardDuty sends findings here
# SNS = Simple Notification Service - AWS's pub/sub messaging
# Think of it as a notification hub that can trigger emails, Lambda, etc.
resource "aws_sns_topic" "guardduty_findings" {
  name = "${var.project_name}-guardduty-findings"
}

# Subscribe your email to the SNS topic
# You'll get an email when GuardDuty fires a finding during attack simulation
resource "aws_sns_topic_subscription" "guardduty_email" {
  topic_arn = aws_sns_topic.guardduty_findings.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule - routes GuardDuty findings to SNS
# EventBridge watches for events in your AWS account
# This rule says: "when GuardDuty generates ANY finding, send it to SNS"
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Routes GuardDuty findings to SNS for lab alerting"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

# Connect the EventBridge rule to the SNS topic
resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_findings.arn
}

# Allow EventBridge to publish to the SNS topic
resource "aws_sns_topic_policy" "guardduty_findings" {
  arn = aws_sns_topic.guardduty_findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.guardduty_findings.arn
      }
    ]
  })
}