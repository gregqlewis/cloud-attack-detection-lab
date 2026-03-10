# vpc_flow_logs.tf
# VPC Flow Logs capture network-level traffic metadata
# Not packet contents - just: who talked to who, on what port, allowed or denied
# Critical for detecting: lateral movement, exfiltration, C2 communication

# Create a dedicated VPC for the lab
# Isolates lab activity from any other AWS resources in your account
resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# CloudWatch Log Group - where VPC Flow Logs will be stored
# We use CloudWatch here because it integrates cleanly with
# the rest of our alerting pipeline
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}-flow-logs"
  retention_in_days = 30    # keep 30 days of flow logs - balances cost vs visibility
}

# IAM Role - allows VPC Flow Logs service to write to CloudWatch
# This is the same pattern as CloudTrail writing to S3
# AWS services need explicit permission to write logs on your behalf
resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.project_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

# Policy attached to the role - specific permissions to write logs
resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.project_name}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# Enable Flow Logs on the lab VPC
resource "aws_flow_log" "lab" {
  vpc_id          = aws_vpc.lab.id
  traffic_type    = "ALL"    # capture ACCEPT and REJECT traffic
                              # REJECT traffic is especially useful for detection
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn
}