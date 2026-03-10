# variables.tf
# Centralizes all configurable values so nothing is hardcoded
# Best practice: if a value might change, it lives here

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Used to prefix all resource names for easy identification"
  type        = string
  default     = "cloud-attack-lab"
}

variable "aws_account_id" {
  description = "Your AWS account ID - used in IAM policies and S3 bucket policies"
  type        = string
  # No default - you'll pass this in to avoid hardcoding account numbers
}

variable "alert_email" {
  description = "Email for billing and security alerts"
  type        = string
}