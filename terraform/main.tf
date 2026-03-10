# main.tf
# Tells Terraform which cloud provider to talk to and how

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"    # use AWS provider version 5.x
    }
  }
}

provider "aws" {
  region  = var.aws_region    # pulls from variables.tf
  profile = "greg-cloudsec-lab" # Tells Terraform to use your AWS CLI profile named "greg-cloudsec-lab"

  # Tags applied to every resource this Terraform creates
  # Critical for cost tracking and cleanup
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "lab"
      Owner       = "greg"
      ManagedBy   = "terraform"
    }
  }
}

# Budget alert - triggers email if monthly spend exceeds $10
resource "aws_budgets_budget" "lab_budget" {
  name         = "${var.project_name}-budget"
  budget_type  = "COST"
  limit_amount = "10"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80    # alert at 80% of budget ($8)
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}