# s3.tf
# Creates two buckets with intentionally opposite security postures
#
# 1. target-data: intentionally misconfigured - the exfiltration target
#    No encryption, no bucket policy, public access not fully blocked
#    Simulates a poorly configured S3 bucket containing sensitive data
#
# 2. exfil-staging: simulates attacker-controlled external bucket
#    Where stolen data gets copied to during exfiltration simulation

# -------------------------------------------------------
# TARGET BUCKET — intentionally misconfigured
# -------------------------------------------------------

resource "aws_s3_bucket" "target_data" {
  bucket        = "${var.project_name}-target-data-${var.aws_account_id}"
  force_destroy = true

  tags = {
    Purpose       = "attack-simulation"
    Scenario      = "s3-exfiltration-target"
    Misconfigured = "true"
    Sensitivity   = "simulated-confidential"
  }
}

# Intentionally NOT adding:
# - aws_s3_bucket_server_side_encryption_configuration
# - aws_s3_bucket_versioning
# - aws_s3_bucket_policy
# These omissions are the misconfiguration we're detecting

# Minimal public access block - note what's missing vs cloudtrail bucket
# restrict_public_buckets and ignore_public_acls intentionally omitted
resource "aws_s3_bucket_public_access_block" "target_data" {
  bucket = aws_s3_bucket.target_data.id

  block_public_acls       = true
  block_public_policy     = false   # intentional misconfiguration
                                    # allows bucket policies to grant public access
  ignore_public_acls      = false   # intentional misconfiguration
  restrict_public_buckets = false   # intentional misconfiguration
}

# -------------------------------------------------------
# SIMULATED SENSITIVE DATA
# Objects that represent realistic exfiltration targets
# All data is clearly fake - labeled as simulation data
# -------------------------------------------------------

# Simulated employee PII export
resource "aws_s3_object" "employee_data" {
  bucket  = aws_s3_bucket.target_data.id
  key     = "hr/employee-records-2024.csv"
  content = <<-EOT
    employee_id,name,ssn,salary,email
    EMP001,John Smith,XXX-XX-0001,85000,jsmith@company.com
    EMP002,Jane Doe,XXX-XX-0002,92000,jdoe@company.com
    EMP003,Bob Johnson,XXX-XX-0003,78000,bjohnson@company.com
    NOTE: THIS IS SIMULATED DATA FOR SECURITY LAB USE ONLY
  EOT

  tags = {
    DataClassification = "SIMULATED-PII"
    LabUseOnly         = "true"
  }
}

# Simulated AWS credentials file - represents credential theft scenario
resource "aws_s3_object" "credentials" {
  bucket  = aws_s3_bucket.target_data.id
  key     = "config/aws-credentials-backup.txt"
  content = <<-EOT
    [default]
    aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    
    NOTE: THIS IS SIMULATED DATA FOR SECURITY LAB USE ONLY
    These are AWS documentation example credentials - not real
  EOT

  tags = {
    DataClassification = "SIMULATED-CREDENTIALS"
    LabUseOnly         = "true"
  }
}

# Simulated financial report
resource "aws_s3_object" "financial_data" {
  bucket  = aws_s3_bucket.target_data.id
  key     = "finance/q4-2024-revenue-report.csv"
  content = <<-EOT
    quarter,revenue,expenses,net_income,margin
    Q1-2024,4200000,3100000,1100000,26%
    Q2-2024,4800000,3400000,1400000,29%
    Q3-2024,5100000,3600000,1500000,29%
    Q4-2024,5900000,4000000,1900000,32%
    NOTE: THIS IS SIMULATED DATA FOR SECURITY LAB USE ONLY
  EOT

  tags = {
    DataClassification = "SIMULATED-FINANCIAL"
    LabUseOnly         = "true"
  }
}

# Simulated application config with database credentials
resource "aws_s3_object" "app_config" {
  bucket  = aws_s3_bucket.target_data.id
  key     = "config/app-config-prod.json"
  content = jsonencode({
    environment = "production"
    database = {
      host     = "prod-db.company.internal"
      port     = 5432
      username = "app_user"
      password = "SIMULATED-PASSWORD-NOT-REAL"
    }
    api_keys = {
      stripe     = "sk_test_SIMULATED_NOT_REAL"
      sendgrid   = "SG.SIMULATED_NOT_REAL"
    }
    note = "THIS IS SIMULATED DATA FOR SECURITY LAB USE ONLY"
  })

  tags = {
    DataClassification = "SIMULATED-CONFIG"
    LabUseOnly         = "true"
  }
}

# -------------------------------------------------------
# EXFIL STAGING BUCKET — simulates attacker-controlled destination
# -------------------------------------------------------

# In a real attack this would be an external bucket
# In the lab it stays in your account for safety and cost control
# The exfil script copies target_data objects here
resource "aws_s3_bucket" "exfil_staging" {
  bucket        = "${var.project_name}-exfil-staging-${var.aws_account_id}"
  force_destroy = true

  tags = {
    Purpose  = "attack-simulation"
    Scenario = "attacker-controlled-destination"
  }
}

# -------------------------------------------------------
# OUTPUTS — used by attack scripts
# -------------------------------------------------------

output "target_bucket_name" {
  value       = aws_s3_bucket.target_data.id
  description = "Name of the misconfigured target bucket - used in exfil script"
}

output "exfil_bucket_name" {
  value       = aws_s3_bucket.exfil_staging.id
  description = "Name of the attacker staging bucket - exfil destination"
}