# iam.tf
# Creates two identities for the lab:
# 1. lab-attacker: limited IAM user simulating compromised credentials
# 2. lab-privileged-role: higher privilege role with a misconfiguration
#    that allows the attacker to assume it (the escalation path)

# -------------------------------------------------------
# ATTACKER IDENTITY
# -------------------------------------------------------

# The attacker IAM user
# Represents compromised developer credentials
# Limited permissions - can enumerate but not act
resource "aws_iam_user" "attacker" {
  name = "${var.project_name}-attacker"

  tags = {
    Purpose = "attack-simulation"
    Scenario = "compromised-developer-credentials"
  }
}

# Access keys for the attacker user
# Your Python scripts will use these credentials
# These get stored in terraform.tfstate - which is why .gitignore matters
resource "aws_iam_access_key" "attacker" {
  user = aws_iam_user.attacker.name
}

# Attacker policy - read-only enumeration permissions
# Enough to map the environment, not enough to act
resource "aws_iam_policy" "attacker_enum" {
  name        = "${var.project_name}-attacker-enum-policy"
  description = "Simulates compromised developer credentials - enumeration only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMEnumeration"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",              # T1069.003 - who exists
          "iam:ListRoles",              # find assumable roles
          "iam:ListPolicies",           # what permissions exist
          "iam:GetPolicy",              # read policy documents
          "iam:GetPolicyVersion",       # read policy version details
          "iam:ListAttachedRolePolicies", # what's attached to roles
          "iam:ListRolePolicies",       # inline policies on roles
          "sts:GetCallerIdentity"       # T1033 - confirm own identity
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Enumeration"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",        # see what buckets exist
          "s3:GetBucketLocation"        # confirm bucket region
        ]
        Resource = "*"
      },
      {
        Sid    = "AssumePrivilegedRole"
        Effect = "Allow"
        Action = ["sts:AssumeRole"]
        # Scoped specifically to the target role - the misconfiguration
        Resource = aws_iam_role.privileged.arn
      }
    ]
  })
}

# Attach the policy to the attacker user
resource "aws_iam_user_policy_attachment" "attacker" {
  user       = aws_iam_user.attacker.name
  policy_arn = aws_iam_policy.attacker_enum.arn
}

# -------------------------------------------------------
# PRIVILEGED ROLE — the escalation target
# -------------------------------------------------------

# This is the misconfigured role the attacker will discover
# and abuse during the privilege escalation scenario
resource "aws_iam_role" "privileged" {
  name        = "${var.project_name}-privileged-role"
  description = "Intentionally misconfigured role for privilege escalation simulation"

  # Trust policy - defines WHO can assume this role
  # The misconfiguration: it trusts the attacker user explicitly
  # In real incidents this is often too-broad trust like "any user in the account"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAttackerAssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_user.attacker.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose     = "attack-simulation"
    Scenario    = "privilege-escalation-target"
    Misconfigured = "true"    # explicit tag so it's obvious in the console
  }
}

# Permissions the privileged role has
# This is what the attacker GAINS after successful escalation
resource "aws_iam_policy" "privileged_access" {
  name        = "${var.project_name}-privileged-access-policy"
  description = "Elevated permissions gained after successful privilege escalation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3FullAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",       # can now read bucket contents - exfil scenario
          "s3:PutObject",       # can write to buckets
          "s3:ListBucket",      # can list bucket contents
          "s3:DeleteObject"     # can destroy evidence
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMExpanded"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListAccessKeys",   # can enumerate access keys - credential theft
          "iam:ListUserPolicies"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach elevated permissions to the privileged role
resource "aws_iam_role_policy_attachment" "privileged" {
  role       = aws_iam_role.privileged.name
  policy_arn = aws_iam_policy.privileged_access.arn
}

# -------------------------------------------------------
# OUTPUTS - values needed by Python attack scripts
# -------------------------------------------------------

# These print to terminal after terraform apply
# You'll use these to configure your attacker boto3 profile
output "attacker_access_key_id" {
  value       = aws_iam_access_key.attacker.id
  description = "Attacker AWS Access Key ID - use in attack script profile"
  sensitive   = false
}

output "attacker_secret_access_key" {
  value       = aws_iam_access_key.attacker.secret
  description = "Attacker AWS Secret Access Key"
  sensitive   = true    # marked sensitive - won't print in plain text
}

output "privileged_role_arn" {
  value       = aws_iam_role.privileged.arn
  description = "ARN of the escalation target role - used in privilege escalation script"
}