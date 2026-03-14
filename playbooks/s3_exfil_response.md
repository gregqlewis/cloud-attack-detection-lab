# S3 Data Exfiltration Response Playbook

**Playbook ID:** PB-002  
**MITRE ATT&CK TTP:** T1530 — Data from Cloud Storage  
**Wazuh Rule:** 100204 (S3 Exfiltration — PutObject/GetObject)  
**Severity:** High  
**Last Updated:** 2026-03-14

---

## Overview

This playbook addresses detections triggered by data staging and exfiltration activity against AWS S3. Rule 100204 fires on `PutObject` and `GetObject` events against the designated exfil bucket, representing the final stage of the lab's simulated attack chain.

**Lab-confirmed attack sequence:**
```
credential_theft.py (T1552.005)
    → s3_exfil.py (T1530)
        ListBuckets → ListObjects → GetObject → PutObject → ListObjects
```

**Key distinction for triage:**

| Event | Signal Strength | Default Action |
|---|---|---|
| `GetObject` | Medium — could be legitimate access | Investigate first |
| `PutObject` to exfil bucket | High — data staging, unambiguous | Immediate containment |

---

## Detection Triggers

| Rule ID | Rule Name | Condition |
|---|---|---|
| 100204 | S3 Data Exfiltration | `PutObject` or `GetObject` on `cloud-attack-lab-exfil-bucket` by attacker identity |

**OpenSearch query to confirm alert scope:**
```
rule.id:100204 AND rule.groups:cloud_attack_lab
```

**Expand scope to full exfil sequence:**
```
aws.userIdentity.userName:cloud-attack-lab-attacker AND
data.aws.eventSource:s3.amazonaws.com AND
data.aws.eventName:(ListBuckets OR ListObjects OR GetObject OR PutObject)
```

---

## Phase 1 — Triage (First 15 Minutes)

### Step 1.1 — Determine Trigger Type

Pull the triggering event and check `aws.eventName` immediately:

**If `PutObject` triggered the alert:**
> ⚠️ **Skip to immediate containment (Phase 3).** Data staging to an exfil bucket from a non-service identity is not a false-positive candidate. Do not delay containment to complete investigation.

**If `GetObject` triggered the alert:**
> Proceed through triage steps below before containment.

### Step 1.2 — Confirm Legitimacy (GetObject Path Only)

Check these fields on the triggering event:

| Field | What to Look For |
|---|---|
| `aws.userIdentity.arn` | Known authorized principal? Check against data access roster. |
| `aws.sourceIPAddress` | Corporate CIDR / known VPN, or external / foreign IP? |
| `aws.requestParameters.bucketName` | Is this a sensitive or restricted bucket? |
| `aws.requestParameters.key` | What specific object was accessed? PII, credentials, config files? |
| Volume | Single object access, or hundreds of `GetObject` calls in a short window? |

**Route to Investigation if:**
- Principal ARN is a known Cloud Ops or data pipeline identity
- Source IP matches corporate CIDR or known VPN
- Access volume is consistent with baseline behavior for this principal
- No `PutObject` has fired in the same session window

**Route to Immediate Containment if:**
- Source IP is foreign, unknown, or associated with Tor / cloud hosting provider
- Principal has no prior S3 access history
- `GetObject` volume is anomalous (spike pattern, not baseline)
- `PutObject` fired in the same session — data was staged, not just read

### Step 1.3 — Check for Upstream TTPs

Before containment, determine whether this is an isolated finding or the final stage of a longer chain. Query for upstream rule hits from the same principal:

```
aws.userIdentity.userName:cloud-attack-lab-attacker AND
rule.id:(100201 OR 100202 OR 100203 OR 100204)
```

If rules 100201–100203 also fired in the same session window, this is a **full-chain compromise** — triage, enumeration, escalation, credential theft, and exfiltration. Escalate immediately and treat as confirmed breach.

---

## Phase 2 — Investigation

### Step 2.1 — Scope What Was Accessed

```bash
# List all S3 API calls by the suspect principal
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=cloud-attack-lab-attacker \
  --start-time <INCIDENT_START> \
  --end-time <NOW> \
  --profile greg-cloudsec-lab \
  | jq '.Events[] | select(.EventSource == "s3.amazonaws.com")'
```

Document:
- All buckets enumerated via `ListBuckets`
- All objects listed via `ListObjects` (attacker's target selection phase)
- All objects retrieved via `GetObject` (what was read)
- All objects staged via `PutObject` (what was moved — highest priority)

### Step 2.2 — Identify Staging Destination

`PutObject` in the exfil sequence means data was moved to an attacker-controlled destination. Determine:

- What bucket received the `PutObject`? Is it in your account or a different account?
- What is the bucket's ACL and policy? Is it publicly accessible?
- What objects were written — do they match objects retrieved via `GetObject` earlier in the session?

```bash
# Check bucket policy of exfil destination
aws s3api get-bucket-policy \
  --bucket <EXFIL_BUCKET_NAME> \
  --profile greg-cloudsec-lab

# Check bucket ACL
aws s3api get-bucket-acl \
  --bucket <EXFIL_BUCKET_NAME> \
  --profile greg-cloudsec-lab
```

### Step 2.3 — Assess Data Sensitivity

Classify what was exfiltrated:
- **PII** (names, emails, SSNs) → breach notification obligations may apply
- **Credentials / secrets** → immediate rotation required, treat all downstream systems as compromised
- **Config / infrastructure data** → attacker may have visibility into your environment topology
- **General assets** → lower urgency, document and remediate

---

## Phase 3 — Containment

### Step 3.1 — Disable Compromised Credentials

```bash
# Deactivate the originating access key
aws iam update-access-key \
  --access-key-id <KEY_ID> \
  --status Inactive \
  --user-name cloud-attack-lab-attacker \
  --profile greg-cloudsec-lab
```

### Step 3.2 — Block S3 Access via Bucket Policy

Apply a deny policy to the exfil bucket to prevent further reads or writes:

```bash
aws s3api put-bucket-policy \
  --bucket <TARGET_BUCKET> \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::<TARGET_BUCKET>",
        "arn:aws:s3:::<TARGET_BUCKET>/*"
      ]
    }]
  }' \
  --profile greg-cloudsec-lab
```

> ⚠️ This blocks all principals including legitimate ones. Use only as emergency containment — scope to the attacker ARN if the blast radius is a concern.

### Step 3.3 — Revoke Assumed Role Sessions (If 100202 Also Fired)

If the exfiltration was performed under an assumed role identity (escalation chain confirmed), revoke active STS sessions per PB-001 Phase 3.1.

### Step 3.4 — Preserve Evidence

```bash
# Export full CloudTrail event record for the incident window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=cloud-attack-lab-attacker \
  --start-time <INCIDENT_START> \
  --end-time <NOW> \
  --profile greg-cloudsec-lab \
  > evidence/s3_exfil_incident_<DATE>.json
```

---

## Phase 4 — Remediation

1. **Rotate all access keys** for the affected principal
2. **Audit bucket policies** on all S3 buckets — tighten to least-privilege; remove any `Principal: *` statements
3. **Enable S3 Block Public Access** at the account level if not already enforced
4. **Enable S3 Object-Level Logging** in CloudTrail if not already active — `GetObject` and `PutObject` are data events and may not be logged under management-events-only configuration
5. **Assess need for breach notification** based on data sensitivity classification from Phase 2.3
6. **Rotate any credentials or secrets** contained in exfiltrated objects

---

## Phase 5 — Detection Tuning

| Observation | Action |
|---|---|
| Rule fired on legitimate Cloud Ops bulk access | Add volume threshold to `GetObject` rule — fire only after N events in T minutes from the same principal |
| `PutObject` to internal bucket (not exfil) by authorized pipeline | Scope rule to sensitive bucket list rather than single bucket name |
| `ListBuckets` not currently covered by any rule | Consider adding a rule that fires on `ListBuckets` from `IAMUser` type — low-effort, high-signal enumeration indicator |
| Full chain confirmed (100201 → 100202 → 100203 → 100204) | Build a correlation rule that elevates severity when all four rules fire within the same session window — this is the highest-confidence compromise pattern in the lab |

---

## Lab Context

This playbook was developed and validated against simulated attack activity in the `cloud-attack-detection-lab` environment:

- **Attack script:** `attacks/s3_exfil.py`
- **Wazuh rule:** `/var/ossec/etc/rules/cloud_attack_lab.xml` (rule 100204)
- **CloudTrail source:** `cloud-attack-lab-cloudtrail-logs-267949707794`
- **Target bucket:** `cloud-attack-lab-exfil-bucket`
- **Detection validated:** 2026-03-14, rule 100204 confirmed firing in `wazuh-alerts-4.x-*`