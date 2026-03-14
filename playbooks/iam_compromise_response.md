# IAM Compromise Response Playbook

**Playbook ID:** PB-001  
**MITRE ATT&CK TTPs:** T1069.003 (Cloud Groups), T1078.004 (Cloud Accounts)  
**Wazuh Rules:** 100201 (IAM Enumeration), 100202 (Privilege Escalation)  
**Severity:** High  
**Last Updated:** 2026-03-14

---

## Overview

This playbook addresses detections triggered by IAM enumeration activity followed by privilege escalation in AWS environments. These two TTPs frequently chain — an attacker enumerates IAM permissions to identify escalation paths, then exploits a misconfigured role or policy to gain elevated access.

**Attack chain modeled in this lab:**
```
iam_enum.py (T1069.003) → privilege_escalation.py (T1078.004)
```

---

## Detection Triggers

| Rule ID | Rule Name | Condition |
|---|---|---|
| 100201 | IAM Enumeration Detected | `ListGroupsForUser`, `ListAttachedUserPolicies`, `ListUserPolicies` calls from non-service principal |
| 100202 | Privilege Escalation Detected | `AssumeRole` call by attacker principal into a higher-privileged role via misconfigured trust policy |

> **Lab Finding:** Rule 100202 was validated against `AssumeRole`-based escalation. `AttachUserPolicy` and `CreatePolicyVersion` are not currently covered — see Phase 5 for detection gap.

**OpenSearch query to confirm alert scope:**
```
rule.id:(100201 OR 100202) AND rule.groups:cloud_attack_lab
```

---

## Phase 1 — Triage (First 15 Minutes)

### Step 1.1 — Confirm Legitimacy Before Any Containment Action

> ⚠️ **Do not block or disable the principal until legitimacy is ruled out. Premature containment of an authorized user or service causes unnecessary work stoppage.**

Pull the triggering CloudTrail event from OpenSearch and evaluate:

```
data.aws.eventSource:iam.amazonaws.com AND data.aws.eventName:(ListUsers OR ListRoles OR ListPolicies)
AND aws.userIdentity.userName:cloud-attack-lab-attacker
```

Check these fields on every alert:

| Field | What to Look For |
|---|---|
| `aws.userIdentity.arn` | Is this a known IAM user, service role, or something unexpected? |
| `aws.sourceIPAddress` | Internal CIDR, known VPN, or AWS service address? External/foreign IP is escalating signal. |
| `aws.userAgent` | AWS Console / CLI = human. Unfamiliar SDK string = investigate further. |
| `aws.requestParameters` | What specific resource was targeted? Is this consistent with that principal's job function? |
| Timestamp | Business hours? Matches known maintenance windows? |

### Step 1.2 — Classify the Finding

**Route to Investigation if:**
- Principal ARN is a known Cloud Ops, DevOps, or admin user
- Source IP matches corporate CIDR or known VPN range
- Activity is consistent with the principal's role (e.g., Cloud Ops performing routine IAM audit)
- No downstream privilege escalation rule (100202) has fired

**Route to Immediate Containment if:**
- Source IP is foreign, unknown, or associated with Tor/hosting provider
- Principal has no prior history of IAM API calls
- Rule 100201 fired AND rule 100202 fired within the same session window
- `userIdentity.type` is `AssumedRole` with an unfamiliar role chain

### Step 1.3 — Notify

- Escalate to Cloud Security Lead if containment path is triggered
- Document finding in incident tracker with CloudTrail event IDs and initial classification

---

## Phase 2 — Investigation

### Step 2.1 — Scope the Compromised Principal

Retrieve all activity from the suspect principal in the past 24 hours:

```
aws.userIdentity.arn:"<SUSPECT_ARN>" AND data.aws.eventSource:iam.amazonaws.com
```

Document:
- All IAM API calls made
- All resources enumerated (`ListGroupsForUser` targets)
- Whether any policy attachment occurred (100202 trigger)
- Whether any new access keys were created (`CreateAccessKey`)

### Step 2.2 — Check for Lateral Movement Indicators

IAM enumeration often precedes lateral movement via role assumption. Pivot to these event names:

```
data.aws.eventName:(AssumeRole OR CreateAccessKey OR UpdateAccessKey OR AddUserToGroup)
AND aws.userIdentity.arn:"<SUSPECT_ARN>"
```

**On `AssumeRole` hits, check:**

| Field | What to Look For |
|---|---|
| `aws.requestParameters.roleArn` | Is the target role admin-level or cross-account? Lab confirmed: `arn:aws:iam::267949707794:role/cloud-attack-lab-privileged-role` |
| `aws.requestParameters.roleSessionName` | ⚠️ Attacker-controlled field. Session names mimicking automation (`backup-restore-session`, `scheduler`, `lambda-exec`) originating from an IAM user — not a service role — are a strong behavioral indicator of tradecraft. |
| `aws.requestParameters.durationSeconds` | Requested credential lifetime. Lab confirmed: 3600s (1 hour). Maximum is 43200s — values near the max suggest persistence intent. |
| `aws.responseElements.assumedRoleUser.arn` | Confirms the session identity granted |
| `aws.responseElements.credentials.expiration` | When do the temporary credentials expire? Determines containment urgency. |

> **Lab-confirmed finding:** `privilege_escalation.py` used `roleSessionName: backup-restore-session` — a deliberate living-off-the-land naming technique designed to blend with legitimate automation. The calling principal was an IAM user (`lab-attacker`), not a service role. This contradiction between session name semantics and caller identity type is a high-fidelity detection signal.

> A misconfigured role trust policy (e.g., `Principal: {"AWS": "*"}` or scoped to the entire account) is the root cause when `AssumeRole` is the escalation vector. Containment must address both the active session *and* the trust policy.

### Step 2.3 — Determine Blast Radius

If privilege escalation (100202) fired:
- Identify which policy was attached (`aws.requestParameters.policyArn`)
- Determine what that policy permits (check AWS IAM or via CLI)
- Identify any resources accessed *after* the policy attachment

---

## Phase 3 — Containment

> Execute only after triage confirms this is not legitimate activity.

### Step 3.1 — Revoke Active STS Session

When escalation occurred via `AssumeRole`, the attacker holds temporary STS credentials. Revoke them by attaching a deny policy to the role:

```bash
# Revoke all active sessions for the assumed role by updating the role's policy
# This invalidates all temporary credentials issued before this timestamp
aws iam put-role-policy \
  --role-name <ESCALATED_ROLE_NAME> \
  --policy-name RevokeActiveSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {"aws:TokenIssueTime": "<REVOCATION_TIMESTAMP>"}
      }
    }]
  }' \
  --profile greg-cloudsec-lab
```

### Step 3.2 — Fix the Trust Policy Misconfiguration

```bash
# Restrict the role trust policy to only the intended principal
aws iam update-assume-role-policy \
  --role-name <ESCALATED_ROLE_NAME> \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::267949707794:user/<AUTHORIZED_USER>"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --profile greg-cloudsec-lab
```

### Step 3.3 — Disable Originating Credentials

```bash
# Export CloudTrail events for incident record before any remediation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<USERNAME> \
  --start-time <INCIDENT_START> \
  --end-time <NOW> \
  --profile greg-cloudsec-lab \
  > evidence/iam_incident_<DATE>.json
```

---

## Phase 4 — Remediation

1. **Rotate all access keys** for the affected principal
2. **Audit IAM policies** attached during the incident window — remove any that should not persist
3. **Review SCPs** — confirm Service Control Policies would block `AttachUserPolicy` on non-admin users in production
4. **Enable MFA enforcement** if not already present on the affected user
5. **Update Wazuh suppression rules** if legitimate activity triggered a false positive — scope suppression to the specific ARN and action, not the entire rule

---

## Phase 5 — Lessons Learned / Detection Tuning

| Observation | Action |
|---|---|
| Alert fired on known Cloud Ops user during scheduled audit | Add ARN-scoped suppression to `cloud_attack_lab.xml` |
| Rule 100201 fired but 100202 did not | Consider adding correlation rule: 100201 + no 100202 within 10 min = lower severity |
| Rule 100202 validated on `AssumeRole` only | **Detection gap:** `AttachUserPolicy` and `CreatePolicyVersion` are not currently covered. Consider adding rule 100205 scoped to those event names for full T1078.004 coverage. |
| `AssumeRole` escalation traced to overly broad trust policy | Root cause is trust policy misconfiguration — add SCP or permission boundary to restrict `sts:AssumeRole` in non-admin accounts |
| `roleSessionName: backup-restore-session` originated from IAM user, not service role | **Enhancement opportunity:** Build a behavioral rule that fires when `roleSessionName` contains automation-suggesting strings (`backup`, `restore`, `scheduler`, `lambda`) but `userIdentity.type` is `IAMUser`. This catches living-off-the-land session naming with low false positive rate. |

---

## Lab Context

This playbook was developed and validated against simulated attack activity in the `cloud-attack-detection-lab` environment:

- **Attack script:** `attacks/privilege_escalation.py`
- **Wazuh rules:** `/var/ossec/etc/rules/cloud_attack_lab.xml`
- **CloudTrail source:** `cloud-attack-lab-cloudtrail-logs-267949707794`
- **Detection validated:** 2026-03-14, rules 100201 and 100202 confirmed firing in `wazuh-alerts-4.x-*`