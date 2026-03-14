# Wazuh Custom Detection Rules — Cloud Attack Lab

**Rule file:** `cloud_attack_lab.xml`  
**Rule ID range:** 100201–100204  
**Rule group:** `cloud_attack_lab`  
**Last updated:** 2026-03-14

---

## Overview

These rules detect a four-stage simulated attack chain against AWS infrastructure, modeled after real-world cloud intrusion patterns. All rules extend Wazuh's base CloudTrail decoder (`if_sid: 80200`) and operate against events ingested via `wodle-aws` from CloudTrail.

**Field path note:** Field references use `aws.*` (e.g., `aws.eventSource`) not `data.aws.*`. This reflects the parsed field structure in `wazuh-alerts-4.x-*` and must match exactly for rules to fire.

**Attack chain:**
```
IAM Enumeration (100201)
    → Privilege Escalation via AssumeRole (100202)
        → Credential Theft / Recon (100203)
            → S3 Data Exfiltration (100204)
```

---

## Rule Reference

### Rule 100201 — IAM Enumeration
**MITRE:** T1069.003 — Permission Groups Discovery: Cloud Groups  
**Severity:** Level 10  
**Fires on:** `ListUsers`, `ListRoles`, `ListPolicies` from `iam.amazonaws.com`

**Design decisions:**
- Scoped to `cloud-attack-lab-attacker` username in this lab. In production, remove the username filter and instead build an allow-list of known automation ARNs, or scope to `userIdentity.type: IAMUser` to reduce noise from service roles performing routine IAM reads.
- `ListUsers` / `ListRoles` / `ListPolicies` in combination represent systematic enumeration — an attacker mapping the account before choosing an escalation path.

**Production tuning guidance:**
- Suppress known Cloud Ops or security tooling ARNs via inline exceptions rather than disabling the rule
- Consider raising severity if all three event names fire within a short window from the same principal (correlation rule opportunity)

---

### Rule 100202 — Privilege Escalation via AssumeRole
**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts  
**Severity:** Level 12  
**Fires on:** `AssumeRole` from `sts.amazonaws.com` where `userIdentity.type` is `IAMUser`

**Design decisions:**
- `userIdentity.type: IAMUser` is the key scoping field. `AssumeRole` is called constantly by Lambda, ECS, EC2 instance profiles, and CI/CD pipelines — all of which present as `AssumedRole` or `AWSService` type. Filtering to `IAMUser` isolates human-initiated role assumption, which is the high-risk pattern.
- In this lab, additionally scoped to `cloud-attack-lab-attacker` to prevent noise during development.

**Lab-confirmed finding:** The attacker script used `roleSessionName: backup-restore-session` — a deliberate living-off-the-land naming technique designed to mimic legitimate backup automation. The calling identity was an IAM user, not a service role. This contradiction between session name semantics and caller identity type is a high-fidelity behavioral signal.

**Production tuning guidance:**
- In production, drop the username filter and retain `userIdentity.type: IAMUser`
- Layer additional signal: source IP outside corporate CIDR, `roleSessionName` containing automation keywords (`backup`, `restore`, `scheduler`, `lambda`) from a human identity, or target role ARN matching a sensitive role name pattern
- **Known detection gap:** Rule 100202 covers `AssumeRole`-based escalation only. `AttachUserPolicy` and `CreatePolicyVersion` (direct policy manipulation) are not currently covered. A rule 100205 scoped to those event names on `iam.amazonaws.com` would complete T1078.004 coverage.

---

### Rule 100203 — Credential Theft Recon (GetCallerIdentity)
**MITRE:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata  
**Severity:** Level 10  
**Fires on:** `GetCallerIdentity` from `sts.amazonaws.com`

**Design decisions:**
- `GetCallerIdentity` is the first call an attacker makes after obtaining stolen credentials — it confirms the credentials are valid and reveals what identity they belong to. It has no legitimate operational purpose that justifies broad use outside of initial SDK configuration.
- The false positive tradeoff is acceptable at baseline: `GetCallerIdentity` from an attacker identity (`cloud-attack-lab-attacker`) is unambiguous recon signal.
- In production, tighten via geolocation rules (fire only if source IP is outside known corporate ranges) or correlation (fire only if `GetCallerIdentity` precedes other suspicious API calls within the same session window).

**Production tuning guidance:**
- Consider enriching alerts with threat intel IP feed lookups on `sourceIPAddress`
- A `GetCallerIdentity` call from a source IP with no prior CloudTrail history in the account is near-zero false positive

---

### Rule 100204 — S3 Data Exfiltration
**MITRE:** T1530 — Data from Cloud Storage  
**Severity:** Level 12  
**Fires on:** `PutObject` or `GetObject` on `cloud-attack-lab-exfil-bucket` from `s3.amazonaws.com`

**Design decisions:**
- Scoped to the specific exfil bucket by `requestParameters.bucketName`. In production, replace with a list of sensitive bucket names or use a tag-based approach if your SIEM supports it.
- **`PutObject` is the higher-confidence signal.** `GetObject` from a bucket could be legitimate access by an authorized user. `PutObject` to an exfil-named bucket from the attacker identity represents data staging — an explicit step in the exfiltration chain.
- Rule fires on individual events, not a volume threshold. In production, a volume threshold (e.g., >50 `GetObject` calls within 5 minutes from the same principal) reduces false positives on buckets with legitimate high-volume access patterns.

**Lab-confirmed attack sequence:**
```
ListBuckets → ListObjects → GetObject → PutObject → ListObjects
```

**Production tuning guidance:**
- Split into two rules: one for `PutObject` (immediate containment threshold) and one for `GetObject` volume (investigation threshold)
- Add `userIdentity.arn` context to alert output for faster triage
- Consider CloudWatch Metric Alarm as a complementary control for `GetObject` volume spikes independent of Wazuh ingestion latency

---

## Validation

All four rules confirmed firing in `wazuh-alerts-4.x-*` index, visible in OpenSearch Discover under:
```
rule.groups: cloud_attack_lab
```
Six confirmed hits across rules 100201–100204 as of 2026-03-14.

**Wazuh version:** 4.14.3  
**CloudTrail source bucket:** `cloud-attack-lab-cloudtrail-logs-267949707794`  
**Index pattern:** `wazuh-alerts-*`