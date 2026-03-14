# OpenSearch Detection Queries — Cloud Attack Detection Lab

These queries run against the `wazuh-alerts-*` index pattern in OpenSearch Dashboards.
All field paths confirmed from live Wazuh 4.14.3 CloudTrail event ingestion.

---

## How to use these queries

1. Open OpenSearch Dashboards → Discover
2. Select index pattern: `wazuh-alerts-*`
3. Paste the DQL query into the search bar
4. Set time range to cover your attack simulation window
5. Save each as a saved search for use in dashboards

---

## Query 1 — IAM Enumeration (T1069.003)

**What it detects:** Programmatic IAM enumeration by a non-admin identity.
Fires on the ListUsers/ListRoles/ListPolicies calls from `iam_enum.py`
and the enumeration phase of `credential_theft.py`.

```
data.aws.eventSource: "iam.amazonaws.com"
AND data.aws.eventName: ("ListUsers" OR "ListRoles" OR "ListPolicies" OR "GetPolicy" OR "ListAttachedRolePolicies")
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

**Key fields to add as columns in Discover:**
- `data.aws.eventName`
- `data.aws.userIdentity.userName`
- `data.aws.sourceIPAddress`
- `data.aws.eventTime`

---

## Query 2 — Privilege Escalation via AssumeRole (T1078.004)

**What it detects:** An IAM user assuming a privileged role. Fires on the
AssumeRole call in `privilege_escalation.py`, `credential_theft.py`,
and `s3_exfil.py`.

```
data.aws.eventSource: "sts.amazonaws.com"
AND data.aws.eventName: "AssumeRole"
AND data.aws.userIdentity.type: "IAMUser"
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

**High-fidelity variant** — add post-escalation S3 access:
```
(data.aws.eventSource: "sts.amazonaws.com" AND data.aws.eventName: "AssumeRole" AND data.aws.userIdentity.type: "IAMUser")
OR
(data.aws.eventSource: "s3.amazonaws.com" AND data.aws.eventName: ("GetObject" OR "ListObjectsV2") AND data.aws.userIdentity.type: "AssumedRole")
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

---

## Query 3 — Credential Theft Chain (T1552.005)

**What it detects:** The post-IMDS-theft usage pattern — GetCallerIdentity
followed by rapid enumeration. The enumeration chain from a single identity
is the key signal since the actual IMDS call never appears in CloudTrail.

```
data.aws.eventName: ("GetCallerIdentity" OR "ListUsers" OR "ListRoles" OR "ListBuckets")
AND data.aws.userIdentity.type: "IAMUser"
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

**Note:** For highest fidelity, correlate these four event names from the
same `data.aws.sourceIPAddress` within a 10-minute window. That correlation
is not possible in a single DQL query — implement as an alert in Wazuh's
rule engine or use an OpenSearch anomaly detector.

---

## Query 4 — S3 Data Exfiltration (T1530)

**What it detects:** The GetObject + PutObject cross-bucket exfiltration
pattern. This is the signal unique to `s3_exfil.py` — reading from the
target bucket and writing to the staging bucket in the same session.

**GetObject on sensitive paths:**
```
data.aws.eventSource: "s3.amazonaws.com"
AND data.aws.eventName: "GetObject"
AND data.aws.userIdentity.type: "AssumedRole"
AND data.aws.requestParameters.key: ("config/*" OR "finance/*" OR "hr/*" OR "secrets/*")
```

**PutObject to staging bucket (the exfiltration write):**
```
data.aws.eventSource: "s3.amazonaws.com"
AND data.aws.eventName: "PutObject"
AND data.aws.userIdentity.type: "AssumedRole"
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

**Combined exfil chain query:**
```
data.aws.eventSource: "s3.amazonaws.com"
AND data.aws.eventName: ("GetObject" OR "PutObject" OR "ListObjectsV2")
AND data.aws.userIdentity.type: "AssumedRole"
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

**Key fields to add as columns in Discover:**
- `data.aws.eventName`
- `data.aws.requestParameters.bucketName`
- `data.aws.requestParameters.key`
- `data.aws.userIdentity.arn`
- `data.aws.sourceIPAddress`

---

## Full Attack Chain Query

Run this to see all four attack scenarios in a single view:

```
(data.aws.eventName: ("ListUsers" OR "ListRoles" OR "ListPolicies") AND data.aws.eventSource: "iam.amazonaws.com")
OR (data.aws.eventName: "AssumeRole" AND data.aws.eventSource: "sts.amazonaws.com")
OR (data.aws.eventName: "GetCallerIdentity" AND data.aws.eventSource: "sts.amazonaws.com")
OR (data.aws.eventName: ("GetObject" OR "PutObject") AND data.aws.eventSource: "s3.amazonaws.com" AND data.aws.userIdentity.type: "AssumedRole")
AND NOT data.aws.userIdentity.userName: "greg-admin"
```

---

## Index pattern
`wazuh-alerts-*`

## Recommended columns for all queries
- `timestamp`
- `data.aws.eventName`
- `data.aws.eventSource`
- `data.aws.userIdentity.type`
- `data.aws.userIdentity.userName`
- `data.aws.sourceIPAddress`
- `rule.description`