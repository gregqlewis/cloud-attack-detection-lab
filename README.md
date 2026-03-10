# cloud-attack-detection-lab
## Lab Infrastructure — Intentional Misconfiguration Map

| Control | cloudtrail-logs bucket | target-data bucket |
|---|---|---|
| Encryption | ✅ AES-256 | ❌ None |
| Versioning | ✅ Enabled | ❌ None |
| Deletion protection | ✅ Deny policy | ❌ None |
| Public access block | ✅ All four settings | ❌ Partial |
| Bucket policy | ✅ Restrictive | ❌ None |

The target-data bucket represents a common real-world finding: 
an S3 bucket provisioned quickly without security controls, 
containing data that was never meant to be exposed.

## Detection Design Decisions

### Why Multi-Region CloudTrail
CloudTrail is configured as a multi-region trail rather than 
region-scoped. An attacker with valid credentials is not constrained 
to operate in the same region as the defender's primary workspace. 
Operating in an unwatched region is a low-effort evasion technique 
that a single-region trail misses entirely.

Setting `is_multi_region_trail = true` ensures all API activity 
across every AWS region flows into the same detection pipeline 
regardless of where the attacker operates.

MITRE ATT&CK reference: T1535 - Unused/Unsupported Cloud Regions

### Why Both Management and Data Events
CloudTrail management events capture control plane activity — 
creating and modifying resources. Data events capture data plane 
activity — actual object-level operations like S3 GetObject.

S3 exfiltration is invisible without data events enabled. The 
attacker's bucket manipulation shows up in management events, 
but the actual file downloads do not. Both are required for 
complete visibility.

### Why GuardDuty Alongside Custom Sigma Rules
GuardDuty provides AWS-native threat detection against the same 
log sources. Running both allows direct comparison between 
managed detection and custom-built rules — a core detection 
engineering skill. Gaps between what GuardDuty finds and what 
custom rules find inform rule quality and tuning.

### Why VPC Flow Logs
CloudTrail shows what API calls were made. VPC Flow Logs show 
what network connections occurred. For exfiltration scenarios 
specifically, seeing both the API call and the corresponding 
network connection tells a complete story that neither source 
tells alone.

## ⚠️ Cost Management & Teardown

This lab uses pay-per-use AWS resources. Always destroy resources
when not actively working to avoid unnecessary charges.

### Estimated Cost
- Active lab session: ~$0.01–0.05/hour
- Idle (nothing running): ~$0.00
- Monthly max (with budget alert): $10 hard ceiling

### Teardown Command
Run this at the end of every lab session:

    terraform destroy -auto-approve

### What Gets Destroyed
- CloudTrail trail and S3 log bucket
- Attacker IAM user and policies
- Target S3 bucket

### What Persists (by design)
- Budget alert (intentional)
- Your local terraform.tfstate file