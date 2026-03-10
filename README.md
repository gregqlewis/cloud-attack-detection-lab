# Cloud Attack Detection Lab

A hands-on cloud security lab simulating real AWS attacks and building detection mechanisms using CloudTrail, VPC Flow Logs, GuardDuty, Python, Sigma rules, and Wazuh/OpenSearch.

This project demonstrates a purple team detection engineering workflow — simulating attacker techniques, capturing evidence across multiple log sources, building custom detection rules, and automating response.

**Author:** Greg Lewis | [gregqlewis.com](https://gregqlewis.com)

---

## Architecture

```
Attack Simulation
(Kali / Python scripts)
        │
        ▼
AWS Environment
(IAM, S3, VPC)
        │
        ▼
Cloud Logs
├── CloudTrail       — API call audit trail (control + data plane)
├── VPC Flow Logs    — network-level traffic metadata
└── GuardDuty        — AWS-native managed threat detection
        │
        ▼
Detection Layer
├── Python log analysis scripts
├── Sigma rules (mapped to MITRE ATT&CK + MITRE ATLAS)
└── Custom OpenSearch queries
        │
        ▼
Security Monitoring
└── Wazuh / OpenSearch (homelab SIEM)
        │
        ▼
Response
├── Automated response (Lambda / Wazuh active response)
└── Documented investigation playbooks
```

---

## Attack Scenarios

| Scenario | MITRE ATT&CK | Status |
|---|---|---|
| IAM Enumeration | T1069.003 | 🔜 In Progress |
| Privilege Escalation via Role Abuse | T1078.004 | 🔜 Planned |
| Credential Theft | T1552.005 | 🔜 Planned |
| S3 Data Exfiltration | T1530 | 🔜 Planned |
| Unauthorized API Usage | T1106 | 🔜 Planned |

---

## Infrastructure Status

| Resource | Status | Purpose |
|---|---|---|
| CloudTrail | ✅ Active | API call audit trail |
| CloudTrail S3 Bucket | ✅ Hardened | Log storage |
| GuardDuty | ✅ Active | Managed threat detection |
| VPC + Flow Logs | ✅ Active | Network-level visibility |
| Attacker IAM User | ✅ Active | Attack simulation identity |
| Privileged IAM Role | ✅ Active | Privilege escalation target |
| Target S3 Bucket | ✅ Misconfigured (intentional) | Exfiltration target |
| SNS Alerting | ✅ Active | GuardDuty finding notifications |

---

## Repository Structure

```
cloud-attack-detection-lab/
├── README.md
├── terraform/
│   ├── main.tf                  # provider config, budget alert
│   ├── cloudtrail.tf            # CloudTrail trail and hardened log bucket
│   ├── guardduty.tf             # GuardDuty detector with SNS alerting
│   ├── vpc_flow_logs.tf         # VPC and flow log configuration
│   ├── iam.tf                   # attacker identity and misconfigured role
│   ├── s3.tf                    # target bucket and simulated sensitive data
│   └── variables.tf             # centralized variable definitions
├── attack-simulation/
│   ├── iam_enum.py              # T1069.003 - IAM enumeration
│   ├── privilege_escalation.py  # T1078.004 - role assumption abuse
│   ├── credential_theft.py      # T1552.005 - credential discovery
│   ├── s3_exfil.py              # T1530 - S3 data exfiltration
│   └── README.md
├── detections/
│   ├── sigma/                   # Sigma rules per attack scenario
│   ├── opensearch/              # Converted OpenSearch queries
│   └── python/                  # Python log analysis scripts
├── playbooks/
│   ├── iam_compromise_response.md
│   └── s3_exfil_response.md
└── blog-post/
    └── cloud-attack-detection-lab.md
```

---

## Detection Design Decisions

### Why Multi-Region CloudTrail
CloudTrail is configured as a multi-region trail rather than region-scoped. An attacker with valid credentials is not constrained to operate in the same region as the defender's primary workspace. Operating in an unwatched region is a low-effort evasion technique that a single-region trail misses entirely.

Setting `is_multi_region_trail = true` ensures all API activity across every AWS region flows into the same detection pipeline regardless of where the attacker operates.

**MITRE ATT&CK reference:** T1535 - Unused/Unsupported Cloud Regions

### Why Both Management and Data Events
CloudTrail management events capture control plane activity — creating and modifying resources. Data events capture data plane activity — actual object-level operations like S3 GetObject.

S3 exfiltration is invisible without data events enabled. The attacker's bucket manipulation shows up in management events, but the actual file downloads do not. Both are required for complete visibility.

### Why GuardDuty Alongside Custom Sigma Rules
GuardDuty provides AWS-native threat detection against the same log sources. Running both allows direct comparison between managed detection and custom-built rules — a core detection engineering skill. Gaps between what GuardDuty finds and what custom rules find inform rule quality and tuning.

### Why VPC Flow Logs
CloudTrail shows what API calls were made. VPC Flow Logs show what network connections occurred. For exfiltration scenarios specifically, seeing both the API call and the corresponding network connection tells a complete story that neither source tells alone.

---

## Lab Infrastructure — Intentional Misconfiguration Map

| Control | cloudtrail-logs bucket | target-data bucket |
|---|---|---|
| Encryption | ✅ AES-256 | ❌ None |
| Versioning | ✅ Enabled | ❌ None |
| Deletion protection | ✅ Deny policy | ❌ None |
| Public access block | ✅ All four settings | ❌ Partial |
| Bucket policy | ✅ Restrictive | ❌ None |

The target-data bucket represents a common real-world finding: an S3 bucket provisioned quickly without security controls, containing data that was never meant to be exposed.

---

## Lessons Learned

### Terraform depends_on — CloudTrail Bucket Policy Race Condition
During initial deployment, CloudTrail failed to create because it validated the S3 bucket policy at creation time — before Terraform had finished applying it. Terraform could not infer this dependency automatically from resource references alone.

Fix: added explicit `depends_on` to the CloudTrail trail resource pointing to both the bucket policy and public access block. This is a common pattern when AWS services validate dependent resources at creation time rather than at runtime.

### Accidentally Committed terraform.tfvars
During lab setup, `terraform.tfvars` containing the AWS account ID and alert email was accidentally committed to the public repository. The file did not contain access keys — credentials live in `~/.aws/credentials` which was never tracked.

Remediation steps taken:
1. Assessed exact contents of the exposed file
2. Removed file from git tracking with `git rm --cached`
3. Scrubbed entire git history using `git filter-repo`
4. Force pushed rewritten history to GitHub
5. Strengthened `.gitignore` with `*.tfvars` wildcard

**MITRE ATT&CK reference:** T1552.001 - Unsecured Credentials: Credentials in Files

Tools that prevent this in production:
- `git-secrets` — pre-commit hook that blocks credential commits
- `truffleHog` — scans git history for exposed secrets
- `AWS Macie` — detects sensitive data patterns in S3

> *"The irony of a security lab teaching its first lesson before a single attack script was written wasn't lost on me."*

---

## Prerequisites

- AWS account with admin access
- Terraform >= 1.0
- Python 3.x with boto3
- AWS CLI configured with lab profile
- Wazuh/OpenSearch running (homelab or managed)

---

## Getting Started

### 1. Clone the repo
```bash
git clone https://github.com/gregqlewis/cloud-attack-detection-lab
cd cloud-attack-detection-lab
```

### 2. Create your local tfvars file (never committed)
```bash
cat > terraform/terraform.tfvars << EOF
aws_account_id = "YOUR_ACCOUNT_ID"
alert_email    = "your@email.com"
EOF
```

### 3. Deploy infrastructure
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 4. Configure attacker profile
```bash
aws configure --profile lab-attacker
# Use credentials from: terraform output attacker_access_key_id
# and: terraform output attacker_secret_access_key
```

---

## ⚠️ Cost Management & Teardown

This lab uses pay-per-use AWS resources. Always destroy resources when not actively working to avoid unnecessary charges.

### Estimated Cost

| Scenario | Monthly Cost |
|---|---|
| Active lab session | ~$0.01–0.05/hour |
| Idle (nothing running) | ~$0.00 |
| GuardDuty (after 30-day free trial) | ~$3–6/month |
| Monthly max (with budget alert) | $10 hard ceiling |

### Teardown Command
Run this at the end of every lab session:

```bash
terraform destroy -auto-approve
```

### What Gets Destroyed
- CloudTrail trail and S3 log bucket
- Attacker IAM user and policies
- Privileged IAM role
- Target S3 bucket and simulated data
- GuardDuty detector
- VPC and flow logs

### What Persists (by design)
- Budget alert (intentional)
- Your local `terraform.tfstate` file
- Your local `terraform.tfvars` file
- Attacker AWS CLI profile (`~/.aws/credentials`)

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| AWS | Cloud infrastructure and attack surface |
| Terraform | Infrastructure as Code — reproducible lab environment |
| Python + boto3 | Attack simulation scripts |
| Sigma | Vendor-agnostic detection rules |
| Wazuh | SIEM — log ingestion, detection, active response |
| OpenSearch | Log indexing and query engine |
| MITRE ATT&CK | Attack technique mapping |
| MITRE ATLAS | AI/ML threat mapping (credential theft scenarios) |