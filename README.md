# Cloud Attack Detection Lab

A hands-on cloud security lab simulating real AWS attacks and building detection mechanisms using CloudTrail, VPC Flow Logs, GuardDuty, Python, Sigma rules, and Wazuh/OpenSearch.

This project demonstrates a purple team detection engineering workflow — simulating attacker techniques, capturing evidence across multiple log sources, building custom detection rules, and automating response.

**Author:** Greg Lewis | [gregqlewis.com](https://gregqlewis.com)

---

## Architecture

```
Attack Simulation (Kali / Python scripts)
│
▼
AWS Environment (IAM, S3, VPC)
│
▼
Cloud Logs
├── CloudTrail — API call audit trail (control + data plane)
├── VPC Flow Logs — network-level traffic metadata
└── GuardDuty — AWS-native managed threat detection
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
| IAM Enumeration | T1069.003 | ✅ Complete |
| Privilege Escalation via Role Abuse | T1078.004 | ✅ Complete |
| Credential Theft | T1552.005 | ✅ Complete |
| S3 Data Exfiltration | T1530 | ✅ Complete |
| Unauthorized API Usage | T1106 | 🔜 Planned |

---

## Where We Stand

```
Attack Simulation
✅ iam_enum.py — T1069.003
✅ privilege_escalation.py — T1078.004
✅ credential_theft.py — T1552.005
✅ s3_exfil.py — T1530

Detection Engineering
✅ sigma/iam_enum.yml
✅ sigma/privilege_escalation.yml
✅ sigma/credential_theft.yml
✅ sigma/s3_exfil.yml
✅ detections/wazuh/cloud_attack_lab.xml — custom Wazuh rules 100201–100204
✅ detections/wazuh/README.md — rule design decisions and production tuning guidance
✅ detections/opensearch/cloudtrail_queries.md — DQL queries per TTP

Response Playbooks
✅ playbooks/iam_compromise_response.md — T1069.003 + T1078.004
✅ playbooks/s3_exfil_response.md — T1530

Detection Pipeline
✅ Wazuh 4.14.3 ingesting CloudTrail via wodle-aws
✅ Custom rules 100201–100204 firing with MITRE tags
✅ Alerts confirmed in wazuh-alerts-4.x-* index
✅ 6 confirmed hits across all four TTPs
```

---

## 🎓 Python Bootcamp

An interactive Python training app built directly from this lab's attack simulation scripts. It teaches Python fundamentals through the lens of cloud security — every concept is grounded in real CloudTrail events, boto3 patterns, and MITRE ATT&CK techniques from this project.

**🔗 Live App:** [gregqlewis.com/cloud-attack-detection-lab/bootcamp/](https://gregqlewis.com/cloud-attack-detection-lab/bootcamp/)

### What It Covers

| Mission | Python Concepts | Lab Script | MITRE |
|---|---|---|---|
| Mission 1: Decode the Evidence | Variables, Dictionaries, Boolean Comparison | `iam_enum.py` | T1069.003 |
| Mission 2: Pattern Recognition | Lists, Loops, Conditionals, `.lower()`, `+=` | `credential_theft.py` | T1530 |
| Mission 3: Build Your First Detection Rule | Functions, Parameters, Return Values, `.get()` | `privilege_escalation.py` | T1078.004 |
| Mission 4: The Attack Chain Analyzer | Classes, `__init__`, `self`, State Persistence | `credential_theft.py` | T1552.005 |

### How It Works

- Each mission opens with a simulated SOC alert tied to a real attack scenario from this lab
- Concept slides explain each Python topic in plain English before any coding
- Fill-in-the-blank challenges use real CloudTrail event structures from the lab's evidence files
- Answers are graded with per-question XP — incorrect answers earn 0 XP, hints cost 10 XP
- Progress saves in `localStorage` at the hosted URL

### Stack
React + Vite, deployed to GitHub Pages via `gh-pages`. Source in `bootcamp/`.

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
│   ├── main.tf                # provider config, budget alert
│   ├── cloudtrail.tf          # CloudTrail trail and hardened log bucket
│   ├── guardduty.tf           # GuardDuty detector with SNS alerting
│   ├── vpc_flow_logs.tf       # VPC and flow log configuration
│   ├── iam.tf                 # attacker identity and misconfigured role
│   ├── s3.tf                  # target bucket and simulated sensitive data
│   └── variables.tf           # centralized variable definitions
├── attack-simulation/
│   ├── evidence/              # Redacted CloudTrail JSON evidence
│   ├── iam_enum.py            # T1069.003 - IAM enumeration
│   ├── iam_enum_cloudtrail_event.json
│   ├── privilege_escalation.py  # T1078.004 - role assumption abuse
│   ├── credential_theft.py    # T1552.005 - credential discovery
│   ├── s3_exfil.py            # T1530 - S3 data exfiltration
│   ├── requirements.txt
│   └── README.md
├── detections/
│   ├── sigma/                 # Sigma rules per attack scenario
│   │   ├── iam_enum.yml
│   │   ├── privilege_escalation.yml
│   │   ├── credential_theft.yml
│   │   └── s3_exfil.yml
│   ├── wazuh/                 # Custom Wazuh rules
│   │   ├── cloud_attack_lab.xml  # Rules 100201–100204 with MITRE tags
│   │   └── README.md          # Rule design decisions + production tuning
│   ├── opensearch/            # DQL queries per TTP
│   │   └── cloudtrail_queries.md
│   └── python/                # Python log analysis scripts
├── playbooks/
│   ├── iam_compromise_response.md  # T1069.003 + T1078.004 response
│   └── s3_exfil_response.md        # T1530 response
├── bootcamp/                  # Interactive Python training app
│   ├── src/App.jsx            # Full bootcamp game — React + Vite
│   ├── vite.config.js
│   └── README.md
└── blog-post/
    └── cloud-attack-detection-lab.md
```

---

## Detection Design Decisions

### Why Multi-Region CloudTrail
CloudTrail is configured as a multi-region trail rather than region-scoped. An attacker with valid credentials is not constrained to operate in the same region as the defender's primary workspace. Operating in an unwatched region is a low-effort evasion technique that a single-region trail misses entirely. Setting `is_multi_region_trail = true` ensures all API activity across every AWS region flows into the same detection pipeline regardless of where the attacker operates.

**MITRE ATT&CK reference:** T1535 - Unused/Unsupported Cloud Regions

### Why Both Management and Data Events
CloudTrail management events capture control plane activity — creating and modifying resources. Data events capture data plane activity — actual object-level operations like S3 GetObject. S3 exfiltration is invisible without data events enabled. The attacker's bucket manipulation shows up in management events, but the actual file downloads do not. Both are required for complete visibility.

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
During initial deployment, CloudTrail failed to create because it validated the S3 bucket policy at creation time — before Terraform had finished applying it. Terraform could not infer this dependency automatically from resource references alone. Fix: added explicit `depends_on` to the CloudTrail trail resource pointing to both the bucket policy and public access block. This is a common pattern when AWS services validate dependent resources at creation time rather than at runtime.

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
# Use credentials from:
terraform output attacker_access_key_id
# and:
terraform output attacker_secret_access_key
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
| React + Vite | Interactive Python bootcamp training app |