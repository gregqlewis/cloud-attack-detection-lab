# cloud-attack-detection-lab
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