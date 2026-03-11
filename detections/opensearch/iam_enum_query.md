# IAM Enumeration — OpenSearch Query

**Converted from:** detections/sigma/iam_enum.yml  
**MITRE ATT&CK:** T1069.003  
**Log source:** CloudTrail → OpenSearch via Wazuh  

## How To Use This Query

1. Open OpenSearch Dashboards
2. Navigate to Dev Tools
3. Paste the query from iam_enum_query.json
4. Set the index pattern to your CloudTrail index
5. Run against your log data

## Field Mapping Notes

CloudTrail fields in OpenSearch may be nested depending on 
your Wazuh ingestion pipeline. Common variations:

| Sigma field | OpenSearch field |
|---|---|
| eventSource | data.eventSource or eventSource |
| eventName | data.eventName or eventName |
| userIdentity.userName | data.userIdentity.userName |
| userAgent | data.userAgent |

Adjust field names to match your Wazuh index mapping.