# iam_enum.py
# MITRE ATT&CK: T1069.003 - Cloud Groups Discovery
# Purpose: Enumerate IAM users in the target AWS account

import boto3
import json
from botocore.exceptions import ClientError  
# botocore is the library underneath boto3
# ClientError is the specific error AWS throws when an API call fails

def list_iam_users():
    client = boto3.client('iam')

    try:
        response = client.list_users()
        users = response['Users']

        print(f"Found {len(users)} IAM users:\n")

        for user in users:
            print(f"  Username: {user['UserName']}")
            print(f"  User ARN: {user['Arn']}")
            print(f"  Created:  {user['CreateDate']}")
            print("-" * 40)

    except ClientError as e:
        # e.response['Error']['Code'] gives you the specific AWS error
        # e.g. 'AccessDenied', 'NoSuchEntity'
        error_code = e.response['Error']['Code']
        error_msg  = e.response['Error']['Message']
        print(f"AWS API Error: {error_code}")
        print(f"Details: {error_msg}")

if __name__ == "__main__":
    list_iam_users()