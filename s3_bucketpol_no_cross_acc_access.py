#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="s3-cross-account-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# CROSS ACCOUNT DETECTION
# ==================================================

def is_cross_account(statement, current_account):

    if statement.get("Effect") != "Allow":
        return False

    principal = statement.get("Principal")
    if not principal:
        return False

    # Ignore public (handled in other control)
    if principal == "*":
        return False

    aws_principals = []

    if isinstance(principal, dict):
        aws_field = principal.get("AWS")
        if isinstance(aws_field, str):
            aws_principals.append(aws_field)
        elif isinstance(aws_field, list):
            aws_principals.extend(aws_field)

    for arn in aws_principals:
        if arn == "*":
            continue

        if ":iam::" in arn:
            account_id = arn.split(":")[4]
            if account_id != current_account:
                return True

    return False

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_s3_cross_account(session):

    s3 = session.client("s3")
    account_id = get_account_id(session)

    results = []
    non_compliant = 0
    total_checked = 0

    buckets = s3.list_buckets().get("Buckets", [])

    print(f"\nTotal Buckets Found: {len(buckets)}\n")

    for bucket in tqdm(buckets, desc="Evaluating Buckets"):

        bucket_name = bucket["Name"]
        total_checked += 1
        cross_account_found = False

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy["Policy"])
        except ClientError as e:
            # No policy means compliant
            results.append({
                "BucketName": bucket_name,
                "CrossAccountAccess": False,
                "Status": "COMPLIANT"
            })
            continue

        statements = policy_doc.get("Statement", [])

        for statement in statements:
            if is_cross_account(statement, account_id):
                cross_account_found = True
                break

        if cross_account_found:
            status = "NON_COMPLIANT"
            non_compliant += 1
        else:
            status = "COMPLIANT"

        results.append({
            "BucketName": bucket_name,
            "CrossAccountAccess": cross_account_found,
            "Status": status
        })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"s3_cross_account_policy_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "BucketName",
            "CrossAccountAccess",
            "Status"
        ]

        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "Account": account_id,
                **r
            })

    return filename

# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ensure S3 bucket policy does not allow cross-account access"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_s3_cross_account(session)

    print("\n====================================================")
    print("CONTROL: S3 Bucket Policy Does Not Allow Cross Account Access")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Buckets Checked : {total_checked}")
    print(f"Compliant             : {compliant}")
    print(f"Non-Compliant         : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
