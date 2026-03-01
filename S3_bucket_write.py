#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError

# --------------------------------------------------
# AUTH
# --------------------------------------------------

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="s3-write-audit"
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

# --------------------------------------------------
# WRITE ACTIONS
# --------------------------------------------------

WRITE_ACTIONS = {
    "s3:putobject",
    "s3:deleteobject",
    "s3:deleteobjectversion",
    "s3:putobjectacl",
    "s3:putbucketacl",
    "s3:putbucketpolicy",
    "s3:*"
}

def action_is_write(action):
    if isinstance(action, str):
        action = [action]

    for act in action:
        act_lower = act.lower()
        if act_lower in WRITE_ACTIONS:
            return True
        if act_lower.startswith("s3:") and "*" in act_lower:
            return True

    return False

# --------------------------------------------------
# PRINCIPAL CHECK
# --------------------------------------------------

def principal_is_public(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")
        if aws_principal == "*":
            return True
    return False

# --------------------------------------------------
# RESTRICTIVE CONDITION CHECK (OPTION B)
# --------------------------------------------------

RESTRICTIVE_KEYS = {
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:userid",
    "aws:principalarn",
    "aws:sourcearn"
}

def has_restrictive_condition(statement):
    condition = statement.get("Condition")
    if not condition:
        return False

    # Condition structure: { Operator: { Key: Value } }
    for operator in condition.values():
        for key in operator.keys():
            if key.lower() in RESTRICTIVE_KEYS:
                return True

    return False

# --------------------------------------------------
# CONTROL LOGIC
# --------------------------------------------------

def check_s3_public_write(session):

    s3 = session.client("s3")

    results = []
    total_checked = 0
    non_compliant = 0

    buckets = s3.list_buckets()["Buckets"]

    for bucket in tqdm(buckets, desc="Scanning Buckets"):
        total_checked += 1
        bucket_name = bucket["Name"]
        status = "COMPLIANT"
        has_policy = "NO"

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            has_policy = "YES"
            policy_doc = json.loads(policy["Policy"])

            for stmt in policy_doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                if not principal_is_public(stmt.get("Principal")):
                    continue

                if not action_is_write(stmt.get("Action")):
                    continue

                # Option B logic
                if not has_restrictive_condition(stmt):
                    status = "NON_COMPLIANT"
                    non_compliant += 1
                    break

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                status = "COMPLIANT"
            else:
                status = "COMPLIANT"

        results.append({
            "BucketName": bucket_name,
            "HasPolicy": has_policy,
            "Status": status
        })

    compliant = total_checked - non_compliant
    return results, total_checked, compliant, non_compliant

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"s3_public_write_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "BucketName",
            "HasPolicy",
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

# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Ensure S3 buckets do not allow public WRITE access"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_s3_public_write(session)

    print("\n====================================================")
    print("CONTROL: S3 Buckets Not Publicly Writable")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Buckets Checked : {total_checked}")
    print(f"Compliant              : {compliant}")
    print(f"Non-Compliant          : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
