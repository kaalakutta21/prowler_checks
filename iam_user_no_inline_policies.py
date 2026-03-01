#!/usr/bin/env python3

import boto3
import argparse
import csv
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
            RoleSessionName="iam-user-policy-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_users_no_direct_policies(session):

    iam = session.client("iam")

    results = []
    non_compliant = 0
    total_checked = 0

    paginator = iam.get_paginator("list_users")

    users = []

    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    print(f"\nTotal IAM Users Found: {len(users)}\n")

    for user in tqdm(users, desc="Evaluating IAM Users"):

        total_checked += 1

        username = user["UserName"]

        # Attached managed policies
        attached = iam.list_attached_user_policies(UserName=username)
        attached_count = len(attached.get("AttachedPolicies", []))

        # Inline policies
        inline = iam.list_user_policies(UserName=username)
        inline_count = len(inline.get("PolicyNames", []))

        if attached_count == 0 and inline_count == 0:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            non_compliant += 1

        results.append({
            "UserName": username,
            "AttachedPolicies": attached_count,
            "InlinePolicies": inline_count,
            "Status": status
        })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"iam_users_no_direct_policies_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "UserName",
            "AttachedPolicies",
            "InlinePolicies",
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
        description="Ensure IAM users have no inline or attached policies"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_users_no_direct_policies(session)

    print("\n====================================================")
    print("CONTROL: IAM Users Have No Inline or Attached Policies")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Users Checked : {total_checked}")
    print(f"Compliant           : {compliant}")
    print(f"Non-Compliant       : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
