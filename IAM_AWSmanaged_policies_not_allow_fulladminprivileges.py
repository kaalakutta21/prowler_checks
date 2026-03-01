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
            RoleSessionName="iam-admin-audit"
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
# FULL ADMIN DETECTION
# ==================================================

def is_full_admin(policy_doc):

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        action = stmt.get("Action")
        resource = stmt.get("Resource")

        # Normalize action
        if isinstance(action, list):
            action_is_star = "*" in action
        else:
            action_is_star = action == "*"

        # Normalize resource
        if isinstance(resource, list):
            resource_is_star = "*" in resource
        else:
            resource_is_star = resource == "*"

        if action_is_star and resource_is_star:
            return True

    return False

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_admin_managed_policies(session):

    iam = session.client("iam")

    full_admin_policies = []

    paginator = iam.get_paginator("list_policies")

    # Step 1: Collect only AWS managed policies
    aws_policies = []
    for page in paginator.paginate(Scope='AWS'):
        aws_policies.extend(page.get("Policies", []))

    print(f"\nTotal AWS Managed Policies Retrieved: {len(aws_policies)}")
    print("Filtering full '*:*' admin policies...\n")

    # Step 2: Filter only full admin policies
    for policy in tqdm(aws_policies, desc="Analyzing Policies"):

        policy_arn = policy["Arn"]
        policy_name = policy["PolicyName"]
        default_version_id = policy["DefaultVersionId"]

        try:
            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )

            policy_doc = version["PolicyVersion"]["Document"]

            if is_full_admin(policy_doc):
                full_admin_policies.append({
                    "PolicyName": policy_name,
                    "PolicyArn": policy_arn
                })

        except ClientError:
            continue

    print(f"\nFull '*:*' Admin Policies Identified: {len(full_admin_policies)}\n")

    # Step 3: Check attachments only for those policies
    results = []
    non_compliant = 0

    for policy in tqdm(full_admin_policies, desc="Checking Attachments"):

        policy_name = policy["PolicyName"]
        policy_arn = policy["PolicyArn"]

        try:
            entities = iam.list_entities_for_policy(
                PolicyArn=policy_arn
            )

            users = entities.get("PolicyUsers", [])
            roles = entities.get("PolicyRoles", [])
            groups = entities.get("PolicyGroups", [])

            attached_count = len(users) + len(roles) + len(groups)

            if attached_count > 0:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "PolicyName": policy_name,
                "AttachedUsers": len(users),
                "AttachedRoles": len(roles),
                "AttachedGroups": len(groups),
                "Status": status
            })

        except ClientError:
            continue

    total_checked = len(full_admin_policies)
    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"iam_admin_policies_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "PolicyName",
            "AttachedUsers",
            "AttachedRoles",
            "AttachedGroups",
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
        description="Ensure AWS Managed full admin policies are not attached"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_admin_managed_policies(session)

    print("\n====================================================")
    print("CONTROL: AWS Managed Full Admin Policies Not Attached")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Admin Policies Checked : {total_checked}")
    print(f"Compliant                    : {compliant}")
    print(f"Non-Compliant                : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
