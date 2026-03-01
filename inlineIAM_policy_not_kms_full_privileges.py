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
            RoleSessionName="inline-kms-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name="us-east-1"
        )
    return boto3.Session(region_name="us-east-1")

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# DETECTION LOGIC
# ==================================================

def allows_kms_wildcard(statement):

    if statement.get("Effect") != "Allow":
        return False

    actions = statement.get("Action")
    if not actions:
        return False

    if isinstance(actions, str):
        actions = [actions]

    for action in actions:
        action_lower = action.lower()

        if action_lower == "*" or action_lower == "kms:*":
            return True

    return False

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_inline_kms_privileges(session):

    iam = session.client("iam")

    results = []
    non_compliant = 0
    total_checked = 0

    # ---------- USERS ----------
    users = iam.list_users()["Users"]

    for user in tqdm(users, desc="Scanning Users"):
        policies = iam.list_user_policies(UserName=user["UserName"])["PolicyNames"]

        for policy_name in policies:
            total_checked += 1

            policy_doc = iam.get_user_policy(
                UserName=user["UserName"],
                PolicyName=policy_name
            )["PolicyDocument"]

            statements = policy_doc.get("Statement", [])

            if not isinstance(statements, list):
                statements = [statements]

            violation = any(allows_kms_wildcard(stmt) for stmt in statements)

            if violation:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "IdentityType": "User",
                "IdentityName": user["UserName"],
                "PolicyName": policy_name,
                "Status": status
            })

    # ---------- ROLES ----------
    roles = iam.list_roles()["Roles"]

    for role in tqdm(roles, desc="Scanning Roles"):
        policies = iam.list_role_policies(RoleName=role["RoleName"])["PolicyNames"]

        for policy_name in policies:
            total_checked += 1

            policy_doc = iam.get_role_policy(
                RoleName=role["RoleName"],
                PolicyName=policy_name
            )["PolicyDocument"]

            statements = policy_doc.get("Statement", [])

            if not isinstance(statements, list):
                statements = [statements]

            violation = any(allows_kms_wildcard(stmt) for stmt in statements)

            if violation:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "IdentityType": "Role",
                "IdentityName": role["RoleName"],
                "PolicyName": policy_name,
                "Status": status
            })

    # ---------- GROUPS ----------
    groups = iam.list_groups()["Groups"]

    for group in tqdm(groups, desc="Scanning Groups"):
        policies = iam.list_group_policies(GroupName=group["GroupName"])["PolicyNames"]

        for policy_name in policies:
            total_checked += 1

            policy_doc = iam.get_group_policy(
                GroupName=group["GroupName"],
                PolicyName=policy_name
            )["PolicyDocument"]

            statements = policy_doc.get("Statement", [])

            if not isinstance(statements, list):
                statements = [statements]

            violation = any(allows_kms_wildcard(stmt) for stmt in statements)

            if violation:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "IdentityType": "Group",
                "IdentityName": group["GroupName"],
                "PolicyName": policy_name,
                "Status": status
            })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"inline_kms_wildcard_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "IdentityType",
            "IdentityName",
            "PolicyName",
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
        description="Ensure inline IAM policies do not allow kms:* privileges"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_inline_kms_privileges(session)

    print("\n====================================================")
    print("CONTROL: Inline IAM Policy Does Not Allow kms:* Privileges")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Inline Policies Checked : {total_checked}")
    print(f"Compliant                      : {compliant}")
    print(f"Non-Compliant                  : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
