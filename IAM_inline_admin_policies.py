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
            RoleSessionName="iam-inline-admin-audit"
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

def check_inline_admin_policies(session):

    iam = session.client("iam")

    results = []
    non_compliant = 0

    # -------------------------
    # USERS
    # -------------------------
    users = iam.get_paginator("list_users")
    for page in tqdm(users.paginate(), desc="Scanning Users"):
        for user in page.get("Users", []):
            user_name = user["UserName"]

            inline_policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]

            for policy_name in inline_policies:
                policy = iam.get_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )

                policy_doc = policy["PolicyDocument"]

                if is_full_admin(policy_doc):
                    non_compliant += 1
                    results.append({
                        "IdentityType": "User",
                        "IdentityName": user_name,
                        "PolicyName": policy_name,
                        "Status": "NON_COMPLIANT"
                    })

    # -------------------------
    # ROLES
    # -------------------------
    roles = iam.get_paginator("list_roles")
    for page in tqdm(roles.paginate(), desc="Scanning Roles"):
        for role in page.get("Roles", []):
            role_name = role["RoleName"]

            inline_policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]

            for policy_name in inline_policies:
                policy = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )

                policy_doc = policy["PolicyDocument"]

                if is_full_admin(policy_doc):
                    non_compliant += 1
                    results.append({
                        "IdentityType": "Role",
                        "IdentityName": role_name,
                        "PolicyName": policy_name,
                        "Status": "NON_COMPLIANT"
                    })

    # -------------------------
    # GROUPS
    # -------------------------
    groups = iam.get_paginator("list_groups")
    for page in tqdm(groups.paginate(), desc="Scanning Groups"):
        for group in page.get("Groups", []):
            group_name = group["GroupName"]

            inline_policies = iam.list_group_policies(GroupName=group_name)["PolicyNames"]

            for policy_name in inline_policies:
                policy = iam.get_group_policy(
                    GroupName=group_name,
                    PolicyName=policy_name
                )

                policy_doc = policy["PolicyDocument"]

                if is_full_admin(policy_doc):
                    non_compliant += 1
                    results.append({
                        "IdentityType": "Group",
                        "IdentityName": group_name,
                        "PolicyName": policy_name,
                        "Status": "NON_COMPLIANT"
                    })

    total_checked = len(results)
    compliant = 0  # Inline admin only counted if exists

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"iam_inline_admin_policies_{account_id}.csv"

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
        description="Ensure inline policies granting full admin are not attached"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_inline_admin_policies(session)

    print("\n====================================================")
    print("CONTROL: Inline Policies Not Granting Full Admin")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Inline Admin Policies Found : {total_checked}")
    print(f"Non-Compliant                     : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
