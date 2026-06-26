#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# ESCALATION ACTIONS
# ==================================================

ESCALATION_ACTIONS = [
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:addusertogroup",
    "iam:updateassumerolepolicy",
    "sts:assumerole"
]

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="iam-inline-escalation-audit"
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
# CHECK LOGIC
# ==================================================

def contains_escalation(statement):

    actions = statement.get("Action", [])

    if isinstance(actions, str):
        actions = [actions]

    actions = [a.lower() for a in actions]

    # Wildcard
    if "*" in actions:
        return True, "Wildcard *"

    for act in actions:
        for esc in ESCALATION_ACTIONS:
            if esc in act:
                return True, act

    return False, None


# ==================================================
# MAIN CONTROL LOGIC
# ==================================================

def check_inline_escalation(session):

    iam = session.client("iam")
    account_id = get_account_id(session)

    results = []
    total = 0
    non_compliant = 0
    skipped = 0

    print("\nScanning IAM Users, Roles, Groups...\n")

    # ==================================================
    # USERS
    # ==================================================

    try:
        users = iam.list_users()["Users"]
    except ClientError:
        users = []

    for user in tqdm(users, desc="Users"):

        user_name = user["UserName"]
        arn = user["Arn"]

        try:
            policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
        except ClientError:
            skipped += 1
            continue

        for pol in policies:

            try:
                doc = iam.get_user_policy(
                    UserName=user_name,
                    PolicyName=pol
                )["PolicyDocument"]
            except ClientError:
                skipped += 1
                continue

            total += 1

            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:

                is_bad, reason = contains_escalation(stmt)

                if is_bad:
                    non_compliant += 1

                    results.append({
                        "EntityType": "User",
                        "EntityName": user_name,
                        "Arn": arn,
                        "Policy": pol,
                        "Status": "NON_COMPLIANT",
                        "Reason": reason
                    })
                    break
            else:
                results.append({
                    "EntityType": "User",
                    "EntityName": user_name,
                    "Arn": arn,
                    "Policy": pol,
                    "Status": "COMPLIANT",
                    "Reason": "No escalation actions"
                })

    # ==================================================
    # ROLES
    # ==================================================

    try:
        roles = iam.list_roles()["Roles"]
    except ClientError:
        roles = []

    for role in tqdm(roles, desc="Roles"):

        role_name = role["RoleName"]
        arn = role["Arn"]

        try:
            policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        except ClientError:
            skipped += 1
            continue

        for pol in policies:

            try:
                doc = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=pol
                )["PolicyDocument"]
            except ClientError:
                skipped += 1
                continue

            total += 1

            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:

                is_bad, reason = contains_escalation(stmt)

                if is_bad:
                    non_compliant += 1

                    results.append({
                        "EntityType": "Role",
                        "EntityName": role_name,
                        "Arn": arn,
                        "Policy": pol,
                        "Status": "NON_COMPLIANT",
                        "Reason": reason
                    })
                    break
            else:
                results.append({
                    "EntityType": "Role",
                    "EntityName": role_name,
                    "Arn": arn,
                    "Policy": pol,
                    "Status": "COMPLIANT",
                    "Reason": "No escalation actions"
                })

    # ==================================================
    # GROUPS
    # ==================================================

    try:
        groups = iam.list_groups()["Groups"]
    except ClientError:
        groups = []

    for group in tqdm(groups, desc="Groups"):

        group_name = group["GroupName"]
        arn = group["Arn"]

        try:
            policies = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
        except ClientError:
            skipped += 1
            continue

        for pol in policies:

            try:
                doc = iam.get_group_policy(
                    GroupName=group_name,
                    PolicyName=pol
                )["PolicyDocument"]
            except ClientError:
                skipped += 1
                continue

            total += 1

            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:

                is_bad, reason = contains_escalation(stmt)

                if is_bad:
                    non_compliant += 1

                    results.append({
                        "EntityType": "Group",
                        "EntityName": group_name,
                        "Arn": arn,
                        "Policy": pol,
                        "Status": "NON_COMPLIANT",
                        "Reason": reason
                    })
                    break
            else:
                results.append({
                    "EntityType": "Group",
                    "EntityName": group_name,
                    "Arn": arn,
                    "Policy": pol,
                    "Status": "COMPLIANT",
                    "Reason": "No escalation actions"
                })

    compliant = total - non_compliant

    return results, total, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"iam_inline_escalation_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "EntityType",
            "EntityName",
            "Arn",
            "Policy",
            "Status",
            "Reason"
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
        description="Ensure no IAM inline policies allow privilege escalation"
    )

    parser.add_argument("-R", "--role-arn", help="Role ARN")

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total, compliant, non_compliant, skipped = \
        check_inline_escalation(session)

    print("\n====================================================")
    print("CONTROL: IAM Inline Privilege Escalation")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Policies Checked : {total}")
    print(f"Compliant              : {compliant}")
    print(f"Non-Compliant          : {non_compliant}")
    print(f"Skipped                : {skipped}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
