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
            RoleSessionName="iam-customer-admin-audit"
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

def check_customer_admin_policies(session):

    iam = session.client("iam")

    results = []
    non_compliant = 0

    paginator = iam.get_paginator("list_policies")

    # Step 1: Get Customer Managed Policies
    customer_policies = []
    for page in paginator.paginate(Scope='Local'):
        customer_policies.extend(page.get("Policies", []))

    print(f"\nTotal Customer Managed Policies Retrieved: {len(customer_policies)}\n")

    for policy in tqdm(customer_policies, desc="Analyzing Customer Policies"):

        policy_arn = policy["Arn"]
        policy_name = policy["PolicyName"]
        default_version_id = policy["DefaultVersionId"]

        try:
            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )

            policy_doc = version["PolicyVersion"]["Document"]

            # Only evaluate full admin policies
            if not is_full_admin(policy_doc):
                continue

            # Check attachments
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

    total_checked = len(results)
    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"iam_customer_admin_policies_{account_id}.csv"

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
        description="Ensure customer managed full admin policies are not attached"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_customer_admin_policies(session)

    print("\n====================================================")
    print("CONTROL: Customer Managed Full Admin Policies Not Attached")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Customer Admin Policies Checked : {total_checked}")
    print(f"Compliant                             : {compliant}")
    print(f"Non-Compliant                         : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
