#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError


def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="confused-deputy-audit"
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


def normalize_to_list(value):
    if isinstance(value, list):
        return value
    return [value]


def is_service_role(trust_policy):
    """
    A role is treated as a service role if any trust policy statement
    has Principal.Service set.
    """

    statements = trust_policy.get("Statement", [])

    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if not isinstance(principal, dict):
            continue

        service = principal.get("Service")
        if not service:
            continue

        services = normalize_to_list(service)

        for svc in services:
            if isinstance(svc, str) and svc.endswith(".amazonaws.com"):
                return True

    return False


def has_confused_deputy_protection(policy_document):
    """
    Check recursively and case-insensitively for aws:SourceAccount or aws:SourceArn.
    """

    policy_text = json.dumps(policy_document).lower()

    return (
        "aws:sourceaccount" in policy_text
        or "aws:sourcearn" in policy_text
    )


def check_service_roles(session, account_id):

    iam = session.client("iam")

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    paginator = iam.get_paginator("list_roles")

    print("\nScanning IAM Service Roles...\n")

    try:
        for page in paginator.paginate():

            for role in tqdm(page.get("Roles", []), leave=False):

                role_name = role["RoleName"]
                role_arn = role["Arn"]

                trust_policy = role.get("AssumeRolePolicyDocument", {})

                # FIX: detect service roles from trust policy, not path
                if not is_service_role(trust_policy):
                    continue

                total += 1

                try:
                    if has_confused_deputy_protection(trust_policy):

                        status = "COMPLIANT"
                        evidence = (
                            "Contains aws:SourceAccount or aws:SourceArn"
                        )
                        compliant += 1

                    else:
                        status = "NON_COMPLIANT"
                        evidence = (
                            "Missing confused deputy protection condition"
                        )
                        non_compliant += 1

                    results.append({
                        "Account": account_id,
                        "RoleName": role_name,
                        "RoleArn": role_arn,
                        "Status": status,
                        "Evidence": evidence
                    })

                except ClientError as e:

                    skipped += 1

                    results.append({
                        "Account": account_id,
                        "RoleName": role_name,
                        "RoleArn": role_arn,
                        "Status": "SKIPPED",
                        "Evidence": str(e)
                    })

    except ClientError as e:
        print(f"Error: {e}")

    return results, total, compliant, non_compliant, skipped


def write_csv(account_id, results):

    filename = f"iam_service_role_confused_deputy_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "RoleName",
            "RoleArn",
            "Status",
            "Evidence"
        ]

        writer = csv.DictWriter(f, fieldnames=fields)

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    return filename


def main():

    parser = argparse.ArgumentParser(
        description="IAM Service Role Confused Deputy Protection Audit"
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Role ARN"
    )

    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id = get_account_id(session)

    results, total, compliant, non_compliant, skipped = (
        check_service_roles(session, account_id)
    )

    print("\n====================================================")
    print("CONTROL: IAM Service Role Prevents Cross-Service Confused Deputy Attack")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Service Roles : {total}")
    print(f"Compliant           : {compliant}")
    print(f"Non-Compliant       : {non_compliant}")
    print(f"Skipped             : {skipped}")

    overall = (
        "COMPLIANT"
        if non_compliant == 0
        else "NON_COMPLIANT"
    )

    print(f"\nOVERALL STATUS: {overall}")

    csv_file = write_csv(account_id, results)

    print(f"\nCSV Report Generated: {csv_file}")


if __name__ == "__main__":
    main()
