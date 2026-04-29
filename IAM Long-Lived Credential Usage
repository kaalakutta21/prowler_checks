#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from datetime import datetime, timedelta

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="iam-long-lived-check"
        )["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=True)["Regions"]
        if r["OptInStatus"] in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# MAIN LOGIC
# ==================================================

def check_iam_usage(session):

    iam = session.client("iam")
    regions = get_regions(session)
    account_id = get_account_id(session)

    results = []
    total = 0
    non_compliant = 0

    # Allowed services
    allowed_services = [
        "iam.amazonaws.com",
        "sts.amazonaws.com"
    ]

    # Look back 90 days
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=90)

    users = iam.list_users()["Users"]

    print(f"\nTotal IAM Users: {len(users)}\n")

    for user in tqdm(users, desc="Checking Users"):

        user_name = user["UserName"]
        total += 1

        status = "COMPLIANT"
        evidence = "No usage outside IAM/STS"

        # Check access keys
        keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

        if not keys:
            results.append({
                "UserName": user_name,
                "Status": status,
                "Evidence": "No access keys"
            })
            continue

        # Check CloudTrail usage
        used_services = set()

        for region in regions:

            ct = session.client("cloudtrail", region_name=region)

            paginator = ct.get_paginator("lookup_events")

            try:
                for page in paginator.paginate(
                    LookupAttributes=[
                        {
                            "AttributeKey": "Username",
                            "AttributeValue": user_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time
                ):

                    for event in page["Events"]:
                        service = event.get("EventSource")
                        if service:
                            used_services.add(service)

            except Exception:
                continue

        # Remove allowed services
        risky_services = [
            s for s in used_services if s not in allowed_services
        ]

        if risky_services:
            status = "NON_COMPLIANT"
            non_compliant += 1
            evidence = f"Used services: {', '.join(risky_services)}"

        results.append({
            "UserName": user_name,
            "Status": status,
            "Evidence": evidence
        })

    return results, total, non_compliant


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"iam_long_lived_usage_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        writer = csv.DictWriter(f, fieldnames=[
            "Account",
            "UserName",
            "Status",
            "Evidence"
        ])

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
        description="IAM long-lived credential usage check"
    )
    parser.add_argument("-R","--role-arn")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total, non_compliant = check_iam_usage(session)

    compliant = total - non_compliant

    print("\n====================================================")
    print("CONTROL: IAM Long-Lived Credential Usage")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Users       : {total}")
    print(f"Compliant         : {compliant}")
    print(f"Non-Compliant     : {non_compliant}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
