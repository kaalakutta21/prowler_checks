#!/usr/bin/env python3

import boto3
import argparse
import csv
from datetime import datetime, timezone
from tqdm import tqdm
from botocore.exceptions import ClientError

# ==================================================
# CONFIG
# ==================================================

MAX_INSTANCE_AGE_DAYS = 90

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="ec2-age-audit"
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
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=True)["Regions"]

    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_ec2_age(session):

    regions = get_regions(session)

    results = []
    total = 0
    non_compliant = 0
    skipped_regions = 0

    account_id = get_account_id(session)

    now = datetime.now(timezone.utc)

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")

        except ClientError as e:
            code = e.response["Error"]["Code"]

            if code in ["AccessDeniedException", "UnauthorizedOperation"]:
                print(f"Skipping region {region} (SCP Denied)")
                skipped_regions += 1
                continue
            else:
                continue

        # ==================================================
        # SAFE PAGINATION
        # ==================================================
        try:
            for page in paginator.paginate():

                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):

                        instance_id = inst["InstanceId"]
                        arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

                        launch_time = inst.get("LaunchTime")

                        if not launch_time:
                            continue

                        total += 1

                        age_days = (now - launch_time).days

                        # ==================================================
                        # LOGIC
                        # ==================================================

                        if age_days > MAX_INSTANCE_AGE_DAYS:
                            status = "NON_COMPLIANT"
                            non_compliant += 1
                            reason = f"Older than {MAX_INSTANCE_AGE_DAYS} days"

                        else:
                            status = "COMPLIANT"
                            reason = "Within allowed age"

                        results.append({
                            "Region": region,
                            "InstanceId": instance_id,
                            "InstanceArn": arn,
                            "LaunchTime": launch_time.strftime("%Y-%m-%d"),
                            "AgeDays": age_days,
                            "Status": status,
                            "Reason": reason
                        })

        except ClientError as e:
            code = e.response["Error"]["Code"]

            if code in ["AccessDeniedException", "UnauthorizedOperation"]:
                print(f"Skipping region {region} during pagination (SCP Denied)")
                skipped_regions += 1
                continue
            else:
                continue

    compliant = total - non_compliant

    return results, total, compliant, non_compliant, skipped_regions


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"ec2_instance_age_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "InstanceId",
            "InstanceArn",
            "LaunchTime",
            "AgeDays",
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
        description="Check EC2 instances older than defined threshold"
    )

    parser.add_argument("-R", "--role-arn", help="Role ARN")

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total, compliant, non_compliant, skipped_regions = \
        check_ec2_age(session)

    print("\n====================================================")
    print("CONTROL: EC2 Instance Age")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Instances Checked : {total}")
    print(f"Compliant               : {compliant}")
    print(f"Non-Compliant           : {non_compliant}")
    print(f"Skipped Regions (SCP)   : {skipped_regions}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
