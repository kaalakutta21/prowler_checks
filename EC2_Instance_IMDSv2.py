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
            RoleSessionName="ec2-imdsv2-instance-audit"
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

def check_ec2_imdsv2(session):

    regions = get_regions(session)

    results = []
    total = 0
    non_compliant = 0
    skipped_instances = 0
    skipped_regions = 0

    account_id = get_account_id(session)

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

                        total += 1

                        metadata = inst.get("MetadataOptions", {})
                        http_tokens = metadata.get("HttpTokens")

                        # ==================================================
                        # LOGIC
                        # ==================================================

                        if http_tokens == "required":
                            status = "COMPLIANT"
                            reason = "IMDSv2 enforced"

                        else:
                            status = "NON_COMPLIANT"
                            non_compliant += 1

                            if not metadata:
                                reason = "MetadataOptions not set"
                            else:
                                reason = f"HttpTokens = {http_tokens}"

                        results.append({
                            "Region": region,
                            "InstanceId": instance_id,
                            "InstanceArn": arn,
                            "IMDSv2": http_tokens if http_tokens else "None",
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

    return results, total, compliant, non_compliant, skipped_instances, skipped_regions


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"ec2_instance_imdsv2_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "InstanceId",
            "InstanceArn",
            "IMDSv2",
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
        description="Ensure EC2 instances enforce IMDSv2"
    )

    parser.add_argument("-R", "--role-arn", help="Role ARN")

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total, compliant, non_compliant, skipped_instances, skipped_regions = \
        check_ec2_imdsv2(session)

    print("\n====================================================")
    print("CONTROL: EC2 Instance IMDSv2")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Instances Checked : {total}")
    print(f"Compliant               : {compliant}")
    print(f"Non-Compliant           : {non_compliant}")
    print(f"Skipped Instances       : {skipped_instances}")
    print(f"Skipped Regions (SCP)   : {skipped_regions}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
