#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

# --------------------------------------------------
# AUTH
# --------------------------------------------------

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="ebs-snapshot-audit"
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

# --------------------------------------------------
# REGIONS
# --------------------------------------------------

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

# --------------------------------------------------
# CONTROL LOGIC
# --------------------------------------------------

def check_ebs_snapshots(session, regions):

    results = []
    total_checked = 0
    non_compliant = 0

    for region in tqdm(regions, desc="Scanning Regions"):
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_snapshots")

            for page in paginator.paginate(OwnerIds=['self']):
                snapshots = page.get("Snapshots", [])

                for snap in tqdm(snapshots, desc=f"{region} Snapshots", leave=False):
                    total_checked += 1
                    snap_id = snap["SnapshotId"]
                    status = "COMPLIANT"

                    attrs = ec2.describe_snapshot_attribute(
                        SnapshotId=snap_id,
                        Attribute="createVolumePermission"
                    )

                    permissions = attrs.get("CreateVolumePermissions", [])

                    for perm in permissions:
                        if perm.get("Group") == "all":
                            status = "NON_COMPLIANT"
                            non_compliant += 1
                            break

                    results.append({
                        "Region": region,
                        "SnapshotId": snap_id,
                        "Status": status
                    })

        except ClientError:
            continue

    compliant = total_checked - non_compliant
    return results, total_checked, compliant, non_compliant

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"ebs_snapshot_public_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "SnapshotId",
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

# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Ensure EBS snapshots are not public"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)
    regions = get_regions(session)

    results, total_checked, compliant, non_compliant = \
        check_ebs_snapshots(session, regions)

    print("\n====================================================")
    print("CONTROL: EBS Snapshots Not Public")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Snapshots Checked : {total_checked}")
    print(f"Compliant               : {compliant}")
    print(f"Non-Compliant           : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
