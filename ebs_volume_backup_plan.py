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
            RoleSessionName="ebs-backup-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# REGIONS
# ==================================================

def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions()["Regions"]
    return [r["RegionName"] for r in regions]

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_ebs_backup_protection(session):

    regions = get_regions(session)

    results = []
    non_compliant = 0
    total_checked = 0

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            ec2 = session.client("ec2", region_name=region)
            backup = session.client("backup", region_name=region)

            # Get EBS volumes
            paginator = ec2.get_paginator("describe_volumes")
            volumes = []

            for page in paginator.paginate():
                volumes.extend(page.get("Volumes", []))

            # Get protected resources from AWS Backup
            protected_resources = []
            backup_paginator = backup.get_paginator("list_protected_resources")

            for page in backup_paginator.paginate():
                for resource in page.get("Results", []):
                    if resource.get("ResourceType") == "EBS":
                        protected_resources.append(
                            resource.get("ResourceArn")
                        )

        except ClientError:
            continue

        for volume in volumes:

            total_checked += 1

            volume_id = volume["VolumeId"]

            volume_arn = f"arn:aws:ec2:{region}:{get_account_id(session)}:volume/{volume_id}"

            if volume_arn in protected_resources:
                status = "COMPLIANT"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1

            results.append({
                "Region": region,
                "VolumeId": volume_id,
                "Status": status
            })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"ebs_backup_protection_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "VolumeId",
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
        description="Ensure EBS volumes are protected by AWS Backup"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_ebs_backup_protection(session)

    print("\n====================================================")
    print("CONTROL: EBS Volume Protected by Backup Plan")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Volumes Checked : {total_checked}")
    print(f"Compliant             : {compliant}")
    print(f"Non-Compliant         : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
