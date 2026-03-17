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
            RoleSessionName="rds-copy-tags-audit"
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
        if r["OptInStatus"] in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_copy_tags_to_snapshot(session):

    regions = get_regions(session)

    results = []
    total_checked = 0
    non_compliant = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            rds = session.client("rds", region_name=region)

            paginator = rds.get_paginator("describe_db_instances")

            pages = paginator.paginate()

        except ClientError as e:

            code = e.response["Error"]["Code"]

            if code in ["AuthFailure","OptInRequired","InvalidClientTokenId"]:
                print(f"Skipping region {region}")
                continue
            else:
                continue


        try:

            for page in pages:

                for db in page.get("DBInstances", []):

                    total_checked += 1

                    db_id = db["DBInstanceIdentifier"]
                    arn = db.get("DBInstanceArn", "")

                    copy_tags = db.get("CopyTagsToSnapshot", False)

                    status = "COMPLIANT" if copy_tags else "NON_COMPLIANT"

                    if not copy_tags:
                        non_compliant += 1

                    results.append({
                        "Region": region,
                        "DBInstanceIdentifier": db_id,
                        "DBInstanceArn": arn,
                        "CopyTagsToSnapshot": copy_tags,
                        "Status": status
                    })

        except ClientError:
            continue


    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"rds_copy_tags_to_snapshot_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "DBInstanceIdentifier",
            "DBInstanceArn",
            "CopyTagsToSnapshot",
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
        description="Ensure RDS instances copy tags to snapshots"
    )

    parser.add_argument("-R","--role-arn",help="Role ARN to assume")

    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id = get_account_id(session)

    results,total_checked,compliant,non_compliant = \
        check_copy_tags_to_snapshot(session)

    print("\n====================================================")
    print("CONTROL: RDS Copy Tags To Snapshots")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"OVERALL STATUS: {overall}\n")

    print("----------------------------------------------------")
    print(f"Total DB Instances Checked : {total_checked}")
    print(f"Compliant                  : {compliant}")
    print(f"Non-Compliant              : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id,results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
