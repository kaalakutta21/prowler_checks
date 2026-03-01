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
            RoleSessionName="rds-public-access-audit"
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

def check_rds_public_instances(session, regions):

    results = []
    total_checked = 0
    non_compliant = 0

    for region in tqdm(regions, desc="Scanning Regions"):
        rds = session.client("rds", region_name=region)

        try:
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                instances = page.get("DBInstances", [])

                for db in tqdm(instances, desc=f"{region} RDS Instances", leave=False):
                    total_checked += 1

                    db_id = db["DBInstanceIdentifier"]
                    engine = db.get("Engine", "unknown")
                    public_flag = db.get("PubliclyAccessible", False)

                    status = "NON_COMPLIANT" if public_flag else "COMPLIANT"

                    if public_flag:
                        non_compliant += 1

                    results.append({
                        "Region": region,
                        "DBInstanceIdentifier": db_id,
                        "Engine": engine,
                        "PubliclyAccessible": str(public_flag),
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
    filename = f"rds_public_instances_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "DBInstanceIdentifier",
            "Engine",
            "PubliclyAccessible",
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
        description="Ensure there are no publicly accessible RDS instances"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)
    regions = get_regions(session)

    results, total_checked, compliant, non_compliant = \
        check_rds_public_instances(session, regions)

    print("\n====================================================")
    print("CONTROL: No Publicly Accessible RDS Instances")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total RDS Instances Checked : {total_checked}")
    print(f"Compliant                    : {compliant}")
    print(f"Non-Compliant                : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
