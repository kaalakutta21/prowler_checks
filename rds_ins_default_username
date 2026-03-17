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
            RoleSessionName="rds-default-username-audit"
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
# DEFAULT USERNAMES
# ==================================================

DEFAULT_USERS = {
    "mysql": ["root"],
    "mariadb": ["root"],
    "postgres": ["postgres"],
    "postgresql": ["postgres"],
    "oracle": ["admin"],
    "sqlserver": ["sa"],
    "aurora-mysql": ["admin"],
    "aurora-postgresql": ["postgres"]
}


def is_default_user(engine, username):

    engine = engine.lower()
    username = username.lower()

    for key in DEFAULT_USERS:
        if key in engine:
            if username in DEFAULT_USERS[key]:
                return True

    return False


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_rds_default_username(session):

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
                    engine = db.get("Engine", "")
                    username = db.get("MasterUsername", "")

                    arn = db.get("DBInstanceArn", "")

                    status = "COMPLIANT"

                    if username and is_default_user(engine, username):
                        status = "NON_COMPLIANT"
                        non_compliant += 1

                    results.append({
                        "Region": region,
                        "DBInstanceIdentifier": db_id,
                        "DBInstanceArn": arn,
                        "Engine": engine,
                        "MasterUsername": username,
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

    filename = f"rds_default_username_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "DBInstanceIdentifier",
            "DBInstanceArn",
            "Engine",
            "MasterUsername",
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
        description="Ensure RDS instances are not using default usernames"
    )

    parser.add_argument("-R","--role-arn",help="Role ARN to assume")

    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id = get_account_id(session)

    results,total_checked,compliant,non_compliant = \
        check_rds_default_username(session)

    print("\n====================================================")
    print("CONTROL: RDS Instances Not Using Default Username")
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
