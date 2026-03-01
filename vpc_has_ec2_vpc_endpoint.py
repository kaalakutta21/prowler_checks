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
            RoleSessionName="vpc-endpoint-audit"
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
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_vpc_ec2_endpoint(session):

    regions = get_regions(session)

    results = []
    non_compliant = 0
    total_checked = 0

    for region in tqdm(regions, desc="Scanning Regions"):

        ec2 = session.client("ec2", region_name=region)

        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
        except ClientError:
            continue

        try:
            endpoints = ec2.describe_vpc_endpoints()["VpcEndpoints"]
        except ClientError:
            endpoints = []

        # Map VPC to EC2 endpoint presence
        vpc_endpoint_map = {}

        for ep in endpoints:
            if ep.get("State") != "available":
                continue

            service_name = ep.get("ServiceName", "")

            # Match EC2 endpoint service
            if ".ec2" in service_name:
                vpc_id = ep.get("VpcId")
                vpc_endpoint_map[vpc_id] = True

        for vpc in vpcs:
            total_checked += 1
            vpc_id = vpc["VpcId"]

            if vpc_endpoint_map.get(vpc_id):
                status = "COMPLIANT"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1

            results.append({
                "Region": region,
                "VpcId": vpc_id,
                "Status": status
            })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"vpc_ec2_endpoint_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "VpcId",
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
        description="Ensure VPC has Amazon EC2 VPC Endpoint"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_vpc_ec2_endpoint(session)

    print("\n====================================================")
    print("CONTROL: VPC Has Amazon EC2 VPC Endpoint")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total VPCs Checked : {total_checked}")
    print(f"Compliant           : {compliant}")
    print(f"Non-Compliant       : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
