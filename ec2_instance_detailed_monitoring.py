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
            RoleSessionName="ec2-monitoring-audit"
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
# REGION DISCOVERY (PROWLER STYLE)
# ==================================================

def get_active_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=False)["Regions"]

    return [r["RegionName"] for r in regions]

# ==================================================
# CONTROL LOGIC (RUNNING INSTANCES ONLY)
# ==================================================

def check_detailed_monitoring(session):

    regions = get_active_regions(session)

    results = []
    total_running = 0
    non_compliant = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            ec2 = session.client("ec2", region_name=region)

            paginator = ec2.get_paginator("describe_instances")

            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ):

                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):

                        total_running += 1

                        instance_id = instance["InstanceId"]
                        monitoring_state = instance["Monitoring"]["State"]

                        if monitoring_state == "enabled":
                            status = "COMPLIANT"
                        else:
                            status = "NON_COMPLIANT"
                            non_compliant += 1

                        results.append({
                            "Region": region,
                            "InstanceId": instance_id,
                            "MonitoringState": monitoring_state,
                            "Status": status
                        })

        except ClientError:
            continue

    compliant = total_running - non_compliant

    return results, total_running, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"ec2_detailed_monitoring_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "InstanceId",
            "MonitoringState",
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
        description="Ensure EC2 running instances have detailed monitoring enabled"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_running, compliant, non_compliant = \
        check_detailed_monitoring(session)

    print("\n====================================================")
    print("CONTROL: EC2 Running Instances Have Detailed Monitoring Enabled")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Running Instances Checked : {total_running}")
    print(f"Compliant                       : {compliant}")
    print(f"Non-Compliant                   : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
