#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm

GREEN = "\033[92m"
RED = "\033[91m"
PURPLE = "\033[95m"
RESET = "\033[0m"

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):

    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="ec2-combined-audit"
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

def get_active_regions(session):

    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=False)["Regions"]

    return [r["RegionName"] for r in regions]


# ==================================================
# MAIN CONTROL LOGIC
# ==================================================

def check_ec2_controls(session):

    regions = get_active_regions(session)
    account_id = get_account_id(session)

    results = []
    non_compliant_details = []

    summary = {
        "Single ENI Attached": {"total": 0, "non_compliant": 0},
        "IAM Instance Profile Attached": {"total": 0, "non_compliant": 0},
        "Detailed Monitoring Enabled": {"total": 0, "non_compliant": 0},
    }

    print(f"\nRegions discovered: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        ec2 = session.client("ec2", region_name=region)

        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():

            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    instance_id = instance["InstanceId"]

                    # -------------------------------------------------
                    # CONTROL 1: SINGLE ENI
                    # -------------------------------------------------

                    control = "Single ENI Attached"
                    summary[control]["total"] += 1

                    eni_count = len(instance.get("NetworkInterfaces", []))

                    compliant = eni_count <= 1

                    status = "COMPLIANT" if compliant else "NON_COMPLIANT"

                    if not compliant:
                        summary[control]["non_compliant"] += 1
                        non_compliant_details.append((instance_id, control, region))

                    results.append([region, instance_id, control, status])

                    # -------------------------------------------------
                    # CONTROL 2: IAM PROFILE
                    # -------------------------------------------------

                    control = "IAM Instance Profile Attached"
                    summary[control]["total"] += 1

                    has_profile = "IamInstanceProfile" in instance

                    status = "COMPLIANT" if has_profile else "NON_COMPLIANT"

                    if not has_profile:
                        summary[control]["non_compliant"] += 1
                        non_compliant_details.append((instance_id, control, region))

                    results.append([region, instance_id, control, status])

                    # -------------------------------------------------
                    # CONTROL 3: DETAILED MONITORING
                    # -------------------------------------------------

                    control = "Detailed Monitoring Enabled"
                    summary[control]["total"] += 1

                    monitoring = instance.get("Monitoring", {}).get("State")

                    enabled = monitoring == "enabled"

                    status = "COMPLIANT" if enabled else "NON_COMPLIANT"

                    if not enabled:
                        summary[control]["non_compliant"] += 1
                        non_compliant_details.append((instance_id, control, region))

                    results.append([region, instance_id, control, status])

    return account_id, results, summary, non_compliant_details


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"ec2_combined_controls_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Account",
            "Region",
            "InstanceId",
            "Control",
            "Status"
        ])

        for region, instance_id, control, status in results:
            writer.writerow([account_id, region, instance_id, control, status])

    return filename


# ==================================================
# MAIN
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description="EC2 Combined Security Controls Audit"
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Role ARN to assume"
    )

    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, summary, non_compliant = check_ec2_controls(session)

    print("\n================================================")
    print("EC2 COMBINED SECURITY CONTROLS AUDIT")
    print(f"ACCOUNT: {account_id}")
    print("================================================\n")

    for control, data in summary.items():

        total = data["total"]
        non_compliant_count = data["non_compliant"]
        compliant = total - non_compliant_count

        if non_compliant_count == 0:
            status = f"{GREEN}COMPLIANT{RESET}"
        else:
            status = f"{RED}NON_COMPLIANT{RESET}"

        print(f"{control}")
        print(f"  Total Checked : {total}")
        print(f"  Compliant     : {compliant}")
        print(f"  Non-Compliant : {non_compliant_count}")
        print(f"  Overall       : {status}")
        print("------------------------------------------------")

    # -------------------------------------------------
    # NON-COMPLIANT DETAILS
    # -------------------------------------------------

    if non_compliant:

        print(f"\n{PURPLE}NON-COMPLIANT RESOURCES{RESET}\n")

        for instance_id, control, region in non_compliant:
            print(f"{instance_id} ({region}) -> {control}")

    else:
        print(f"\n{GREEN}All instances are compliant for tested controls{RESET}\n")

    csv_file = write_csv(account_id, results)

    print(f"\nCSV report generated: {csv_file}\n")


if __name__ == "__main__":
    main()
