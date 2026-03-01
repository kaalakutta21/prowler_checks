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
            RoleSessionName="ssm-patch-audit"
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
# CONTROL LOGIC (PROWLER-ALIGNED)
# --------------------------------------------------

def check_ssm_patch_compliance(session, regions):

    results = []
    total_checked = 0
    non_compliant_instances = 0

    for region in tqdm(regions, desc="Scanning Regions"):
        ssm = session.client("ssm", region_name=region)

        try:
            # Get SSM managed instances
            paginator = ssm.get_paginator("describe_instance_information")

            managed_instances = []
            for page in paginator.paginate():
                managed_instances.extend(page.get("InstanceInformationList", []))

            if not managed_instances:
                continue

            # Get patch compliance summaries
            compliance_data = {}
            paginator = ssm.get_paginator("list_resource_compliance_summaries")

            for page in paginator.paginate(
                Filters=[{
                    "Key": "ComplianceType",
                    "Values": ["Patch"]
                }]
            ):
                for item in page.get("ResourceComplianceSummaryItems", []):
                    compliance_data[item["ResourceId"]] = item["ComplianceSummary"]

            for instance in tqdm(managed_instances, desc=f"{region} Instances", leave=False):
                instance_id = instance["InstanceId"]
                total_checked += 1

                summary = compliance_data.get(instance_id)

                # PROWLER-ALIGNED LOGIC
                if summary:
                    non_compliant_count = summary.get("NonCompliantCount", 0)

                    if non_compliant_count > 0:
                        status = "NON_COMPLIANT"
                        non_compliant_instances += 1
                    else:
                        status = "COMPLIANT"
                else:
                    # No patch compliance data → treat as compliant (Prowler behavior)
                    status = "COMPLIANT"

                results.append({
                    "Region": region,
                    "InstanceId": instance_id,
                    "Status": status
                })

        except ClientError:
            continue

    compliant_instances = total_checked - non_compliant_instances

    return results, total_checked, compliant_instances, non_compliant_instances

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"ssm_patch_compliance_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "InstanceId",
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
        description="Ensure SSM managed EC2 instances are patch compliant (Prowler aligned)"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)
    regions = get_regions(session)

    results, total_checked, compliant, non_compliant = \
        check_ssm_patch_compliance(session, regions)

    print("\n====================================================")
    print("CONTROL: EC2 Patch Compliance via Systems Manager")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Managed Instances Checked : {total_checked}")
    print(f"Compliant                       : {compliant}")
    print(f"Non-Compliant                   : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
