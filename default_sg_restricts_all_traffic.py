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
            RoleSessionName="default-sg-audit"
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
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_default_sg(session):

    regions = get_regions(session)

    results = []
    non_compliant = 0
    total_checked = 0

    for region in tqdm(regions, desc="Scanning Regions"):

        ec2 = session.client("ec2", region_name=region)

        try:
            response = ec2.describe_security_groups(
                Filters=[
                    {
                        "Name": "group-name",
                        "Values": ["default"]
                    }
                ]
            )
        except ClientError:
            continue

        for sg in response.get("SecurityGroups", []):
            total_checked += 1

            sg_id = sg["GroupId"]
            vpc_id = sg["VpcId"]

            ingress_rules = sg.get("IpPermissions", [])
            egress_rules = sg.get("IpPermissionsEgress", [])

            # Prowler logic: ANY rule means NON_COMPLIANT
            if ingress_rules or egress_rules:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "Region": region,
                "VpcId": vpc_id,
                "SecurityGroupId": sg_id,
                "Status": status
            })

    compliant = total_checked - non_compliant

    return results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"default_sg_restriction_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "VpcId",
            "SecurityGroupId",
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
        description="Ensure default security groups restrict all traffic"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_default_sg(session)

    print("\n====================================================")
    print("CONTROL: Default Security Group Restricts All Traffic")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Default SGs Checked : {total_checked}")
    print(f"Compliant                 : {compliant}")
    print(f"Non-Compliant             : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
