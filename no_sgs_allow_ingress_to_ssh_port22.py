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
            RoleSessionName="sg-ssh-audit"
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
# SSH EXPOSURE CHECK
# ==================================================

def is_ssh_exposed(permission):

    protocol = permission.get("IpProtocol")

    # Accept tcp or all protocols
    if protocol not in ("tcp", "-1"):
        return False

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    # If protocol is -1 (all), assume port exposure
    if protocol == "-1":
        port_match = True
    else:
        if from_port is None or to_port is None:
            return False
        port_match = from_port <= 22 <= to_port

    if not port_match:
        return False

    # Check IPv4
    for ip_range in permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            return True

    # Check IPv6
    for ip_range in permission.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") == "::/0":
            return True

    return False

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_ssh_exposure(session):

    regions = get_regions(session)

    results = []
    non_compliant = 0
    total_sgs = 0

    for region in tqdm(regions, desc="Scanning Regions"):

        ec2 = session.client("ec2", region_name=region)

        try:
            response = ec2.describe_security_groups()
        except ClientError:
            continue

        security_groups = response.get("SecurityGroups", [])

        for sg in security_groups:
            total_sgs += 1
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            exposed = False

            for permission in sg.get("IpPermissions", []):
                if is_ssh_exposed(permission):
                    exposed = True
                    break

            if exposed:
                status = "NON_COMPLIANT"
                non_compliant += 1
            else:
                status = "COMPLIANT"

            results.append({
                "Region": region,
                "SecurityGroupId": sg_id,
                "SecurityGroupName": sg_name,
                "Status": status
            })

    compliant = total_sgs - non_compliant

    return results, total_sgs, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"sg_ssh_exposure_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "SecurityGroupId",
            "SecurityGroupName",
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
        description="Ensure no Security Groups allow SSH from 0.0.0.0/0 or ::/0"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_ssh_exposure(session)

    print("\n====================================================")
    print("CONTROL: No Internet SSH Exposure (Port 22)")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Security Groups Checked : {total_checked}")
    print(f"Compliant                     : {compliant}")
    print(f"Non-Compliant                 : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
