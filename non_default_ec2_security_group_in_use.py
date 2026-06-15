#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
import time
from datetime import datetime, UTC
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Non-default EC2 Security Group Is In Use"
SEVERITY = "MEDIUM"


# ==================================================
# AUTHENTICATION
# ==================================================

def get_session(role_arn=None):

    if role_arn:

        sts = boto3.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sg-in-use-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):

    return session.client(
        "sts"
    ).get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================

def get_regions(session):

    ec2 = session.client(
        "ec2",
        region_name="us-east-1"
    )

    response = ec2.describe_regions(
        AllRegions=False
    )

    return sorted([
        r["RegionName"]
        for r in response["Regions"]
    ])


# ==================================================
# HELPERS
# ==================================================

def get_vpc_name(ec2, vpc_id):

    try:

        response = ec2.describe_vpcs(
            VpcIds=[vpc_id]
        )

        vpc = response["Vpcs"][0]

        for tag in vpc.get("Tags", []):

            if tag["Key"] == "Name":
                return tag["Value"]

        return "NoName"

    except Exception:

        return "Unknown"


def build_sg_arn(
    region,
    account_id,
    sg_id
):

    return (
        f"arn:aws:ec2:{region}:"
        f"{account_id}:security-group/{sg_id}"
    )


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_security_groups(
    session,
    account_id
):

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    scan_time = datetime.now(
        UTC
    ).isoformat()

    regions = get_regions(session)

    print(
        f"\nRegions to Scan: {len(regions)}\n"
    )

    for region in tqdm(
        regions,
        desc="Scanning Regions"
    ):

        ec2 = session.client(
            "ec2",
            region_name=region
        )

        try:

            paginator = ec2.get_paginator(
                "describe_security_groups"
            )

            for page in paginator.paginate():

                security_groups = page.get(
                    "SecurityGroups",
                    []
                )

                for sg in security_groups:

                    # Ignore default SGs
                    if sg["GroupName"] == "default":
                        continue

                    total += 1

                    sg_id = sg["GroupId"]

                    sg_name = sg["GroupName"]

                    description = sg.get(
                        "Description",
                        ""
                    )

                    vpc_id = sg.get(
                        "VpcId",
                        "N/A"
                    )

                    vpc_name = get_vpc_name(
                        ec2,
                        vpc_id
                    )

                    sg_arn = build_sg_arn(
                        region,
                        account_id,
                        sg_id
                    )

                    try:

                        eni_response = (
                            ec2.describe_network_interfaces(
                                Filters=[
                                    {
                                        "Name":
                                            "group-id",
                                        "Values":
                                            [sg_id]
                                    }
                                ]
                            )
                        )

                        interfaces = (
                            eni_response.get(
                                "NetworkInterfaces",
                                []
                            )
                        )

                        attachment_count = (
                            len(interfaces)
                        )

                        if attachment_count > 0:

                            status = "COMPLIANT"

                            evidence = (
                                f"Security group "
                                f"attached to "
                                f"{attachment_count} "
                                f"resource(s)"
                            )

                            compliant += 1

                        else:

                            status = (
                                "NON_COMPLIANT"
                            )

                            evidence = (
                                "Security group "
                                "not attached "
                                "to any resource"
                            )

                            non_compliant += 1

                        results.append({

                            "Account":
                                account_id,

                            "Region":
                                region,

                            "SecurityGroupId":
                                sg_id,

                            "SecurityGroupArn":
                                sg_arn,

                            "SecurityGroupName":
                                sg_name,

                            "Description":
                                description,

                            "VpcId":
                                vpc_id,

                            "VpcName":
                                vpc_name,

                            "AttachedResources":
                                attachment_count,

                            "Severity":
                                SEVERITY,

                            "Status":
                                status,

                            "Evidence":
                                evidence,

                            "ScanTime":
                                scan_time
                        })

                    except ClientError as e:

                        skipped += 1

                        results.append({

                            "Account":
                                account_id,

                            "Region":
                                region,

                            "SecurityGroupId":
                                sg_id,

                            "SecurityGroupArn":
                                sg_arn,

                            "SecurityGroupName":
                                sg_name,

                            "Description":
                                description,

                            "VpcId":
                                vpc_id,

                            "VpcName":
                                vpc_name,

                            "AttachedResources":
                                "N/A",

                            "Severity":
                                SEVERITY,

                            "Status":
                                "SKIPPED",

                            "Evidence":
                                str(e),

                            "ScanTime":
                                scan_time
                        })

        except ClientError as e:

            skipped += 1

            print(
                f"Region {region} Error: {e}"
            )

    return (
        results,
        total,
        compliant,
        non_compliant,
        skipped
    )


# ==================================================
# CSV REPORT
# ==================================================

def write_csv(
    account_id,
    results
):

    filename = (
        f"non_default_ec2_security_group_"
        f"in_use_{account_id}.csv"
    )

    fields = [

        "Account",
        "Region",
        "SecurityGroupId",
        "SecurityGroupArn",
        "SecurityGroupName",
        "Description",
        "VpcId",
        "VpcName",
        "AttachedResources",
        "Severity",
        "Status",
        "Evidence",
        "ScanTime"
    ]

    with open(
        filename,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    return filename


# ==================================================
# JSON REPORT
# ==================================================

def write_json(
    account_id,
    results
):

    filename = (
        f"non_default_ec2_security_group_"
        f"in_use_{account_id}.json"
    )

    with open(
        filename,
        "w"
    ) as f:

        json.dump(
            results,
            f,
            indent=4
        )

    return filename


# ==================================================
# MAIN
# ==================================================

def main():

    start_time = time.time()

    parser = argparse.ArgumentParser(
        description=CONTROL_NAME
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Cross Account Role ARN"
    )

    args = parser.parse_args()

    session = get_session(
        args.role_arn
    )

    account_id = get_account_id(
        session
    )

    (
        results,
        total,
        compliant,
        non_compliant,
        skipped

    ) = check_security_groups(
        session,
        account_id
    )

    if total == 0:

        overall = "NOT_APPLICABLE"

    elif non_compliant == 0:

        overall = "COMPLIANT"

    else:

        overall = "NON_COMPLIANT"

    print(
        "\n===================================================="
    )

    print(
        f"CONTROL : {CONTROL_NAME}"
    )

    print(
        f"ACCOUNT : {account_id}"
    )

    print(
        "===================================================="
    )

    print(
        f"\nTotal Non-Default Security Groups : {total}"
    )

    print(
        f"Compliant                         : {compliant}"
    )

    print(
        f"Non-Compliant                     : {non_compliant}"
    )

    print(
        f"Skipped                           : {skipped}"
    )

    print(
        f"\nOVERALL STATUS                    : {overall}"
    )

    csv_file = write_csv(
        account_id,
        results
    )

    json_file = write_json(
        account_id,
        results
    )

    execution_time = round(
        time.time() - start_time,
        2
    )

    print(
        f"\nCSV Report  : {csv_file}"
    )

    print(
        f"JSON Report : {json_file}"
    )

    print(
        f"Execution Time : "
        f"{execution_time} seconds"
    )

    print(
        "\n====================================================\n"
    )


if __name__ == "__main__":
    main()
