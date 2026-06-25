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
            RoleSessionName="vpc-peering-route-audit"
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
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================

def classify_error(e):
    return e.response["Error"]["Code"]


def get_route_table_name(route_table):
    for tag in route_table.get("Tags", []):
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def get_destination(route):
    return route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", "")


def evaluate_route(route):
    """
    Prowler-like relaxed logic:
    ONLY flag default routes pointing to the peering connection.
    Do NOT flag full requester/accepter CIDR routes.
    """
    destination = get_destination(route)

    if not destination:
        return False, "No CIDR destination"

    if destination in ["0.0.0.0/0", "::/0"]:
        return True, f"Default route {destination} points to peering connection"

    return False, f"Non-default route {destination} points to peering connection"


def skipped_row(region, pcx_id, pcx_arn, reason):
    return {
        "Region": region,
        "VpcPeeringConnectionId": pcx_id,
        "VpcPeeringConnectionArn": pcx_arn,
        "VpcPeeringStatus": "N/A",
        "RouteTableId": "N/A",
        "RouteTableName": "N/A",
        "VpcId": "N/A",
        "Destination": "N/A",
        "Status": "SKIPPED",
        "Evidence": reason
    }


# ==================================================
# CONTROL LOGIC
# ==================================================
#
# Control:
# VPC peering connection route tables do not include
# 0.0.0.0/0 or ::/0 routes pointing to the peering connection.
#
# Summary counts are based on VPC peering connections.
# Detailed CSV rows are route-table / route level.
# ==================================================

def check_control(session):
    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            ec2 = session.client("ec2", region_name=region)
        except ClientError as e:
            skipped += 1
            results.append(skipped_row(
                region,
                "N/A",
                "N/A",
                f"Client init failed: {classify_error(e)}"
            ))
            continue

        try:
            pcx_resp = ec2.describe_vpc_peering_connections()
            peerings = pcx_resp.get("VpcPeeringConnections", [])
        except ClientError as e:
            skipped += 1
            results.append(skipped_row(
                region,
                "N/A",
                "N/A",
                f"describe_vpc_peering_connections failed: {classify_error(e)}"
            ))
            continue

        if not peerings:
            continue

        for pcx in peerings:

            pcx_id = pcx["VpcPeeringConnectionId"]
            pcx_arn = f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection/{pcx_id}"
            pcx_status = pcx.get("Status", {}).get("Code", "")

            total_checked += 1
            peering_non_compliant = False
            peering_has_routes = False

            try:
                paginator = ec2.get_paginator("describe_route_tables")

                for page in paginator.paginate(
                    Filters=[{
                        "Name": "route.vpc-peering-connection-id",
                        "Values": [pcx_id]
                    }]
                ):
                    for route_table in page.get("RouteTables", []):

                        route_table_id = route_table["RouteTableId"]
                        route_table_name = get_route_table_name(route_table)
                        vpc_id = route_table.get("VpcId", "")

                        for route in route_table.get("Routes", []):

                            if route.get("VpcPeeringConnectionId") != pcx_id:
                                continue

                            peering_has_routes = True

                            destination = get_destination(route)
                            is_bad, evidence = evaluate_route(route)
                            status = "NON_COMPLIANT" if is_bad else "COMPLIANT"

                            if is_bad:
                                peering_non_compliant = True

                            results.append({
                                "Region": region,
                                "VpcPeeringConnectionId": pcx_id,
                                "VpcPeeringConnectionArn": pcx_arn,
                                "VpcPeeringStatus": pcx_status,
                                "RouteTableId": route_table_id,
                                "RouteTableName": route_table_name,
                                "VpcId": vpc_id,
                                "Destination": destination,
                                "Status": status,
                                "Evidence": evidence
                            })

            except ClientError as e:
                skipped += 1
                results.append(skipped_row(
                    region,
                    pcx_id,
                    pcx_arn,
                    f"describe_route_tables failed: {classify_error(e)}"
                ))
                continue

            if peering_non_compliant:
                non_compliant += 1
            else:
                compliant += 1

            if not peering_has_routes:
                results.append({
                    "Region": region,
                    "VpcPeeringConnectionId": pcx_id,
                    "VpcPeeringConnectionArn": pcx_arn,
                    "VpcPeeringStatus": pcx_status,
                    "RouteTableId": "",
                    "RouteTableName": "",
                    "VpcId": "",
                    "Destination": "",
                    "Status": "COMPLIANT",
                    "Evidence": "No route tables reference this peering connection"
                })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):
    filename = f"vpc_peering_route_tables_no_default_routes_{account_id}.csv"

    fields = [
        "Account",
        "Region",
        "VpcPeeringConnectionId",
        "VpcPeeringConnectionArn",
        "VpcPeeringStatus",
        "RouteTableId",
        "RouteTableName",
        "VpcId",
        "Destination",
        "Status",
        "Evidence"
    ]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for row in results:
            writer.writerow({
                "Account": account_id,
                **row
            })

    return filename


# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "VPC peering connection route tables do not include 0.0.0.0/0 or ::/0 routes"
        )
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="IAM Role ARN to assume for the audit"
    )

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant, skipped = \
        check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print("\n====================================================")
    print("CONTROL : VPC Peering Connection Route Tables Do Not Include 0.0.0.0/0 Routes")
    print(f"ACCOUNT : {account_id}")
    print("====================================================")
    print(f"Total Checked  : {total_checked}")
    print(f"Compliant      : {compliant}")
    print(f"Non-Compliant  : {non_compliant}")
    print(f"Skipped        : {skipped}")
    print(f"\nOVERALL STATUS : {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Generated  : {csv_file}\n")


if __name__ == "__main__":
    main()
