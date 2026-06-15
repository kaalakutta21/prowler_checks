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

def get_route_table_name(route_table):
    for tag in route_table.get("Tags", []):
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def get_peering_cidrs(pcx):
    cidrs = set()

    requester_info = pcx.get("RequesterVpcInfo", {})
    accepter_info = pcx.get("AccepterVpcInfo", {})

    if requester_info.get("CidrBlock"):
        cidrs.add(requester_info["CidrBlock"])

    if accepter_info.get("CidrBlock"):
        cidrs.add(accepter_info["CidrBlock"])

    for assoc in requester_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    for assoc in accepter_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    return cidrs


def evaluate_route(route, peering_cidrs):
    destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")

    if not destination:
        return False, "No CIDR destination"

    if destination in ["0.0.0.0/0", "::/0"]:
        return True, f"Default route {destination} points to peering connection"

    if destination in peering_cidrs:
        return True, f"Full VPC CIDR {destination} points to peering connection"

    return False, f"Specific route {destination} only"


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_vpc_peering_routes(session):

    regions = get_regions(session)

    results = []
    skipped = 0

    total_peerings = 0
    compliant_peerings = 0
    non_compliant_peerings = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            ec2 = session.client("ec2", region_name=region)
        except ClientError:
            skipped += 1
            continue

        try:
            peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        except ClientError:
            skipped += 1
            continue

        if not peerings:
            continue

        try:
            route_tables = []
            paginator = ec2.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                route_tables.extend(page.get("RouteTables", []))
        except ClientError:
            skipped += 1
            continue

        for pcx in peerings:

            pcx_id = pcx["VpcPeeringConnectionId"]
            pcx_status = pcx.get("Status", {}).get("Code", "")
            peering_cidrs = get_peering_cidrs(pcx)

            total_peerings += 1
            peering_non_compliant = False
            peering_has_route = False

            for rt in route_tables:

                route_table_id = rt["RouteTableId"]
                route_table_name = get_route_table_name(rt)
                vpc_id = rt.get("VpcId", "")

                for route in rt.get("Routes", []):

                    if route.get("VpcPeeringConnectionId") != pcx_id:
                        continue

                    peering_has_route = True

                    destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", "")
                    is_bad, evidence = evaluate_route(route, peering_cidrs)

                    status = "NON_COMPLIANT" if is_bad else "COMPLIANT"

                    if is_bad:
                        peering_non_compliant = True

                    results.append({
                        "Region": region,
                        "VpcPeeringConnectionId": pcx_id,
                        "VpcPeeringStatus": pcx_status,
                        "RouteTableId": route_table_id,
                        "RouteTableName": route_table_name,
                        "VpcId": vpc_id,
                        "Destination": destination,
                        "Status": status,
                        "Evidence": evidence
                    })

            if peering_non_compliant:
                non_compliant_peerings += 1
            else:
                compliant_peerings += 1

            if not peering_has_route:
                results.append({
                    "Region": region,
                    "VpcPeeringConnectionId": pcx_id,
                    "VpcPeeringStatus": pcx_status,
                    "RouteTableId": "",
                    "RouteTableName": "",
                    "VpcId": "",
                    "Destination": "",
                    "Status": "COMPLIANT",
                    "Evidence": "No route tables reference this peering connection"
                })

    return (
        results,
        total_peerings,
        compliant_peerings,
        non_compliant_peerings,
        skipped
    )


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"vpc_peering_route_tables_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "VpcPeeringConnectionId",
            "VpcPeeringStatus",
            "RouteTableId",
            "RouteTableName",
            "VpcId",
            "Destination",
            "Status",
            "Evidence"
        ]

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
        description="VPC peering connection route tables do not include 0.0.0.0/0 or full requester/accepter VPC CIDR routes"
    )

    parser.add_argument("-R", "--role-arn", help="Role ARN")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_peerings, compliant_peerings, non_compliant_peerings, skipped = \
        check_vpc_peering_routes(session)

    print("\n====================================================")
    print("CONTROL: VPC Peering Connection Route Tables Do Not Include 0.0.0.0/0 Or Entire Requester/Accepter VPC CIDR Routes")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total VPC Peering Connections Checked : {total_peerings}")
    print(f"Compliant                             : {compliant_peerings}")
    print(f"Non-Compliant                         : {non_compliant_peerings}")
    print(f"Skipped                               : {skipped}")

    overall = "COMPLIANT" if non_compliant_peerings == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
