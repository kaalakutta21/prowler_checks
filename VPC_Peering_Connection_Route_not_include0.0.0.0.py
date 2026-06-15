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

def get_peering_cidrs(pcx):
    """
    Collect requester/accepter IPv4 and IPv6 CIDRs from the peering object.
    """

    cidrs = set()

    requester_info = pcx.get("RequesterVpcInfo", {})
    accepter_info = pcx.get("AccepterVpcInfo", {})

    # IPv4
    if requester_info.get("CidrBlock"):
        cidrs.add(requester_info["CidrBlock"])
    if accepter_info.get("CidrBlock"):
        cidrs.add(accepter_info["CidrBlock"])

    # IPv6
    for assoc in requester_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    for assoc in accepter_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    return cidrs


def check_route_against_peering(route, peering_cidrs):
    """
    Flag if route to pcx uses:
    - 0.0.0.0/0
    - ::/0
    - full requester/accepter VPC CIDR
    """

    destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")

    if not destination:
        return False, "No CIDR destination"

    if destination in ["0.0.0.0/0", "::/0"]:
        return True, f"Default route {destination} points to peering connection"

    if destination in peering_cidrs:
        return True, f"Full VPC CIDR {destination} points to peering connection"

    return False, f"Specific route {destination} only"


def get_route_table_name(rt):
    for tag in rt.get("Tags", []):
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_vpc_peering_routes(session):

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
        except ClientError:
            skipped += 1
            continue

        try:
            pcx_resp = ec2.describe_vpc_peering_connections()
            peerings = pcx_resp.get("VpcPeeringConnections", [])
        except ClientError:
            skipped += 1
            continue

        # Build peering lookup
        peering_map = {}
        for pcx in peerings:
            pcx_id = pcx["VpcPeeringConnectionId"]
            peering_map[pcx_id] = {
                "Cidrs": get_peering_cidrs(pcx),
                "Status": pcx.get("Status", {}).get("Code", ""),
                "RequesterVpcId": pcx.get("RequesterVpcInfo", {}).get("VpcId", ""),
                "AccepterVpcId": pcx.get("AccepterVpcInfo", {}).get("VpcId", "")
            }

        try:
            paginator = ec2.get_paginator("describe_route_tables")

            for page in paginator.paginate():

                for rt in page.get("RouteTables", []):

                    route_table_id = rt["RouteTableId"]
                    route_table_name = get_route_table_name(rt)
                    vpc_id = rt.get("VpcId", "")

                    for route in rt.get("Routes", []):

                        pcx_id = route.get("VpcPeeringConnectionId")
                        if not pcx_id:
                            continue

                        total_checked += 1

                        if pcx_id not in peering_map:
                            status = "SKIPPED"
                            evidence = f"Peering connection {pcx_id} not found"
                            skipped += 1

                            results.append({
                                "Region": region,
                                "RouteTableId": route_table_id,
                                "RouteTableName": route_table_name,
                                "VpcId": vpc_id,
                                "VpcPeeringConnectionId": pcx_id,
                                "Destination": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", ""),
                                "Status": status,
                                "Evidence": evidence
                            })
                            continue

                        peering_info = peering_map[pcx_id]
                        peering_cidrs = peering_info["Cidrs"]

                        is_bad, evidence = check_route_against_peering(route, peering_cidrs)

                        if is_bad:
                            status = "NON_COMPLIANT"
                            non_compliant += 1
                        else:
                            status = "COMPLIANT"
                            compliant += 1

                        results.append({
                            "Region": region,
                            "RouteTableId": route_table_id,
                            "RouteTableName": route_table_name,
                            "VpcId": vpc_id,
                            "VpcPeeringConnectionId": pcx_id,
                            "Destination": route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", ""),
                            "Status": status,
                            "Evidence": evidence
                        })

        except ClientError:
            skipped += 1
            continue

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"vpc_peering_route_tables_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "RouteTableId",
            "RouteTableName",
            "VpcId",
            "VpcPeeringConnectionId",
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

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Role ARN"
    )

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant, skipped = \
        check_vpc_peering_routes(session)

    print("\n====================================================")
    print("CONTROL: VPC Peering Connection Route Tables Do Not Include 0.0.0.0/0 Or Entire Requester/Accepter VPC CIDR Routes")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Peering Routes Checked : {total_checked}")
    print(f"Compliant                    : {compliant}")
    print(f"Non-Compliant                : {non_compliant}")
    print(f"Skipped                      : {skipped}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
