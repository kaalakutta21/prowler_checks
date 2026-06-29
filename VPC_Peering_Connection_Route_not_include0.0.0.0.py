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


def get_requester_cidrs(pcx):
    cidrs = set()
    requester_info = pcx.get("RequesterVpcInfo", {})

    if requester_info.get("CidrBlock"):
        cidrs.add(requester_info["CidrBlock"])

    for assoc in requester_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    return cidrs


def get_accepter_cidrs(pcx):
    cidrs = set()
    accepter_info = pcx.get("AccepterVpcInfo", {})

    if accepter_info.get("CidrBlock"):
        cidrs.add(accepter_info["CidrBlock"])

    for assoc in accepter_info.get("Ipv6CidrBlockAssociationSet", []):
        if assoc.get("Ipv6CidrBlock"):
            cidrs.add(assoc["Ipv6CidrBlock"])

    return cidrs


def evaluate_route(route, route_table_vpc_id, requester_vpc_id, accepter_vpc_id,
                   requester_cidrs, accepter_cidrs):
    """
    Side-aware logic:
    - default routes to pcx are always bad
    - if route table belongs to requester VPC, only accepter CIDRs are relevant
    - if route table belongs to accepter VPC, only requester CIDRs are relevant
    """
    destination = get_destination(route)

    if not destination:
        return False, "No CIDR destination"

    if destination in ["0.0.0.0/0", "::/0"]:
        return True, f"Default route {destination} points to peering connection"

    if route_table_vpc_id == requester_vpc_id:
        if destination in accepter_cidrs:
            return True, f"Full accepter VPC CIDR {destination} points to peering connection"
        return False, f"Specific/non-full accepter-side route {destination} only"

    if route_table_vpc_id == accepter_vpc_id:
        if destination in requester_cidrs:
            return True, f"Full requester VPC CIDR {destination} points to peering connection"
        return False, f"Specific/non-full requester-side route {destination} only"

    return False, (
        f"Route table VPC {route_table_vpc_id} does not match requester/accepter VPC; "
        f"route {destination} not evaluated as broad"
    )


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
# 0.0.0.0/0 or entire requester/accepter VPC CIDR routes
#
# Logic:
# - Only ACTIVE peering connections are checked
# - Each pcx is processed once globally
# - Only route tables referencing that pcx are checked
# - Default routes to pcx are NON_COMPLIANT
# - Full peer CIDR routes are evaluated side-aware:
#     requester-side RT -> accepter full CIDR is bad
#     accepter-side RT  -> requester full CIDR is bad
# - Peerings with no referencing routes are not counted
#
# Summary counts are by VPC peering connection.
# CSV rows are route-table / route level.
# ==================================================

def check_vpc_peering_routes(session):

    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    skipped = 0

    total_peerings = 0
    compliant_peerings = 0
    non_compliant_peerings = 0

    seen_pcx_ids = set()

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
            peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
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

            if pcx_id in seen_pcx_ids:
                continue

            seen_pcx_ids.add(pcx_id)

            pcx_status = pcx.get("Status", {}).get("Code", "")
            if pcx_status != "active":
                continue

            pcx_arn = f"arn:aws:ec2:{region}:{account_id}:vpc-peering-connection/{pcx_id}"

            requester_info = pcx.get("RequesterVpcInfo", {})
            accepter_info = pcx.get("AccepterVpcInfo", {})

            requester_vpc_id = requester_info.get("VpcId", "")
            accepter_vpc_id = accepter_info.get("VpcId", "")

            requester_cidrs = get_requester_cidrs(pcx)
            accepter_cidrs = get_accepter_cidrs(pcx)

            peering_non_compliant = False
            peering_has_referencing_route = False

            try:
                paginator = ec2.get_paginator("describe_route_tables")

                for page in paginator.paginate(
                    Filters=[{
                        "Name": "route.vpc-peering-connection-id",
                        "Values": [pcx_id]
                    }]
                ):
                    for rt in page.get("RouteTables", []):

                        route_table_id = rt["RouteTableId"]
                        route_table_name = get_route_table_name(rt)
                        vpc_id = rt.get("VpcId", "")

                        for route in rt.get("Routes", []):

                            if route.get("VpcPeeringConnectionId") != pcx_id:
                                continue

                            peering_has_referencing_route = True

                            destination = get_destination(route)
                            is_bad, evidence = evaluate_route(
                                route,
                                vpc_id,
                                requester_vpc_id,
                                accepter_vpc_id,
                                requester_cidrs,
                                accepter_cidrs
                            )

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

            if not peering_has_referencing_route:
                continue

            total_peerings += 1

            if peering_non_compliant:
                non_compliant_peerings += 1
            else:
                compliant_peerings += 1

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
            "VpcPeeringConnectionArn",
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
