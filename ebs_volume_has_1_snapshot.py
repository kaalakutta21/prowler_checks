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
            RoleSessionName="ebs-snapshot-audit"
        )

        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

    return boto3.Session()


def get_account_id(session):

    return (
        session.client("sts")
        .get_caller_identity()["Account"]
    )

# ==================================================
# REGIONS
# ==================================================

def get_regions(session):

    ec2 = session.client(
        "ec2",
        region_name="us-east-1"
    )

    regions = ec2.describe_regions(
        AllRegions=False
    )

    return sorted([
        r["RegionName"]
        for r in regions["Regions"]
    ])

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_ebs_snapshots(
    session,
    account_id
):

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

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

            snapshot_map = {}

            snapshot_paginator = (
                ec2.get_paginator(
                    "describe_snapshots"
                )
            )

            for page in snapshot_paginator.paginate(
                OwnerIds=["self"]
            ):

                for snapshot in page.get(
                    "Snapshots",
                    []
                ):

                    volume_id = snapshot.get(
                        "VolumeId"
                    )

                    if volume_id:

                        snapshot_map.setdefault(
                            volume_id,
                            []
                        ).append(
                            snapshot["SnapshotId"]
                        )

            volume_paginator = (
                ec2.get_paginator(
                    "describe_volumes"
                )
            )

            for page in volume_paginator.paginate():

                for volume in page.get(
                    "Volumes",
                    []
                ):

                    total += 1

                    volume_id = volume[
                        "VolumeId"
                    ]

                    volume_state = volume.get(
                        "State",
                        "Unknown"
                    )

                    snapshots = snapshot_map.get(
                        volume_id,
                        []
                    )

                    snapshot_count = len(
                        snapshots
                    )

                    if snapshot_count > 0:

                        status = "COMPLIANT"

                        evidence = (
                            f"Volume has "
                            f"{snapshot_count} "
                            f"snapshot(s)"
                        )

                        compliant += 1

                    else:

                        status = (
                            "NON_COMPLIANT"
                        )

                        evidence = (
                            "No snapshots "
                            "found for volume"
                        )

                        non_compliant += 1

                    results.append({
                        "Account":
                            account_id,
                        "Region":
                            region,
                        "VolumeId":
                            volume_id,
                        "VolumeState":
                            volume_state,
                        "SnapshotCount":
                            snapshot_count,
                        "Status":
                            status,
                        "Evidence":
                            evidence
                    })

        except ClientError as e:

            skipped += 1

            results.append({
                "Account":
                    account_id,
                "Region":
                    region,
                "VolumeId":
                    "N/A",
                "VolumeState":
                    "N/A",
                "SnapshotCount":
                    "N/A",
                "Status":
                    "SKIPPED",
                "Evidence":
                    str(e)
            })

    return (
        results,
        total,
        compliant,
        non_compliant,
        skipped
    )

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(
    account_id,
    results
):

    filename = (
        f"ebs_volume_has_snapshot_"
        f"{account_id}.csv"
    )

    with open(
        filename,
        "w",
        newline=""
    ) as f:

        fields = [
            "Account",
            "Region",
            "VolumeId",
            "VolumeState",
            "SnapshotCount",
            "Status",
            "Evidence"
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for row in results:

            writer.writerow(row)

    return filename

# ==================================================
# MAIN
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "EBS Volume Has "
            "At Least One Snapshot Audit"
        )
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Role ARN"
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
    ) = check_ebs_snapshots(
        session,
        account_id
    )

    print(
        "\n======================================="
    )

    print(
        "CONTROL: EBS Volume Has "
        "At Least One Snapshot"
    )

    print(
        f"ACCOUNT: {account_id}"
    )

    print(
        "=======================================\n"
    )

    print(
        f"Total Volumes      : {total}"
    )

    print(
        f"Compliant          : {compliant}"
    )

    print(
        f"Non-Compliant      : "
        f"{non_compliant}"
    )

    print(
        f"Skipped            : {skipped}"
    )

    overall = (
        "COMPLIANT"
        if non_compliant == 0
        else "NON_COMPLIANT"
    )

    print(
        f"\nOVERALL STATUS: "
        f"{overall}"
    )

    print(
        "\n=======================================\n"
    )

    csv_file = write_csv(
        account_id,
        results
    )

    print(
        f"CSV Generated: "
        f"{csv_file}\n"
    )

if __name__ == "__main__":
    main()
