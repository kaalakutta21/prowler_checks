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
            RoleSessionName="rds-snapshot-audit"
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
# CONTROL LOGIC
# --------------------------------------------------

def check_rds_snapshots(session, regions):

    results = []
    total_checked = 0
    non_compliant = 0

    for region in tqdm(regions, desc="Scanning Regions"):
        rds = session.client("rds", region_name=region)

        try:
            # -------------------------
            # ALL DB SNAPSHOTS
            # -------------------------
            db_paginator = rds.get_paginator("describe_db_snapshots")

            for page in db_paginator.paginate():
                snapshots = page.get("DBSnapshots", [])

                for snap in tqdm(snapshots, desc=f"{region} DB Snapshots", leave=False):
                    total_checked += 1
                    snap_id = snap["DBSnapshotIdentifier"]
                    snap_type = snap.get("SnapshotType", "UNKNOWN")
                    status = "COMPLIANT"

                    try:
                        attrs = rds.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snap_id
                        )

                        for attr in attrs["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
                            if attr["AttributeName"] == "restore":
                                if "all" in attr["AttributeValues"]:
                                    status = "NON_COMPLIANT"
                                    non_compliant += 1
                    except ClientError:
                        pass

                    results.append({
                        "Region": region,
                        "SnapshotType": f"DB_SNAPSHOT ({snap_type})",
                        "SnapshotIdentifier": snap_id,
                        "Status": status
                    })

            # -------------------------
            # ALL DB CLUSTER SNAPSHOTS
            # -------------------------
            cluster_paginator = rds.get_paginator("describe_db_cluster_snapshots")

            for page in cluster_paginator.paginate():
                snapshots = page.get("DBClusterSnapshots", [])

                for snap in tqdm(snapshots, desc=f"{region} Cluster Snapshots", leave=False):
                    total_checked += 1
                    snap_id = snap["DBClusterSnapshotIdentifier"]
                    snap_type = snap.get("SnapshotType", "UNKNOWN")
                    status = "COMPLIANT"

                    try:
                        attrs = rds.describe_db_cluster_snapshot_attributes(
                            DBClusterSnapshotIdentifier=snap_id
                        )

                        for attr in attrs["DBClusterSnapshotAttributesResult"]["DBClusterSnapshotAttributes"]:
                            if attr["AttributeName"] == "restore":
                                if "all" in attr["AttributeValues"]:
                                    status = "NON_COMPLIANT"
                                    non_compliant += 1
                    except ClientError:
                        pass

                    results.append({
                        "Region": region,
                        "SnapshotType": f"DB_CLUSTER_SNAPSHOT ({snap_type})",
                        "SnapshotIdentifier": snap_id,
                        "Status": status
                    })

        except ClientError:
            continue

    compliant = total_checked - non_compliant
    return results, total_checked, compliant, non_compliant

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"rds_snapshot_public_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "SnapshotType",
            "SnapshotIdentifier",
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
        description="Ensure RDS Snapshots and Cluster Snapshots are not public"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)
    regions = get_regions(session)

    results, total_checked, compliant, non_compliant = \
        check_rds_snapshots(session, regions)

    print("\n====================================================")
    print("CONTROL: RDS Snapshots Not Public")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Snapshots Checked : {total_checked}")
    print(f"Compliant               : {compliant}")
    print(f"Non-Compliant           : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
