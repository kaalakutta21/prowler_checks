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
            RoleSessionName="dynamodb-kms-audit"
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
# CONTROL LOGIC (SCP SAFE + PAGINATION FIXED)
# ==================================================

def check_dynamodb_kms(session):

    regions = get_regions(session)

    results = []
    total = 0
    non_compliant = 0
    skipped_tables = 0
    skipped_regions = 0

    account_id = get_account_id(session)

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):

        try:
            dynamodb = session.client("dynamodb", region_name=region)
            paginator = dynamodb.get_paginator("list_tables")

        except ClientError as e:
            code = e.response["Error"]["Code"]

            if code in ["AccessDeniedException", "UnauthorizedOperation"]:
                print(f"Skipping region {region} (SCP Denied)")
                skipped_regions += 1
                continue
            else:
                continue

        # ==================================================
        # SAFE PAGINATION (CRITICAL FIX)
        # ==================================================
        try:
            for page in paginator.paginate():

                for table_name in page.get("TableNames", []):

                    arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"

                    # ---------- DESCRIBE TABLE ----------
                    try:
                        desc = dynamodb.describe_table(
                            TableName=table_name
                        )["Table"]

                    except ClientError as e:
                        code = e.response["Error"]["Code"]

                        if code in ["AccessDeniedException", "UnauthorizedOperation"]:
                            skipped_tables += 1

                            results.append({
                                "Region": region,
                                "TableName": table_name,
                                "TableArn": arn,
                                "SSEType": "UNKNOWN",
                                "KMSKey": "UNKNOWN",
                                "Status": "SKIPPED",
                                "Reason": "Access Denied (SCP/IAM)"
                            })
                            continue
                        else:
                            continue

                    total += 1

                    sse = desc.get("SSEDescription", {})

                    sse_type = sse.get("SSEType")
                    kms_key = sse.get("KMSMasterKeyArn")
                    status_flag = sse.get("SSEStatus")

                    # ---------- LOGIC ----------
                    if (
                        sse_type == "KMS"
                        and kms_key
                        and status_flag == "ENABLED"
                        and "alias/aws/dynamodb" not in (kms_key or "").lower()
                    ):
                        status = "COMPLIANT"
                        reason = "Customer Managed CMK"

                    else:
                        status = "NON_COMPLIANT"
                        non_compliant += 1

                        if not sse:
                            reason = "No encryption"
                        elif not kms_key:
                            reason = "No KMS key"
                        elif "alias/aws/dynamodb" in (kms_key or "").lower():
                            reason = "AWS Managed Key"
                        else:
                            reason = "Unknown configuration"

                    results.append({
                        "Region": region,
                        "TableName": table_name,
                        "TableArn": arn,
                        "SSEType": sse_type if sse_type else "None",
                        "KMSKey": kms_key if kms_key else "None",
                        "Status": status,
                        "Reason": reason
                    })

        except ClientError as e:
            code = e.response["Error"]["Code"]

            if code in ["AccessDeniedException", "UnauthorizedOperation"]:
                print(f"Skipping region {region} during pagination (SCP Denied)")
                skipped_regions += 1
                continue
            else:
                continue

    compliant = total - non_compliant

    return results, total, compliant, non_compliant, skipped_tables, skipped_regions


# ==================================================
# CSV
# ==================================================

def write_csv(account_id, results):

    filename = f"dynamodb_kms_encryption_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        fields = [
            "Account",
            "Region",
            "TableName",
            "TableArn",
            "SSEType",
            "KMSKey",
            "Status",
            "Reason"
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
        description="Ensure DynamoDB tables use CMK encryption (SCP Safe)"
    )

    parser.add_argument("-R", "--role-arn", help="Role ARN")

    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total, compliant, non_compliant, skipped_tables, skipped_regions = \
        check_dynamodb_kms(session)

    print("\n====================================================")
    print("CONTROL: DynamoDB Encryption with CMK")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Tables Checked     : {total}")
    print(f"Compliant                : {compliant}")
    print(f"Non-Compliant            : {non_compliant}")
    print(f"Skipped Tables (SCP)     : {skipped_tables}")
    print(f"Skipped Regions (SCP)    : {skipped_regions}")

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    print(f"\nOVERALL STATUS: {overall}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)

    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
