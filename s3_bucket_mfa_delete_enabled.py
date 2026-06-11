#!/usr/bin/env python3

import boto3
import argparse
import csv
from botocore.exceptions import ClientError
from tqdm import tqdm

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):

    if role_arn:

        base = boto3.Session()

        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="s3-mfa-delete-audit"
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
# CONTROL LOGIC
# ==================================================

def check_s3_mfa_delete(session):

    s3 = session.client("s3")

    account_id = get_account_id(session)

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print("\nScanning S3 Buckets...\n")

    try:

        buckets = s3.list_buckets()["Buckets"]

    except ClientError as e:

        print(f"Unable to list buckets: {e}")

        return [], 0, 0, 0, 1

    for bucket in tqdm(
        buckets,
        desc="Checking Buckets"
    ):

        bucket_name = bucket["Name"]

        total += 1

        try:

            versioning = s3.get_bucket_versioning(
                Bucket=bucket_name
            )

            versioning_status = versioning.get(
                "Status",
                "Disabled"
            )

            mfa_delete_status = versioning.get(
                "MFADelete",
                "Disabled"
            )

            if (
                versioning_status == "Enabled"
                and
                mfa_delete_status == "Enabled"
            ):

                status = "COMPLIANT"

                evidence = (
                    "Versioning=Enabled, "
                    "MFADelete=Enabled"
                )

                compliant += 1

            else:

                status = "NON_COMPLIANT"

                evidence = (
                    f"Versioning={versioning_status}, "
                    f"MFADelete={mfa_delete_status}"
                )

                non_compliant += 1

            results.append({
                "Account": account_id,
                "BucketName": bucket_name,
                "VersioningStatus": versioning_status,
                "MFADeleteStatus": mfa_delete_status,
                "Status": status,
                "Evidence": evidence
            })

        except ClientError as e:

            skipped += 1

            results.append({
                "Account": account_id,
                "BucketName": bucket_name,
                "VersioningStatus": "UNKNOWN",
                "MFADeleteStatus": "UNKNOWN",
                "Status": "SKIPPED",
                "Evidence": str(e)
            })

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

def write_csv(account_id, results):

    filename = (
        f"s3_bucket_mfa_delete_"
        f"{account_id}.csv"
    )

    with open(
        filename,
        "w",
        newline=""
    ) as f:

        fields = [
            "Account",
            "BucketName",
            "VersioningStatus",
            "MFADeleteStatus",
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
            "S3 Bucket Has MFA Delete Enabled"
        )
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Cross-account Role ARN"
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
    ) = check_s3_mfa_delete(
        session
    )

    print("\n====================================================")
    print("CONTROL: S3 Bucket Has MFA Delete Enabled")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    print(f"Total Buckets   : {total}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")

    overall = (
        "COMPLIANT"
        if non_compliant == 0
        else "NON_COMPLIANT"
    )

    print(f"\nOVERALL STATUS: {overall}")

    print("\n====================================================\n")

    csv_file = write_csv(
        account_id,
        results
    )

    print(
        f"CSV Report Generated: "
        f"{csv_file}\n"
    )


if __name__ == "__main__":
    main()
