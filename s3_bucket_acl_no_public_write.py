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
            RoleSessionName="s3-acl-audit"
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
# CONTROL LOGIC
# ==================================================

def check_s3_acl_write_access(session):

    s3 = session.client("s3")

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    account_id = get_account_id(session)

    print("\nScanning S3 Buckets...\n")

    try:

        buckets = s3.list_buckets()["Buckets"]

    except ClientError as e:

        print(f"Unable to list buckets: {e}")

        return [], 0, 0, 0, 1

    for bucket in tqdm(
        buckets,
        desc="Checking Bucket ACLs"
    ):

        bucket_name = bucket["Name"]

        total += 1

        try:

            acl = s3.get_bucket_acl(
                Bucket=bucket_name
            )

            public_write_found = False

            evidence = []

            for grant in acl.get(
                "Grants",
                []
            ):

                permission = grant.get(
                    "Permission",
                    ""
                )

                grantee = grant.get(
                    "Grantee",
                    {}
                )

                uri = grantee.get(
                    "URI",
                    ""
                )

                if (
                    uri.endswith("/AllUsers")
                    or
                    uri.endswith("/AuthenticatedUsers")
                ):

                    if permission in [
                        "WRITE",
                        "WRITE_ACP",
                        "FULL_CONTROL"
                    ]:

                        public_write_found = True

                        evidence.append(
                            f"{uri} -> {permission}"
                        )

            if public_write_found:

                status = "NON_COMPLIANT"

                non_compliant += 1

                reason = "; ".join(
                    evidence
                )

            else:

                status = "COMPLIANT"

                compliant += 1

                reason = (
                    "No public/customer "
                    "write permissions found"
                )

            results.append({
                "Account": account_id,
                "BucketName": bucket_name,
                "Status": status,
                "Reason": reason
            })

        except ClientError as e:

            skipped += 1

            results.append({
                "Account": account_id,
                "BucketName": bucket_name,
                "Status": "SKIPPED",
                "Reason": str(e)
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
        f"s3_acl_public_write_"
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
            "Status",
            "Reason"
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
            "Ensure S3 bucket ACL "
            "does not grant write "
            "access to everyone "
            "or any AWS customer"
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
    ) = check_s3_acl_write_access(
        session
    )

    print("\n====================================================")
    print("CONTROL: S3 Bucket ACL Does Not Grant Write Access")
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
