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
            RoleSessionName="s3-combined-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name="us-east-1"
        )
    return boto3.Session(region_name="us-east-1")

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# MAIN CONTROL LOGIC
# ==================================================

def check_s3_controls(session):

    s3 = session.client("s3")
    account_id = get_account_id(session)

    buckets = s3.list_buckets().get("Buckets", [])
    print(f"\nTotal Buckets Found: {len(buckets)}\n")

    results = []

    # Separate counters per control
    summary = {
        "MFA Delete Enabled": {"total": 0, "non_compliant": 0},
        "Bucket ACLs Disabled": {"total": 0, "non_compliant": 0},
        "Default SSE Enabled": {"total": 0, "non_compliant": 0},
        "Object Versioning Enabled": {"total": 0, "non_compliant": 0},
        "Server Access Logging Enabled": {"total": 0, "non_compliant": 0},
        "SSE Uses AWS KMS": {"total": 0, "non_compliant": 0},
    }

    for bucket in tqdm(buckets, desc="Evaluating Buckets"):

        bucket_name = bucket["Name"]

        # -------------------------------------------------
        # Get bucket metadata once
        # -------------------------------------------------
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        except ClientError:
            versioning = {}

        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]
        except ClientError:
            rules = []

        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)
        except ClientError:
            logging = {}

        try:
            ownership = s3.get_bucket_ownership_controls(Bucket=bucket_name)
            ownership_rules = ownership["OwnershipControls"]["Rules"]
        except ClientError:
            ownership_rules = []

        # -------------------------------------------------
        # 1) MFA DELETE
        # -------------------------------------------------
        control = "MFA Delete Enabled"
        summary[control]["total"] += 1

        mfa_status = versioning.get("MFADelete", "Disabled")
        version_status = versioning.get("Status", "Disabled")

        if version_status == "Enabled" and mfa_status == "Enabled":
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 2) BUCKET ACLs DISABLED
        # -------------------------------------------------
        control = "Bucket ACLs Disabled"
        summary[control]["total"] += 1

        acl_disabled = any(
            rule.get("ObjectOwnership") == "BucketOwnerEnforced"
            for rule in ownership_rules
        )

        if acl_disabled:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 3) DEFAULT SSE ENABLED
        # -------------------------------------------------
        control = "Default SSE Enabled"
        summary[control]["total"] += 1

        if rules:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 4) OBJECT VERSIONING ENABLED
        # -------------------------------------------------
        control = "Object Versioning Enabled"
        summary[control]["total"] += 1

        if version_status == "Enabled":
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 5) SERVER ACCESS LOGGING ENABLED
        # -------------------------------------------------
        control = "Server Access Logging Enabled"
        summary[control]["total"] += 1

        if "LoggingEnabled" in logging:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 6) SSE WITH AWS KMS
        # -------------------------------------------------
        control = "SSE Uses AWS KMS"
        summary[control]["total"] += 1

        uses_kms = any(
            rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
            for rule in rules
        )

        if uses_kms:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

    return account_id, results, summary

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"s3_combined_controls_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Account", "BucketName", "Control", "Status"])

        for bucket, control, status in results:
            writer.writerow([account_id, bucket, control, status])

    return filename

# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Combined S3 Security Controls Audit"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, summary = check_s3_controls(session)

    print("\n====================================================")
    print("S3 COMBINED SECURITY CONTROLS")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    for control, data in summary.items():
        total = data["total"]
        non_compliant = data["non_compliant"]
        compliant = total - non_compliant
        overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

        print(f"CONTROL: {control}")
        print(f"  Total Checked : {total}")
        print(f"  Compliant     : {compliant}")
        print(f"  Non-Compliant : {non_compliant}")
        print(f"  OVERALL       : {overall}")
        print("----------------------------------------------------")

    csv_file = write_csv(account_id, results)
    print(f"\nCSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
