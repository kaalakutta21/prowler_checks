#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError

GREEN = "\033[92m"
RED = "\033[91m"
PURPLE = "\033[95m"
RESET = "\033[0m"

# ==================================================
# AUTH
# ==================================================

def get_session(role_arn=None):

    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")

        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="s3-advanced-audit"
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
# REGION DISCOVERY
# ==================================================

def get_active_regions(session):

    ec2 = session.client("ec2", region_name="us-east-1")

    regions = ec2.describe_regions(AllRegions=False)["Regions"]

    return [r["RegionName"] for r in regions]


# ==================================================
# POLICY CHECK
# ==================================================

def denies_insecure_transport(policy_doc):

    statements = policy_doc.get("Statement", [])

    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:

        if stmt.get("Effect") == "Deny":

            condition = stmt.get("Condition", {})
            bool_condition = condition.get("Bool", {})

            if bool_condition.get("aws:SecureTransport") == "false":
                return True

    return False


# ==================================================
# MAIN CONTROL LOGIC
# ==================================================

def check_s3_controls(session):

    s3 = session.client("s3")

    account_id = get_account_id(session)

    buckets = s3.list_buckets()["Buckets"]

    print(f"\nBuckets discovered: {len(buckets)}\n")

    results = []

    non_compliant_details = []

    summary = {
        "Deny Insecure Transport": {"total": 0, "non_compliant": 0},
        "Object Lock Enabled": {"total": 0, "non_compliant": 0},
        "Lifecycle Configuration Enabled": {"total": 0, "non_compliant": 0},
        "Event Notification Enabled": {"total": 0, "non_compliant": 0},
    }

    for bucket in tqdm(buckets, desc="Evaluating Buckets"):

        bucket_name = bucket["Name"]

        # -------------------------------------------------
        # DENY INSECURE TRANSPORT
        # -------------------------------------------------

        control = "Deny Insecure Transport"
        summary[control]["total"] += 1

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy["Policy"])
            secure = denies_insecure_transport(policy_doc)

        except ClientError:
            secure = False

        status = "COMPLIANT" if secure else "NON_COMPLIANT"

        if not secure:
            summary[control]["non_compliant"] += 1
            non_compliant_details.append((bucket_name, control))

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # OBJECT LOCK
        # -------------------------------------------------

        control = "Object Lock Enabled"
        summary[control]["total"] += 1

        try:
            lock = s3.get_object_lock_configuration(Bucket=bucket_name)

            enabled = (
                lock.get("ObjectLockConfiguration", {})
                .get("ObjectLockEnabled") == "Enabled"
            )

        except ClientError:
            enabled = False

        status = "COMPLIANT" if enabled else "NON_COMPLIANT"

        if not enabled:
            summary[control]["non_compliant"] += 1
            non_compliant_details.append((bucket_name, control))

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # LIFECYCLE CONFIGURATION
        # -------------------------------------------------

        control = "Lifecycle Configuration Enabled"
        summary[control]["total"] += 1

        try:
            lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)

            has_rules = len(lifecycle.get("Rules", [])) > 0

        except ClientError:
            has_rules = False

        status = "COMPLIANT" if has_rules else "NON_COMPLIANT"

        if not has_rules:
            summary[control]["non_compliant"] += 1
            non_compliant_details.append((bucket_name, control))

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # EVENT NOTIFICATIONS
        # -------------------------------------------------

        control = "Event Notification Enabled"
        summary[control]["total"] += 1

        try:
            notification = s3.get_bucket_notification_configuration(
                Bucket=bucket_name
            )

            enabled = any([
                notification.get("LambdaFunctionConfigurations"),
                notification.get("QueueConfigurations"),
                notification.get("TopicConfigurations")
            ])

        except ClientError:
            enabled = False

        status = "COMPLIANT" if enabled else "NON_COMPLIANT"

        if not enabled:
            summary[control]["non_compliant"] += 1
            non_compliant_details.append((bucket_name, control))

        results.append([bucket_name, control, status])

    return account_id, results, summary, non_compliant_details


# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):

    filename = f"s3_advanced_controls_{account_id}.csv"

    with open(filename, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Account",
            "BucketName",
            "Control",
            "Status"
        ])

        for bucket, control, status in results:
            writer.writerow([account_id, bucket, control, status])

    return filename


# ==================================================
# MAIN
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description="Advanced S3 Security Controls Audit"
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="Role ARN to assume"
    )

    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, summary, non_compliant = check_s3_controls(session)

    print("\n================================================")
    print("S3 ADVANCED SECURITY CONTROLS AUDIT")
    print(f"ACCOUNT: {account_id}")
    print("================================================\n")

    for control, data in summary.items():

        total = data["total"]
        non_compliant_count = data["non_compliant"]
        compliant = total - non_compliant_count

        if non_compliant_count == 0:
            status = f"{GREEN}COMPLIANT{RESET}"
        else:
            status = f"{RED}NON_COMPLIANT{RESET}"

        print(f"{control}")
        print(f"  Total Checked : {total}")
        print(f"  Compliant     : {compliant}")
        print(f"  Non-Compliant : {non_compliant_count}")
        print(f"  Overall       : {status}")
        print("------------------------------------------------")

    # Detailed findings

    if non_compliant:

        print(f"\n{PURPLE}NON-COMPLIANT RESOURCES{RESET}\n")

        for bucket, control in non_compliant:
            print(f"{bucket} -> {control}")

    else:

        print(f"\n{GREEN}All buckets are compliant for tested controls{RESET}\n")

    csv_file = write_csv(account_id, results)

    print(f"\nCSV report generated: {csv_file}\n")


if __name__ == "__main__":
    main()
