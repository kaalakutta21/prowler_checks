#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
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
            RoleSessionName="s3-advanced-audit"
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
# POLICY CHECK: DENY INSECURE TRANSPORT
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

    buckets = s3.list_buckets().get("Buckets", [])
    print(f"\nTotal Buckets Found: {len(buckets)}\n")

    results = []

    summary = {
        "Deny Insecure Transport": {"total": 0, "non_compliant": 0},
        "Object Lock Enabled": {"total": 0, "non_compliant": 0},
        "Lifecycle Configuration Enabled": {"total": 0, "non_compliant": 0},
        "Event Notification Enabled": {"total": 0, "non_compliant": 0},
    }

    for bucket in tqdm(buckets, desc="Evaluating Buckets"):

        bucket_name = bucket["Name"]

        # -------------------------------------------------
        # 1) DENY INSECURE TRANSPORT
        # -------------------------------------------------
        control = "Deny Insecure Transport"
        summary[control]["total"] += 1

        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy["Policy"])
            secure = denies_insecure_transport(policy_doc)
        except ClientError:
            secure = False

        if secure:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 2) OBJECT LOCK ENABLED
        # -------------------------------------------------
        control = "Object Lock Enabled"
        summary[control]["total"] += 1

        try:
            lock = s3.get_object_lock_configuration(Bucket=bucket_name)
            enabled = lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
        except ClientError:
            enabled = False

        if enabled:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 3) LIFECYCLE CONFIGURATION
        # -------------------------------------------------
        control = "Lifecycle Configuration Enabled"
        summary[control]["total"] += 1

        try:
            lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            has_rules = len(lifecycle.get("Rules", [])) > 0
        except ClientError:
            has_rules = False

        if has_rules:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"
            summary[control]["non_compliant"] += 1

        results.append([bucket_name, control, status])

        # -------------------------------------------------
        # 4) EVENT NOTIFICATIONS
        # -------------------------------------------------
        control = "Event Notification Enabled"
        summary[control]["total"] += 1

        try:
            notification = s3.get_bucket_notification_configuration(Bucket=bucket_name)
            enabled = any([
                notification.get("LambdaFunctionConfigurations"),
                notification.get("QueueConfigurations"),
                notification.get("TopicConfigurations")
            ])
        except ClientError:
            enabled = False

        if enabled:
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
    filename = f"s3_advanced_controls_{account_id}.csv"

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
        description="Advanced S3 Security Controls Audit"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, summary = check_s3_controls(session)

    print("\n====================================================")
    print("S3 ADVANCED SECURITY CONTROLS")
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
