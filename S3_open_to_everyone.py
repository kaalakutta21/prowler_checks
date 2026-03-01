#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
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
            RoleSessionName="s3-public-audit"
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
# PRINCIPAL CHECK
# --------------------------------------------------

def principal_is_public(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        if principal.get("AWS") == "*":
            return True
    return False

# --------------------------------------------------
# SEMANTIC CONDITION RESTRICTION CHECK
# --------------------------------------------------

RESTRICTIVE_PATTERNS = [
    "principal",
    "account",
    "org",
    "source",
    "vpc",
    "vpce",
    "ip",
    "accesspoint",
    "user"
]

def condition_is_restrictive(statement):
    condition = statement.get("Condition")
    if not condition:
        return False

    for operator_block in condition.values():

        if not isinstance(operator_block, dict):
            continue

        for key, value in operator_block.items():

            if not key:
                continue

            if not value:
                continue

            key_lower = key.lower()

            for pattern in RESTRICTIVE_PATTERNS:
                if pattern in key_lower:
                    return True

    return False

# --------------------------------------------------
# BPA CHECK
# --------------------------------------------------

def bpa_enabled(config):
    return (
        config.get("BlockPublicAcls", False) and
        config.get("IgnorePublicAcls", False) and
        config.get("BlockPublicPolicy", False) and
        config.get("RestrictPublicBuckets", False)
    )

# --------------------------------------------------
# CONTROL LOGIC
# --------------------------------------------------

def check_s3_public_access(session):

    s3 = session.client("s3")

    # Proper region handling for s3control
    default_region = session.region_name or "us-east-1"
    s3control = session.client("s3control", region_name=default_region)

    account_id = get_account_id(session)

    # -------------------------
    # Account-Level BPA
    # -------------------------
    account_bpa_enabled = False
    try:
        account_bpa = s3control.get_public_access_block(AccountId=account_id)
        account_bpa_enabled = bpa_enabled(
            account_bpa["PublicAccessBlockConfiguration"]
        )
    except ClientError:
        account_bpa_enabled = False

    results = []
    total_checked = 0
    non_compliant = 0

    buckets = s3.list_buckets()["Buckets"]

    for bucket in tqdm(buckets, desc="Scanning Buckets"):
        total_checked += 1
        bucket_name = bucket["Name"]

        policy_public = "NO"
        acl_public = "NO"
        status = "COMPLIANT"
        bucket_bpa_enabled = False

        # -------------------------
        # Bucket Policy Check
        # -------------------------
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy["Policy"])

            for stmt in policy_doc.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue

                if principal_is_public(stmt.get("Principal")):
                    if not condition_is_restrictive(stmt):
                        policy_public = "YES"
                        status = "NON_COMPLIANT"
                        break

        except ClientError:
            pass

        # -------------------------
        # Bucket ACL Check
        # -------------------------
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")

                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    acl_public = "YES"
                    status = "NON_COMPLIANT"

        except ClientError:
            pass

        # -------------------------
        # Bucket-Level BPA
        # -------------------------
        try:
            bucket_bpa = s3.get_public_access_block(Bucket=bucket_name)
            bucket_bpa_enabled = bpa_enabled(
                bucket_bpa["PublicAccessBlockConfiguration"]
            )
        except ClientError:
            bucket_bpa_enabled = False

        # -------------------------
        # Effective Exposure
        # -------------------------
        config_public = (policy_public == "YES" or acl_public == "YES")

        effective_public = (
            "YES"
            if config_public and not (bucket_bpa_enabled or account_bpa_enabled)
            else "NO"
        )

        if status == "NON_COMPLIANT":
            non_compliant += 1

        results.append({
            "BucketName": bucket_name,
            "PolicyPublic": policy_public,
            "ACLPublic": acl_public,
            "BucketBPAEnabled": str(bucket_bpa_enabled),
            "AccountBPAEnabled": str(account_bpa_enabled),
            "EffectivePublicExposure": effective_public,
            "Status": status
        })

    compliant = total_checked - non_compliant
    return results, total_checked, compliant, non_compliant

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"s3_public_access_with_bpa_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "BucketName",
            "PolicyPublic",
            "ACLPublic",
            "BucketBPAEnabled",
            "AccountBPAEnabled",
            "EffectivePublicExposure",
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
        description="Ensure S3 buckets are not open to everyone"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_s3_public_access(session)

    print("\n====================================================")
    print("CONTROL: S3 Buckets Not Open To Everyone")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Buckets Checked : {total_checked}")
    print(f"Compliant              : {compliant}")
    print(f"Non-Compliant          : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
