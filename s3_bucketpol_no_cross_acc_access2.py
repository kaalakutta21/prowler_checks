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
            RoleSessionName="s3-cross-account-audit"
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
# HELPERS
# ==================================================

def normalize(value):
    if isinstance(value, list):
        return value
    return [value]


def extract_account_id_from_arn(arn):
    try:
        parts = arn.split(":")
        if len(parts) >= 5:
            return parts[4]
    except Exception:
        pass
    return None


def condition_text(condition):
    if not condition:
        return ""
    return json.dumps(condition, sort_keys=True).lower()


def is_cloudfront_oac_allowed(principal, condition):
    """
    Allow CloudFront OAC pattern:
      Principal.Service == cloudfront.amazonaws.com
      AND AWS:SourceArn references a CloudFront distribution
    """
    if not isinstance(principal, dict):
        return False

    service_vals = normalize(principal.get("Service", []))
    if "cloudfront.amazonaws.com" not in service_vals:
        return False

    cond_str = condition_text(condition)

    return (
        "aws:sourcearn" in cond_str
        and "arn:aws:cloudfront::" in cond_str
        and ":distribution/" in cond_str
    )


def is_cloudfront_oai_allowed(principal):
    """
    Allow legacy CloudFront OAI style principals.

    Common patterns include IAM-style CloudFront OAI ARNs or canonical-user-
    style CloudFront identity references embedded under AWS principal forms.
    """
    values = []

    if isinstance(principal, str):
        values = [principal]
    elif isinstance(principal, dict):
        for key in ["AWS", "CanonicalUser"]:
            v = principal.get(key)
            if v:
                values.extend(normalize(v))

    for v in values:
        text = str(v)
        if "cloudfront" in text.lower() and "origin-access-identity" in text.lower():
            return True

    return False


def statement_allows_cross_account(statement, current_account, trusted_account_ids):
    """
    Prowler-like behavior:
    - Allow statements only
    - Principal "*" => NON_COMPLIANT
    - Explicit AWS principals from other accounts => NON_COMPLIANT
      unless account is current account or in trusted_account_ids
    - CloudFront OAC/OAI patterns => allowed
    - Generic service principals are NOT automatically flagged
    """

    if statement.get("Effect") != "Allow":
        return False, "Statement is not Allow"

    principal = statement.get("Principal")
    if not principal:
        return False, "No Principal"

    condition = statement.get("Condition")

    # Public / wildcard
    if principal == "*":
        return True, 'Principal "*"'

    if isinstance(principal, dict):
        # CloudFront OAC exception
        if is_cloudfront_oac_allowed(principal, condition):
            return False, "Allowed CloudFront OAC pattern"

        # CloudFront OAI exception
        if is_cloudfront_oai_allowed(principal):
            return False, "Allowed CloudFront OAI pattern"

        aws_vals = normalize(principal.get("AWS", []))

        for p in aws_vals:
            if p == "*":
                return True, 'Principal.AWS contains "*"'

            if isinstance(p, str) and p.startswith("arn:aws"):
                acc_id = extract_account_id_from_arn(p)

                if acc_id and acc_id != current_account and acc_id not in trusted_account_ids:
                    return True, f"External AWS principal account {acc_id}"

            # Bare account ID form
            if isinstance(p, str) and p.isdigit() and len(p) == 12:
                if p != current_account and p not in trusted_account_ids:
                    return True, f"External AWS principal account {p}"

        # Generic service principals are not auto-cross-account for this control
        return False, "No external AWS principal detected"

    # String principals that are not dicts
    if isinstance(principal, str):
        if principal == "*":
            return True, 'Principal "*"'

        if principal.isdigit() and len(principal) == 12:
            if principal != current_account and principal not in trusted_account_ids:
                return True, f"External AWS principal account {principal}"

        if principal.startswith("arn:aws"):
            acc_id = extract_account_id_from_arn(principal)
            if acc_id and acc_id != current_account and acc_id not in trusted_account_ids:
                return True, f"External AWS principal account {acc_id}"

    return False, "No cross-account principal found"


# ==================================================
# CONTROL LOGIC
# ==================================================

def check_s3_cross_account(session, trusted_account_ids=None):
    if trusted_account_ids is None:
        trusted_account_ids = []

    s3 = session.client("s3")
    account_id = get_account_id(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        results.append({
            "BucketName": "N/A",
            "BucketArn": "N/A",
            "Status": "SKIPPED",
            "Evidence": f"Unable to list buckets: {error_code}"
        })
        return results, total_checked, compliant, non_compliant, 1

    print(f"\nTotal Buckets Found: {len(buckets)}\n")

    for bucket in tqdm(buckets, desc="Evaluating Buckets"):
        bucket_name = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        total_checked += 1
        bucket_non_compliant = False
        evidence = "No cross-account access"

        try:
            policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy_resp["Policy"])
        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            # No policy => compliant for this control
            if error_code in ["NoSuchBucketPolicy", "NoSuchBucket"]:
                compliant += 1
                results.append({
                    "BucketName": bucket_name,
                    "BucketArn": bucket_arn,
                    "Status": "COMPLIANT",
                    "Evidence": "No bucket policy"
                })
                continue

            skipped += 1
            results.append({
                "BucketName": bucket_name,
                "BucketArn": bucket_arn,
                "Status": "SKIPPED",
                "Evidence": f"Unable to read bucket policy: {error_code}"
            })
            continue

        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            is_cross, stmt_evidence = statement_allows_cross_account(
                statement,
                account_id,
                trusted_account_ids
            )
            if is_cross:
                bucket_non_compliant = True
                evidence = stmt_evidence
                break

        if bucket_non_compliant:
            status = "NON_COMPLIANT"
            non_compliant += 1
        else:
            status = "COMPLIANT"
            compliant += 1

        results.append({
            "BucketName": bucket_name,
            "BucketArn": bucket_arn,
            "Status": status,
            "Evidence": evidence
        })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"s3_cross_account_policy_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "BucketName",
            "BucketArn",
            "Status",
            "Evidence"
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
        description="Ensure S3 bucket policy does not allow cross-account access (Prowler-like)"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    parser.add_argument(
        "--trusted-account-ids",
        nargs="*",
        default=[],
        help="Additional trusted account IDs to allow"
    )
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    # Always trust current account as Prowler does conceptually
    trusted_accounts = set(args.trusted_account_ids)
    trusted_accounts.add(account_id)

    results, total_checked, compliant, non_compliant, skipped = \
        check_s3_cross_account(session, sorted(trusted_accounts))

    print("\n====================================================")
    print("CONTROL: S3 Bucket Policy Does Not Allow Cross Account Access")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Buckets Checked : {total_checked}")
    print(f"Compliant             : {compliant}")
    print(f"Non-Compliant         : {non_compliant}")
    print(f"Skipped               : {skipped}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")


if __name__ == "__main__":
    main()
