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
            RoleSessionName="cloudfront-tls-audit"
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
# CONTROL LOGIC
# ==================================================

def check_cloudfront_origin_tls(session):

    cf = session.client("cloudfront")
    account_id = get_account_id(session)

    results = []
    non_compliant = 0
    total_checked = 0

    paginator = cf.get_paginator("list_distributions")

    distributions = []

    for page in paginator.paginate():
        items = page.get("DistributionList", {}).get("Items", [])
        distributions.extend(items)

    print(f"\nTotal Distributions Found: {len(distributions)}\n")

    for dist in tqdm(distributions, desc="Evaluating Distributions"):

        dist_id = dist["Id"]
        total_checked += 1
        violation_found = False

        origins = dist.get("Origins", {}).get("Items", [])

        for origin in origins:

            # Only custom origins have SSL settings
            if "CustomOriginConfig" not in origin:
                continue

            protocols = origin["CustomOriginConfig"]["OriginSslProtocols"]["Items"]

            for proto in protocols:
                if proto in ["SSLv3", "TLSv1", "TLSv1.1"]:
                    violation_found = True
                    break

            if violation_found:
                break

        if violation_found:
            status = "NON_COMPLIANT"
            non_compliant += 1
        else:
            status = "COMPLIANT"

        results.append({
            "DistributionId": dist_id,
            "Status": status
        })

    compliant = total_checked - non_compliant

    return account_id, results, total_checked, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"cloudfront_origin_tls_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "DistributionId",
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

# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ensure CloudFront does not use SSLv3, TLSv1, or TLSv1.1 for origin connections"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, total_checked, compliant, non_compliant = \
        check_cloudfront_origin_tls(session)

    print("\n====================================================")
    print("CONTROL: CloudFront Origin Does Not Use Weak TLS")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Distributions Checked : {total_checked}")
    print(f"Compliant                   : {compliant}")
    print(f"Non-Compliant               : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
