#!/usr/bin/env python3

import boto3
import argparse
import csv
import json
from tqdm import tqdm
from botocore.exceptions import ClientError

# --------------------------------------------------
# AUTH (Prowler-style -R support)
# --------------------------------------------------

def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="lambda-policy-audit"
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

def check_lambda_public_policy(session, regions):

    results = []
    total_checked = 0
    non_compliant = 0

    for region in tqdm(regions, desc="Scanning Regions"):
        lambda_client = session.client("lambda", region_name=region)

        functions = lambda_client.list_functions()["Functions"]

        for fn in tqdm(functions, desc=f"{region} Lambdas", leave=False):
            total_checked += 1
            function_name = fn["FunctionName"]

            has_policy = "NO"
            status = "COMPLIANT"

            try:
                policy_response = lambda_client.get_policy(
                    FunctionName=function_name
                )

                has_policy = "YES"
                policy_doc = json.loads(policy_response["Policy"])

                for stmt in policy_doc.get("Statement", []):
                    principal = stmt.get("Principal")

                    # Case 1: Principal is "*"
                    if principal == "*":
                        status = "NON_COMPLIANT"
                        break

                    # Case 2: Principal is dict containing AWS "*"
                    if isinstance(principal, dict):
                        aws_principal = principal.get("AWS")
                        if aws_principal == "*":
                            status = "NON_COMPLIANT"
                            break

            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    # No policy attached → compliant
                    has_policy = "NO"
                    status = "COMPLIANT"
                else:
                    # Any other error treat as compliant but visible
                    has_policy = "ERROR"
                    status = "COMPLIANT"

            if status == "NON_COMPLIANT":
                non_compliant += 1

            results.append({
                "Region": region,
                "FunctionName": function_name,
                "HasPolicy": has_policy,
                "Status": status
            })

    compliant = total_checked - non_compliant
    return results, total_checked, compliant, non_compliant

# --------------------------------------------------
# CSV OUTPUT
# --------------------------------------------------

def write_csv(account_id, results):
    filename = f"lambda_public_policy_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "Region",
            "FunctionName",
            "HasPolicy",
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
        description="Ensure Lambda functions do not have public resource-based policies"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)
    regions = get_regions(session)

    results, total_checked, compliant, non_compliant = \
        check_lambda_public_policy(session, regions)

    print("\n====================================================")
    print("CONTROL: Lambda Resource Policy Not Public")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Lambda Functions Checked : {total_checked}")
    print(f"Compliant                      : {compliant}")
    print(f"Non-Compliant                  : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
