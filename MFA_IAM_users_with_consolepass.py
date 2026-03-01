#!/usr/bin/env python3

import boto3
import argparse
import csv
import time
import io
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
            RoleSessionName="iam-mfa-audit"
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
# CREDENTIAL REPORT HANDLING
# ==================================================

def get_credential_report_content(iam):

    # Trigger generation
    response = iam.generate_credential_report()

    # Wait until complete
    while response["State"] != "COMPLETE":
        time.sleep(1)
        response = iam.generate_credential_report()

    report = iam.get_credential_report()
    return report["Content"].decode("utf-8")

# ==================================================
# CONTROL LOGIC (PROWLER-ALIGNED)
# ==================================================

def check_mfa_for_console_users(session):

    iam = session.client("iam")

    content = get_credential_report_content(iam)
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    results = []
    non_compliant = 0
    total_console_users = 0

    print(f"\nTotal IAM Users in Credential Report: {len(rows)}\n")

    for row in tqdm(rows, desc="Evaluating IAM Users"):

        user = row["user"]

        # Skip root (separate control)
        if user == "<root_account>":
            continue

        password_enabled = row["password_enabled"]
        password_last_used = row["password_last_used"]
        mfa_active = row["mfa_active"]

        # Proper console detection (Prowler style)
        has_console = (
            password_enabled.lower() == "true"
            or password_last_used.lower() not in ("n/a", "no_information")
        )

        if not has_console:
            continue

        total_console_users += 1

        if mfa_active.lower() != "true":
            status = "NON_COMPLIANT"
            non_compliant += 1
        else:
            status = "COMPLIANT"

        results.append({
            "UserName": user,
            "PasswordEnabled": password_enabled,
            "PasswordLastUsed": password_last_used,
            "MFAActive": mfa_active,
            "Status": status
        })

    compliant = total_console_users - non_compliant

    return results, total_console_users, compliant, non_compliant

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"iam_console_mfa_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        fields = [
            "Account",
            "UserName",
            "PasswordEnabled",
            "PasswordLastUsed",
            "MFAActive",
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
        description="Ensure MFA is enabled for IAM users with console password"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    results, total_checked, compliant, non_compliant = \
        check_mfa_for_console_users(session)

    print("\n====================================================")
    print("CONTROL: MFA Enabled For IAM Users With Console Access")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")

    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"
    print(f"OVERALL STATUS: {overall_status}\n")

    print("----------------------------------------------------")
    print(f"Total Console Users Checked : {total_checked}")
    print(f"Compliant                   : {compliant}")
    print(f"Non-Compliant               : {non_compliant}")
    print("====================================================\n")

    csv_file = write_csv(account_id, results)
    print(f"CSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
