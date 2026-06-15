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
            RoleSessionName="confused-deputy-audit"
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

def check_confused_deputy(session):

    iam = session.client("iam")

    account_id = get_account_id(session)

    results = []

    total = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print("\nScanning IAM Roles...\n")

    try:

        paginator = iam.get_paginator(
            "list_roles"
        )

        all_roles = []

        for page in paginator.paginate():

            all_roles.extend(
                page.get("Roles", [])
            )

    except ClientError as e:

        print(
            f"Unable to enumerate roles: {e}"
        )

        return [], 0, 0, 0, 1

    for role in tqdm(
        all_roles,
        desc="Checking Roles"
    ):

        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Skip AWS Service Linked Roles
        if role_name.startswith(
            "AWSServiceRoleFor"
        ):
            continue

        total += 1

        try:

            trust_policy = role[
                "AssumeRolePolicyDocument"
            ]

            statements = trust_policy.get(
                "Statement",
                []
            )

            if not isinstance(
                statements,
                list
            ):
                statements = [statements]

            status = "COMPLIANT"

            service_principal = ""

            evidence = (
                "No service principals found"
            )

            for stmt in statements:

                if stmt.get(
                    "Effect"
                ) != "Allow":
                    continue

                principal = stmt.get(
                    "Principal",
                    {}
                )

                if "Service" not in principal:
                    continue

                services = principal[
                    "Service"
                ]

                if not isinstance(
                    services,
                    list
                ):
                    services = [services]

                for service in services:

                    service_principal = service

                    conditions = stmt.get(
                        "Condition",
                        {}
                    )

                    has_source_arn = False
                    has_source_account = False

                    def find_keys(obj):

                        found = []

                        if isinstance(
                            obj,
                            dict
                        ):

                            for k, v in obj.items():

                                if (
                                    k ==
                                    "aws:SourceArn"
                                ):
                                    found.append(
                                        "aws:SourceArn"
                                    )

                                if (
                                    k ==
                                    "aws:SourceAccount"
                                ):
                                    found.append(
                                        "aws:SourceAccount"
                                    )

                                found.extend(
                                    find_keys(v)
                                )

                        elif isinstance(
                            obj,
                            list
                        ):

                            for item in obj:

                                found.extend(
                                    find_keys(item)
                                )

                        return found

                    found_keys = find_keys(
                        conditions
                    )

                    has_source_arn = (
                        "aws:SourceArn"
                        in found_keys
                    )

                    has_source_account = (
                        "aws:SourceAccount"
                        in found_keys
                    )

                    if not (
                        has_source_arn
                        or
                        has_source_account
                    ):

                        status = (
                            "NON_COMPLIANT"
                        )

                        evidence = (
                            f"Service principal "
                            f"{service} lacks "
                            f"aws:SourceArn and "
                            f"aws:SourceAccount"
                        )

                        break

                    if has_source_arn:

                        evidence = (
                            f"Service principal "
                            f"{service} protected "
                            f"with aws:SourceArn"
                        )

                    elif has_source_account:

                        evidence = (
                            f"Service principal "
                            f"{service} protected "
                            f"with aws:SourceAccount"
                        )

                if status == "NON_COMPLIANT":
                    break

            if status == "COMPLIANT":
                compliant += 1
            else:
                non_compliant += 1

            results.append({

                "Account":
                    account_id,

                "RoleName":
                    role_name,

                "RoleArn":
                    role_arn,

                "ServicePrincipal":
                    service_principal,

                "Status":
                    status,

                "Evidence":
                    evidence
            })

        except ClientError as e:

            skipped += 1

            results.append({

                "Account":
                    account_id,

                "RoleName":
                    role_name,

                "RoleArn":
                    role_arn,

                "ServicePrincipal":
                    "",

                "Status":
                    "SKIPPED",

                "Evidence":
                    str(e)
            })

    return (
        results,
        total,
        compliant,
        non_compliant,
        skipped
    )


# ==================================================
# CSV
# ==================================================

def write_csv(
    account_id,
    results
):

    filename = (
        f"iam_service_role_confused_deputy_"
        f"{account_id}.csv"
    )

    with open(
        filename,
        "w",
        newline=""
    ) as f:

        fields = [

            "Account",

            "RoleName",

            "RoleArn",

            "ServicePrincipal",

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
        description=
        "IAM Service Role Prevents "
        "Cross-Service Confused Deputy Attack"
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

    ) = check_confused_deputy(
        session
    )

    print(
        "\n======================================="
    )

    print(
        "CONTROL: IAM Service Role Prevents "
        "Cross-Service Confused Deputy Attack"
    )

    print(
        f"ACCOUNT: {account_id}"
    )

    print(
        "=======================================\n"
    )

    print(
        f"Total Roles Checked : {total}"
    )

    print(
        f"Compliant           : {compliant}"
    )

    print(
        f"Non-Compliant       : {non_compliant}"
    )

    print(
        f"Skipped             : {skipped}"
    )

    overall = (
        "COMPLIANT"
        if non_compliant == 0
        else "NON_COMPLIANT"
    )

    print(
        f"\nOVERALL STATUS: "
        f"{overall}"
    )

    print(
        "\n=======================================\n"
    )

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
