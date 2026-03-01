#!/usr/bin/env python3

import boto3
import argparse
import csv
from tqdm import tqdm
from datetime import datetime, timedelta, timezone
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
            RoleSessionName="cloudtrail-combined-audit"
        )
        creds = assumed["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    return boto3.Session()

def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]

# ==================================================
# GET UNIQUE TRAILS (DEDUP MULTI-REGION)
# ==================================================

def get_unique_trails(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions()["Regions"]

    unique_trails = {}

    for region_data in regions:
        region = region_data["RegionName"]

        try:
            ct = session.client("cloudtrail", region_name=region)

            trails = ct.describe_trails(
                includeShadowTrails=False
            )["trailList"]

            for trail in trails:

                # Only count trail in its HomeRegion
                if trail["HomeRegion"] != region:
                    continue

                unique_trails[trail["Name"]] = {
                    "Region": region,
                    "Trail": trail
                }

        except ClientError:
            continue

    return unique_trails

# ==================================================
# CONTROL LOGIC
# ==================================================

def check_cloudtrail_controls(session):

    account_id = get_account_id(session)
    trails = get_unique_trails(session)

    results = []

    summary = {
        "Insights Enabled": {"total": 0, "non_compliant": 0},
        "Logs Delivered Last 24 Hours": {"total": 0, "non_compliant": 0},
        "S3 Object-Level Logging All Buckets": {"total": 0, "non_compliant": 0},
    }

    for trail_name, trail_data in tqdm(trails.items(), desc="Evaluating Trails"):

        region = trail_data["Region"]
        trail = trail_data["Trail"]

        ct = session.client("cloudtrail", region_name=region)
        cw = session.client("cloudwatch", region_name=region)

        # ==================================================
        # 1️⃣ INSIGHTS ENABLED
        # ==================================================

        summary["Insights Enabled"]["total"] += 1

        try:
            insights = ct.get_insight_selectors(TrailName=trail_name)
            selectors = insights.get("InsightSelectors", [])

            if any(s["InsightType"] == "ApiCallRateInsight"
                   for s in selectors):
                status = "COMPLIANT"
            else:
                status = "NON_COMPLIANT"
                summary["Insights Enabled"]["non_compliant"] += 1

        except ClientError:
            status = "NON_COMPLIANT"
            summary["Insights Enabled"]["non_compliant"] += 1

        results.append([region, trail_name, "Insights Enabled", status])

        # ==================================================
        # 2️⃣ LOGS DELIVERED LAST 24 HOURS
        # ==================================================

        summary["Logs Delivered Last 24 Hours"]["total"] += 1

        if trail.get("CloudWatchLogsLogGroupArn"):

            end = datetime.now(timezone.utc)
            start = end - timedelta(hours=24)

            try:
                metrics = cw.get_metric_statistics(
                    Namespace="AWS/CloudTrail",
                    MetricName="DeliveryTime",
                    Dimensions=[{"Name": "TrailName", "Value": trail_name}],
                    StartTime=start,
                    EndTime=end,
                    Period=3600,
                    Statistics=["Sum"]
                )

                if metrics["Datapoints"]:
                    status = "COMPLIANT"
                else:
                    status = "NON_COMPLIANT"
                    summary["Logs Delivered Last 24 Hours"]["non_compliant"] += 1

            except ClientError:
                status = "NON_COMPLIANT"
                summary["Logs Delivered Last 24 Hours"]["non_compliant"] += 1

        else:
            status = "NON_COMPLIANT"
            summary["Logs Delivered Last 24 Hours"]["non_compliant"] += 1

        results.append([region, trail_name,
                        "Logs Delivered Last 24 Hours", status])

        # ==================================================
        # 3️⃣ S3 OBJECT-LEVEL LOGGING ALL BUCKETS
        # ==================================================

        summary["S3 Object-Level Logging All Buckets"]["total"] += 1

        try:
            selectors = ct.get_event_selectors(TrailName=trail_name)
            event_selectors = selectors.get("EventSelectors", [])

            s3_logging_all = False

            for selector in event_selectors:
                for dr in selector.get("DataResources", []):
                    if dr["Type"] == "AWS::S3::Object":
                        values = dr.get("Values", [])
                        if "arn:aws:s3:::" in values or \
                           "arn:aws:s3:::*" in values:
                            s3_logging_all = True

            if s3_logging_all:
                status = "COMPLIANT"
            else:
                status = "NON_COMPLIANT"
                summary["S3 Object-Level Logging All Buckets"]["non_compliant"] += 1

        except ClientError:
            status = "NON_COMPLIANT"
            summary["S3 Object-Level Logging All Buckets"]["non_compliant"] += 1

        results.append([region, trail_name,
                        "S3 Object-Level Logging All Buckets", status])

    return account_id, results, summary

# ==================================================
# CSV OUTPUT
# ==================================================

def write_csv(account_id, results):
    filename = f"cloudtrail_combined_{account_id}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Account", "Region", "TrailName", "Control", "Status"])

        for region, trail, control, status in results:
            writer.writerow([account_id, region, trail, control, status])

    return filename

# ==================================================
# MAIN
# ==================================================

def main():
    parser = argparse.ArgumentParser(
        description="CloudTrail Combined Controls (Prowler-Aligned)"
    )
    parser.add_argument("-R", "--role-arn", help="Role ARN to assume")
    args = parser.parse_args()

    session = get_session(args.role_arn)

    account_id, results, summary = check_cloudtrail_controls(session)

    print("\n====================================================")
    print("CLOUDTRAIL COMBINED SECURITY CONTROLS")
    print(f"ACCOUNT: {account_id}")
    print("====================================================\n")

    for control, data in summary.items():
        total = data["total"]
        non_compliant = data["non_compliant"]
        compliant = total - non_compliant
        overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

        print(f"CONTROL: {control}")
        print(f"  Total Evaluated : {total}")
        print(f"  Compliant       : {compliant}")
        print(f"  Non-Compliant   : {non_compliant}")
        print(f"  OVERALL         : {overall}")
        print("----------------------------------------------------")

    csv_file = write_csv(account_id, results)
    print(f"\nCSV Report Generated: {csv_file}\n")

if __name__ == "__main__":
    main()
